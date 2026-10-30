"""Unprivileged ownership rules and shared group updates survive joint resumes."""
import gzip,json,re,shutil,struct,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from capture_linux_aarch64 import reviewed_adapter,digest
from generate_linux_aarch64_application import generate
from prepare_linux_aarch64_port import build_bundle
from run_linux_aarch64_checkpoint_pipeline import run,verify_pipeline
from export_syscall_slices import export
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-fchown-native'
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(dst);return dst
class LinuxFchownTests(unittest.TestCase):
    def test_generated_witness_and_original_chown_source_are_bound(self):
        r=reviewed_adapter();p=ROOT/'integrations/linux_aarch64/fchown';s=generate('fchown')
        self.assertEqual(s,(p/'application.c').read_text());self.assertEqual(s,(FIXTURE/'sources/application.c').read_text())
        old,_=r.source_identity(ROOT/'integrations/linux_aarch64/fchmod');new,defs=r.source_identity(p)
        self.assertEqual(len(defs),67)
        for n,h in old['definitions'].items():self.assertEqual(new['definitions'][n],h)
        self.assertIn(b'user != (uid_t)-1',defs['chown_common']['body'])
        self.assertIn(b'attr->ia_valid |= ATTR_GID;',defs['setattr_vfsgid']['body'])
        self.assertIn(b'fdput(f);',defs['ksys_fchown']['body'])
        self.assertIn(b'mnt_drop_write_file(file);',defs['vfs_fchown']['body'])
        v=json.loads((p/'port-template.json').read_text());v['roots']=[x for x in v['roots'] if x['number']!=55]
        with self.assertRaisesRegex(ValueError,'no reviewed route'):r.application_source('fchown',v)
    def test_group_changes_authorization_aliases_and_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-fchown-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);_,states=r.projection(c)
            names={n:i for i,(n,_,_) in enumerate(r.fchown_plan())};row=lambda n:c['calls'][names[n]]
            output=lambda n:struct.pack('<32I',*row(n)['stat_words'])
            self.assertEqual(len(c['calls']),328)
            self.assertEqual(c['initial']['owner_groups'],[0]);self.assertEqual(c['initial']['ownership_effective_caps'],0)
            for n in ('chown_bad_fd','chown_after_last_release','chown_final_closed_fd'):self.assertEqual(row(n)['raw_bits'],(1<<64)-9)
            for n in ('chown_console_denied','chown_foreign_uid_denied','chown_foreign_group_denied','chown_denied_pair_atomic'):self.assertEqual(row(n)['raw_bits'],(1<<64)-1)
            for n in ('chown_same_owner','chown_effective_group','chown_sentinels_keep_group','chown_narrow_arguments','chown_no_access_mode','chown_via_alias','chown_original_shared','chown_restore_group'):self.assertEqual(row(n)['raw_bits'],0)
            for n,gid in [('stat_group_2002',2002),('stat_group_after_denials',2002),('stat_group_sentinels',2002),('stat_group_narrowed',0),('stat_group_no_access',2002),('stat_group_alias_zero',0),('stat_group_alias_2002',2002),('stat_group_denied_atomic',2002),('stat_group_restored',0)]:
                b=output(n);self.assertEqual(struct.unpack_from('<II',b,24),(1002,gid),n)
                self.assertEqual((row(n)['file_after']['uid'],row(n)['file_after']['gid']),(1002,gid),n)
                self.assertEqual(b[72:120],bytes(48));self.assertEqual(b[120:],bytes(8))
            self.assertEqual(row('chown_no_access_mode')['file_after']['mode'],0o100000)
            self.assertEqual(row('read_initial')['raw_bits'],6)
            self.assertEqual(row('stat_group_alias_2002')['file_after']['pos'],row('stat_mode_shared_alias')['file_after']['pos'])
            self.assertEqual(output('stat_group_alias_2002')[8:16],output('stat_initial_regular')[8:16])
            # Ownership output/digest can change; inherited return/I-O/descriptor/
            # content/position/allocation/mode observations remain identical.
            old=json.loads((ROOT/'tests/fixtures/linux-aarch64-fchmod-native/capture.json').read_text());oldnames={n for n,_,_ in r.fchmod_plan()}
            def stable(v):
                v=json.loads(json.dumps(v));del v['stat_words'];del v['stat_digest']
                if v['file_after'] is not None:
                    for field in ('uid','gid'):v['file_after'].pop(field,None)
                return v
            self.assertEqual([stable(v) for (n,_,_),v in zip(r.fchown_plan(),c['calls']) if n in oldnames],[stable(v) for v in old['calls']])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(328,32,1088,964))
            self.assertEqual(len(result['syscalls']),24);self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual(result['pause_ordinals'],[104,109,117,232,238,298])
            self.assertEqual([s['inode_metadata'][1]['gid'] for s in result['saved_state']],[2002,2002,2002,2002,2002,0])
            self.assertEqual(result['saved_state'][-1]['file_counts'],[3,0])
            for s in result['saved_state']:
                self.assertEqual(s['file_mounts'],[1,2]);self.assertEqual(s['mount_ids'],[1,2]);self.assertEqual(s['inode_metadata'][1]['uid'],1002)
                self.assertEqual(s['inode_metadata'][1]['gid'],s['file']['gid'])
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual(k['target_observations']['verified_calls'],984);self.assertEqual(k['target_observations']['isolation_checks'],656)
            spec=json.loads((stage/'pipeline/port/spec.json').read_text());self.assertEqual([(o['id'],o['bytes']) for o in spec['objects']],[(1,32),(2,128)])
            self.assertTrue(any(a['symbol']=='stat_digest' for a in spec['assertions']))
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_group_write_uid_permission_membership_and_sentinel_mutants_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('if(a->ia_valid&ATTR_GID)p->gid=a->ia_vfsgid;','(void)a;'),
                     ('if((a->ia_valid&ATTR_UID) && (!owner || a->ia_vfsuid!=p->uid))return -EPERM;','(void)owner;'),
                     ('if((a->ia_valid&ATTR_GID) && (!owner || (a->ia_vfsgid!=p->gid && a->ia_vfsgid!=current_egid() && a->ia_vfsgid!=LINUX_INITIAL_OWNER_GROUP)))return -EPERM;','(void)owner;'),
                     ('if(a->ia_valid&ATTR_GID)p->gid=a->ia_vfsgid;','p->gid=a->ia_vfsgid;')]
            for i,(a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_source_abi_and_forged_native_ownership_or_authorization_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,a,b in [('upstream/fs/open.c',b'newattrs.ia_valid =  ATTR_CTIME;',b'newattrs.ia_valid = 0;'),('upstream/fs/open.c',b'return ksys_fchown(fd, user, group);',b'return 0;'),('upstream/include/uapi/asm-generic/unistd.h',b'__NR_fchown 55',b'__NR_fchown 54')]:
                p=native/filename;s=p.read_bytes();self.assertIn(a,s);p.write_bytes(s.replace(a,b,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(s)
            original={n:(native/n).read_bytes() for n in ('capture.json','qemu.log','capture.manifest.json')}
            for field in ('gid','owner_groups','ownership_effective_caps'):
                v=json.loads(original['capture.json'])
                if field=='gid':
                    i=next(i for i,(n,_,_) in enumerate(reviewed_adapter().fchown_plan()) if n=='chown_effective_group');v['calls'][i]['file_after']['gid']=3001
                elif field=='owner_groups':v['initial'][field]=[3001]
                else:v['initial'][field]=1
                (native/'capture.json').write_text(json.dumps(v,indent=2)+'\n');uart={k:x for k,x in v.items() if k!='format'}
                altered,count=re.subn(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}\r?$','OSREC_LINUX_CAPTURE '+json.dumps(uart),original['qemu.log'].decode(),flags=re.M)
                self.assertEqual(count,1);(native/'qemu.log').write_text(altered)
                m=json.loads(original['capture.manifest.json']);m['capture_sha256']=digest((native/'capture.json').read_bytes());m['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(m,indent=2)+'\n')
                with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ|authorization entry state differs'):build_bundle(native,stage/'bad-native')
                self.assertFalse((stage/'bad-native').exists())
                for n,data in original.items():(native/n).write_bytes(data)
if __name__=='__main__':unittest.main()
