"""CAP_CHOWN ownership transfer, distinct chmod authority, and joint resumes."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-fchown-capable-native'
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(dst);return dst
class LinuxFchownCapableTests(unittest.TestCase):
    def test_generated_witness_retains_original_source_and_persists_capability(self):
        r=reviewed_adapter();p=ROOT/'integrations/linux_aarch64/fchown-capable'
        self.assertEqual(generate('fchown-capable'),(p/'application.c').read_text())
        self.assertEqual((p/'application.c').read_bytes(),(FIXTURE/'sources/application.c').read_bytes())
        old,_=r.source_identity(ROOT/'integrations/linux_aarch64/fchown');new,defs=r.source_identity(p)
        self.assertEqual(new['definitions'],old['definitions']);self.assertEqual(len(defs),67)
        self.assertIn(b'return ksys_fchown(fd, user, group);',defs['fchown']['body'])
        policy=json.loads((p/'checkpoint-policy.json').read_text())
        self.assertEqual(policy['fields']['creds']['members']['cap_effective'],{'type':'uint64_t','policy':'persist'})
        v=json.loads((p/'port-template.json').read_text());v['roots']=[x for x in v['roots'] if x['number']!=55]
        with self.assertRaisesRegex(ValueError,'no reviewed route'):r.application_source('fchown-capable',v)
    def test_privileged_transfer_chmod_denial_aliases_and_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-fchown-capable-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native)
            names={n:i for i,(n,_,_) in enumerate(r.fchown_capable_plan())};row=lambda n:c['calls'][names[n]]
            self.assertEqual(len(c['calls']),330);self.assertEqual(c['initial']['ownership_effective_caps'],1)
            self.assertEqual(c['initial']['uids'],[1001,1002,0]);self.assertEqual(c['initial']['owner_groups'],[0])
            for n in ('privileged_bad_fd','privileged_after_last_release','privileged_final_closed_fd'):self.assertEqual(row(n)['raw_bits'],(1<<64)-9)
            for n in ('privileged_chmod_nonowner_denied','privileged_chmod_zero_owner_denied','privileged_chmod_original_denied','chmod_console_denied'):self.assertEqual(row(n)['raw_bits'],(1<<64)-1)
            for n in ('privileged_transfer','privileged_console_same_owner','privileged_foreign_owner_group','privileged_sentinels','privileged_narrow_restore','privileged_no_access','privileged_reclaim_from_root','privileged_alias_transfer','privileged_original_group','privileged_alias_reclaim'):self.assertEqual(row(n)['raw_bits'],0)
            for n,uid,gid,mode in [('stat_privileged_transfer',9001,3001,0o100600),('stat_privileged_denied_mode',9001,3001,0o100600),('stat_privileged_sentinels',9001,3003,0o100600),('stat_privileged_restored',1002,0,0o100600),('stat_privileged_no_access',0,4001,0o100000),('stat_privileged_reclaimed',1002,0,0o100000),('stat_privileged_alias_transfer',9002,4003,0o100604),('stat_privileged_alias_group',9002,4007,0o100604),('stat_privileged_restored_alias',1002,0,0o100604)]:
                b=struct.pack('<32I',*row(n)['stat_words']);self.assertEqual(struct.unpack_from('<II',b,24),(uid,gid),n)
                self.assertEqual((row(n)['file_after']['uid'],row(n)['file_after']['gid'],row(n)['file_after']['mode']),(uid,gid,mode),n)
                self.assertEqual(b[72:120],bytes(48))
            self.assertEqual(row('privileged_pread_foreign_owner')['raw_bits'],1)
            self.assertEqual(row('privileged_pread_foreign_owner')['file_after']['pos'],row('stat_mode_none')['file_after']['pos'])
            old=json.loads((ROOT/'tests/fixtures/linux-aarch64-fchmod-native/capture.json').read_text());oldnames={n for n,_,_ in r.fchmod_plan()}
            def stable(v):
                v=json.loads(json.dumps(v));del v['stat_digest']
                if v['file_after'] is not None:
                    for field in ('uid','gid'):v['file_after'].pop(field,None)
                return v
            self.assertEqual([stable(v) for (n,_,_),v in zip(r.fchown_capable_plan(),c['calls']) if n in oldnames],[stable(v) for v in old['calls']])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(330,32,1096,972))
            self.assertEqual(len(result['syscalls']),24);self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual([(s['file']['uid'],s['file']['gid']) for s in result['saved_state']],[(9001,3001),(9001,3003),(0,4001),(9002,4007),(1002,0),(1002,0)])
            self.assertEqual(result['saved_state'][-1]['file_counts'],[3,0])
            for s in result['saved_state']:
                self.assertEqual(s['ownership_effective_caps'],1);self.assertEqual(s['file_mounts'],[1,2]);self.assertEqual(s['mount_ids'],[1,2])
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual(k['target_observations']['verified_calls'],990);self.assertEqual(k['target_observations']['isolation_checks'],660)
            self.assertTrue(any(f['path']=='creds.cap_effective' for f in k['checkpoint_codec']['fields']))
            spec=json.loads((stage/'pipeline/port/spec.json').read_text());self.assertEqual([(o['id'],o['bytes']) for o in spec['objects']],[(1,32),(2,128)])
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_capability_authority_owner_write_group_write_and_chmod_mutants_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('bool chown=current_cred()->cap_effective&UINT64_C(1);','bool chown=false;'),
                     ('if(a->ia_valid&ATTR_UID)p->uid=a->ia_vfsuid;','(void)a;'),
                     ('if(a->ia_valid&ATTR_GID)p->gid=a->ia_vfsgid;','(void)a;'),
                     ('if(p->uid!=current_euid())return -EPERM;','if(p->uid!=current_euid() && !(current_cred()->cap_effective&1))return -EPERM;')]
            for i,(a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_source_abi_and_forged_native_authority_or_transfer_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,a,b in [('upstream/fs/open.c',b'return ksys_fchown(fd, user, group);',b'return 0;'),('upstream/include/uapi/asm-generic/unistd.h',b'__NR_capset 91',b'__NR_capset 92')]:
                p=native/filename;s=p.read_bytes();self.assertIn(a,s);p.write_bytes(s.replace(a,b,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(s)
            original={n:(native/n).read_bytes() for n in ('capture.json','qemu.log','capture.manifest.json')}
            for field in ('uid','gid','ownership_effective_caps'):
                v=json.loads(original['capture.json'])
                if field in ('uid','gid'):
                    i=next(i for i,(n,_,_) in enumerate(reviewed_adapter().fchown_capable_plan()) if n=='privileged_transfer');v['calls'][i]['file_after'][field]=1002 if field=='uid' else 0
                else:v['initial'][field]=9
                (native/'capture.json').write_text(json.dumps(v,indent=2)+'\n');uart={k:x for k,x in v.items() if k!='format'}
                altered,count=re.subn(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}\r?$','OSREC_LINUX_CAPTURE '+json.dumps(uart),original['qemu.log'].decode(),flags=re.M)
                self.assertEqual(count,1);(native/'qemu.log').write_text(altered)
                m=json.loads(original['capture.manifest.json']);m['capture_sha256']=digest((native/'capture.json').read_bytes());m['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(m,indent=2)+'\n')
                with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ|authorization entry state differs'):build_bundle(native,stage/'bad-native')
                self.assertFalse((stage/'bad-native').exists())
                for n,data in original.items():(native/n).write_bytes(data)
if __name__=='__main__':unittest.main()
