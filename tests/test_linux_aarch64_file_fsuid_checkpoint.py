"""Filesystem UID, commoncap fixup and shared inode permission checkpoints."""
import gzip,json,re,shutil,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from capture_linux_aarch64 import reviewed_adapter,digest
from generate_linux_aarch64_application import generate
from prepare_linux_aarch64_port import build_bundle
from run_linux_aarch64_checkpoint_pipeline import run,verify_pipeline
from export_syscall_slices import export
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-file-fsuid-native'
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(dst);return dst
class LinuxFileFsuidTests(unittest.TestCase):
    def test_original_fsuid_fixup_helpers_generated_workload_and_persisted_fields(self):
        r=reviewed_adapter();p=ROOT/'integrations/linux_aarch64/file-fsuid'
        self.assertEqual(generate('file-fsuid'),(p/'application.c').read_text());self.assertEqual((p/'application.c').read_bytes(),(FIXTURE/'sources/application.c').read_bytes())
        old,_=r.source_identity(ROOT/'integrations/linux_aarch64/file-fsgid');new,defs=r.source_identity(p);fs,_=r.source_identity(ROOT/'integrations/linux_aarch64/fsuid')
        self.assertEqual(len(defs),81)
        for n,h in old['definitions'].items():self.assertEqual(new['definitions'][n],h)
        for n in ('setfsuid','__sys_setfsuid','cap_emulate_setxuid','cap_task_fix_setuid','cap_drop','cap_drop_fs_set','cap_raise_fs_set'):self.assertEqual(new['definitions'][n],fs['definitions'][n])
        self.assertIn(b'security_task_fix_setuid(new, old, LSM_SETID_FS)',defs['__sys_setfsuid']['body'])
        self.assertIn(b'cap_raise_fs_set(new->cap_effective,',defs['cap_task_fix_setuid']['body'])
        fields=json.loads((p/'checkpoint-policy.json').read_text())['fields']['credential_pool']['element']['members']
        for n in ('fsuid','fsgid','securebits'):self.assertEqual(fields[n],{'type':'uint32_t','policy':'persist'})
        v=json.loads((p/'port-template.json').read_text());v['roots']=[x for x in v['roots'] if x['number']!=151]
        with self.assertRaisesRegex(ValueError,'no reviewed route'):r.application_source('file-fsuid',v)
    def test_live_fsuid_owner_checks_root_capability_fixup_and_joint_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-fsuid-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);_,states=r.projection(c)
            names={n:i for i,(n,_,_) in enumerate(r.file_fsuid_plan())};row=lambda n:c['calls'][names['file_fsuid_'+n]]
            self.assertEqual(len(c['calls']),452);self.assertEqual((c['initial']['file_fsuid'],c['initial']['file_securebits']),(1002,0))
            self.assertEqual((row('real')['raw_bits'],row('real')['file_fsuid_after']),(1002,1001))
            self.assertEqual((row('effective_query')['raw_bits'],row('effective_query')['file_fsuid_after']),(1002,1001))
            for n in ('foreign_denied','invalid_query','same_no_publish'):self.assertEqual((row(n)['raw_bits'],row(n)['file_fsuid_after']),(1001,1001))
            for n in ('real_mode_denied','real_owner_denied','dropped_mode_denied','dropped_reclaim_denied','effective_nonowner_denied','alias_nonowner_denied'):self.assertEqual(row(n)['raw_bits'],(1<<64)-1,n)
            for n in ('root_transfer','root_mode','reclaim_real','owner_mode','owner_group','owner_saved_group','alias_mode','alias_group'):self.assertEqual(row(n)['raw_bits'],0,n)
            for n in ('root_narrow','root_reclaim','root_restore','alias_root','alias_root_restore'):self.assertEqual(row(n)['file_caps_after'][0],9,n)
            for n in ('drop_root','become_owner','restore_effective','alias_become_owner','alias_restore_effective'):self.assertEqual(row(n)['file_caps_after'][0],0,n)
            for n,uid,gid,mode in [('real_denied',1002,0,0o100600),('root_foreign',9001,3001,0o100640),('dropped',9001,3001,0o100640),('owner',1001,2002,0o100604),('owner_group',1001,2003,0o100604),('effective_denied',1001,2003,0o100604),('restored',1002,0,0o100600),('alias_group',1001,2003,0o100604),('alias_restored',1002,2001,0o100400)]:
                v=row('stat_'+n)['file_after'];self.assertEqual((v['uid'],v['gid'],v['mode']),(uid,gid,mode),n)
            for n in ('foreign_denied','invalid_query','same_no_publish'):
                i=names['file_fsuid_'+n];a=states[i]['file_credentials'];b=states[i+1]['file_credentials'];self.assertEqual((a['active'],a['generation'],a['epochs']),(b['active'],b['generation'],b['epochs']))
            for n in ('refresh_nondefault','saved_group','alias_refresh_nondefault','alias_saved_group'):
                i=names['file_fsuid_'+n];self.assertEqual(states[i+1]['file_credentials']['fsuids'],[1001,1001])
            old=json.loads((ROOT/'tests/fixtures/linux-aarch64-file-fsgid-native/capture.json').read_text());oldnames={n for n,_,_ in r.file_fsgid_plan()}
            def stable(v):
                v=dict(v);v.pop('file_fsuid_after',None);v.pop('stat_digest',None);return v
            self.assertEqual([stable(v) for (n,_,_),v in zip(r.file_fsuid_plan(),c['calls']) if n in oldnames],[stable(v) for v in old['calls']])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],len(result['syscalls'])),(452,32,27));self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual([s['fsuid'] for s in result['saved_state']],[1001,0,1001,1001,1001,1002])
            self.assertEqual([s['ownership_effective_caps'] for s in result['saved_state']],[0,9,0,0,0,0])
            for s in result['saved_state']:
                st=states[s['ordinal']]['file_credentials'];self.assertEqual(s['file_fsuids'],st['fsuids']);self.assertEqual(s['file_fsgids'],st['fsgids']);self.assertEqual(s['file_capability_pool'],st['caps']);self.assertEqual(s['uids'],[1001,1002,0]);self.assertEqual(s['generation'],st['generation']);self.assertEqual(s['credential_securebits'],[0,0])
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual((k['target_observations']['verified_calls'],k['target_observations']['isolation_checks']),(1356,904))
            paths={f['path'] for f in k['checkpoint_codec']['fields']}
            for i in range(2):
                for n in ('fsuid','securebits'):self.assertIn('credential_pool['+str(i)+'].'+n,paths)
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_owner_fixup_stale_publication_and_absent_setuid_mutants_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-fsuid-mutants-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('bool owner=p->uid==current_fsuid();','bool owner=p->uid==current_euid();'),
                     ('? cap_task_fix_setuid(candidate,old,flags) : -EINVAL;','? 0 : -EINVAL;'),
                     ('current->cred=candidate;++credential_generation;','candidate->fsuid=current->cred->fsuid;current->cred=candidate;++credential_generation;'),
                     ('(current_cred()->cap_effective.val&(UINT64_C(1)<<cap))','(cap==CAP_SETUID || (current_cred()->cap_effective.val&(UINT64_C(1)<<cap)))')]
            for i,(a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_source_abi_securebits_and_jointly_forged_native_observations_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-fsuid-forged-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,a,b in [('upstream/kernel/sys.c',b'new->fsuid = kuid;',b'new->fsuid = old->fsuid;'),('upstream/include/uapi/asm-generic/unistd.h',b'__NR_setfsuid 151',b'__NR_setfsuid 153'),('upstream/include/uapi/linux/securebits.h',b'SECURE_NO_SETUID_FIXUP',b'SECURE_NO_SETUID_FIXED')]:
                p=native/filename;s=p.read_bytes();self.assertIn(a,s);p.write_bytes(s.replace(a,b,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(s)
            original={n:(native/n).read_bytes() for n in ('capture.json','qemu.log','capture.manifest.json')};names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_fsuid_plan())}
            for field in ('initial','securebits','live','caps','owner'):
                v=json.loads(original['capture.json'])
                if field=='initial':v['initial']['file_fsuid']=1001
                elif field=='securebits':v['initial']['file_securebits']=4
                elif field=='live':v['calls'][names['file_fsuid_effective_query']]['file_fsuid_after']=1002
                elif field=='caps':v['calls'][names['file_fsuid_root_narrow']]['file_caps_after'][0]=0
                else:v['calls'][names['file_fsuid_owner_mode']]['file_after']['uid']=1002
                (native/'capture.json').write_text(json.dumps(v,indent=2)+'\n');uart={k:x for k,x in v.items() if k!='format'}
                altered,count=re.subn(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}\r?$','OSREC_LINUX_CAPTURE '+json.dumps(uart),original['qemu.log'].decode(),flags=re.M)
                self.assertEqual(count,1);(native/'qemu.log').write_text(altered)
                m=json.loads(original['capture.manifest.json']);m['capture_sha256']=digest((native/'capture.json').read_bytes());m['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(m,indent=2)+'\n')
                with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ|filesystem-user entry state differs'):build_bundle(native,stage/'bad-native')
                self.assertFalse((stage/'bad-native').exists())
                for n,data in original.items():(native/n).write_bytes(data)
if __name__=='__main__':unittest.main(verbosity=2)
