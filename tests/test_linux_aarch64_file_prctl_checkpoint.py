"""Commoncap prctl, securebit-aware FSUID and the persistent Linux file session."""
import gzip,json,re,shutil,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from capture_linux_aarch64 import reviewed_adapter,profile_integration,digest
from generate_linux_aarch64_application import generate
from prepare_linux_aarch64_port import build_bundle
from run_linux_aarch64_checkpoint_pipeline import run,verify_pipeline
from export_syscall_slices import export
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-file-prctl-native'
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'));(dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()));reviewed_adapter().validate_capture(dst);return dst
class LinuxFilePrctlTests(unittest.TestCase):
    def test_generated_witness_original_hook_routing_and_five_arguments(self):
        r=reviewed_adapter();p=profile_integration('file-prctl');new,defs=r.source_identity(p);old,_=r.source_identity(profile_integration('file-capget'));standalone,_=r.source_identity(profile_integration('prctl'))
        self.assertEqual(len(defs),99);self.assertEqual(len(new['additional_sources']),10)
        self.assertEqual({n:new['definitions'][n] for n in old['definitions']},old['definitions'])
        for n in ('cap_prctl_drop','cap_task_prctl'):self.assertEqual(new['definitions'][n],standalone['definitions'][n])
        self.assertNotIn('prctl',defs);self.assertIn('routing evidence',new['scope']);self.assertEqual(new['prctl_dispatch_prefix_sha256'],standalone['prctl_dispatch_prefix_sha256'])
        self.assertEqual(generate('file-prctl'),(p/'application.c').read_text());self.assertEqual((p/'application.c').read_bytes(),(FIXTURE/'sources/application.c').read_bytes())
        route=next(v for v in json.loads((p/'port-template.json').read_text())['roots'] if v['number']==167);self.assertEqual(route['function'],'cap_task_prctl');self.assertEqual(len(route['arguments']),5)
        for i,(_,entry,data) in enumerate(r.file_prctl_plan()):
            self.assertEqual(len(entry['args']),5);expected=list(data) if data is not None else [0xa5a50000+j for j in range(8)];words=r.input_words('file-prctl',i);self.assertEqual(words,expected);words[0]^=0xffffffff;self.assertEqual(r.input_words('file-prctl',i),expected)
        for profile in ('fsuid','setresuid','uid-setters','credential-setters','fd-dup','file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget'):self.assertEqual(generate(profile),(profile_integration(profile)/'application.c').read_text())
    def test_live_bounding_ambient_locks_fixup_and_joint_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-prctl-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);_,states=r.projection(c);plan=r.file_prctl_plan();names={n:i for i,(n,_,_) in enumerate(plan)};row=lambda n:c['calls'][names['file_prctl_'+n]]
            self.assertEqual(len(c['calls']),767);self.assertEqual(c['initial']['file_capabilities'][1],r.FILE_CAP_INITIAL|64|256)
            for n,value in [('initial_bounding_high',1),('read_dropped_high',0),('narrow_option',0),('ambient_is_set',1),('ambient_cleared_by_capset',0),('get_keepcaps',1),('get_locked_securebits',48),('final_bounding',0),('final_ambient',0),('final_keepcaps',1),('final_securebits',48)]:self.assertEqual(row(n)['raw_bits'],value,n)
            for n in ('drop_invalid_unprivileged','ambient_missing_inheritable','ambient_chown_denied','ambient_noatime_denied','suppressed_chown_denied','raise_forbidden','drop_invalid_without_privilege','securebits_denied','clear_locked_keepcaps','unlock_rejected','change_locked_rejected','unsupported_securebits','drop_after_permitted_removal','final_drop_denied','final_keepcaps_denied'):self.assertEqual(row(n)['raw_bits'],(1<<64)-1,n)
            for n in ('invalid_cap_privileged','high_unsigned_cap','ambient_bad_arg4','ambient_bad_arg5','ambient_unknown','ambient_invalid_cap','clear_bad_arg3','clear_bad_arg4','clear_bad_arg5','keepcaps_invalid'):self.assertEqual(row(n)['raw_bits'],(1<<64)-22,n)
            self.assertEqual(row('ambient_raise')['file_prctl_after'],[(1<<40)-1,1,0]);self.assertEqual(row('ambient_fowner')['file_prctl_after'],[(1<<40)-1,8,0]);self.assertEqual(row('drop_inheritable_chown')['file_prctl_after'],[(1<<40)-1,0,0])
            self.assertEqual(row('suppressed_root')['file_caps_after'][0],320);self.assertEqual(row('root_fixup')['file_caps_after'][0],329)
            self.assertEqual(row('root_transfer')['file_after']['uid'],9001);self.assertEqual(row('root_reclaim')['file_after']['uid'],1002)
            for n in ('drop_invalid_without_privilege','ambient_bad_arg5','clear_locked_keepcaps','unsupported_securebits'):
                i=names['file_prctl_'+n];self.assertEqual(states[i],states[i+1])
            old=json.loads((ROOT/'tests/fixtures/linux-aarch64-file-capget-native/capture.json').read_text());oldnames={n for n,_,_ in r.file_capget_plan()};inherited=[]
            for (n,_,_),v in zip(plan,c['calls']):
                if n not in oldnames:continue
                v=dict(v);v.pop('file_prctl_after');self.assertEqual(v['args'][-1],0);v['args']=v['args'][:-1]
                if len(inherited)<20:v['file_caps_after']=v['file_caps_after'][:];v['file_caps_after'][1]&=~256
                inherited.append(v)
            self.assertEqual(inherited,old['calls'])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU));self.assertEqual((result['logical_calls'],len(result['syscalls']),result['qemu_matrix_executions']),(767,34,32));self.assertFalse(result['runtime_host_interaction']);self.assertEqual(result['pause_ordinals'],[32,44,49,73,423,764]);self.assertEqual((result['context_bytes'],result['record_bytes']),(1336,1188))
            self.assertEqual([v['file_prctl_after'][1:] for v in result['saved_state']],[[1,0],[1,4],[1,0],[0,48],[0,48],[0,48]])
            for st in result['saved_state']:
                expected=states[st['ordinal']];cred=expected['file_credentials'];self.assertEqual(st['file_capability_pool'],cred['caps']);self.assertEqual(st['credential_securebits'],cred['securebits']);self.assertEqual(st['generation'],cred['generation']);self.assertEqual(st['file_flags'],expected['file_status']);self.assertEqual(st['file_gid_pool'],cred['gids']);self.assertEqual(st['file_fsuids'],cred['fsuids'])
            final=states[-1]['file_credentials'];self.assertEqual((final['generation'],final['epochs'],final['active'],final['securebits']),(108,[108,107],0,[48,48]));self.assertEqual(final['caps'],[[0,r.FILE_CAP_BOOT,0,(1<<40)-1,0]]*2)
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text());self.assertEqual((k['target_observations']['verified_calls'],k['target_observations']['isolation_checks']),(2301,1534));shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_privilege_securebit_copy_fixup_and_ambient_permission_mutants_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-prctl-mutants-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('models.c','return cap_capable(current_cred(),ns,cap,CAP_OPT_NONE)==0;','(void)cap;return ns==current_user_ns();'),
                     ('models.c','*candidate=*current->cred;get_group_info(candidate->group_info);','*candidate=*current->cred;candidate->securebits=LINUX_INITIAL_FILE_SECUREBITS;get_group_info(candidate->group_info);'),
                     ('model.h','#define issecure(bit) (current_cred()->securebits & issecure_mask(bit))','#define issecure(bit) ((uint32_t)0)'),
                     ('models.c','bool chown=current_cred()->cap_effective.val&UINT64_C(1);','bool chown=(current_cred()->cap_effective.val|current_cred()->cap_ambient.val)&UINT64_C(1);')]
            for i,(filename,a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/filename;s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs'][filename]=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_original_hook_abi_routing_and_jointly_forged_native_evidence_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-prctl-forged-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,a,b in [('upstream/security/commoncap.c',b'if (!cap_valid(cap))',b'if (cap_valid(cap))'),('upstream/include/uapi/linux/prctl.h',b'#define PR_CAPBSET_DROP 24',b'#define PR_CAPBSET_DROP 25'),('upstream/kernel/prctl-dispatch-prefix.txt',b'return error;',b'return -ENOSYS;')]:
                p=native/filename;original=p.read_bytes();self.assertIn(a,original);p.write_bytes(original.replace(a,b,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(original)
            original={n:(native/n).read_bytes() for n in ('capture.json','qemu.log','capture.manifest.json')};names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_prctl_plan())}
            for field in ('bounding','ambient','fixup','lock','fifth'):
                v=json.loads(original['capture.json'])
                if field=='bounding':v['calls'][names['file_prctl_drop_high']]['file_prctl_after'][0]=(1<<41)-1
                elif field=='ambient':v['calls'][names['file_prctl_ambient_raise']]['file_prctl_after'][1]=0
                elif field=='fixup':v['calls'][names['file_prctl_suppressed_root']]['file_caps_after'][0]=329
                elif field=='lock':v['calls'][names['file_prctl_lock_keepcaps']]['file_prctl_after'][2]=0
                else:v['calls'][names['file_prctl_ambient_bad_arg5']]['raw_bits']=0
                (native/'capture.json').write_text(json.dumps(v,indent=2)+'\n');uart={k:x for k,x in v.items() if k!='format'};altered,count=re.subn(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}\r?$','OSREC_LINUX_CAPTURE '+json.dumps(uart),original['qemu.log'].decode(),flags=re.M);self.assertEqual(count,1);(native/'qemu.log').write_text(altered)
                m=json.loads(original['capture.manifest.json']);m['capture_sha256']=digest((native/'capture.json').read_bytes());m['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(m,indent=2)+'\n')
                with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ'):build_bundle(native,stage/'bad-native')
                self.assertFalse((stage/'bad-native').exists())
                for n,data in original.items():(native/n).write_bytes(data)
if __name__=='__main__':unittest.main(verbosity=2)
