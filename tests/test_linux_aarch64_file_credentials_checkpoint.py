"""Scalar UID/accounting paths in the complete bounded Linux file session."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-file-credentials-native'
def prepare_capture(dst):
    shutil.copytree(FIXTURE,dst,ignore=shutil.ignore_patterns('root.ext2.gz'));(dst/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()));reviewed_adapter().validate_capture(dst);return dst
class LinuxFileCredentialsTests(unittest.TestCase):
    def test_generated_witness_original_uid_accounting_and_all_routes(self):
        r=reviewed_adapter();p=profile_integration('file-credentials');new,defs=r.source_identity(p);old,_=r.source_identity(profile_integration('file-prctl'));standalone,_=r.source_identity(profile_integration('credential-setters'))
        self.assertEqual(len(defs),108);self.assertEqual(len(new['additional_sources']),11)
        self.assertEqual({n:new['definitions'][n] for n in old['definitions']},old['definitions'])
        for n in ('setuid','__sys_setuid','setreuid','__sys_setreuid','setresuid','__sys_setresuid','set_user','flag_nproc_exceeded','set_cred_ucounts'):self.assertEqual(new['definitions'][n],standalone['definitions'][n])
        self.assertEqual(generate('file-credentials'),(p/'application.c').read_text());self.assertEqual((p/'application.c').read_bytes(),(FIXTURE/'sources/application.c').read_bytes())
        routes={v['number'] for v in json.loads((p/'port-template.json').read_text())['roots']};all_routes=set()
        for q in [ROOT/'integrations/linux_aarch64']+list((ROOT/'integrations/linux_aarch64').iterdir()):
            if q.is_dir() and (q/'port-template.json').exists():all_routes.update(x['number'] for x in json.loads((q/'port-template.json').read_text())['roots'])
        self.assertLessEqual(routes,all_routes);self.assertEqual(len(routes),37)
        for i,(_,entry,data) in enumerate(r.file_credentials_plan()):
            self.assertEqual(len(entry['args']),5);expected=list(data) if data is not None else [0xa5a50000+j for j in range(8)];words=r.input_words('file-credentials',i);self.assertEqual(words,expected);words[0]^=0xffffffff;self.assertEqual(r.input_words('file-credentials',i),expected)
        for profile in ('fsuid','setresuid','uid-setters','credential-setters','fd-dup','file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl'):self.assertEqual(generate(profile),(profile_integration(profile)/'application.c').read_text())
    def test_live_uid_fixups_file_access_accounting_abort_and_joint_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-credentials-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');r=reviewed_adapter();c,_=r.validate_capture(native);_,states=r.projection(c);plan=r.file_credentials_plan();names={n:i for i,(n,_,_) in enumerate(plan)};row=lambda n:c['calls'][names['file_credentials_'+n]]
            self.assertEqual(len(c['calls']),821);self.assertEqual(c['initial']['file_capabilities'][1],r.FILE_CAP_INITIAL|64|256|128);self.assertEqual(c['initial']['nproc_limit'],[(1<<64)-1]*2)
            for n,ids in [('move_accounting_user',[9001,1002,0]),('privileged_root',[9002,0,0]),('drop_effective_root',[9002,1002,0]),('partial_real_then_effective_denied',[9002,1002,0]),('unprivileged_real_setuid',[9002,9002,0]),('saved_root_setuid',[9002,0,0]),('drop_all_root_keepcaps',[9001,9001,9002]),('privileged_all_ids',[9002]*3),('suppressed_nonroot',[9001,9002,9001]),('restore_initial_ids',[1001,1002,0])]:self.assertEqual(row(n)['file_uids_after'],ids,n)
            for n,e in [('caps_after_root',4194761),('caps_after_effective_drop',0),('kept_permitted_caps',0),('suppressed_root_caps',457),('suppressed_caps',457),('root_regained_caps',4194761),('restored_caps',1)]:self.assertEqual(row(n)['words'][2],e,n)
            self.assertEqual(row('real_after_change')['raw_bits'],9001);self.assertEqual(row('effective_after_change')['raw_bits'],1002);self.assertEqual(row('effective_after_root')['raw_bits'],0)
            self.assertEqual(row('invalid_setuid')['raw_bits'],(1<<64)-22)
            for n in ('foreign_resuid_denied','partial_real_then_effective_denied','saved_only_real_denied','dropped_owner_denied','dropped_chmod_denied','dropped_noatime_denied'):self.assertEqual(row(n)['raw_bits'],(1<<64)-1,n)
            self.assertEqual(row('kept_permitted_caps')['file_caps_after'],[0,4194761,1]);self.assertEqual(row('drop_all_root_keepcaps')['file_prctl_after'][1:],[0,16])
            self.assertEqual(row('suppressed_nonroot')['file_prctl_after'][1:],[1,4]);self.assertEqual(row('suppressed_transfer')['file_after']['uid'],9001);self.assertEqual(row('suppressed_reclaim')['file_after']['uid'],1002)
            self.assertEqual(row('open_pread_after_drop')['raw_bits'],4);self.assertEqual(row('open_pread_after_drop')['words'][2],int.from_bytes(b'abcd','little'));self.assertEqual(row('open_pread_after_drop')['file_after']['pos'],0)
            self.assertEqual(row('partial_uid_output')['raw_bits'],(1<<64)-14);self.assertEqual(row('partial_uid_output')['words'][1:4],[1001,0xa5a50002,0xa5a50003]);self.assertEqual(row('aliased_uid_output')['words'][1],0)
            i=names['file_credentials_partial_real_then_effective_denied'];before=states[i]['file_credentials'];after=states[i+1]['file_credentials'];self.assertEqual(after['active'],before['active']);self.assertEqual(after['generation'],before['generation']);candidate=1-after['active'];self.assertEqual(after['uids'][candidate],[1002,9001,0]);self.assertEqual(after['user_links'][candidate],[3,3])
            old=json.loads((ROOT/'tests/fixtures/linux-aarch64-file-prctl-native/capture.json').read_text());oldnames={n for n,_,_ in r.file_prctl_plan()};inherited=[]
            for (n,_,_),v in zip(plan,c['calls']):
                if n not in oldnames:continue
                v=dict(v);v.pop('file_uids_after')
                if len(inherited)<20:v['file_caps_after']=v['file_caps_after'][:];v['file_caps_after'][1]&=~128
                inherited.append(v)
            self.assertEqual(inherited,old['calls'])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU));self.assertEqual((result['logical_calls'],len(result['syscalls']),result['qemu_matrix_executions']),(821,37,32));self.assertFalse(result['runtime_host_interaction']);self.assertEqual(result['pause_ordinals'],[23,33,43,57,68,818]);self.assertEqual((result['context_bytes'],result['record_bytes']),(1488,1292))
            self.assertEqual([v['uids'] for v in result['saved_state']],[[9001,1002,0],[9002,1002,0],[9001,9001,9002],[9001,9002,9001],[1001,1002,0],[1001,1002,0]])
            for st in result['saved_state']:
                expected=states[st['ordinal']];cred=expected['file_credentials'];self.assertEqual(st['file_uid_pool'],cred['uids']);self.assertEqual(st['user_links'],[v[0]+1 for v in cred['user_links']]);self.assertEqual(st['accounting_links'],[v[1]+1 for v in cred['user_links']]);self.assertEqual(st['file_capability_pool'],cred['caps']);self.assertEqual(st['credential_securebits'],cred['securebits']);self.assertEqual(st['generation'],cred['generation']);self.assertEqual(st['file_flags'],expected['file_status'])
                self.assertEqual(st['user_accounting'],[dict(uid=uid,usage=int(uid==st['uids'][0])) for uid in (1001,0,9001,9002)])
            aborted=result['saved_state'][1];inactive=2-aborted['credential_id'];self.assertEqual(aborted['file_uid_pool'][inactive],[1002,9001,0]);self.assertEqual(aborted['user_links'][inactive],4);self.assertEqual(aborted['accounting_links'][inactive],4)
            final=states[-1]['file_credentials'];self.assertEqual((final['generation'],final['epochs'],final['active']),(130,[130,129],0));self.assertEqual(final['uids'],[[1001,1002,0]]*2);self.assertEqual(final['user_links'],[[0,0]]*2)
            k=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            for j in range(4):
                field=next(f for f in k['checkpoint_codec']['fields'] if f['path']==f'ucounts_pool[{j}].ns');self.assertEqual((field['policy'],field['target']),('self_reference','user_ns'));self.assertNotIn('wire_offset',field)
            self.assertEqual((k['target_observations']['verified_calls'],k['target_observations']['isolation_checks']),(2463,1642));shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
    def test_uid_getter_fixups_abort_links_and_reference_mutants_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-credentials-mutants-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('get_uid(candidate->user);get_ucounts(candidate->ucounts);','get_ucounts(candidate->ucounts);'),
                     ('return &ucounts_pool[i];','return &ucounts_pool[0];'),
                     ('uid_t current_uid(void){return current_cred()->uid;}','uid_t current_uid(void){return LINUX_INITIAL_UID;}'),
                     ('put_ucounts(candidate->ucounts);pending_credential=0;','put_ucounts(candidate->ucounts);*candidate=*current->cred;pending_credential=0;'),
                     ('? cap_task_fix_setuid(candidate,old,flags) : -EINVAL;','? (flags==LSM_SETID_FS ? cap_task_fix_setuid(candidate,old,flags) : 0) : -EINVAL;')]
            for i,(a,b) in enumerate(changes):
                bundle=stage/str(i);port=build_bundle(native,bundle);p=bundle/'models.c';s=p.read_text();self.assertEqual(s.count(a),1);p.write_text(s.replace(a,b));v=json.loads(port.read_text());v['bundle']['inputs']['models.c']=digest(p.read_bytes());port.write_text(json.dumps(v));out=stage/('bad-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=out,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(out.exists())
    def test_original_uid_accounting_abi_and_jointly_forged_evidence_reject(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-file-credentials-forged-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for filename,a,b in [('upstream/kernel/cred.c',b'put_ucounts(old_ucounts);',b'get_ucounts(old_ucounts);'),('upstream/kernel/sys.c',b'new->uid = kruid;',b'new->uid = old->uid;'),('upstream/include/uapi/asm-generic/unistd.h',b'#define __NR_setuid 146',b'#define __NR_setuid 246')]:
                p=native/filename;original=p.read_bytes();self.assertIn(a,original);p.write_bytes(original.replace(a,b,1))
                with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
                self.assertFalse((stage/'bad-source').exists());p.write_bytes(original)
            original={n:(native/n).read_bytes() for n in ('capture.json','qemu.log','capture.manifest.json')};names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_credentials_plan())}
            for field in ('uid','partial','keepcaps','fixup','open_access'):
                v=json.loads(original['capture.json'])
                if field=='uid':v['calls'][names['file_credentials_move_accounting_user']]['file_uids_after'][0]=1001
                elif field=='partial':v['calls'][names['file_credentials_partial_real_then_effective_denied']]['raw_bits']=0
                elif field=='keepcaps':v['calls'][names['file_credentials_drop_all_root_keepcaps']]['file_caps_after'][1]=0
                elif field=='fixup':v['calls'][names['file_credentials_suppressed_root']]['file_caps_after'][0]=4194761
                else:v['calls'][names['file_credentials_open_pread_after_drop']]['raw_bits']=(1<<64)-13
                (native/'capture.json').write_text(json.dumps(v,indent=2)+'\n');uart={k:x for k,x in v.items() if k!='format'};altered,count=re.subn(r'^OSREC_LINUX_CAPTURE \{[^\r\n]+\}\r?$','OSREC_LINUX_CAPTURE '+json.dumps(uart),original['qemu.log'].decode(),flags=re.M);self.assertEqual(count,1);(native/'qemu.log').write_text(altered)
                m=json.loads(original['capture.manifest.json']);m['capture_sha256']=digest((native/'capture.json').read_bytes());m['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(m,indent=2)+'\n')
                with self.assertRaisesRegex(ValueError,'return/memory/state transitions differ'):build_bundle(native,stage/'bad-native')
                self.assertFalse((stage/'bad-native').exists())
                for n,data in original.items():(native/n).write_bytes(data)
if __name__=='__main__':unittest.main(verbosity=2)
