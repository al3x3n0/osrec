"""Original setuid/setreuid paths preserve saved IDs and aborted credential graphs."""
import gzip
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from capture_linux_aarch64 import reviewed_adapter,digest
from generate_linux_aarch64_application import generate
from prepare_linux_aarch64_port import build_bundle
from run_linux_aarch64_checkpoint_pipeline import run,verify_pipeline
from export_syscall_slices import export

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-uid-setters-native'
BOOT=1<<22;GID=1<<6;PCAP=1<<8;UID=1<<7
FS=sum(1<<n for n in (0,1,2,3,4,9,27,32));INITIAL=BOOT|GID|PCAP|UID|FS
INHERIT=(1<<0)|(1<<32)

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxUidSettersTests(unittest.TestCase):
    def test_generated_witness_binds_id_and_re_arguments(self):
        source=generate('uid-setters')
        self.assertEqual(source,(ROOT/'integrations/linux_aarch64/uid-setters/application.c').read_text())
        self.assertEqual(source,(FIXTURE/'sources/application.c').read_text())
        original=json.loads((ROOT/'integrations/linux_aarch64/uid-setters/port-template.json').read_text())
        for number,arity in ((146,1),(145,2)):
            port=json.loads(json.dumps(original));route=next(r for r in port['roots'] if r['number']==number)
            self.assertEqual(route['arguments'],['unsigned']*arity);port['roots'].remove(route)
            with self.assertRaisesRegex(ValueError,'no reviewed route'):reviewed_adapter().application_source('uid-setters',port)

    def test_saved_id_rules_partial_aborts_and_accounting_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-uid-setters-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');review=reviewed_adapter()
            captured,manifest=review.validate_capture(native);calls=captured['calls'];_,states=review.projection(captured)
            names={n:i for i,(n,_,_) in enumerate(review.uid_setters_plan())}
            row=lambda n:calls[names[n]]
            after=lambda n:states[names[n]+1]
            inactive=lambda n:after(n)['uids'][1-after(n)['active']]
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(len(calls),93)
            self.assertEqual(captured['initial']['nproc_limit'],[(1<<64)-1]*2)
            for n in ('invalid_setuid','truncated_invalid_setuid'):
                self.assertEqual(row(n)['raw_bits'],(1<<64)-22);self.assertEqual(after(n),states[names[n]])
            self.assertEqual(row('privileged_root_setuid')['uids_after'],[0,0,0])
            self.assertEqual(row('unprivileged_real_setuid')['uids_after'],[1001,1001,0])
            self.assertEqual(row('unprivileged_real_setuid')['capabilities_after'],[0,INITIAL,INHERIT,(1<<41)-1,INHERIT])
            self.assertEqual(row('saved_root_setuid')['uids_after'],[1001,0,0])
            self.assertEqual(row('saved_root_setuid')['capabilities_after'][0],INITIAL)
            self.assertEqual(row('partial_uid_output')['raw_bits'],(1<<64)-14)
            self.assertEqual(row('partial_uid_output')['words'][1:4],[1001,0xa5a50002,0xa5a50003])
            for n in ('same_root_publishes','same_unprivileged_setuid_publishes','sentinels_publish_and_repair_fsuid','same_real_publishes','same_ids_publish','truncated_sentinels_publish','locked_sentinels_overwrite_abort'):
                self.assertEqual(after(n)['generation'],states[names[n]]['generation']+1)
                self.assertNotEqual(after(n)['active'],states[names[n]]['active'])
            self.assertEqual(row('filesystem_diverge')['fsuid_after'],1001)
            self.assertEqual(row('sentinels_publish_and_repair_fsuid')['fsuid_after'],0)
            self.assertEqual(row('sentinels_publish_and_repair_fsuid')['capabilities_after'][0],BOOT|GID|PCAP)
            self.assertEqual(row('effective_to_real_preserves_saved')['uids_after'],[1001,1001,0])
            self.assertEqual(row('saved_root_preserved')['words'][1:4],[1001,1001,0])
            for n,expected in (('foreign_real_denied',[9001,1001,0]),('foreign_effective_denied',[1001,9002,0]),('saved_only_real_denied',[9002,0,9002]),('partial_real_then_effective_denied',[9001,9002,0]),('locked_partial_abort',[1001,9001,1001])):
                state=after(n);old=states[names[n]]
                self.assertEqual(row(n)['raw_bits'],(1<<64)-1);self.assertEqual(state['active'],old['active']);self.assertEqual(state['generation'],old['generation'])
                self.assertEqual(inactive(n),expected)
                self.assertEqual(state['user_links'][1-state['active']],old['user_links'][old['active']])
                self.assertEqual(state['uids'][state['active']],old['uids'][old['active']])
            self.assertEqual(row('real_to_effective_root')['uids_after'],[0,0,0])
            self.assertEqual(row('res_foreign_real_denied')['raw_bits'],(1<<64)-1)
            self.assertEqual(row('active_real_after_abort')['raw_bits'],1001)
            self.assertEqual(row('active_effective_after_abort')['raw_bits'],9001)
            self.assertEqual(row('swap_real_root_to_effective')['uids_after'],[0,1001,1001])
            self.assertEqual(row('swap_root_back')['uids_after'],[1001,0,0])
            self.assertEqual(row('truncated_foreign_real')['uids_after'],[9001,0,0])
            self.assertEqual(row('truncated_effective_to_real')['uids_after'],[1001,1001,0])
            self.assertEqual(row('privileged_nonroot_setuid_keepcaps')['uids_after'],[9002]*3)
            self.assertEqual(row('privileged_nonroot_setuid_keepcaps')['capabilities_after'],[0,INITIAL,INHERIT,(1<<41)-1,0])
            self.assertEqual(row('root_setuid_denied_without_effective')['raw_bits'],(1<<64)-1)
            self.assertEqual(row('privileged_restore_all_root')['uids_after'],[0]*3)
            self.assertEqual(row('suppressed_setuid_all_nonroot')['uids_after'],[9001]*3)
            self.assertEqual(row('suppressed_setuid_all_nonroot')['capabilities_after'],[INITIAL,INITIAL,INHERIT,(1<<41)-1,1<<32])
            self.assertEqual(row('suppressed_real_and_effective')['uids_after'],[9002,1001,1001])
            self.assertEqual(row('groups_allowed_suppressed')['groups_after'],[7001,7003,7007])
            self.assertEqual(row('suppressed_sentinels_repair_fsuid')['fsuid_after'],1001)
            self.assertEqual(row('locked_setuid_real')['uids_after'],[9002,9002,1001])
            self.assertEqual(row('locked_effective_saved_allowed')['uids_after'],[9002,1001,1001])
            self.assertEqual(row('locked_sentinels_overwrite_abort')['capabilities_after'][0],BOOT)
            self.assertEqual(row('aliased_final_user_ids')['words'][1],1001)
            self.assertEqual(row('final_securebits')['raw_bits'],12);self.assertEqual(states[-1]['generation'],50)
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU,pause_ordinals=None))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(93,32,536,444))
            self.assertEqual(len(result['syscalls']),19);self.assertFalse(result['runtime_host_interaction'])
            pauses=('unprivileged_real_setuid','saved_only_real_denied','partial_real_then_effective_denied','privileged_nonroot_setuid_keepcaps','suppressed_real_and_effective','locked_partial_abort')
            self.assertEqual([r['ordinal'] for r in result['saved_state']],[names[n]+1 for n in pauses])
            mismatch_count=0
            for saved in result['saved_state']:
                state=states[saved['ordinal']]
                self.assertEqual(saved['credential_uids'],state['uids']);self.assertEqual(saved['credential_fsuids'],state['fsuid'])
                self.assertEqual(saved['credential_capabilities'],state['capabilities']);self.assertEqual(saved['credential_securebits'],state['securebits'])
                self.assertEqual(saved['user_links'],[v[0]+1 for v in state['user_links']]);self.assertEqual(saved['accounting_links'],[v[1]+1 for v in state['user_links']])
                self.assertEqual(sum(p['usage'] for p in saved['user_accounting']),1)
                candidate=1-state['active']
                if state['uids'][candidate][0]!=[1001,0,9001,9002][state['user_links'][candidate][0]]:mismatch_count+=1
            self.assertEqual(mismatch_count,3)
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            for field in ('verified_calls','return_value_checks','application_memory_checks'):self.assertEqual(kernel['target_observations'][field],279)
            self.assertEqual(kernel['target_observations']['isolation_checks'],186)
            self.assertEqual(len(kernel['source_identity']['reviewed_source']['definitions']),43)
            functions=kernel['context_plan']['context_functions']+kernel['context_plan']['pure_functions']
            for helper in ('__sys_setuid','__sys_setreuid','__sys_setresuid','set_user','set_cred_ucounts','cap_emulate_setxuid'):self.assertTrue(any(n.endswith(helper) for n in functions))
            self.assertFalse(kernel['source_identity']['native_source_build_attested'])
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_fixup_permission_and_erased_inactive_mutants_fail_target_proof(self):
        changes=[('return cap_task_fix_setuid(candidate,old,flags);','return 0;'),
                 ('(current_cred()->cap_effective.val&(UINT64_C(1)<<cap))!=0;',
                  '(current_cred()->cap_permitted.val&(UINT64_C(1)<<cap))!=0;'),
                 ('pending_credential=0;}}','pending_credential=0;*candidate=*current->cred;}}')]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);model=bundle/'models.c';source=model.read_text();self.assertEqual(source.count(original),1);model.write_text(source.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):
                    export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/uid-setters/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_original_id_re_helpers_and_native_uid_observations_are_bound(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(path,needle,mutation,error) in enumerate([
                ('upstream/kernel/sys.c',b'if (ruid != (uid_t) -1 ||',b'if (ruid != (uid_t) -1 &&','reviewed source identity'),
                ('upstream/kernel/sys.c',b'new->suid = new->uid = kuid;',b'new->uid = kuid;','reviewed source identity'),
                ('upstream/include/uapi/asm-generic/unistd.h',b'__NR_setuid 146',b'__NR_setuid 145','syscall ABI source identity')]):
                source=native/path;raw=source.read_bytes();self.assertEqual(raw.count(needle),1);source.write_bytes(raw.replace(needle,mutation))
                output=stage/('bad-source-'+str(i))
                with self.assertRaisesRegex(ValueError,error):build_bundle(native,output)
                self.assertFalse(output.exists());source.write_bytes(raw)
            captured=json.loads((native/'capture.json').read_text());names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().uid_setters_plan())}
            captured['calls'][names['partial_real_then_effective_denied']]['uids_after'][0]=9001
            (native/'capture.json').write_text(json.dumps(captured))
            log=(native/'qemu.log').read_text();start=log.index('OSREC_LINUX_CAPTURE ');end=log.index('\n',start)
            log=log[:start]+'OSREC_LINUX_CAPTURE '+json.dumps({k:v for k,v in captured.items() if k!='format'})+log[end:];(native/'qemu.log').write_text(log)
            manifest=json.loads((native/'capture.manifest.json').read_text());manifest['capture_sha256']=digest((native/'capture.json').read_bytes());manifest['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'state transitions differ'):build_bundle(native,stage/'bad-observation')
            self.assertFalse((stage/'bad-observation').exists())

if __name__=='__main__':unittest.main()
