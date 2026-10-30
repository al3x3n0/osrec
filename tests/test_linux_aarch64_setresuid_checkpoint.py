"""Original UID transitions and typed user accounting survive fresh-image resumes."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-setresuid-native'
BOOT=1<<22;GID=1<<6;PCAP=1<<8;UID=1<<7
FS=sum(1<<n for n in (0,1,2,3,4,9,27,32));INITIAL=BOOT|GID|PCAP|UID|FS
INHERIT=(1<<0)|(1<<32);PERMITTED=INITIAL&~INHERIT

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxSetresuidTests(unittest.TestCase):
    def test_generated_witness_binds_all_uid_arguments(self):
        source=generate('setresuid')
        self.assertEqual(source,(ROOT/'integrations/linux_aarch64/setresuid/application.c').read_text())
        self.assertEqual(source,(FIXTURE/'sources/application.c').read_text())
        port=json.loads((ROOT/'integrations/linux_aarch64/setresuid/port-template.json').read_text())
        route=next(r for r in port['roots'] if r['number']==147)
        self.assertEqual(route['arguments'],['unsigned']*3)
        port['roots'].remove(route)
        with self.assertRaisesRegex(ValueError,'no reviewed route'):reviewed_adapter().application_source('setresuid',port)

    def test_uid_fixups_accounting_and_later_calls_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-setresuid-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');review=reviewed_adapter()
            captured,manifest=review.validate_capture(native);calls=captured['calls'];_,states=review.projection(captured)
            names={n:i for i,(n,_,_) in enumerate(review.setresuid_plan())}
            row=lambda n:calls[names[n]]
            after=lambda n:states[names[n]+1]
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(len(calls),82)
            self.assertEqual(captured['initial']['nproc_limit'],[(1<<64)-1]*2)
            self.assertEqual(row('drop_effective_root')['uids_after'],[1001,1001,0])
            self.assertEqual(row('drop_effective_root')['capabilities_after'],[0,INITIAL,INHERIT,(1<<41)-1,INHERIT])
            self.assertEqual(row('restore_saved_root')['capabilities_after'][0],INITIAL)
            self.assertEqual(row('real_to_saved_root')['uids_after'],[0,0,0])
            self.assertEqual(row('real_to_foreign_privileged')['uids_after'],[9001,0,0])
            self.assertEqual(row('saved_to_foreign_privileged')['uids_after'],[9001,0,9002])
            self.assertEqual(row('read_foreign_ids')['words'][1:4],[9001,0,9002])
            for n in ('all_sentinels','same_ids','sentinels_preserve_fsuid','truncated_sentinel','locked_noop'):
                self.assertEqual(after(n),states[names[n]])
            self.assertEqual(row('sentinels_preserve_fsuid')['fsuid_after'],1001)
            self.assertEqual(row('explicit_euid_repairs_fsuid')['fsuid_after'],0)
            # RES fixup follows effective UID, so repairing FSUID alone does not
            # run the filesystem capability raise branch.
            self.assertEqual(row('caps_fs_repair_is_res_fixup')['capabilities_after'][0],INITIAL&~FS)
            for n in ('foreign_uid_denied','foreign_effective_denied','foreign_saved_denied','restore_real_with_permitted','cannot_restore_root_without_effective','locked_foreign_denied','locked_root_denied'):
                self.assertEqual(row(n)['raw_bits'],(1<<64)-1)
                self.assertEqual(after(n),states[names[n]])
            kept=row('drop_all_root_ids_keepcaps')
            self.assertEqual(kept['uids_after'],[1001]*3)
            self.assertEqual(kept['capabilities_after'],[0,INITIAL,INHERIT,(1<<41)-1,0])
            self.assertEqual(kept['securebits_after'],16)
            suppressed=row('drop_all_with_suppression')
            self.assertEqual(suppressed['uids_after'],[9001,9001,9002])
            self.assertEqual(suppressed['capabilities_after'],[INITIAL,INITIAL,INHERIT,(1<<41)-1,1<<32])
            self.assertEqual(row('groups_allowed_suppressed')['groups_after'],[7001,7003])
            self.assertEqual(row('truncated_real_uid')['uids_after'][0],9001)
            self.assertEqual(row('effective_uid_changed')['raw_bits'],1001)
            self.assertEqual(row('selective_root_caps')['capabilities_after'][0],PERMITTED)
            self.assertEqual(row('selective_root_caps')['words'][5:],[0,0,1])
            self.assertEqual(row('locked_drop_without_cap_setuid')['capabilities_after'][0],BOOT)
            self.assertEqual(row('final_securebits')['raw_bits'],12)
            self.assertEqual(states[-1]['uids'][states[-1]['active']],[1001]*3)
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU,pause_ordinals=None))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(82,32,536,444))
            self.assertEqual(len(result['syscalls']),17);self.assertFalse(result['runtime_host_interaction'])
            pause_names=('drop_effective_root','real_to_saved_root','real_to_foreign_privileged','drop_all_root_ids_keepcaps','drop_all_with_suppression','locked_drop_without_cap_setuid')
            self.assertEqual([r['ordinal'] for r in result['saved_state']],[names[n]+1 for n in pause_names])
            for saved in result['saved_state']:
                state=states[saved['ordinal']]
                self.assertEqual(saved['credential_uids'],state['uids'])
                self.assertEqual(saved['credential_capabilities'],state['capabilities'])
                self.assertEqual(saved['credential_securebits'],state['securebits'])
                self.assertEqual(saved['credential_fsuids'],state['fsuid'])
                expected_links=[[1001,0,9001,9002].index(slot[0])+1 for slot in state['uids']]
                self.assertEqual(saved['user_links'],expected_links)
                self.assertEqual(saved['accounting_links'],expected_links)
                self.assertEqual(sum(p['usage'] for p in saved['user_accounting']),1)
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            for field in ('verified_calls','return_value_checks','application_memory_checks'):self.assertEqual(kernel['target_observations'][field],246)
            self.assertEqual(kernel['target_observations']['isolation_checks'],164)
            self.assertEqual(len(kernel['source_identity']['reviewed_source']['definitions']),39)
            functions=kernel['context_plan']['context_functions']+kernel['context_plan']['pure_functions']
            for helper in ('__sys_setresuid','set_user','set_cred_ucounts','flag_nproc_exceeded','cap_emulate_setxuid'):self.assertTrue(any(n.endswith(helper) for n in functions))
            self.assertFalse(kernel['source_identity']['native_source_build_attested'])
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_fixup_permission_and_accounting_mutants_fail_target_proof(self):
        changes=[('return cap_task_fix_setuid(candidate,old,flags);','return 0;'),
                 ('(current_cred()->cap_effective.val&(UINT64_C(1)<<cap))!=0;',
                  '(current_cred()->cap_permitted.val&(UINT64_C(1)<<cap))!=0;'),
                 ('free_uid(current->cred->user);put_ucounts(current->cred->ucounts);','free_uid(current->cred->user);')]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);model=bundle/'models.c';source=model.read_text();self.assertEqual(source.count(original),1);model.write_text(source.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):
                    export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/setresuid/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_original_user_accounting_and_native_uid_observations_are_bound(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(path,needle,mutation,error) in enumerate([
                ('upstream/kernel/sys.c',b'new->uid = kruid;',b'new->uid = old->uid;','reviewed source identity'),
                ('upstream/kernel/cred.c',b'new->ucounts = new_ucounts;',b'new->ucounts = old_ucounts;','user-accounting source identity'),
                ('upstream/security/commoncap.c',b'new->cap_effective = new->cap_permitted;',b'cap_clear(new->cap_effective);','capability source identity')]):
                source=native/path;raw=source.read_bytes();self.assertEqual(raw.count(needle),1);source.write_bytes(raw.replace(needle,mutation))
                output=stage/('bad-source-'+str(i))
                with self.assertRaisesRegex(ValueError,error):build_bundle(native,output)
                self.assertFalse(output.exists());source.write_bytes(raw)
            captured=json.loads((native/'capture.json').read_text());names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().setresuid_plan())}
            captured['calls'][names['foreign_uid_denied']]['uids_after'][0]=9001
            (native/'capture.json').write_text(json.dumps(captured))
            log=(native/'qemu.log').read_text();start=log.index('OSREC_LINUX_CAPTURE ');end=log.index('\n',start)
            log=log[:start]+'OSREC_LINUX_CAPTURE '+json.dumps({k:v for k,v in captured.items() if k!='format'})+log[end:];(native/'qemu.log').write_text(log)
            manifest=json.loads((native/'capture.manifest.json').read_text());manifest['capture_sha256']=digest((native/'capture.json').read_bytes());manifest['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'state transitions differ'):build_bundle(native,stage/'bad-observation')
            self.assertFalse((stage/'bad-observation').exists())

if __name__=='__main__':unittest.main()
