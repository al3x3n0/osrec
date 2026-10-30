"""Original setfsuid and commoncap fixups survive fresh-image restoration."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-fsuid-native'
BOOT=1<<22;GID=1<<6;PCAP=1<<8;UID=1<<7;BASE=BOOT|GID|PCAP
FS=sum(1<<n for n in (0,1,2,3,4,9,27,32));INITIAL=BASE|UID|FS
INHERIT=(1<<0)|(1<<32);PERMITTED=INITIAL&~INHERIT

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxFsuidTests(unittest.TestCase):
    def test_generated_witness_is_bound_to_recipe_and_argument_kinds(self):
        source=generate('fsuid')
        self.assertEqual(source,(ROOT/'integrations/linux_aarch64/fsuid/application.c').read_text())
        self.assertEqual(source,(FIXTURE/'sources/application.c').read_text())
        review=reviewed_adapter();port=json.loads((ROOT/'integrations/linux_aarch64/fsuid/port-template.json').read_text())
        # Removing an input route must prevent witness construction.
        port['roots']=[r for r in port['roots'] if r['number']!=151]
        with self.assertRaisesRegex(ValueError,'no reviewed route'):review.application_source('fsuid',port)

    def test_fsuid_capability_fixup_suppression_and_later_calls_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-fsuid-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');review=reviewed_adapter()
            captured,manifest=review.validate_capture(native);calls=captured['calls'];_,states=review.projection(captured)
            names={n:i for i,(n,_,_) in enumerate(review.fsuid_plan())}
            row=lambda n:calls[names[n]]
            after=lambda n:states[names[n]+1]
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(len(calls),84)
            self.assertEqual(captured['initial']['capabilities'][:3],[INITIAL,INITIAL,0])
            self.assertEqual(row('drop_fs_caps')['fsuid_after'],1001)
            self.assertEqual(row('drop_fs_caps')['capabilities_after'][:3],[BASE|UID,INITIAL,0])
            self.assertEqual(row('restore_fs_caps')['capabilities_after'][0],INITIAL)
            self.assertEqual(row('privileged_foreign_uid')['fsuid_after'],9001)
            self.assertEqual(row('restore_from_foreign')['raw_bits'],9001)
            self.assertEqual(row('real_uid_unchanged')['raw_bits'],1001)
            self.assertEqual(row('effective_uid_unchanged')['raw_bits'],0)
            self.assertTrue(all(c['gids_after']==[2001,2002,2003] for c in calls))
            self.assertEqual(row('initial_caps')['words'][5:],[1,1,0])
            self.assertEqual(row('caps_dropped')['words'][5:],[0,1,0])
            self.assertEqual(row('caps_with_ambient')['words'][5:],[0,1,1])
            self.assertEqual(row('drop_with_ambient')['capabilities_after'][4],INHERIT)
            self.assertEqual(row('restore_without_setuid')['capabilities_after'][0],INITIAL&~UID)
            for n in ('foreign_uid_denied','denied_with_fixup_suppressed','foreign_denied_without_effective'):
                self.assertEqual(row(n)['raw_bits'],1001)
                self.assertEqual(row(n)['fsuid_after'],1001)
                self.assertEqual(after(n)['active'],states[names[n]]['active'])
                self.assertEqual(after(n)['generation'],states[names[n]]['generation'])
                self.assertEqual(after(n)['fsuid'][1-after(n)['active']],1001)
            for n in ('initial_probe','invalid_probe','truncated_invalid','final_probe'):
                self.assertEqual(after(n),states[names[n]])
            self.assertEqual(row('suppressed_drop')['fsuid_after'],1001)
            self.assertEqual(row('suppressed_drop')['capabilities_after'][0],INITIAL&~UID)
            self.assertEqual(row('suppressed_drop')['securebits_after'],4)
            self.assertEqual(row('drop_after_enabling')['capabilities_after'][0],BASE)
            self.assertEqual(row('remove_permitted_fs_bits')['capabilities_after'][4],0)
            self.assertEqual(row('restore_remaining_permitted')['capabilities_after'][0],PERMITTED&~UID)
            self.assertEqual(row('bounded_restore')['words'][5:],[0,0,1])
            self.assertEqual(row('cannot_regain_permitted')['raw_bits'],(1<<64)-1)
            self.assertEqual(row('truncated_nonroot')['fsuid_after'],1001)
            self.assertEqual(row('truncated_root')['fsuid_after'],0)
            self.assertEqual(row('replace_groups')['groups_after'],[6001,6003,6007])
            self.assertEqual(row('selective_effective_regain')['capabilities_after'][0],BOOT|PCAP|(PERMITTED&FS))
            for n in ('groups_denied_nonroot','groups_still_denied_root','groups_denied_final'):
                self.assertEqual(row(n)['raw_bits'],(1<<64)-1)
                self.assertEqual(row(n)['groups_after'],[6001,6003,6007])
            self.assertEqual(row('unlock_fixup_denied')['raw_bits'],(1<<64)-1)
            self.assertEqual(row('locked_restore_after_capset')['capabilities_after'][0],BOOT)
            self.assertEqual(row('final_securebits')['raw_bits'],12)
            self.assertEqual(states[-1]['generation'],29)
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU,pause_ordinals=None))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(84,32,392,340))
            self.assertEqual(len(result['syscalls']),16);self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual([r['ordinal'] for r in result['saved_state']],[35,37,44,52,66,71])
            self.assertEqual([r['generation'] for r in result['saved_state']],[8,8,12,17,24,28])
            self.assertEqual([r['fsuid'] for r in result['saved_state']],[1001,1001,1001,0,0,1001])
            for saved in result['saved_state']:
                state=states[saved['ordinal']]
                self.assertEqual(saved['credential_capabilities'],state['capabilities'])
                self.assertEqual(saved['credential_securebits'],state['securebits'])
                self.assertEqual(saved['credential_fsuids'],state['fsuid'])
                self.assertEqual(saved['group_pool'],state['group_pool'])
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            for field in ('verified_calls','return_value_checks','application_memory_checks'):self.assertEqual(kernel['target_observations'][field],252)
            self.assertEqual(kernel['target_observations']['isolation_checks'],168)
            self.assertEqual(len(kernel['source_identity']['reviewed_source']['definitions']),34)
            for helper in ('__sys_setfsuid','cap_task_fix_setuid','cap_emulate_setxuid','cap_drop_fs_set','cap_raise_fs_set'):
                self.assertTrue(any(n.endswith(helper) for n in kernel['context_plan']['context_functions']+kernel['context_plan']['pure_functions']))
            self.assertFalse(kernel['source_identity']['native_source_build_attested'])
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_skipped_fixup_or_permitted_authorization_fails_target_proof(self):
        changes=[('return cap_task_fix_setuid(candidate,old,flags);','return 0;'),
                 ('(current_cred()->cap_effective.val&(UINT64_C(1)<<cap))!=0;',
                  '(current_cred()->cap_permitted.val&(UINT64_C(1)<<cap))!=0;')]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);model=bundle/'models.c';source=model.read_text();self.assertEqual(source.count(original),1);model.write_text(source.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):
                    export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/fsuid/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_original_fsuid_helper_fs_mask_and_native_state_are_bound(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for path,needle,mutation,error in [
                ('upstream/kernel/sys.c',b'new->fsuid = kuid;',b'new->fsuid = old->fsuid;','reviewed source identity'),
                ('upstream/include/linux/capability.h',b'BIT_ULL(CAP_MAC_OVERRIDE)',b'BIT_ULL(CAP_SETUID)','filesystem-capability source identity'),
                ('upstream/security/commoncap.c',b'cap_drop_fs_set(new->cap_effective)',b'new->cap_effective','capability source identity')]:
                source=native/path;raw=source.read_bytes();self.assertEqual(raw.count(needle),1);source.write_bytes(raw.replace(needle,mutation))
                with self.assertRaisesRegex(ValueError,error):build_bundle(native,stage/('bad-source-'+str(len(path))))
                self.assertFalse((stage/('bad-source-'+str(len(path)))).exists());source.write_bytes(raw)
            captured=json.loads((native/'capture.json').read_text());captured['calls'][36]['fsuid_after']=9001
            (native/'capture.json').write_text(json.dumps(captured))
            log=(native/'qemu.log').read_text();start=log.index('OSREC_LINUX_CAPTURE ');end=log.index('\n',start)
            log=log[:start]+'OSREC_LINUX_CAPTURE '+json.dumps({k:v for k,v in captured.items() if k!='format'})+log[end:];(native/'qemu.log').write_text(log)
            manifest=json.loads((native/'capture.manifest.json').read_text());manifest['capture_sha256']=digest((native/'capture.json').read_bytes());manifest['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'state transitions differ'):build_bundle(native,stage/'bad-observation')
            self.assertFalse((stage/'bad-observation').exists())

if __name__=='__main__':unittest.main()
