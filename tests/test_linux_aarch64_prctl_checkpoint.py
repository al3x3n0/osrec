"""Original Linux capability-prctl paths preserve live state across resumes."""
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
from prepare_linux_aarch64_port import build_bundle
from run_linux_aarch64_checkpoint_pipeline import run,verify_pipeline
from export_syscall_slices import export

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-prctl-native'
BOOT=1<<22;GID=1<<6;PCAP=1<<8;ALL=BOOT|GID|PCAP
EPERM=(1<<64)-1;EINVAL=(1<<64)-22

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxPrctlTests(unittest.TestCase):
    def test_bounding_ambient_securebits_and_later_calls_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-prctl-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');review=reviewed_adapter()
            captured,manifest=review.validate_capture(native);calls=captured['calls'];_,states=review.projection(captured)
            names={n:i for i,(n,_,_) in enumerate(review.prctl_plan(review.recipes('minimal')))}
            row=lambda n:calls[names[n]]
            after=lambda n:states[names[n]+1]
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(len(calls),92)
            self.assertTrue(all(len(c['args'])==5 for c in calls))
            self.assertEqual(row('bounding_initial')['raw_bits'],1)
            self.assertEqual(row('bounding_gid_dropped')['raw_bits'],0)
            self.assertEqual(row('drop_gid')['capabilities_after'][:3],[ALL,ALL,GID])
            self.assertEqual(row('drop_gid')['capabilities_after'][3:],[(1<<41)-1-GID,GID])
            self.assertEqual(row('groups_after_bounding_drop')['groups_after'],[6001,6003])
            self.assertEqual(row('ambient_after_bounding_drop')['raw_bits'],1)
            self.assertEqual(row('remove_inheritable_gid')['capabilities_after'][4],0)
            for n in ('raise_without_inheritable','raise_gid_after_inheritable_drop','cannot_restore_inheritable_gid','cannot_add_inheritable_uid',
                      'drop_without_effective_setpcap','drop_invalid_unprivileged','securebits_without_setpcap','securebits_reject_raise',
                      'unlock_rejected','change_locked_rejected','unsupported_securebits','locked_keepcaps_rejected',
                      'cannot_regain_permitted_setpcap','bounding_drop_after_permitted_drop','locked_raise_after_permitted_drop'):
                self.assertEqual(row(n)['raw_bits'],EPERM,n)
                self.assertEqual(after(n)['active'],states[names[n]]['active'],n)
                self.assertEqual(after(n)['generation'],states[names[n]]['generation'],n)
            for n in ('bounding_invalid','bounding_unsigned','drop_invalid_privileged','ambient_unknown','ambient_invalid_cap',
                      'ambient_arg4','ambient_arg5','clear_arg3','clear_arg4','clear_arg5','keepcaps_invalid','locked_keepcaps_invalid'):
                self.assertEqual(row(n)['raw_bits'],EINVAL,n)
                self.assertEqual(after(n),states[names[n]],n)
            self.assertEqual(row('ambient_arg4')['args'][3:], [1,0]);self.assertEqual(row('ambient_arg5')['args'][3:],[0,1])
            self.assertEqual(row('raise_gid')['capabilities_after'][4],GID)
            self.assertEqual(row('raise_setpcap')['capabilities_after'][4],PCAP)
            self.assertEqual(row('forbid_ambient_raise')['capabilities_after'][4],PCAP)
            self.assertEqual(row('forbid_ambient_raise')['securebits_after'],64)
            self.assertEqual(row('clear_all')['capabilities_after'][4],0)
            self.assertEqual(after('clear_all_again')['generation'],after('clear_all')['generation']+1)
            self.assertEqual(after('lower_gid_again')['generation'],after('ambient_gid_clear')['generation']+1)
            self.assertEqual(row('securebits_keepcaps')['raw_bits'],16)
            self.assertEqual(row('locked_securebits_read')['raw_bits'],240)
            self.assertEqual(row('locked_keepcaps_read')['raw_bits'],1)
            self.assertEqual(row('caps_after_permitted_drop')['words'][2:5],[BOOT|GID,BOOT|GID,PCAP])
            self.assertEqual(row('empty_groups')['groups_after'],[])
            self.assertEqual(states[-1]['generation'],26)
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU,pause_ordinals=None))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(92,32,392,340))
            self.assertEqual(len(result['syscalls']),15);self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual([r['ordinal'] for r in result['saved_state']],[28,43,50,75,83,88])
            self.assertEqual([r['generation'] for r in result['saved_state']],[2,7,9,24,25,26])
            for row in result['saved_state']:
                state=states[row['ordinal']]
                self.assertEqual(row['credential_capabilities'],state['capabilities'])
                self.assertEqual(row['credential_securebits'],state['securebits'])
                self.assertEqual(row['group_pool'],state['group_pool'])
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            for field in ('verified_calls','return_value_checks','application_memory_checks'):self.assertEqual(kernel['target_observations'][field],276)
            self.assertEqual(kernel['target_observations']['isolation_checks'],184)
            self.assertEqual(len(kernel['source_identity']['reviewed_source']['definitions']),27)
            self.assertTrue(any(n.endswith('cap_task_prctl') for n in kernel['context_plan']['context_functions']))
            self.assertTrue(any(n.endswith('cap_prctl_drop') for n in kernel['context_plan']['context_functions']))
            self.assertFalse(kernel['source_identity']['native_source_build_attested'])
            self.assertEqual(next(r['function'] for r in kernel['port']['roots'] if r['number']==167),'cap_task_prctl')
            self.assertTrue(any('general sys_prctl wrapper is not exported' in s for s in kernel['source_identity']['modeled_dependencies']))
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_permitted_permission_or_lost_securebits_fails_target_proof(self):
        changes=[('return cap_capable(current_cred(),ns,cap,CAP_OPT_NONE)==0;',
                  'return ns->initial && cap>=0 && cap<=40 && (current_cred()->cap_permitted.val&(UINT64_C(1)<<cap));'),
                 ('*candidate=*current->cred;','*candidate=*current->cred;candidate->securebits=0;')]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);model=bundle/'models.c';source=model.read_text();self.assertEqual(source.count(original),1);model.write_text(source.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaisesRegex(ValueError,'target replay diverged'):
                    export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/prctl/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_original_hook_dispatch_abi_and_native_state_are_bound(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for path,needle,mutation,error in [
                ('upstream/security/commoncap.c',b'cap_lower(new->cap_bset, cap);',b'cap_clear(new->cap_bset);','capability source identity'),
                ('upstream/kernel/prctl-dispatch-prefix.txt',b'error != -ENOSYS',b'error == -ENOSYS','dispatch evidence'),
                ('upstream/include/uapi/linux/securebits.h',b'SECURE_KEEP_CAPS_LOCKED 5',b'SECURE_KEEP_CAPS_LOCKED 7','prctl ABI identity')]:
                source=native/path;raw=source.read_bytes();self.assertEqual(raw.count(needle),1);source.write_bytes(raw.replace(needle,mutation))
                with self.assertRaisesRegex(ValueError,error):build_bundle(native,stage/('bad-source-'+source.name))
                self.assertFalse((stage/('bad-source-'+source.name)).exists());source.write_bytes(raw)
            captured=json.loads((native/'capture.json').read_text());captured['calls'][74]['securebits_after']=0
            (native/'capture.json').write_text(json.dumps(captured))
            log=(native/'qemu.log').read_text();start=log.index('OSREC_LINUX_CAPTURE ');end=log.index('\n',start)
            log=log[:start]+'OSREC_LINUX_CAPTURE '+json.dumps({k:v for k,v in captured.items() if k!='format'})+log[end:];(native/'qemu.log').write_text(log)
            manifest=json.loads((native/'capture.manifest.json').read_text());manifest['capture_sha256']=digest((native/'capture.json').read_bytes());manifest['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'state transitions differ'):build_bundle(native,stage/'bad-observation')
            self.assertFalse((stage/'bad-observation').exists())

if __name__=='__main__':unittest.main()
