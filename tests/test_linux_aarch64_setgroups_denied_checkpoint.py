"""Original Linux setgroups permission rejection preserves the sequential session."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-setgroups-denied-native'

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxSetgroupsDeniedTests(unittest.TestCase):
    def test_permission_precedence_unchanged_pools_and_later_calls_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-setgroups-denied-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');review=reviewed_adapter()
            captured,manifest=review.validate_capture(native);calls=captured['calls'];_,states=review.projection(captured)
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(captured['initial']['uids'],[1001,1002,0])
            self.assertEqual(captured['initial']['cap_setgid'],0);self.assertTrue(all(c['cap_setgid_after']==0 for c in calls))
            denied=[i for i,c in enumerate(calls) if c['number']==159];self.assertEqual(len(denied),21)
            for i in denied:
                self.assertEqual(calls[i]['raw_bits'],(1<<64)-1)
                self.assertEqual(calls[i]['words'],calls[i]['input_words']);self.assertEqual(states[i+1],states[i])
            # Permission denial precedes invalid size, invalid ID, NULL,
            # guarded input reads and even allocations beyond model capacity.
            for i in (30,32,34,35,36,39,44,45,46,50,56,57,58):self.assertIn(i,denied)
            self.assertEqual(calls[56]['args'][0],5);self.assertEqual(calls[57]['args'][0],65536)
            self.assertEqual(calls[58]['args'][0],0x80000000)
            self.assertTrue(all(s==states[0] for s in states))
            self.assertTrue(all(c['groups_after']==[4001,4003,4007] for c in calls))
            self.assertEqual(calls[37]['raw_bits'],(1<<64)-14) # A denied clear left a nonempty list.
            self.assertEqual(calls[41]['raw_bits'],(1<<64)-22) # A denied one-ID replacement left length three.
            self.assertEqual(calls[29]['words'][6:],[4001,4003]);self.assertEqual(calls[29]['raw_bits'],(1<<64)-14)
            self.assertEqual(calls[53]['words'][1:4],[4001,4003,4007]);self.assertEqual(calls[59]['raw_bits'],3)
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU,pause_ordinals=None))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(60,32,312,260))
            self.assertEqual(len(result['syscalls']),12);self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual([r['ordinal'] for r in result['saved_state']],[22,31,35,40,53,59])
            self.assertEqual([r['umask'] for r in result['saved_state']],[18,18,18,18,63,18])
            for row in result['saved_state']:
                self.assertEqual((row['cap_setgid'],row['credential_cap_setgid']),(0,[0,0]))
                self.assertEqual((row['credential_id'],row['generation'],row['slot_generations']),(1,0,[0,0]))
                self.assertEqual(row['credential_group_ids'],[1,1]);self.assertEqual(row['group_pool'],states[0]['group_pool'])
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            for field in ('verified_calls','return_value_checks','application_memory_checks'):self.assertEqual(kernel['target_observations'][field],180)
            self.assertEqual(kernel['target_observations']['isolation_checks'],120)
            caps=[f for f in kernel['checkpoint_codec']['fields'] if f['path'].endswith('.cap_setgid')]
            self.assertEqual(len(caps),2);self.assertTrue(all(f['policy']=='persist' and f['bytes']==4 for f in caps))
            self.assertIn('capability_abi_sha256',kernel['source_identity']['reviewed_source'])
            self.assertFalse(kernel['source_identity']['native_source_build_attested'])
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_false_capability_or_side_effect_on_denial_fails_target_proof(self):
        original='return ns->initial && cap==CAP_SETGID && current_cred()->cap_setgid!=0;'
        mutations=['return ns->initial && cap==CAP_SETGID;','++credential_generation;'+original]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,mutation in enumerate(mutations):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);model=bundle/'models.c';source=model.read_text();self.assertEqual(source.count(original),1);model.write_text(source.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaises(ValueError):
                    export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/setgroups-denied/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_capability_abi_and_native_capability_observations_are_bound(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            source=native/'upstream/include/uapi/linux/capability.h';raw=source.read_bytes()
            source.write_bytes(raw.replace(b'0x20080522',b'0x19980330'))
            with self.assertRaisesRegex(ValueError,'capability observation ABI'):build_bundle(native,stage/'bad-abi')
            self.assertFalse((stage/'bad-abi').exists());source.write_bytes(raw)
            captured=json.loads((native/'capture.json').read_text());captured['calls'][30]['cap_setgid_after']=1
            (native/'capture.json').write_text(json.dumps(captured))
            log=(native/'qemu.log').read_text();start=log.index('OSREC_LINUX_CAPTURE ');end=log.index('\n',start)
            log=log[:start]+'OSREC_LINUX_CAPTURE '+json.dumps({k:v for k,v in captured.items() if k!='format'})+log[end:];(native/'qemu.log').write_text(log)
            manifest=json.loads((native/'capture.manifest.json').read_text());manifest['capture_sha256']=digest((native/'capture.json').read_bytes());manifest['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'state transitions differ'):build_bundle(native,stage/'bad-observation')
            self.assertFalse((stage/'bad-observation').exists())

if __name__=='__main__':unittest.main()
