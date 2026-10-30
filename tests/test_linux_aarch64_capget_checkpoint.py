"""Application capget snapshots live capabilities through checkpoint resumes."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-capget-native'
BOOT=1<<22;GID=1<<6

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxCapgetTests(unittest.TestCase):
    def test_live_queries_null_version_order_and_partial_output_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-capget-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');review=reviewed_adapter()
            captured,manifest=review.validate_capture(native);calls=captured['calls'];_,states=review.projection(captured)
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(len(calls),85)
            query_indices=[i for i,c in enumerate(calls) if c['number']==90];self.assertEqual(len(query_indices),21)
            for i in query_indices:self.assertEqual(states[i+1],states[i])
            self.assertEqual(calls[20]['words'][2:],[BOOT|GID,BOOT|GID,0,0,0,0])
            self.assertEqual(calls[24]['words'][2:],[BOOT,BOOT|GID,0,0,0,0])
            self.assertEqual(calls[28]['input_words'][:2],[0x20071026,1]);self.assertEqual(calls[28]['words'][2:],[BOOT|GID,BOOT|GID,0,0,0,0])
            self.assertEqual(calls[33]['input_words'][0],0x19980330);self.assertEqual(calls[33]['words'][2:5],[BOOT|GID,BOOT|GID,0])
            self.assertEqual(calls[33]['words'][5:],calls[33]['input_words'][5:])
            # Unsupported versions are rewritten; NULL output changes EINVAL
            # to success, without accessing PID or querying a task.
            self.assertEqual(calls[36]['raw_bits'],0);self.assertEqual(calls[36]['words'][0],0x20080522)
            self.assertEqual(calls[37]['raw_bits'],(1<<64)-22);self.assertEqual(calls[37]['words'][0],0x20080522)
            for i in (38,39):self.assertEqual(calls[i]['raw_bits'],0);self.assertEqual(calls[i]['words'],calls[i]['input_words'])
            self.assertEqual(calls[38]['input_words'][1],0xffffffff);self.assertEqual(calls[39]['args'][:2],[28,(1<<64)-1])
            self.assertEqual(calls[50]['raw_bits'],(1<<64)-22)
            self.assertEqual(calls[51]['input_words'][1],0x7fffffff);self.assertEqual(calls[51]['raw_bits'],(1<<64)-3)
            for i in (40,52,53,54,55,56):self.assertEqual(calls[i]['raw_bits'],(1<<64)-14)
            self.assertEqual(calls[53]['words'][:6],calls[53]['input_words'][:6]);self.assertEqual(calls[53]['words'][6:],[BOOT,BOOT|GID])
            self.assertEqual(calls[58]['words'][2:5],[BOOT|GID,BOOT|GID,GID])
            self.assertEqual(calls[61]['args'][:2],[0,0]);self.assertEqual(calls[61]['words'][:6],[BOOT|GID,BOOT|GID,GID,0,0,0])
            self.assertEqual(calls[71]['words'][2:5],[BOOT,BOOT,GID]);self.assertEqual(calls[78]['words'][2:5],[BOOT,BOOT,0])
            self.assertEqual(states[-1]['generation'],16)
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU,pause_ordinals=None))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(85,32,376,332))
            self.assertEqual(len(result['syscalls']),14);self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual([r['ordinal'] for r in result['saved_state']],[24,28,54,61,71,78])
            self.assertEqual([r['generation'] for r in result['saved_state']],[2,3,7,9,14,16])
            for row in result['saved_state']:
                state=states[row['ordinal']];self.assertEqual(row['credential_capabilities'],state['capabilities']);self.assertEqual(row['group_pool'],state['group_pool'])
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            for field in ('verified_calls','return_value_checks','application_memory_checks'):self.assertEqual(kernel['target_observations'][field],255)
            self.assertEqual(kernel['target_observations']['isolation_checks'],170)
            self.assertEqual(len(kernel['source_identity']['reviewed_source']['definitions']),25)
            for helper in ('cap_get_target_pid','cap_capget','linux_copy_to_user'):
                self.assertTrue(any(n.endswith(helper) for n in kernel['context_plan']['context_functions']))
            self.assertFalse(kernel['source_identity']['native_source_build_attested'])
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_wrong_effective_snapshot_or_omitted_output_fails_target_proof(self):
        changes=[('return cap_capget(target,e,i,p);','int ret=cap_capget(target,e,i,p);*e=current_cred()->cap_permitted;return ret;'),
                 ('*destination=source[j];','(void)source;')]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);model=bundle/'models.c';source=model.read_text();self.assertEqual(source.count(original),1);model.write_text(source.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaises(ValueError):
                    export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/capget/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_original_getter_and_native_query_bytes_are_bound(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            source=native/'upstream/security/commoncap.c';raw=source.read_bytes()
            self.assertEqual(raw.count(b'*effective   = cred->cap_effective;'),1)
            source.write_bytes(raw.replace(b'*effective   = cred->cap_effective;',b'*effective   = cred->cap_permitted;'))
            with self.assertRaisesRegex(ValueError,'capability source identity'):build_bundle(native,stage/'bad-source')
            self.assertFalse((stage/'bad-source').exists());source.write_bytes(raw)
            captured=json.loads((native/'capture.json').read_text());captured['calls'][24]['words'][2]=BOOT|GID
            (native/'capture.json').write_text(json.dumps(captured))
            log=(native/'qemu.log').read_text();start=log.index('OSREC_LINUX_CAPTURE ');end=log.index('\n',start)
            log=log[:start]+'OSREC_LINUX_CAPTURE '+json.dumps({k:v for k,v in captured.items() if k!='format'})+log[end:];(native/'qemu.log').write_text(log)
            manifest=json.loads((native/'capture.manifest.json').read_text());manifest['capture_sha256']=digest((native/'capture.json').read_bytes());manifest['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'state transitions differ'):build_bundle(native,stage/'bad-observation')
            self.assertFalse((stage/'bad-observation').exists())

if __name__=='__main__':unittest.main()
