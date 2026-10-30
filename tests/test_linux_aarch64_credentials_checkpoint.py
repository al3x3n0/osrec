"""Native Linux credential transitions survive portable gateway checkpoints."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-credentials-native'

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxCredentialsTests(unittest.TestCase):
    def test_native_changes_and_dynamic_credential_links_resume_in_fresh_images(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-creds-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');review=reviewed_adapter()
            captured,manifest=review.validate_capture(native);_,states=review.projection(captured)
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(captured['profile'],'credentials')
            # Native EPERM and all-unchanged requests retain state; changing to
            # an old saved ID drops the formerly effective ID from the set.
            for i in (20,28):
                self.assertEqual(captured['calls'][i]['raw_bits'],(1<<64)-1)
                self.assertEqual(states[i+1],states[i])
            for i in (21,36):
                self.assertEqual(captured['calls'][i]['raw_bits'],0)
                self.assertEqual(states[i+1],states[i])
            self.assertEqual(captured['calls'][25]['args'][0],0x1000007d3)
            self.assertEqual(captured['calls'][25]['gids_after'],[2003,2003,2001])
            self.assertEqual(captured['calls'][33]['raw_bits'],(1<<64)-14)
            self.assertEqual(captured['calls'][33]['words'][1:4],[2001,2003,0xa5a50003])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU,pause_ordinals=None))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(42,28,216,184))
            self.assertEqual([(s['ordinal'],s['credential_id'],s['generation']) for s in result['saved_state']],[(8,1,0),(23,2,1),(26,1,2),(35,2,5),(41,2,5)])
            self.assertEqual(result['saved_state'][2]['gids'],[2003,2003,2001])
            self.assertEqual(result['saved_state'][3]['slot_generations'],[4,5])
            self.assertEqual(result['saved_state'][3]['credential_pool'],[[2001,2003,2003,2003],[2001,2001,2003,2001]])
            self.assertEqual(len(result['syscalls']),11);self.assertFalse(result['runtime_host_interaction'])
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            observations=kernel['target_observations']
            for field in ('verified_calls','return_value_checks','application_memory_checks'):
                self.assertEqual(observations[field],126)
            self.assertEqual(observations['isolation_checks'],84)
            self.assertIn('__sys_setresgid',kernel['context_plan']['context_functions'])
            link=next(f for f in kernel['checkpoint_codec']['fields'] if f['path']=='task.cred')
            self.assertEqual(link['policy'],'context_reference');self.assertFalse(link['nullable'])
            self.assertFalse(kernel['source_identity']['native_source_build_attested'])
            shutil.rmtree(native)
            self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_omitting_clone_publication_or_generation_fails_target_proof(self):
        changes=[('*candidate=*current->cred;pending_credential=candidate;','pending_credential=candidate;'),
                 ('current->cred=candidate;++credential_generation;','++credential_generation;'),
                 ('++credential_generation;','credential_generation+=2;')]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle)
                model=bundle/'models.c';source=model.read_text();self.assertEqual(source.count(original),1)
                model.write_text(source.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaises(ValueError):
                    export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/credentials/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_original_helper_and_native_state_observations_are_bound(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            with self.assertRaisesRegex(ValueError,'profile differs'):
                run(SimpleNamespace(capture=native,out=stage/'bad-profile',profile='minimal'))
            self.assertFalse((stage/'bad-profile').exists())
            source=native/'upstream/kernel/sys.c';raw=source.read_bytes()
            self.assertEqual(raw.count(b'new->fsgid = new->egid;'),1)
            source.write_bytes(raw.replace(b'new->fsgid = new->egid;',b'new->fsgid = new->gid;'))
            with self.assertRaises(ValueError):build_bundle(native,stage/'bad-helper')
            self.assertFalse((stage/'bad-helper').exists());source.write_bytes(raw)
            # Re-pin both JSON and UART evidence to ensure the independent
            # transition decoder also checks observed credential state.
            captured=json.loads((native/'capture.json').read_text());captured['calls'][22]['fsgid_after']=2002
            (native/'capture.json').write_text(json.dumps(captured))
            log=(native/'qemu.log').read_text()
            start=log.index('OSREC_LINUX_CAPTURE ');end=log.index('\n',start)
            log=log[:start]+'OSREC_LINUX_CAPTURE '+json.dumps({k:v for k,v in captured.items() if k!='format'})+log[end:]
            (native/'qemu.log').write_text(log)
            manifest=json.loads((native/'capture.manifest.json').read_text())
            manifest['capture_sha256']=digest((native/'capture.json').read_bytes());manifest['qemu_log_sha256']=digest((native/'qemu.log').read_bytes())
            (native/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'state transitions differ'):build_bundle(native,stage/'bad-observation')
            self.assertFalse((stage/'bad-observation').exists())

if __name__=='__main__':unittest.main()
