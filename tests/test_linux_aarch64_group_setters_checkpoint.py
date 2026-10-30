"""Linux saved-GID rules and partially changed candidates survive slice resumes."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-group-setters-native'

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxGroupSetterTests(unittest.TestCase):
    def test_saved_ids_partial_abort_and_unchanged_publication_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-group-setters-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');review=reviewed_adapter()
            captured,manifest=review.validate_capture(native);_,states=review.projection(captured);calls=captured['calls']
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(captured['profile'],'group-setters')
            self.assertEqual(calls[62]['gids_after'],[2003,2001,2001])
            for i in (64,66,73,79,87):
                self.assertEqual(calls[i]['raw_bits'],(1<<64)-1)
                for field in ('active','generation','epochs','gids','fsgid'):
                    self.assertEqual(states[i][field],states[i+1][field])
            for i in (65,85):
                self.assertEqual(calls[i]['raw_bits'],(1<<64)-22);self.assertEqual(states[i],states[i+1])
            # The real-ID update is allowed, then the effective-ID check fails.
            # Only the inactive candidate changes; native active IDs stay intact.
            self.assertEqual(states[67]['pool'],[[2001,2001,2001,2001],[2003,2001,2001,2001]])
            self.assertEqual(calls[67]['raw_bits'],2003)
            for i in (68,71,77,84):
                self.assertEqual(calls[i]['raw_bits'],0)
                self.assertEqual(states[i]['gids'],states[i+1]['gids'])
                self.assertEqual(states[i+1]['generation'],states[i]['generation']+1)
                self.assertNotEqual(states[i]['active'],states[i+1]['active'])
            # Specified real ID replaces saved ID; effective=old real preserves it.
            self.assertEqual((calls[69]['args'][0],calls[69]['gids_after']),(0x1000007d1,[2001,2003,2003]))
            self.assertEqual(calls[72]['gids_after'],[2001,2001,2003])
            # Effective-only GID is insufficient for unprivileged setgid.
            self.assertEqual(calls[78]['gids_after'],[2001,2003,2001])
            self.assertEqual(calls[79]['gids_after'],[2001,2003,2001])
            self.assertEqual(calls[80]['gids_after'],[2001,2003,2003])
            self.assertEqual(calls[70]['raw_bits'],(1<<64)-14)
            self.assertEqual(calls[70]['words'][1:4],[2001,0xa5a50002,0xa5a50003])
            self.assertEqual(calls[82]['args'][0],0x1000007d1)
            self.assertEqual(calls[86]['gids_after'],[2001]*3)
            self.assertEqual(calls[88]['fsgid_after'],2001)
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU,pause_ordinals=None))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(94,32,216,184))
            rows=result['saved_state']
            self.assertEqual([(r['ordinal'],r['credential_id'],r['generation']) for r in rows],[(63,2,13),(67,2,13),(70,2,15),(80,1,22),(87,2,27),(93,2,27)])
            self.assertEqual(rows[1]['credential_pool'],[[2001,2001,2001,2001],[2003,2001,2001,2001]])
            self.assertEqual(rows[1]['slot_generations'],[12,13])
            self.assertEqual(rows[3]['gids'],[2001,2003,2001])
            self.assertEqual(rows[4]['credential_pool'],[[2001,2001,2003,2001],[2001,2001,2001,2001]])
            self.assertEqual(rows[5]['credential_pool'],[[2001,2001,2001,2001]]*2)
            self.assertEqual(len(result['syscalls']),14);self.assertFalse(result['runtime_host_interaction'])
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            for field in ('verified_calls','return_value_checks','application_memory_checks'):
                self.assertEqual(kernel['target_observations'][field],282)
            self.assertEqual(kernel['target_observations']['isolation_checks'],188)
            for name in ('__sys_setgid','__sys_setregid'):self.assertIn(name,kernel['context_plan']['context_functions'])
            self.assertFalse(kernel['source_identity']['native_source_build_attested'])
            shutil.rmtree(native)
            self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_publishing_failed_candidate_or_rejecting_admitted_hooks_fails_proof(self):
        original='void abort_creds(struct cred *candidate){if(candidate==pending_credential)pending_credential=0;}'
        mutation='void abort_creds(struct cred *candidate){if(candidate==pending_credential){if(candidate->gid!=current->cred->gid)current->cred=candidate;pending_credential=0;}}'
        changes=[(original,mutation),(' || flags==LSM_SETID_ID',''),(' || flags==LSM_SETID_RE)',' )')]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);model=bundle/'models.c';source=model.read_text();self.assertEqual(source.count(original),1);model.write_text(source.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaises(ValueError):
                    export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/group-setters/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_saved_id_helper_tampering_and_false_active_state_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            source=native/'upstream/kernel/sys.c';raw=source.read_bytes()
            self.assertEqual(raw.count(b'new->sgid = new->egid;'),1)
            source.write_bytes(raw.replace(b'new->sgid = new->egid;',b'new->sgid = old->sgid;'))
            with self.assertRaises(ValueError):build_bundle(native,stage/'bad-helper')
            self.assertFalse((stage/'bad-helper').exists());source.write_bytes(raw)
            captured=json.loads((native/'capture.json').read_text());captured['calls'][66]['gids_after'][0]=2001
            (native/'capture.json').write_text(json.dumps(captured))
            log=(native/'qemu.log').read_text();start=log.index('OSREC_LINUX_CAPTURE ');end=log.index('\n',start)
            log=log[:start]+'OSREC_LINUX_CAPTURE '+json.dumps({k:v for k,v in captured.items() if k!='format'})+log[end:];(native/'qemu.log').write_text(log)
            manifest=json.loads((native/'capture.manifest.json').read_text());manifest['capture_sha256']=digest((native/'capture.json').read_bytes());manifest['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'state transitions differ'):build_bundle(native,stage/'bad-observation')
            self.assertFalse((stage/'bad-observation').exists())

if __name__=='__main__':unittest.main()
