"""Filesystem-group changes and aborted credentials survive Linux slice resume."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-fsgid-native'

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxFilesystemGroupTests(unittest.TestCase):
    def test_old_return_values_abort_state_and_fresh_image_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-fsgid-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');review=reviewed_adapter()
            captured,manifest=review.validate_capture(native);_,states=review.projection(captured)
            calls=captured['calls']
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(captured['profile'],'fsgid')
            self.assertEqual((calls[42]['raw_bits'],calls[42]['fsgid_after']),(2001,2003))
            self.assertEqual((calls[45]['raw_bits'],calls[45]['fsgid_after']),(2003,2003))
            # Permission failures/no-ops allocate and abort a copied candidate.
            # They leave the active slot and generations unchanged, while the
            # inactive slot can change; invalid-GID probes allocate nothing.
            for i in (45,46,55,57):
                for field in ('active','generation','epochs','gids','fsgid'):
                    self.assertEqual(states[i][field],states[i+1][field])
                self.assertEqual(calls[i]['raw_bits'],states[i]['fsgid'])
                self.assertEqual(states[i+1]['pool'][1-states[i]['active']],states[i]['pool'][states[i]['active']])
            self.assertNotEqual(states[45]['pool'],states[46]['pool'])
            for i in (43,50,58):self.assertEqual(states[i],states[i+1])
            self.assertEqual((calls[47]['raw_bits'],calls[47]['gids_after'],calls[47]['fsgid_after']),(0,[2001,2001,2003],2001))
            self.assertEqual(calls[48]['args'][0],0x1000007d3)
            self.assertEqual((calls[48]['raw_bits'],calls[48]['fsgid_after']),(2001,2003))
            self.assertEqual(calls[54]['raw_bits'],(1<<64)-14)
            self.assertEqual(calls[54]['words'],[0xa5a50000+i for i in range(8)])
            self.assertEqual(calls[59]['words'][1],2001)
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU,pause_ordinals=None))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(62,32,216,184))
            rows=result['saved_state']
            self.assertEqual([(r['ordinal'],r['credential_id'],r['generation'],r['fsgid']) for r in rows],[(43,1,6,2003),(46,1,6,2003),(48,2,7,2001),(54,2,11,2001),(58,1,12,2003),(61,1,12,2003)])
            self.assertEqual(rows[1]['slot_generations'],[6,5])
            self.assertEqual(rows[1]['credential_pool'],[[2001,2001,2003,2003]]*2)
            self.assertEqual(rows[3]['gids'],[2003,2003,2001]);self.assertNotEqual(rows[3]['gids'][1],rows[3]['fsgid'])
            self.assertEqual(rows[4]['credential_pool'],[[2003,2003,2001,2003]]*2)
            self.assertEqual(rows[4]['slot_generations'],[12,11])
            self.assertEqual(len(result['syscalls']),12);self.assertFalse(result['runtime_host_interaction'])
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            for field in ('verified_calls','return_value_checks','application_memory_checks'):
                self.assertEqual(kernel['target_observations'][field],186)
            self.assertEqual(kernel['target_observations']['isolation_checks'],124)
            self.assertIn('__sys_setfsgid',kernel['context_plan']['context_functions'])
            self.assertFalse(kernel['source_identity']['native_source_build_attested'])
            shutil.rmtree(native)
            self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_unreleased_candidates_and_rejected_fs_hook_fail_target_proof(self):
        changes=[('if(candidate==pending_credential)pending_credential=0;','(void)candidate;'),
                 ('(flags==LSM_SETID_RES || flags==LSM_SETID_FS)','flags==LSM_SETID_RES')]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle)
                model=bundle/'models.c';source=model.read_text();self.assertEqual(source.count(original),1);model.write_text(source.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaises(ValueError):
                    export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/fsgid/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_helper_tampering_and_silent_denial_observation_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            source=native/'upstream/kernel/sys.c';raw=source.read_bytes()
            source.write_bytes(raw.replace(b'new->fsgid = kgid;',b'new->fsgid = new->gid;'))
            with self.assertRaises(ValueError):build_bundle(native,stage/'bad-helper')
            self.assertFalse((stage/'bad-helper').exists());source.write_bytes(raw)
            # Same raw return does not establish success: independently reject
            # a falsely reported filesystem-group change on a denied request.
            captured=json.loads((native/'capture.json').read_text());captured['calls'][45]['fsgid_after']=3000
            (native/'capture.json').write_text(json.dumps(captured))
            log=(native/'qemu.log').read_text();start=log.index('OSREC_LINUX_CAPTURE ');end=log.index('\n',start)
            log=log[:start]+'OSREC_LINUX_CAPTURE '+json.dumps({k:v for k,v in captured.items() if k!='format'})+log[end:];(native/'qemu.log').write_text(log)
            manifest=json.loads((native/'capture.manifest.json').read_text());manifest['capture_sha256']=digest((native/'capture.json').read_bytes());manifest['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'state transitions differ'):build_bundle(native,stage/'bad-observation')
            self.assertFalse((stage/'bad-observation').exists())

if __name__=='__main__':unittest.main()
