"""Original capset/commoncap controls later setgroups calls in the same context."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-capabilities-native'
BOOT=1<<22;GID=1<<6;VALID=(1<<41)-1

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxCapabilitiesTests(unittest.TestCase):
    def test_drop_regain_permanent_drop_and_group_updates_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-capabilities-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');review=reviewed_adapter()
            captured,manifest=review.validate_capture(native);calls=captured['calls'];_,states=review.projection(captured)
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(captured['initial']['capabilities'],[BOOT|GID,BOOT|GID,0,VALID,0])
            self.assertEqual(calls[21]['groups_after'],[5001,5005,5009]);self.assertEqual(calls[22]['capabilities_after'][:2],[BOOT,BOOT|GID])
            self.assertEqual(calls[23]['raw_bits'],(1<<64)-1);self.assertEqual(calls[23]['groups_after'],calls[21]['groups_after'])
            self.assertEqual(calls[25]['capabilities_after'][:2],[BOOT|GID]*2);self.assertEqual(calls[26]['groups_after'],[6001,6003])
            self.assertEqual(calls[28]['raw_bits'],0);self.assertEqual(states[29]['generation'],states[28]['generation']+1)
            for i in (23,29,37,39,45,48,49,52,53,54,58,59):self.assertEqual(calls[i]['raw_bits'],(1<<64)-1)
            self.assertEqual(calls[31]['raw_bits'],(1<<64)-22);self.assertEqual(calls[31]['words'][0],0x20080522)
            self.assertEqual(calls[31]['input_words'][0],0)
            for i in (32,33,34,35,36):self.assertEqual(calls[i]['raw_bits'],(1<<64)-14)
            self.assertEqual(calls[38]['input_words'][1],1);self.assertEqual(calls[38]['raw_bits'],0)
            self.assertEqual(calls[41]['capabilities_after'][2],GID);self.assertEqual(calls[42]['groups_after'],[])
            self.assertEqual(calls[43]['raw_bits'],0);self.assertEqual(calls[44]['input_words'][0],0x19980330)
            self.assertEqual(calls[46]['input_words'][0],0x20071026);self.assertEqual(calls[47]['groups_after'],[9001])
            self.assertEqual(calls[50]['input_words'][5:],[0x80000000]*3);self.assertEqual(calls[50]['raw_bits'],0)
            self.assertEqual(calls[50]['capabilities_after'][:3],[BOOT|GID,BOOT|GID,GID])
            self.assertEqual(calls[51]['capabilities_after'][:3],[BOOT,BOOT,GID])
            self.assertEqual(calls[57]['capabilities_after'][:3],[BOOT,BOOT,0]);self.assertEqual(states[-1]['generation'],16)
            for i,c in enumerate(calls):
                if c['number'] in (91,159) and c['raw_bits']:
                    active=states[i]['active']
                    self.assertEqual(states[i+1]['active'],active);self.assertEqual(states[i+1]['generation'],states[i]['generation'])
                    self.assertEqual(states[i+1]['capabilities'][active],states[i]['capabilities'][active])
                    self.assertEqual(c['groups_after'],calls[i-1]['groups_after'])
            # Failed capset still prepared an inactive copy, then released it.
            self.assertNotEqual(states[53]['capabilities'][1],states[54]['capabilities'][1])
            self.assertEqual(states[53]['epochs'],states[54]['epochs'])
            for state in states:
                selected=state['credential_groups'][state['active']]
                self.assertEqual([p['usage'] for p in state['group_pool']],[int(i==selected) for i in range(2)])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU,pause_ordinals=None))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(64,32,376,332))
            self.assertEqual(len(result['syscalls']),13);self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual([r['generation'] for r in result['saved_state']],[2,4,6,9,14,16])
            self.assertEqual([r['capabilities'][0] for r in result['saved_state']],[BOOT,BOOT|GID,BOOT|GID,BOOT|GID,BOOT,BOOT])
            self.assertEqual([r['supplementary_groups'] for r in result['saved_state']],[[5001,5005,5009],[6001,6003],[7001,7001,7003,7007],[],[9001],[9001]])
            for row in result['saved_state']:
                state=states[row['ordinal']];self.assertEqual(row['credential_capabilities'],state['capabilities']);self.assertEqual(row['group_pool'],state['group_pool'])
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            for field in ('verified_calls','return_value_checks','application_memory_checks'):self.assertEqual(kernel['target_observations'][field],192)
            self.assertEqual(kernel['target_observations']['isolation_checks'],128)
            caps=[f for f in kernel['checkpoint_codec']['fields'] if '.cap_' in f['path']]
            self.assertEqual(len(caps),10);self.assertTrue(all(f['policy']=='persist' and f['bytes']==8 for f in caps))
            review=kernel['source_identity']['reviewed_source'];self.assertEqual(len(review['definitions']),22)
            self.assertEqual(set(review['additional_sources']),{'kernel/groups.c','kernel/capability.c','security/commoncap.c'})
            self.assertIn('upstream_capability.h',kernel['checkpoint_codec']['identity']['closure_sha256'])
            self.assertFalse(kernel['source_identity']['native_source_build_attested'])
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_stale_permission_or_leaked_aborted_reference_fails_target_proof(self):
        original='(current_cred()->cap_effective.val&(UINT64_C(1)<<CAP_SETGID))!=0'
        changes=[(original,'(current_cred()->cap_permitted.val&(UINT64_C(1)<<CAP_SETGID))!=0'),
                 ('put_group_info(candidate->group_info);pending_credential=0;','pending_credential=0;')]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);model=bundle/'models.c';source=model.read_text();self.assertEqual(source.count(original),1);model.write_text(source.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaises(ValueError):
                    export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/capabilities/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_original_commoncap_and_native_irreversible_drop_are_bound(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            source=native/'upstream/security/commoncap.c';raw=source.read_bytes()
            self.assertEqual(raw.count(b'if (!cap_issubset(*permitted, old->cap_permitted))'),1)
            source.write_bytes(raw.replace(b'if (!cap_issubset(*permitted, old->cap_permitted))',b'if (0)'))
            with self.assertRaisesRegex(ValueError,'capability source identity'):build_bundle(native,stage/'bad-source')
            self.assertFalse((stage/'bad-source').exists());source.write_bytes(raw)
            captured=json.loads((native/'capture.json').read_text());captured['calls'][53]['capabilities_after'][0]|=GID
            (native/'capture.json').write_text(json.dumps(captured))
            log=(native/'qemu.log').read_text();start=log.index('OSREC_LINUX_CAPTURE ');end=log.index('\n',start)
            log=log[:start]+'OSREC_LINUX_CAPTURE '+json.dumps({k:v for k,v in captured.items() if k!='format'})+log[end:];(native/'qemu.log').write_text(log)
            manifest=json.loads((native/'capture.manifest.json').read_text());manifest['capture_sha256']=digest((native/'capture.json').read_bytes());manifest['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'state transitions differ'):build_bundle(native,stage/'bad-observation')
            self.assertFalse((stage/'bad-observation').exists())

if __name__=='__main__':unittest.main()
