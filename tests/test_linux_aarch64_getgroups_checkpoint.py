"""Original Linux supplementary-group queries and guard faults replay locally."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-getgroups-native'

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxSupplementaryGroupsTests(unittest.TestCase):
    def test_count_queries_partial_faults_and_shared_links_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-getgroups-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');review=reviewed_adapter()
            captured,manifest=review.validate_capture(native);calls=captured['calls'];groups=[4001,4003,4007]
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(captured['profile'],'getgroups')
            self.assertEqual(captured['initial']['groups'],groups)
            self.assertTrue(all(c['groups_after']==groups for c in calls))
            # Count-only requests ignore NULL/invalid pointers after int truncation.
            for i in (94,100,109,111):
                self.assertEqual(calls[i]['raw_bits'],3);self.assertEqual(calls[i]['words'],[0xa5a50000+j for j in range(8)])
            for i in (96,97,102):self.assertEqual(calls[i]['raw_bits'],(1<<64)-22)
            for i in (98,99,104,106):self.assertEqual(calls[i]['raw_bits'],(1<<64)-14)
            self.assertEqual(calls[95]['words'][1:4],groups)
            self.assertEqual(calls[101]['args'][0],0x100000003)
            self.assertEqual(calls[101]['words'][1:4],groups)
            self.assertEqual(calls[103]['words'][1:5],groups+[0xa5a50004])
            self.assertEqual(calls[99]['words'],[0xa5a50000+j for j in range(7)]+[4001])
            self.assertEqual(calls[106]['words'],[0xa5a50000+j for j in range(6)]+[4001,4003])
            self.assertEqual(calls[107]['words'][:4],groups+[0xa5a50003])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU,pause_ordinals=None))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(112,32,256,204))
            self.assertEqual([(r['ordinal'],r['credential_id'],r['generation']) for r in result['saved_state']],[(67,2,13),(95,2,27),(100,2,27),(106,1,28),(109,2,29),(111,2,29)])
            self.assertTrue(all(r['supplementary_groups']==groups and r['supplementary_capacity']==4 for r in result['saved_state']))
            self.assertEqual(len(result['syscalls']),15);self.assertFalse(result['runtime_host_interaction'])
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            for field in ('verified_calls','return_value_checks','application_memory_checks'):
                self.assertEqual(kernel['target_observations'][field],336)
            self.assertEqual(kernel['target_observations']['isolation_checks'],224)
            self.assertTrue(any(n.endswith('groups_to_user') for n in kernel['context_plan']['context_functions']))
            links=[f for f in kernel['checkpoint_codec']['fields'] if f['path'].endswith('.group_info')]
            self.assertEqual(len(links),2)
            self.assertTrue(all(f['policy']=='self_reference' and f['target']=='supplementary_groups' for f in links))
            self.assertFalse(kernel['source_identity']['native_source_build_attested'])
            self.assertIn('kernel/groups.c',kernel['source_identity']['reviewed_source']['additional_sources'])
            shutil.rmtree(native)
            self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_lost_list_link_or_missing_group_copy_fails_target_proof(self):
        changes=[('*candidate=*current->cred;pending_credential=candidate;','*candidate=*current->cred;candidate->group_info=0;pending_credential=candidate;'),
                 ('for(unsigned i=0;i<4;++i)target[i]=(unsigned char)(value>>(8*i));','if(value<4000)for(unsigned i=0;i<4;++i)target[i]=(unsigned char)(value>>(8*i));')]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);model=bundle/'models.c';source=model.read_text();self.assertEqual(source.count(original),1);model.write_text(source.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaises(ValueError):
                    export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/getgroups/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_extra_source_and_native_list_observations_are_bound(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            source=native/'upstream/kernel/groups.c';raw=source.read_bytes()
            self.assertEqual(raw.count(b'i = cred->group_info->ngroups;'),1)
            source.write_bytes(raw.replace(b'i = cred->group_info->ngroups;',b'i = 0;'))
            with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
            self.assertFalse((stage/'bad-source').exists());source.write_bytes(raw)
            captured=json.loads((native/'capture.json').read_text());captured['calls'][105]['groups_after'][0]=2001
            (native/'capture.json').write_text(json.dumps(captured))
            log=(native/'qemu.log').read_text();start=log.index('OSREC_LINUX_CAPTURE ');end=log.index('\n',start)
            log=log[:start]+'OSREC_LINUX_CAPTURE '+json.dumps({k:v for k,v in captured.items() if k!='format'})+log[end:];(native/'qemu.log').write_text(log)
            manifest=json.loads((native/'capture.manifest.json').read_text());manifest['capture_sha256']=digest((native/'capture.json').read_bytes());manifest['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'state transitions differ'):build_bundle(native,stage/'bad-observation')
            self.assertFalse((stage/'bad-observation').exists())

if __name__=='__main__':unittest.main()
