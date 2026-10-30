"""Original Linux supplementary-group replacement, copy errors and list lifetimes."""
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
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-setgroups-native'

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxSetgroupsTests(unittest.TestCase):
    def test_replacements_duplicates_empty_lists_and_lifetimes_resume(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-setgroups-') as name:
            stage=Path(name);native=prepare_capture(stage/'native');review=reviewed_adapter()
            captured,manifest=review.validate_capture(native);calls=captured['calls'];_,states=review.projection(captured)
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(captured['initial']['uids'],[1001,0,0])
            self.assertEqual(calls[21]['groups_after'],[5001,5005,5009]);self.assertEqual(calls[24]['groups_after'],[6003,6003])
            self.assertEqual(calls[26]['groups_after'],[7001,7001,7003,7007])
            self.assertEqual(calls[29]['words'][6:],[7001,7001]);self.assertEqual(calls[29]['raw_bits'],(1<<64)-14)
            for i in (30,44,45,46):self.assertEqual(calls[i]['raw_bits'],(1<<64)-14)
            for i in (28,32,34,35,50):self.assertEqual(calls[i]['raw_bits'],(1<<64)-22)
            for i in (30,32,34,35,44,45,46,50):
                self.assertEqual(calls[i]['groups_after'],calls[i-1]['groups_after'])
                self.assertEqual(calls[i]['words'],calls[i]['input_words'])
            for ordinal,count,prefix in ((31,3,[8001]),(33,2,[8003]),(47,3,[42,41])):
                state=states[ordinal];inactive=1-state['credential_groups'][state['active']];p=state['group_pool'][inactive]
                self.assertEqual((p['usage'],p['ngroups']),(0,count));self.assertEqual(p['gid'][:len(prefix)],prefix)
            for i in (36,37,38,39):self.assertEqual(calls[i]['groups_after'],[])
            self.assertEqual(calls[37]['raw_bits'],0);self.assertEqual(calls[37]['words'],calls[37]['input_words'])
            self.assertEqual(calls[42]['args'][0],0x100000002);self.assertEqual(calls[42]['groups_after'],[0,0xfffffffe])
            self.assertEqual(calls[49]['groups_after'],calls[48]['groups_after'])
            self.assertEqual(states[50]['generation'],states[49]['generation']+1)
            self.assertEqual(states[-1]['generation'],10)
            for state in states:
                selected=state['credential_groups'][state['active']]
                self.assertEqual([p['usage'] for p in state['group_pool']],[int(i==selected) for i in range(2)])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU,pause_ordinals=None))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(56,32,296,252))
            self.assertEqual(len(result['syscalls']),12);self.assertFalse(result['runtime_host_interaction'])
            self.assertEqual([r['supplementary_groups'] for r in result['saved_state']],[[7001,7001,7003,7007]]*3+[[],[0,0xfffffffe],[4001,4003]])
            for row in result['saved_state']:
                state=states[row['ordinal']]
                self.assertEqual(row['credential_group_ids'],[v+1 for v in state['credential_groups']])
                self.assertEqual(row['group_pool'],state['group_pool']);self.assertEqual(row['generation'],state['generation'])
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            for field in ('verified_calls','return_value_checks','application_memory_checks'):self.assertEqual(kernel['target_observations'][field],168)
            self.assertEqual(kernel['target_observations']['isolation_checks'],112)
            links=[f for f in kernel['checkpoint_codec']['fields'] if f['path'].endswith('.group_info')]
            self.assertEqual(len(links),2)
            self.assertTrue(all(f['policy']=='context_reference' and f['targets']==['group_pool[0]','group_pool[1]'] and f['nullable'] is False for f in links))
            for helper in ('groups_from_user','set_groups','set_current_groups','may_setgroups'):
                self.assertTrue(any(n.endswith(helper) for n in kernel['context_plan']['context_functions']))
            self.assertFalse(kernel['source_identity']['native_source_build_attested'])
            shutil.rmtree(native);self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')

    def test_lost_publication_leaked_refs_or_missing_sort_fails_target_proof(self):
        changes=[('put_group_info(current->cred->group_info);current->cred=candidate;++credential_generation;',
                  'put_group_info(current->cred->group_info);++credential_generation;'),
                 ('void get_group_info(struct group_info *p){++p->usage;}','void get_group_info(struct group_info *p){(void)p;}'),
                 ('while(j>0 && p->gid[j-1]>v)','while(j>0 && p->gid[j-1]<v)')]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle);model=bundle/'models.c';source=model.read_text();self.assertEqual(source.count(original),1);model.write_text(source.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaises(ValueError):
                    export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/setgroups/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_original_copy_source_and_native_replacement_observations_are_bound(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            source=native/'upstream/kernel/groups.c';raw=source.read_bytes();self.assertEqual(raw.count(b'group_info->gid[i] = kgid;'),1)
            source.write_bytes(raw.replace(b'group_info->gid[i] = kgid;',b'group_info->gid[i] = 0;'))
            with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
            self.assertFalse((stage/'bad-source').exists());source.write_bytes(raw)
            captured=json.loads((native/'capture.json').read_text());captured['calls'][30]['groups_after']=[8001]
            (native/'capture.json').write_text(json.dumps(captured))
            log=(native/'qemu.log').read_text();start=log.index('OSREC_LINUX_CAPTURE ');end=log.index('\n',start)
            log=log[:start]+'OSREC_LINUX_CAPTURE '+json.dumps({k:v for k,v in captured.items() if k!='format'})+log[end:];(native/'qemu.log').write_text(log)
            manifest=json.loads((native/'capture.manifest.json').read_text());manifest['capture_sha256']=digest((native/'capture.json').read_bytes());manifest['qemu_log_sha256']=digest((native/'qemu.log').read_bytes());(native/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'state transitions differ'):build_bundle(native,stage/'bad-observation')
            self.assertFalse((stage/'bad-observation').exists())

if __name__=='__main__':unittest.main()
