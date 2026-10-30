"""Real ARM64 Linux observations replay through original slices and local gateway."""
import gzip
import json
import shutil
import struct
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
from minimal_ext2 import root_disk

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-native'

def prepare_capture(destination):
    shutil.copytree(FIXTURE,destination,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (destination/'root.ext2').write_bytes(gzip.decompress((FIXTURE/'root.ext2.gz').read_bytes()))
    reviewed_adapter().validate_capture(destination)
    return destination

class LinuxCheckpointTests(unittest.TestCase):
    def test_original_linux_slices_gateway_and_checkpoint_resumes(self):
        with tempfile.TemporaryDirectory(prefix='osrec-linux-a64-') as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            captured,manifest=reviewed_adapter().validate_capture(native)
            self.assertTrue(manifest['native_linux_boot']);self.assertEqual(manifest['identity']['architecture'],'aarch64')
            self.assertEqual(captured['calls'][7]['raw_bits'],0o22)
            self.assertEqual(captured['calls'][11]['raw_bits'],(1<<64)-14)
            self.assertEqual(captured['calls'][11]['words'][1:4],[1001,0xa5a50002,0xa5a50003])
            self.assertEqual(captured['calls'][16]['words'][1:4],[2001,2002,0xa5a50003])
            result=run(SimpleNamespace(capture=native,out=stage/'pipeline',llvm_bin=LLVM,qemu=QEMU,pause_ordinals=[8,15,19]))
            self.assertEqual((result['logical_calls'],result['qemu_matrix_executions'],result['context_bytes'],result['record_bytes']),(20,20,136,112))
            self.assertEqual([(s['ordinal'],s['umask']) for s in result['saved_state']],[(8,0o77),(15,0o2),(19,0o22)])
            self.assertEqual(len(result['syscalls']),10);self.assertFalse(result['runtime_host_interaction'])
            self.assertFalse(result['native_source_build_attested'])
            kernel=json.loads((stage/'pipeline/kernel/manifest.json').read_text())
            self.assertEqual(kernel['target_observations']['verified_calls'],60)
            self.assertEqual(kernel['target_observations']['return_value_checks'],60)
            self.assertEqual(kernel['target_observations']['application_memory_checks'],60)
            self.assertIn('linux_umask',kernel['context_plan']['context_functions'])
            self.assertIn('current', {f['name'] for f in kernel['context_plan']['owned_state']})
            abi=kernel['port']['application_abi'];self.assertEqual((abi['number_register'],abi['argument_registers'],abi['result_register']),(8,[0,1,2,3,4,5],0))
            shutil.rmtree(native)
            self.assertEqual(verify_pipeline(stage/'pipeline')['status'],'verified')
            record=stage/'pipeline/chain/stage-0/checkpoint/kernel.bin'
            data=record.read_bytes();record.write_bytes(data[:-1]+bytes([data[-1]^1]))
            with self.assertRaises(ValueError):verify_pipeline(stage/'pipeline')

    def test_native_capture_and_source_tampering_reject_before_publication(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            source=native/'upstream/kernel/sys.c';raw=source.read_bytes()
            source.write_bytes(raw.replace(b'return task_tgid_vnr(current);',b'return 1;',1))
            with self.assertRaises(ValueError):build_bundle(native,stage/'bad-source')
            self.assertFalse((stage/'bad-source').exists());source.write_bytes(raw)
            captured=native/'capture.json';raw=captured.read_bytes();data=json.loads(raw);data['calls'][7]['raw_bits']=0
            captured.write_text(json.dumps(data))
            with self.assertRaises(ValueError):build_bundle(native,stage/'bad-capture')
            self.assertFalse((stage/'bad-capture').exists());captured.write_bytes(raw)
            self.assertEqual(len(reviewed_adapter().validate_capture(native)[0]['calls']),20)

    def test_missing_state_updates_and_user_copies_fail_target_proof(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);native=prepare_capture(stage/'native')
            changes=[('int old=*p;*p=value;return old;','int old=*p;(void)value;return old;'),('for(unsigned i=0;i<4;++i)target[i]=(unsigned char)(value>>(8*i));','(void)value;(void)target;')]
            for i,(original,mutation) in enumerate(changes):
                bundle=stage/('port-'+str(i));port=build_bundle(native,bundle)
                model=bundle/'models.c';text=model.read_text();self.assertEqual(text.count(original),1);model.write_text(text.replace(original,mutation))
                descriptor=json.loads(port.read_text());descriptor['bundle']['inputs']['models.c']=digest(model.read_bytes());port.write_text(json.dumps(descriptor))
                output=stage/('bad-kernel-'+str(i))
                with self.assertRaises(ValueError):export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=ROOT/'integrations/linux_aarch64/upstream',out=output,port=port,llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000))
                self.assertFalse(output.exists())

    def test_root_disk_layout_keeps_inode_and_indirect_file_offsets(self):
        # Read using the ext2 on-disk layout, independently of the constructor.
        program=bytes(range(256))*80;raw=root_disk(program)
        self.assertEqual(len(raw),2*1024*1024)
        self.assertEqual(struct.unpack_from('<H',raw,1024+56)[0],0xef53)
        inode_bytes=struct.unpack_from('<H',raw,1024+88)[0]
        table=struct.unpack_from('<I',raw,2048+8)[0]*1024
        root=table+inode_bytes;self.assertEqual(struct.unpack_from('<H',raw,root)[0],0o40755)
        init=table+11*inode_bytes;self.assertEqual(struct.unpack_from('<H',raw,init)[0],0o100755)
        size=struct.unpack_from('<I',raw,init+4)[0];self.assertEqual(size,len(program))
        blocks=list(struct.unpack_from('<12I',raw,init+40));indirect=struct.unpack_from('<I',raw,init+88)[0]
        blocks+=list(struct.unpack_from('<8I',raw,indirect*1024))
        self.assertEqual(b''.join(raw[b*1024:(b+1)*1024] for b in blocks)[:size],program)
        with self.assertRaises(ValueError):root_disk(b'')
        with self.assertRaises(ValueError):root_disk(bytes(256*1024+1))

if __name__=='__main__':unittest.main()
