"""Validate standalone ARM images, raw loading, corrupt captures and host-service rejection."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from export_freestanding_umask import audit,export
from klee_liteos import digest
from live_umask_replay import MASKS,decode_umask,prepare_source
from run_freestanding_armv7 import observe,require_success

KERNEL=ROOT/'build/kernel_liteos_a'
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
QEMU='qemu-system-arm'


def capture(directory,initial=18,bad_return=False,bad_state=False):
    directory.mkdir();user=[];kernel=[];before=initial
    for i,mask in enumerate(MASKS):
        after=mask&511;raw=before
        if bad_return and i==0:raw=(raw+1)&0xffffffff
        if bad_state and i==5:after=1
        user.append(struct.pack('<3I',mask,raw,16))
        kernel.append(struct.pack('<5I',mask,before,raw,after,0x113));before=after
    user=b''.join(user);kernel=b''.join(kernel)
    _,identity=prepare_source(KERNEL)
    metadata={'format':'osrec-live-umask-replay-v1','user_observations_sha256':digest(user),
              'kernel_observations_sha256':digest(kernel),'source_identity':identity,
              'calls':decode_umask(user,kernel),'kernel_image_sha256':'0'*64}
    (directory/'umask-user-observations.bin').write_bytes(user)
    (directory/'umask-kernel-observations.bin').write_bytes(kernel)
    (directory/'umask-replay.manifest.json').write_text(json.dumps({'metadata':metadata}))


class ImageTests(unittest.TestCase):
    def args(self,stage):
        return SimpleNamespace(arch='armv7',capture=stage/'capture',out=stage/'image',kernel_root=KERNEL,llvm_bin=LLVM,qemu=QEMU)

    def test_elf_and_raw_without_construction_inputs(self):
        for initial in (18,0xdeadbeef):
            with self.subTest(initial=initial),tempfile.TemporaryDirectory() as name:
                stage=Path(name);args=self.args(stage);capture(args.capture,initial);export(args)
                manifest=json.loads((args.out/'manifest.json').read_text())
                self.assertFalse(manifest['runtime_host_interaction'])
                self.assertEqual(manifest['system_libraries'],[])
                self.assertTrue(manifest['raw_image_execution_match'])
                # Remove all construction data before observing the two image forms again.
                import shutil
                shutil.rmtree(args.capture);shutil.rmtree(args.out/'sources')
                (args.out/'checkpoint.json').unlink();(args.out/'manifest.json').unlink()
                for filename in ('umask.elf','umask.bin'):
                    result,_=observe(args.out/filename,QEMU);require_success(result)
                    self.assertEqual(result['initial_mask'],initial)
                    self.assertEqual(result['final_mask'],0)
                    self.assertEqual([call['raw'] for call in result['actual_calls']],[initial,0,18,511,0,63])
                # ARM bank preparation is supported, but QEMU's bare-metal
                # device tree overlaps this legacy layout at RAM base.
                with self.assertRaisesRegex(ValueError,'requires AArch64'):
                    observe(args.out/'umask.elf','does-not-exist-qemu',load_bundle=stage/'unused')

    def test_target_divergence_does_not_publish(self):
        for label in ('return','state'):
            with self.subTest(label=label),tempfile.TemporaryDirectory() as name:
                args=self.args(Path(name));capture(args.capture,bad_return=label=='return',bad_state=label=='state')
                with self.assertRaisesRegex(ValueError,'target replay diverged'):
                    export(args)
                self.assertFalse(args.out.exists())

    def test_service_trap_and_dynamic_segment_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);args=self.args(stage);capture(args.capture);export(args)
            original=(args.out/'umask.elf').read_bytes()
            entry,phoff=struct.unpack_from('<II',original,24);phsize,phcount=struct.unpack_from('<HH',original,42)
            data=bytearray(original)
            for i in range(phcount):
                kind,offset,address,_,size,_,_,_=struct.unpack_from('<8I',data,phoff+i*phsize)
                if kind==1 and address<=entry<address+size:
                    struct.pack_into('<I',data,offset+entry-address,0xef123456);break
            trap=stage/'trap.elf';trap.write_bytes(data)
            with self.assertRaisesRegex(ValueError,'service/trap'):
                audit(trap,LLVM)
            data=bytearray(original);struct.pack_into('<I',data,phoff,3)
            dynamic=stage/'dynamic.elf';dynamic.write_bytes(data)
            with self.assertRaisesRegex(ValueError,'dynamic loader'):
                audit(dynamic,LLVM)


if __name__=='__main__':
    if len(sys.argv)==4:
        KERNEL=Path(sys.argv[1]);LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
