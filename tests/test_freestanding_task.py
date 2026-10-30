"""Check AArch64 task object reconstruction, unsigned IDs and corrupt checkpoints."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from klee_liteos import digest
from live_task_replay import CALLS,decode_task,prepare_source,export_live_task
from export_freestanding_task import export
from freestanding_elf import describe
from run_freestanding_armv7 import observe,require_success
KERNEL=ROOT/'build/kernel_liteos_a';LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'

class TaskTests(unittest.TestCase):
    def args(self,stage):
        return SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000,
            capture=stage/'capture',out=stage/'image',kernel_root=KERNEL,llvm_bin=LLVM,qemu=QEMU)

    def capture(self,args,pid=3,parent=1,tid=7,bad=None):
        args.capture.mkdir();_,identity=prepare_source(KERNEL)
        returns=[parent,tid,parent,tid]
        if bad=='parent':returns[0]^=1
        if bad=='task':returns[1]^=1
        user=b''.join(struct.pack('<3I',number,raw,16) for number,raw in zip(CALLS,returns))
        kernel=b''.join(struct.pack('<6I',number,pid,parent,tid,raw,0x113) for number,raw in zip(CALLS,returns))
        metadata={'format':'osrec-live-task-checkpoint-v1','source_identity':identity,'checkpoint':decode_task(user,kernel),
            'kernel_image_sha256':'0'*64,'user_observations_sha256':digest(user),'kernel_observations_sha256':digest(kernel)}
        (args.capture/'task-user-observations.bin').write_bytes(user)
        (args.capture/'task-kernel-observations.bin').write_bytes(kernel)
        (args.capture/'task-checkpoint.manifest.json').write_text(json.dumps(metadata))
        return user,kernel

    def test_standalone_reconstruction_and_full_width_scalars(self):
        for pid,parent,tid in ((3,1,7),(0xffffffff,0x80000000,0xdeadbeef),(7,0,0)):
            with self.subTest(pid=pid),tempfile.TemporaryDirectory() as directory:
                args=self.args(Path(directory));self.capture(args,pid,parent,tid)
                with contextlib.redirect_stdout(io.StringIO()):export(args)
                elf=args.out/'task.elf';layout=describe(elf)
                self.assertEqual(layout['entry'],args.entry_address);self.assertEqual(layout['result_address'],args.result_address)
                manifest=json.loads((args.out/'manifest.json').read_text())
                self.assertFalse(manifest['runtime_host_interaction']);self.assertEqual(manifest['system_libraries'],[])
                shutil.rmtree(args.capture);shutil.rmtree(args.out/'sources')
                (args.out/'checkpoint.json').unlink();(args.out/'manifest.json').unlink()
                report,raw=observe(elf,QEMU);require_success(report)
                raw_report,raw_result=observe(args.out/'task.bin',QEMU,descriptor=elf);require_success(raw_report)
                self.assertEqual(raw,raw_result)
                self.assertEqual(report['current_pid'],pid);self.assertEqual(report['parent_pid'],parent);self.assertEqual(report['task_id'],tid)
                self.assertEqual([call['raw'] for call in report['actual_calls']],[parent,tid,parent,tid])
                self.assertEqual(report['process_accesses'],2);self.assertEqual(report['task_accesses'],2)

    def test_wrong_capture_expectation_fails_in_target(self):
        for label in ('parent','task'):
            with self.subTest(label=label),tempfile.TemporaryDirectory() as directory:
                args=self.args(Path(directory));self.capture(args,bad=label)
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(args)
                self.assertFalse(args.out.exists())

    def test_inconsistent_inputs_never_publish(self):
        for label in ('hash','source','graph','configuration','state','mode','kernel_result'):
            with self.subTest(label=label),tempfile.TemporaryDirectory() as directory:
                args=self.args(Path(directory));user,kernel=self.capture(args)
                path=args.capture/'task-checkpoint.manifest.json';metadata=json.loads(path.read_text())
                if label=='hash':(args.capture/'task-user-observations.bin').write_bytes(b'bad')
                elif label=='source':metadata['source_identity']['source']['revision']='changed'
                elif label=='graph':metadata['checkpoint']['objects'][0]['parent']=1
                elif label=='configuration':metadata['checkpoint']['configuration']['LOSCFG_PID_CONTAINER']=True
                else:
                    data=bytearray(kernel)
                    # Change the second call's task state, mode, or kernel raw return.
                    offset={'state':36,'mode':44,'kernel_result':40}[label]
                    struct.pack_into('<I',data,offset,8)
                    (args.capture/'task-kernel-observations.bin').write_bytes(data)
                    metadata['kernel_observations_sha256']=digest(data)
                path.write_text(json.dumps(metadata))
                with self.assertRaises(ValueError):export(args)
                self.assertFalse(args.out.exists())

    def test_live_capture_requires_child_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            args=self.args(Path(directory));user,kernel=self.capture(args,pid=1,parent=0)
            args.out.mkdir()
            with self.assertRaisesRegex(ValueError,'child of PID 1'):export_live_task(args,user,kernel,'0'*64)
            self.assertEqual(list(args.out.iterdir()),[])

if __name__=='__main__':
    if len(sys.argv)==4:
        KERNEL=Path(sys.argv[1]);LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
