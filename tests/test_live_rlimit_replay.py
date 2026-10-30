"""Native getrlimit SVC capture -> self-contained replay and QEMU acceptance."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from export_freestanding_rlimit import export
from rtl_load_bundle import prepare
from rtl_boot_bundle import prepare as prepare_boot
from verify_qemu_bundle import verify


class LiveRlimitTests(unittest.TestCase):
    def test_native_capture_and_replay(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture'
            result=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),'--resource-limits','--out',str(capture)],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            report=json.loads((capture/'report.json').read_text())
            self.assertTrue(report['rlimit_capture']['original_syscall_executed'])
            args=SimpleNamespace(arch='aarch64',capture=capture,out=stage/'image',entry_address=0x40400000,result_address=0x40380000,
                kernel_root=ROOT/'build/kernel_liteos_a',llvm_bin=Path('/opt/homebrew/opt/llvm@16/bin'),qemu='qemu-system-aarch64')
            exported=export(args);self.assertEqual(exported['target_observations']['completed_calls'],6)
            expected=(args.out/'target-result.bin').read_bytes()
            for raw in (False,True):
                base=stage/('raw' if raw else 'elf');base.mkdir();replay=base/'replay'
                prepare(args.out/'rlimit.elf',[{'address':0x40000000,'bytes':64*1024*1024}],replay,args.out/'rlimit.bin' if raw else None)
                prepare_boot(replay,base/'boot')
                for bundle,label in ((replay,'el1'),(base/'boot','el3')):
                    checked=verify(bundle,base/label)
                    self.assertEqual(checked['status'],'verified');self.assertEqual((base/label/'target-result.bin').read_bytes(),expected)


if __name__=='__main__':unittest.main()
