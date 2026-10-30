"""Verify host-independent scalar images, unsigned PID handling and capture rejection."""
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
from export_freestanding_scalar import ROOTS,export,prepare_sources
from klee_liteos import digest
from run_freestanding_armv7 import observe,require_success
KERNEL=ROOT/'build/kernel_liteos_a'
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
QEMU='qemu-system-arm'


class ScalarImageTests(unittest.TestCase):
    def args(self,stage):
        return SimpleNamespace(arch='armv7',capture=stage/'capture',out=stage/'image',kernel_root=KERNEL,llvm_bin=LLVM,qemu=QEMU)

    def capture(self,directory,pid=42,bad_priority=None):
        directory.mkdir();_,identities=prepare_sources(KERNEL)
        for function,filename,prefix,number in ROOTS:
            if number==20:
                data=struct.pack('<2I',pid,16);calls=[{'raw':pid,'user_mode':16}]
            else:
                raw=[31 if number==159 else 10,-22,-22]
                if prefix==bad_priority:raw[0]+=1
                policies=[2,1,0xffffffff]
                data=b''.join(struct.pack('<3I',policy,value&0xffffffff,16) for policy,value in zip(policies,raw))
                calls=[{'policy_bits':policy,'raw':value,'user_mode':16} for policy,value in zip(policies,raw)]
            metadata={'format':'osrec-live-pid-replay-v1' if number==20 else 'osrec-live-priority-replay-v1',
                      'root':function,'source_identity':identities[function],'live_observations_sha256':digest(data),
                      'kernel_image_sha256':'0'*64,'calls':calls}
            if number==20:metadata['checkpoint']={'current_process_id':pid}
            (directory/(prefix+'-observations.bin')).write_bytes(data)
            (directory/(prefix+'-replay.manifest.json')).write_text(json.dumps({'metadata':metadata}))

    def test_standalone_formats_and_unsigned_pid(self):
        for pid in (42,0xdeadbeef):
            with self.subTest(pid=pid),tempfile.TemporaryDirectory() as name:
                args=self.args(Path(name));self.capture(args.capture,pid)
                with contextlib.redirect_stdout(io.StringIO()):export(args)
                manifest=json.loads((args.out/'manifest.json').read_text())
                self.assertFalse(manifest['runtime_host_interaction']);self.assertEqual(manifest['system_libraries'],[])
                shutil.rmtree(args.capture);shutil.rmtree(args.out/'sources')
                (args.out/'checkpoint.json').unlink();(args.out/'manifest.json').unlink()
                for filename in ('scalar.elf','scalar.bin'):
                    result,_=observe(args.out/filename,QEMU);require_success(result)
                    self.assertEqual(result['abi_version'],3);self.assertEqual(result['initial_pid'],pid)
                    self.assertEqual([call['raw'] for call in result['actual_calls']],[31,-22,-22,10,-22,-22,pid])
                    self.assertEqual(result['pid_dependency_calls'],1)

    def test_target_priority_divergence_does_not_publish(self):
        for prefix in ('priority','priority-min'):
            with self.subTest(prefix=prefix),tempfile.TemporaryDirectory() as name:
                args=self.args(Path(name));self.capture(args.capture,bad_priority=prefix)
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(args)
                self.assertFalse(args.out.exists())

    def test_inconsistent_capture_does_not_publish(self):
        for case in ('hash','checkpoint','kernel','source'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as name:
                args=self.args(Path(name));self.capture(args.capture)
                path=args.capture/'pid-replay.manifest.json';document=json.loads(path.read_text())
                if case=='hash':
                    data=args.capture/'pid-observations.bin';data.write_bytes(b'bad')
                elif case=='checkpoint':document['metadata']['checkpoint']['current_process_id']=43
                elif case=='kernel':document['metadata']['kernel_image_sha256']='1'*64
                else:document['metadata']['source_identity']['source']['function_sha256']='1'*64
                path.write_text(json.dumps(document))
                with self.assertRaises(ValueError):export(args)
                self.assertFalse(args.out.exists())


if __name__=='__main__':
    if len(sys.argv)==4:
        KERNEL=Path(sys.argv[1]);LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
