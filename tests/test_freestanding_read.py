"""Check target object reconstruction, persistent read state and corruption rejection."""
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from export_freestanding_read import export
from run_freestanding_armv7 import observe,require_success
KERNEL=ROOT/'build/kernel_liteos_a'
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
QEMU='qemu-system-arm'


class ReadImageTests(unittest.TestCase):
    def args(self,stage):
        return SimpleNamespace(arch='armv7',capture=stage/'input/capture.json',out=stage/'image',kernel_root=KERNEL,llvm_bin=LLVM,qemu=QEMU)

    def capture(self,args,case):
        args.capture.parent.mkdir();path=args.capture.parent/'case.json';path.write_text(json.dumps(case))
        completed=subprocess.run([sys.executable,str(ROOT/'tools/syscall_checkpoint.py'),'capture',
                                  '--kernel-root',str(KERNEL),'--case',str(path),'--out',str(args.capture)],
                                 capture_output=True,text=True,timeout=60)
        self.assertEqual(completed.returncode,0,completed.stderr)
        return json.loads(args.capture.read_text())

    def test_aliases_wraparound_faults_and_separate_files(self):
        base=json.loads((ROOT/'examples/sysread_session_case.json').read_text())
        cases={'aliases':base,'wrap':copy.deepcopy(base),'fault':copy.deepcopy(base),'separate':copy.deepcopy(base)}
        cases['wrap']['entry']['objects'][1]['fields']['position']=0xfffffffe
        cases['fault']['calls'][0]['buffer']['offset']=8
        cases['separate']['entry']['objects'].insert(2,{'id':21,'type':'file','fields':{'backend_fd':18,'position':100}})
        cases['separate']['entry']['objects'][-1]['fields']['fd4']['object']=21
        for label,case in cases.items():
            with self.subTest(label=label),tempfile.TemporaryDirectory() as name:
                args=self.args(Path(name));document=self.capture(args,case)
                with contextlib.redirect_stdout(io.StringIO()):export(args)
                final=document['expected'][-1]
                shutil.rmtree(args.capture.parent);shutil.rmtree(args.out/'sources')
                (args.out/'checkpoint.json').unlink();(args.out/'manifest.json').unlink()
                for filename in ('read.elf','read.bin'):
                    result,_=observe(args.out/filename,QEMU);require_success(result)
                    self.assertEqual(result['abi_version'],4)
                    self.assertEqual(result['memory'],final['memory'])
                    self.assertEqual(result['user_errno'],final['errno'])
                    self.assertEqual(result['kernel_errno'],final['kernel_errno'])
                    self.assertEqual(result['file_positions'],[final['file_positions'][key] for key in sorted(final['file_positions'],key=int)])
                    self.assertEqual(result['actual_calls'],[{key:step[key] for key in ('raw','return','errno','recognized')} for step in document['expected']])
                if label=='wrap':self.assertEqual(result['file_positions'],[1])
                if label=='fault':self.assertEqual(result['actual_calls'][0]['raw'],-14)
                if label=='separate':self.assertEqual(result['file_positions'],[12,101])

    def test_target_corruption_does_not_publish(self):
        base=json.loads((ROOT/'examples/sysread_session_case.json').read_text())
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);args=self.args(stage);original=self.capture(args,base)
            def corrupt(label):
                value=copy.deepcopy(original)
                if label=='payload':value['transcript'][0][2]['payload']='4143'
                elif label=='entry_bytes':value['entry']['objects'][0]['data']='ff11223344556677'
                elif label=='alias':value['entry']['objects'][2]['fields']['fd4']={'object':0,'offset':0}
                elif label=='cursor':value['entry']['objects'][1]['fields']['position']=11
                elif label=='event_order':value['transcript'][0][0],value['transcript'][0][1]=value['transcript'][0][1],value['transcript'][0][0]
                elif label=='missing':value['transcript'][2].pop()
                elif label=='errno':value['transcript'][2][2]['errno']=5
                else:value['expected'][-1]['memory']='0011414243556600'
                return value
            for label in ('payload','entry_bytes','alias','cursor','event_order','missing','errno','expected_memory'):
                with self.subTest(label=label):
                    args.capture.write_text(json.dumps(corrupt(label)))
                    with self.assertRaisesRegex(ValueError,'target replay diverged'):export(args)
                    self.assertFalse(args.out.exists())
            value=copy.deepcopy(original);value['identity']['kernel_slice_sha256']='0'*64
            args.capture.write_text(json.dumps(value))
            with self.assertRaises(ValueError):export(args)
            self.assertFalse(args.out.exists())
            args.out.mkdir();sentinel=args.out/'read.bin';sentinel.write_bytes(b'preserve')
            with self.assertRaises(ValueError):export(args)
            self.assertEqual(sentinel.read_bytes(),b'preserve')


if __name__=='__main__':
    if len(sys.argv)==4:
        KERNEL=Path(sys.argv[1]);LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
