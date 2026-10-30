"""Verify getpriority argument resolution, ordered boundaries and closed images."""
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
from live_getpriority_replay import CALLS,decode_getpriority,prepare_source
from export_freestanding_getpriority import export
from run_freestanding_armv7 import observe,require_success
from freestanding_elf import describe
KERNEL=ROOT/'build/kernel_liteos_a';LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'

class GetPriorityTests(unittest.TestCase):
    def args(self,stage):
        return SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000,
            capture=stage/'capture',out=stage/'image',kernel_root=KERNEL,llvm_bin=LLVM,qemu=QEMU)

    def capture(self,args,pid=42,priority=17,bad=None):
        args.capture.mkdir();_,identity=prepare_source(KERNEL)
        returns=[priority,priority,(-22)&0xffffffff,(-22)&0xffffffff,(-22)&0xffffffff,priority]
        rows=[]
        for index,(which,who) in enumerate(CALLS):
            if who==0:rows.append([index,1,0,0,pid])
            rows.append([index,2,which,pid if who==0 else who,returns[index]])
        user_returns=list(returns)
        if bad=='expected':user_returns[0]^=1
        if bad=='resolved_pid':rows[1][3]^=1
        if bad=='which':rows[1][2]=1
        if bad=='order':rows[0],rows[1]=rows[1],rows[0]
        if bad=='invocation':rows[1][0]=1
        if bad=='missing':rows.pop()
        if bad=='extra':rows.append([5,2,0,pid,priority])
        user=b''.join(struct.pack('<4I',which,who,raw,16) for (which,who),raw in zip(CALLS,user_returns))
        transcript=b''.join(struct.pack('<5I',*row) for row in rows)
        metadata={'format':'osrec-live-getpriority-checkpoint-v1','source_identity':identity,
            'checkpoint':decode_getpriority(user,transcript),'kernel_image_sha256':'0'*64,
            'user_observations_sha256':digest(user),'dependency_transcript_sha256':digest(transcript)}
        (args.capture/'getpriority-user-observations.bin').write_bytes(user)
        (args.capture/'getpriority-dependencies.bin').write_bytes(transcript)
        (args.capture/'getpriority-checkpoint.manifest.json').write_text(json.dumps(metadata))
        return returns

    def test_closed_images_and_full_width_dependency_values(self):
        for pid,priority in ((42,17),(0x80000000,0xdeadbeef)):
            with self.subTest(pid=pid),tempfile.TemporaryDirectory() as directory:
                args=self.args(Path(directory));returns=self.capture(args,pid,priority)
                with contextlib.redirect_stdout(io.StringIO()):export(args)
                elf=args.out/'getpriority.elf';layout=describe(elf)
                self.assertEqual(layout['entry'],args.entry_address);self.assertEqual(layout['result_address'],args.result_address)
                manifest=json.loads((args.out/'manifest.json').read_text())
                self.assertFalse(manifest['runtime_host_interaction']);self.assertEqual(manifest['system_libraries'],[])
                shutil.rmtree(args.capture);shutil.rmtree(args.out/'sources')
                (args.out/'checkpoint.json').unlink();(args.out/'manifest.json').unlink()
                report,raw=observe(elf,QEMU);require_success(report)
                binary_report,binary_raw=observe(args.out/'getpriority.bin',QEMU,descriptor=elf);require_success(binary_report)
                self.assertEqual(raw,binary_raw)
                self.assertEqual([call['raw_bits'] for call in report['actual_calls']],returns)
                self.assertEqual([call['dependencies_consumed'] for call in report['actual_calls']],[2,3,4,6,8,10])
                self.assertEqual(report['pid_queries'],4);self.assertEqual(report['priority_queries'],6)

    def test_divergent_boundary_transcripts_fail_in_target(self):
        for label in ('expected','resolved_pid','which','order','invocation','missing','extra'):
            with self.subTest(label=label),tempfile.TemporaryDirectory() as directory:
                args=self.args(Path(directory));self.capture(args,bad=label)
                with self.assertRaisesRegex(ValueError,'target replay diverged'):export(args)
                self.assertFalse(args.out.exists())

    def test_bad_inputs_never_publish(self):
        for label in ('hash','source','checkpoint','kind','argument','mode'):
            with self.subTest(label=label),tempfile.TemporaryDirectory() as directory:
                args=self.args(Path(directory));self.capture(args)
                path=args.capture/'getpriority-checkpoint.manifest.json';metadata=json.loads(path.read_text())
                if label=='hash':(args.capture/'getpriority-dependencies.bin').write_bytes(b'bad')
                elif label=='source':metadata['source_identity']['source']['revision']='changed'
                elif label=='checkpoint':metadata['checkpoint']['calls'][0]['raw_bits']=999
                else:
                    name='getpriority-dependencies.bin' if label=='kind' else 'getpriority-user-observations.bin'
                    data=bytearray((args.capture/name).read_bytes())
                    struct.pack_into('<I',data,{'kind':4,'argument':0,'mode':12}[label],99)
                    (args.capture/name).write_bytes(data)
                    key='dependency_transcript_sha256' if label=='kind' else 'user_observations_sha256'
                    metadata[key]=digest(data)
                path.write_text(json.dumps(metadata))
                with self.assertRaises(ValueError):export(args)
                self.assertFalse(args.out.exists())

if __name__=='__main__':
    if len(sys.argv)==4:
        KERNEL=Path(sys.argv[1]);LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
