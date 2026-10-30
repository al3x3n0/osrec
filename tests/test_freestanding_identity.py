"""Execute identity images without host services and reject corrupt dependency transcripts."""
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
from export_freestanding_identity import export
from klee_liteos import digest
from live_identity_replay import CALLS,decode_identity,prepare_source
from run_freestanding_armv7 import observe,require_success

KERNEL=ROOT/'build/kernel_liteos_a'
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
QEMU='qemu-system-arm'


class IdentityImageTests(unittest.TestCase):
    def setUp(self):
        self.rows=[(0,2,0,123),(1,3,0,456),(2,1,0,7),(2,4,7,72),
                   (3,1,0,7),(3,4,7,72),(4,4,1,73),(5,4,0xffffffff,0xffffffea),
                   (6,1,0,7),(6,4,7,72)]
        self.results=[123,456,72,72,73,-22,72]

    def args(self,stage):
        return SimpleNamespace(arch='armv7',capture=stage/'capture',out=stage/'image',kernel_root=KERNEL,llvm_bin=LLVM,qemu=QEMU)

    def capture(self,directory,rows,results):
        directory.mkdir()
        user=b''.join(struct.pack('<4I',number,argument,raw&0xffffffff,16)
                      for (number,argument),raw in zip(CALLS,results))
        transcript=b''.join(struct.pack('<4I',*row) for row in rows)
        calls,events=decode_identity(user,transcript);_,identity=prepare_source(KERNEL)
        metadata={'format':'osrec-live-identity-replay-v1','live_observations_sha256':digest(user),
                  'dependency_transcript_sha256':digest(transcript),'source_identity':identity,
                  'calls':calls,'dependency_transcript':events,'kernel_image_sha256':'0'*64}
        (directory/'identity-observations.bin').write_bytes(user)
        (directory/'identity-dependencies.bin').write_bytes(transcript)
        (directory/'identity-replay.manifest.json').write_text(json.dumps({'metadata':metadata}))

    def test_nondefault_state_and_standalone_formats(self):
        with tempfile.TemporaryDirectory() as name:
            args=self.args(Path(name));self.capture(args.capture,self.rows,self.results)
            with contextlib.redirect_stdout(io.StringIO()):export(args)
            metadata=json.loads((args.out/'manifest.json').read_text())
            self.assertFalse(metadata['runtime_host_interaction']);self.assertEqual(metadata['system_libraries'],[])
            self.assertTrue(metadata['raw_image_execution_match'])
            shutil.rmtree(args.capture);shutil.rmtree(args.out/'sources')
            (args.out/'checkpoint.json').unlink();(args.out/'manifest.json').unlink()
            for filename in ('identity.elf','identity.bin'):
                result,_=observe(args.out/filename,QEMU);require_success(result)
                self.assertEqual(result['abi_version'],2)
                self.assertEqual([call['raw'] for call in result['actual_calls']],self.results)
                self.assertEqual([call['dependencies_consumed'] for call in result['actual_calls']],[1,2,4,6,7,8,10])

    def test_target_transcript_corruption_does_not_publish(self):
        argument=list(self.rows);argument[3]=(2,4,1,72)
        result=list(self.rows);result[0]=(0,2,0,124)
        invocation=list(self.rows);invocation[3]=(3,4,7,72)
        pid=list(self.rows);pid[2]=(2,1,0,8)
        kind=list(self.rows);kind[0]=(0,3,0,123)
        cases=[('missing',self.rows[:-1],self.results),('extra',self.rows+[self.rows[-1]],self.results),
               ('reordered',[self.rows[1],self.rows[0],*self.rows[2:]],self.results),
               ('argument',argument,self.results),('result',result,self.results),
               ('invocation',invocation,self.results),('pid_substitution',pid,self.results),
               ('kind',kind,self.results),('expected_return',self.rows,[124,*self.results[1:]])]
        for label,rows,results in cases:
            with self.subTest(label=label),tempfile.TemporaryDirectory() as name:
                args=self.args(Path(name));self.capture(args.capture,rows,results)
                with self.assertRaisesRegex(ValueError,'target replay diverged'):
                    export(args)
                self.assertFalse(args.out.exists())

    def test_hash_mismatch_and_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as name:
            args=self.args(Path(name));self.capture(args.capture,self.rows,self.results)
            path=args.capture/'identity-dependencies.bin';path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaisesRegex(ValueError,'hashes differ'):export(args)
            self.assertFalse(args.out.exists())
            args.out.mkdir();sentinel=args.out/'identity.bin';sentinel.write_bytes(b'preserve')
            with self.assertRaisesRegex(ValueError,'new output'):export(args)
            self.assertEqual(sentinel.read_bytes(),b'preserve')


if __name__=='__main__':
    if len(sys.argv)==4:
        KERNEL=Path(sys.argv[1]);LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
