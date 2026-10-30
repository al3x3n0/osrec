"""Exercise identity dependency models and reject corrupt transcripts without replacing artifacts."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from live_identity_replay import CALLS, export_live_identity


class IdentityReplayTests(unittest.TestCase):
    def setUp(self):
        # Deliberately differs from PID 1/root credentials: replay must use the dependencies.
        self.rows = [(0,2,0,123), (1,3,0,456), (2,1,0,7), (2,4,7,72),
                     (3,1,0,7), (3,4,7,72), (4,4,1,73), (5,4,0xffffffff,0xffffffea),
                     (6,1,0,7), (6,4,7,72)]
        self.observations = b''.join(struct.pack('<4I',number,argument,result&0xffffffff,16)
                                   for (number,argument),result in zip(CALLS,[123,456,72,72,73,-22,72]))

    def transcript(self, rows=None):
        return b''.join(struct.pack('<4I',*row) for row in (self.rows if rows is None else rows))

    def args(self, directory):
        return SimpleNamespace(out=Path(directory),kernel_root=ROOT/'build/kernel_liteos_a',compiler='cc')

    def test_nondefault_dependency_results_and_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(directory)
            report = export_live_identity(args,self.observations,self.transcript(),'0'*64)
            self.assertEqual([call['raw'] for call in report['calls']],[123,456,72,72,73,-22,72])
            metadata = json.loads(subprocess.check_output([str(args.out/'identity-replay'),'--describe'],text=True))
            self.assertEqual(metadata,report['metadata'])
            isolated = args.out/'isolated'; isolated.mkdir()
            binary = isolated/'replay'; binary.write_bytes((args.out/'identity-replay').read_bytes()); binary.chmod(0o755)
            self.assertEqual(subprocess.check_output([str(binary)],cwd=isolated,
                             env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},text=True).strip(),
                             'identity session verified: 7 calls')

    def test_corruption_preserves_existing_binary(self):
        changed_argument = list(self.rows); changed_argument[3]=(2,4,1,72)
        changed_result = list(self.rows); changed_result[0]=(0,2,0,124)
        changed_invocation = list(self.rows); changed_invocation[3]=(3,4,7,72)
        changed_pid = list(self.rows); changed_pid[2]=(2,1,0,8)
        wrong_mode = bytearray(self.observations); struct.pack_into('<I',wrong_mode,12,19)
        wrong_number = bytearray(self.observations); struct.pack_into('<I',wrong_number,0,24)
        cases = [
            ('truncated',self.observations,self.transcript()[:-1]),
            ('missing',self.observations,self.transcript(self.rows[:-1])),
            ('extra',self.observations,self.transcript(self.rows+[self.rows[-1]])),
            ('reordered',self.observations,self.transcript([self.rows[1],self.rows[0],*self.rows[2:]])),
            ('argument',self.observations,self.transcript(changed_argument)),
            ('result',self.observations,self.transcript(changed_result)),
            ('invocation',self.observations,self.transcript(changed_invocation)),
            ('pid_resolution',self.observations,self.transcript(changed_pid)),
            ('mode',bytes(wrong_mode),self.transcript()),
            ('number',bytes(wrong_number),self.transcript()),
        ]
        for label,observations,transcript in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                args=self.args(directory); binary=args.out/'identity-replay'; binary.write_bytes(b'preserve')
                with self.assertRaises((ValueError,subprocess.CalledProcessError)):
                    export_live_identity(args,observations,transcript,'0'*64)
                self.assertEqual(binary.read_bytes(),b'preserve')
                self.assertFalse((args.out/'identity.sources').exists())


if __name__ == '__main__':
    unittest.main()
