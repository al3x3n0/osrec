"""Test retained umask state, high-bit filtering and rejection before artifact publication."""
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
from live_umask_replay import MASKS, export_live_umask


def observations(initial):
    user=[]; kernel=[]; before=initial
    for mask in MASKS:
        after=mask&0o777
        user.append(struct.pack('<3I',mask,before,16))
        kernel.append(struct.pack('<5I',mask,before,before,after,0x113))
        before=after
    return b''.join(user),b''.join(kernel)


class UmaskReplayTests(unittest.TestCase):
    def args(self,directory):
        return SimpleNamespace(out=Path(directory),kernel_root=ROOT/'build/kernel_liteos_a',compiler='cc')

    def test_entry_mask_is_restored_once(self):
        for initial in (0,0o22,0o777,0xdeadbeef):
            with self.subTest(initial=initial), tempfile.TemporaryDirectory() as directory:
                args=self.args(directory);user,kernel=observations(initial)
                report=export_live_umask(args,user,kernel,'0'*64)
                self.assertEqual(report['metadata']['checkpoint']['current_process_umask'],initial)
                self.assertEqual([call['raw'] for call in report['calls']],[initial,0,18,511,0,63])
                isolated=args.out/'alone';isolated.mkdir()
                binary=isolated/'replay';binary.write_bytes((args.out/'umask-replay').read_bytes());binary.chmod(0o755)
                self.assertEqual(subprocess.check_output([str(binary)],cwd=isolated,
                                 env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},text=True).strip(),
                                 'umask session verified: 6 calls')
                self.assertEqual(json.loads(subprocess.check_output([str(binary),'--describe'],text=True)),report['metadata'])

    def test_corruption_preserves_artifact(self):
        user,kernel=observations(18)
        def mutate(data,offset,value):
            result=bytearray(data);struct.pack_into('<I',result,offset,value);return bytes(result)
        cases=[('user_truncated',user[:-1],kernel),('kernel_truncated',user,kernel[:-1]),
               ('argument',mutate(user,12,0),kernel),('user_mode',mutate(user,8,19),kernel),
               ('kernel_mode',user,mutate(kernel,16,0x13)),
               ('return_mismatch',mutate(user,4,19),kernel),
               ('discontinuous',user,mutate(kernel,24,18)),
               ('wrong_post_state',user,mutate(kernel,5*20+12,1)),
               ('consistent_wrong_return',mutate(user,4,19),mutate(kernel,8,19)),
               # Incorrect entry masking would lose high bits; keep observations but alter entry snapshot.
               ('wrong_entry',user,mutate(kernel,4,0))]
        for label,bad_user,bad_kernel in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                args=self.args(directory);binary=args.out/'umask-replay';binary.write_bytes(b'preserve')
                with self.assertRaises((ValueError,subprocess.CalledProcessError)):
                    export_live_umask(args,bad_user,bad_kernel,'0'*64)
                self.assertEqual(binary.read_bytes(),b'preserve')
                self.assertFalse((args.out/'umask.sources').exists())


if __name__=='__main__':unittest.main()
