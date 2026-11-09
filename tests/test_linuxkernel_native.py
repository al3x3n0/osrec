"""Opt-in integration against actual captured kernel instructions on arm64 Linux."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = os.environ.get('OSREC_NATIVE_PACKAGE')
ORACLE = os.environ.get('OSREC_NATIVE_ORACLE')


class NativeKernel(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'linux' and platform.machine() in ('aarch64', 'arm64')
                         and PACKAGE and ORACLE and shutil.which('make'),
                         'arm64 Linux, OSREC_NATIVE_PACKAGE and OSREC_NATIVE_ORACLE required')
    def test_captured_kernel(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ['make', '-C', str(ROOT/'runtime/linuxkernel_el0'),
                 'OUT='+directory, 'CC='+('clang-19' if shutil.which('clang-19') else 'cc'),
                 'PACKAGE='+str(Path(PACKAGE).resolve()),
                 'ORACLE='+str(Path(ORACLE).resolve()), 'check-native'],
                check=True, capture_output=True, text=True, timeout=180)
            self.assertIn('native captured Linux passed:', result.stdout)


if __name__ == '__main__':
    unittest.main()
