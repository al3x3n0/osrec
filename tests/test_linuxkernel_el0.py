"""Public library entry contracts; the fixture backend is not Linux syscalls."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class LibraryEntry(unittest.TestCase):
    @unittest.skipUnless(shutil.which('cc'), 'C compiler required')
    def test_public_entry_contracts(self):
        with tempfile.TemporaryDirectory() as directory:
            exe=Path(directory)/'checkpoint'
            command=['cc','-std=c11','-O2','-Wall','-Wextra','-Werror','-pthread',
                     '-I'+str(ROOT/'include'),'-I'+str(ROOT/'runtime/el0'),
                     str(ROOT/'runtime/linuxkernel_el0/entry.c'),str(ROOT/'runtime/el0/emulate.c'),
                     str(ROOT/'tests/linuxkernel_el0_host.c')]
            import platform,sys
            if sys.platform=='linux' and platform.machine() in ('aarch64','arm64'):
                command += [str(ROOT/'runtime/linuxkernel_el0/veneer.S'),'-mgeneral-regs-only','-mbranch-protection=none']
            subprocess.run(command+['-o',str(exe)],check=True,capture_output=True,text=True)
            result=subprocess.run([str(exe)],check=True,capture_output=True,text=True,timeout=30)
            self.assertIn('library contracts passed: 128 paired entries',result.stdout)


if __name__=='__main__':unittest.main()
