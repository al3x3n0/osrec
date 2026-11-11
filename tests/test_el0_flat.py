"""Shared EL0 software memory and standalone native gateway contracts."""
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from kernel_source_verify import Elf


class FlatMemory(unittest.TestCase):
    @unittest.skipUnless(shutil.which('cc'),'host C compiler required')
    def test_software_translation_contract(self):
        with tempfile.TemporaryDirectory() as name:
            binary=Path(name)/'memory'
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(ROOT/'runtime/el0_flat'),
                            str(ROOT/'runtime/el0_flat/memory.c'),str(ROOT/'tests/el0_flat_memory_host.c'),'-o',str(binary)],
                           check=True,capture_output=True,text=True)
            result=subprocess.run([str(binary)],check=True,capture_output=True,text=True)
            self.assertIn('live PTE changes',result.stdout)


@unittest.skipUnless(sys.platform=='linux' and platform.machine() in ('aarch64','arm64') and shutil.which('make'),
                     'native AArch64 Linux and make required')
class FlatGateway(unittest.TestCase):
    def test_register_restore_boundaries_and_recovery(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            subprocess.run(['make','-C',str(ROOT/'runtime/el0_flat'),'OUT='+str(root),
                            'CC='+('clang-19' if shutil.which('clang-19') else 'cc'),'check-gateway'],
                           check=True,capture_output=True,text=True,timeout=120)
            image=root/'gateway-check';elf=Elf(image);data=bytearray(elf.data)
            pc=next(s['value'] for s in elf.symbols if s['name']=='flat_probe_resume2')
            section=next(s for s in elf.sections if s['addr']<=pc<s['addr']+s['size'])
            offset=section['offset']+pc-section['addr'];word,=struct.unpack_from('<I',data,offset)
            # Corrupt the restore of a live guest register; the self-test must notice.
            struct.pack_into('<I',data,offset,(word&~(31<<10))|(31<<10))
            bad=root/'bad-restore';bad.write_bytes(data);bad.chmod(0o755)
            result=subprocess.run([str(bad)],capture_output=True,timeout=20)
            self.assertEqual(result.returncode,1)


if __name__=='__main__':unittest.main()
