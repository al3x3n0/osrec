"""EL0 native gateway, software memory and target instruction audits."""
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from check_el0_flat import audit,run
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


@unittest.skipUnless(os.environ.get('OSREC_FLAT_IMAGE'),'set OSREC_FLAT_IMAGE for built-image tests')
class FlatImage(unittest.TestCase):
    def setUp(self):self.image=Path(os.environ['OSREC_FLAT_IMAGE']).resolve()
    def mutated(self,path,symbol,transform):
        data=bytearray((self.image/'checkpoint').read_bytes());elf=Elf(self.image/'checkpoint')
        pc=next(s['value'] for s in elf.symbols if s['name']==symbol)
        section=next(s for s in elf.sections if s['addr']<=pc<s['addr']+s['size'])
        offset=section['offset']+pc-section['addr'];word,=struct.unpack_from('<I',data,offset)
        struct.pack_into('<I',data,offset,transform(word));path.write_bytes(data);path.chmod(0o755)
    def test_image_audit_rejects_privilege_and_atomic_changes(self):
        checked=audit(self.image/'checkpoint');self.assertEqual(checked['runtime_el'],0)
        self.assertEqual(len(checked['terminal_exit_sites']),1)
        with tempfile.TemporaryDirectory() as name:
            bad=Path(name)/'checkpoint'
            self.mutated(bad,'flat_capture_rest',lambda word:0xd5384240) # MRS CurrentEL
            with self.assertRaisesRegex(ValueError,'system register'):audit(bad)
            self.mutated(bad,'umask_atomic_body',lambda word:0xd503201f)
            with self.assertRaisesRegex(ValueError,'exclusive sequence'):audit(bad)
    @unittest.skipUnless(os.environ.get('OSREC_FLAT_NATIVE'),'set OSREC_FLAT_NATIVE=1 for native execution')
    def test_el0_execution_and_broken_register_restore(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            report=run(self.image,root/'positive',timeout=20)
            self.assertTrue(report['verified']);self.assertEqual(report['result']['calls'],6)
            bad=root/'bad';bad.mkdir()
            self.mutated(bad/'checkpoint','flat_probe_resume2',lambda word:(word&~(31<<10))|(31<<10))
            with self.assertRaisesRegex(ValueError,'checkpoint failed'):run(bad,root/'negative',timeout=20)
            observed=json.loads((root/'negative/validation.json').read_text())
            self.assertEqual(observed['result']['status'],2)


if __name__=='__main__':unittest.main()
