"""Audit current EL0 executor admission without a captured kernel fixture."""
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from audit_el0_image import audit
from kernel_source_verify import Elf

LLVM=Path(os.environ.get('OSREC_LLVM16_BIN','/opt/homebrew/opt/llvm@16/bin'))
SOURCE='''
.text
.global _start,guest_block,flat_completed
_start:
    b guest_block
guest_block:
    nop
    b flat_completed
flat_completed:
    mov x8,#93
    svc #0
.bss
.balign 16
.global flat_full_result
.type flat_full_result,%object
flat_full_result:
    .space 320
.size flat_full_result,.-flat_full_result
'''


@unittest.skipUnless((LLVM/'llvm-mc').is_file() and (LLVM/'ld.lld').is_file(),
                     'AArch64 llvm-mc and ld.lld required')
class ImageAudit(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);(self.root/'image.S').write_text(SOURCE)
        subprocess.run([str(LLVM/'llvm-mc'),'-triple=aarch64-linux-gnu','-filetype=obj',
                        str(self.root/'image.S'),'-o',str(self.root/'image.o')],check=True,capture_output=True)
        self.image=self.root/'checkpoint'
        subprocess.run([str(LLVM/'ld.lld'),'-static','-e','_start',str(self.root/'image.o'),
                        '-o',str(self.image)],check=True,capture_output=True)
        self.elf=Elf(self.image)

    def mutate_word(self,symbol,word,displacement=0):
        pc=next(s['value'] for s in self.elf.symbols if s['name']==symbol)+displacement
        section=next(s for s in self.elf.sections if s['addr']<=pc<s['addr']+s['size'])
        data=bytearray(self.elf.data)
        struct.pack_into('<I',data,section['offset']+pc-section['addr'],word)
        target=self.root/'changed';target.write_bytes(data);return target

    def test_complete_executor_contract(self):
        checked=audit(self.image)
        self.assertEqual((checked['runtime_el'],checked['result_bytes']),(0,320))
        self.assertEqual(len(checked['terminal_exit_sites']),1)
        self.assertFalse(checked['libc']);self.assertFalse(checked['host_signals'])

    def test_privileged_register_and_nonterminal_syscall_rejected(self):
        for word,message in [(0xd5384240,'system register'),(0xd4000001,'trap/service')]:
            with self.subTest(word=hex(word)),self.assertRaisesRegex(ValueError,message):
                audit(self.mutate_word('guest_block',word))

    def test_missing_terminal_syscall_rejected(self):
        with self.assertRaisesRegex(ValueError,'exactly one terminal exit'):
            audit(self.mutate_word('flat_completed',0xd503201f,4))

    def test_dynamic_loader_segment_rejected(self):
        data=bytearray(self.elf.data);phoff,=struct.unpack_from('<Q',data,32)
        struct.pack_into('<I',data,phoff,3)
        target=self.root/'dynamic';target.write_bytes(data)
        with self.assertRaisesRegex(ValueError,'dynamic loader'):
            audit(target)


if __name__=='__main__':unittest.main()
