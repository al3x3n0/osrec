"""Architecture-edge tests run the shared freestanding core on the host."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from source_image_el0 import BRK_SITE, NOP, Tables, instruction_ranges, rewrite, site_page_index


class EmulationCore(unittest.TestCase):
    @unittest.skipUnless(shutil.which('cc'), 'host C compiler required')
    def test_host_contracts(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = str(Path(tmp) / 'emulate')
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-I' + str(ROOT / 'runtime/el0'),
                            str(ROOT / 'runtime/el0/emulate.c'), str(ROOT / 'tests/el0_emulate_host.c'),
                            '-o', exe], check=True, capture_output=True, text=True)
            result = subprocess.run([exe], check=True, capture_output=True, text=True)
            self.assertIn('contracts passed', result.stdout)

    def test_instruction_edge(self):
        for insn in (0xd5384100, 0xd5182000, 0xd5034fdf, 0xd508871f, 0xd69f03e0, 0xd503207f):
            self.assertEqual(rewrite(insn)[0], BRK_SITE)
        for insn in (0xd503201f, 0xd5033fdf, 0xd53b4200, 0xd53bd040, 0xd65f03c0):
            self.assertEqual(rewrite(insn), (insn, None))
        for insn in (0xd503233f, 0xd50323bf, 0xd50320ff):
            self.assertEqual(rewrite(insn), (NOP, 'pac-hint'))

    def test_dczid_read_requires_a_captured_encodable_value(self):
        for rd in range(32):
            insn = 0xd53b00e0 | rd
            self.assertEqual(rewrite(insn, 4), (0xd2800080 | rd, 'inline sysreg'))
            self.assertEqual(rewrite(insn)[0], BRK_SITE)
            self.assertEqual(rewrite(insn, 0x10000)[0], BRK_SITE)
        self.assertEqual(rewrite(0xd53b4200, 4), (0xd53b4200, None))

    def test_kernel_tls_accesses_trap_when_the_slot_is_borrowed(self):
        for opcode in (0xd53bd040, 0xd51bd040):
            for rd in range(32):
                insn = opcode | rd
                self.assertEqual(rewrite(insn), (insn, None))
                self.assertEqual(rewrite(insn, shadow_tls=True), (BRK_SITE, 'sysreg'))

    def test_literal_pools_are_not_instruction_ranges(self):
        from types import SimpleNamespace
        image = SimpleNamespace(symbols=[dict(name='$x.0', value=0x1000),
                                         dict(name='$d.1', value=0x1008),
                                         dict(name='$x.2', value=0x1010)])
        self.assertEqual(instruction_ranges(image, [(0x1000, 0x1020)]),
                         [(0x1000, 0x1008), (0x1010, 0x1020)])
        with self.assertRaisesRegex(ValueError, 'mapping symbol'):
            instruction_ranges(image, [(0x2000, 0x3000)])

    def test_emulation_index_preserves_empty_pages_and_exact_end(self):
        self.assertEqual(site_page_index([]), (0, [0]))
        self.assertEqual(site_page_index([(0xc080000004, 1, 0), (0xc080000ffc, 2, 0),
                                          (0xc080002000, 3, 0)]),
                         (0xc080000000, [0, 2, 2, 3]))

    def test_upper_and_lower_mapping_paths(self):
        import struct
        for va in (0x40201000, 0xffff800080010000):
            t = Tables(48)
            t.map(va, 0x45678000, 0x740)
            node = t.root
            for shift in (39, 30, 21):
                d, = struct.unpack_from('<Q', t.pages[node], (va >> shift & 511) * 8)
                self.assertEqual(d & 3, 3)
                node = d & ~0xfff
            leaf, = struct.unpack_from('<Q', t.pages[node], (va >> 12 & 511) * 8)
            self.assertEqual(leaf, 0x45678743)


if __name__ == '__main__':
    unittest.main()
