"""Architecture-edge tests run the shared freestanding core on the host."""
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from source_image_el0 import (BRK_SITE, NOP, Tables, fixed_system_reads,
                             instruction_ranges, reserve_load_ranges, rewrite, site_page_index)
from va_constants import bitmask, move_immediate


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
        key = (0xd53b00e0 >> 5) & 0xffff
        for rd in range(32):
            insn = 0xd53b00e0 | rd
            self.assertEqual(rewrite(insn, {key: move_immediate(4)}), (0xd2800080 | rd, 'inline sysreg'))
            self.assertEqual(rewrite(insn)[0], BRK_SITE)
        self.assertEqual(rewrite(0xd51b00e0, {key: move_immediate(4)}), (BRK_SITE, 'sysreg'))

    def test_constant_read_proof_excludes_mutable_registers(self):
        cpu = {'sysregs': {'TPIDR_EL1': 0, 'DCZID_EL0': 4},
               'sysregs_all': {'CurrentEL': 0, 'DAIF': 0, 'SP_EL0': 0, 'CNTVCT_EL0': 0,
                               'ID_AA64PFR0_EL1': 0x22, 'DCZID_EL0': 0}}
        self.assertEqual(fixed_system_reads(cpu), {'CurrentEL': 4, 'DCZID_EL0': 4, 'ID_AA64PFR0_EL1': 0x22})

    def test_single_move_encodings_and_discarded_destination(self):
        self.assertEqual(move_immediate(0x123400000000), 0xd2c24680)
        self.assertEqual(move_immediate(0xffffedcbffffffff), 0x92c24680)
        self.assertEqual(move_immediate(0xffff1234), 0x129db960)
        self.assertIsNone(move_immediate(0x12345678))
        self.assertIsNone(move_immediate(0xffffffbf9fcbd000))
        key = (0xd53b00e0 >> 5) & 0xffff
        for value in (0xff00ff00, 0xff00ff00ff00ff):
            word = move_immediate(value)
            width = 64 if word & (1 << 31) else 32
            actual = bitmask((word >> 22) & 1, (word >> 16) & 63, (word >> 10) & 63)
            self.assertEqual(actual & ((1 << width) - 1), value)
            self.assertEqual(rewrite(0xd53b00ff, {key: word}), (NOP, 'inline sysreg'))

    def test_kernel_tls_accesses_trap_when_the_slot_is_borrowed(self):
        for opcode in (0xd53bd040, 0xd51bd040):
            for rd in range(32):
                insn = opcode | rd
                self.assertEqual(rewrite(insn), (insn, None))
                self.assertEqual(rewrite(insn, shadow_tls=True), (BRK_SITE, 'sysreg'))

    def test_profile_counts_veneers_as_kernel_payload(self):
        from source_image_profile import summarize
        result = summarize((0,) * 14 + (12, 23, 3, 20, 3, 5))
        self.assertEqual(result, dict(total=38, kernel_payload=23, user=3, kernel_visits=20,
                                      branch_veneer=5, trapping_kernel_sites=2, monitor=10, runtime=12))

    def test_elf_load_ranges_cover_zero_pages_without_file_padding(self):
        from el0_instruction_profile import segments
        from kernel_boundary_replay import elf
        from source_image_load import LoadMap
        runs = [(0x2000, b'abc'), (0x4000, b'def'), (0x9000, b'entry')]
        loads = reserve_load_ranges(runs, [(0x1000, 0x6000), (0x9000, 0xb000)])
        raw = elf(loads, 0x9000)
        self.assertEqual(struct.unpack_from('<Q', raw, 24)[0], 0x9000)
        headers = segments(raw)
        self.assertEqual([(row[4], row[5], row[6]) for row in headers],
                         [(0x1000, 0, 0x1000), (0x2000, 3, 0x2000),
                          (0x4000, 3, 0x2000), (0x9000, 5, 0x2000)])
        for (_, _, off, va, pa, size, _, align), (_, data, _) in zip(headers, loads):
            self.assertEqual(va, pa)
            self.assertEqual(off % align, va % align)
            self.assertEqual(raw[off:off + size], data)
        layout = LoadMap(raw)
        layout.require(0x1000, 0x5000, 'guest RAM')
        with self.assertRaisesRegex(ValueError, 'guest RAM.*not fully mapped'):
            layout.require(0x1000, 0x6000, 'guest RAM')
        with self.assertRaisesRegex(ValueError, 'boot data.*not fully file-backed'):
            layout.require(0x2000, 4, 'boot data', initialized=True)

    def test_elf_preflight_rejects_bad_headers_and_uninitialized_entry(self):
        from kernel_boundary_replay import elf
        from source_image_load import LoadMap
        with self.assertRaisesRegex(ValueError, 'ELF entry.*not fully file-backed'):
            LoadMap(elf([(0x1000, b'', 4096)], 0x1000))
        raw = bytearray(elf([(0x1000, b'abcd', 4096)], 0x1000))
        struct.pack_into('<Q', raw, 64 + 8, 4097)  # unaligned p_offset
        with self.assertRaisesRegex(ValueError, 'invalid segment-only PT_LOAD'):
            LoadMap(raw)

    def test_elf_preflight_requires_runtime_tables_and_veneer_backing(self):
        from types import SimpleNamespace
        from kernel_boundary_replay import elf
        from source_image_load import LoadMap, audit_tables, audit_veneers

        tables = Tables(47)
        code, spill, va = 0x71000000, 0x72000000, 0xc086000000
        tables.map(va, code, 0)
        tables.map(va + 4096, spill, 0)
        tables.map(va + 8192, spill + 4096, 0)
        runs = [(pa, bytes(data)) for pa, data in tables.pages.items()]
        runs += [(code, bytes(4096)), (spill, bytes(8192)), (0x74000000, bytes(4096))]
        entry = 0x74000000
        image = SimpleNamespace(sections=[dict(name='.osrec.veneer.text', addr=va, size=4)])
        roots = tables.root, tables.root
        layout = LoadMap(elf(runs, entry))
        self.assertEqual(audit_tables(layout, roots), len(tables.pages))
        self.assertEqual(audit_veneers(image, layout, roots, spill), 4)

        partial = LoadMap(elf([(pa, data) for pa, data in runs if pa != code], entry))
        with self.assertRaisesRegex(ValueError, 'veneer code.*not fully file-backed'):
            audit_veneers(image, partial, roots, spill)
        missing = max(tables.pages)
        partial = LoadMap(elf([(pa, data) for pa, data in runs if pa != missing], entry))
        with self.assertRaisesRegex(ValueError, 'TTBR0 level-3 table.*not fully file-backed'):
            audit_tables(partial, roots)

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
