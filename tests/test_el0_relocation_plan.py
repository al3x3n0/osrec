import unittest
from types import SimpleNamespace
from el0_relocation_plan import CompactBacking
from export_el0_program import captured_kernel_words


class CompactLayoutTests(unittest.TestCase):
    def layout(self, second_pa=0x401000):
        return CompactBacking(0x400000, 0x4000, 0x10000000, [
            dict(va=0x1000, pa=0x400000, bytes=4096),
            dict(va=0x2000, pa=second_pa, bytes=4096),
            dict(va=0xffffc39f7000, pa=0x400000, bytes=4096)])

    def test_alias_identity_and_cross_page_access(self):
        p = self.layout()
        self.assertEqual(p.resolve(0xffffc39f7000), 0x10000000)
        self.assertEqual(p.resolve(0x1000), p.resolve(0xffffc39f7000))
        self.assertEqual(p.resolve(0x1ffc, 8), 0x10000ffc)
        self.assertIsNone(self.layout(0x403000).resolve(0x1ffc, 8))
        self.assertIsNone(p.resolve(0x2ffc, 8))

    def test_missing_and_overflow_addresses_are_not_truncated(self):
        p = self.layout()
        for address, size in [(0, 1), (-1, 1), (0x1000, 0),
                              (0xffffffffffffffff, 2), (0xffffffffc39f7000, 1)]:
            self.assertIsNone(p.resolve(address, size))
        self.assertFalse(p.report()['executable'])
        self.assertEqual(p.report()['ram_bytes'], 0x4000)

    def test_overlaps_and_invalid_backing_are_rejected(self):
        with self.assertRaises(ValueError):
            CompactBacking(0x400000, 0x4000, 1 << 48, [])
        with self.assertRaises(ValueError):
            CompactBacking(0x400000, 0x4000, 0x10000000,
                           [dict(va=0x1000, pa=0x400000, bytes=8192),
                            dict(va=0x2000, pa=0x402000, bytes=4096)])


    def test_host_page_projection_coalesces_only_identical_shared_backing(self):
        def alias(va, pa, size, attrs):
            return dict(va=va, pa=pa, bytes=size, attrs=attrs, domain='kernel')

        rw = 1 << 53
        ro = rw | 1 << 7
        aliases = [alias(0x10000, 0x400000, 0x8000, rw),
                   alias(0x18000, 0x408000, 0x1000, rw),
                   alias(0x19000, 0x40e000, 0x1000, rw),
                   alias(0x1a000, 0x40a000, 0x2000, ro),
                   alias(0x1c000, 0x40c000, 0x1000, rw),
                   alias(0x24000, 0x404000, 0x4000, rw)]
        projection = CompactBacking(0x400000, 0x10000, 0x10000000, aliases).host_page_projection(
            0x4000, 0x10000, 0x24000)
        self.assertFalse(projection['initial_ram_representable'])
        self.assertEqual(projection['compatible_captured_pages'], 8)
        self.assertEqual(projection['blocked_captured_pages'], 9)
        self.assertEqual(projection['host_alias_candidates'],
                         [dict(va=0x10000, backing=0x10000000, bytes=0x8000, flags=6)])
        self.assertEqual([row['reasons'] for row in projection['blocked_ranges']],
                         [['incompatible-backing', 'incompatible-permissions'],
                          ['partially-mapped-host-page'],
                          ['outside-host-address-window']])


class WholeCodeTests(unittest.TestCase):
    def test_unseeded_code_and_symbol_gaps_are_included_but_literals_are_not(self):
        code = SimpleNamespace(extent=lambda f: (f, f+16))
        package = SimpleNamespace(word=lambda pc: pc ^ 0x12345678)
        executable = [(0x1000, 0x1008), (0x1010, 0x1018), (0x2000, 0x2004)]
        selected = captured_kernel_words(package, code, {0x1000}, executable)
        whole = captured_kernel_words(package, code, {0x1000}, executable, True)
        self.assertEqual(set(selected), {0x1000, 0x1004})
        self.assertEqual(set(whole), {0x1000, 0x1004, 0x1010, 0x1014, 0x2000})
        self.assertEqual(whole[0x2000], package.word(0x2000))

    def test_missing_capture_is_an_error_in_whole_code_mode(self):
        def missing(pc):
            raise ValueError('missing')
        code = SimpleNamespace(extent=lambda f: (f, f+4))
        package = SimpleNamespace(word=missing)
        self.assertEqual(captured_kernel_words(package, code, {0x1000}, [(0x1000, 0x1004)]), {})
        with self.assertRaisesRegex(ValueError, 'absent from capture'):
            captured_kernel_words(package, code, set(), [(0x1000, 0x1004)], True)
        absent=[]
        self.assertEqual(captured_kernel_words(package, code, set(), [(0x1000, 0x1008)], True, absent), {})
        self.assertEqual(absent, [[0x1000, 0x1008]])
