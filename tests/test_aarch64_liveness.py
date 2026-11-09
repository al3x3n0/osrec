"""Soundness cases for reducing the future emulation-veneer save set."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from aarch64_liveness import ALL, NZCV, SIMD, SP, effect, live_after, names, preservation_mask, reg


class Liveness(unittest.TestCase):
    def analyse(self, *words, **kwargs):
        return live_after({4 * (i + 1): w for i, w in enumerate(words)}, 0, **kwargs)

    def test_overwrite_and_w_alias(self):
        for mov in (0xd2800020, 0x52800020):  # mov x0/w0, #1
            self.assertEqual(self.analyse(mov), ALL & ~reg(0))

    def test_movk_needs_old_value(self):
        self.assertEqual(self.analyse(0xf2800020), ALL)

    def test_unknown_call_has_no_abi_assumptions(self):
        self.assertEqual(self.analyse(0x94000010), ALL & ~reg(30))
        self.assertEqual(self.analyse(0xd63f0200), ALL)  # BLR: conservative

    def test_unknown_and_faults_observe_full_context(self):
        for first in (0x00000000, 0xf9400021, 0xd65f03c0, 0xd69f03e0):
            self.assertEqual(self.analyse(first, 0xd2800000), ALL)

    def test_flag_kill_and_use(self):
        self.assertFalse(self.analyse(0xf100003f) & NZCV)  # cmp x1, #0
        self.assertTrue(self.analyse(0x54000040, 0xf100003f) & NZCV)
        self.assertFalse(self.analyse(0xd51b4200) & NZCV)  # msr nzcv,x0
        self.assertTrue(self.analyse(0xd53b4200) & NZCV)   # mrs x0,nzcv

    def test_all_paths_must_overwrite(self):
        # cbz x1,+8; mov x0,#0; unknown exit (taken path preserves x0)
        self.assertTrue(self.analyse(0xb4000041, 0xd2800000, 0) & reg(0))
        # Both arms overwrite x0 before joining the exit at address 24.
        code = {4: 0xb4000061, 8: 0xd2800000, 12: 0x14000003,
                16: 0xd2800020, 20: 0xd503201f, 24: 0}
        self.assertFalse(live_after(code, 0) & reg(0))

    def test_loop_reaches_fixed_point(self):
        # mov x0,#0; cbnz x1,-4; unknown exit
        self.assertEqual(self.analyse(0xd2800000, 0xb5ffffe1, 0), ALL & ~reg(0))

    def test_unknown_target_and_budget(self):
        self.assertEqual(self.analyse(0x14000100), ALL)
        self.assertEqual(self.analyse(0xd2800000, max_instructions=1), ALL)

    def test_sp_zero_register_and_flags(self):
        # add sp,sp,#16 reads the old SP; add x0,sp,#16 kills x0, not SP.
        self.assertEqual(effect(4, 0x910043ff).uses, SP)
        self.assertEqual(effect(4, 0x910043ff).defines, SP)
        self.assertEqual(effect(4, 0x910043e0).defines, reg(0))
        self.assertEqual(effect(4, 0xf100003f).defines, NZCV)

    def test_invalid_encodings_are_not_kills(self):
        for word in (0x52c00000, 0x32800000, 0x0bc00000, 0x0b008000):
            self.assertEqual(effect(4, word).uses, ALL)
            self.assertEqual(effect(4, word).defines, 0)

    def test_saves_intersect_live_and_actual_clobbers(self):
        clobbers = reg(0) | reg(1) | reg(30) | NZCV
        live = ALL & ~reg(30) & ~NZCV
        self.assertEqual(preservation_mask(live, clobbers, reg(0)), reg(1))
        self.assertTrue(live & SIMD)  # no accidental ABI-based FP kills
        self.assertEqual(names(reg(30) | NZCV), ['x30', 'nzcv'])


if __name__ == '__main__':
    unittest.main()
