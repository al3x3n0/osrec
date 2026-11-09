import shutil
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from aarch64_liveness import ALL, NZCV, reg
from source_image_calls import FIELDS, analyse_sites, assembly, branch, choose_base, plan, sysreg
NATIVE_CC = shutil.which('clang-19') or shutil.which('clang')


def mrs(key, rt=0):
    return 0xd5200000 | key << 5 | rt


def msr(key, rt=0):
    return 0xd5000000 | key << 5 | rt


class Calls(unittest.TestCase):
    def test_live_scratch_is_spilled_outside_checkpoint_stack(self):
        v = plan(0x1000, mrs(sysreg(3, 0, 4, 1, 0)))
        self.assertEqual(v.address, 0)
        self.assertEqual(v.saves, reg(v.temporary))
        self.assertEqual(v.report()['stack_bytes'], 0)
        source = assembly([v])
        self.assertNotIn('sp,', source)
        self.assertNotIn('nzcv', source)
        self.assertIn('str x16, [x0]', source)

    def test_dead_scratch_needs_no_save(self):
        v = plan(0x1000, mrs(sysreg(3, 0, 4, 1, 0)), ALL & ~reg(16))
        self.assertEqual(v.saves, 0)
        self.assertNotIn('str x16, [x0]\n', assembly([v]))

    def test_write_requires_dead_address_register_and_keeps_input(self):
        op = msr(sysreg(3, 0, 4, 0, 1), 16)
        self.assertIsNone(plan(0x1000, op))
        self.assertIsNone(plan(0x1000, op, ALL & ~reg(16)))
        v = plan(0x1000, op, ALL & ~reg(17))
        self.assertNotIn(16, (v.address, v.temporary))

    def test_fault_observer_prevents_dead_write_scratch(self):
        op = msr(sysreg(3, 0, 4, 0, 1))
        words = {4: 0xf9400021, 8: 0xd2800010}  # load can fault before mov x16
        self.assertEqual(analyse_sites([(0, op, 0)], words), [])

    def test_analysis_drives_save_set_and_honours_lowering_metadata(self):
        op = mrs(sysreg(3, 0, 4, 1, 0))
        words = {4: 0xd2800010, 8: 0}
        self.assertEqual(analyse_sites([(0, op, 0)], words)[0].saves, 0)
        self.assertEqual(analyse_sites([(0, op, 1)], words), [])
        shifted = analyse_sites([(0x1000, op, 0)], words, lambda pc: pc - 0x1000)
        self.assertEqual(shifted[0].pc, 0x1000)
        self.assertEqual(shifted[0].saves, 0)

    def test_read_discarded_result_can_use_dead_scratch(self):
        op = mrs(sysreg(3, 0, 4, 1, 0), 31)
        self.assertIsNone(plan(0, op))
        self.assertEqual(len(analyse_sites([(0, op, 0)], {4: 0xd2800010, 8: 0})), 1)

    def test_lowering_stop_is_an_observer_before_original_kill(self):
        op = mrs(sysreg(3, 0, 4, 1, 0))
        words = {4: 0xd2800010, 8: 0}  # normally kills x16
        self.assertEqual(analyse_sites([(0,op,0)],words)[0].saves,0)
        guarded = analyse_sites([(0,op,0),(4,words[4],0x20000000)],words)
        self.assertEqual(guarded[0].saves,reg(16))

    def test_no_platform_or_unknown_operations_are_inlined(self):
        for op in (msr(sysreg(3, 0, 2, 0, 0)), mrs(0xffff),
                   msr(sysreg(3, 0, 4, 2, 2)), 0xd69f03e0, 0xd508871f):
            self.assertIsNone(plan(0, op, 0))

    def test_branch_limits_and_occupied_windows(self):
        self.assertEqual(branch(0x1000, 0x1008), 0x14000002)
        self.assertEqual(branch(0x1000, 0x0ff8), 0x17fffffe)
        for target in (0x1001, 0x1000 + (1 << 27)):
            with self.assertRaises(ValueError): branch(0x1000, target)
        v = plan(0xffff800080000000, mrs(sysreg(3, 0, 4, 1, 0)))
        base, size = choose_base([(0xffff800086000000, 0, 0)], [v], v.pc)
        self.assertEqual(base, 0xffff800086400000)
        self.assertEqual(size, 4 * len(v.instructions('end')))

    @unittest.skipUnless(Path('/opt/homebrew/opt/llvm@16/bin/clang').exists(), 'cross LLVM required')
    def test_every_supported_form_assembles(self):
        compiler = '/opt/homebrew/opt/llvm@16/bin/clang'
        veneers = []
        for key in FIELDS:
            for op in (mrs(key), mrs(key, 31), msr(key), msr(key, 31)):
                v = plan(0x1000, op, 0)
                if v is not None: veneers.append(v)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'veneers.S'
            source.write_text(assembly(veneers))
            subprocess.run([compiler, '--target=aarch64-none-elf', '-c', str(source),
                            '-o', str(Path(directory) / 'veneers.o')], check=True,
                           capture_output=True, text=True)

    @unittest.skipUnless(sys.platform=='linux' and platform.machine() in ('aarch64','arm64')
                         and NATIVE_CC, 'native arm64 Linux and clang required')
    def test_native_against_full_context_reference(self):
        from el0_calls_fixture import emit
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            emit(out)
            exe = out / 'test'
            subprocess.run([NATIVE_CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-mgeneral-regs-only', '-mbranch-protection=none', '-no-pie',
                            '-I'+str(ROOT/'runtime/el0'), '-I'+str(out),
                            str(ROOT/'runtime/el0/emulate.c'), str(ROOT/'tests/el0_calls_host.c'),
                            str(out/'fixtures.S'), '-o', str(exe)], check=True, capture_output=True, text=True)
            result = subprocess.run([str(exe)], check=True, capture_output=True, text=True, timeout=120)
            self.assertIn('5888 native veneer/full-save comparisons passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
