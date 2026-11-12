"""Hardware alias admission and executable inline fast/slow-path contracts."""
import os
from pathlib import Path
import platform
import json
import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from el0_flat_lower import decode, STACK
from el0_hardware import direct_ranges, memory_path, stack_path


class Ranges(unittest.TestCase):
    def test_hardware_executor_cannot_receive_a_software_load_plan(self):
        from check_el0_program import make_load_plan
        with self.assertRaisesRegex(ValueError, 'hardware load plan'):
            make_load_plan({'memory_backend': 'hardware-kernel'})

    def test_devices_unbacked_pages_and_all_code_alias_writes_are_excluded(self):
        attrs = 1 << 10
        mappings = [(0x10000, 0x4000, 0x3000, attrs),
                    (0x20000, 0x5000, 0x1000, attrs),
                    (0x30000, 0x7000, 0x1000, attrs | (1 << 7)),
                    (0x40000, 0x9000000, 0x1000, attrs),
                    (0x50000, 0x8000, 0x1000, attrs),
                    (0x60000, 0x4000, 0x1000, 0)]
        aliases, reads, writes = direct_ranges(mappings, 0x4000, 0x4000, [(0x5000, 0x1000)])
        self.assertEqual(len(aliases), 3)
        self.assertEqual(reads, [(0x10000, 0x13000), (0x20000, 0x21000), (0x30000, 0x31000)])
        self.assertEqual(writes, [(0x10000, 0x11000), (0x12000, 0x13000)])

    def test_explicit_user_accesses_keep_permission_checked_software_path(self):
        self.assertEqual(memory_path(0x1000, decode(0xf8400820), '.Lnext'), '')


@unittest.skipUnless(platform.machine() in ('aarch64', 'arm64') and sys.platform == 'linux' and
                     (shutil.which('clang-19') or shutil.which('clang')), 'native AArch64 Linux compiler required')
class Execution(unittest.TestCase):
    def test_scalar_vector_register_offset_sp_flags_and_slow_paths(self):
        cases = [
            (0xf9400020, 0, False, 'cmp x0,#123\nb.ne fail'), # ldr x0,[x1]
            (0xf9000030, 0, False, 'ldr x0,[x1]\ncmp x0,#116\nb.ne fail'), # str x16,[x1]
            (0xb862d820, 0, False, 'cmp x0,#456\nb.ne fail'), # ldr w0,[x1,w2,sxtw #2]
            (0x3dc00020, 0, False, 'umov x0,v0.d[0]\ncmp x0,#123\nb.ne fail'),
            (0xa9400820, 0, False, 'cmp x0,#123\nb.ne fail\nldr x0,[x1,#8]\ncmp x0,x2\nb.ne fail'),
            (0xf94003e0, 0, False, 'cmp x0,#123\nb.ne fail'), # logical SP
            (0xf8008c30, 0, False, 'ldr x0,[x1]\ncmp x0,#116\nb.ne fail'), # pre-index store
            (0xa8c10820, 0, False, 'cmp x0,#123\nb.ne fail\ncmp x2,#456\nb.ne fail'), # post-index pair
            (0x910003e0, 0, False, 'cmp x0,x1\nb.ne fail'), # mov x0,sp
            (0xd10043ff, 0, False, 'ldr x0,[x5]\nadd x0,x0,#16\ncmp x0,x1\nb.ne fail'), # sub sp,sp,#16
            (0xf9400020, 0, True, ''), # user mode must use software
            (0xf9400020, 60, False, ''), # crossing the end is not admitted
        ]
        source = '.text\n.global _start\n_start:\nadrp x0,stack_end\nadd x0,x0,:lo12:stack_end\nmov sp,x0\n'
        for i, (word, offset, user, checks) in enumerate(cases):
            slow_expected = user or offset != 0
            source += '''adrp x1,testdata
add x1,x1,:lo12:testdata
adrp x5,control
add x5,x5,:lo12:control
str x1,[x5]
mov x0,#123
str x0,[x1]
mov x0,#456
str w0,[x1,#8]
mov x0,#0
mov x2,#2
mov x16,#116
mov x17,#117
mov x15,#115
mov x14,#114
adrp x3,flat_shadow
add x3,x3,:lo12:flat_shadow
mov x4,#%d
str x4,[x3,#80]
add x1,x1,#%d
cmp xzr,xzr
''' % (not user, offset)
            op = decode(word)
            if op.kind == STACK:
                source += stack_path(op) + 'b .Lgood%d\n' % i
            else:
                source += memory_path(0x1000 + i * 4, op, '.Lgood%d' % i)
            source += 'b .Lslow%d\n.Lgood%d:\n' % (i, i)
            source += 'b fail\n' if slow_expected else 'b .Lchecked%d\n' % i
            source += '.Lslow%d:\n' % i
            source += 'b fail\n' if not slow_expected else 'b .Lchecked%d\n' % i
            source += '.Lchecked%d:\nb.ne fail\n' % i
            source += checks + '\n'
            source += 'cmp x16,#116\nb.ne fail\ncmp x17,#117\nb.ne fail\ncmp x15,#115\nb.ne fail\ncmp x14,#114\nb.ne fail\n'
        source += '''mov x0,#0
mov x8,#93
svc #0
fail:
mov x0,#1
mov x8,#93
svc #0
.data
.balign 16
flat_shadow: .zero 88
flat_active: .quad control
control: .quad testdata
flat_direct_read: .quad testdata,testdata+64,0,0
flat_direct_write: .quad testdata,testdata+32,0,0
testdata: .zero 64
.bss
.balign 16
.space 16384
stack_end:
'''
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            (path / 'test.S').write_text(source)
            subprocess.run([shutil.which('clang-19') or shutil.which('clang'), '-nostdlib', '-static',
                            '-fuse-ld=lld', '-Wl,-e,_start', str(path / 'test.S'), '-o', str(path / 'test')],
                           check=True, capture_output=True)
            subprocess.run([str(path / 'test')], check=True, timeout=10)


@unittest.skipUnless(os.environ.get('OSREC_EL0_HARDWARE_IMAGE') and os.environ.get('OSREC_EL0_HARDWARE_PREPARED'),
                     'set hardware image and prepared paths for the complete QEMU workload')
class FullCheckpoint(unittest.TestCase):
    def test_complete_workload_without_hardware_fault_services(self):
        from el0_hardware_model import run
        with tempfile.TemporaryDirectory() as folder:
            result = run(os.environ['OSREC_EL0_HARDWARE_IMAGE'], os.environ['OSREC_EL0_HARDWARE_PREPARED'], Path(folder) / 'run')
        self.assertTrue(result['verified'], result)
        self.assertEqual(result['hardware_exceptions'], 0)
        self.assertEqual((result['result']['events'], result['result']['counters'], result['result']['uart_bytes']), (2272, 9, 92))
        self.assertLess(result['result']['transitions'], 2261577)

    def test_missing_kernel_alias_stops_instead_of_using_el1_services(self):
        from el0_hardware_model import run
        prepared = Path(os.environ['OSREC_EL0_HARDWARE_PREPARED'])
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            plan = json.loads((prepared / 'hardware-load-plan.json').read_text())
            tables = bytearray((prepared / 'page-tables.bin').read_bytes())
            # Remove the captured kernel linear-map subtree. Identity mappings
            # of the executor/result remain available to report the failure.
            import struct
            struct.pack_into('<Q', tables, 8 * (0x200000000000 >> 39), 0)
            (root / 'page-tables.bin').write_bytes(tables)
            plan['page_tables']['sha256'] = hashlib.sha256(tables).hexdigest()
            (root / 'hardware-load-plan.json').write_text(json.dumps(plan))
            shutil.copyfile(prepared / 'setup.elf', root / 'setup.elf')
            result = run(os.environ['OSREC_EL0_HARDWARE_IMAGE'], root, root / 'run')
        self.assertFalse(result['verified'])
        self.assertEqual(result['hardware_exceptions'], 1)


if __name__ == '__main__':
    unittest.main()
