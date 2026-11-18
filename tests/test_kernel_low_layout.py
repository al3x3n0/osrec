import json
import struct
import tempfile
import unittest
from pathlib import Path

from kernel_low_layout import audit, windows
from kernel_replay_tables import ADDRESS, PXN, TABLE_NO_EL0, TABLE_UXN, USER_ACCESS, UXN, build
from source_image import PAGE, Ram
from source_image_el0 import Tables


class KernelLowLayout(unittest.TestCase):
    def test_39_bit_windows_and_47_bit_bound(self):
        self.assertEqual(windows(39, 39, 47),
                         (0x8000000000, 0xffffff8000000000, 0x8000000000, 0x10000000000))
        for args in ((48, 48, 47), (39, 39, 39), (39, 39, 47, 0), (39, 39, 47, 0x8000001000)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                windows(*args)

    def test_live_tables_preserve_user_stack_and_shared_physical_page(self):
        base = 0x40000000
        code = 0xffffffc080001000
        kernel_stack = 0xffffff8000010000
        user_stack = 0x7fffffe000
        shared = base + 16 * PAGE
        ttbr0 = Tables(39, base)
        ttbr0.map(0x201000, shared + PAGE, 0)
        ttbr0.map(user_stack, shared, 0)
        ttbr1 = Tables(39, base + 8 * PAGE)
        ttbr1.map(code, shared + 2 * PAGE, 0)
        ttbr1.map(kernel_stack, shared, 0)
        memory = bytearray(24 * PAGE)
        for tables in (ttbr0, ttbr1):
            for pa, data in tables.pages.items():
                memory[pa-base:pa-base+PAGE] = data

        sysregs = dict(TCR_EL1=25 | (25 << 16) | (2 << 30), TTBR0_EL1=ttbr0.root,
                       TTBR1_EL1=ttbr1.root, SP_EL0=user_stack + PAGE, VBAR=code, ELR_EL1=0x201004)
        state = dict(cpu=dict(pc=code + 0x400, sp=kernel_stack + PAGE, sysregs=sysregs),
                     ram=dict(base=base, size=len(memory)))
        with tempfile.TemporaryDirectory() as directory:
            dump = Path(directory)
            (dump / 'state.json').write_text(json.dumps(state))
            (dump / 'ram.bin').write_bytes(memory)
            ram = Ram(dump)
            with ram.file, ram.ram:
                report = audit(ram)
                self.assertEqual(report['physical_pages_shared'], 1)
                self.assertEqual(report['user']['pages'], 2)
                self.assertEqual(report['kernel']['mapped_replay_range'], ['0x8000010000', '0xc080002000'])
                self.assertEqual(report['registers']['PC']['replay'], '0xc080001400')
                self.assertEqual(report['registers']['SP_EL0']['replay'], hex(user_stack + PAGE))
                self.assertEqual(report['registers']['SP_EL1']['probe_pa'], hex(shared + PAGE - 1))
                ram.sysregs['SP_EL0'] += 1
                with self.assertRaisesRegex(ValueError, 'TTBR0 mappings'):
                    audit(ram)

    def test_replay_root_reuses_user_tables_and_preserves_kernel_backing(self):
        base = 0x40000000
        code = 0xffffffc080000000
        readonly = 1 << 7
        table_readonly = 1 << 62
        ttbr0 = Tables(39, base)
        ttbr0.map(0x200000, base + 16 * PAGE, USER_ACCESS)
        ttbr1 = Tables(39, base + 8 * PAGE)
        ttbr1.map(code, base + 17 * PAGE, UXN | readonly)
        ttbr1.map(code + PAGE, base + 18 * PAGE, PXN | UXN)
        index = (code >> 30) & 511
        pmd = struct.unpack_from('<Q', ttbr1.pages[ttbr1.root], 8 * index)[0]
        struct.pack_into('<Q', ttbr1.pages[ttbr1.root], 8 * index,
                         pmd | TABLE_UXN | TABLE_NO_EL0 | table_readonly)
        struct.pack_into('<Q', ttbr1.pages[pmd & ADDRESS], 8, 0x9000000 | 1 | PXN | UXN)
        memory = bytearray(24 * PAGE)
        for tables in (ttbr0, ttbr1):
            for pa, data in tables.pages.items():
                memory[pa - base:pa - base + PAGE] = data
        target = base + len(memory)
        sysregs = dict(TCR_EL1=25 | (25 << 16) | (1 << 22) | (2 << 30) | (2 << 32),
                       TTBR0_EL1=ttbr0.root, TTBR1_EL1=(3 << 48) | ttbr1.root, MAIR_EL1=0xff)
        state = dict(cpu=dict(sysregs=sysregs), ram=dict(base=base, size=len(memory)))
        with tempfile.TemporaryDirectory() as directory:
            dump = Path(directory)
            (dump / 'state.json').write_text(json.dumps(state))
            (dump / 'ram.bin').write_bytes(memory)
            ram = Ram(dump)
            with ram.file, ram.ram:
                report, root = build(ram, target)
                device_report, device_root = build(ram, target, [(0x9000000, 0x9200000)])
                with self.assertRaisesRegex(ValueError, 'above the captured RAM'):
                    build(ram, base)
                with self.assertRaisesRegex(ValueError, 'straddles the device range'):
                    build(ram, target, [(0x9000000, 0x9000000 + PAGE)])
                self.assertEqual(ram.page(pmd & ADDRESS), ttbr1.pages[pmd & ADDRESS])

            wrapper = base + 12 * PAGE
            struct.pack_into('<QQ', memory, wrapper - base, ttbr0.root | 3, ttbr1.root | 3)
            sysregs.update(TCR_EL1=int(report['registers']['TCR_EL1'], 16),
                           TTBR0_EL1=(3 << 48) | wrapper, TTBR1_EL1=0)
            (dump / 'state.json').write_text(json.dumps(state))
            (dump / 'ram.bin').write_bytes(memory)
            ram = Ram(dump)
            with ram.file, ram.ram:
                shared_report, shared_root = build(ram, target)
            self.assertEqual(shared_report['capture_mode'], 'shared')
            self.assertEqual(shared_report['registers'], report['registers'])
            self.assertEqual(shared_root, root)

        self.assertEqual(struct.unpack_from('<QQ', root), (ttbr0.root | 3, target + PAGE | 3))
        self.assertEqual(report['ram_pages_el0'], 2)
        self.assertEqual(report['outside_ram_pages_el1'], 512)
        self.assertEqual(int(report['registers']['TTBR0_EL1'], 16), (3 << 48) | target)
        self.assertEqual(report['registers']['TTBR1_EL1'], '0x0')
        new_pmd = struct.unpack_from('<Q', root, PAGE + 8 * index)[0]
        self.assertEqual(new_pmd & ~ADDRESS, table_readonly | 3)
        pmd_offset = (new_pmd & ADDRESS) - target
        code_table, device_block = struct.unpack_from('<QQ', root, pmd_offset)
        self.assertEqual(device_block, 0x9000000 | 1 | PXN | UXN)
        self.assertEqual(device_report['device_pages_el0'], 512)
        self.assertEqual(device_report['outside_ram_pages_el1'], 0)
        self.assertEqual(struct.unpack_from('<Q', device_root, pmd_offset + 8)[0], device_block | USER_ACCESS)
        self.assertEqual(struct.unpack_from('<QQ', root, (code_table & ADDRESS) - target),
                         ((base + 17 * PAGE) | 3 | USER_ACCESS | readonly,
                          (base + 18 * PAGE) | 3 | USER_ACCESS | PXN | UXN))
