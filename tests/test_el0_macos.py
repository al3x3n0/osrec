"""Execute a checked, self-contained ELF on an Apple Silicon vCPU."""
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from el0_macos import (DEFAULT_LOADER, EVENT, HOST_ALIAS, MAPPING_GATE_CODE, MAPPING_WINDOW,
                       UACCESS_PAIR, check_ram_preload, host_aliases, host_mapping_gate, host_uaccess_table,
                       run, verify_event_log)
from el0_macos_native import DEFAULT_LOADER as NATIVE_LOADER, load_command as native_command, run as run_native
from kernel_source_verify import Elf
from pretranslate_el0_image import file_offset


class RamPreload(unittest.TestCase):
    def test_canonical_ram_loads_cover_sparse_bank_and_packed_payload(self):
        elf = SimpleNamespace(data=bytes(64), sections=[dict(type=1, addr=0x1000, offset=0x100, size=8192)],
                              read=lambda address, size: struct.pack('<Q', 1))
        symbols = dict(flat_elf_ram_initialization=dict(value=0x1000, shndx=0),
                       flat_phys=dict(value=0x8000, size=12288), flat_payload=dict(value=0x2000, size=4096))
        segments = [
            dict(address=address, file_offset=offset, file_bytes=file_bytes, memory_bytes=4096, flags=6)
            for address, offset, file_bytes in [(0x8000, 0, 0), (0x9000, 0x1100, 4096), (0xa000, 0, 0)]
        ]
        self.assertTrue(check_ram_preload(elf, symbols, segments))
        with self.assertRaisesRegex(ValueError, 'cover the ELF snapshot'):
            check_ram_preload(elf, symbols, segments[:-1])
        with self.assertRaisesRegex(ValueError, 'packed ELF snapshot'):
            check_ram_preload(elf, symbols, [segments[0], dict(segments[1], file_offset=0x1200), segments[2]])
        with self.assertRaisesRegex(ValueError, 'not initialized'):
            check_ram_preload(elf, symbols, [dict(segments[0], address=0x7000, memory_bytes=16384)])


class HostAliases(unittest.TestCase):
    def test_backs_alias_across_adjacent_loads_and_rejects_invalid_layouts(self):
        page = 0x4000
        ro, rw, dst = 0x40200000, 0x40204000, 0x8000800000
        segments = [
            dict(address=ro, memory_bytes=page, file_bytes=page, flags=4),
            dict(address=rw, memory_bytes=page, file_bytes=page, flags=6),
            dict(address=rw+page, memory_bytes=page, file_bytes=0, flags=6),
        ]

        def check(rows, flat=True, granule=page):
            raw = b''.join(HOST_ALIAS.pack(*row) for row in rows)
            elf = SimpleNamespace(sections=[{'flags': 0}], read=lambda va, size: raw)
            records = {'flat_host_aliases': dict(shndx=0, value=ro, size=len(raw))}
            return host_aliases(elf, records, segments, flat, granule)

        rows = [(dst+2*page, ro, page, 4), (dst, rw, 2*page, 6)]
        self.assertEqual(check(rows), sorted(rows))
        for row, message in (
            ((dst, rw, 4096, 6), 'invalid host alias'),
            ((dst, rw, page, 5), 'compatible ELF backing'),
            ((dst, rw+page, 2*page, 6), 'compatible ELF backing'),
            ((ro, rw, page, 6), 'overlapping host alias'),
        ):
            with self.subTest(row=row), self.assertRaisesRegex(ValueError, message):
                check([row])
        with self.assertRaisesRegex(ValueError, 'overlapping host alias'):
            check(rows+[(dst+page, rw, page, 4)])
        with self.assertRaisesRegex(ValueError, 'require a flat checkpoint'):
            check(rows, flat=False)
        subpages = [(dst, rw+4096, 4096, 4), (dst+4096, rw+4096, 4096, 6),
                    (dst+8192, rw, 4096, 4)]
        self.assertEqual(check(subpages, granule=4096), subpages)
        with self.assertRaisesRegex(ValueError, 'invalid host alias'):
            check(subpages)

    def test_mapping_gate_requires_a_separate_window_and_writable_backing(self):
        page = 0x4000
        ro, rx, rw, dst = 0x40200000, 0x40204000, 0x40208000, 0x8000800000
        segments = [
            dict(address=ro, file_bytes=page, memory_bytes=page, flags=4),
            dict(address=rx, file_bytes=page, memory_bytes=page, flags=5),
            dict(address=rw, file_bytes=0, memory_bytes=page, flags=6),
        ]
        records = {
            'flat_host_mapping_window': dict(shndx=0, value=ro, size=MAPPING_WINDOW.size),
            'flat_host_mapping_gate': dict(shndx=0, value=rx, size=len(MAPPING_GATE_CODE)),
        }

        def check(address=dst, backing=rw, size=page, aliases=(), code=MAPPING_GATE_CODE, flat=True):
            data = {rx: code, ro: MAPPING_WINDOW.pack(address, size, backing, page)}
            elf = SimpleNamespace(sections=[{'flags': 0}], read=lambda va, length: data[va])
            return host_mapping_gate(elf, records, segments, flat, page, aliases, (rx+4,))

        self.assertEqual(check(), (rx, dst, page, rw, page))
        with self.assertRaisesRegex(ValueError, 'invalid host mapping gate'):
            check(code=MAPPING_GATE_CODE[::-1])
        with self.assertRaisesRegex(ValueError, 'alignment or size'):
            check(size=4096)
        with self.assertRaisesRegex(ValueError, 'overlaps an initial mapping'):
            check(aliases=[(dst, rw, page, 6)])
        with self.assertRaisesRegex(ValueError, 'overlaps an initial mapping'):
            check(address=ro)
        with self.assertRaisesRegex(ValueError, 'no writable ELF backing'):
            check(backing=rx)
        with self.assertRaisesRegex(ValueError, 'require a flat image'):
            check(flat=False)


class HostEvents(unittest.TestCase):
    def test_recomputes_count_order_and_completed_results(self):
        syscall = EVENT.pack(0, 59, 1, 2, 3, 4, 5, 6, 7, 1)
        fault = EVENT.pack(1, (1 << 64) - 1, 8, 9, 10, 0, 0, 0, 0, 0)
        expected = syscall + fault
        self.assertEqual(verify_event_log(syscall + fault + fault, expected), 2)
        with self.assertRaisesRegex(ValueError, 'count mismatch'):
            verify_event_log(syscall, expected)
        with self.assertRaisesRegex(ValueError, 'event 0 differs'):
            verify_event_log(fault + syscall, expected)
        changed = bytearray(syscall)
        struct.pack_into('<Q', changed, 64, 8)
        with self.assertRaisesRegex(ValueError, 'event 0 differs'):
            verify_event_log(changed + fault, expected)


class HostUserCopy(unittest.TestCase):
    def test_fixups_require_sorted_unprivileged_accesses_in_executable_aliases(self):
        ro, rx, alias = 0x40200000, 0x40204000, 0xc080234000
        segments = [
            dict(address=ro, file_bytes=0x4000, memory_bytes=0x4000, flags=4),
            dict(address=rx, file_bytes=0x4000, memory_bytes=0x4000, flags=5),
        ]
        entries = (alias, alias+8)
        fixups = [(alias, alias+4), (alias+8, alias+12)]

        def check(rows, aliases=((alias, rx, 0x4000, 5),), gate=(1,)):
            raw = b''.join(UACCESS_PAIR.pack(*row) for row in [entries, *rows])
            code = (0xf8400823, 0xd65f03c0, 0xf80008c3, 0xd65f03c0, 0xd503201f)
            data = {ro: raw, **{rx+4*i: struct.pack('<I', word) for i, word in enumerate(code)}}
            elf = SimpleNamespace(sections=[{'flags': 0}], read=lambda va, size: data[va])
            records = {'flat_host_uaccess_fixups': dict(shndx=0, value=ro, size=len(raw))}
            return host_uaccess_table(elf, records, segments, aliases, gate)

        self.assertEqual(check(fixups), struct.pack('<7Q', *entries, 2, *fixups[0], *fixups[1]))
        with self.assertRaisesRegex(ValueError, 'distinct sorted sites'):
            check(fixups[::-1])
        with self.assertRaisesRegex(ValueError, 'not an LDTR or STTR'):
            check([(alias+16, alias+12)])
        with self.assertRaisesRegex(ValueError, 'ELF load does not cover'):
            check(fixups, aliases=[])
        with self.assertRaisesRegex(ValueError, 'missing mapping gate'):
            check(fixups, gate=None)


def patch_instruction(elf, target, address, words):
    payload = struct.pack(f'<{len(words)}I', *words)
    offset = file_offset(elf, address, len(payload))
    with target.open('wb') as file:
        file.write(memoryview(elf.data)[:offset])
        file.write(payload)
        file.write(memoryview(elf.data)[offset + len(payload):])


@unittest.skipUnless(sys.platform == 'darwin' and platform.machine() == 'arm64' and
                     DEFAULT_LOADER.is_file() and os.environ.get('OSREC_EL0_MACOS_CHECKPOINT'),
                     'requires the Apple Silicon loader and a checked checkpoint ELF')
class MacOSCheckpoint(unittest.TestCase):
    def test_flat_execution_completes_and_rejects_unaligned_execution(self):
        image = Path(os.environ['OSREC_EL0_MACOS_CHECKPOINT'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = run(image, root / 'checked')
            self.assertTrue(report['verified'], report)
            self.assertTrue(report['el0_interval_verified'])
            self.assertTrue(report['user_entry']['verified'], report)
            self.assertEqual(report['address_space'], 'flat')
            self.assertFalse(report['guest_stage1_translation'])
            self.assertEqual((report['completion']['ttbr0'], report['completion']['ttbr1']), (0, 0))
            self.assertGreater(report['result']['events'], 0)
            self.assertEqual(report['host_events_verified'], report['result']['expected'])
            self.assertFalse(report['terminal_exit_executed'])

            elf = Elf(image)
            entry, = struct.unpack_from('<Q', elf.data, 24)
            invalid = root / 'bad-target.elf'
            # ADR X0, .+1; BR X0 forces a PC alignment exception.
            patch_instruction(elf, invalid, entry, (0x30000000, 0xd61f0000))
            del elf
            failed = run(invalid, root / 'bad-target')
            self.assertFalse(failed['verified'], failed)
            self.assertFalse(failed['el0_interval_verified'])
            self.assertIn('completion', failed, failed)
            stop = failed['completion']
            self.assertEqual(stop['el1_esr'] >> 26, 0x22, failed)
            self.assertEqual(stop['el1_elr'], entry + 1, failed)

    def test_rejects_wrong_registers_at_the_correct_linked_user_entry(self):
        image = Path(os.environ['OSREC_EL0_MACOS_CHECKPOINT'])
        elf = Elf(image)
        symbols = {symbol['name']: symbol for symbol in elf.symbols if symbol['shndx']}
        restore = symbols['flat_restore']
        code = elf.read(restore['value'], restore['size'])
        restore_x0 = code.index(struct.pack('<I', 0xa94007e0))  # LDP X0, X1, [SP]
        expected_x0, = struct.unpack('<Q', elf.read(symbols['flat_initial']['value'], 8))
        value = 0xa55a if expected_x0 != 0xa55a else 0xa55b
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = root / 'bad-register.elf'
            patch_instruction(elf, invalid, restore['value'] + restore_x0, (0xd2800000 | value << 5,))
            del elf
            report = run(invalid, root / 'bad-register')
        self.assertFalse(report['verified'], report)
        self.assertTrue(report['user_entry']['reached'], report)
        self.assertFalse(report['user_entry']['verified'], report)
        self.assertIn('x0', report['user_entry']['register_mismatches'])
        self.assertEqual(report['result']['events'], 0)


@unittest.skipUnless(sys.platform == 'darwin' and platform.machine() == 'arm64' and NATIVE_LOADER.is_file() and
                     os.environ.get('OSREC_EL0_MACOS_NATIVE_CHECKPOINT'),
                     'requires the native Apple Silicon loader and a native-linked ELF')
class MacOSNativeCheckpoint(unittest.TestCase):
    def test_native_execution_and_unexpected_instruction_fault(self):
        image = Path(os.environ['OSREC_EL0_MACOS_NATIVE_CHECKPOINT'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            verified = run_native(image, root / 'verified')
            self.assertTrue(verified['verified'], verified)
            self.assertTrue(verified['el0_interval_verified'])
            self.assertFalse(verified['hypervisor'])
            self.assertFalse(verified['terminal_exit_executed'])

            elf = Elf(image)
            entry, = struct.unpack_from('<Q', elf.data, 24)
            invalid = root / 'unaligned.elf'
            # ADR X0, .+1; BR X0 forces a PC alignment exception.
            patch_instruction(elf, invalid, entry, (0x30000000, 0xd61f0000))
            del elf
            failed = run_native(invalid, root / 'unaligned')
            self.assertFalse(failed['verified'], failed)
            self.assertFalse(failed['user_entry']['reached'], failed)
            self.assertEqual(failed['completion']['syndrome'] >> 26, 0x22, failed)


CROSS_CLANG = Path(os.environ.get('OSREC_TEST_CLANG', '/opt/homebrew/opt/llvm@16/bin/clang'))


@unittest.skipUnless(sys.platform == 'darwin' and platform.machine() == 'arm64' and
                     NATIVE_LOADER.is_file() and CROSS_CLANG.is_file(),
                     'requires the native Apple Silicon loader and an ELF cross compiler')
class MacOSDirectMemory(unittest.TestCase):
    def test_user_and_kernel_access_one_backing_without_memory_gateways(self):
        from audit_el0_image import audit_elf
        from el0_application import lower_application

        kernel_va, user_va, physical = 0x8000800000, 0x7f00040000, 0x40000000
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, reference = root / 'state', root / 'reference'
            state.mkdir()
            reference.mkdir()

            def assemble(name, address, source):
                path, binary = root / (name + '.S'), root / (name + '.elf')
                path.write_text(source)
                command = [str(CROSS_CLANG), '--target=aarch64-none-elf', '-nostdlib', '-fuse-ld=lld',
                           f'-Wl,-Ttext={address:#x},-e,_start,-z,max-page-size=16384',
                           str(path), '-o', str(binary)]
                subprocess.run(command, check=True, capture_output=True, text=True)
                return binary, Elf(binary)

            _, kernel = assemble('kernel', kernel_va, '''
.text
.global _start, observe, stop
_start:
    nop
    .space 0x3fc
    cmp x8, #93
    b.eq stop
    ldr x2, [x1]
    cmp x2, #42
    b.ne bad
    adrp x3, _start
    add x3, x3, #8, lsl #12
    sub x3, x3, #32
1:  ldxr x2, [x3]
    add x2, x2, #1
    stxr w4, x2, [x3]
    cbnz w4, 1b
    ldr x2, [x1]
    str x2, [sp, #-16]!
    ldr x2, [sp], #16
    cmp x2, #43
    b.ne bad
    mov x0, x2
    mov x2, xzr
    sub x3, sp, #0x150
    str x0, [x3]
    mov x3, xzr
observe:
    nop
    eret
stop:
    brk #0xf01
bad:
    brk #0xf02
''')
            user_path, user = assemble('user', user_va, '''
.text
.global _start
_start:
    mov x2, #42
    str x2, [sp, #-16]!
    mov x1, sp
    mov x2, xzr
    mov x8, #172
    svc #0
    cmp x0, #43
    b.ne bad
    ldr x2, [sp]
    cmp x2, #43
    b.ne bad
    mov x0, xzr
    mov x2, xzr
    mov x8, #93
    svc #0
bad:
    mov x0, #1
    mov x8, #93
    svc #0
''')
            ram = bytearray(0x20000)
            for binary, offset in ((kernel, 0x4000), (user, 0x8000)):
                text = next(section for section in binary.sections if section['name'] == '.text')
                ram[offset:offset + text['size']] = binary.read(text['addr'], text['size'])
            for level, shift in enumerate((39, 30, 21)):
                index = (user_va >> shift) & 511
                struct.pack_into('<Q', ram, 4096*level + 8*index, (physical + 4096*(level + 1)) | 3)
            for index in range(8):
                slot = ((user_va >> 12) & 511) + index
                attrs = 0x443 | (0x80 if index < 4 else 1 << 54)
                struct.pack_into('<Q', ram, 0x3000 + 8*slot, (physical + 0x8000 + 4096*index) | attrs)
            shadow = bytearray(532584)
            struct.pack_into('<Q', shadow, 8, kernel_va + 0xc000)
            struct.pack_into('<QQ', shadow, 64, kernel_va, physical)
            struct.pack_into('<Q', shadow, 104 + 8192 + 8*0xd807, 4)
            initial = struct.pack('<34Q', *([0]*31), user_va + 0x7ff0, user_va, 0x1000) + bytes(520)
            maps = [(kernel_va, physical + 0x4000, 0x4000, 0x480),
                    (kernel_va + 0x4000, physical + 0xc000, 0x4000, (1 << 53) | 0x400),
                    (kernel_va + 0x8000, physical + 0x10000, 0x4000, (1 << 53) | 0x400)]
            header = struct.pack('<10Q', 0x3145564954414e4c, 1, physical, len(ram), 16, 1, 0, 0, 0, len(maps))
            (state / 'native.bin').write_bytes(header + initial + shadow + struct.pack('<2Q', kernel_va, kernel_va + 4096)
                                               + b''.join(struct.pack('<4Q', *row) for row in maps))
            (state / 'memory.bin').write_bytes(ram)
            identity = hashlib.sha256(ram).hexdigest()
            observe = next(symbol['value'] for symbol in kernel.symbols if symbol['name'] == 'observe')
            (state / 'manifest.json').write_text(json.dumps(dict(source_image_sha256=identity,
                application=dict(user_elf_sha256=hashlib.sha256(user_path.read_bytes()).hexdigest(),
                                 result_hook=hex(observe)))))
            stop = next(symbol['value'] for symbol in kernel.symbols if symbol['name'] == 'stop')
            arguments = [0, user_va + 0x7fe0, 0, 0, 0, 0]
            (reference / 'calls.json').write_text(json.dumps(dict(source_image_sha256=identity, end=dict(pc=hex(stop)),
                calls=[dict(number=172, arguments=arguments, result=43),
                       dict(number=93, arguments=arguments, result=None)])))
            for name in ('counters.bin', 'mmio.bin'):
                (reference / name).write_bytes(b'')

            exported, verification, _ = lower_application(
                state, reference, root, user_path, root, None, True,
                macos_cc=str(CROSS_CLANG), macos_native=True, macos_direct_memory=True)
            self.assertTrue(exported['whole_kernel_text'])
            report = verification['macos']
            self.assertTrue(report['direct_memory'])
            self.assertTrue(report['el0_interval_verified'])
            self.assertEqual(report['host_events_verified'], 2)
            # Two syscall entries and the terminal boundary. Observe and ERET are inline.
            self.assertEqual(report['result']['transitions'], 3)
            self.assertFalse(report['guest_page_tables'])

            image = root / 'program/checkpoint'
            disassembly = subprocess.check_output([str(CROSS_CLANG.with_name('llvm-objdump')), '-d', str(image)], text=True)
            self.assertNotRegex(disassembly, r'\b(?:b|bl)\s+[^\n]*<flat_translate>')
            binary = Elf(image)
            aliases = next(symbol for symbol in binary.symbols if symbol['name'] == 'flat_host_aliases')
            backing, = struct.unpack('<Q', binary.read(aliases['value'] + 8, 8))
            changed = root / 'bad-alias.elf'
            changed_backing = (backing + 0x4000) & ~0x3fff
            patch_instruction(binary, changed, aliases['value'] + 8, (changed_backing & 0xffffffff, changed_backing >> 32))
            bad = Elf(changed)
            with self.assertRaisesRegex(ValueError, 'aliases differ from the captured mappings'):
                native_command(bad, audit_elf(bad))
