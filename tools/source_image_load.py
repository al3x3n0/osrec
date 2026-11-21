#!/usr/bin/env python3
"""Check the physical load contract of a segment-only shared-root ELF."""
import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import struct
from typing import NamedTuple

from el0_instruction_profile import segments
from kernel_source_verify import Elf

PAGE = 4096
ADDRESS = 0x0000fffffffff000
UART = 0x09000000
PF_X, PF_W, PF_R = 1, 2, 4


class LoadSegment(NamedTuple):
    address: int
    offset: int
    file_size: int
    memory_size: int
    flags: int


class LoadMap:
    def __init__(self, data):
        if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
            raise ValueError('expected a little-endian ELF64 file')
        file_type, machine, version, entry, phoff = struct.unpack_from('<HHIQQ', data, 16)
        header_size, stride, count = struct.unpack_from('<HHH', data, 52)
        if ((file_type, machine, version) != (2, 183, 1) or header_size != 64 or stride != 56 or
                phoff < header_size or not count or phoff + count * stride > len(data)):
            raise ValueError('invalid AArch64 executable program headers')
        self.data, self.entry = data, entry
        self.loads = []
        end = 0
        for kind, flags, off, va, pa, file_size, memory_size, alignment in segments(data):
            if kind != 1:
                continue
            if (va != pa or pa < end or pa % PAGE or off % PAGE or alignment != PAGE or
                    not memory_size or memory_size % PAGE or pa + memory_size > 1 << 64 or
                    file_size > memory_size or off + file_size > len(data) or not 0 < flags <= 7):
                raise ValueError(f'invalid segment-only PT_LOAD at {pa:#x}')
            self.loads.append(LoadSegment(pa, off, file_size, memory_size, flags))
            end = pa + memory_size
        self.starts = [s.address for s in self.loads]
        if entry % 4:
            raise ValueError('unaligned ELF entry')
        self.require(entry, 4, 'ELF entry', flags=PF_X, initialized=True)

    def require(self, address, size, label, *, flags=PF_R, initialized=False):
        first = bisect_right(self.starts, address) - 1
        cursor, end = address, address + size
        if size > 0 and first >= 0:
            for segment in self.loads[first:]:
                limit = segment.address + (segment.file_size if initialized else segment.memory_size)
                if not segment.address <= cursor < limit or segment.flags & flags != flags:
                    break
                if end <= limit:
                    return
                cursor = limit
        kind = 'file-backed' if initialized else 'mapped'
        raise ValueError(f'{label} at {address:#x} is not fully {kind} by PT_LOAD')

    def read(self, address, size):
        self.require(address, size, 'bootstrap data', initialized=True)
        segment = self.loads[bisect_right(self.starts, address) - 1]
        within = address - segment.address
        if within + size > segment.file_size:
            raise ValueError(f'bootstrap data crosses a PT_LOAD boundary at {address:#x}')
        offset = segment.offset + within
        return self.data[offset:offset + size]


def translate_ttbr0(read, root, va):
    """Resolve a VA or report the failing level of the 47-bit TTBR0 walk."""
    if not 0 <= va < 1 << 47:
        raise ValueError(f'address outside the checkpoint TTBR0: {va:#x}')
    table = root & ADDRESS
    for level, shift in enumerate((39, 30, 21, 12)):
        descriptor = int.from_bytes(read(table + 8 * ((va >> shift) & 511), 8), 'little')
        if not descriptor & 1 or ((level == 0 or level == 3) and not descriptor & 2):
            return None, level
        table = descriptor & ADDRESS
        if level == 3 or not descriptor & 2:
            return (table & (-1 << shift)) | (va & ((1 << shift) - 1)), level


def audit_tables(load, roots):
    """Every table referenced by a generated TTBR0 tree has file backing."""
    pending = [(root, 0) for root in roots]
    checked = set()
    while pending:
        table, level = pending.pop()
        if (table, level) in checked:
            continue
        checked.add((table, level))
        load.require(table, PAGE, f'TTBR0 level-{level} table', initialized=True)
        raw = load.read(table, PAGE)
        entries = raw[:PAGE // 2] if level == 0 else raw  # 256 entries for a 47-bit root
        for descriptor, in struct.iter_unpack('<Q', entries):
            if not descriptor & 1:
                continue
            is_table_or_page = descriptor & 2
            if level in (0, 3) and not is_table_or_page:
                raise ValueError(f'invalid level-{level} TTBR0 descriptor in table {table:#x}')
            if level < 3 and is_table_or_page:
                pending.append((descriptor & ADDRESS, level + 1))
    return len({table for table, _ in checked})


def audit_veneers(elf, load, roots, spill_pa):
    total = 0
    for section in elf.sections:
        if section['name'] != '.osrec.veneer.text' or not section['size']:
            continue
        start, size = section['addr'], section['size']
        if start % PAGE:
            raise ValueError('veneer code is not page aligned')
        for offset in range(0, size, PAGE):
            va = start + offset
            user_pa, kernel_pa = (translate_ttbr0(load.read, root, va)[0] for root in roots)
            if kernel_pa is None or user_pa != kernel_pa:
                raise ValueError(f'veneer code at {va:#x} differs between TTBR0 views')
            load.require(kernel_pa, min(PAGE, size - offset), 'veneer code', flags=PF_R | PF_X, initialized=True)
        alias = (start + size + PAGE - 1) & -PAGE
        for offset in (0, PAGE):
            va, expected = alias + offset, (spill_pa & -PAGE) + offset
            for root in roots:
                if translate_ttbr0(load.read, root, va)[0] != expected:
                    raise ValueError(f'veneer state alias at {va:#x} maps to the wrong physical page')
        total += size
    return total


def audit(elf, load):
    symbols = {s['name']: s['value'] for s in elf.symbols
               if s['shndx'] < len(elf.sections) and elf.sections[s['shndx']]['name'].startswith('.osrec.runtime.')}

    def address(name):
        try:
            return load.entry + symbols[name] - symbols['_start']
        except KeyError as error:
            raise ValueError(f'missing runtime ELF symbol {error.args[0]}') from error

    def quad(name):
        return int.from_bytes(load.read(address(name), 8), 'little')

    ram, ram_size = quad('osrec_shared_ram_pa'), quad('osrec_shared_ram_size')
    load.require(ram, ram_size, 'captured guest RAM', flags=PF_R | PF_W)
    monitor_end = (address('osrec_monitor_end') + PAGE - 1) & -PAGE
    load.require(load.entry, monitor_end - load.entry, 'monitor and BSS', flags=PF_R | PF_W)
    _, tcr, ttbr1, root, _, _, _, vectors, stack, main = struct.unpack('<10Q', load.read(address('boot_params'), 80))
    if ttbr1 or tcr & 63 != 17 or tcr & (3 << 14) or not tcr & (1 << 23):
        raise ValueError('bootstrap must use the shared 47-bit TTBR0 regime')
    if stack != symbols['osrec_monitor_stack_top'] or vectors != symbols['minios_vectors'] or main != symbols['minios_main']:
        raise ValueError('bootstrap vector, stack or entry differs from its ELF symbol')
    roots = (root & ADDRESS, quad('osrec_ttbr1_root'), quad('osrec_ttbr1_user_root'))
    table_count = audit_tables(load, roots)
    app_view, kernel_view = struct.unpack('<2Q', load.read(address('osrec_shared_kernel'), 16))
    for table, slot, descriptor in ((roots[0], 2, quad('osrec_shared_monitor')),
                                    (roots[1], 1, kernel_view), (roots[2], 1, app_view)):
        if descriptor & 3 != 3 or int.from_bytes(load.read(table + slot * 8, 8), 'little') != descriptor:
            raise ValueError(f'runtime TTBR0 view differs from table {table:#x} slot {slot}')
    for va in (load.entry, vectors, main, stack - 1):
        expected = va if va == load.entry else va + load.entry - symbols['_start']
        if translate_ttbr0(load.read, root, va)[0] != expected:
            raise ValueError(f'bootstrap TTBR0 maps {va:#x} to the wrong physical page')
        if va != stack - 1:
            load.require(expected, 4, 'bootstrap instruction', flags=PF_X, initialized=True)
    veneer_bytes = audit_veneers(elf, load, (roots[2], roots[1]), address('osrec_branch_state'))
    count = quad('staged_count')
    if count:
        for source, target in struct.iter_unpack('<QQ', load.read(address('staged_pages'), count * 16)):
            if source % PAGE or target % PAGE or not ram <= target <= ram + ram_size - PAGE:
                raise ValueError(f'invalid staged-page destination {target:#x}')
            load.require(source, PAGE, 'staged-page source', initialized=True)
    if any(s.address < UART + PAGE and s.address + s.memory_size > UART for s in load.loads):
        raise ValueError('PT_LOAD overlaps the PL011 device page')
    return dict(status='pass', image_sha256=hashlib.sha256(elf.data).hexdigest(), entry=hex(load.entry),
                startup='AArch64 non-secure EL1h with MMU off', guest_ram={'base': hex(ram), 'bytes': ram_size},
                monitor={'base': hex(load.entry), 'bytes': monitor_end - load.entry},
                staged_pages=count, translation_roots=[hex(root) for root in roots],
                translation_table_pages=table_count, veneer_code_bytes=veneer_bytes,
                devices=[dict(name='PL011', address=hex(UART), bytes=PAGE)],
                load_segments=[dict(p_paddr=hex(s.address), p_offset=s.offset, p_filesz=s.file_size,
                                    p_memsz=s.memory_size, p_flags=s.flags) for s in load.loads])


def check(image):
    elf = Elf(image)
    return audit(elf, LoadMap(elf.data))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    text = json.dumps(check(args.elf), indent=2) + '\n'
    if args.out:
        with args.out.open('x') as report:
            report.write(text)
    else:
        print(text, end='')
