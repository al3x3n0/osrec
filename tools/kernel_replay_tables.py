#!/usr/bin/env python3
"""Build an EL0 replay root for a split 39-bit or shared 47-bit Linux capture."""

import argparse
import json
import struct
from collections import Counter
from pathlib import Path

from kernel_low_layout import capture_windows
from source_image import PAGE, Ram

ADDRESS = (1 << 48) - PAGE
VALID = 1 << 0
TABLE = 1 << 1
USER_ACCESS = 1 << 6
CONTIGUOUS = 1 << 52
PXN = 1 << 53
UXN = 1 << 54
TABLE_PXN = 1 << 59
TABLE_UXN = 1 << 60
TABLE_NO_EL0 = 1 << 61
TCR_A1 = 1 << 22
TCR_EPD1 = 1 << 23
TCR_HPD0 = 1 << 41
TCR_HPD1 = 1 << 42
PA_BITS = (32, 36, 40, 42, 44, 48)
KERNEL_BASE = 1 << 39


def captured_roots(ram):
    tcr = ram.sysregs['TCR_EL1']
    if not tcr & TCR_EPD1:
        if ram.bits != {0: 39, 1: 39}:
            raise ValueError('split captures require two 39-bit windows')
        capture_windows(ram)
        if bool(tcr & TCR_HPD0) != bool(tcr & TCR_HPD1):
            raise ValueError('the captured windows must have the same hierarchical permission policy')
        return ram.roots[0] | VALID | TABLE, ram.roots[1] | VALID | TABLE, 'split'

    if ram.bits[0] != 47 or tcr & ((1 << 7) | (3 << 14) | (1 << 59)):
        raise ValueError('shared captures require a live 47-bit TTBR0 with standard 4 KiB descriptors')
    root = ram.page(ram.roots[0])
    if root is None:
        raise ValueError('the captured TTBR0 root is outside RAM')
    slots = struct.unpack_from('<128Q', root)
    if any(d & (VALID | TABLE) != VALID | TABLE for d in slots[:2]) or any(d & VALID for d in slots[2:]):
        raise ValueError('the captured TTBR0 root must contain exactly the user and kernel table entries')
    return slots[0], slots[1], 'shared'


def el0_table(descriptor, address):
    attrs = descriptor & ~(ADDRESS | TABLE_UXN | TABLE_NO_EL0)
    return address | attrs | (TABLE_UXN if descriptor & TABLE_PXN else 0)


def build(ram, base, devices=()):
    """Return the table image and manifest. Device ranges are physical [start, end) pairs."""
    user_entry, kernel_entry, capture_mode = captured_roots(ram)
    tcr = ram.sysregs['TCR_EL1']
    ips = (tcr >> 32) & 7
    if ips >= len(PA_BITS):
        raise ValueError('the replay root requires at most 48-bit physical addresses')
    physical_limit = 1 << PA_BITS[ips]
    ram_end = ram.base + ram.size
    if base % PAGE or not ram_end <= base <= physical_limit - PAGE:
        raise ValueError('the table arena must start at a page boundary above the captured RAM')
    devices = tuple(devices)
    for start, end in devices:
        if start % PAGE or end % PAGE or not 0 <= start < end <= physical_limit:
            raise ValueError('device ranges must cover whole pages within the physical address width')
    for root in (user_entry & ADDRESS, kernel_entry & ADDRESS):
        if ram.page(root) is None:
            raise ValueError(f'captured root {root:#x} is outside RAM')

    image = bytearray(PAGE)
    cloned = {}
    physical_ranges = []
    ranges = [(ram.base, ram_end, 'RAM'), *((start, end, 'device') for start, end in devices)]

    def backing(pa, size):
        for start, end, kind in ranges:
            if start <= pa and pa + size <= end:
                return kind
            if pa < end and start < pa + size:
                raise ValueError(f'mapping at {pa:#x} straddles the {kind} range boundary')
        return 'outside'

    def clone(pa, level):
        if (pa, level) in cloned:
            return cloned[pa, level]
        page = ram.page(pa)
        if page is None:
            raise ValueError(f'kernel table {pa:#x} is outside captured RAM')
        offset = len(image)
        image.extend(page)
        span = 1 << (12 + 9 * (3 - level))
        counts = Counter()
        for index, (descriptor,) in enumerate(struct.iter_unpack('<Q', page)):
            if not descriptor & VALID:
                continue
            address = descriptor & ADDRESS & -span
            if level < 3 and descriptor & TABLE:
                child, child_counts = clone(descriptor & ADDRESS, level + 1)
                counts.update(child_counts)
                new = el0_table(descriptor, child)
            else:
                if level == 3 and not descriptor & TABLE:
                    raise ValueError(f'invalid page descriptor in kernel table {pa:#x}')
                physical_ranges.append((address, address + span))
                kind = backing(address, span)
                counts[kind] += span // PAGE
                if kind == 'RAM':
                    new = (descriptor & ~UXN) | USER_ACCESS | (UXN if descriptor & PXN else 0)
                elif kind == 'device':
                    new = descriptor | USER_ACCESS | PXN | UXN
                else:
                    new = (descriptor & ~USER_ACCESS) | UXN
                if descriptor & CONTIGUOUS:
                    group = 16 * span  # 4 KiB contiguous page/PMD groups in the captured profile.
                    backing(address & -group, group)
            struct.pack_into('<Q', image, offset + 8 * index, new)
        cloned[pa, level] = base + offset, counts
        return cloned[pa, level]

    kernel_root, counts = clone(kernel_entry & ADDRESS, 1)
    # Install the user entry unchanged and the EL0-accessible kernel entry beside it.
    struct.pack_into('<QQ', image, 0, user_entry, el0_table(kernel_entry, kernel_root))
    end = base + len(image)
    if end > physical_limit:
        raise ValueError('table image exceeds the captured physical address width')
    physical_ranges.extend((pa, pa + PAGE) for va, pa, _ in ram.mappings(0)[0] if va < KERNEL_BASE)
    if any(start < end and base < stop for start, stop in physical_ranges):
        raise ValueError('the table arena overlaps the backing of a captured mapping')

    # The live ASID was selected from TTBR1 when A1 was set. Move it to the new TTBR0.
    asid_source = ram.sysregs['TTBR1_EL1' if tcr & TCR_A1 else 'TTBR0_EL1']
    asid = asid_source & (0xffff << 48)
    registers = dict(TCR_EL1=(tcr & ~(0x3f | TCR_A1)) | (64 - 47) | TCR_EPD1,
                     TTBR0_EL1=asid | base, TTBR1_EL1=0, MAIR_EL1=ram.sysregs['MAIR_EL1'])
    report = dict(format='osrec-kernel-replay-tables-v1', table_base=hex(base), table_bytes=len(image),
                  capture_mode=capture_mode, user_root=hex(user_entry & ADDRESS),
                  replay_kernel_root=hex(kernel_root), kernel_base=hex(KERNEL_BASE),
                  ram_pages_el0=counts['RAM'], device_pages_el0=counts['device'],
                  outside_ram_pages_el1=counts['outside'],
                  registers={name: hex(value) for name, value in registers.items()})
    return report, image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dump', type=Path, required=True)
    parser.add_argument('--profile', type=Path, help='source image profile listing direct MMIO ranges')
    parser.add_argument('--table-base', type=lambda value: int(value, 0), required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    ram = Ram(args.dump)
    with ram.file, ram.ram:
        try:
            profile = json.loads(args.profile.read_text()) if args.profile else {}
            devices = [(int(item['pa'], 16), int(item['pa'], 16) + int(item['size'], 16))
                       for item in profile.get('devices', [])]
            report, image = build(ram, args.table_base, devices)
        except ValueError as exc:
            parser.error(str(exc))
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'page-tables.bin').write_bytes(image)
    (args.out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
