#!/usr/bin/env python3
"""Inventory link-time and boot-time address fixups in an AArch64 ELF."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from kernel_source_verify import Elf, RELOCATIONS


def relr_count(data):
    """Count ELF64 RELR locations, including the locations in each bitmap."""
    count = 0
    have_base = False
    for entry, in struct.iter_unpack('<Q', data):
        if entry & 1:
            if not have_base:
                raise ValueError('RELR bitmap without a base address')
            count += (entry >> 1).bit_count()
        else:
            if entry % 8:
                raise ValueError('unaligned ELF64 RELR address')
            have_base = True
            count += 1
    return count


def inventory(path):
    elf = Elf(path)
    kind, machine = struct.unpack_from('<HH', elf.data, 16)
    if machine != 183 or kind not in (1, 2, 3):
        raise ValueError('expected an AArch64 object or linked ELF')

    names = {number: name for number, (name, _) in RELOCATIONS.items()}
    names.update({257: 'R_AARCH64_ABS64', 258: 'R_AARCH64_ABS32',
                  260: 'R_AARCH64_PREL64', 261: 'R_AARCH64_PREL32',
                  1027: 'R_AARCH64_RELATIVE'})
    rows = []
    totals = Counter()
    for section in elf.sections:
        section_type = section['type']
        if section_type not in (4, 9, 19):  # SHT_RELA, SHT_REL, SHT_RELR
            continue
        target_index = section['info']
        target = elf.sections[target_index] if target_index else None
        if target is not None and not target['flags'] & 2:  # SHF_ALLOC
            continue  # Debug and other metadata do not address loaded memory.
        start = section['offset']
        raw = memoryview(elf.data)[start:start + section['size']]
        if section_type == 19:
            counts = {'R_AARCH64_RELATIVE': relr_count(raw)}
        else:
            record = '<QQq' if section_type == 4 else '<QQ'
            counts = Counter(names.get(row[1] & 0xffffffff, str(row[1] & 0xffffffff))
                             for row in struct.iter_unpack(record, raw))
        if section['flags'] & 2 and not target_index:
            category = 'boot_dynamic'
        elif target is not None:
            category = 'executable_section' if target['flags'] & 4 else 'loaded_data_section'
        else:
            category = 'other'
        count = sum(counts.values())
        totals[category] += count
        rows.append(dict(section=section['name'], target=target['name'] if target else None,
                         category=category, bytes=section['size'], relocations=count, types=dict(counts)))
    return dict(elf=str(Path(path).resolve()), elf_type={1: 'object', 2: 'executable', 3: 'shared'}[kind],
                counts=dict(totals), sections=rows,
                scope='ELF relocation records only. Addresses produced during boot or held in a capture require separate analysis.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', required=True)
    parser.add_argument('--out')
    args = parser.parse_args()
    report = json.dumps(inventory(args.elf), indent=2) + '\n'
    if args.out:
        Path(args.out).write_text(report)
    else:
        print(report, end='')
