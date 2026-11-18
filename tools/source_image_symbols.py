#!/usr/bin/env python3
"""Embed kernel and EL0 runtime symbols without changing the checkpoint's load segments."""

import argparse
import bisect
import hashlib
import json
import re
import struct
from collections import Counter
from pathlib import Path

from kernel_source_verify import Elf
from source_image_calls import shadow_operation

PAGE = 4096
MASK64 = (1 << 64) - 1
SECTION = struct.Struct('<IIQQQQIIQQ')
SYMBOL = struct.Struct('<IBBHQQ')


class Strings:
    def __init__(self):
        self.data = bytearray(b'\0')
        self.offsets = {'': 0}

    def add(self, name):
        if name not in self.offsets:
            self.offsets[name] = len(self.data)
            self.data.extend(name.encode() + b'\0')
        return self.offsets[name]


def veneer_operation(insn):
    read, offset, kind = shadow_operation(insn, percpu=True)
    if kind == 'percpu':
        return 'mrs_tpidr_el1'
    if kind in ('daifset', 'daifclr'):
        return f'{kind}_{(insn >> 8) & 15:x}'
    register = {0: 'sp_el0', 8: 'sp_el1', 16: 'elr_el1', 24: 'spsr_el1', 32: 'esr_el1',
                40: 'far_el1', 48: 'daif', 56: 'pan', 64: 'vbar_el1', 72: 'ttbr0_el1',
                None: 'currentel'}[offset]
    return ('mrs_' if read else 'msr_') + register


def embed(raw, manifest, kernel, monitor, veneers=None, calls=()):
    """Append an ELF section/symbol table to a sectionless AArch64 load image."""
    if len(raw) < 64 or raw[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', raw, 18)[0] != 183:
        raise ValueError('expected a little-endian AArch64 ELF')
    if struct.unpack_from('<Q', raw, 40)[0] or struct.unpack_from('<H', raw, 60)[0]:
        raise ValueError('checkpoint already has an ELF section table')

    names, strings = Strings(), Strings()
    sections = [bytes(SECTION.size)]
    symbols = []
    counts = Counter()
    shift = int(manifest.get('kernel_shift', '0'), 0)
    mapped_text = {int(p.get('original_va', p['va']), 16): int(p['va'], 16)
                   for p in manifest['pages'] if p['kind'] == 'text'}

    def add_section(name, kind, flags, va=0, offset=0, size=0, link=0, info=0, align=1, entsize=0):
        sections.append(SECTION.pack(names.add(name), kind, flags, va, offset, size, link, info, align, entsize))
        return len(sections) - 1

    def add_symbols(image, role, delta=0, rename=None, selected=None):
        indexes = {}
        for symbol in image.symbols:
            index = symbol['shndx']
            name = symbol['name']
            if not name or name.startswith(('$', '.')) or index == 0 or index >= len(image.sections):
                continue
            section = image.sections[index]
            if not section['flags'] & 2 or symbol['type'] not in (0, 1, 2):
                continue
            if selected is not None and not selected(symbol, section):
                continue
            if index not in indexes:
                indexes[index] = add_section('.osrec.' + role + section['name'], 8, section['flags'] & 7,
                                             (section['addr'] + delta) & MASK64, size=section['size'])
            if rename is not None:
                name = rename(name)
            symbols.append((symbol['bind'], symbol['type'], name, indexes[index],
                            (symbol['value'] + delta) & MASK64, symbol['size']))
            counts[role] += 1

    def live_code(symbol, section):
        address = symbol['value']
        page = address & -PAGE
        return bool(section['flags'] & 4) and mapped_text.get(page) == ((page + shift) & MASK64)

    add_symbols(kernel, 'kernel', shift, selected=live_code)
    add_symbols(monitor, 'runtime')
    entry = struct.unpack_from('<Q', raw, 24)[0]
    boot_index = add_section('.osrec.boot', 8, 6, entry, size=PAGE)
    symbols.append((1, 2, 'osrec_monitor_boot', boot_index, entry, 0))
    counts['runtime'] += 1

    if veneers is not None:
        owners = sorted((s['value'], s['size'], s['name']) for s in kernel.symbols
                        if s['type'] in (0, 2) and s['size'] and 0 < s['shndx'] < len(kernel.sections)
                        and live_code(s, kernel.sections[s['shndx']]))
        starts = [owner[0] for owner in owners]

        def veneer_name(name):
            site = calls[int(name.removeprefix('osrec_call_'))]
            address = int(site['pc'], 16)
            original = (address - shift) & MASK64
            index = bisect.bisect_right(starts, original) - 1
            owner = 'kernel'
            if index >= 0 and original < starts[index] + owners[index][1]:
                owner = re.sub('[^A-Za-z0-9_]', '_', owners[index][2])
            return f'osrec_veneer_{owner}_{veneer_operation(int(site["insn"], 16))}_{address:x}'

        add_symbols(veneers, 'veneer', rename=veneer_name,
                    selected=lambda s, _: re.fullmatch(r'osrec_call_[0-9]+', s['name']) is not None)

    # ELF groups local symbols before the first non-local symbol (sh_info).
    symbols.sort(key=lambda s: (s[0] != 0, s[4], s[2]))
    records = bytearray(SYMBOL.size)
    for binding, kind, name, index, value, size in symbols:
        records.extend(SYMBOL.pack(strings.add(name), binding << 4 | kind, 0, index, value, size))
    first_global = 1 + sum(s[0] == 0 for s in symbols)
    image = bytearray(raw)
    image.extend(bytes(-len(image) % 8))
    table_offset = len(image)
    image.extend(records)
    strings_index = add_section('.strtab', 3, 0, offset=len(image), size=len(strings.data))
    image.extend(strings.data)
    add_section('.symtab', 2, 0, offset=table_offset, size=len(records), link=strings_index,
                info=first_global, align=8, entsize=SYMBOL.size)
    names.add('.shstrtab')
    names_index = add_section('.shstrtab', 3, 0, offset=len(image), size=len(names.data))
    image.extend(names.data)
    image.extend(bytes(-len(image) % 8))
    struct.pack_into('<Q', image, 40, len(image))
    struct.pack_into('<HH', image, 60, len(sections), names_index)
    image.extend(b''.join(sections))
    return image, dict(counts)


def symbolize(directory, raw, manifest, kernel=None, monitor=None):
    calls = directory / 'calls.elf'
    has_veneers = bool(manifest.get('branch_sites'))
    return embed(raw, manifest, kernel or Elf(manifest['vmlinux']), monitor or Elf(directory/'monitor.elf'),
                 Elf(calls) if has_veneers else None,
                 json.loads((directory/'calls.json').read_text()) if has_veneers else ())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.image/'manifest.json').read_text())
    raw = (args.image/'image.elf').read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['image_sha256']:
        raise ValueError('checkpoint hash differs from its manifest')
    updated, counts = symbolize(args.image, raw, manifest)
    with args.out.open('xb') as stream:
        stream.write(updated)
    print(json.dumps(dict(symbols=counts, image_sha256=hashlib.sha256(updated).hexdigest())))


if __name__ == '__main__':
    main()
