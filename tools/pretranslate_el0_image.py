#!/usr/bin/env python3
"""Finalize a self-contained ELF with canonical RAM and optional model tables.

Canonical RAM is initialized by non-overlapping PT_LOAD segments referring to
the checkpoint payload already in the file. Optionally merge RAM loads into
page-aligned clusters for a standard 4 KiB Linux ELF loader.
No instruction performs a snapshot copy or a mapping walk during startup.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import tempfile

from el0_hardware_model import prepare
from kernel_source_verify import Elf

PAGE = 4096
PHDR = struct.Struct('<II6Q')
EXTENT = struct.Struct('<3Q')
NOTE_TYPE = 0x4f535243
NOTE_NAME = b'OSREC\0'


def file_offset(elf, address, size=1):
    for section in elf.sections:
        if section['type'] != 8 and section['addr'] <= address and address+size <= section['addr']+section['size']:
            return section['offset'] + address - section['addr']
    raise ValueError('not backed by ELF file: ' + hex(address))


def snapshot_extents(elf, ram_bytes, payload, extents):
    """Return validated (RAM offset, size, packed file offset) records."""
    cursor = packed = 0
    for lo, size, payload_offset in extents:
        if (lo < cursor or size <= 0 or lo+size > ram_bytes or
                (lo | size) % PAGE or payload_offset != packed):
            raise ValueError('invalid initial RAM extents')
        yield lo, size, file_offset(elf, payload+payload_offset, size)
        cursor = lo + size
        packed += size


def ram_load_segments(elf, backing, ram_bytes, payload, extents):
    """Describe the complete canonical bank, including untouched zero pages."""
    segments = []
    cursor = 0
    for lo, size, offset in snapshot_extents(elf, ram_bytes, payload, extents):
        if lo > cursor:
            segments.append((1, 6, 0, backing+cursor, backing+cursor, 0, lo-cursor, PAGE))
        segments.append((1, 6, offset, backing+lo, backing+lo, size, size, 1))
        cursor = lo + size
    if cursor < ram_bytes:
        segments.append((1, 6, 0, backing+cursor, backing+cursor, 0, ram_bytes-cursor, PAGE))
    return segments


def program_headers(data):
    offset, = struct.unpack_from('<Q', data, 32)
    stride, count = struct.unpack_from('<HH', data, 54)
    return [PHDR.unpack_from(data, offset + i * stride) for i in range(count)]


def merge_ram_loads(data, source, backing, ram_bytes, extents, budget):
    if (backing | ram_bytes) % PAGE or budget < 1:
        raise ValueError('merged RAM loads require 4 KiB alignment and space for a program header')
    if not extents:
        return [(1, 6, 0, backing, backing, 0, ram_bytes, PAGE)]
    segments = []
    if extents[0][0]:
        segments.append((1, 6, 0, backing, backing, 0, extents[0][0], PAGE))
        budget -= 1
        if budget < 1:
            raise ValueError('no program-header space after leading zero RAM')

    # Every cut saves the zero gap before it from occupying file space.
    gaps = [(extents[i][0] - (lo + size), i)
            for i, (lo, size, _) in enumerate(extents[:-1], 1)]
    cuts = sorted(i for _, i in sorted(gaps, key=lambda gap: (-gap[0], gap[1]))[:budget-1])
    bounds = [0, *cuts, len(extents)]
    for first, after in zip(bounds, bounds[1:]):
        lo = cursor = extents[first][0]
        end = extents[after][0] if after < len(extents) else ram_bytes
        data.extend(bytes(-len(data) % PAGE))
        offset = len(data)
        for address, size, packed in extents[first:after]:
            data.extend(bytes(address-cursor))
            data.extend(source[packed:packed+size])
            cursor = address + size
        segments.append((1, 6, offset, backing+lo, backing+lo, cursor-lo, end-lo, PAGE))
    return segments


def append_ram_note(data, extents):
    """Retain the snapshot extent map for self-contained loader verification."""
    data.extend(bytes(-len(data) % 4))
    offset = len(data)
    desc_size = EXTENT.size * len(extents)
    data.extend(struct.pack('<III', len(NOTE_NAME), desc_size, NOTE_TYPE))
    data.extend(NOTE_NAME.ljust(8, b'\0'))
    data.extend(b''.join(EXTENT.pack(*extent) for extent in extents))
    size = len(data) - offset
    return (4, 4, offset, 0, 0, size, size, 4)


def merged_ram_extents(elf):
    extents = None
    for kind, _, offset, _, _, size, _, _ in program_headers(elf.data):
        if kind != 4 or size < 20 or elf.data[offset+12:offset+18] != NOTE_NAME:
            continue
        names, desc, note_type = struct.unpack_from('<III', elf.data, offset)
        if (extents is not None or names != len(NOTE_NAME) or note_type != NOTE_TYPE or
                desc % EXTENT.size or 20 + desc != size or offset + size > len(elf.data)):
            raise ValueError('invalid merged RAM extent note')
        extents = [list(row) for row in EXTENT.iter_unpack(memoryview(elf.data)[offset+20:offset+size])]
    return extents


def verify_merged_ram(elf, backing, ram_bytes, payload, segments, extents):
    """Check that loads recreate the packed snapshot and zero every RAM gap."""
    rows = iter(snapshot_extents(elf, ram_bytes, payload, extents))
    row = next(rows, None)
    cursor = 0
    source = memoryview(elf.data)
    message = 'canonical RAM loads differ from merged ELF extents'
    if (backing | ram_bytes) % PAGE:
        raise ValueError(message)
    for segment in segments:
        lo = segment['address'] - backing
        size = segment['file_bytes']
        offset = segment['file_offset']
        stop = lo + segment['memory_bytes']
        if (lo != cursor or not lo < stop <= ram_bytes or segment['flags'] != 6 or
                (lo | stop | size | offset) % PAGE or size > stop-lo or offset+size > len(source)):
            raise ValueError(message)
        at, end = offset, offset + size
        while row is not None and row[0] < stop:
            address, count, packed = row
            start = offset + address - lo
            if (not at <= start <= end-count or elf.data.count(b'\0', at, start) != start-at or
                    source[start:start+count] != source[packed:packed+count]):
                raise ValueError(message)
            at = start + count
            row = next(rows, None)
        if elf.data.count(b'\0', at, end) != end-at:
            raise ValueError(message)
        cursor = stop
    if cursor != ram_bytes or row is not None:
        raise ValueError(message)


def finalize(image, *, merge_segments=False):
    image=Path(image).resolve();path=image/'checkpoint'
    manifest=json.loads((image/'manifest.json').read_text())
    metadata=json.loads((image/'hardware-memory.json').read_text())
    if manifest.get('elf_ram_initialization'):
        config=metadata['elf_ram_initialization']
    elif manifest.get('pretranslated_memory'):
        config=metadata['pretranslated_memory']
    else:
        raise ValueError('export did not select ELF RAM initialization')
    elf=Elf(path);syms={s['name']:s for s in elf.symbols if s['shndx']}
    table_capacity=config['table_capacity']
    direct = manifest.get('macos_direct_memory', False)
    if not table_capacity and not (direct or (manifest.get('elf_ram_initialization') and metadata.get('alias_free_memory'))):
        raise ValueError('RAM-only loads require an alias-free ELF')
    data=bytearray(elf.data)
    previous=image/'pretranslated-elf.json'
    mapping_hash=hashlib.sha256((image/'hardware-memory.json').read_bytes()).hexdigest()
    if previous.exists():
        old=json.loads(previous.read_text())
        if (old.get('image_sha256') == hashlib.sha256(data).hexdigest() and
                old.get('mapping_sha256') == mapping_hash and
                (not merge_segments or old.get('merge_segments'))):
            return old
    backing=syms['flat_phys']['value'];ram_bytes=metadata['ram_bytes'];end=backing+ram_bytes
    payload=syms['flat_payload']['value']
    extents = config['initial_extents']
    sparse = ram_load_segments(elf, backing, ram_bytes, payload, extents)
    headers = program_headers(data)
    ram = [h for h in headers if h[0] == 1 and h[3] < end and backing < h[3]+h[6]]
    if merge_segments and ram == sparse:
        # Upgrade an existing packed image using its original payload and addresses.
        prefix = suffix = []
    else:
        if len(ram) != 1 or not ram[0][3] <= backing <= end <= ram[0][3]+ram[0][6]:
            raise ValueError('canonical RAM is not in one original LOAD (already finalized?)')
        kind,flags,offset,va,pa,filesz,memsz,align = ram[0]
        if filesz > backing-va:
            raise ValueError('canonical RAM was not zero-backed')
        prefix = [(kind,flags,offset,va,pa,filesz,backing-va,align)] if backing > va else []
        suffix = [(1,flags,0,end,end,0,va+memsz-end,PAGE)] if end < va+memsz else []
    first = headers.index(ram[0])
    # PT_PHDR is optional; its old address is stale after moving the table.
    before = [h for h in headers[:first] if h[0] != 6] + prefix
    after = suffix + [h for h in headers[first:] if h[0] != 6 and h not in ram]
    if merge_segments:
        budget = PAGE // PHDR.size - len(before) - len(after) - 1  # One PT_NOTE.
        packed = list(snapshot_extents(elf, ram_bytes, payload, extents))
        loads = merge_ram_loads(data, memoryview(elf.data), backing, ram_bytes, packed, budget)
        new = before + loads + after + [append_ram_note(data, extents)]
        if any(h[0] == 1 and (h[2]-h[3]) % PAGE for h in new):
            raise ValueError('merged ELF requires 4 KiB file and virtual offsets to match')
    else:
        loads = sparse
        new = before + loads + after
    if len(new)>=65535:raise ValueError('too many ELF program headers')
    data.extend(bytes((-len(data))%8));new_offset=len(data)
    data.extend(b''.join(PHDR.pack(*h) for h in new))
    struct.pack_into('<Q',data,32,new_offset);struct.pack_into('<H',data,56,len(new))
    with tempfile.TemporaryDirectory(dir=image) as directory:
        temporary=Path(directory)
        finalized=temporary/'checkpoint'
        finalized.write_bytes(data)
        for name in ('manifest.json','hardware-memory.json'):(temporary/name).symlink_to(image/name)
        if table_capacity:
            tables=prepare(temporary,temporary/'unused-table-output',_tables_only=True)
            if tables['bytes']>table_capacity:raise ValueError('embedded table reservation too small')
            offset=file_offset(elf,tables['address'],table_capacity)
            data[offset:offset+table_capacity]=tables['data']+bytes(table_capacity-tables['bytes'])
            finalized.write_bytes(data)
            table_report=dict(address=hex(tables['address']),bytes=tables['bytes'],
                              sha256=hashlib.sha256(tables['data']).hexdigest())
        elif direct:
            from audit_el0_image import audit_elf
            from el0_macos_native import load_command
            native = Elf(finalized)
            load_command(native, audit_elf(native))
            table_report=None
        else:
            prepare(temporary,temporary/'unused-table-output',_validate_only=True)
            table_report=None
        report=dict(image_sha256=hashlib.sha256(data).hexdigest(),mapping_sha256=mapping_hash,elf_ram_initialization=True,
                    initial_loads=len(extents),load_segments=sum(h[0]==1 for h in new),
                    embedded_page_tables=table_report,
                    user_aliases=len(config.get('user_aliases',[])),runtime_snapshot_copy=False,
                    external_page_table_image_required=False)
        if merge_segments:
            report.update(merge_segments=True, program_headers=len(new), ram_load_segments=len(loads),
                          ram_gap_file_bytes=sum(h[5] for h in loads)-sum(size for _, size, _ in extents))
        staged_report = temporary / previous.name
        staged_report.write_text(json.dumps(report, indent=2)+'\n')
        finalized.chmod(path.stat().st_mode & 0o777)
        # A retry can rebuild the old checkpoint if publication stops here.
        staged_report.replace(previous)
        finalized.replace(path)
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image',required=True)
    parser.add_argument('--merge-segments', action='store_true',
                        help='cluster canonical RAM loads within the 4 KiB Linux ELF header budget')
    args=parser.parse_args()
    print(json.dumps(finalize(args.image, merge_segments=args.merge_segments),indent=2))
