#!/usr/bin/env python3
"""Finalize a self-contained ELF: load canonical RAM and resolved MMU tables.

Canonical RAM is initialized by non-overlapping PT_LOAD segments referring to
the checkpoint payload already in the file. Zero gaps remain zero-fill loads.
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


def file_offset(elf, address, size=1):
    for section in elf.sections:
        if section['type'] != 8 and section['addr'] <= address and address+size <= section['addr']+section['size']:
            return section['offset'] + address - section['addr']
    raise ValueError('not backed by ELF file: ' + hex(address))


def ram_load_segments(elf, backing, ram_bytes, payload, extents):
    """Describe the complete canonical bank, including untouched zero pages."""
    segments = []
    cursor = packed = 0
    for lo, size, payload_offset in extents:
        if (lo < cursor or size <= 0 or lo+size > ram_bytes or
                (lo | size) & 4095 or payload_offset != packed):
            raise ValueError('invalid initial RAM extents')
        if lo > cursor:
            segments.append((1, 6, 0, backing+cursor, backing+cursor, 0, lo-cursor, 4096))
        offset = file_offset(elf, payload+payload_offset, size)
        segments.append((1, 6, offset, backing+lo, backing+lo, size, size, 1))
        cursor = lo + size
        packed += size
    if cursor < ram_bytes:
        segments.append((1, 6, 0, backing+cursor, backing+cursor, 0, ram_bytes-cursor, 4096))
    return segments


def finalize(image):
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
    data=bytearray(elf.data)
    previous=image/'pretranslated-elf.json'
    mapping_hash=hashlib.sha256((image/'hardware-memory.json').read_bytes()).hexdigest()
    if previous.exists():
        old=json.loads(previous.read_text())
        if old.get('image_sha256')==hashlib.sha256(data).hexdigest() and old.get('mapping_sha256')==mapping_hash:return old
    backing=syms['flat_phys']['value'];end=backing+metadata['ram_bytes']
    payload=syms['flat_payload']['value']
    phoff,=struct.unpack_from('<Q',data,32);stride,count=struct.unpack_from('<HH',data,54)
    headers=[struct.unpack_from('<II6Q',data,phoff+i*stride) for i in range(count)]
    # Already-finalized images may be relinked or inspected, but finalization
    # itself requires the original single canonical zero-backed LOAD.
    containing=[h for h in headers if h[0]==1 and h[3]<=backing and end<=h[3]+h[6]]
    if len(containing)!=1:raise ValueError('canonical RAM is not in one original LOAD (already finalized?)')
    original=containing[0]
    if original[5]>backing-original[3]:raise ValueError('canonical RAM was not zero-backed')
    new=[]
    for h in headers:
        if h[0]==6:continue # PT_PHDR is optional; its old address will be stale.
        if h!=original:new.append(h);continue
        kind,flags,offset,va,pa,filesz,memsz,align=h
        if backing>va:new.append((kind,flags,offset,va,pa,filesz,backing-va,align))
        new.extend(ram_load_segments(elf,backing,metadata['ram_bytes'],payload,config['initial_extents']))
        if end<va+memsz:new.append((1,flags,0,end,end,0,va+memsz-end,4096))
    if len(new)>=65535:raise ValueError('too many ELF program headers')
    data.extend(bytes((-len(data))%8));new_offset=len(data)
    data.extend(b''.join(struct.pack('<II6Q',*h) for h in new))
    struct.pack_into('<Q',data,32,new_offset);struct.pack_into('<H',data,56,len(new))
    with tempfile.TemporaryDirectory(dir=image) as directory:
        temporary=Path(directory)
        (temporary/'checkpoint').write_bytes(data)
        for name in ('manifest.json','hardware-memory.json'):(temporary/name).symlink_to(image/name)
        tables=prepare(temporary,temporary/'unused-table-output',_tables_only=True)
        if tables['bytes']>config['table_capacity']:raise ValueError('embedded table reservation too small')
        offset=file_offset(elf,tables['address'],config['table_capacity'])
        data[offset:offset+config['table_capacity']]=tables['data']+bytes(config['table_capacity']-tables['bytes'])
        finalized=temporary/'checkpoint'
        finalized.write_bytes(data)
        finalized.chmod(path.stat().st_mode & 0o777)
        finalized.replace(path)
    report=dict(image_sha256=hashlib.sha256(data).hexdigest(),mapping_sha256=mapping_hash,elf_ram_initialization=True,
                initial_loads=len(config['initial_extents']),load_segments=sum(h[0]==1 for h in new),
                embedded_page_tables=dict(address=hex(tables['address']),bytes=tables['bytes'],
                                          sha256=hashlib.sha256(tables['data']).hexdigest()),
                user_aliases=len(config.get('user_aliases',[])),runtime_snapshot_copy=False,
                external_page_table_image_required=False)
    (image/'pretranslated-elf.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image',required=True)
    print(json.dumps(finalize(parser.parse_args().image),indent=2))
