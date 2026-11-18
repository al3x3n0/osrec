"""Admission for generated live-address conversions into canonical RAM."""
import struct


def validate_tables(elf,checked,metadata,manifest,immutable_pages):
    from el0_hardware import (COMPACT_ACCESS_WIDTHS, COMPACT_LINKED_BIAS, COMPACT_LINKED_BIAS_ENCODING,
                              COMPACT_WIDTH_BOUNDS, COMPACT_WIDTH_BOUNDS_ENCODING,
                              compact_ranges, compact_width_ranges, ranked_compact_ranges)
    symbols={s['name']:s for s in elf.symbols if s['shndx']}
    flag=symbols.get('flat_compact_memory_mode')
    mode=struct.unpack('<Q',elf.read(flag['value'],8))[0] if flag else 0
    config=metadata.get('compact_dynamic_memory')
    encodings = {0: None, 1: None, COMPACT_LINKED_BIAS: COMPACT_LINKED_BIAS_ENCODING,
                 COMPACT_WIDTH_BOUNDS: COMPACT_WIDTH_BOUNDS_ENCODING}
    if mode not in encodings or bool(mode)!=bool(config) or bool(mode)!=manifest.get('compact_dynamic_memory',False):
        raise ValueError('compact dynamic memory mode differs from ELF')
    encoding=config.get('encoding') if config else None
    if encoding != encodings[mode]:
        raise ValueError('compact translation encoding differs from ELF')
    alias_flag=symbols.get('flat_alias_free_memory_mode')
    alias_mode=struct.unpack('<Q',elf.read(alias_flag['value'],8))[0] if alias_flag else 0
    if alias_mode not in (0,1) or bool(alias_mode)!=metadata.get('alias_free_memory',False) or bool(alias_mode)!=manifest.get('alias_free_memory',False):
        raise ValueError('alias-free memory mode differs from ELF')
    if alias_mode and (not mode or any(metadata.get(k) for k in
                       ('aliases','read_ranges','write_ranges','pretranslated_memory','native_kernel_stack'))):
        raise ValueError('alias-free memory requires compact translation and logical guest stacks')
    if not mode:return
    def readonly(symbol,size):
        lo=symbol['value']&-4096;hi=(symbol['value']+size+4095)&-4096
        if elf.sections[symbol['shndx']]['flags']&1 or any(
                s['flags']&2 and lo<((s['address']+s['memory_bytes']+4095)&-4096) and
                (s['address']&-4096)<hi for s in checked['load_segments']):
            raise ValueError('compact translation tables are writable')
    readonly(flag,8)
    if alias_mode:
        readonly(alias_flag,8)
        for name in ('flat_direct_read','flat_direct_write'):
            if elf.read(symbols[name]['value'],16)!=bytes(16):
                raise ValueError('alias-free image has a native address range')
    program=symbols['flat_program']['value']
    pointer,count=struct.unpack('<2Q',elf.read(program+16,16))
    maps=list(struct.iter_unpack('<4Q',elf.read(pointer,32*count)))
    ranges=compact_ranges(maps,metadata['ram_base'],metadata['ram_bytes'],[(pa,4096) for pa in sorted(immutable_pages)])
    def verify_table(symbol,rows):
        size = 24*(len(rows)+1)
        readonly(symbol,size)
        actual = list(struct.iter_unpack('<3Q',elf.read(symbol['value'],size)))
        if actual != rows+[(0,0,0)]:
            raise ValueError('compact translation table differs from ELF')

    def linked_bias(rows):
        backing = symbols['flat_phys']['value']
        return [(lo,hi,(backing+offset-lo)&((1<<64)-1)) for lo,hi,offset in rows]
    for access,expected in zip(('read','write'),ranges):
        if config[access]!=expected:raise ValueError('compact translation differs from captured mappings')
        if mode==COMPACT_WIDTH_BOUNDS:
            for width in COMPACT_ACCESS_WIDTHS:
                symbol = symbols['flat_compact_%s_%d' % (access,width)]
                if symbol['value']%32:
                    raise ValueError('compact width table is not 32-byte aligned')
                rows = linked_bias(compact_width_ranges(expected,width))
                verify_table(symbol,rows or [(1,0,0)])
        elif mode==COMPACT_LINKED_BIAS:
            verify_table(symbols['flat_compact_'+access],linked_bias(ranked_compact_ranges(expected)))
        else:
            verify_table(symbols['flat_compact_'+access],[tuple(row) for row in expected])


def audit_sources(image):
    """Reject original memory entries or call copies that bypass adapters."""
    import json,re,hashlib
    from pathlib import Path
    from export_el0_program import Package
    from el0_flat_lower import decode,MEMORY,COVERAGE,UNSUPPORTED,SYSTEM
    image=Path(image);manifest=json.loads((image/'manifest.json').read_text())
    if not manifest.get('compact_dynamic_memory'):raise ValueError('image has no dynamic compact conversion')
    package=Package(Path(manifest['package']))
    entries=set();operations={};table=False
    with (image/'program.S').open() as stream:
        for line in stream:
            match=re.fullmatch(r'\.Lp([0-9a-f]+):\n',line)
            if match:entries.add(int(match[1],16))
            if line.strip()=='flat_ops:':table=True;continue
            if table and line.strip().startswith('.quad '):
                fields=line.strip()[6:].split(',')
                operations[int(fields[0],0)]=int(fields[5],0)
    memory=zero=0
    try:
        for pc in entries:
            if operations.get(pc)==COVERAGE:continue
            word=package.word(pc)
            if word==0xd421e000 and pc in package.sites:word=package.sites[pc][0]
            is_memory=decode(word).kind==MEMORY;is_zero=word&~31==0xd50b7420
            if (is_memory or is_zero) and pc not in operations:
                raise ValueError('original memory entry bypasses compact adapter: '+hex(pc))
            if is_memory and operations[pc] not in (MEMORY,UNSUPPORTED):
                raise ValueError('original memory entry has an incompatible adapter: '+hex(pc))
            if is_zero and operations[pc] not in (SYSTEM,UNSUPPORTED):
                raise ValueError('zeroing entry has an incompatible adapter: '+hex(pc))
            memory+=is_memory;zero+=is_zero
        copy_path=image/'call-specialization.json'
        copies=json.loads(copy_path.read_text()) if copy_path.exists() else dict(functions=[],calls=[])
        if len(copies['calls'])!=manifest.get('specialized_calls',0):
            raise ValueError('call specialization records differ from manifest')
        for function in copies['functions']:
            for pc,word in function['instructions']:
                word=int(word,0)
                if decode(word).kind==MEMORY or word&~31==0xd50b7420:
                    raise ValueError('call copy bypasses compact adapter: '+pc)
        report=dict(source_entries=len(entries),memory_entries=memory,zero_entries=zero,
                    call_copies_without_memory=len(copies['calls']),
                    program_sha256=hashlib.sha256((image/'program.S').read_bytes()).hexdigest(),
                    complete_static_relocation=False,
                    scope='source entry and copied-code admission')
        (image/'compact-dynamic-audit.json').write_text(json.dumps(report,indent=2)+'\n')
        return report
    finally:
        package.memory.close();package.file.close()


if __name__=='__main__':
    import argparse,json
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True)
    print(json.dumps(audit_sources(parser.parse_args().image),indent=2))
