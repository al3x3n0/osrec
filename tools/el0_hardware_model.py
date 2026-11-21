#!/usr/bin/env python3
"""Prepare hardware aliases and functionally validate an EL0 checkpoint in QEMU.

The separate QEMU setup stub establishes page tables before ELF entry. After
entry every exception vector stops: no EL1 monitor services the computation.
Other models can install the declared register values and RAM directly.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time

from audit_el0_image import audit
from gdb_remote import Remote
from kernel_source_verify import Elf
from source_image import LLVM
from source_image_el0 import Tables
from svc_boundary import free_port

PAGE = 4096
SETUP = 0x40100000
TABLES = 0xa0000000
RAM_BASE, RAM_END = 0x40000000, 0xc0000000
RESULT_NAMES = ('magic', 'version', 'status', 'events', 'expected', 'transitions',
                'reason', 'pc', 'detail', 'far', 'counters', 'uart_bytes',
                'first_mismatch', 'missing_pc', 'elapsed', 'reserved')
PSTATE_NON_EL0T = 31 | (3 << 20)  # M, IL and SS


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def platform_registers(va_bits, root, zero_bytes):
    # 4 KiB TTBR0, normal WB walks, inner shareable. TTBR1 stays disabled.
    tcr = (64 - va_bits) | (1 << 8) | (1 << 10) | (3 << 12) | (16 << 16) | (1 << 23) | (2 << 30) | (2 << 32)
    return dict(MAIR_EL1=0xff, TCR_EL1=tcr, TTBR0_EL1=root, TTBR1_EL1=0,
                CPACR_EL1=3 << 20, SCTLR_EL1=0x30d01805 | ((1 << 14) if zero_bytes else 0))


def audit_exception_trace(path, entry):
    raw = path.read_bytes()
    lines = raw.splitlines()
    expected = f'Exception return from AArch64 EL1 to AArch64 EL0 PC {entry:#x}'.encode()
    # The generated setup has exactly one exception return. Require it as a
    # positive control, so missing or unrecognized logging cannot pass.
    bootstrap_observed = bool(lines and lines[0] == expected)
    remainder = lines[int(bootstrap_observed):]
    return dict(file=path.name, sha256=hashlib.sha256(raw).hexdigest(),
                bootstrap_to_entry_observed=bootstrap_observed,
                unexpected_log_lines=len(remainder),
                hardware_exceptions=sum(line.startswith(b'Taking exception ') for line in remainder))


def prepare(image, out, llvm=LLVM, _tables_only=False, _validate_only=False):
    image, out = Path(image).resolve(), Path(out).resolve()
    metadata = json.loads((image / 'hardware-memory.json').read_text())
    manifest = json.loads((image / 'manifest.json').read_text())
    if manifest.get('memory_backend') != 'hardware-kernel' or sha(image / 'hardware-memory.json') != manifest['hardware_memory_sha256']:
        raise ValueError('hardware mapping metadata is not bound to this export')
    checked = audit(image / 'checkpoint')
    zero_bytes=checked.get('native_zero_bytes',0)
    if zero_bytes!=metadata.get('native_zero_bytes',0):raise ValueError('native zero-block metadata differs from ELF')
    elf = Elf(image / 'checkpoint')
    symbols = {s['name']: s for s in elf.symbols if s['shndx']}
    validation_flag=symbols.get('flat_validation_enabled')
    validation_mode=1 if validation_flag is None else struct.unpack('<Q',elf.read(validation_flag['value'],8))[0]
    if validation_mode not in (0,1) or bool(validation_mode)!=manifest.get('runtime_validation',True):
        raise ValueError('runtime validation mode differs between ELF and manifest')
    if validation_flag and elf.sections[validation_flag['shndx']]['flags']&1:
        raise ValueError('runtime validation mode is writable')
    shadow_flag=symbols.get('flat_shadow_header_alignment')
    shadow_align=0 if not shadow_flag or elf.sections[shadow_flag['shndx']]['type']==8 else struct.unpack('<Q',elf.read(shadow_flag['value'],8))[0]
    shadow_backend='page-offset' if shadow_align else 'base'
    if shadow_align not in (0,128) or metadata.get('shadow_header_alignment',0)!=shadow_align or manifest.get('shadow_access_backend','base')!=shadow_backend:
        raise ValueError('shadow header alignment differs between ELF and metadata')
    if shadow_align:
        lo=shadow_flag['value']&-PAGE;hi=(shadow_flag['value']+8+PAGE-1)&-PAGE
        writable=any(s['flags']&2 and lo<((s['address']+s['memory_bytes']+PAGE-1)&-PAGE) and
                     (s['address']&-PAGE)<hi for s in checked['load_segments'])
        if elf.sections[shadow_flag['shndx']]['flags']&1 or writable:
            raise ValueError('shadow header alignment flag is writable')
        shadow=symbols['flat_shadow']['value']
        if shadow%shadow_align:
            raise ValueError('shadow header is not aligned for page-offset access')
        if struct.unpack('<Q',elf.read(symbols['flat_program']['value']+48,8))[0]!=shadow:
            raise ValueError('shadow header binding differs from ELF symbol')
    native_flag=symbols.get('flat_native_kernel_stack')
    native_mode=0 if not native_flag or elf.sections[native_flag['shndx']]['type']==8 else struct.unpack('<Q',elf.read(native_flag['value'],8))[0]
    if native_mode not in (0,1) or bool(native_mode)!=bool(metadata.get('native_kernel_stack')) or bool(native_mode)!=bool(manifest.get('native_kernel_stack')):
        raise ValueError('native kernel stack mode differs between ELF and mapping metadata')
    if native_mode:
        count=struct.unpack('<Q',elf.read(symbols['flat_native_stack_range_count']['value'],8))[0]
        domains=[list(row) for row in struct.iter_unpack('<2Q',elf.read(symbols['flat_native_stack_ranges']['value'],count*16))]
        if domains!=metadata['native_kernel_stack']['ranges']:
            raise ValueError('native kernel stack domains differ from ELF')
    pretranslated=metadata.get('pretranslated_memory')
    trust_syscall_abi=bool(manifest.get('trust_syscall_abi',False))
    if trust_syscall_abi and validation_mode:
        raise ValueError('trusted syscall ABI requires execution-only mode')
    if pretranslated and not validation_mode and pretranslated.get('user_native_sites') and not trust_syscall_abi:
        raise ValueError('unchecked direct user accesses require the trusted syscall ABI contract')
    pre_flag=symbols.get('flat_pretranslated_memory')
    pre_mode=0 if not pre_flag or elf.sections[pre_flag['shndx']]['type']==8 else struct.unpack('<Q',elf.read(pre_flag['value'],8))[0]
    if pre_mode not in (0,1) or bool(pre_mode)!=bool(pretranslated) or bool(pre_mode)!=bool(manifest.get('pretranslated_memory')):
        raise ValueError('pretranslated memory mode differs between ELF and metadata')
    elf_ram = metadata.get('elf_ram_initialization')
    ram_flag = symbols.get('flat_elf_ram_initialization')
    ram_mode = struct.unpack('<Q',elf.read(ram_flag['value'],8))[0] if ram_flag else 0
    if ram_mode not in (0,1) or bool(ram_mode)!=bool(elf_ram) or bool(ram_mode)!=manifest.get('elf_ram_initialization',False):
        raise ValueError('ELF RAM initialization mode differs from metadata')
    if elf_ram and (pretranslated or native_mode or not metadata.get('alias_free_memory')):
        raise ValueError('ELF RAM initialization requires alias-free memory with logical stacks')
    embedded = pretranslated or (elf_ram if elf_ram and elf_ram['table_capacity'] else None)
    if bool(embedded) != ('flat_embedded_page_tables' in symbols):
        raise ValueError('embedded page-table reservation differs from mapping metadata')
    native_entry=metadata.get('native_syscall_entry')
    if bool(native_entry)!=bool(manifest.get('native_syscall_sites',0)):
        raise ValueError('native syscall entry mode differs between manifest and metadata')
    if native_entry:
        if validation_mode or not pre_mode or manifest.get('syscall_backend')!='inline-native':
            raise ValueError('native syscall entry requires execution-only pretranslated mode')
        lo,hi=native_entry['stack_range']
        if [lo,hi] not in metadata['write_ranges'] or hi-lo<64 or lo+64>=1<<64:
            raise ValueError('native syscall stack interval differs from writable kernel ranges')
        operations=symbols['flat_ops'];operation_bytes=manifest['adaptations']*64
        if elf.sections[operations['shndx']]['flags']&1 or any(
                segment['flags']&2 and segment['address']<operations['value']+operation_bytes and
                operations['value']<segment['address']+segment['memory_bytes'] for segment in checked['load_segments']):
            raise ValueError('native syscall operations are writable')
        rows=struct.iter_unpack('<8Q',elf.read(operations['value'],operation_bytes))
        expected=[[pc,word] for pc,native,following,word,description,kind,info,immediate in rows
                  if kind==5 and not description and word&0xffe0001f==0xd4000001 and not pc&3 and pc<=(1<<64)-5]
        if native_entry['sites']!=expected or len(expected)!=manifest['native_syscall_sites']:
            raise ValueError('native syscall source sites differ from ELF operations')
    table_base=symbols['flat_embedded_page_tables']['value'] if embedded else TABLES
    if pretranslated:
        count=struct.unpack('<Q',elf.read(symbols['flat_pretranslated_binding_count']['value'],8))[0]
        bindings=list(struct.iter_unpack('<4Q',elf.read(symbols['flat_pretranslated_bindings']['value'],count*32)))
        if bindings!=[(a['va'],a['pa'],a['bytes'],a['attrs']) for a in pretranslated['user_aliases']]:
            raise ValueError('pretranslated bindings differ from ELF')
    backing = symbols['flat_phys']['value']
    if pretranslated and 'descriptor_checks' in pretranslated:
        count=struct.unpack('<Q',elf.read(symbols['flat_pretranslated_check_count']['value'],8))[0]
        checks=list(struct.iter_unpack('<3Q',elf.read(symbols['flat_pretranslated_checks']['value'],count*24)))
        if checks!=[(backing+pa-metadata['ram_base'],mask,value) for pa,mask,value in pretranslated['descriptor_checks']]:
            raise ValueError('pretranslated descriptor checks differ from ELF')
    tracking=symbols.get('flat_translation_tracking')
    tracking_mode=struct.unpack('<Q',elf.read(tracking['value'],8))[0] if tracking else 0
    watched=pretranslated.get('watched_pages') if pretranslated else None
    if tracking_mode not in (0,1) or bool(tracking_mode)!=(watched is not None):
        raise ValueError('descriptor write tracking differs from ELF')
    if watched is not None:
        if watched!=sorted({pa&-PAGE for pa,mask,value in pretranslated['descriptor_checks']}):
            raise ValueError('watched pages differ from descriptor dependencies')
        for name,size in [('flat_translation_tracking',8),('flat_pretranslated_check_count',8),
                          ('flat_pretranslated_checks',24*len(checks)),('flat_pretranslated_root',8),('flat_pretranslated_tcr',8)]:
            symbol=symbols[name]
            lo=symbol['value']&-PAGE;hi=(symbol['value']+size+PAGE-1)&-PAGE
            if elf.sections[symbol['shndx']]['flags']&1 or any(
                    s['flags']&2 and (s['address']&-PAGE)<hi and lo<((s['address']+s['memory_bytes']+PAGE-1)&-PAGE)
                    for s in checked['load_segments']):
                raise ValueError('descriptor tracking dependencies are writable')
        if struct.unpack('<Q',elf.read(symbols['flat_translation_dirty']['value'],8))[0]!=1:
            raise ValueError('descriptor tracking must start dirty')
    if symbols['flat_phys']['size'] != metadata['ram_bytes']:
        raise ValueError('canonical RAM extent differs from mapping metadata')
    if elf_ram or pretranslated:
        from pretranslate_el0_image import merged_ram_extents, ram_load_segments, verify_merged_ram
        ram_end = backing + metadata['ram_bytes']
        loads = [s for s in checked['load_segments']
                 if s['address'] < ram_end and backing < s['address']+s['memory_bytes']]
        extents = merged_ram_extents(elf)
        payload = symbols['flat_payload']['value']
        if extents is not None:
            if extents != (elf_ram or pretranslated)['initial_extents']:
                raise ValueError('merged RAM extent note differs from mapping metadata')
            verify_merged_ram(elf, backing, metadata['ram_bytes'], payload, loads, extents)
        elif elf_ram:
            actual = [(s['address'],s['file_offset'],s['file_bytes'],s['memory_bytes'],s['flags']) for s in loads]
            expected = [(va,offset,filesz,memsz,flags) for _,flags,offset,va,_,filesz,memsz,_ in
                        ram_load_segments(elf,backing,metadata['ram_bytes'],payload,elf_ram['initial_extents'])]
            if actual!=expected:
                raise ValueError('canonical RAM loads differ from packed ELF extents; run pretranslate_el0_image.py')
    if elf_ram and embedded:
        from pretranslate_el0_image import file_offset
        table_capacity = embedded['table_capacity']
        table_offset = file_offset(elf,table_base,table_capacity)
        if table_base%PAGE or table_capacity<=0 or table_capacity%PAGE or not any(
                s['flags']==4 and s['address']<=table_base and
                table_base+table_capacity<=s['address']+s['file_bytes'] and
                s['file_offset']+table_base-s['address']==table_offset for s in checked['load_segments']):
            raise ValueError('embedded tables require file-backed read-only storage')
    immutable_pages=set()
    if metadata.get('native_kernel_stack') or metadata.get('alias_free_memory'):
        count=struct.unpack('<Q',elf.read(symbols['flat_immutable_text_count']['value'],8))[0]
        for pa,size in struct.iter_unpack('<2Q',elf.read(symbols['flat_immutable_text']['value'],count*16)):
            immutable_pages.update(range(pa&-PAGE,(pa+size+PAGE-1)&-PAGE,PAGE))
    bitmap=metadata.get('immutable_page_bitmap')
    bitmap_symbol=symbols.get('flat_immutable_page_bits')
    if (bitmap is not None)!=bool(bitmap_symbol):
        raise ValueError('immutable page bitmap mode differs between ELF and metadata')
    if bitmap is not None:
        from el0_user_memory import immutable_page_bitmap
        symbol=bitmap_symbol
        lo=symbol['value']&-PAGE;hi=(symbol['value']+symbol['size']+PAGE-1)&-PAGE
        writable=any(s['flags']&2 and lo<((s['address']+s['memory_bytes']+PAGE-1)&-PAGE) and
                     (s['address']&-PAGE)<hi for s in checked['load_segments'])
        if elf.sections[symbol['shndx']]['flags']&1 or writable:
            raise ValueError('immutable page bitmap is absent or writable')
        count=struct.unpack('<Q',elf.read(symbols['flat_immutable_text_count']['value'],8))[0]
        spans=list(struct.iter_unpack('<2Q',elf.read(symbols['flat_immutable_text']['value'],count*16)))
        expected=immutable_page_bitmap(metadata['ram_base'],metadata['ram_bytes'],spans+[(pa,PAGE) for pa in watched or []])
        actual=elf.read(symbol['value'],symbol['size'])
        if bitmap.get('page_bytes')!=PAGE or bitmap['bytes']!=len(expected) or actual!=expected or hashlib.sha256(actual).hexdigest()!=bitmap['sha256']:
            raise ValueError('immutable page bitmap differs from ELF protected spans')
    immutable_pages.update(watched or [])
    from el0_compact_dynamic import validate_tables
    validate_tables(elf,checked,metadata,manifest,immutable_pages)
    if manifest.get('dataflow_memory') and not _tables_only:
        from el0_pointer_flow import verify_compiled
        verify_compiled(image,compiler=str(Path(llvm)/'clang'))
    if watched is not None:
        from el0_hardware import direct_ranges
        program=symbols['flat_program']['value']
        pointer,count=struct.unpack('<2Q',elf.read(program+16,16))
        maps=list(struct.iter_unpack('<4Q',elf.read(pointer,32*count)))
        aliases,reads,writes=direct_ranges(maps,metadata['ram_base'],metadata['ram_bytes'],[(pa,PAGE) for pa in sorted(immutable_pages)])
        if metadata['write_ranges']!=[list(row) for row in writes]:
            raise ValueError('native write ranges do not exclude descriptor dependencies')
    if pretranslated and not validation_mode:
        from el0_return import user_resume_ranges
        ranges=user_resume_ranges(pretranslated['user_aliases'],[(pa,PAGE) for pa in sorted(immutable_pages)])
        if pretranslated.get('user_resume_ranges')!=[list(row) for row in ranges]:
            raise ValueError('user resume ranges differ from writable aliases')
        symbol=symbols['flat_user_resume_ranges'];size=16*(len(ranges)+1)
        actual=list(struct.iter_unpack('<2Q',elf.read(symbol['value'],size)))
        if actual!=ranges+[(0,0)]:raise ValueError('user resume ranges differ from ELF')
        if elf.sections[symbol['shndx']]['flags']&1 or any(
                s['flags']&2 and s['address']<symbol['value']+size and symbol['value']<s['address']+s['memory_bytes']
                for s in checked['load_segments']):
            raise ValueError('user resume ranges are writable')
    # Preserve the established header/bitmap diagnostics before checking the
    # additional read-only dispatch records, which may share their LOAD.
    from el0_memory_elision import validate_page_cache_ranges
    validate_page_cache_ranges(elf,checked,metadata)
    from el0_user_exclusion import validate_exclusion_buckets
    validate_exclusion_buckets(elf,checked,metadata)
    from el0_dispatch import validate_dispatch_tables
    validate_dispatch_tables(elf,checked,manifest)
    if _validate_only:
        return
    # Tables has a historical monitor-arena limit. Use the same implementation
    # at relative addresses, then relocate only table descriptors when writing.
    va_bits = 47 if metadata.get('alias_free_memory') else 48
    tables = Tables(va_bits, 0)
    mapped = {}
    def map_page(va, pa, writable, executable=False, user=True):
        if va % PAGE or pa % PAGE or not RAM_BASE <= pa < RAM_END:
            raise ValueError('unaligned or out-of-RAM hardware mapping')
        if not 0 <= va < 1 << va_bits:
            raise ValueError('hardware mapping exceeds TTBR0 address width at ' + hex(va))
        attrs = (1 << 10) | (3 << 8) | (int(user) << 6) | (int(not writable) << 7)
        attrs |= (int(user) << 53) | (int(not executable or not user) << 54)
        old = mapped.get(va)
        if old is not None:
            if old[0] != pa:
                raise ValueError('hardware alias collides with executable RAM at ' + hex(va))
            # ELF segments may share a boundary page; union their permissions.
            writable = writable or old[1]
            executable = executable or old[2]
            attrs &= ~((1 << 7) | (1 << 54))
            attrs |= (int(not writable) << 7) | (int(not executable) << 54)
        mapped[va] = (pa, writable, executable)
        tables.map(va, pa, attrs)
    for segment in checked['load_segments']:
        va = segment['address']
        size = segment['memory_bytes']
        flags = segment['flags']
        if va < SETUP + 0x10000 and va + size > SETUP or not embedded and va < RAM_END and va + size > TABLES:
            raise ValueError('ELF overlaps setup/table reservation')
        for address in range(va & -PAGE, (va + size + PAGE - 1) & -PAGE, PAGE):
            map_page(address, address, bool(flags & 2), bool(flags & 1))
    for alias in metadata['aliases']+(pretranslated['user_aliases'] if pretranslated else []):
        for offset in range(0, alias['bytes'], PAGE):
            map_page(alias['va'] + offset, backing + alias['pa'] - metadata['ram_base'] + offset,
                     not alias['attrs'] & (1 << 7) and alias['pa']+offset not in immutable_pages)
    # Setup is executable only at EL1 and is never a computation helper.
    for address in range(SETUP, SETUP + 0x10000, PAGE):
        map_page(address, address, True, True, False)
    raw = bytearray(tables.next)
    for offset, page in tables.pages.items():
        for index in range(512):
            value = struct.unpack_from('<Q', page, index * 8)[0]
            if value & 3 == 3 and value & 0x0000fffffffff000 < tables.next:
                value += table_base
            struct.pack_into('<Q', raw, offset + index * 8, value)
    if table_base + len(raw) > RAM_END:
        raise ValueError('page tables exceed model RAM')
    if _tables_only:
        return dict(address=table_base,data=bytes(raw),bytes=len(raw))
    if embedded:
        if len(raw)>embedded['table_capacity'] or elf.read(table_base,len(raw))!=raw:
            name = 'embedded pretranslated page tables' if pretranslated else 'embedded page tables'
            raise ValueError('ELF lacks matching '+name+'; run pretranslate_el0_image.py')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'page-tables.bin').write_bytes(raw)
    registers = platform_registers(va_bits, table_base + tables.root, zero_bytes)
    source = '.text\n.global _start\n_start:\n    msr daifset,#15\n'
    for name, value in registers.items():
        source += '    ldr x0,=0x%x\n    msr %s,x0\n' % (value, name.lower()) if name != 'SCTLR_EL1' else ''
    source += '''    adr x0,hardware_vectors
    msr vbar_el1,x0
    dsb sy
    isb
    tlbi vmalle1
    dsb sy
    isb
    ldr x0,=0x%x
    msr sctlr_el1,x0
    isb
'''%registers['SCTLR_EL1']
    if zero_bytes:
        expected=(zero_bytes//4).bit_length()-1
        source+='''    mrs x0,dczid_el0
.global hardware_zero_check
hardware_zero_check:
    mov x1,#%d
    cmp x0,x1
    b.eq 1f
    mov x2,#0xdc
    b hardware_unexpected
1:
'''%expected
    source+='''
    mov x0,#0x3c0
    msr spsr_el1,x0
    ldr x0,=%s
    msr elr_el1,x0
    eret
    .ltorg
    .balign 2048
hardware_vectors:
    .rept 16
    .balign 128
    b hardware_exception
    .endr
hardware_exception:
    mrs x0,esr_el1
    mrs x1,elr_el1
    mrs x2,far_el1
.global hardware_unexpected
hardware_unexpected:
    b hardware_unexpected
''' % checked['entry']
    (out / 'setup.S').write_text(source)
    subprocess.run([str(Path(llvm) / 'clang'), '--target=aarch64-none-elf', '-mcpu=cortex-a53',
                    '-nostdlib', '-static', '-fuse-ld=lld', '-Wl,--build-id=none,-Ttext=0x%x,-e,_start' % SETUP,
                    str(out / 'setup.S'), '-o', str(out / 'setup.elf')], check=True)
    setup = Elf(out / 'setup.elf')
    stop = next(s['value'] for s in setup.symbols if s['name'] == 'hardware_unexpected')
    plan = dict(format='osrec-el0-hardware-load-v1', image='checkpoint',
                image_sha256=checked['image_sha256'], mapping_sha256=sha(image / 'hardware-memory.json'),
                page_tables=dict(address=table_base, bytes=len(raw), sha256=sha(out / 'page-tables.bin'),embedded=bool(embedded)),
                load_segments=checked['load_segments'], entry=checked['entry'], execution_level=0,
                platform_registers=registers, ram=dict(address=RAM_BASE, bytes=RAM_END - RAM_BASE),
                native_zero_bytes=zero_bytes, runtime_validation=bool(validation_mode),trust_syscall_abi=trust_syscall_abi,
                result=dict(address=checked['result_address'], bytes=checked['result_bytes']),
                completion_pc=checked['terminal_pc'], unexpected_pc=hex(stop),
                setup=dict(image='setup.elf', sha256=sha(out / 'setup.elf'), entry=SETUP,
                           scope='QEMU model initialization only; outside delivered EL0 computation'),
                runtime_el1_services=False, physical_devices=False, cycles_verified=False,
                rtl_execution_verified=False)
    if metadata.get('alias_free_memory'):
        plan['address_bits']=va_bits
        plan['original_va_aliases']=0
    if elf_ram:
        plan['elf_ram_initialization']=True
        plan['runtime_snapshot_copy']=False
    if metadata.get('native_kernel_stack'):
        plan['native_kernel_stack']=dict(writable_static_stack_required=True,logical_user_stack=not bool(pretranslated),
                                        immutable_alias_pages_readonly=len(immutable_pages))
    if native_entry:
        plan['native_syscall_entry']=dict(sites=len(native_entry['sites']),stack_range=native_entry['stack_range'])
    if pretranslated:
        plan['pretranslated_memory']=dict(elf_ram_initialization=True,embedded_tables=True,
                                          initial_user_aliases=len(pretranslated['user_aliases']),native_user_stack=True)
    if 'flat_memory_profile' in symbols:
        profile=symbols['flat_memory_profile']
        if profile['size']!=64:raise ValueError('unsupported memory-profile layout')
        plan['memory_profile']=dict(address=profile['value'],bytes=profile['size'])
    if 'flat_system_profile' in symbols:
        profile=symbols['flat_system_profile']
        if profile['size']!=4096*24:raise ValueError('unsupported system-profile layout')
        plan['system_profile']=dict(address=profile['value'],bytes=profile['size'])
    (out / 'hardware-load-plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    return plan


def run(image, prepared, out, timeout=180, qemu='qemu-system-aarch64', plugin=None):
    image, prepared, out = (Path(p).resolve() for p in (image, prepared, out))
    plan = json.loads((prepared / 'hardware-load-plan.json').read_text())
    artifacts=[(image / 'checkpoint', plan['image_sha256']),
                           (image / 'hardware-memory.json', plan['mapping_sha256']),
                           (prepared / 'setup.elf', plan['setup']['sha256'])]
    if not plan['page_tables'].get('embedded'):
        artifacts.append((prepared / 'page-tables.bin', plan['page_tables']['sha256']))
    for path,expected in artifacts:
        if sha(path) != expected:
            raise ValueError('hardware artifact changed: ' + str(path))
    out.mkdir(parents=True, exist_ok=False)
    exception_log = out / 'qemu-exceptions.log'
    port = free_port()
    command = [qemu, '-M', 'virt-9.2,secure=off,virtualization=off', '-cpu', 'cortex-a53',
               '-accel', 'tcg', '-smp', '1', '-m', '2048M', '-nodefaults', '-display', 'none',
               '-monitor', 'none', '-serial', 'none', '-semihosting-config', 'enable=off',
               '-d', 'int', '-D', str(exception_log),
               '-device', 'loader,file=' + str(image / 'checkpoint'),
               '-device', 'loader,file=' + str(prepared / 'setup.elf') + ',cpu-num=0',
               '-S', '-gdb', 'tcp:127.0.0.1:%d' % port]
    if not plan['page_tables'].get('embedded'):
        command+=['-device','loader,file='+str(prepared/'page-tables.bin')+',addr=0x%x,force-raw=on'%plan['page_tables']['address']]
    if plugin is not None:
        command += ['-plugin', plugin]
    started = time.monotonic()
    remote = None
    with (out / 'qemu.stderr.log').open('wb') as errors:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors)
        try:
            remote = Remote(port, timeout=timeout)
            entry, completion, unexpected = (int(plan[k], 0) for k in ('entry', 'completion_pc', 'unexpected_pc'))
            remote.breakpoint(entry)
            remote.breakpoint(unexpected)
            remote.resume()
            pc = remote.wait(timeout)
            entry_state = remote.registers(('pc', 'cpsr'))
            if pc != entry or entry_state['cpsr'] & PSTATE_NON_EL0T:
                raise ValueError('hardware setup failed before EL0 entry: '+json.dumps(remote.registers(('pc','cpsr','x0','x1','x2'))))
            remote.breakpoint(entry, False)
            remote.breakpoint(completion)
            remote.resume()
            pc = remote.wait(timeout)
            state = remote.registers(('pc', 'cpsr', 'x0', 'x1', 'x2'))
            raw = remote.read(int(plan['result']['address'], 0), plan['result']['bytes'])
            uart_bytes=struct.unpack_from('<Q',raw,11*8)[0]
            if uart_bytes>4096:raise ValueError('runtime UART output exceeds buffer')
            image_symbols={s['name']:s for s in Elf(image/'checkpoint').symbols if s['shndx']}
            uart_symbol=image_symbols['flat_uart']
            uart=remote.read(uart_symbol['value'],uart_bytes) if uart_bytes else b''
            # Host-side evidence only: exclude the frame's uninitialized
            # padding, and never add comparison code or expected data to ELF.
            guest_state=remote.read(image_symbols['flat_initial']['value'],792) if 'flat_initial' in image_symbols else None
            shadow_state=remote.read(image_symbols['flat_shadow']['value'],104) if 'flat_shadow' in image_symbols else None
            memory_profile=remote.read(plan['memory_profile']['address'],64) if 'memory_profile' in plan else None
            system_profile=remote.read(plan['system_profile']['address'],4096*24) if 'system_profile' in plan else None
        finally:
            if remote:
                remote.socket.close()
            process.terminate()
            process.wait(timeout=10)
    values = struct.unpack('<40Q', raw)
    result = dict(zip(RESULT_NAMES, values[:16]))
    result['debug'] = values[16:]
    profile = None
    if result['debug'][13] == 0x31464f525052534f:
        kinds = ('native', 'memory', 'stack', 'system', 'indirect', 'svc', 'boundary', 'unsupported', 'observe', 'coverage')
        profile = dict(zip(kinds, result['debug'][14:]))
    memory_counts=struct.unpack('<8Q',memory_profile) if memory_profile is not None else None
    system_counts=[dict(word=hex(word),metadata=hex(metadata),count=count) for word,metadata,count in
                   struct.iter_unpack('<3Q',system_profile) if count] if system_profile is not None else None
    trace = audit_exception_trace(exception_log, entry)
    el0_interval_verified = (pc == completion and not state['cpsr'] & PSTATE_NON_EL0T and
                             trace['bootstrap_to_entry_observed'] and not trace['unexpected_log_lines'])
    verified = (el0_interval_verified and state['x0'] == 0 and
                result['magic'] == 0x324c55464652534f and result['version'] == 2 and result['status'] == 1 and
                result['first_mismatch'] == (1 << 64) - 1 and not result['missing_pc'] and
                (profile is None or sum(profile.values()) == result['transitions']) and
                (memory_counts is None or profile is None or sum(memory_counts[:5])+memory_counts[7]==profile['memory']) and
                (system_counts is None or profile is None or sum(r['count'] for r in system_counts)==profile['system']))
    report = dict(verified=verified, runtime_validation=plan.get('runtime_validation',True),
                  trust_syscall_abi=plan.get('trust_syscall_abi',False),
                  verification_scope='workload-results' if plan.get('runtime_validation',True) else 'execution-completion',
                  entry=entry_state, completion=state, result=result,
                  image_sha256=plan['image_sha256'], mapping_sha256=plan['mapping_sha256'],
                  page_tables_sha256=plan['page_tables']['sha256'], hardware_exceptions=trace['hardware_exceptions'],
                  el0_interval_verified=el0_interval_verified, exception_trace=trace,
                  execution_interval='ELF entry up to the completion breakpoint, before terminal exit',
                  runtime_el1_services=False, host_calls_before_completion=0 if el0_interval_verified else None,
                  functional_model='QEMU system Cortex-A53', seconds=round(time.monotonic() - started, 3),
                  cycles_verified=False, rtl_execution_verified=False)
    if plan.get('pretranslated_memory') or plan.get('elf_ram_initialization'):
        report['elf_ram_initialization']=True
        report['embedded_page_tables']=bool(plan['page_tables'].get('embedded'))
        report['external_page_tables_loaded']=not report['embedded_page_tables']
    if plan.get('native_syscall_entry'):
        report['native_syscall_entry']=plan['native_syscall_entry']
    if profile is not None:
        report['gateway_profile'] = profile
    if memory_profile is not None:
        names=('user','kernel','user_copy','exclusive','hint','uart','fault','post')
        report['memory_profile']=dict(zip(names,memory_counts))
    if system_counts is not None:
        report['system_profile']=sorted(system_counts,key=lambda r:-r['count'])
    (out / 'result.bin').write_bytes(raw)
    (out / 'uart.bin').write_bytes(uart)
    terminal={}
    for name,data in (('guest',guest_state),('shadow',shadow_state)):
        if data is not None:
            (out/(name+'-state.bin')).write_bytes(data)
            terminal[name]=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
    if terminal:report['terminal_state']=terminal
    (out / 'validation.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('prepare')
    build.add_argument('--image', required=True)
    build.add_argument('--out', required=True)
    build.add_argument('--llvm', type=Path, default=LLVM)
    check = commands.add_parser('run')
    check.add_argument('--image', required=True)
    check.add_argument('--prepared', required=True)
    check.add_argument('--out', required=True)
    check.add_argument('--timeout', type=int, default=180)
    check.add_argument('--plugin', help='QEMU instruction plugin and its comma-separated arguments')
    args = parser.parse_args()
    report = prepare(args.image, args.out, args.llvm) if args.command == 'prepare' else run(args.image, args.prepared, args.out, args.timeout, plugin=args.plugin)
    print(json.dumps(report, indent=2))
    if args.command == 'run' and not report['verified']:
        raise SystemExit(1)
