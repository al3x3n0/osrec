#!/usr/bin/env python3
"""Build an EL0 source image for the research mini-OS.

The live instructions are changed only at the architecture edge: system operations,
exception returns and PAC hints. Boundaries are BRKs. The site table retains each
original instruction. Unknown operations stop in the shared core.
Optional linked branch veneers handle simple shadow-register operations without
exceptions; unsupported sites retain the trap path.
"""
import bisect
import collections
import hashlib
import json
import struct
import subprocess
import shutil
from pathlib import Path

from kernel_sysregs import encodings
from va_constants import move_immediate

PAGE = 4096
MONITOR_PA = 0x71000000
MONITOR_VA = 0xffff8000f0000000
MONITOR_SIZE = 16 << 20
SHARED_MONITOR_VA = 1 << 40
SHARED_RAM_VA = SHARED_MONITOR_VA + (1 << 30)
TABLE_PA = 0x70000000
STAGE = 0x78000000
BRK_SITE = 0xd4200000 | (0xf00 << 5)
BRK_BOUNDARY = 0xd4200000 | (0xf01 << 5)
NOP = 0xd503201f
MASK48 = (1 << 48) - 1
FIXED_CPU_REGISTERS = {'AIDR', 'AIDR_EL1', 'CLIDR', 'CLIDR_EL1', 'CTR_EL0',
                       'DCZID_EL0', 'MIDR_EL1', 'MPIDR_EL1', 'REVIDR_EL1',
                       'MVFR0_EL1', 'MVFR1_EL1', 'MVFR2_EL1'}


def instruction_ranges(image, sections):
    """Use ELF $x/$d mapping symbols so literal pools stay byte-for-byte intact."""
    ranges=[]
    for lo,hi in sections:
        events=sorted({(s['value'],s['name'].split('.')[0]) for s in image.symbols
                       if lo<=s['value']<hi and s['name'].split('.')[0] in ('$x','$d')})
        if not events or events[0][0]!=lo:
            raise ValueError('executable section at 0x%x has no initial mapping symbol'%lo)
        for i,(at,kind) in enumerate(events):
            end=events[i+1][0] if i+1<len(events) else hi
            if kind=='$x' and at<end:ranges.append((at,end))
    return sorted(ranges)


def fixed_system_reads(cpu):
    """Values fixed by the logical EL1 mode or the captured single CPU model."""
    captured = dict(cpu.get('sysregs_all', {}), **cpu['sysregs'])
    return dict(CurrentEL=4, **{name: value for name, value in captured.items()
                               if name in FIXED_CPU_REGISTERS or name.startswith('ID_')})


def system_read_moves(values):
    """{MRS register key: the single move into x0, if one exists}."""
    keys, _ = encodings(values)
    return {key: word for name, key in keys.items()
            if (word := move_immediate(values[name])) is not None}


def rewrite(insn, constant_moves=None, *, shadow_tls=False):
    """Return (replacement, kind). An unrecognised trapped op is an explicit stop.

    NZCV and FP retain their hardware meaning. The user thread register can
    be shadowed in kernel code when the veneers use the hardware slot. Counter
    reads retain the existing source-image clock limitation. Barriers and BTI are
    legal at EL0. All other system operations go through the shadow core.
    """
    if insn in {0xd503211f, 0xd503215f, 0xd503219f, 0xd50321df,
                0xd503233f, 0xd503237f, 0xd50323bf, 0xd50323ff, 0xd50320ff}:
        return NOP, 'pac-hint'
    if insn & 0xfff00000 in (0xd5300000, 0xd5100000):
        key = insn >> 5 & 0xffff
        if constant_moves and insn & 0xfff00000 == 0xd5300000 and key in constant_moves:
            # ORR-immediate Rd=31 writes SP. An MRS to XZR discards the result.
            rd = insn & 31
            move = constant_moves[key]
            if rd == 31 and move & 0x7f800000 == 0x32000000:
                return NOP, 'inline sysreg'
            return move | rd, 'inline sysreg'
        if key in {0xda10, 0xda20, 0xda21} or (key == 0xde82 and not shadow_tls):
            return insn, None
        if insn & 0xfff00000 == 0xd5300000 and key in {0xdf01, 0xdf02}:
            return insn, None  # CNTPCT, CNTVCT
        return BRK_SITE, 'sysreg'
    if insn & 0xfff8f01f == 0xd500401f:
        return BRK_SITE, 'pstate'
    if insn & 0xfff80000 in (0xd5080000, 0xd5280000):
        if insn & ~31 == 0xd50b7420:  # DC ZVA: enabled at EL0, same address and effect
            return insn, None
        return BRK_SITE, 'sys'
    if insn in {0xd69f03e0, 0xd69f0bff, 0xd69f0fff, 0xd503205f, 0xd503207f}:
        return BRK_SITE, 'control'  # ERET variants, WFE, WFI
    if insn & 0xffe0001f in (0xd4000002, 0xd4000003):
        return BRK_SITE, 'control'  # HVC, SMC
    return insn, None


class Tables:
    """4 KiB arm64 translation tables, with no inherited table restrictions."""
    def __init__(self, bits, base=TABLE_PA):
        if not 25 <= bits <= 48:
            raise ValueError('only 4 KiB, 25..48-bit address spaces are supported')
        self.bits = bits
        self.start = 3 - (bits - 13) // 9
        self.pages = {}
        self.next = base
        self.root = self.allocate()

    def allocate(self):
        pa = self.next
        self.next += PAGE
        if self.next > MONITOR_PA:
            raise ValueError('translation tables overlap the monitor')
        self.pages[pa] = bytearray(PAGE)
        return pa

    def map(self, va, pa, attrs):
        node = self.root
        for level in range(self.start, 3):
            shift = 12 + 9 * (3 - level)
            index = va >> shift & ((1 << (self.bits - shift)) - 1 if level == self.start else 511)
            d, = struct.unpack_from('<Q', self.pages[node], index * 8)
            if not d:
                d = self.allocate() | 3
                struct.pack_into('<Q', self.pages[node], index * 8, d)
            node = d & MASK48 & ~0xfff
        index = va >> 12 & 511
        struct.pack_into('<Q', self.pages[node], index * 8, pa | attrs | 3)


def shadow_image(cpu):
    sr = cpu['sysregs']
    all_regs = dict(cpu.get('sysregs_all', {}), **sr)
    keys, missing = encodings(all_regs)
    known = bytearray(8192)
    values = bytearray(65536 * 8)
    for name, key in keys.items():
        known[key >> 3] |= 1 << (key & 7)
        struct.pack_into('<Q', values, key * 8, all_regs[name])
    fields = [sr['SP_EL0'], cpu['sp'], sr['ELR_EL1'], sr['SPSR_EL1'],
              sr['ESR_EL1'], sr['FAR_EL1'], sr['SPSR_EL1'] & 0x3c0,
              sr['SPSR_EL1'] >> 22 & 1, sr['VBAR'], sr['TTBR0_EL1'], 0, 0, 0]
    return struct.pack('<13Q', *fields) + known + values, missing


def site_page_index(sites):
    if not sites:
        return 0, [0]
    addresses = [va for va, _, _ in sites]
    base = addresses[0] & -PAGE
    end = (addresses[-1] & -PAGE) + PAGE
    return base, [bisect.bisect_left(addresses, page) for page in range(base, end + PAGE, PAGE)]


def reserve_load_ranges(segments, ranges):
    """Cover RAM and BSS with PT_LOAD memory tails, preserving the file bytes."""
    runs = dict(segments)
    sizes = {address: len(data) for address, data in runs.items()}
    for start, end in ranges:
        addresses = sorted(pa for pa in runs if start <= pa < end)
        if not addresses or addresses[0] != start:
            runs[start] = b''
            sizes[start] = 0
            addresses.insert(0, start)
        for address, limit in zip(addresses, addresses[1:] + [end]):
            if address + sizes[address] > limit:
                raise ValueError(f'ELF load segment exceeds the reserved memory at {address:#x}')
            sizes[address] = limit - address
    return [(address, runs[address], sizes[address]) for address in sorted(runs)]


def build(dump, vmlinux, profile_path, out, dwarf_db=None,lower_kernel=0,va_profile=None,dispatch='traps',
          segment_only=False):
    from source_image import Ram, text_ranges, boundary_extents, LLVM, ROOT, DTB, ATTRS, CONTIGUOUS, NT
    from kernel_boundary_replay import elf

    ram = Ram(dump)
    if dispatch not in ('traps','branches'):
        raise ValueError('unknown EL0 dispatch backend')
    if len(ram.ram)!=ram.size:raise ValueError('RAM dump size does not match state.json')
    if ram.base + ram.size > TABLE_PA:
        raise ValueError('captured RAM overlaps the monitor reservation')
    tcr = ram.sysregs['TCR_EL1']
    if ram.sysregs['SPSR_EL1'] & ~0xf0000000:
        raise ValueError('captured user PSTATE needs unsupported architecture state')
    if (tcr >> 14 & 3) != 0 or (tcr >> 30 & 3) != 2:
        raise ValueError('the EL0 monitor requires 4 KiB granules')
    from kernel_replay_tables import KERNEL_BASE, TCR_A1, TCR_EPD1, captured_roots
    shared = bool(tcr & TCR_EPD1)
    if segment_only and not shared:
        raise ValueError('segment-only loading requires a shared-root capture')
    if shared:
        if lower_kernel or tcr & TCR_A1:
            raise ValueError('the shared root requires TTBR0 ASIDs and an already low-linked kernel')
        _, guest_kernel_entry, _ = captured_roots(ram)
    fast_sysregs = shared and dispatch == 'branches'
    fixed_reads = fixed_system_reads(ram.state['cpu']) if fast_sysregs else {}
    constant_moves = system_read_moves(fixed_reads) if fixed_reads else {}
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    image, text = text_ranges(vmlinux)
    instructions=instruction_ranges(image,text)
    instruction_starts=[lo for lo,_ in instructions]
    def is_instruction(va):
        i=bisect.bisect_right(instruction_starts,va)-1
        return i>=0 and va<instructions[i][1]
    profile = json.loads(Path(profile_path).read_text())
    cuts = boundary_extents(profile, image)
    starts = [a for a, _, _ in cuts]
    def boundary(va):
        i = bisect.bisect_right(starts, va) - 1
        return i >= 0 and va < cuts[i][1]
    user, _ = ram.mappings(0)
    if shared:
        upper = [leaf for leaf in user if leaf[0] >= KERNEL_BASE]
        user = [leaf for leaf in user if leaf[0] < KERNEL_BASE]
    else:
        upper, _ = ram.mappings(1)
    devices = [(int(d['pa'], 16), int(d['pa'], 16) + int(d['size'], 16)) for d in profile.get('devices', [])]
    symbols = {s['name']: s['value'] for s in image.symbols if s['value']}
    lowering=None
    if lower_kernel:
        if lower_kernel!=32<<40:raise ValueError('the EL0 lower MMU currently uses a 32 TiB linear shift')
        if not dwarf_db or not va_profile:raise ValueError('lowering requires --dwarf-db and --va-profile')
        from kernel_dwarf_db import load
        from va_lowering import plan
        lowering=plan(ram,image,json.loads(Path(va_profile).read_text()),load(dwarf_db),instructions)
    move=lowering['move'] if lowering else lambda va:va
    monitor_va = SHARED_MONITOR_VA if shared else MONITOR_VA & MASK48 if lowering else MONITOR_VA
    table_window=0x8000e0000000
    init = symbols['__init_begin'], symbols['__init_end']
    blob = {}
    sites = []
    counts = collections.Counter()
    mapped = []
    actual_mapped=[]
    kernel_bits = ram.bits[0] if shared else ram.bits[1]
    root = Tables(kernel_bits)
    for va, pa, d in upper:
        data = ram.page(pa)
        executable = any(lo <= va < hi for lo, hi in text)
        if init[0] <= va < init[1]:
            continue
        if data is None:
            if not any(lo <= pa < hi for lo, hi in devices):
                continue
            kind = 'device'
        elif executable:
            words = bytearray(data)
            for k in range(0, PAGE, 4):
                if not is_instruction(va+k):continue
                original, = struct.unpack_from('<I', words, k)
                if boundary(va + k):
                    replacement, kind = BRK_BOUNDARY, 'boundary'
                else:
                    replacement, kind = rewrite(original, constant_moves, shadow_tls=fast_sysregs)
                    if lowering and va+k in lowering['code']:
                        replacement=lowering['code'][va+k];kind='lowered code'
                if kind:
                    counts[kind] += 1
                    if replacement == BRK_SITE:
                        metadata=lowering['extended'].get(va+k,(original,0))[1] if lowering else 0
                        sites.append((move(va+k),original,metadata))
                    struct.pack_into('<I', words, k, replacement)
            blob[pa] = bytes(words)
            kind = 'text'
        else:
            kind = 'data'
            if data != bytes(PAGE):
                blob.setdefault(pa, data)
        attrs = d & ATTRS & ~CONTIGUOUS & ~NT
        attrs |= 1 << 6  # AP[1]: kernel code and data become EL0 accessible
        attrs = (attrs & ~(1 << 54)) if executable else attrs | (1 << 54)
        attrs |= 1 << 53  # PXN: the EL1 monitor never executes captured text
        root.map(move(va), pa, attrs)
        actual_mapped.append((move(va),pa,attrs))
        mapped.append(dict(va=hex(move(va)),original_va=hex(va),pa=hex(pa),kind=kind))
    calls=[]
    call_base=call_size=0
    percpu_offset = None
    if dispatch=='branches':
        from source_image_calls import analyse_sites,choose_base,assembly,BRANCH_PA
        original_pages={va:pa for va,pa,_ in upper}
        originals={move(va):va for va,_,_ in upper}
        class OriginalWords:
            def __contains__(self,pc):
                return (pc%4==0 and is_instruction(pc) and pc&~4095 in original_pages
                        and not init[0]<=pc<init[1] and not boundary(pc))
            def __getitem__(self,pc):
                if pc not in self:raise KeyError(pc)
                return struct.unpack_from('<I',ram.ram,original_pages[pc&~4095]-ram.base+(pc&4095))[0]
        calls=analyse_sites(sites, OriginalWords(), lambda pc: originals[pc&~4095]+(pc&4095),
                            percpu=fast_sysregs and 'TPIDR_EL1' in ram.sysregs, tls_spill=fast_sysregs)
        if calls:
            percpu_offset = next((v.offset for v in calls if v.kind == 'percpu'), None)
            alias_bytes = (3 if percpu_offset is not None else 2)*PAGE
            call_base,call_size=choose_base(actual_mapped+user,calls,calls[0].pc)
            call_alias=call_base+((call_size+4095)&~4095)
            if shared and not KERNEL_BASE <= call_base < call_alias + alias_bytes <= SHARED_MONITOR_VA:
                raise ValueError('shared-root veneers must fit in the kernel window')
            (out/'calls.S').write_text(assembly(calls))
            (out/'calls.json').write_text(json.dumps([v.report() for v in calls],indent=1)+'\n')
            attrs=(1<<6)|(1<<10)|(3<<8)|(1<<53)
            for k in range(0,(call_size+4095)&~4095,PAGE):
                root.map(call_base+k,BRANCH_PA+k,attrs)
                actual_mapped.append((call_base+k,BRANCH_PA+k,attrs))
            # Reserve the alias pages before the monitor link determines the
            # physical shadow address. The range list needs their VAs now.
            for k in range(0,alias_bytes,PAGE):
                a=(1<<6)|(1<<10)|(3<<8)|(1<<53)|(1<<54)
                root.map(call_alias+k,MONITOR_PA+k,a)
                actual_mapped.append((call_alias+k,MONITOR_PA+k,a))
    # Preserve all nonzero RAM, including pages reached by allocator/page-table
    # updates after the capture, and all aliases of rewritten text.
    for pa in range(ram.base, ram.base + ram.size, PAGE):
        data = ram.page(pa)
        if data != bytes(PAGE):
            blob.setdefault(pa, data)
    if lowering:
        for pa,(_,new,why) in lowering['patches'].items():
            page=pa&~4095;b=bytearray(blob.get(page,bytes(PAGE)))
            struct.pack_into('<Q',b,pa&4095,new);blob[page]=bytes(b)
    monitor_attrs = (1 << 54) | (1 << 10) | (3 << 8)
    if not shared:
        for k in range(0, MONITOR_SIZE, PAGE):
            root.map(monitor_va + k, MONITOR_PA + k, monitor_attrs)
            actual_mapped.append((monitor_va+k,MONITOR_PA+k,monitor_attrs))
    if lowering:
        for k in range(0,MONITOR_PA-TABLE_PA,PAGE):
            root.map(table_window+k,TABLE_PA+k,monitor_attrs)
            actual_mapped.append((table_window+k,TABLE_PA+k,monitor_attrs))
        data=lowering['veneer'];data+=bytes(-len(data)%PAGE)
        attrs=(1<<6)|(1<<10)|(3<<8)|(1<<53)
        for k in range(0,len(data),PAGE):
            va,pa=lowering['veneer_va']+k,lowering['veneer_pa']+k
            root.map(va,pa,attrs);blob[pa]=data[k:k+PAGE]
            actual_mapped.append((va,pa,attrs))
    native_upper=Tables(kernel_bits,root.next)
    mapped_vas={int(m['original_va'],16) for m in mapped}
    for va,pa,d in upper:
        if va in mapped_vas:native_upper.map(move(va),pa,d&ATTRS&~CONTIGUOUS&~NT)
    if not shared:
        for k in range(0, MONITOR_SIZE, PAGE):
            native_upper.map(monitor_va+k,MONITOR_PA+k,monitor_attrs)
    if lowering:
        for va,pa,attrs in actual_mapped:
            if table_window<=va<table_window+(MONITOR_PA-TABLE_PA):native_upper.map(va,pa,attrs)
            if lowering['veneer_va']<=va<lowering['veneer_va']+len(lowering['veneer']):
                native_upper.map(va,pa,(attrs&~(1<<6))|(1<<54))
    if calls:
        for k in range(0,(call_size+4095)&~4095,PAGE):
            native_upper.map(call_base+k,BRANCH_PA+k,(1<<10)|(3<<8)|(1<<53)|(1<<54))
        for k in range(0,alias_bytes,PAGE):
            native_upper.map(call_alias+k,MONITOR_PA+k,(1<<10)|(3<<8)|(1<<53)|(1<<54))
    identity = Tables(ram.bits[0], native_upper.next)
    for k in range(0, MONITOR_SIZE, PAGE):
        identity.map(MONITOR_PA + k, MONITOR_PA + k, monitor_attrs & ~(1 << 54))
        if shared:
            identity.map(monitor_va + k, MONITOR_PA + k, monitor_attrs)
    if shared:
        for k in range(0, ram.size, PAGE):
            identity.map(SHARED_RAM_VA + k, ram.base + k, monitor_attrs | (1 << 53))
    if lowering:
        for va,pa,attrs in actual_mapped:identity.map(va,pa,attrs)

    if dwarf_db:
        from kernel_dwarf_db import load
        from kernel_sysregs import from_cpu_data
        recovered=from_cpu_data(ram,image,load(dwarf_db))
        recovered.update(ram.state['cpu'].get('sysregs_all',{}))
        ram.state['cpu']['sysregs_all']=recovered
        if lowering:
            recovered.update(lowering['cpu']['sysregs_all']);lowering['cpu']['sysregs_all']=recovered
    cpu=lowering['cpu'] if lowering else ram.state['cpu']
    shadow, missing = shadow_image(cpu)
    if fast_sysregs:
        from source_image_calls import TPIDR_EL0, TPIDR_EL1
        required = [('TPIDR_EL0', TPIDR_EL0)]
        if percpu_offset is not None:
            required.append(('TPIDR_EL1', TPIDR_EL1))
        for name, key in required:
            if not shadow[13*8 + (key >> 3)] & (1 << (key & 7)):
                raise ValueError(f'shared-root branch dispatch requires a captured {name} value')
    (out / 'shadow.bin').write_bytes(shadow)
    sites.sort()
    (out / 'sites.bin').write_bytes(b''.join(struct.pack('<QII', *site) for site in sites))
    sr = cpu['sysregs']
    context = [cpu['gprs']['x%d' % i] for i in range(31)] + [sr['SP_EL0'], sr['ELR_EL1'] - 4, sr['SPSR_EL1'] & 0xf0000000]
    fp = b''.join(int(cpu['fp']['v']['v%d' % i], 16).to_bytes(16, 'little') for i in range(32))
    fp += struct.pack('<4Q', cpu['fp']['fpsr'], cpu['fp']['fpcr'], sr['TPIDR_EL0'], sr['TPIDRRO_EL0'])
    (out / 'fp.bin').write_bytes(fp)
    staged = sorted(pa for pa in blob if DTB[0] <= pa < DTB[1])
    def quad(values):
        return ''.join('    .quad %s\n' % (hex(v) if isinstance(v, int) else v) for v in values)
    data = '.section .data,"aw"\n.balign 16\n.global boot_params\nboot_params:\n'
    # No hardware PAN, pointer signing, WXN or EL0 trap of counter/cache access.
    sctlr = sr['SCTLR'] & ~((1 << 19) | (1 << 31) | (1 << 30) | (1 << 27) | (1 << 13))
    actual_tcr=tcr|(1<<23) if lowering else tcr
    actual_ttbr1 = 0 if shared else sr['TTBR1_EL1'] & 0xffff000000000000 if lowering else root.root
    data += quad([sr['MAIR_EL1'], actual_tcr, actual_ttbr1, identity.root, sr['CPACR'], sr['CNTKCTL'] | 3,
                  sctlr, 'minios_vectors', 'osrec_monitor_stack_top', 'minios_main'])
    for name, body in [('staged_count', quad([len(staged)])),
                       ('staged_pages', quad([v for i, pa in enumerate(staged) for v in (STAGE + i * PAGE, pa)])),
                       ('osrec_ttbr1_root', quad([root.root])),
                       ('osrec_ttbr1_user_root', quad([native_upper.root])),
                       ('osrec_site_count', quad([len(sites)])),
                       ('osrec_branch_state', '    .zero 16\n'),
                       ('osrec_shadow', '    .incbin "%s"\n' % (out / 'shadow.bin')),
                       ('osrec_sites', '    .incbin "%s"\n' % (out / 'sites.bin')),
                       ('osrec_start_context', quad(context)),
                       ('osrec_start_fp', '    .incbin "%s"\n' % (out / 'fp.bin'))]:
        data += '.balign 16\n.global %s\n%s:\n%s' % (name, name, body)
    if lowering:
        from va_lowering import intervals
        ranges=intervals(va for va,_,_ in actual_mapped)
        for name,values in [('osrec_kernel_range_count',[len(ranges)]),
                            ('osrec_kernel_ranges',[v for pair in ranges for v in pair]),
                            ('osrec_veneer_base',[lowering['veneer_va']]),
                            ('osrec_veneer_count',[len(lowering['origins'])]),
                            ('osrec_veneer_origins',lowering['origins'])]:
            data+='\n.balign 16\n.global %s\n%s:\n%s'%(name,name,quad(values))
    if shared:
        user_kernel_entry = struct.unpack_from('<Q', native_upper.pages[native_upper.root], 8)[0]
        el0_kernel_entry = struct.unpack_from('<Q', root.pages[root.root], 8)[0]
        monitor_entry = struct.unpack_from('<Q', identity.pages[identity.root], 16)[0]
        for name, values in [('osrec_shared_ram_pa', [ram.base]), ('osrec_shared_ram_size', [ram.size]),
                             ('osrec_shared_ram_va', [SHARED_RAM_VA]), ('osrec_shared_monitor_pa', [MONITOR_PA]),
                             ('osrec_shared_monitor_va', [monitor_va]), ('osrec_shared_monitor', [monitor_entry]),
                             ('osrec_shared_guest_kernel', [guest_kernel_entry]),
                             ('osrec_shared_kernel', [user_kernel_entry, el0_kernel_entry])]:
            data += '.balign 8\n.global %s\n%s:\n%s' % (name, name, quad(values))
        site_base, offsets = site_page_index(sites)
        data += '.balign 8\n.global osrec_site_base, osrec_site_pages, osrec_site_offsets\n'
        data += 'osrec_site_base:\n' + quad([site_base])
        data += 'osrec_site_pages:\n' + quad([len(offsets) - 1])
        data += 'osrec_site_offsets:\n' + ''.join('    .long %d\n' % i for i in offsets)
    data += '.section .bss,"aw",@nobits\n.balign 4096\n.space 65536\n.global osrec_monitor_stack_top\nosrec_monitor_stack_top:\n'
    (out / 'data.S').write_text(data)
    (out / 'monitor.ld').write_text('ENTRY(_start)\nSECTIONS { . = 0x%x; .text : { *(.text.boot) *(.text*) } .rodata : { *(.rodata*) } .data : { *(.data*) } .bss : { *(.bss*) *(COMMON) } osrec_monitor_end = .; }\n' % monitor_va)
    runtime = ROOT / 'runtime/el0'
    command = [str(LLVM / 'clang'), '--target=aarch64-none-elf', '-mcpu=cortex-a53', '-O2', '-g',
               '-mgeneral-regs-only', '-ffreestanding', '-fno-stack-protector', '-fno-builtin', '-nostdlib', '-static', '-fuse-ld=lld',
               '-Wl,-T,' + str(out / 'monitor.ld'), '-Wl,--build-id=none',
               str(runtime / 'minios.S'), str(runtime / 'minios.c'), str(runtime / 'emulate.c'), str(out / 'data.S'), '-o', str(out / 'monitor.elf')]
    if lowering:command.extend(['-DOSREC_LOWERED',str(runtime/'lower.c'),str(runtime/'lower_mmu.c')])
    if shared:command.extend(['-DOSREC_SHARED_ROOT',str(runtime/'shared_mmu.c')])
    if fast_sysregs:command.append('-DOSREC_BRANCH_TLS')
    subprocess.run(command, check=True)
    from kernel_source_verify import Elf
    monitor = Elf(out / 'monitor.elf')
    ms = {s['name']: s['value'] for s in monitor.symbols}
    if ms['osrec_monitor_end'] > monitor_va + MONITOR_SIZE:
        raise ValueError('monitor exceeds its reservation')
    if calls:
        from source_image_calls import branch
        if ms['osrec_shadow']!=ms['osrec_branch_state']+16:
            raise ValueError('branch spill area must immediately precede shadow state')
        script='ENTRY(osrec_call_0)\nSECTIONS { . = 0x%x; .text : { *(.text*) } /DISCARD/ : { *(.comment) *(.note*) } }\n'%call_base
        script+='osrec_branch_state = 0x%x;\n'%(call_alias+(ms['osrec_branch_state']&4095))
        if percpu_offset is not None:
            percpu_value = ms['osrec_shadow'] + percpu_offset
            percpu_alias = call_alias + 2*PAGE
            script += 'osrec_branch_tpidr = 0x%x;\n' % (percpu_alias + (percpu_value & (PAGE-1)))
        script+=''.join('osrec_call_return_%d = 0x%x;\n'%(i,v.pc+4) for i,v in enumerate(calls))
        (out/'calls.ld').write_text(script)
        subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-mcpu=cortex-a53','-nostdlib',
                        '-static','-fuse-ld=lld','-Wl,-T,'+str(out/'calls.ld'),'-Wl,--build-id=none',
                        str(out/'calls.S'),'-o',str(out/'calls.elf')],check=True)
        linked=Elf(out/'calls.elf');cs={s['name']:s['value'] for s in linked.symbols}
        subprocess.run([str(LLVM/'llvm-objcopy'),'-O','binary',str(out/'calls.elf'),str(out/'calls.bin')],check=True)
        raw=(out/'calls.bin').read_bytes()
        if len(raw)!=call_size:raise ValueError('unexpected linked veneer size')
        raw+=bytes(-len(raw)%PAGE)
        for k in range(0,len(raw),PAGE):blob[BRANCH_PA+k]=raw[k:k+PAGE]
        physical_by_va={move(va):pa for va,pa,_ in upper}
        for i,v in enumerate(calls):
            pa=physical_by_va[v.pc&~4095];page=bytearray(blob[pa])
            struct.pack_into('<I',page,v.pc&4095,branch(v.pc,cs['osrec_call_%d'%i]));blob[pa]=bytes(page)
        # Use a separate EL0 alias. Changing AP on the monitor's own mapping
        # can prevent EL1 instruction/data access (and a page may contain both
        # monitor text and data). The original mapping remains privileged.
        shadow_page=MONITOR_PA+(ms['osrec_branch_state']&~4095)-monitor_va
        for k in range(0,2*PAGE,PAGE):
            attrs=monitor_attrs|(1<<6)|(1<<53)
            root.map(call_alias+k,shadow_page+k,attrs)
            native_upper.map(call_alias+k,shadow_page+k,(attrs&~(1<<6)))
            if lowering:identity.map(call_alias+k,shadow_page+k,attrs)
        if percpu_offset is not None:
            physical = MONITOR_PA + (percpu_value & -PAGE) - monitor_va
            read_only = monitor_attrs | (1 << 7) | (1 << 53)
            root.map(percpu_alias, physical, read_only | (1 << 6))
            native_upper.map(percpu_alias, physical, read_only)
    subprocess.run([str(LLVM / 'llvm-objcopy'), '-O', 'binary', str(out / 'monitor.elf'), str(out / 'monitor.bin')], check=True)
    code = (out / 'monitor.bin').read_bytes()
    code += bytes(-len(code) % PAGE)
    pages = {pa: data for pa, data in blob.items() if not DTB[0] <= pa < DTB[1]}
    pages.update({STAGE + i * PAGE: blob[pa] for i, pa in enumerate(staged)})
    pages.update({pa: bytes(data) for pa, data in {**root.pages, **native_upper.pages, **identity.pages}.items()})
    pages.update({MONITOR_PA + k: code[k:k + PAGE] for k in range(0, len(code), PAGE)})
    segments = []
    run = bytearray()
    address = None
    for pa, data in sorted(pages.items()):
        if address is not None and pa != address + len(run):
            segments.append((address, bytes(run)))
            run = bytearray()
        if not run:
            address = pa
        run.extend(data)
    if run:
        segments.append((address, bytes(run)))
    if segment_only:
        monitor_size = (ms['osrec_monitor_end'] - monitor_va + PAGE - 1) & -PAGE
        segments = reserve_load_ranges(segments, [(ram.base, ram.base + ram.size),
                                                  (MONITOR_PA, MONITOR_PA + monitor_size)])
    checkpoint = elf(segments, MONITOR_PA)
    manifest = dict(format='osrec-source-image-v1', execution='el0-minios',
                    ram=ram.state['ram'],
                    dump=str(Path(dump).resolve()), vmlinux=str(Path(vmlinux).resolve()), profile=str(Path(profile_path).resolve()),
                    code='whole', state='full', rewrite=dict(counts), site_count=len(sites),
                    table_pages=len(root.pages) + len(native_upper.pages) + len(identity.pages), blob_pages=len(blob), image_ram_mb=1024,
                    ttbr1=hex(root.root),ttbr1_user=hex(native_upper.root), stub=hex(MONITOR_PA), stop=hex(ms['osrec_stopped']),
                    shadow_pa=hex(ms['osrec_shadow'] - monitor_va + MONITOR_PA),
                    context_pointer_pa=hex(ms['osrec_active_context'] - monitor_va + MONITOR_PA),
                    monitor_va=hex(monitor_va),monitor_pa=hex(MONITOR_PA),
                    lowered=lowering['summary'] if lowering else None, shared_root=shared, segment_only=segment_only,
                    dispatch=dispatch, branch_sites=len(calls),
                    inline_system_reads=fixed_reads if counts['inline sysreg'] else {},
                    kernel_tls_shadow=fast_sysregs,
                    branch_veneers=dict(va=hex(call_base),pa=hex(BRANCH_PA),size=call_size,
                                        state_va=hex(call_alias+(ms['osrec_branch_state']&4095))) if calls else None,
                    kernel_shift='0x1000000000000' if lowering else '0x0',
                    vector_base=hex(sr['VBAR']), pages=mapped, uncaptured_sysreg_names=missing,
                    boundary_functions=[n for _, _, n in cuts])
    if shared:
        from source_image_symbols import symbolize
        checkpoint, manifest['symbols'] = symbolize(out, checkpoint, manifest, kernel=image, monitor=monitor)
    (out / 'image.elf').write_bytes(checkpoint)
    if segment_only:
        from source_image_load import check
        (out / 'load-plan.json').write_text(json.dumps(check(out / 'image.elf'), indent=2) + '\n')
    manifest['image_sha256'] = hashlib.sha256(checkpoint).hexdigest()
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=1) + '\n')
    return {k: manifest[k] for k in ('execution', 'rewrite', 'site_count', 'table_pages', 'stop')}


def relink(image_dir,out):
    """Rebuild only the monitor, preserving the already transformed kernel state.

    This keeps short runtime-debug cycles independent of the state/code scan.
    Output is a new image directory; the validated input image is untouched.
    """
    from source_image import LLVM,ROOT
    from kernel_source_verify import Elf
    from kernel_boundary_replay import elf
    image_dir=Path(image_dir).resolve();out=Path(out).resolve()
    m=json.loads((image_dir/'manifest.json').read_text())
    if m.get('branch_sites'):raise ValueError('linked branch veneers require a full rebuild when relinking the monitor')
    out.mkdir(parents=True,exist_ok=False)
    for name in ('shadow.bin','sites.bin','fp.bin','monitor.ld'):shutil.copyfile(image_dir/name,out/name)
    (out/'data.S').write_text((image_dir/'data.S').read_text().replace(str(image_dir),str(out)))
    runtime=ROOT/'runtime/el0'
    command=[str(LLVM/'clang'),'--target=aarch64-none-elf','-mcpu=cortex-a53','-O2','-g','-mgeneral-regs-only',
             '-ffreestanding','-fno-stack-protector','-fno-builtin','-nostdlib','-static','-fuse-ld=lld',
             '-Wl,-T,'+str(out/'monitor.ld'),'-Wl,--build-id=none',str(runtime/'minios.S'),str(runtime/'minios.c'),
             str(runtime/'emulate.c'),str(out/'data.S'),'-o',str(out/'monitor.elf')]
    if m.get('lowered'):command+=['-DOSREC_LOWERED',str(runtime/'lower.c'),str(runtime/'lower_mmu.c')]
    if m.get('shared_root'):command+=['-DOSREC_SHARED_ROOT',str(runtime/'shared_mmu.c')]
    subprocess.run(command,check=True)
    monitor=Elf(out/'monitor.elf');symbols={s['name']:s['value'] for s in monitor.symbols}
    monitor_va=int(m['monitor_va'],16)
    if symbols['osrec_monitor_end']>monitor_va+MONITOR_SIZE:raise ValueError('monitor exceeds reservation')
    subprocess.run([str(LLVM/'llvm-objcopy'),'-O','binary',str(out/'monitor.elf'),str(out/'monitor.bin')],check=True)
    raw=(image_dir/'image.elf').read_bytes();phoff=struct.unpack_from('<Q',raw,32)[0]
    stride,count=struct.unpack_from('<HH',raw,54);segments=[]
    for i in range(count):
        kind,flags,offset,va,pa,size,memsize,align=struct.unpack_from('<IIQQQQQQ',raw,phoff+i*stride)
        if kind==1 and not MONITOR_PA<=pa<MONITOR_PA+MONITOR_SIZE:
            segments.append((pa,raw[offset:offset+size],memsize))
    code=(out/'monitor.bin').read_bytes();code+=bytes(-len(code)%PAGE)
    monitor_size = (symbols['osrec_monitor_end'] - monitor_va + PAGE - 1) & -PAGE if m.get('segment_only') else len(code)
    segments.append((MONITOR_PA,code,monitor_size));segments.sort()
    checkpoint = elf(segments, MONITOR_PA)
    if m.get('shared_root'):
        from source_image_symbols import symbolize
        checkpoint, m['symbols'] = symbolize(out, checkpoint, m, monitor=monitor)
    (out/'image.elf').write_bytes(checkpoint)
    if m.get('segment_only'):
        from source_image_load import check
        (out / 'load-plan.json').write_text(json.dumps(check(out / 'image.elf'), indent=2) + '\n')
    m.update(stop=hex(symbols['osrec_stopped']),shadow_pa=hex(symbols['osrec_shadow']-monitor_va+MONITOR_PA),
             context_pointer_pa=hex(symbols['osrec_active_context']-monitor_va+MONITOR_PA),relinked_from=str(image_dir),
             image_sha256=hashlib.sha256(checkpoint).hexdigest())
    (out/'manifest.json').write_text(json.dumps(m,indent=1)+'\n')
    return dict(stop=m['stop'],relinked_from=str(image_dir))


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['relink']);p.add_argument('image');p.add_argument('--out',required=True)
    a=p.parse_args();print(json.dumps(relink(a.image,a.out)))
