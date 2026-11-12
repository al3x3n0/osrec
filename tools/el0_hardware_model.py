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


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prepare(image, out, llvm=LLVM):
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
    backing = symbols['flat_phys']['value']
    if symbols['flat_phys']['size'] != metadata['ram_bytes']:
        raise ValueError('canonical RAM extent differs from mapping metadata')
    # Tables has a historical monitor-arena limit. Use the same implementation
    # at relative addresses, then relocate only table descriptors when writing.
    tables = Tables(48, 0)
    mapped = {}
    def map_page(va, pa, writable, executable=False, user=True):
        if va % PAGE or pa % PAGE or not RAM_BASE <= pa < RAM_END:
            raise ValueError('unaligned or out-of-RAM hardware mapping')
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
        if va < SETUP + 0x10000 and va + size > SETUP or va < RAM_END and va + size > TABLES:
            raise ValueError('ELF overlaps setup/table reservation')
        for address in range(va & -PAGE, (va + size + PAGE - 1) & -PAGE, PAGE):
            map_page(address, address, bool(flags & 2), bool(flags & 1))
    for alias in metadata['aliases']:
        for offset in range(0, alias['bytes'], PAGE):
            map_page(alias['va'] + offset, backing + alias['pa'] - metadata['ram_base'] + offset,
                     not alias['attrs'] & (1 << 7))
    # Setup is executable only at EL1 and is never a computation helper.
    for address in range(SETUP, SETUP + 0x10000, PAGE):
        map_page(address, address, True, True, False)
    raw = bytearray(tables.next)
    for offset, page in tables.pages.items():
        for index in range(512):
            value = struct.unpack_from('<Q', page, index * 8)[0]
            if value & 3 == 3 and value & 0x0000fffffffff000 < tables.next:
                value += TABLES
            struct.pack_into('<Q', raw, offset + index * 8, value)
    if TABLES + len(raw) > RAM_END:
        raise ValueError('page tables exceed model RAM')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'page-tables.bin').write_bytes(raw)
    # 48-bit TTBR0, 4 KiB granules, normal WB walks, inner shareable; TTBR1 off.
    tcr = 16 | (1 << 8) | (1 << 10) | (3 << 12) | (16 << 16) | (1 << 23) | (2 << 30) | (2 << 32)
    registers = dict(MAIR_EL1=0xff, TCR_EL1=tcr, TTBR0_EL1=TABLES + tables.root,
                     TTBR1_EL1=0, CPACR_EL1=3 << 20, SCTLR_EL1=0x30d01805 | ((1<<14) if zero_bytes else 0))
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
                page_tables=dict(address=TABLES, bytes=len(raw), sha256=sha(out / 'page-tables.bin')),
                load_segments=checked['load_segments'], entry=checked['entry'], execution_level=0,
                platform_registers=registers, ram=dict(address=RAM_BASE, bytes=RAM_END - RAM_BASE),
                native_zero_bytes=zero_bytes,
                result=dict(address=checked['result_address'], bytes=checked['result_bytes']),
                completion_pc=checked['terminal_pc'], unexpected_pc=hex(stop),
                setup=dict(image='setup.elf', sha256=sha(out / 'setup.elf'), entry=SETUP,
                           scope='QEMU model initialization only; outside delivered EL0 computation'),
                runtime_el1_services=False, physical_devices=False, cycles_verified=False,
                rtl_execution_verified=False)
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


def run(image, prepared, out, timeout=180, qemu='qemu-system-aarch64'):
    image, prepared, out = (Path(p).resolve() for p in (image, prepared, out))
    plan = json.loads((prepared / 'hardware-load-plan.json').read_text())
    for path, expected in [(image / 'checkpoint', plan['image_sha256']),
                           (image / 'hardware-memory.json', plan['mapping_sha256']),
                           (prepared / 'page-tables.bin', plan['page_tables']['sha256']),
                           (prepared / 'setup.elf', plan['setup']['sha256'])]:
        if sha(path) != expected:
            raise ValueError('hardware artifact changed: ' + str(path))
    out.mkdir(parents=True, exist_ok=False)
    port = free_port()
    command = [qemu, '-M', 'virt-9.2,secure=off,virtualization=off', '-cpu', 'cortex-a53',
               '-accel', 'tcg', '-smp', '1', '-m', '2048M', '-nodefaults', '-display', 'none',
               '-monitor', 'none', '-serial', 'none', '-semihosting-config', 'enable=off',
               '-device', 'loader,file=' + str(image / 'checkpoint'),
               '-device', 'loader,file=' + str(prepared / 'page-tables.bin') + ',addr=0x%x,force-raw=on' % TABLES,
               '-device', 'loader,file=' + str(prepared / 'setup.elf') + ',cpu-num=0',
               '-S', '-gdb', 'tcp:127.0.0.1:%d' % port]
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
            if pc != entry or remote.register('cpsr') & 15:
                raise ValueError('hardware setup failed before EL0 entry: '+json.dumps(remote.registers(('pc','cpsr','x0','x1','x2'))))
            entry_state = remote.registers(('pc', 'cpsr'))
            remote.breakpoint(entry, False)
            remote.breakpoint(completion)
            remote.resume()
            pc = remote.wait(timeout)
            state = remote.registers(('pc', 'cpsr', 'x0', 'x1', 'x2'))
            raw = remote.read(int(plan['result']['address'], 0), plan['result']['bytes'])
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
    verified = (pc == completion and not state['cpsr'] & 15 and state['x0'] == 0 and
                result['magic'] == 0x324c55464652534f and result['version'] == 2 and result['status'] == 1 and
                result['first_mismatch'] == (1 << 64) - 1 and not result['missing_pc'] and
                (profile is None or sum(profile.values()) == result['transitions']) and
                (memory_counts is None or profile is None or sum(memory_counts[:5])+memory_counts[7]==profile['memory']) and
                (system_counts is None or profile is None or sum(r['count'] for r in system_counts)==profile['system']))
    report = dict(verified=verified, entry=entry_state, completion=state, result=result,
                  image_sha256=plan['image_sha256'], mapping_sha256=plan['mapping_sha256'],
                  page_tables_sha256=plan['page_tables']['sha256'], hardware_exceptions=int(pc == unexpected),
                  runtime_el1_services=False, host_calls_before_completion=0,
                  functional_model='QEMU system Cortex-A53', seconds=round(time.monotonic() - started, 3),
                  cycles_verified=False, rtl_execution_verified=False)
    if profile is not None:
        report['gateway_profile'] = profile
    if memory_profile is not None:
        names=('user','kernel','user_copy','exclusive','hint','uart','fault','post')
        report['memory_profile']=dict(zip(names,memory_counts))
    if system_counts is not None:
        report['system_profile']=sorted(system_counts,key=lambda r:-r['count'])
    (out / 'result.bin').write_bytes(raw)
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
    args = parser.parse_args()
    report = prepare(args.image, args.out, args.llvm) if args.command == 'prepare' else run(args.image, args.prepared, args.out, args.timeout)
    print(json.dumps(report, indent=2))
    if args.command == 'run' and not report['verified']:
        raise SystemExit(1)
