#!/usr/bin/env python3
"""Run a segment-only shared-root checkpoint with Unicorn 2.1.4."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from aarch64_liveness import signed
from kernel_replay_tables import KERNEL_BASE
from kernel_source_verify import Elf
from source_image import PAGE, PT_REGS_OFFSET, SVC_OFFSET, compare, result_point
from source_image_load import LoadMap, UART, audit, translate_ttbr0
from source_image_memory import snapshot_pages

SCR, HCR, SCTLR, TCR = (3, 6, 1, 1, 0), (3, 4, 1, 1, 0), (3, 0, 1, 0, 0), (3, 0, 2, 0, 2)
SPSR = (3, 0, 4, 0, 0)
SVC, DATA_ABORT, BRK = 2, 4, 7  # Unicorn's AArch64 interrupt numbers


def map_ram(cpu, load):
    """Map p_memsz and initialize p_filesz for each physical PT_LOAD."""
    for pa, off, file_size, size, flags in load.loads:
        # ELF R/W/X bits 4/2/1 are Unicorn's 1/2/4.
        permissions = ((flags & 4) >> 2) | (flags & 2) | ((flags & 1) << 2)
        cpu.mem_map(pa, size, permissions)
        if file_size:
            cpu.mem_write(pa, load.data[off:off + file_size])


def read_int(cpu, pa, size):
    return int.from_bytes(cpu.mem_read(pa, size), 'little')


def run(image, out, reference=None, timeout=30):
    import unicorn as u
    from unicorn import arm64_const as reg

    manifest = json.loads((image / 'manifest.json').read_text()) if image.is_dir() else None
    if manifest is not None and not manifest.get('segment_only'):
        raise ValueError('build the checkpoint with --segment-only')
    if reference is not None and manifest is None:
        raise ValueError('native comparison requires the source-image directory')
    elf = Elf(image / 'image.elf' if manifest is not None else image)
    load = LoadMap(elf.data)
    image_sha = audit(elf, load)['image_sha256']
    if manifest is not None and image_sha != manifest['image_sha256']:
        raise ValueError('ELF differs from the source-image manifest')
    symbols = {s['name']: s['value'] for s in elf.symbols}
    stop = symbols['osrec_stopped']
    cpu = u.Uc(u.UC_ARCH_ARM64, u.UC_MODE_ARM)
    cpu.ctl_set_cpu_model(reg.UC_CPU_ARM64_A53)
    cpu.ctl_set_tlb_mode(u.UC_TLB_CPU)
    map_ram(cpu, load)
    cpu.cpr_write(*SCR, (1 << 10) | 1)  # non-secure, AArch64 EL2
    cpu.cpr_write(*HCR, 1 << 31)        # AArch64 EL1
    cpu.reg_write(reg.UC_ARM64_REG_PSTATE, 0x3c5)
    read, write = cpu.reg_read, cpu.reg_write
    x = [getattr(reg, f'UC_ARM64_REG_X{i}') for i in range(31)]
    uart, uart_registers = bytearray(), {}

    def uart_read(engine, offset, size, data):
        return 0x90 if offset == 0x18 else uart_registers.get(offset, 0)  # TX empty, RX empty

    def uart_write(engine, offset, size, value, data):
        if offset == 0:
            uart.append(value & 255)
        else:
            uart_registers[offset] = value

    cpu.mmio_map(UART, PAGE, uart_read, None, uart_write, None)
    entries, faults = Counter(), []

    def read_virtual(va, size):
        pa, _ = translate_ttbr0(cpu.mem_read, read(reg.UC_ARM64_REG_TTBR0_EL1), va)
        if pa is None:
            raise ValueError(f'checkpoint address {va:#x} is unmapped')
        return read_int(cpu, pa, size)

    def interrupt(engine, number, data):
        pc, state = read(reg.UC_ARM64_REG_PC), read(reg.UC_ARM64_REG_PSTATE)
        if state & 15:
            raise ValueError(f'unexpected monitor exception {number} at {pc:#x}')
        if number in (SVC, BRK):
            insn = read_virtual(pc - 4 if number == SVC else pc, 4)
            opcode, ec = (0xd4000001, 0x15) if number == SVC else (0xd4200000, 0x3c)
            if insn & 0xffe0001f != opcode:
                raise ValueError(f'exception {number} does not match instruction {insn:#x} at {pc:#x}')
            syndrome = (ec << 26) | (1 << 25) | ((insn >> 5) & 0xffff)
        elif number == DATA_ABORT:
            # Unicorn reports the interrupt number without populating ESR/FAR.
            # Admit translation faults from the checkpoint's LDTR/STTR uaccess.
            insn = read_virtual(pc, 4)
            op, base = (insn >> 22) & 3, (insn >> 5) & 31
            if insn & 0x3f200c00 != 0x38000800 or op > 1:
                raise ValueError(f'unsupported data-abort instruction {insn:#x} at {pc:#x}')
            base_register = x[base] if base < 31 else reg.UC_ARM64_REG_SP
            addr = (read(base_register) + signed((insn >> 12) & 511, 9)) & ((1 << 64) - 1)
            pa, level = translate_ttbr0(cpu.mem_read, read(reg.UC_ARM64_REG_TTBR0_EL1), addr)
            if pa is not None:
                raise ValueError(f'unsupported data abort on a mapped address {addr:#x} at {pc:#x}')
            syndrome = 0x92000004 | ((op == 0) << 6) | level
            write(reg.UC_ARM64_REG_FAR_EL1, addr)
            faults.append(dict(pc=hex(pc), address=hex(addr), esr=hex(syndrome)))
        else:
            raise ValueError(f'unexpected Unicorn exception {number} at {pc:#x}')
        entries[number] += 1
        sp_el1 = read(reg.UC_ARM64_REG_SP_EL1)
        write(reg.UC_ARM64_REG_SP_EL0, read(reg.UC_ARM64_REG_SP))
        write(reg.UC_ARM64_REG_ELR_EL1, pc)
        write(reg.UC_ARM64_REG_ESR_EL1, syndrome)
        cpu.cpr_write(*SPSR, state)
        write(reg.UC_ARM64_REG_PSTATE, (state & 0xf0000000) | 0x3c5)
        write(reg.UC_ARM64_REG_SP, sp_el1)
        # Unicorn 2.1.4 needs a translation-state refresh after a host EL change.
        for key in (SCR, HCR, SCTLR, TCR):
            cpu.cpr_write(*key, cpu.cpr_read(*key))
        cpu.ctl_set_tlb_mode(u.UC_TLB_CPU)
        write(reg.UC_ARM64_REG_PC, read(reg.UC_ARM64_REG_VBAR_EL1) + SVC_OFFSET)

    cpu.hook_add(u.UC_HOOK_INTR, interrupt)
    calls, pending = [], None
    if reference is not None:
        shadow = int(manifest['shadow_pa'], 16)
        ram = manifest['ram']
        ram_range = (ram['base'], ram['base'] + ram['size'])

        def enter_syscall(engine, address, size, data):
            nonlocal pending
            elr, _, esr, far = struct.unpack('<4Q', cpu.mem_read(shadow + 16, 32))
            if esr >> 26 != 0x15:
                calls.append(dict(event='exception', number=-1, arguments=[esr, far, elr], result=None))
                return
            pending = dict(number=read(x[8]), arguments=[read(r) for r in x[:6]],
                           frame=read(reg.UC_ARM64_REG_SP) - PT_REGS_OFFSET,
                           root=read_int(cpu, shadow + 72, 8), tcr=cpu.cpr_read(*TCR))

        def syscall_result(engine, address, size, data):
            nonlocal pending
            if pending is not None:
                pending['result'] = read_virtual(pending.pop('frame'), 8)
                pending['memory'] = snapshot_pages(cpu.mem_read, pending.pop('root'), pending.pop('tcr'),
                                                   ram_range, KERNEL_BASE)
                calls.append(pending)
                pending = None

        vector = int(manifest['vector_base'], 16) + SVC_OFFSET
        result = result_point(manifest['vmlinux'])
        cpu.hook_add(u.UC_HOOK_CODE, enter_syscall, begin=vector, end=vector)
        cpu.hook_add(u.UC_HOOK_CODE, syscall_result, begin=result, end=result)

    out.mkdir(parents=True)
    cpu.emu_start(load.entry, stop, timeout=timeout * 1_000_000)
    (out / 'console.txt').write_bytes(uart)
    if read(reg.UC_ARM64_REG_PC) != stop or read(x[0]) != 1 or read(x[1]) != symbols['kernel_power_off']:
        raise ValueError('checkpoint did not reach its kernel_power_off boundary')
    if b'OSREC_VM_PASS ' not in uart or b'OSREC_VM_FAIL ' in uart:
        raise ValueError('checkpoint workload did not report success on PL011')
    report = dict(status='pass', engine=u.__version__, image_sha256=image_sha, load_segments=len(load.loads),
                  ram_from_elf_only=True, svc=entries[SVC], brk=entries[BRK], data_aborts=faults,
                  console=uart.decode('ascii', errors='replace').strip())
    if reference is not None:
        if pending is not None:
            calls.append(dict(number=pending['number'], arguments=pending['arguments'], result=None))
        recording = out / 'calls.json'
        recording.write_text(json.dumps(dict(calls=calls), indent=1) + '\n')
        report['comparison'] = compare(reference, recording)
        if not report['comparison']['matches']:
            report['status'] = 'mismatch'
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True, help='image.elf or its source-image directory')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--reference', type=Path, help='compare against native Linux calls.json with memory snapshots')
    parser.add_argument('--timeout', type=int, default=30)
    result = run(**vars(parser.parse_args()))
    print(json.dumps(result, indent=2))
    if result['status'] != 'pass':
        raise SystemExit(1)
