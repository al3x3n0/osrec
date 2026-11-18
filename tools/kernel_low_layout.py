#!/usr/bin/env python3
"""Audit a fixed-offset TTBR1 projection into a replay TTBR0 window."""

import argparse
import json
from pathlib import Path

from source_image import PAGE, Ram


def windows(user_bits, kernel_bits, replay_bits, kernel_base=None):
    user_end = 1 << user_bits
    kernel_size = 1 << kernel_bits
    if kernel_base is None:
        kernel_base = max(user_end, kernel_size)
    if kernel_base < user_end or kernel_base % kernel_size:
        raise ValueError('kernel window must be aligned to its size and lie above the user window')
    kernel_end = kernel_base + kernel_size
    if kernel_end > 1 << replay_bits:
        raise ValueError(f'{user_bits}-bit user and {kernel_bits}-bit kernel windows do not fit below '
                         f'{1 << replay_bits:#x}')
    return user_end, (1 << 64) - kernel_size, kernel_base, kernel_end


def capture_windows(ram, replay_bits=47, kernel_base=None):
    tcr = ram.sysregs['TCR_EL1']
    if ((tcr >> 14) & 3) != 0 or ((tcr >> 30) & 3) != 2:
        raise ValueError('the dump must use 4 KiB granules in TTBR0 and TTBR1')
    if tcr & (1 << 59):
        raise ValueError('the dump must use the standard 4 KiB descriptor format without LPA2')
    if tcr & ((1 << 7) | (1 << 23)):
        raise ValueError('both captured translation table walks must be enabled')
    if any(not 25 <= bits <= 48 for bits in ram.bits.values()):
        raise ValueError('the dump must use 25- to 48-bit address windows')
    return windows(ram.bits[0], ram.bits[1], replay_bits, kernel_base)


def audit(ram, replay_bits=47, kernel_base=None):
    user_end, original_base, projected_base, projected_end = capture_windows(ram, replay_bits, kernel_base)
    delta = projected_base - original_base

    def collect(upper, start, end, offset):
        leaves, tables = ram.mappings(upper)
        pages = {}
        physical = set()
        ram_pages = 0
        for va, pa, _ in leaves:
            if va % PAGE or not start <= va < end or va in pages:
                raise ValueError(f'invalid or duplicate TTBR{upper} leaf at {va:#x}')
            pages[va] = pa
            physical.add(pa)
            ram_pages += ram.base <= pa and pa + PAGE <= ram.base + ram.size
        if not pages:
            raise ValueError(f'no TTBR{upper} leaves in the captured RAM')
        return pages, physical, dict(
            pages=len(pages), ram_pages=ram_pages, outside_ram_pages=len(pages) - ram_pages,
            physical_pages=len(physical), table_pages=len(set(tables)),
            mapped_replay_range=[hex(min(pages) + offset), hex(max(pages) + PAGE + offset)])

    user, user_pa, user_summary = collect(0, 0, user_end, 0)
    kernel, kernel_pa, kernel_summary = collect(1, original_base, 1 << 64, delta)
    cpu = ram.state['cpu']

    def location(value, *, table, stack=False):
        # The first stack push may use the page below a page-aligned SP.
        probe = value - int(stack)
        page = probe & -PAGE
        mappings = kernel if table else user
        if page not in mappings:
            raise ValueError(f'captured address {value:#x} is outside its expected TTBR{table} mappings')
        return dict(captured=hex(value), replay=hex(value + (delta if table else 0)),
                    probe_pa=hex(mappings[page] + (probe & (PAGE - 1))))

    return dict(
        format='osrec-kernel-low-layout-v1', replay_va_bits=replay_bits,
        replay_limit=hex(1 << replay_bits), user_va_bits=ram.bits[0], kernel_va_bits=ram.bits[1],
        user_window=['0x0', hex(user_end)], kernel_window=[hex(projected_base), hex(projected_end)],
        captured_kernel_window=[hex(original_base), hex(1 << 64)],
        kernel_delta_mod_2_64=hex(delta % (1 << 64)), user=user_summary, kernel=kernel_summary,
        physical_pages_shared=len(user_pa & kernel_pa),
        registers=dict(
            PC=location(cpu['pc'], table=1),
            VBAR=location(ram.sysregs['VBAR'], table=1),
            ELR_EL1=location(ram.sysregs['ELR_EL1'], table=0),
            SP_EL0=location(ram.sysregs['SP_EL0'], table=0, stack=True),
            SP_EL1=location(cpu['sp'], table=1, stack=True)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dump', type=Path, required=True)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--replay-bits', type=int, choices=range(25, 49), metavar='BITS', default=47)
    parser.add_argument('--kernel-base', type=lambda value: int(value, 0))
    args = parser.parse_args()

    ram = Ram(args.dump)
    with ram.file, ram.ram:
        try:
            report = audit(ram, args.replay_bits, args.kernel_base)
        except ValueError as exc:
            parser.error(str(exc))
    result = json.dumps(report, indent=2) + '\n'
    if args.out:
        args.out.write_text(result)
    else:
        print(result, end='')


if __name__ == '__main__':
    main()
