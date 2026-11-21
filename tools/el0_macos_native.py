#!/usr/bin/env python3
"""Run a static AArch64 checkpoint ELF inside an Apple Silicon macOS process."""
import argparse
import json
import math
import os
from pathlib import Path
import platform
import signal
import struct
import subprocess
import sys

from audit_el0_image import audit_elf
from el0_macos import (ENTRY_AUX, FRAME_BYTES, HOST_ALIAS, PSTATE_NON_EL0T, check_ram_preload,
                      differing_registers, execution_contract, host_aliases, memory_segment,
                      record_completion, verify_result)
from el0_relocation_plan import MACOS_PAGE, macos_direct_aliases
from kernel_source_verify import Elf

DEFAULT_LOADER = Path(__file__).resolve().parents[1] / 'build/el0-macos/native-loader'
OBSERVATION_FIELDS = ('signal', 'code', 'syndrome', 'pc', 'pstate', 'x0', 'far')
OBSERVATION = struct.Struct('<7Q')
RESULT_BYTES = 320


def expected_direct_aliases(elf, records, segments):
    """Bind host aliases to the RAM and permissions used by the checkpoint."""
    def read(address, size):
        if size:
            memory_segment(segments, address, size, 4, initialized=True)
        return elf.read(address, size) if size else b''

    def table(address, count, fields):
        row = struct.Struct(f'<{fields}Q')
        return row.iter_unpack(read(address, count * row.size))

    try:
        ram, _, maps, map_count = struct.unpack('<4Q', read(records['flat_program']['value'], 32))
        base, size, backing = struct.unpack('<3Q', read(ram, 24))
        if (backing, size) != (records['flat_phys']['value'], records['flat_phys']['size']):
            raise ValueError('native direct-memory bank differs from canonical ELF RAM')
        user_count, = struct.unpack('<Q', read(records['flat_pretranslated_binding_count']['value'], 8))
        user = [dict(va=va, pa=pa, bytes=length, attrs=attrs) for va, pa, length, attrs in
                table(records['flat_pretranslated_bindings']['value'], user_count, 4)]
        immutable_count, = struct.unpack('<Q', read(records['flat_immutable_text_count']['value'], 8))
        immutable = list(table(records['flat_immutable_text']['value'], immutable_count, 2))
        layout = macos_direct_aliases(base, size, table(maps, map_count, 4), user, immutable)
    except KeyError as error:
        raise ValueError('native direct-memory ELF is missing its captured mappings') from error
    return [(row['va'], backing + row['backing'], row['bytes'], row['flags']) for row in layout]


def load_command(elf, checked, user_elf=None, reference=None):
    records = {symbol['name']: symbol for symbol in elf.symbols if symbol['shndx']}
    direct = records.get('flat_macos_direct_memory')
    if direct and (direct['size'] != 8 or
                   elf.read(direct['value'], 8) != struct.pack('<Q', 1) or
                   elf.sections[direct['shndx']]['flags'] & 1 or
                   'flat_embedded_page_tables' in records or
                   'flat_alias_free_memory_mode' in records):
        raise ValueError('invalid native macOS direct-memory contract')
    if checked['memory_backend'] != 'software':
        flag = records.get('flat_alias_free_memory_mode')
        if not direct and (flag is None or elf.read(flag['value'], 8) != struct.pack('<Q', 1)):
            raise ValueError('native execution requires alias-free memory or preinstalled direct mappings')
    if {'flat_host_mapping_gate', 'flat_host_mapping_window', 'flat_host_uaccess_fixups'} & records.keys():
        raise ValueError('native execution supports preinstalled ELF aliases')
    page = os.sysconf('SC_PAGE_SIZE')
    segments = sorted(checked['load_segments'], key=lambda region: region['address'])
    if not segments:
        raise ValueError('native checkpoint has no ELF load segments')
    base = segments[0]['address'] & -page
    if base < 1 << 32:
        raise ValueError('ELF overlaps the macOS page-zero range, link with MACOS_NATIVE=1')
    end = base
    for region in segments:
        address = region['address']
        if (address < end or not region['memory_bytes'] or address + region['memory_bytes'] >= 1 << 64 or
                region['flags'] not in (4, 5, 6)):
            raise ValueError(f'invalid native ELF segment at {address:#x}')
        end = address + region['memory_bytes']
    end = (end + page - 1) & -page
    if end - base > 4 << 30:
        raise ValueError('native ELF exceeds the supported mapping span')
    start, done, result = (int(checked[name], 0) for name in ('entry', 'terminal_pc', 'result_address'))
    memory_segment(segments, start, 4, 5, initialized=True)
    memory_segment(segments, done, 8, 5, initialized=True)
    memory_segment(segments, result, RESULT_BYTES, 6)
    if checked['result_bytes'] != RESULT_BYTES:
        raise ValueError('unsupported native checkpoint result layout')
    preloaded = check_ram_preload(elf, records, segments)
    contract = execution_contract(elf, records, segments, checked, preloaded, user_elf, reference)
    aliases = host_aliases(elf, records, segments, True, page, ram_range=(base, end))
    if any(address < 1 << 32 for address, _, _, _ in aliases):
        raise ValueError('native ELF alias overlaps the macOS page-zero range')
    if direct:
        bank = records.get('flat_phys')
        if page != MACOS_PAGE or not preloaded or not aliases or not bank or bank['value'] % page:
            raise ValueError('native direct memory requires aligned preloaded RAM and host aliases')
        if aliases != expected_direct_aliases(elf, records, segments):
            raise ValueError('native direct aliases differ from the captured mappings')
        stack, = struct.unpack_from('<Q', contract['frame'], 248)
        if not contract['native_stack'] or not any(
                permissions == 6 and address + 64 <= stack <= address + length
                for address, _, length, permissions in aliases):
            raise ValueError('native direct memory requires a writable saved user stack')
    contract.update(page=page, preloaded=preloaded, host_alias_count=len(aliases),
                    runtime_snapshot_copy=not preloaded and 'flat_payload' in records,
                    direct_memory=bool(direct))
    header = struct.pack('<17Q', 1, base, end - base, start, done, result, checked['native_zero_bytes'], len(segments),
                         *(records[name]['value'] for name in ('flat_initial', 'flat_shadow', 'flat_uart')),
                         contract['linked_pc'], contract['native_stack'], records['flat_active']['value'],
                         contract['event_addr'], contract['event_capacity'], len(aliases))
    loads = b''.join(struct.pack('<5Q', *(region[key] for key in
                     ('address', 'file_offset', 'file_bytes', 'memory_bytes', 'flags'))) for region in segments)
    return header + loads + b''.join(HOST_ALIAS.pack(*row) for row in aliases), contract


def observe(data, offset=0):
    return dict(zip(OBSERVATION_FIELDS, OBSERVATION.unpack_from(data, offset)))


def breakpoint(observation, address, immediate):
    syndrome = observation['syndrome']
    return (observation['signal'] == signal.SIGTRAP and syndrome >> 26 == 0x3c and
            syndrome & 0xffff == immediate and observation['pc'] == address and
            not observation['pstate'] & PSTATE_NON_EL0T)


def run(image, out, loader=DEFAULT_LOADER, timeout=120, user_elf=None, reference=None):
    if sys.platform != 'darwin' or platform.machine() != 'arm64':
        raise ValueError('native execution requires Apple Silicon macOS')
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('timeout must be positive and finite')
    image, out, loader = (Path(path).resolve() for path in (image, out, loader))
    elf = Elf(image)
    checked = audit_elf(elf)
    command, contract = load_command(elf, checked, user_elf, reference)
    del elf
    out.mkdir(parents=True, exist_ok=False)
    report = dict(verified=False, image_sha256=checked['image_sha256'],
                  runtime_validation=checked['runtime_validation'], verification_scope=checked['verification_scope'],
                  platform='Apple Silicon macOS native process', address_space='native-process',
                  hypervisor=False, guest_page_tables=False, host_page_bytes=contract['page'],
                  host_alias_count=contract['host_alias_count'], direct_memory=contract['direct_memory'], entry=checked['entry'],
                  elf_ram_initialization=contract['preloaded'], runtime_snapshot_copy=contract['runtime_snapshot_copy'],
                  external_reference_verified=contract['external_reference_verified'], el0_interval_verified=False)
    try:
        execution = subprocess.run([str(loader), str(image)], input=command, capture_output=True, timeout=timeout)
        if execution.returncode:
            detail = execution.stderr.decode(errors='replace').strip()
            raise ValueError(f'native loader exited with status {execution.returncode}' + (f'\n{detail}' if detail else ''))
        data = execution.stdout
        entry = observe(data)
        reached, matched, actual_sp, private_sp, mode = ENTRY_AUX.unpack_from(data, OBSERVATION.size)
        frame_start = OBSERVATION.size + ENTRY_AUX.size
        frame_end = frame_start + FRAME_BYTES
        entry_frame = data[frame_start:frame_end]
        entry_verified = bool(reached and matched and entry_frame == contract['frame'] and
                              breakpoint(entry, contract['linked_pc'], 0x411))
        report['user_entry'] = dict(original_pc=hex(contract['original_pc']), linked_pc=hex(contract['linked_pc']),
                                    observation=entry, reached=bool(reached), verified=entry_verified,
                                    user_elf_entry=(hex(contract['user_elf_entry']) if user_elf is not None else None),
                                    user_elf_text_verified=contract['user_elf_text_verified'],
                                    actual_sp=hex(actual_sp), runtime_stack_top=hex(private_sp), shadow_mode=mode)
        if reached and not entry_verified:
            report['user_entry']['register_mismatches'] = differing_registers(entry_frame, contract['frame'])
        completion = observe(data, frame_end)
        report['completion'] = completion
        complete = entry_verified and breakpoint(completion, int(checked['terminal_pc'], 0), 0x412)
        report['el0_interval_verified'] = complete
        result_start = frame_end + OBSERVATION.size
        raw = data[result_start:result_start + RESULT_BYTES]
        state = data[result_start + RESULT_BYTES:]
        words, events, uart = record_completion(out, report, checked, contract, raw, state, entry_frame, reached)
        if not entry_verified:
            raise ValueError('saved user state was not verified at the native entry')
        if not complete:
            raise ValueError('native process stopped outside the completion breakpoint')
        report['terminal_exit_executed'] = False
        verify_result(report, checked, contract, raw, words, events, uart)
        report['verified'] = True
    except (ValueError, OSError, struct.error, subprocess.TimeoutExpired) as error:
        report['error'] = str(error)
    (out / 'validation.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path, help='static checkpoint ELF linked with MACOS_NATIVE=1')
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--loader', type=Path, default=DEFAULT_LOADER)
    parser.add_argument('--user-elf', type=Path, help='verify the original user ELF entry before replay')
    parser.add_argument('--reference', type=Path, help='verify the embedded event table against recorded calls.json')
    parser.add_argument('--timeout', type=float, default=120)
    try:
        report = run(**vars(parser.parse_args()))
    except (ValueError, OSError, struct.error) as error:
        parser.exit(1, f'{error}\n')
    print(json.dumps(report, indent=2))
    if not report['verified']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
