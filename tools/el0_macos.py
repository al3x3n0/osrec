#!/usr/bin/env python3
"""Load a self-contained EL0 checkpoint onto an Apple Silicon hardware vCPU."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys

from audit_el0_image import audit_elf
from el0_hardware_model import PAGE, PSTATE_NON_EL0T, RAM_BASE, RAM_END, RESULT_NAMES, SETUP, platform_registers
from el0_model import decode_result
from kernel_source_verify import Elf
from pretranslate_el0_image import file_offset, merged_ram_extents, verify_merged_ram

DEFAULT_LOADER = Path(__file__).resolve().parents[1] / 'build/el0-macos/elf-loader'
REGISTER_NAMES = ('MAIR_EL1', 'TCR_EL1', 'TTBR0_EL1', 'TTBR1_EL1', 'CPACR_EL1', 'SCTLR_EL1')
OBSERVATION_FIELDS = ('reason', 'syndrome', 'pc', 'pstate', 'x0', 'el1_esr', 'el1_elr', 'far', 'ipa',
                      'sctlr', 'ttbr0', 'ttbr1', 'hcr')
OBSERVATION = struct.Struct(f'<{len(OBSERVATION_FIELDS)}Q')
ENTRY_AUX = struct.Struct('<5Q')
FRAME_BYTES = 792
EVENT = struct.Struct('<10Q')
NZCV = 0xf0000000
LOGICAL_RESUME = (0xa94847f0, 0x910c83ff)
NATIVE_RESUME = (0xf9407ff1, 0xd1004231, 0xf94043f0, 0xf9000230,
                 0xf94047f0, 0xf9000630, 0x9100023f, 0xa8c147f0)
HOST_ALIAS = struct.Struct('<4Q')
MAX_HOST_ALIASES = 65536
MAPPING_WINDOW = struct.Struct('<4Q')
MAPPING_GATE = struct.Struct('<5Q')
MAPPING_COUNTS = struct.Struct('<4Q')
MAPPING_GATE_CODE = struct.pack('<2I', 0xd503201f, 0xd65f03c0)  # nop; ret
UACCESS_PAIR = struct.Struct('<2Q')
MAX_UACCESS_FIXUPS = 4096


def memory_segment(segments, address, size, flags, *, initialized=False):
    extent = 'file_bytes' if initialized else 'memory_bytes'
    for segment in segments:
        start = segment['address']
        if start <= address and address + size <= start + segment[extent] and segment['flags'] & flags == flags:
            return segment
    raise ValueError(f'ELF load does not cover {address:#x} with the required permissions')


def has_alias_backing(segments, address, size, flags):
    end = address + size
    extent = 'file_bytes' if flags & 1 else 'memory_bytes'
    for segment in segments:
        limit = segment['address'] + segment[extent]
        if limit <= address:
            continue
        if segment['address'] > address or segment['flags'] & flags != flags:
            return False
        address = min(limit, end)
        if address == end:
            return True
    return False


def host_aliases(elf, records, segments, flat, page_size, *, ram_range=(RAM_BASE, RAM_END)):
    table = records.get('flat_host_aliases')
    if table is None:
        return []
    if not flat:
        raise ValueError('host aliases require a flat checkpoint')
    size = table['size']
    if not 0 < size <= MAX_HOST_ALIASES * HOST_ALIAS.size or size % HOST_ALIAS.size:
        raise ValueError('invalid flat_host_aliases table size')
    storage = memory_segment(segments, table['value'], size, 4, initialized=True)
    if storage['flags'] != 4 or elf.sections[table['shndx']]['flags'] & 1:
        raise ValueError('flat_host_aliases must be read-only data')
    rows = sorted(HOST_ALIAS.iter_unpack(elf.read(table['value'], size)))
    previous_end = 0
    for address, backing, length, flags in rows:
        end = address + length
        if (not length or (address | backing | length) % page_size or
                end >= 1 << 64 or flags not in (4, 5, 6)):
            raise ValueError(f'invalid host alias at {address:#x}')
        if address < previous_end or (address < ram_range[1] and ram_range[0] < end):
            raise ValueError(f'overlapping host alias at {address:#x}')
        if not has_alias_backing(segments, backing, length, flags):
            raise ValueError(f'host alias at {address:#x} has no compatible ELF backing')
        previous_end = end
    return rows


def host_mapping_gate(elf, records, segments, flat, page_size, aliases, boundaries):
    gate = records.get('flat_host_mapping_gate')
    window = records.get('flat_host_mapping_window')
    if gate is None and window is None:
        return None
    if not flat or gate is None or window is None:
        raise ValueError('host mapping updates require a flat image with a gate and a window')
    pc = gate['value']
    code = memory_segment(segments, pc, len(MAPPING_GATE_CODE), 5, initialized=True)
    if (pc % 4 or pc in boundaries or gate['size'] != len(MAPPING_GATE_CODE) or
            code['flags'] != 5 or elf.sections[gate['shndx']]['flags'] & 1 or
            elf.read(pc, len(MAPPING_GATE_CODE)) != MAPPING_GATE_CODE):
        raise ValueError('invalid host mapping gate instructions or address')
    storage = memory_segment(segments, window['value'], MAPPING_WINDOW.size, 4, initialized=True)
    if (window['size'] != MAPPING_WINDOW.size or storage['flags'] != 4 or
            elf.sections[window['shndx']]['flags'] & 1):
        raise ValueError('host mapping window must be read-only data')
    address, size, backing, backing_size = MAPPING_WINDOW.unpack(elf.read(window['value'], MAPPING_WINDOW.size))
    end = address + size
    if (not size or not backing_size or end >= 1 << 64 or
            (address | backing | size | backing_size) % page_size):
        raise ValueError('invalid host mapping window alignment or size')
    if ((address < RAM_END and RAM_BASE < end) or
            any(address < a + length and a < end for a, _, length, _ in aliases)):
        raise ValueError('host mapping window overlaps an initial mapping')
    if not has_alias_backing(segments, backing, backing_size, 6):
        raise ValueError('host mapping window has no writable ELF backing')
    return pc, address, size, backing, backing_size


def host_uaccess_table(elf, records, segments, aliases, gate):
    table = records.get('flat_host_uaccess_fixups')
    if table is None:
        return b''
    size = table['size']
    if (gate is None or not 2 * UACCESS_PAIR.size <= size <= (1 + MAX_UACCESS_FIXUPS) * UACCESS_PAIR.size or
            size % UACCESS_PAIR.size):
        raise ValueError('invalid host user-copy table or missing mapping gate')
    storage = memory_segment(segments, table['value'], size, 4, initialized=True)
    if storage['flags'] != 4 or elf.sections[table['shndx']]['flags'] & 1:
        raise ValueError('host user-copy table must be read-only data')
    raw = elf.read(table['value'], size)
    entries, *fixups = UACCESS_PAIR.iter_unpack(raw)

    def instruction(pc):
        if pc % 4:
            raise ValueError('unaligned host user-copy address')
        for address, backing, length, flags in aliases:
            if flags == 5 and address <= pc and pc + 4 <= address + length:
                pc = backing + pc - address
                break
        if memory_segment(segments, pc, 4, 5, initialized=True)['flags'] != 5:
            raise ValueError('host user-copy code must be executable and read-only')
        return struct.unpack('<I', elf.read(pc, 4))[0]

    for entry in entries:
        instruction(entry)
    previous = -1
    for pc, target in fixups:
        if pc <= previous or pc == target:
            raise ValueError('host user-copy fixups must have distinct sorted sites and a different target')
        if instruction(pc) & 0x3fa00c00 != 0x38000800:
            raise ValueError('host user-copy fixup site is not an LDTR or STTR instruction')
        instruction(target)
        previous = pc
    return UACCESS_PAIR.pack(*entries) + struct.pack('<Q', len(fixups)) + raw[UACCESS_PAIR.size:]


def check_ram_preload(elf, symbols, segments):
    flag = symbols.get('flat_elf_ram_initialization') or symbols.get('flat_pretranslated_memory')
    if flag is None or elf.sections[flag['shndx']]['type'] == 8:
        return False
    if elf.read(flag['value'], 8) != struct.pack('<Q', 1):
        raise ValueError('invalid ELF RAM initialization mode')
    bank = symbols['flat_phys']
    payload = symbols['flat_payload']
    cursor, end = bank['value'], bank['value'] + bank['size']
    loads = [s for s in segments if s['address'] < end and cursor < s['address']+s['memory_bytes']]
    extents = merged_ram_extents(elf)
    if extents is not None:
        if payload['size'] and sum(size for _, size, _ in extents) != payload['size']:
            raise ValueError('merged RAM extent note does not cover the ELF snapshot')
        verify_merged_ram(elf, cursor, bank['size'], payload['value'], loads, extents)
        return True
    offset = file_offset(elf, payload['value'])
    loaded = 0
    for segment in loads:
        start = segment['address']
        stop = start + segment['memory_bytes']
        if start != cursor or stop > end or segment['flags'] != 6:
            raise ValueError('canonical RAM is not initialized by ELF loads')
        file_bytes = segment['file_bytes']
        if file_bytes and (file_bytes != segment['memory_bytes'] or segment['file_offset'] != offset + loaded):
            raise ValueError('canonical RAM loads do not reference the packed ELF snapshot')
        loaded += file_bytes
        cursor = stop
    if cursor != end or not loaded or (payload['size'] and loaded != payload['size']):
        raise ValueError('canonical RAM loads do not cover the ELF snapshot')
    return True


def resume_target(elf, segments, table, count, original_pc):
    segment = memory_segment(segments, table, count * 16, 4, initialized=True)
    if not count or segment['flags'] & 2:
        raise ValueError('invalid read-only checkpoint PC table')
    base = segment['file_offset'] + table - segment['address']
    lo, hi = 0, count
    while lo < hi:
        mid = (lo + hi) // 2
        pc, thunk = struct.unpack_from('<2Q', elf.data, base + mid * 16)
        if pc < original_pc:
            lo = mid + 1
        elif pc > original_pc:
            hi = mid
        else:
            break
    else:
        raise ValueError(f'saved user PC {original_pc:#x} has no linked resume target')
    first, = struct.unpack('<I', elf.read(thunk, 4))
    prefix = NATIVE_RESUME if first == NATIVE_RESUME[0] else LOGICAL_RESUME
    memory_segment(segments, thunk, 4 * (len(prefix) + 1), 5, initialized=True)
    *instructions, branch = struct.unpack(f'<{len(prefix)+1}I', elf.read(thunk, 4 * (len(prefix) + 1)))
    if tuple(instructions) != prefix or branch >> 26 != 5:
        raise ValueError('unsupported user-entry resume thunk')
    distance = ((branch & 0x3ffffff) ^ 0x2000000) - 0x2000000
    linked = thunk + 4 * (len(prefix) + distance)
    memory_segment(segments, linked, 4, 5, initialized=True)
    return linked, prefix == NATIVE_RESUME


def verify_user_text(elf, segments, program, user_elf, user, mappings):
    original = Elf(user_elf)
    ram_pa, ram_bytes, ram = struct.unpack('<3Q', elf.read(program[0], 24))
    for low, high in user['code']:
        cursor = low
        while cursor < high:
            mapping = next(((va, pa, size) for va, pa, size in mappings if va <= cursor < va + size), None)
            if mapping is None:
                raise ValueError(f'supplied user code {cursor:#x} is outside captured user text')
            va, pa, size = mapping
            count = min(high, va + size, (cursor & -PAGE) + PAGE) - cursor
            offset = pa + cursor - va - ram_pa
            if offset < 0 or offset + count > ram_bytes:
                raise ValueError(f'supplied user code {cursor:#x} is outside canonical RAM')
            address = ram + offset
            segment = memory_segment(segments, address, count, 4, initialized=True)
            file_start = segment['file_offset'] + address - segment['address']
            if elf.data[file_start:file_start + count] != original.read(cursor, count):
                raise ValueError(f'supplied user ELF bytes differ from captured user text at {cursor:#x}')
            cursor += count


def execution_contract(elf, records, segments, checked, preloaded, user_elf, reference):
    program = struct.unpack('<16Q', elf.read(records['flat_program']['value'], 128))
    table, entries = program[7:9]
    if table != records['flat_pcs']['value']:
        raise ValueError('checkpoint PC table does not match its ELF symbol')
    initial = elf.read(records['flat_initial']['value'], FRAME_BYTES)
    original_pc, = struct.unpack_from('<Q', initial, 256)
    if original_pc % 4:
        raise ValueError('unaligned saved user PC')
    user = None
    if user_elf is not None:
        from el0_application import inspect_user
        user = inspect_user(user_elf)
        if original_pc != user['entry']:
            raise ValueError(f'saved user PC {original_pc:#x} differs from supplied user ELF entry {user["entry"]:#x}')
    count, = struct.unpack('<Q', elf.read(records['flat_user_text_count']['value'], 8))
    user_text = list(struct.iter_unpack('<3Q', elf.read(records['flat_user_text']['value'], count * 24)))
    if not any(va <= original_pc and original_pc + 4 <= va + size
               for va, _, size in user_text):
        raise ValueError('saved user PC is outside the checkpoint user text')
    if user and preloaded:
        verify_user_text(elf, segments, program, user_elf, user, user_text)
    linked, native_stack = resume_target(elf, segments, table, entries, original_pc)
    if linked in (int(checked['entry'], 0), int(checked['terminal_pc'], 0)):
        raise ValueError('linked user entry coincides with an executor boundary')
    frame = bytearray(initial)
    struct.pack_into('<Q', frame, 256, linked)
    expected_ptr, expected_count = program[10:12]
    event_buffer = records.get('flat_events')
    expected_events = b''
    expected_uart = b''
    event_addr, capacity = 0, 0
    if checked['runtime_validation']:
        if not event_buffer or event_buffer['size'] % EVENT.size:
            raise ValueError('invalid checkpoint event buffer')
        event_addr, capacity = event_buffer['value'], event_buffer['size'] // EVENT.size
        if not 0 < expected_count <= capacity or expected_ptr != records['flat_expected']['value']:
            raise ValueError('invalid checkpoint expected event table')
        memory_segment(segments, event_addr, event_buffer['size'], 6)
        expected_events = elf.read(expected_ptr, expected_count * EVENT.size)
        uart_count, = struct.unpack('<Q', elf.read(records['flat_expected_uart_bytes']['value'], 8))
        if uart_count > 4096:
            raise ValueError('invalid checkpoint expected UART size')
        if uart_count:
            expected_uart = elf.read(records['flat_expected_uart']['value'], uart_count)
    if reference is not None:
        from export_el0_program import expected_events as pack_events
        ledger = json.loads(Path(reference).read_text())
        if not checked['runtime_validation']:
            raise ValueError('an external event reference requires a validation-enabled ELF')
        stop = ledger['end']['pc']
        if isinstance(stop, str):
            stop = int(stop, 0)
        if pack_events(ledger['calls'])[0] != expected_events or stop != program[14]:
            raise ValueError('embedded event reference or stop PC differs from the supplied recording')
    return dict(original_pc=original_pc, linked_pc=linked, native_stack=native_stack, frame=frame,
                user_elf_entry=original_pc if user_elf is not None else None, stop_pc=program[14],
                user_elf_text_verified=bool(user and preloaded), external_reference_verified=reference is not None,
                counters=program[13], expected_events=expected_events, expected_uart=expected_uart,
                event_addr=event_addr, event_capacity=capacity)


def load_command(elf, checked, user_elf=None, reference=None, ipa_4k=False):
    records = {symbol['name']: symbol for symbol in elf.symbols if symbol['shndx']}
    symbols = {name: symbol['value'] for name, symbol in records.items()}
    alias_free = symbols.get('flat_alias_free_memory_mode')
    if alias_free is not None and elf.read(alias_free, 8) != struct.pack('<Q', 1):
        raise ValueError('invalid alias-free mode in ELF')
    flat = checked['memory_backend'] == 'software' or alias_free is not None
    root = 0 if flat else symbols.get('flat_embedded_page_tables', 0)
    segments = sorted(checked['load_segments'], key=lambda segment: segment['address'])
    end = RAM_BASE
    for segment in segments:
        address = segment['address']
        if (address < end or not segment['memory_bytes'] or address + segment['memory_bytes'] > RAM_END or
                address < SETUP + PAGE and address + segment['memory_bytes'] > SETUP):
            raise ValueError(f'invalid or overlapping checkpoint load at {address:#x}')
        end = address + segment['memory_bytes']
    preloaded = check_ram_preload(elf, records, segments)
    entry, completion, result = (int(checked[key], 0) for key in ('entry', 'terminal_pc', 'result_address'))
    if not flat:
        if (root % PAGE or not any(s['address'] <= root and root + PAGE <= s['address'] + s['file_bytes']
                                  and s['flags'] == 4 for s in segments) or
                not any(elf.read(root, PAGE))):
            raise ValueError('checkpoint uses hardware aliases and requires initialized embedded tables')
    if checked['result_bytes'] != 320:
        raise ValueError('unsupported checkpoint result layout')
    zero_bytes = checked['native_zero_bytes']
    registers = platform_registers(48, root, zero_bytes)
    if flat:
        registers['SCTLR_EL1'] &= ~1
    if ipa_4k and not flat:
        raise ValueError('4 KiB IPA mappings require a flat checkpoint')
    page_size = PAGE if ipa_4k else os.sysconf('SC_PAGE_SIZE')
    aliases = host_aliases(elf, records, segments, flat, page_size)
    contract = execution_contract(elf, records, segments, checked, preloaded, user_elf, reference)
    gate = host_mapping_gate(elf, records, segments, flat, page_size, aliases,
                             (entry, completion, contract['linked_pc']))
    uaccess = host_uaccess_table(elf, records, segments, aliases, gate)
    contract['host_alias_count'] = len(aliases)
    contract['host_mapping_gate'] = gate is not None
    contract['host_uaccess'] = bool(uaccess)
    contract['host_ipa_granule_bytes'] = page_size
    contract['runtime_snapshot_copy'] = not preloaded and 'flat_payload' in records
    version = 6 if uaccess else 5 if gate is not None else 3 if aliases else 2
    header = struct.pack('<23Q', version, RAM_BASE, RAM_END - RAM_BASE, entry, completion, result,
                         *(registers[key] for key in REGISTER_NAMES), SETUP, zero_bytes, len(segments),
                         *(symbols[name] for name in ('flat_initial', 'flat_shadow', 'flat_uart')),
                         contract['linked_pc'], int(contract['native_stack']), symbols['flat_active'],
                         contract['event_addr'], contract['event_capacity'])
    loads = b''.join(struct.pack('<4Q', s['address'], s['file_offset'], s['file_bytes'], s['memory_bytes'])
                     for s in segments)
    if version >= 3:
        loads += struct.pack('<Q', len(aliases)) + b''.join(HOST_ALIAS.pack(*alias) for alias in aliases)
    if gate is not None:
        loads += MAPPING_GATE.pack(*gate) + uaccess
    return header + loads, flat, preloaded, contract


def verify_event_log(raw, expected):
    actual = []
    previous = None
    for event in EVENT.iter_unpack(raw):
        if not (previous and event[0] and previous[0] and event[2:5] == previous[2:5]):
            actual.append(event)
        previous = event
    expected = list(EVENT.iter_unpack(expected))
    if len(actual) != len(expected):
        raise ValueError(f'host event count mismatch: {len(actual)} != {len(expected)}')
    for i, (seen, wanted) in enumerate(zip(actual, expected)):
        if seen[:8] != wanted[:8] or seen[9] != wanted[9] or (seen[9] and seen[8] != wanted[8]):
            raise ValueError(f'host event {i} differs from the embedded reference')
    return len(actual)


def differing_registers(actual, expected):
    names = [f'x{i}' for i in range(31)] + ['sp', 'pc', 'pstate']
    return ([name for i, name in enumerate(names) if actual[i * 8:(i + 1) * 8] != expected[i * 8:(i + 1) * 8]] +
            [f'q{i}' for i in range(32) if actual[272 + i * 16:288 + i * 16] != expected[272 + i * 16:288 + i * 16]] +
            [name for offset, name in [(784, 'fpsr'), (788, 'fpcr')]
             if actual[offset:offset + 4] != expected[offset:offset + 4]])


def record_completion(out, report, checked, contract, raw, state, entry_frame, reached):
    words = struct.unpack('<40Q', raw)
    result = dict(zip(RESULT_NAMES, words[:16]), debug=list(words[16:]))
    report['result'] = result
    uart_bytes = result['uart_bytes']
    uart_end = FRAME_BYTES + 104 + uart_bytes
    event_bytes = state[uart_end:]
    if (len(state) != uart_end + result['events'] * EVENT.size or uart_bytes > 4096 or
            result['events'] > contract['event_capacity']):
        raise ValueError('ELF loader returned incomplete terminal state')
    evidence = {'result.bin': raw, 'guest-state.bin': state[:FRAME_BYTES],
                'shadow-state.bin': state[FRAME_BYTES:FRAME_BYTES + 104], 'uart.bin': state[FRAME_BYTES + 104:uart_end]}
    if reached:
        evidence['user-entry-state.bin'] = entry_frame
    if checked['runtime_validation']:
        evidence['events.bin'] = event_bytes
    for name, data in evidence.items():
        (out / name).write_bytes(data)
    report['evidence_sha256'] = {name: hashlib.sha256(data).hexdigest() for name, data in evidence.items()}
    return words, event_bytes, evidence['uart.bin']


def verify_result(report, checked, contract, raw, words, event_bytes, uart):
    result = report['result']
    if checked['runtime_validation']:
        decode_result(raw)
        if (result['expected'] != len(contract['expected_events']) // EVENT.size or
                result['counters'] != contract['counters'] or uart != contract['expected_uart']):
            raise ValueError('host result, counter count or UART differs from the embedded reference')
        report['host_events_verified'] = verify_event_log(event_bytes, contract['expected_events'])
    elif (words[:3] != (0x324c55464652534f, 2, 1) or result['reason'] != 1 or
          result['first_mismatch'] != (1 << 64) - 1 or result['missing_pc']):
        raise ValueError('checkpoint reported an execution failure')
    if report['completion']['x0']:
        raise ValueError('checkpoint returned a nonzero status')
    if result['pc'] != contract['stop_pc']:
        raise ValueError('reported guest stop PC differs from the checkpoint contract')


def run(image, out, loader=DEFAULT_LOADER, timeout=120, user_elf=None, reference=None, ipa_4k=False):
    if sys.platform != 'darwin' or platform.machine() != 'arm64':
        raise ValueError('the ELF loader requires Apple Silicon macOS')
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('timeout must be positive and finite')
    image, out, loader = (Path(path).resolve() for path in (image, out, loader))
    elf = Elf(image)
    checked = audit_elf(elf)
    command, flat, preloaded, contract = load_command(elf, checked, user_elf, reference, ipa_4k=ipa_4k)
    del elf
    out.mkdir(parents=True, exist_ok=False)
    report = dict(verified=False, image_sha256=checked['image_sha256'],
                  runtime_validation=checked['runtime_validation'], verification_scope=checked['verification_scope'],
                  platform='Apple Silicon Hypervisor.framework', entry=checked['entry'],
                  address_space='flat' if flat else 'guest-hardware-aliases',
                  host_ipa_granule_bytes=contract['host_ipa_granule_bytes'],
                  host_alias_count=contract['host_alias_count'],
                  elf_ram_initialization=preloaded, runtime_snapshot_copy=contract['runtime_snapshot_copy'],
                  external_reference_verified=contract['external_reference_verified'],
                  el0_interval_verified=False, rtl_execution_verified=False, cycles_verified=False)
    try:
        arguments = [str(loader), str(image)]
        if ipa_4k:
            arguments.append('--4k-ipa')
        execution = subprocess.run(arguments, input=command, capture_output=True, timeout=timeout)
        if execution.returncode:
            detail = execution.stderr.decode(errors='replace').strip()
            message = f'ELF loader exited with status {execution.returncode}'
            raise ValueError(f'{message}\n{detail}' if detail else message)
        data = execution.stdout
        entry = dict(zip(OBSERVATION_FIELDS, OBSERVATION.unpack_from(data)))
        reached, matched, actual_sp, private_sp, mode = ENTRY_AUX.unpack_from(data, OBSERVATION.size)
        frame_start = OBSERVATION.size + ENTRY_AUX.size
        frame_end = frame_start + FRAME_BYTES
        entry_frame = data[frame_start:frame_end]
        entry_verified = bool(reached and matched and entry_frame == contract['frame'])
        report['user_entry'] = dict(original_pc=hex(contract['original_pc']), linked_pc=hex(contract['linked_pc']),
                                    user_elf_entry=(hex(contract['user_elf_entry'])
                                                    if contract['user_elf_entry'] is not None else None),
                                    user_elf_text_verified=contract['user_elf_text_verified'],
                                    verified=entry_verified, reached=bool(reached), observation=entry,
                                    actual_sp=hex(actual_sp), runtime_stack_top=hex(private_sp), shadow_mode=mode,
                                    stack_mode='native' if contract['native_stack'] else 'logical')
        if reached and not entry_verified:
            report['user_entry']['register_mismatches'] = differing_registers(entry_frame, contract['frame'])
        observed = dict(zip(OBSERVATION_FIELDS, OBSERVATION.unpack_from(data, frame_end)))
        report['completion'] = observed
        report['guest_stage1_translation'] = bool(observed['sctlr'] & 1)
        completion_pc = int(checked['terminal_pc'], 0)
        # EC 0x30 is the instruction-breakpoint exception from a lower EL.
        complete = (entry_verified and observed['reason'] == 1 and observed['syndrome'] >> 26 == 0x30 and
                    observed['pc'] == completion_pc and not observed['pstate'] & PSTATE_NON_EL0T and
                    not observed['el1_esr'] and not observed['el1_elr'])
        report['el0_interval_verified'] = complete
        if complete:
            report.update(hardware_exceptions=0, guest_el1_services=0,
                          terminal_exit_executed=False)
        result_start = frame_end + OBSERVATION.size
        raw = data[result_start:result_start + 320]
        state = data[result_start + 320:]
        if contract['host_uaccess']:
            report['host_uaccess_calls'], report['host_uaccess_fixups'] = UACCESS_PAIR.unpack(state[-UACCESS_PAIR.size:])
            state = state[:-UACCESS_PAIR.size]
        if contract['host_mapping_gate']:
            maps, unmaps, protects, queries = MAPPING_COUNTS.unpack(state[-MAPPING_COUNTS.size:])
            report['host_mapping_updates'] = dict(map=maps, unmap=unmaps, protect=protects)
            report['host_access_queries'] = queries
            state = state[:-MAPPING_COUNTS.size]
        words, event_bytes, uart = record_completion(out, report, checked, contract, raw, state, entry_frame, reached)
        if not entry_verified:
            raise ValueError('saved user state was not verified at the relocated entry')
        if not complete:
            raise ValueError('vCPU stopped outside the EL0 completion breakpoint')
        if flat and any(stop['sctlr'] & 1 or stop['ttbr0'] or stop['ttbr1'] or not stop['hcr'] & (1 << 12)
                        for stop in (entry, observed)):
            raise ValueError('flat run did not retain the expected translation controls')
        verify_result(report, checked, contract, raw, words, event_bytes, uart)
        report['verified'] = True
    except (ValueError, OSError, struct.error, subprocess.TimeoutExpired) as error:
        report['error'] = str(error)
    (out / 'validation.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True, help='self-contained checkpoint ELF')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--loader', type=Path, default=DEFAULT_LOADER)
    parser.add_argument('--user-elf', type=Path, help='verify the original user ELF entry before replay')
    parser.add_argument('--reference', type=Path, help='verify the embedded event table against recorded calls.json')
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--4k-ipa', dest='ipa_4k', action='store_true',
                        help='use 4 KiB host IPA mappings with the macOS 26 Hypervisor API')
    args = parser.parse_args()
    try:
        report = run(**vars(args))
    except (ValueError, OSError, struct.error) as error:
        parser.exit(1, f'{error}\n')
    print(json.dumps(report, indent=2))
    if not report['verified']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
