#!/usr/bin/env python3
"""Measure shared-root Linux replay and its native QEMU reference."""
import argparse
import bisect
import hashlib
import json
import struct
import subprocess
import time
from collections import Counter
from pathlib import Path

import qemu_vm_checkpoint as checkpoint
from el0_instruction_profile import segments
from kernel_source_verify import Elf
from source_image import PAGE, Ram, qemu_boot_image, text_ranges
from source_image_calls import branch
from source_image_el0 import BRK_BOUNDARY, BRK_SITE, rewrite, system_read_moves

COUNTS = struct.Struct('<20Q')
KERNEL_PAYLOAD, APPLICATION, KERNEL_VISIT, APPLICATION_VISIT, VENEER = 1, 2, 4, 8, 16


def classify(image, manifest, ram):
    """Audit every changed text word and identify the slots that enter EL1."""
    linked = (image / 'image.elf').read_bytes()
    if hashlib.sha256(linked).hexdigest() != manifest['image_sha256']:
        raise ValueError('image differs from its manifest')
    loads = sorted((pa, pa + size, offset)
                   for kind, _, offset, _, pa, size, _, _ in segments(linked) if kind == 1)
    starts = [pa for pa, _, _ in loads]
    moves = system_read_moves(manifest.get('inline_system_reads', {}))
    veneer_words = {}
    if manifest['branch_sites']:
        targets = {s['name']: s['value'] for s in Elf(image / 'calls.elf').symbols}
        for i, site in enumerate(json.loads((image / 'calls.json').read_text())):
            pc = int(site['pc'], 16)
            veneer_words[pc] = branch(pc, targets[f'osrec_call_{i}'])
    changes = Counter()
    traps = set()
    for page in manifest['pages']:
        if page['kind'] != 'text':
            continue
        va, pa = int(page['va'], 16), int(page['pa'], 16)
        index = bisect.bisect_right(starts, pa) - 1
        if index < 0 or pa + PAGE > loads[index][1]:
            raise ValueError(f'linked image is missing physical text at {pa:#x}')
        lo, _, offset = loads[index]
        at = offset + pa - lo
        original_page = ram.page(pa)
        for i in range(0, PAGE, 4):
            original, = struct.unpack_from('<I', original_page, i)
            patched, = struct.unpack_from('<I', linked, at + i)
            if patched == original:
                continue
            pc = va + i
            if patched == BRK_BOUNDARY:
                kind = 'profile_boundary'
            elif patched == veneer_words.get(pc):
                kind = 'architecture_branch'
            else:
                expected, kind = rewrite(original, moves, shadow_tls=manifest.get('kernel_tls_shadow', False))
                if patched != expected or kind is None:
                    raise ValueError(f'unexpected replacement at {pc:#x}: {original:#x} -> {patched:#x}')
            changes[kind] += 1
            if patched in (BRK_SITE, BRK_BOUNDARY):
                traps.add(pc)
    return changes, traps


def prepare(directory, text, application, traps, veneers, start, stop):
    directory.mkdir()
    rows = {pc: KERNEL_VISIT | (0 if pc in traps else KERNEL_PAYLOAD)
            for lo, hi in text for pc in range(lo, hi, 4)}
    for section in application.sections:
        if section['flags'] & 4:
            for pc in range(section['addr'], section['addr'] + section['size'], 4):
                if pc in rows:
                    raise ValueError(f'application and kernel text overlap at {pc:#x}')
                rows[pc] = APPLICATION_VISIT | APPLICATION
    if veneers:
        base = int(veneers['va'], 16)
        for pc in range(base, base + veneers['size'], 4):
            if pc in rows:
                raise ValueError(f'veneer overlaps captured text at {pc:#x}')
            rows[pc] = VENEER | KERNEL_PAYLOAD
    pc_map = directory / 'map.bin'
    pc_map.write_bytes(b''.join(struct.pack('<QQ', pc, flags) for pc, flags in sorted(rows.items())))
    return dict(map=pc_map, out=directory / 'counts.bin', start=hex(start),
                begin=hex(start), end=hex(stop), stop=hex(stop))


def wait_for_counts(path, process, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and path.stat().st_size == COUNTS.size:
            counts = COUNTS.unpack(path.read_bytes())
            if counts[5]:
                if counts[:6] != (0x3150434952534f, 1, 1, 1, 1, 1):
                    raise ValueError('unexpected QEMU profile window boundaries')
                return counts
        if process.poll() is not None:
            raise ValueError('QEMU exited before producing profile counts')
        time.sleep(.02)
    raise TimeoutError('QEMU did not reach the profile stop')


def summarize(counts):
    runtime, kernel, user, kernel_visits, user_visits, veneers = counts[14:20]
    kernel_sites = kernel - veneers
    trap_sites = kernel_visits - kernel_sites
    if not 0 <= trap_sites <= runtime or kernel_sites < 0 or user != user_visits:
        raise ValueError('conflicting QEMU instruction counts')
    return dict(total=runtime + kernel + user, kernel_payload=kernel, user=user,
                kernel_visits=kernel_visits, branch_veneer=veneers, trapping_kernel_sites=trap_sites,
                monitor=runtime - trap_sites, runtime=runtime)


def profile(image, bundle, application, plugin, out, timeout):
    manifest = json.loads((image / 'manifest.json').read_text())
    if manifest.get('execution') != 'el0-minios' or not manifest.get('shared_root'):
        raise ValueError('profiling requires a shared-root EL0 source image')
    if not plugin.is_file():
        raise ValueError(f'missing QEMU instruction-counting plugin: {plugin}')
    spec = checkpoint.verify(bundle)
    oracle = spec['protocol']['expected_success']
    kernel, text = text_ranges(manifest['vmlinux'])
    stop = next(s['value'] for s in kernel.symbols if s['name'] == 'kernel_power_off')
    ram = Ram(manifest['dump'])
    with ram.file, ram.ram:
        native_manifest = json.loads((bundle / 'manifest.json').read_text())
        if ram.state['checkpoint']['vmstate_sha256'] != native_manifest['vmstate_sha256']:
            raise ValueError('the native checkpoint differs from the source image capture')
        start = ram.sysregs['ELR_EL1'] - 4
        changes, traps = classify(image, manifest, ram)
    app = Elf(application)
    out.mkdir(parents=True)
    native = out / 'native'
    options = prepare(native, text, app, set(), None, start, stop)
    with checkpoint.Machine(bundle, 'count', incoming=True, timeout=timeout,
                            execution_dir=native, plugin=(plugin, options)) as vm:
        vm.request('migrate-incoming', dict(uri='file:' + str(bundle / 'vmstate.bin')))
        vm.migration_complete()
        if vm.continue_guest() != oracle:
            raise ValueError('native QEMU workload did not match the checkpoint oracle')
        native_counts = wait_for_counts(options['out'], vm.process, timeout)

    el0 = out / 'el0'
    options = prepare(el0, text, app, traps, manifest['branch_veneers'], start, stop)
    console = el0 / 'console.txt'
    args = ','.join([f'file={plugin}', *(f'{k}={v}' for k, v in options.items())])
    command = [spec['qemu'], '-M', 'virt-9.2,secure=off,virtualization=off', '-cpu', 'cortex-a53',
               '-accel', 'tcg', '-smp', '1', '-m', str(manifest['image_ram_mb']) + 'M',
               '-nodefaults', '-display', 'none', '-monitor', 'none', '-serial', f'file:{console}',
               '-semihosting-config', 'enable=off', *qemu_boot_image(image, manifest),
               '-plugin', args]
    checkpoint.write(el0 / 'command.json', command)
    with (el0 / 'qemu.stderr.log').open('wb') as log, subprocess.Popen(command, stdout=log, stderr=log) as vm:
        try:
            el0_counts = wait_for_counts(options['out'], vm, timeout)
            if oracle not in console.read_text().splitlines():
                raise ValueError('EL0 workload did not match the checkpoint oracle')
        finally:
            vm.terminate()
            vm.wait(timeout=10)
    report = dict(status='pass', start=hex(start), stop_exclusive=hex(stop),
                  image_sha256=manifest['image_sha256'], modified_words=dict(changes),
                  native=summarize(native_counts), el0=summarize(el0_counts))
    replay = report['el0']
    report['guest_total_ratio'] = replay['total'] / report['native']['total']
    report['runtime_per_kernel_visit'] = replay['runtime'] / replay['kernel_visits']
    checkpoint.write(out / 'counts.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'bundle', 'application', 'plugin', 'out'):
        parser.add_argument('--' + name, type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument('--timeout', type=int, default=60)
    print(json.dumps(profile(**vars(parser.parse_args())), indent=2))
