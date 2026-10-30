#!/usr/bin/env python3
"""Replay a single-CPU completion capture using real AArch64 nested IRQs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from export_task_capsule import decode, REGION, MAX_BYTES
from freestanding_armv7 import audit, run
from freestanding_elf import prepare_target, target_metadata
from run_freestanding_armv7 import observe, require_success

ROOT = Path(__file__).resolve().parents[1]


def export(args):
    capture_path = Path(args.capture).resolve()
    out = Path(args.out).resolve()
    if out.exists():
        raise ValueError('choose a new output directory')
    with capture_path.open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    source = REGION.read_bytes()
    capture = decode(raw, source)
    if len(capture.initial_tasks) != 1 or any(e.cpu != 0 for e in capture.events):
        raise ValueError('hardware IRQ replay requires a single-CPU capture')
    args.arch = 'aarch64'
    digest = lambda data: hashlib.sha256(data).hexdigest()
    values = dict(available=capture.available, demand=capture.demand,
                  outer=capture.events[3].b, nested=capture.events[5].b,
                  selected=capture.selected_task, background=capture.events[1].b,
                  wait=capture.events[0].a, generation=capture.events[0].b)
    header = '#include <stdint.h>\n'
    header += ''.join(f'static const uint64_t checkpoint_{k}=UINT64_C({v});\n'
                      for k, v in values.items())
    header += f'static const char checkpoint_source[]="{digest(source)}";\n'
    header += 'static const unsigned char checkpoint_trace[]={' + ','.join(map(str, raw)) + '};\n'
    with tempfile.TemporaryDirectory(prefix='osrec-async-task-') as name:
        stage = Path(name)
        sources = stage / 'sources'
        sources.mkdir()
        flags = prepare_target(args, sources)
        shutil.copyfile(ROOT/'integrations/rtl_aarch64/async_start.S', sources/'start.S')
        shutil.copyfile(ROOT/'integrations/rtl_aarch64/async_replay.c', sources/'replay.c')
        shutil.copyfile(REGION, sources/'task_region.h')
        for filename in ('context.c', 'recorder.c'):
            shutil.copyfile(ROOT/'runtime'/filename, sources/filename)
        shutil.copytree(ROOT/'include/osrec', sources/'osrec')
        (sources/'async_checkpoint.h').write_text(header)
        image = stage/'async-task.elf'
        binary = stage/'async-task.bin'
        run([args.llvm_bin/'clang', *flags, '-std=c11', '-O1', '-ffreestanding',
             '-fno-builtin', '-fno-stack-protector', '-fno-unwind-tables',
             '-fno-asynchronous-unwind-tables', '-Wall', '-Wextra', '-Werror',
             '-nostdlib', '-static', '-fuse-ld=lld', '-Wl,--no-undefined',
             '-Wl,-T,'+str(sources/'image.ld'), '-I'+str(sources),
             sources/'start.S', sources/'replay.c', sources/'context.c',
             sources/'recorder.c', '-o', image])
        inspection = audit(image, args.llvm_bin)
        symbols = [line.split() for line in run([args.llvm_bin/'llvm-nm',
                                                '--defined-only', '--format=posix', image]).stdout.splitlines()]
        trace_symbols = [row for row in symbols if row[0] == 'osrec_async_trace']
        if len(trace_symbols) != 1 or int(trace_symbols[0][3], 16) != 4096:
            raise ValueError('image has no bounded target trace storage')
        trace_address = int(trace_symbols[0][2], 16)
        run([args.llvm_bin/'llvm-objcopy', '-O', 'binary', image, binary])
        observations = []
        for index, (payload, descriptor) in enumerate(((image, None), (binary, image))):
            trace_dump = stage/f'target-context-{index}.osrec'
            observed, result = observe(payload, args.qemu, descriptor=descriptor,
                                       memory_dumps=({'address': trace_address, 'bytes': len(raw),
                                                      'file': str(trace_dump)},))
            require_success(observed)
            if trace_dump.read_bytes() != raw:
                raise ValueError('independent RAM trace differs from captured context events')
            if (observed['remaining'], observed['return_value']) != (capture.remaining, capture.result):
                raise ValueError('hardware IRQ task output differs from capture')
            observations.append((observed, result))
        if observations[0][1] != observations[1][1]:
            raise ValueError('ELF/raw hardware IRQ results differ')
        target = target_metadata(inspection, 27)
        target.update(interrupts_enabled=True, interrupt_controller='QEMU virt GICv2',
                      interrupt_sources=['physical timer PPI 30', 'higher-priority SGI 1'])
        manifest = dict(format='osrec-async-task-image-v1', status='verified',
                        target=target, image_audit=inspection,
                        capture_sha256=digest(raw), source_sha256=digest(source),
                        independent_ram_trace_verified=True, target_trace_sha256=digest(raw),
                        runtime_host_interaction=False, hardware_irq_delivery=True,
                        kernel_scheduler_reproduction=False, cpu_migration=False,
                        continuation_scheduler=True, rtl_validated=False,
                        cycle_timing_equivalence_verified=False,
                        compiler=run([args.llvm_bin/'clang', '--version']).stdout.splitlines()[0],
                        qemu=run([args.qemu, '--version']).stdout.splitlines()[0],
                        exporter_sha256=digest(Path(__file__).read_bytes()),
                        target_observations=observations[0][0], raw_image_execution_match=True,
                        elf_sha256=digest(image.read_bytes()), binary_sha256=digest(binary.read_bytes()),
                        source_hashes={str(p.relative_to(sources)): digest(p.read_bytes())
                                       for p in sorted(sources.rglob('*')) if p.is_file()})
        (stage/'capture.osrec').write_bytes(raw)
        (stage/'target-result.bin').write_bytes(observations[0][1])
        (stage/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(stage, out)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--llvm-bin', type=Path, default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--qemu', default='qemu-system-aarch64')
    parser.add_argument('--entry-address', type=lambda v: int(v, 0), default=0x40200000)
    parser.add_argument('--result-address', type=lambda v: int(v, 0), default=0x40180000)
    args = parser.parse_args()
    try:
        report = export(args)
    except subprocess.CalledProcessError as error:
        parser.exit(1, f'async task build failed: {error.stderr}\n')
    except (ValueError, OSError) as error:
        parser.exit(1, f'async task export failed: {error}\n')
    print(json.dumps(report['target_observations'], indent=2))


if __name__ == '__main__':
    main()
