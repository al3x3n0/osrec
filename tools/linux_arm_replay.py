#!/usr/bin/env python3
"""Rebuild a validated standalone replay as static ARMv7 Linux ELF."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from syscall_checkpoint import identity, load, main_source, validate_capture
from klee_liteos import ROOT, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--replay', type=Path, required=True)
    parser.add_argument('--kernel-root', type=Path, default=ROOT/'build/kernel_liteos_a')
    parser.add_argument('--llvm-bin', type=Path, default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--qemu', default='qemu-arm')
    parser.add_argument('--build-only', action='store_true')
    args = parser.parse_args()
    output = args.out.resolve()
    if output.exists():
        parser.error('output directory must be new')
    manifest = load(Path(str(args.replay)+'.manifest.json'))
    if digest(args.replay.read_bytes()) != manifest['artifact_sha256']:
        parser.error('original replay hash differs from its manifest')
    metadata = manifest['metadata']
    capture = metadata['capture']
    record, generated, sources = identity(args.kernel_root)
    objects = validate_capture(capture, record)
    runtime = ROOT/'integrations/linux_arm'
    output.mkdir(parents=True)
    stage = output/'sources'
    stage.mkdir()
    (stage/'osrec').mkdir()
    for path, data in sources.items():
        target = stage/'osrec/checkpoint.h' if path.name == 'checkpoint.h' else stage/path.name
        target.write_bytes(data)
    for path in runtime.iterdir():
        shutil.copy2(path, stage/path.name)
    (stage/'kernel_sysread.c').write_text(generated)
    (stage/'main.c').write_text(main_source(capture, objects, metadata=metadata))
    binary = output/'replay'
    command = [str(args.llvm_bin/'clang'), '--target=arm-linux-musleabi', '-mcpu=cortex-a7',
               '-marm', '-mfloat-abi=soft', '-std=c11', '-O0', '-ffreestanding', '-fno-builtin',
               '-fno-stack-protector', '-fno-pic', '-fno-pie', '-nostdlib', '-static',
               '-Wall', '-Wextra', '-Werror', '-fuse-ld=lld', '-Wl,-e,_start',
               '-I'+str(stage), *[str(stage/name) for name in
               ('start.S', 'runtime.c', 'kernel_sysread.c', 'checkpoint.c', 'syscall_checkpoint.c', 'main.c')],
               '-o', str(binary)]
    subprocess.run(command, check=True)
    report = {'format': 'osrec-linux-arm-replay-v1', 'target': 'ARMv7 Linux EABI, static ELF',
              'artifact_sha256': digest(binary.read_bytes()), 'artifact_bytes': binary.stat().st_size,
              'source_sha256': {str(p.relative_to(stage)): digest(p.read_bytes()) for p in stage.rglob('*') if p.is_file()},
              'build_command': command, 'qemu_verified': False,
              'original_artifact_sha256': manifest['artifact_sha256'],
              'runtime': 'minimal Linux EABI startup/write/exit and string/memory operations',
              'modeled_dependencies': metadata['modeled_dependencies']}
    if not args.build_only:
        qemu = shutil.which(args.qemu)
        if not qemu:
            (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
            parser.error('ELF built, but qemu-arm is unavailable; run on a Linux host')
        with tempfile.TemporaryDirectory(prefix='osrec-linux-arm-alone-') as directory:
            alone = Path(directory)/'replay'
            shutil.copy2(binary, alone)
            result = subprocess.run([qemu, '-cpu', 'cortex-a7', str(alone)], cwd=directory,
                                    capture_output=True, text=True, check=True, timeout=30)
            expected = f"syscall session verified: {len(capture['calls'])} calls"
            if result.stdout.strip() != expected:
                raise ValueError('unexpected replay output')
            description = subprocess.run([qemu, '-cpu', 'cortex-a7', str(alone), '--describe'],
                                         cwd=directory, capture_output=True, text=True, check=True, timeout=30)
            if json.loads(description.stdout) != metadata:
                raise ValueError('embedded checkpoint differs')
            report.update(qemu_verified=True, stdout=result.stdout, exit_status=result.returncode,
                          qemu_version=subprocess.check_output([qemu, '--version'], text=True).splitlines()[0])
            (output/'qemu.log').write_text(result.stdout+result.stderr)
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'executable': str(binary), 'qemu_verified': report['qemu_verified']}, indent=2))


if __name__ == '__main__':
    main()
