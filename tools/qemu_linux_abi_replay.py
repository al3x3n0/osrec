#!/usr/bin/env python3
"""Execute an unchanged Linux ARM ELF with a limited QEMU system ABI adapter."""
import argparse
import collections
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess

from klee_liteos import ROOT, digest


def run(command, **kwargs):
    return subprocess.run(list(map(str, command)), check=True, capture_output=True,
                          text=True, timeout=60, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--llvm-bin', type=Path, default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--qemu', default='qemu-system-arm')
    args = parser.parse_args()
    raw = args.elf.read_bytes()
    header = struct.unpack_from('<16sHHIIIIIHHHHHH', raw)
    ident, kind, machine, version, entry, phoff, _, _, _, phsize, phcount, *_ = header
    if ident[:7] != b'\x7fELF\x01\x01\x01' or kind != 2 or machine != 40 or version != 1 or phsize != 32:
        raise ValueError('requires little-endian ARM ELF32 executable')
    memory = bytearray(0x100000)
    executable = []
    loads = []
    for i in range(phcount):
        segment = struct.unpack_from('<8I', raw, phoff+i*phsize)
        ptype, offset, address, _, filesize, memsize, flags, _ = segment
        if ptype == 3:
            raise ValueError('dynamic loaders are unsupported')
        if ptype != 1:
            continue
        if filesize > memsize or address < 0x10000 or address+memsize >= 0xe0000 or offset+filesize > len(raw):
            raise ValueError('ELF segment exceeds bounded adapter memory')
        memory[address:address+filesize] = raw[offset:offset+filesize]
        loads.append((address, filesize))
        if flags & 1:
            executable.append((address, address+filesize))
    if not any(low <= entry < high for low, high in executable) or entry % 4:
        raise ValueError('entry is not ARM code in an executable segment')
    if args.out.exists():
        raise ValueError('output must be a new directory')
    args.out.mkdir(parents=True)
    stage = args.out/'sources'
    shutil.copytree(ROOT/'integrations/linux_arm_qemu', stage)
    (stage/'image.bin').write_bytes(memory)
    (stage/'image.S').write_text('.section .rodata,"a"\n.global replay_image\nreplay_image:\n.incbin "image.bin"\n')
    symbols = run([args.llvm_bin/'llvm-nm', '-S', '--defined-only', args.elf]).stdout
    function_ranges = []
    for line in symbols.splitlines():
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [Tt] (\S+)', line)
        if match:
            address, size, name = match.groups()
            function_ranges.append((int(address, 16), int(address, 16)+int(size, 16), name))
    base = [args.qemu, '-M', 'virt-9.2,secure=off,virtualization=off', '-cpu', 'cortex-a7',
            '-accel', 'tcg,one-insn-per-tb=on', '-smp', '1', '-m', '64M',
            '-display', 'none', '-monitor', 'none', '-serial', 'stdio',
            '-semihosting-config', 'enable=on,target=native']
    report = {'format': 'osrec-qemu-linux-abi-replay-v1', 'status': 'not-yet-verified',
              'elf_sha256': digest(raw), 'elf_bytes': len(raw),
              'scope': 'unchanged Linux ARM ELF in user mode under a minimal write/exit ABI adapter; no Linux kernel, no qemu-arm',
              'instruction_count_method': 'one instruction per translation block; complete exec,nochain trace; count PCs in ELF executable segments',
              'qemu_version': run([args.qemu, '--version']).stdout.splitlines()[0],
              'executable_segments': executable}
    for describe in (False, True):
        name = 'describe' if describe else 'replay'
        segment_values = ','.join('{'+f'{address}U,{size}U'+'}' for address, size in loads)
        (stage/'config.h').write_text(f'#define ELF_ENTRY {entry}U\n#define DESCRIBE {int(describe)}\n'
                                    + '#define ELF_LOAD_SEGMENTS {'+segment_values+'}\n')
        image = (args.out/(name+'-adapter.elf')).resolve()
        build = [args.llvm_bin/'clang', '--target=arm-none-eabi', '-mcpu=cortex-a7',
                 '-marm', '-mfloat-abi=soft', '-O1', '-ffreestanding', '-fno-builtin',
                 '-fno-stack-protector', '-Wall', '-Wextra', '-Werror', '-nostdlib',
                 '-fuse-ld=lld', '-Wl,-T,guest.ld', 'start.S', 'guest.c', 'image.S', '-o', image]
        run(build, cwd=stage)
        trace = (args.out/(name+'-trace.log')).resolve()
        command = base+['-d', 'exec,nochain', '-dfilter', '0x10000..0xdffff', '-D', trace, '-kernel', image]
        result = run(command)
        (args.out/(name+'.log')).write_text(result.stdout+result.stderr)
        counts = collections.Counter()
        for line in trace.read_text().splitlines():
            match = re.match(r'Trace \d+: \S+ \[[0-9a-f]+/([0-9a-f]+)/', line)
            if not match:
                continue
            pc = int(match.group(1), 16)
            if any(low <= pc < high for low, high in executable):
                counts[pc] += 1
        if not counts:
            raise ValueError('no ELF instruction execution found')
        by_function = {symbol: sum(count for pc, count in counts.items() if low <= pc < high)
                       for low, high, symbol in function_ranges}
        if describe:
            observed = json.loads(result.stdout)
            original = json.loads((args.elf.parent/'sources/main.c').read_text().split('puts(', 1)[1].split(');', 1)[0])
            if observed != json.loads(original):
                raise ValueError('embedded metadata mismatch')
        elif result.stdout.strip() != 'syscall session verified: 4 calls':
            raise ValueError('replay did not verify four calls')
        report[name] = {'exit_status': result.returncode, 'stdout': result.stdout,
                        'dynamic_elf_instructions': sum(counts.values()), 'per_function': by_function,
                        'trace_sha256': digest(trace.read_bytes()), 'adapter_sha256': digest(image.read_bytes()),
                        'qemu_command': list(map(str, command))}
    report['status'] = 'verified'
    report['adapter_source_hashes'] = {str(p.relative_to(stage)): digest(p.read_bytes()) for p in stage.rglob('*') if p.is_file()}
    (args.out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({key: report[key] for key in ('status', 'scope')} | {
        'dynamic_replay_instructions': report['replay']['dynamic_elf_instructions'],
        'dynamic_sysread_instructions': report['replay']['per_function'].get('SysRead'),
        'output': str(args.out)}, indent=2))


if __name__ == '__main__':
    main()
