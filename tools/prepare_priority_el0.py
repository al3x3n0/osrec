#!/usr/bin/env python3
"""Prepare a complete pinned scheduler priority-limit syscall for EL0 extraction."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from klee_liteos import ROOT, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-root', required=True, type=Path)
    parser.add_argument('--llvm-bin', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--function', choices=['SysSchedGetPriorityMax', 'SysSchedGetPriorityMin'], default='SysSchedGetPriorityMax')
    args = parser.parse_args()
    lock_name = 'sched-priority-min-source-lock.json' if args.function.endswith('Min') else 'sched-priority-source-lock.json'
    lock = json.loads((ROOT/'integrations/liteos_a'/lock_name).read_text())
    revision = subprocess.check_output(['git', '-C', str(args.kernel_root), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != lock['revision']:
        raise ValueError('kernel revision differs from the source lock')
    raw = (args.kernel_root/lock['source']).read_bytes()
    if digest(raw) != lock['source_sha256']:
        raise ValueError('syscall source changed')
    for relative, expected in lock['headers'].items():
        if digest((args.kernel_root/relative).read_bytes()) != expected:
            raise ValueError('scheduler constant header changed')
    source = raw.decode()
    match = re.search(rf'int {args.function}\(int policy\)\s*\{{.*?\n\}}', source, re.DOTALL)
    if not match or digest(match[0].encode()) != lock['function_sha256']:
        raise ValueError('function body differs from the source lock')
    license_text = source[:source.index('*/')+2]
    prelude = '\n/* Preserve ARM32 scalar ABI; no dependency functions or state models. */\n'
    prelude += '\n'.join(f'#define {name} {value}'+('U' if name == 'LOS_SCHED_RR' else '')
                         for name, value in lock['constants'].items())+'\n'
    generated = license_text+prelude+f'#line {source[:match.start()].count(chr(10))+1} "{lock["source"]}"\n'+match[0]+'\n'
    output = args.out.resolve()
    if output.exists() or output.is_relative_to(args.kernel_root.resolve()):
        raise ValueError('output must be a new directory outside the checkout')
    output.mkdir(parents=True)
    path = output/'sched_priority.c'
    path.write_text(generated)
    module = output/'sched_priority.bc'
    subprocess.run([str(args.llvm_bin/'clang'), '-O1', '-g', '-ffreestanding', '-fno-builtin',
                    '-fno-stack-protector', '-emit-llvm', '-c', str(path), '-o', str(module)], check=True)
    identity = {'format': 'osrec-el0-source-identity-v1', 'module_sha256': digest(module.read_bytes()),
                'source': lock, 'license': license_text,
                'type_contract': 'int is signed 32-bit; LOS_SCHED_RR is unsigned 32-bit; exact function body; compile-time constants pinned; no modeled dependencies'}
    (output/'source-identity.json').write_text(json.dumps(identity, indent=2)+'\n')
    print(json.dumps({'root': lock['function'], 'module': str(module), 'source_identity': str(output/'source-identity.json')}, indent=2))


if __name__ == '__main__':
    main()
