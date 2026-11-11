#!/usr/bin/env python3
"""Audit reviewed Linux profiles and prerequisites before booting a new Image.

This is a construction check, not evidence of syscall behavior on that kernel.
Run the native capture and full QEMU checkpoint pipeline after it passes.
"""
import argparse
import json
import re
import shutil
import subprocess
import zlib
from pathlib import Path

from capture_linux_aarch64 import (
    ROOT, INTEGRATION, PROFILES, GENERATED_PROFILES, digest, kernel_identity, missing_config,
    profile_integration, required_config, reviewed_adapter,
)
from export_syscall_slices import validate_port

FORMAT = 'osrec-linux-aarch64-preflight-v1'
MODEL_INPUTS = ('model.h', 'models.c', 'adapter.c', 'proof.c',
                'checkpoint-policy.json', 'application.c', 'port-template.json',
                'source-identity.json')
LLVM_TOOLS = ('clang', 'ld.lld', 'llvm-ar', 'llvm-nm', 'llvm-objcopy',
              'llvm-readelf', 'llvm-objdump')


def discover_profiles():
    return {'minimal' if p == INTEGRATION else p.name
            for p in [INTEGRATION, *INTEGRATION.iterdir()]
            if p.is_dir() and (p / 'port-template.json').is_file()}


def inspect_profile(profile, review=None):
    integration = profile_integration(profile)
    review = review or reviewed_adapter()
    identity, definitions = review.source_identity(integration)
    if identity.get('profile', 'minimal') != profile:
        raise ValueError('source identity profile differs from selection')
    port = json.loads((integration / 'port-template.json').read_text())
    if 'bundle' in port or 'capture_adapter' in port:
        raise ValueError('reviewed template must precede bundle construction')
    # Templates acquire their pinned prepare.py adapter when build_bundle runs.
    validate_port(dict(port, capture_adapter='prepare'))
    if port['application_abi'] != {
        'format': 'osrec-aarch64-syscall-registers-v1',
        'number_register': 8, 'argument_registers': [0, 1, 2, 3, 4, 5],
        'result_register': 0, 'continuation': 'svc-pc-plus-4',
    }:
        raise ValueError('Linux AArch64 application ABI differs')
    abi_text = (review.upstream(integration) / 'include/uapi/asm-generic/unistd.h').read_text()
    abi = {name: int(number) for name, number in re.findall(
        r'^#define __NR(?:3264)?_(\w+)\s+(\d+)\s*$', abi_text, re.M)}
    reported_routes = []
    for route in port['roots']:
        name = route['function'].removeprefix('linux_')
        abi_name = {'newfstat': 'fstat', 'cap_task_prctl': 'prctl'}.get(name, name)
        if abi.get(abi_name) != route['number']:
            raise ValueError('route number differs from pinned syscall ABI')
        if name in definitions:
            signature = definitions[name]['signature'].strip()
            arity = 0 if signature == 'void' else len(signature.split(','))
            implementation = 'original_definition'
        elif route['function'] == 'linux_fcntl':
            arity = 3
            implementation = 'reviewed_model'
        else:
            raise ValueError('route has no reviewed implementation: ' + route['function'])
        if len(route['arguments']) != arity:
            raise ValueError('route arity differs from reviewed implementation')
        reported_routes.append(dict(route, implementation=implementation))
    json.loads((integration / 'checkpoint-policy.json').read_text())
    calls = review.recipes(profile)
    routes = {r['number']: r for r in port['roots']}
    if not calls or {c['number'] for c in calls} != set(routes):
        raise ValueError('recipe and reviewed route sets differ')
    for call in calls:
        if not isinstance(call['args'], list) or not 1 <= len(call['args']) <= 6:
            raise ValueError('recipe argument width is unsupported')
        if len(routes[call['number']]['arguments']) > len(call['args']):
            raise ValueError('recipe omits syscall arguments')
        if any(type(v) is not int or not 0 <= v < 1 << 64 for v in call['args']):
            raise ValueError('recipe argument is not a 64-bit value')
    generated = profile in GENERATED_PROFILES
    if generated and (integration / 'application.c').read_text() != review.application_source(profile, port):
        raise ValueError('generated application differs from reviewed recipe')
    # Include hand-written witnesses and all model inputs even where witness
    # generation is not supported. These hashes are provenance, not attestations.
    inputs = {n: digest((integration / n).read_bytes()) for n in MODEL_INPUTS}
    return dict(
        profile=profile, status='inputs_validated', logical_calls=len(calls),
        routes=sorted(reported_routes, key=lambda r: r['number']),
        route_count=len(routes), original_definition_count=len(definitions),
        original_definitions={n: d['sha256'] for n, d in sorted(definitions.items())},
        selected_source_release=identity['release'],
        generated_witness_verified=generated,
        required_builtin_config=['CONFIG_' + s for s in required_config(profile)],
        input_sha256=inputs, native_behavior_verified=False,
        argument_domain='reviewed recipe and bounded dependency models',
    )


def probe(command):
    try:
        result = subprocess.run([str(v) for v in command], capture_output=True,
                                text=True, timeout=10, check=True)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError('tool probe failed: ' + str(command[0])) from error
    return result.stdout + result.stderr


def inspect_tools(llvm_bin, qemu, accel='tcg'):
    llvm_bin = Path(llvm_bin).resolve()
    versions = {}
    for name in LLVM_TOOLS:
        path = llvm_bin / name
        output = probe([path, '--version'])
        lines = output.splitlines()
        if not lines:
            raise ValueError('tool version is empty: ' + name)
        versions[name] = dict(path=str(path), version=lines[0])
    targets = probe([llvm_bin / 'clang', '--print-targets'])
    if not re.search(r'^\s*aarch64\s+-', targets, re.M):
        raise ValueError('clang has no AArch64 target')
    resolved = shutil.which(str(qemu))
    if resolved is None:
        raise ValueError('QEMU executable not found: ' + str(qemu))
    version = probe([resolved, '--version']).splitlines()
    if not version or 'QEMU emulator version' not in version[0]:
        raise ValueError('QEMU version is missing')
    accelerators = probe([resolved, '-accel', 'help']).splitlines()
    if accel not in [line.strip() for line in accelerators]:
        raise ValueError('QEMU accelerator unavailable: ' + accel)
    versions['qemu'] = dict(path=resolved, version=version[0], accelerator=accel)
    return versions


def preflight(profile='all', kernel_image=None, config=None, check_tools=False,
              llvm_bin=Path('/opt/homebrew/opt/llvm@16/bin'),
              qemu='qemu-system-aarch64', accel='tcg'):
    if profile != 'all' and profile not in PROFILES:
        raise ValueError('unsupported Linux profile')
    if accel not in ('tcg', 'hvf'):
        raise ValueError('unsupported QEMU accelerator')
    if config is not None and kernel_image is None:
        raise ValueError('--config requires --kernel-image')
    selected = PROFILES if profile == 'all' else (profile,)
    report = dict(format=FORMAT, status='inputs_validated', profiles=[],
                  kernel=None, tools=None, errors=[], native_behavior_verified=False,
                  kernel_configuration_source=('supplied' if config is not None else
                                               'embedded' if kernel_image is not None else None),
                  native_source_build_attested=False,
                  next_step='run native capture and the full QEMU checkpoint pipeline',
                  construction_sha256={
                      n: digest((ROOT / 'tools' / n).read_bytes())
                      for n in ('preflight_linux_aarch64.py', 'capture_linux_aarch64.py',
                                'export_syscall_slices.py')
                  },
                  reviewed_extractor_sha256=digest((INTEGRATION / 'prepare.py').read_bytes()))
    if profile == 'all':
        discovered = discover_profiles()
        missing = sorted(set(PROFILES) - discovered)
        unregistered = sorted(discovered - set(PROFILES))
        if missing or unregistered:
            report['errors'].append('profile registry differs from disk: ' +
                                    json.dumps(dict(missing=missing, unregistered=unregistered)))
    kernel_config = None
    if kernel_image is not None:
        try:
            report['kernel'], kernel_config = kernel_identity(kernel_image, config)
        except (ValueError, OSError, UnicodeError, EOFError, zlib.error) as error:
            report['errors'].append(str(error))
    if check_tools:
        try:
            report['tools'] = inspect_tools(llvm_bin, qemu, accel)
        except ValueError as error:
            report['errors'].append(str(error))
    review = reviewed_adapter()
    for name in selected:
        try:
            entry = inspect_profile(name, review)
            if kernel_config is not None:
                missing = missing_config(kernel_config, required_config(name))
                entry['missing_builtin_config'] = ['CONFIG_' + s for s in missing]
                if missing:
                    entry['status'] = 'rejected'
                    entry['error'] = 'kernel configuration does not meet profile prerequisites'
                else:
                    entry['status'] = 'prerequisites_validated'
            report['profiles'].append(entry)
        except (ValueError, OSError, KeyError, TypeError) as error:
            report['profiles'].append(dict(profile=name, status='rejected', error=str(error)))
    valid = [p for p in report['profiles'] if p['status'] != 'rejected']
    routes = sorted({r['number'] for p in valid for r in p['routes']})
    report['coverage'] = dict(validated_profiles=len(valid), distinct_routes=routes,
                              profiles_covering_union=[p['profile'] for p in valid
                                                       if [r['number'] for r in p['routes']] == routes])
    if report['errors'] or len(valid) != len(selected):
        report['status'] = 'rejected'
    elif kernel_image is not None:
        report['status'] = 'prerequisites_validated'
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('all',) + PROFILES, default='all')
    parser.add_argument('--kernel-image', type=Path)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--check-tools', action='store_true')
    parser.add_argument('--llvm-bin', type=Path, default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--qemu', default='qemu-system-aarch64')
    parser.add_argument('--accel', choices=('tcg', 'hvf'), default='tcg')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args(argv)
    if args.config is not None and args.kernel_image is None:
        parser.error('--config requires --kernel-image')
    if args.out is not None and args.out.exists():
        parser.error('--out already exists')
    report = preflight(args.profile, args.kernel_image, args.config, args.check_tools,
                       args.llvm_bin, args.qemu, args.accel)
    text = json.dumps(report, indent=2) + '\n'
    if args.out is None:
        print(text, end='')
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open('x') as stream:
            stream.write(text)
        print(args.out)
    return int(report['status'] == 'rejected')


if __name__ == '__main__':
    raise SystemExit(main())
