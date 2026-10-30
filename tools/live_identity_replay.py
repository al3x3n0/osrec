"""Replay live OHOS identity queries using original bodies and ordered scalar dependencies."""
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

from klee_liteos import ROOT, digest
from export_sysread import dependencies

# Full-width UID/GID ABI. The pinned getpgrp dispatcher also takes a PID argument.
CALLS = ((199, 0), (200, 0), (65, 0), (132, 0), (132, 1), (132, 0xffffffff), (132, 0))
BOUNDARIES = {1: 'LOS_GetCurrProcessID', 2: 'LOS_GetUserID', 3: 'LOS_GetGroupID', 4: 'LOS_GetProcessGroupID'}


def decode_identity(observations, transcript):
    if len(observations) != len(CALLS)*16:
        raise ValueError('identity observation size differs')
    calls = []
    signed = lambda bits: bits if bits < 0x80000000 else bits-0x100000000
    for i, (number, argument) in enumerate(CALLS):
        actual_number, actual_argument, raw, mode = struct.unpack_from('<4I', observations, i*16)
        if (actual_number, actual_argument) != (number, argument) or mode != 0x10:
            raise ValueError('identity syscall argument, number or user mode differs')
        calls.append({'number': number, 'argument_bits': argument, 'raw': signed(raw), 'user_mode': mode})
    if not transcript or len(transcript)%16 or len(transcript) > 16*16:
        raise ValueError('identity dependency transcript size differs')
    events = []
    for invocation, kind, argument, raw in struct.iter_unpack('<4I', transcript):
        if invocation >= len(CALLS) or kind not in BOUNDARIES or (kind != 4 and argument != 0):
            raise ValueError('invalid identity dependency event')
        events.append({'invocation': invocation, 'kind': kind, 'argument_bits': argument, 'result_bits': raw})
    return calls, events


def prepare_source(kernel_root):
    lock = json.loads((ROOT/'integrations/liteos_a/identity-source-lock.json').read_text())
    revision = subprocess.check_output(['git', '-C', str(kernel_root), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != lock['revision']:
        raise ValueError('identity kernel revision differs from source lock')
    live = ROOT/'build/ohos/kernel/liteos_a'
    for root in (kernel_root, live):
        if digest((root/lock['source']).read_bytes()) != lock['source_sha256']:
            raise ValueError('identity syscall source changed')
        for relative, expected in lock['headers'].items():
            if digest((root/relative).read_bytes()) != expected:
                raise ValueError('identity dispatch/declaration header changed')
    source = (kernel_root/lock['source']).read_text()
    bodies = []
    for name, contract in lock['functions'].items():
        pattern = rf'int {name}\({re.escape(contract["signature"])}\)\s*\{{.*?\n\}}'
        match = re.search(pattern, source, re.DOTALL)
        if not match or digest(match[0].encode()) != contract['sha256']:
            raise ValueError('identity function body differs from source lock')
        bodies.append(match[0])
    license_text = source[:source.index('*/')+2]
    prelude = '''
extern unsigned int LOS_GetCurrProcessID(void);
extern int LOS_GetUserID(void);
extern int LOS_GetGroupID(void);
extern int LOS_GetProcessGroupID(unsigned int pid);
'''
    generated = license_text+prelude+'\n\n'.join(bodies)+'\n'
    identity = {'source': lock, 'license': license_text, 'generated_source_sha256': digest(generated.encode()),
                'type_contract': 'int and unsigned int are 32-bit; exact syscall bodies; explicit ordered dependency models'}
    return generated, identity


def export_live_identity(args, observations, transcript, kernel_image_hash):
    calls, events = decode_identity(observations, transcript)
    generated, identity = prepare_source(args.kernel_root)
    metadata = {'format': 'osrec-live-identity-replay-v1', 'source_identity': identity,
                'provenance': 'actual LiteOS-A PID 1 SVC queries with kernel dependency boundary capture',
                'calls': calls, 'dependency_transcript': events, 'modeled_dependencies': list(BOUNDARIES.values()),
                'kernel_image_sha256': kernel_image_hash, 'live_observations_sha256': digest(observations),
                'dependency_transcript_sha256': digest(transcript), 'symbolic_equivalence_verified': False,
                'scheduler_irq_execution': False, 'process_object_discovery': False}
    rows = ',\n'.join('{'+','.join(f'UINT32_C({event[key]})' for key in
                     ('invocation', 'kind', 'argument_bits', 'result_bits'))+'}' for event in events)
    main = '''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
_Static_assert(sizeof(int)==4 && sizeof(unsigned int)==4, "32-bit scalar ABI required");
struct event { uint32_t invocation, kind, argument, raw; };
static const struct event events[] = {@EVENTS@};
static unsigned cursor, invocation;
static uint32_t consume(uint32_t kind,uint32_t argument) {
if(cursor>=sizeof(events)/sizeof(events[0])) exit(1);
const struct event *event=&events[cursor++];
if(event->invocation!=invocation || event->kind!=kind || event->argument!=argument) exit(1);
return event->raw;
}
unsigned int LOS_GetCurrProcessID(void) { return consume(1,0); }
int LOS_GetUserID(void) { return (int32_t)consume(2,0); }
int LOS_GetGroupID(void) { return (int32_t)consume(3,0); }
int LOS_GetProcessGroupID(unsigned int pid) { return (int32_t)consume(4,pid); }
extern int SysGetUserID(void);
extern int SysGetGroupID(void);
extern int SysGetProcessGroupID(unsigned int pid);
int main(int argc,char **argv) {
if(argc==2 && strcmp(argv[1],"--describe")==0) { puts(@METADATA@); return 0; }
if(argc!=1) return 2;
@CHECKS@
if(cursor!=sizeof(events)/sizeof(events[0])) return 1;
puts("identity session verified: 7 calls"); return 0;
}
'''
    checks = []
    for i, call in enumerate(calls):
        if call['number'] == 199:
            expression = 'SysGetUserID()'
        elif call['number'] == 200:
            expression = 'SysGetGroupID()'
        else:
            expression = f'SysGetProcessGroupID(UINT32_C({call["argument_bits"]}))'
        checks.append(f'invocation={i}; if({expression}!={call["raw"]}) return 1;')
    main = main.replace('@EVENTS@', rows).replace('@METADATA@', json.dumps(json.dumps(metadata, sort_keys=True))).replace('@CHECKS@', '\n'.join(checks))
    binary = args.out/'identity-replay'
    # Keep generated sources and the artifact staged until execution consumes all boundaries.
    with tempfile.TemporaryDirectory(prefix='osrec-identity-export-') as stage_name:
        stage = Path(stage_name)
        (stage/'identity.c').write_text(generated)
        (stage/'main.c').write_text(main)
        temporary = stage/'replay'
        subprocess.run(list(map(str, [args.compiler, '-std=c11', '-O0', '-fno-lto', '-Wall', '-Wextra', '-Werror',
                                     stage/'identity.c', stage/'main.c', '-o', temporary])),
                       check=True, capture_output=True, text=True, timeout=60)
        libraries = dependencies(temporary)
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
        result = subprocess.run([str(temporary)], cwd=stage, env=env, check=True, capture_output=True, text=True, timeout=30)
        described = subprocess.run([str(temporary), '--describe'], cwd=stage, env=env, check=True, capture_output=True, text=True, timeout=30)
        if json.loads(described.stdout) != metadata:
            raise ValueError('identity metadata differs')
        source_directory = args.out/'identity.sources'
        source_directory.mkdir()
        for name in ('identity.c', 'main.c'):
            shutil.copy2(stage/name, source_directory/name)
        shutil.copy2(temporary, binary)
    report = {'metadata': metadata, 'artifact_sha256': digest(binary.read_bytes()),
              'artifact_bytes': binary.stat().st_size, 'live_native_observations_match': True,
              'isolated_execution': result.stdout.strip(), 'system_libraries': libraries}
    (args.out/'identity-observations.bin').write_bytes(observations)
    (args.out/'identity-dependencies.bin').write_bytes(transcript)
    (args.out/'identity-replay.manifest.json').write_text(json.dumps(report, indent=2)+'\n')
    return {**report, 'calls': calls, 'modeled_dependencies': metadata['modeled_dependencies']}
