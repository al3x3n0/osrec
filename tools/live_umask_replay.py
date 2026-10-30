"""Replay a live SysUmask session with restored entry state and explicit lock/process models."""
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

from klee_liteos import ROOT, digest
from export_sysread import dependencies

MASKS = (0, 0o22, 0xffffffff, 0x80000000, 0o77, 0)
MODEL_HEADER = '''#ifndef OSREC_UMASK_MODEL_H
#define OSREC_UMASK_MODEL_H
#include <stdint.h>
struct osrec_process { uint32_t umask; };
struct osrec_process *OsCurrProcessGet(void);
void OsrecSchedulerLock(uint32_t *saved);
void OsrecSchedulerUnlock(uint32_t saved);
#endif
'''


def decode_umask(user, kernel):
    if len(user) != len(MASKS)*12 or len(kernel) != len(MASKS)*20:
        raise ValueError('umask observation size differs')
    calls = []
    for i, mask in enumerate(MASKS):
        argument, raw, user_mode = struct.unpack_from('<3I', user, i*12)
        kernel_argument, before, kernel_raw, after, kernel_mode = struct.unpack_from('<5I', kernel, i*20)
        if argument != mask or kernel_argument != mask or raw != kernel_raw:
            raise ValueError('umask kernel/user argument or return differs')
        if user_mode != 0x10 or kernel_mode != 0x113:
            raise ValueError('umask user/kernel mode or MMU differs')
        if i and before != calls[-1]['mask_after']:
            raise ValueError('umask state is discontinuous between calls')
        calls.append({'mask_bits': mask, 'mask_before': before, 'raw': raw,
                      'mask_after': after, 'user_mode': user_mode, 'kernel_mode': kernel_mode})
    return calls


def prepare_source(kernel_root):
    lock = json.loads((ROOT/'integrations/liteos_a/umask-source-lock.json').read_text())
    revision = subprocess.check_output(['git', '-C', str(kernel_root), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != lock['revision']:
        raise ValueError('umask kernel revision differs from source lock')
    for root in (kernel_root, ROOT/'build/ohos/kernel/liteos_a'):
        if digest((root/lock['source']).read_bytes()) != lock['source_sha256']:
            raise ValueError('umask source changed')
        for relative, expected in lock['headers'].items():
            if digest((root/relative).read_bytes()) != expected:
                raise ValueError('umask constant, process, lock or dispatch header changed')
    source = (kernel_root/lock['source']).read_text()
    match = re.search(r'mode_t SysUmask\(mode_t mask\)\s*\{.*?\n\}', source, re.DOTALL)
    if not match or digest(match[0].encode()) != lock['function_sha256']:
        raise ValueError('umask body differs from source lock')
    license_text = source[:source.index('*/')+2]
    prelude = '''
#include "umask_model.h"
typedef uint32_t UINT32;
typedef uint32_t mode_t;
#define UMASK_FULL @FULL@
#define SCHEDULER_LOCK(state) OsrecSchedulerLock(&(state))
#define SCHEDULER_UNLOCK(state) OsrecSchedulerUnlock(state)
'''.replace('@FULL@', str(lock['constants']['UMASK_FULL']))
    generated = license_text+prelude+match[0]+'\n'
    identity = {'source': lock, 'license': license_text, 'generated_source_sha256': digest(generated.encode()),
                'model_header_sha256': digest(MODEL_HEADER.encode()), 'type_contract': lock['type_contract']}
    return generated, identity


def driver_source(calls, metadata):
    # Restore only the initial mask. Later snapshots are assertions, never assignments.
    checks = []
    for i, call in enumerate(calls):
        checks.append(f'''if(process.umask!=UINT32_C({call['mask_before']})) return 1;
if(SysUmask(UINT32_C({call['mask_bits']}))!=UINT32_C({call['raw']})) return 1;
if(process.umask!=UINT32_C({call['mask_after']}) || locked || locks!={i+1} || unlocks!={i+1} || accesses!={2*(i+1)}) return 1;''')
    return '''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "umask_model.h"
static struct osrec_process process;
static unsigned locked,locks,unlocks,accesses;
void OsrecSchedulerLock(uint32_t *saved) {
if(locked) exit(1);
*saved=UINT32_C(0x13579bdf); locked=1; ++locks;
}
void OsrecSchedulerUnlock(uint32_t saved) {
if(!locked || saved!=UINT32_C(0x13579bdf)) exit(1);
locked=0; ++unlocks;
}
struct osrec_process *OsCurrProcessGet(void) {
if(!locked) exit(1);
++accesses; return &process;
}
extern uint32_t SysUmask(uint32_t mask);
int main(int argc,char **argv) {
if(argc==2 && strcmp(argv[1],"--describe")==0) { puts(@METADATA@); return 0; }
if(argc!=1) return 2;
process.umask=UINT32_C(@INITIAL@);
@CHECKS@
puts("umask session verified: 6 calls"); return 0;
}
'''.replace('@METADATA@', json.dumps(json.dumps(metadata, sort_keys=True))).replace('@INITIAL@', str(calls[0]['mask_before'])).replace('@CHECKS@', '\n'.join(checks))


def export_live_umask(args, user, kernel, kernel_image_hash):
    calls = decode_umask(user, kernel)
    generated, identity = prepare_source(args.kernel_root)
    metadata = {'format': 'osrec-live-umask-replay-v1', 'root': 'SysUmask', 'source_identity': identity,
                'provenance': 'actual LiteOS-A PID 1 SVC calls with kernel entry/post-call umask capture',
                'checkpoint': {'current_process_umask': calls[0]['mask_before']}, 'calls': calls,
                'modeled_dependencies': ['OsCurrProcessGet', 'SCHEDULER_LOCK', 'SCHEDULER_UNLOCK'],
                'kernel_image_sha256': kernel_image_hash, 'user_observations_sha256': digest(user),
                'kernel_observations_sha256': digest(kernel), 'symbolic_equivalence_verified': False,
                'scheduler_irq_execution': False, 'process_layout': 'semantic umask-only object, not kernel memory layout'}
    main = driver_source(calls, metadata)
    binary = args.out/'umask-replay'
    with tempfile.TemporaryDirectory(prefix='osrec-umask-export-') as stage_name:
        stage = Path(stage_name)
        (stage/'umask.c').write_text(generated)
        (stage/'umask_model.h').write_text(MODEL_HEADER)
        (stage/'main.c').write_text(main)
        temporary = stage/'replay'
        subprocess.run(list(map(str, [args.compiler, '-std=c11', '-O0', '-fno-lto', '-Wall', '-Wextra', '-Werror',
                                     stage/'umask.c', stage/'main.c', '-o', temporary])),
                       check=True, capture_output=True, text=True, timeout=60)
        libraries = dependencies(temporary)
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
        result = subprocess.run([str(temporary)], cwd=stage, env=env, check=True, capture_output=True, text=True, timeout=30)
        described = subprocess.run([str(temporary), '--describe'], cwd=stage, env=env, check=True, capture_output=True, text=True, timeout=30)
        if json.loads(described.stdout) != metadata:
            raise ValueError('umask metadata differs')
        source_directory = args.out/'umask.sources'
        source_directory.mkdir()
        for name in ('umask.c', 'umask_model.h', 'main.c'):
            shutil.copy2(stage/name, source_directory/name)
        shutil.copy2(temporary, binary)
    report = {'metadata': metadata, 'artifact_sha256': digest(binary.read_bytes()),
              'artifact_bytes': binary.stat().st_size, 'live_native_observations_match': True,
              'isolated_execution': result.stdout.strip(), 'system_libraries': libraries}
    (args.out/'umask-user-observations.bin').write_bytes(user)
    (args.out/'umask-kernel-observations.bin').write_bytes(kernel)
    (args.out/'umask-replay.manifest.json').write_text(json.dumps(report, indent=2)+'\n')
    return {**report, 'calls': calls, 'modeled_dependencies': metadata['modeled_dependencies']}
