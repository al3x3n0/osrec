"""Replay the pinned SysGetPID body with an explicit captured process-ID model."""
import json
import re
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

from klee_liteos import ROOT, digest
from export_sysread import dependencies


def export_live_pid(args, observations, kernel_image_hash, owner):
    if len(observations) != 8:
        raise ValueError('PID observation size differs')
    pid, mode = struct.unpack('<2I', observations)
    if pid != owner or not 0 < pid <= 0xffffffff or mode != 0x10:
        raise ValueError('PID observation differs from capture owner or user mode')
    lock = json.loads((ROOT/'integrations/liteos_a/getpid-source-lock.json').read_text())
    revision = subprocess.check_output(['git', '-C', str(args.kernel_root), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != lock['revision']:
        raise ValueError('PID kernel revision differs from source lock')
    raw = (args.kernel_root/lock['source']).read_bytes()
    if digest(raw) != lock['source_sha256']:
        raise ValueError('PID source changed')
    live = ROOT/'build/ohos/kernel/liteos_a'
    for root in (args.kernel_root, live):
        if digest((root/lock['source']).read_bytes()) != lock['source_sha256']:
            raise ValueError('live PID source differs from replay source')
        for relative, expected in lock['headers'].items():
            if digest((root/relative).read_bytes()) != expected:
                raise ValueError('PID dependency declaration header changed')
    source = raw.decode()
    match = re.search(r'unsigned int SysGetPID\(void\)\s*\{.*?\n\}', source, re.DOTALL)
    if not match or digest(match[0].encode()) != lock['function_sha256']:
        raise ValueError('PID body differs from source lock')
    license_text = source[:source.index('*/')+2]
    generated = license_text+'\nextern unsigned int LOS_GetCurrProcessID(void);\n'+match[0]+'\n'
    identity = {'source': lock, 'license': license_text, 'generated_source_sha256': digest(generated.encode()),
                'type_contract': 'unsigned int is 32-bit; exact syscall body; captured process-ID dependency model'}
    metadata = {'format': 'osrec-live-pid-replay-v1', 'root': 'SysGetPID', 'source_identity': identity,
                'provenance': 'actual LiteOS-A PID 1 SVC call captured through report driver',
                'checkpoint': {'current_process_id': owner}, 'calls': [{'raw': pid, 'user_mode': mode}],
                'modeled_dependencies': ['LOS_GetCurrProcessID'], 'scheduler_irq_execution': False,
                'symbolic_equivalence_verified': False, 'kernel_image_sha256': kernel_image_hash,
                'live_observations_sha256': digest(observations)}
    directory = args.out/'pid.sources'
    directory.mkdir()
    (directory/'getpid.c').write_text(generated)
    # The model restores the entry PID; expected return is used only for comparison.
    main = '''#include <stdint.h>
#include <stdio.h>
#include <string.h>
_Static_assert(sizeof(unsigned int)==4, "32-bit PID ABI required");
static unsigned int current_process_id;
static unsigned int dependency_calls;
unsigned int LOS_GetCurrProcessID(void) { ++dependency_calls; return current_process_id; }
extern unsigned int SysGetPID(void);
int main(int argc, char **argv) {
if(argc==2 && strcmp(argv[1],"--describe")==0) { puts(@METADATA@); return 0; }
if(argc!=1) return 2;
current_process_id=UINT32_C(@OWNER@);
if(SysGetPID()!=UINT32_C(@PID@) || dependency_calls!=1) return 1;
puts("PID session verified: 1 call"); return 0;
}
'''.replace('@METADATA@', json.dumps(json.dumps(metadata, sort_keys=True))).replace('@OWNER@', str(owner)).replace('@PID@', str(pid))
    (directory/'main.c').write_text(main)
    binary = args.out/'pid-replay'
    with tempfile.TemporaryDirectory(prefix='osrec-pid-export-') as stage:
        temporary = Path(stage)/'replay'
        subprocess.run(list(map(str, [args.compiler, '-std=c11', '-O0', '-fno-lto', '-Wall', '-Wextra', '-Werror',
                                     directory/'getpid.c', directory/'main.c', '-o', temporary])),
                       check=True, capture_output=True, text=True, timeout=60)
        libraries = dependencies(temporary)
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
        result = subprocess.run([str(temporary)], cwd=stage, env=env, check=True, capture_output=True, text=True, timeout=30)
        described = subprocess.run([str(temporary), '--describe'], cwd=stage, env=env, check=True, capture_output=True, text=True, timeout=30)
        if json.loads(described.stdout) != metadata:
            raise ValueError('PID metadata differs')
        shutil.copy2(temporary, binary)
    report = {'metadata': metadata, 'artifact_sha256': digest(binary.read_bytes()),
              'artifact_bytes': binary.stat().st_size, 'live_native_observations_match': True,
              'isolated_execution': result.stdout.strip(), 'system_libraries': libraries}
    (args.out/'pid-observations.bin').write_bytes(observations)
    (args.out/'pid-replay.manifest.json').write_text(json.dumps(report, indent=2)+'\n')
    return {**report, 'calls': metadata['calls'], 'modeled_dependencies': metadata['modeled_dependencies']}
