"""Build a complete scheduler priority-limit replay from live SVC observations."""
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

from klee_liteos import ROOT, digest
from export_sysread import dependencies


def export_live_priority(args, observations, kernel_image_hash, function="SysSchedGetPriorityMax"):
    if function not in ('SysSchedGetPriorityMax', 'SysSchedGetPriorityMin'):
        raise ValueError('unsupported priority function')
    minimum = function == "SysSchedGetPriorityMin"
    prefix = "priority-min" if minimum else "priority"
    if len(observations)!=36:
        raise ValueError('priority observation size differs')
    calls=[]
    for i,expected_policy in enumerate((2,1,0xffffffff)):
        policy,raw,mode=struct.unpack_from('<3I',observations,i*12)
        if policy!=expected_policy or mode!=0x10:
            raise ValueError('priority call argument or user mode differs')
        signed=lambda value:value if value<0x80000000 else value-0x100000000
        calls.append({'policy_bits':policy,'raw':signed(raw),'user_mode':mode})
    source=args.out/(prefix+'.sources')
    command=[sys.executable,ROOT/'tools/prepare_priority_el0.py','--kernel-root',args.kernel_root,
             '--llvm-bin',args.llvm_bin,'--out',source,'--function',function]
    subprocess.run(list(map(str,command)),check=True,capture_output=True,text=True,timeout=60)
    identity=json.loads((source/'source-identity.json').read_text())
    # Check the actual booted kernel source against the same reviewed lock.
    lock=identity['source']
    live=ROOT/'build/ohos/kernel/liteos_a'
    if digest((live/lock['source']).read_bytes())!=lock['source_sha256']:
        raise ValueError('live priority implementation differs from replay source')
    for relative,expected in lock['headers'].items():
        if digest((live/relative).read_bytes())!=expected:
            raise ValueError('live priority constants differ from replay source')
    metadata={'format':'osrec-live-priority-replay-v1','root':function,
              'provenance':'actual LiteOS-A PID 1 SVC calls captured through report driver',
              'source_identity':identity,'calls':calls,'kernel_image_sha256':kernel_image_hash,
              'live_observations_sha256':digest(observations),'modeled_dependencies':[],
              'scheduler_irq_execution':False}
    # Embed the captured arguments/results, not a return-value replacement.
    lines=['#include <stdint.h>','#include <stdio.h>','#include <string.h>',
           f'extern int {function}(int policy);','int main(int argc,char **argv) {',
           'if(argc==2 && strcmp(argv[1],"--describe")==0) { puts('
           +json.dumps(json.dumps(metadata,sort_keys=True))+'); return 0; }',
           '(void)argv; if(argc!=1) return 2;']
    for call in calls:
        lines.append(f'if({function}((int32_t)UINT32_C({call["policy_bits"]})) != {call["raw"]}) return 1;')
    lines+=['puts("priority session verified: 3 calls"); return 0;','}']
    (source/'main.c').write_text('\n'.join(lines)+'\n')
    binary=args.out/(prefix+'-replay')
    with tempfile.TemporaryDirectory(prefix='osrec-priority-export-') as stage:
        temporary=Path(stage)/'replay'
        command=[args.compiler,'-std=c11','-O0','-fno-lto','-Wall','-Wextra','-Werror',
                 source/'sched_priority.c',source/'main.c','-o',temporary]
        subprocess.run(list(map(str,command)),check=True,capture_output=True,text=True,timeout=60)
        libraries=dependencies(temporary)
        environment={'PATH':'/usr/bin:/bin','LC_ALL':'C'}
        result=subprocess.run([str(temporary)],cwd=stage,env=environment,check=True,capture_output=True,text=True,timeout=30)
        described=subprocess.run([str(temporary),'--describe'],cwd=stage,env=environment,check=True,capture_output=True,text=True,timeout=30)
        if json.loads(described.stdout)!=metadata:
            raise ValueError('priority metadata differs')
        shutil.copy2(temporary,binary)
    report={'metadata':metadata,'artifact_sha256':digest(binary.read_bytes()),
            'artifact_bytes':binary.stat().st_size,'live_native_observations_match':True,
            'isolated_execution':result.stdout.strip(),'system_libraries':libraries}
    (args.out/(prefix+'-observations.bin')).write_bytes(observations)
    (args.out/(prefix+'-replay.manifest.json')).write_text(json.dumps(report,indent=2)+'\n')
    return {'calls':calls,'live_native_observations_match':True,'modeled_dependencies':[],
            'artifact_sha256':report['artifact_sha256'],'observations_sha256':digest(observations),
            'isolated_execution':report['isolated_execution']}
