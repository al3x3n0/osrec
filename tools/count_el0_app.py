#!/usr/bin/env python3
"""Run the EL0 native checkpoint in QEMU Linux application mode and count it.

One-instruction translation blocks expose every dynamic guest instruction. Counts
are functional instruction counts, not cycles or original-kernel timing claims.
"""
import argparse
import gzip
import json
from pathlib import Path
import re
import subprocess

from check_el0_flat import audit
from kernel_source_verify import Elf

ROOT=Path(__file__).resolve().parents[1]


def count_trace(path,begin,end,ranges):
    translated=set();block=[];total=native=inside=inside_native=0
    starts=ends=0;active=False;intervals=[];first=last=None
    opener=gzip.open if str(path).endswith('.gz') else open
    with opener(path,'rt') as stream:
        for raw in stream:
            line=raw.strip()
            if line.startswith('IN:'):
                if block:raise ValueError('translated block lacks execution trace')
                continue
            instruction=re.match(r'^0x([0-9a-fA-F]+):',line)
            if instruction:
                block.append(int(instruction[1],16));continue
            execution=re.match(r'^Trace \d+:.*\[([0-9a-fA-F]+)/([0-9a-fA-F]+)/',line)
            if not execution:continue
            if block:
                if len(block)!=1:raise ValueError('QEMU translated more than one instruction per block')
                translated.add(block[0]);block=[]
            pc=int(execution[2],16)
            if pc not in translated:raise ValueError('execution without a single-instruction translation record')
            if first is None:first=pc
            last=pc;total+=1
            original=any(lo<=pc<lo+size for lo,size in ranges)
            native+=original
            if pc==end and active:
                intervals.append(dict(instructions=inside,native_kernel_instructions=inside_native));ends+=1;active=False
            if pc==begin:
                if active:raise ValueError('nested counting interval')
                active=True;inside=inside_native=0;starts+=1
            if active:inside+=1;inside_native+=original
    if block:raise ValueError('unexecuted final translation record')
    return dict(instructions=total,native_kernel_instructions=native,begin_hits=starts,end_hits=ends,
                complete=not active and starts==ends,intervals=intervals,
                first_pc=hex(first) if first is not None else None,last_pc=hex(last) if last is not None else None,
                translated_instruction_addresses=len(translated))


def run(image,out,docker_image='osrec-qemu-user:20261109'):
    image,out=Path(image).resolve(),Path(out).resolve();binary=image/'checkpoint'
    checked=audit(binary);elf=Elf(binary)
    symbols={s['name']:s['value'] for s in elf.symbols if s['shndx']}
    groups=[('entry',3),('load_arg',1),('load_fs',1),('arithmetic',2),('atomic',5),('tail',1)]
    ranges=[(symbols['umask_'+name+'_body'],words*4) for name,words in groups]
    begin,end=symbols['umask_entry_body'],symbols['flat_escape']
    out.mkdir(parents=True,exist_ok=False)
    command=['docker','run','--rm','--network','none','--read-only','--tmpfs','/tmp:rw,size=64m',
             '--mount','type=bind,src='+str(ROOT/'tests/el0_flat_count.S')+',dst=/sanity.S,readonly',
             '--mount','type=bind,src='+str(out)+',dst=/out',docker_image,'sh','-c',
             'clang-19 -nostdlib -static -Wl,-Ttext=0x400000,-e,_start /sanity.S -o /out/sanity && qemu-aarch64 --version']
    built=subprocess.run(command,capture_output=True,text=True,timeout=120)
    (out/'build.log').write_text(built.stdout+built.stderr)
    if built.returncode:raise ValueError('counter reference build failed: '+built.stderr)
    def execute(target,trace):
        cmd=['docker','run','--rm','--network','none','--read-only',
             '--mount','type=bind,src='+str(target)+',dst=/checkpoint,readonly',
             '--mount','type=bind,src='+str(out)+',dst=/out','--entrypoint','qemu-aarch64',docker_image,
             '-cpu','cortex-a53','-one-insn-per-tb','-d','in_asm,exec,nochain','-D','/out/'+trace,'-strace','/checkpoint']
        result=subprocess.run(cmd,capture_output=True,text=True,timeout=180)
        (out/(trace+'.stdout')).write_text(result.stdout);(out/(trace+'.syscalls')).write_text(result.stderr)
        if result.returncode:raise ValueError('QEMU application execution failed: '+result.stderr)
        # With -D, QEMU routes syscall tracing into that log as well.
        with (out/trace).open() as stream:
            calls=[line.strip() for line in stream if re.match(r'^\d+\s+',line)]
        if len(calls)!=1 or not re.fullmatch(r'\d+\s+exit\(0\)',calls[0]):raise ValueError('unexpected guest services: '+result.stderr)
    execute(out/'sanity','sanity-trace.log')
    sanity=Elf(out/'sanity');ss={s['name']:s['value'] for s in sanity.symbols if s['shndx']}
    reference=count_trace(out/'sanity-trace.log',ss['_start'],ss['count_end'],[(ss['count_loop'],ss['count_end']-ss['count_loop'])])
    if not reference['complete'] or reference['instructions']!=20 or reference['native_kernel_instructions']!=15 or reference['intervals']!=[dict(instructions=17,native_kernel_instructions=15)]:
        raise ValueError('dynamic loop counter failed its independent check: '+json.dumps(reference))
    (out/'sanity-counts.json').write_text(json.dumps(reference,indent=2)+'\n')
    execute(binary,'trace.log')
    counts=count_trace(out/'trace.log',begin,end,ranges);intervals=counts['intervals']
    if not counts['complete'] or len(intervals)!=7 or any(i['native_kernel_instructions']<13 for i in intervals[:6]) or intervals[6]['native_kernel_instructions']!=3 or counts['first_pc']!=checked['entry'] or int(counts['last_pc'],0)!=int(checked['terminal_pc'],0)+4:
        raise ValueError('instruction intervals are incomplete: '+json.dumps(counts))
    (out/'counts.json').write_text(json.dumps(counts,indent=2)+'\n')
    # Keep the complete execution evidence without retaining a large text file.
    with (out/'trace.log').open('rb') as source,gzip.open(out/'trace.log.gz','wb') as dest:
        while block:=source.read(1<<20):dest.write(block)
    (out/'trace.log').unlink()
    positive=sum(i['instructions'] for i in intervals[:6]);native=sum(i['native_kernel_instructions'] for i in intervals[:6])
    report=dict(format='osrec-el0-application-instruction-count-v1',verified=True,qemu_mode='Linux user/application mode',
                execution_scope='EL0 gateway bring-up fixture: direct __arm64_sys_umask calls',
                full_checkpoint_executed=False,syscall_entry_and_dispatch_executed=False,user_checkpoint_resumed=False,
                qemu_version=built.stdout.strip(),cpu='cortex-a53',image_sha256=checked['image_sha256'],
                full_program_instructions=counts['instructions'],six_kernel_calls_instructions=positive,
                six_calls_original_kernel_instructions=native,fault_check_instructions=intervals[6]['instructions'],
                startup_gateway_tests_validation_and_other_instructions=counts['instructions']-sum(i['instructions'] for i in intervals),
                intervals=intervals,interval_definition='first native umask instruction through runtime dispatch, stopping before flat_escape restores caller state',
                guest_services=['terminal exit(0)'],host_calls_before_terminal_exit=0,
                counter='QEMU -one-insn-per-tb -d in_asm,exec,nochain; one instruction verified in every translated block',
                counter_sanity_check=reference,trace='trace.log.gz',
                cycles_measured=False,rtl_execution_verified=False)
    (out/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',required=True);p.add_argument('--out',required=True)
    p.add_argument('--docker-image',default='osrec-qemu-user:20261109')
    a=p.parse_args();r=run(a.image,a.out,a.docker_image)
    print(json.dumps({k:r[k] for k in ('verified','qemu_mode','full_program_instructions','six_kernel_calls_instructions','six_calls_original_kernel_instructions','fault_check_instructions')},indent=2))
