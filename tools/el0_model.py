#!/usr/bin/env python3
"""Load/verify an EL0 executor over GDB and inspect RAM before terminal exit."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import time
import zlib

from audit_el0_image import audit
from check_el0_program import make_load_plan
from el0_gdb import GdbTarget

MAX64=(1<<64)-1
RESULT_NAMES=('magic','version','status','events','expected','transitions','reason','pc','detail','far',
              'counters','uart_bytes','first_mismatch','missing_pc','elapsed','reserved')
REVERSE_BYTES=bytes(int(f'{n:08b}'[::-1],2) for n in range(256))


def sha(data):return hashlib.sha256(data).hexdigest()
def write_json(path,value):Path(path).write_text(json.dumps(value,indent=2)+'\n')


def rsp_crc(data):
    """GDB qCRC: MSB-first IEEE polynomial, initial FFFFFFFF, no final inversion.

    Reverse input bits for zlib's reflected implementation, then undo its final
    inversion and reflect the result. Byte translation and CRC run in C.
    """
    return int(f'{zlib.crc32(data.translate(REVERSE_BYTES))^0xffffffff:032b}'[::-1],2)


def artifact(image,max_memory_bytes=4<<30):
    image=Path(image).resolve();checked=audit(image/'checkpoint')
    raw=(image/'load-plan.json').read_bytes();plan=json.loads(raw)
    if json.dumps(plan,sort_keys=True)!=json.dumps(make_load_plan(checked),sort_keys=True):
        raise ValueError('load plan differs from audited executable')
    regions=sorted(checked['load_segments'],key=lambda s:s['address'])
    if not regions or sum(s['memory_bytes'] for s in regions)>max_memory_bytes:
        raise ValueError('image exceeds configured memory budget')
    end=0
    for segment in regions:
        at=segment['address'];size=segment['memory_bytes']
        if not size or at<end or at+size>1<<64 or segment['flags']&3==3:
            raise ValueError('overlapping, invalid or writable-executable load segment')
        end=at+size
    def contains(address,size,flags,file_backed=False):
        return any(s['flags']&flags==flags and s['address']<=address and
                   address+size<=s['address']+s['file_bytes' if file_backed else 'memory_bytes'] for s in regions)
    entry=int(plan['entry'],0);stop=int(plan['stop_before_optional_exit'],0);result=plan['result']
    if (not contains(entry,4,1,True) or not contains(stop,8,1,True) or result['bytes']!=320 or
            not contains(int(result['address'],0),320,2)):
        raise ValueError('entry, completion or result outside admitted segments')
    return checked,plan,sha(raw)


def initial_blocks(binary,segments,chunk_bytes=1<<20):
    """Every file-backed byte and zero-filled tail; bounded allocations."""
    with Path(binary).open('rb') as stream:
        for s in sorted(segments,key=lambda v:v['address']):
            stream.seek(s['file_offset'])
            for offset in range(0,s['file_bytes'],chunk_bytes):
                count=min(chunk_bytes,s['file_bytes']-offset);data=stream.read(count)
                if len(data)!=count:raise ValueError('ELF changed or truncated during loading')
                yield s['address']+offset,data,'file'
            for offset in range(s['file_bytes'],s['memory_bytes'],chunk_bytes):
                yield s['address']+offset,bytes(min(chunk_bytes,s['memory_bytes']-offset)),'zero'


def initialize(target,binary,segments,load,method,progress=None):
    if method not in ('bytes','crc32'):raise ValueError('unknown initial memory check')
    segments=tuple(segments);expected_bytes=sum(s['memory_bytes'] for s in segments)
    total=written=zero=0;digest=hashlib.sha256();next_progress=64<<20
    for address,data,kind in initial_blocks(binary,segments):
        if load:target.write(address,data);written+=len(data)
        if method=='crc32':
            if target.crc32(address,len(data))!=rsp_crc(data):
                raise ValueError('initial memory CRC mismatch at '+hex(address))
        else:
            if target.read(address,len(data))!=data:raise ValueError('initial memory bytes differ at '+hex(address))
        digest.update(struct.pack('<QQ',address,len(data)));digest.update(data)
        total+=len(data);zero+=len(data) if kind=='zero' else 0
        if progress is not None and (total>=next_progress or total==expected_bytes):
            progress(total,expected_bytes);next_progress=total+(64<<20)
    return dict(method=method,verified_bytes=total,zero_tail_bytes=zero,written_bytes=written,
                exact_byte_comparison=method=='bytes',expected_memory_sha256=digest.hexdigest(),
                scope='every PT_LOAD file byte and memory tail; gaps between segments excluded')


def cpu_state(target,pc=None):
    state=dict(pc=target.register('pc'),pstate=target.register(target.pstate),x0=target.register('x0'))
    if pc is not None and state['pc']!=pc:raise ValueError('target PC differs from required boundary')
    if state['pstate']&31 or state['pstate']&(3<<20):
        raise ValueError('target must be AArch64 EL0t with IL/SS clear')
    return state


def decode_result(raw):
    if len(raw)!=320:raise ValueError('incomplete EL0 result record')
    words=struct.unpack('<40Q',raw);result=dict(zip(RESULT_NAMES,words[:16]));result['debug']=list(words[16:])
    if (result['magic']!=0x324c55464652534f or result['version']!=2 or result['status']!=1 or
            result['reason']!=1 or not result['expected'] or result['events']<result['expected'] or
            not result['transitions'] or result['first_mismatch']!=MAX64 or result['missing_pc']):
        raise ValueError('EL0 computation/result validation failed: '+json.dumps(result))
    return result


def run(image,out,port,host='127.0.0.1',preloaded=False,memory_check='bytes',timeout=120,
        label='GDB target',max_memory_bytes=4<<30,target_factory=GdbTarget,progress=None):
    # Complete offline admission before connecting to or mutating a target.
    if not math.isfinite(timeout) or timeout<=0 or not 0<port<65536 or max_memory_bytes<=0:
        raise ValueError('invalid runner limits')
    checked,plan,plan_hash=artifact(image,max_memory_bytes)
    image=Path(image).resolve();out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
    started=time.monotonic();target=None;armed=running=False;stage='connect'
    report=dict(format='osrec-el0-model-verification-v1',verified=False,label=label,
                image_sha256=checked['image_sha256'],load_plan_sha256=plan_hash,
                el0_interval_verified=False,rtl_execution_verified=False,
                cycles_verified=False,instruction_count=None,cycle_count=None,
                scope='GDB-observed initialization, EL0 boundaries and embedded functional checks',
                cpu_fields_checked=['PC','PSTATE.M','PSTATE.IL','PSTATE.SS','completion X0'],
                platform_controls_verified=False,memory_type_verified=False,
                execution_interval='ELF entry through completion; includes startup, adaptation and validation',
                privileged_bootstrap=False,terminal_exit_executed_before_observation=None)
    write_json(out/'load-plan.json',plan)
    stop=int(plan['stop_before_optional_exit'],0)
    try:
        target=target_factory(port,host,timeout);stage='entry'
        reply=target.request('?')
        if not reply.startswith(('T00','S00','T02','S02','T05','S05')):
            raise ValueError('target must be halted at reset or by debugger control before loading')
        cpu_state(target)
        if preloaded:cpu_state(target,int(plan['entry'],0))
        stage='initial-memory'
        report['initial_memory']=initialize(target,image/'checkpoint',checked['load_segments'],not preloaded,memory_check,progress)
        if sha((image/'checkpoint').read_bytes())!=checked['image_sha256']:
            raise ValueError('ELF changed during initialization')
        if not preloaded:target.set_pc(int(plan['entry'],0))
        entry=cpu_state(target,int(plan['entry'],0));write_json(out/'entry.json',entry)
        if target.read(int(plan['result']['address'],0),320)!=bytes(320):
            raise ValueError('initial result record is not clear')
        stage='execution';target.breakpoint(stop);armed=True;running=True
        then=time.monotonic();target.resume();observed=target.wait(timeout);running=False
        report['execution_wall_seconds']=round(time.monotonic()-then,6)
        if observed!=stop:raise ValueError('unexpected model stop at '+hex(observed))
        terminal=cpu_state(target,stop);write_json(out/'completion.json',terminal)
        report['terminal_exit_executed_before_observation']=False
        raw=target.read(int(plan['result']['address'],0),320);(out/'result.bin').write_bytes(raw)
        stage='result';result=decode_result(raw)
        if terminal['x0']!=0:raise ValueError('executor returned a nonzero result')
        report.update(verified=True,result=result,completion_pc=hex(stop),execution_level=0,
                      result_sha256=sha(raw),preloaded=preloaded)
    except Exception as error:
        report.update(error=str(error),failed_stage=stage)
    finally:
        if target is not None:
            try:
                target.timeout=min(2,getattr(target,'timeout',2))
                if running and getattr(target,'execution_state',None) not in ('halted','exited'):
                    target.interrupt();running=False
                if armed and getattr(target,'execution_state',None)!='exited':target.breakpoint(stop,False)
            except Exception as error:
                if report['verified']:report['failed_stage']='cleanup'
                report['cleanup_error']=str(error);report['verified']=False
            if hasattr(target,'last_stop_reply'):report['execution_stop_reply']=target.last_stop_reply
            if hasattr(target,'execution_state'):report['target_execution_state']=target.execution_state
            try:target.close()
            except Exception as error:
                if report['verified']:report['failed_stage']='cleanup'
                report['cleanup_error']=str(error);report['verified']=False
        report['evidence_files']=[dict(file=name,sha256=sha((out/name).read_bytes()))
                                  for name in ('load-plan.json','entry.json','completion.json','result.bin') if (out/name).is_file()]
        report['wall_seconds']=round(time.monotonic()-started,6)
        write_json(out/'verification.json',report)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--port',type=int,required=True);parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--preloaded',action='store_true',help='verify model-loaded segments; write no RAM or registers')
    parser.add_argument('--memory-check',choices=('bytes','crc32'),default='bytes')
    parser.add_argument('--timeout',type=float,default=120);parser.add_argument('--label',default='GDB target')
    parser.add_argument('--max-memory-bytes',type=lambda v:int(v,0),default=4<<30)
    args=parser.parse_args()
    def progress(done,total):print(f'Initial RAM checked: {done}/{total} bytes ({args.memory_check})',file=sys.stderr,flush=True)
    try:report=run(**vars(args),progress=progress)
    except (ValueError,OSError) as error:parser.exit(1,str(error)+'\n')
    print(json.dumps({k:report[k] for k in ('verified','completion_pc','failed_stage','error','cleanup_error') if k in report},indent=2))
    if not report['verified']:raise SystemExit(1)


if __name__=='__main__':main()
