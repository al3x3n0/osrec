#!/usr/bin/env python3
"""Audit and validate an EL0-only RAM-backed native checkpoint.

A separate Linux validation process observes exec entry and the first syscall,
which must be terminal exit, and reads the image's completed RAM result there.
The observer is a host tool and is never linked into the delivery image.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import time

from kernel_source_verify import Elf
from source_image_el0 import instruction_ranges


def audit(binary,full=False):
    image=Elf(binary);data=image.data
    if struct.unpack_from('<HH',data,16)!=(2,183):raise ValueError('requires an arm64 ET_EXEC')
    symbols={s['name']:s for s in image.symbols if s['shndx']}
    if any(s['name'] and not s['shndx'] for s in image.symbols):raise ValueError('unresolved image dependency')
    if any(s['type']==6 for s in image.symbols):raise ValueError('TLS dependency')
    phoff,=struct.unpack_from('<Q',data,32);stride,count=struct.unpack_from('<HH',data,54)
    loads=[]
    for i in range(count):
        kind,flags,off,va,pa,size,mem,align=struct.unpack_from('<IIQQQQQQ',data,phoff+i*stride)
        if kind in (2,3,7):raise ValueError('dynamic loader or TLS dependency')
        if kind==1:
            if va!=pa or off+size>len(data) or size>mem:raise ValueError('invalid flat ELF load')
            loads.append(dict(address=va,file_offset=off,file_bytes=size,memory_bytes=mem,flags=flags))
    entry,=struct.unpack_from('<Q',data,24)
    if entry!=symbols['_start']['value']:raise ValueError('incorrect entry')
    end=symbols['flat_completed']['value'];exit_pc=end+4
    if struct.unpack('<I',image.read(end,4))[0]!=0xd2800ba8:raise ValueError('terminal exit must select syscall 93')
    ranges=[(s['addr'],s['addr']+s['size']) for s in image.sections if s['flags']&4 and s['size']]
    if max(hi for lo,hi in ranges)-min(lo for lo,hi in ranges)>=1<<27:
        raise ValueError('code span permits branch veneers that could clobber guest registers')
    allowed={0xda10,0xda20,0xda21};exit_sites=[];system=[];instructions=0
    for lo,hi in instruction_ranges(image,ranges):
        for pc in range(lo,hi,4):
            word,=struct.unpack('<I',image.read(pc,4));instructions+=1
            trap=word&0xffe0001f
            if trap in (0xd4000001,0xd4000002,0xd4000003,0xd4200000,0xd4400000):
                if word!=0xd4000001 or pc!=exit_pc:raise ValueError('unexpected trap/service instruction at '+hex(pc))
                exit_sites.append(pc)
            if word&0xffff0000==0xd69f0000:raise ValueError('privileged exception return')
            if word&0xff000000!=0xd5000000:continue
            family=word&0xfff00000
            if family in (0xd5300000,0xd5100000):
                key=word>>5&65535
                if key not in allowed:raise ValueError('privileged/non-RAM system register at '+hex(pc))
                system.append(key)
            elif word not in (0xd503201f,0xd503203f,0xd503229f,0xd503241f,0xd503245f,0xd503249f,0xd50324df) and\
                 word&0xfffff0ff not in (0xd50330bf,0xd503309f,0xd50330df,0xd503305f):
                raise ValueError('unsupported system instruction at '+hex(pc))
    if exit_sites!=[exit_pc]:raise ValueError('exactly one terminal exit required')
    if not full:
        atomic=symbols['umask_atomic_body']['value']
        expected=(0xf9800111,0x885f7d0b,0x880afd09,0x35ffffca,0xd5033bbf)
        if struct.unpack('<5I',image.read(atomic,20))!=expected:raise ValueError('original exclusive sequence was changed')
    result=symbols['flat_full_result' if full else 'flat_result']
    return dict(image_sha256=hashlib.sha256(data).hexdigest(),image_bytes=len(data),entry=hex(entry),terminal_pc=hex(end),
                result_address=hex(result['value']),result_bytes=result['size'],
                load_segments=loads,runtime_el=0,libc=False,tls=False,undefined_symbols=0,
                instructions= instructions,terminal_exit_sites=[hex(exit_pc)],
                system_registers=sorted(set(map(hex,system))),exclusive_sequence_intact=None if full else True,
                real_mmio=False,host_signals=False)


def run(image,out,timeout=60,observer=None):
    image,out=Path(image).resolve(),Path(out).resolve();binary=image/'checkpoint';checked=audit(binary)
    observer=Path(observer or os.environ.get('OSREC_FLAT_OBSERVER',Path(__file__).resolve().parents[1]/'build/el0-flat/flat-observe')).resolve()
    if not observer.is_file():raise ValueError('build the Linux validation observer first')
    out.mkdir(parents=True,exist_ok=False)
    command=['docker','run','--rm','--network','none','--read-only','--cap-add','SYS_PTRACE',
             '--mount','type=bind,src='+str(binary)+',dst=/checkpoint,readonly',
             '--mount','type=bind,src='+str(observer)+',dst=/observer,readonly',
             '--entrypoint','/observer','alpine:3','/checkpoint',checked['result_address']]
    started=time.monotonic();observed=subprocess.run(command,capture_output=True,text=True,timeout=timeout)
    (out/'observer.stdout').write_text(observed.stdout);(out/'observer.stderr').write_text(observed.stderr)
    if observed.returncode:raise ValueError('native EL0 validation failed: '+observed.stderr)
    execution=json.loads(observed.stdout)
    if execution['entry_pc']!=int(checked['entry'],0) or execution['exit_pc']!=int(checked['terminal_pc'],0)+8:
        raise ValueError('image entry/terminal address differs')
    values=execution.pop('words')
    names=('magic','version','status','calls','gateway_checks','transitions','reason','pc','detail','far',
           'initial_mask','final_mask','fault_checks','failure','reserved1','reserved2')
    result=dict(zip(names,values[:16]));calls=[dict(zip(('input','returned','mask','pc'),values[16+i*4:20+i*4])) for i in range(6)]
    (out/'result.bin').write_bytes(struct.pack('<40Q',*values))
    report=dict(checked,result=result,calls=calls,verified=result['status']==1,execution=execution,
                observation='native arm64 Linux EL0; stopped at exec entry and first syscall (terminal exit) only',
                host_calls_observed=1,host_calls_before_terminal_exit=0,
                seconds=round(time.monotonic()-started,3),rtl_execution_verified=False,cycle_accuracy_verified=False)
    (out/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
    if result['status']!=1 or result['calls']!=6 or result['gateway_checks']!=1 or result['fault_checks']!=1 or execution['exit_status']:
        raise ValueError('EL0 checkpoint failed: '+json.dumps(result))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',required=True);p.add_argument('--out',required=True)
    p.add_argument('--timeout',type=int,default=60)
    p.add_argument('--observer',help='separate native Linux validation tool')
    a=p.parse_args();r=run(a.image,a.out,a.timeout,a.observer)
    print(json.dumps(dict(verified=r['verified'],runtime_el=r['runtime_el'],calls=r['result']['calls'],exclusive_sequence=r['exclusive_sequence_intact'])))
