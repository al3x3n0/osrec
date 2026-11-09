#!/usr/bin/env python3
"""Run a memory-only monitor checkpoint; observe only its terminal boundary.

QEMU is a functional test of the model-loading contract, not RTL timing evidence.
No syscall-result/counter breakpoints or runtime host services drive the guest.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time

from gdb_remote import Remote
from kernel_boundary_capture import physical
from svc_boundary import free_port
from source_image import compare

RESULT_FIELDS=('magic','version','status','reason','pc','detail','far','events','expected_events',
               'counters','expected_counters','first_mismatch','measurement_started','measurement_finished','reserved0','reserved1')


def run(image,out,oracle=None,timeout=90,elf=None,success=True,code_log=None):
    image,out=Path(image).resolve(),Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
    plan=json.loads((image/'load-plan.json').read_text());binary=Path(elf).resolve() if elf else image/'image.elf'
    if not elf and hashlib.sha256(binary.read_bytes()).hexdigest()!=plan['image_sha256']:raise ValueError('image differs from load plan')
    port=free_port()
    command=['qemu-system-aarch64','-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53','-accel','tcg',
             '-smp','1','-m','1024M','-nodefaults','-display','none','-monitor','none',
             '-serial','file:'+str(out/'uart.bin'),'-semihosting-config','enable=off',
             '-device','loader,file='+str(binary)+',cpu-num=0','-S','-gdb','tcp:127.0.0.1:'+str(port)]
    if code_log:command+=['-d','in_asm','-D',str(Path(code_log).resolve())]
    start=time.monotonic();remote=None
    with (out/'qemu.stderr.log').open('wb') as err:
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=err)
        try:
            remote=Remote(port,timeout=timeout)
            if remote.register('pc')!=int(plan['entry'],0):raise ValueError('model did not start at image entry')
            remote.breakpoint(int(plan['stop'],0));remote.resume();stopped=remote.wait(timeout)
            if stopped!=int(plan['stop'],0):raise ValueError('unexpected model stop at '+hex(stopped))
            physical(remote,True)
            result=dict(zip(RESULT_FIELDS,struct.unpack('<16Q',remote.read(int(plan['result']['physical_address'],0),128))))
            if result['magic']!=0x31544c555345524f or result['version']!=1:raise ValueError('invalid RAM result record')
            if result['events']>plan['trace']['capacity']:raise ValueError('invalid RAM event count')
            raw=remote.read(int(plan['trace']['physical_address'],0),result['events']*80)
            physical(remote,False)
        finally:
            if remote:remote.socket.close()
            process.terminate();process.wait(timeout=10)
    events=[]
    for exception,number,*rest in struct.iter_unpack('<10Q',raw):
        args=rest[:6];value,completed=rest[6:]
        row=dict(number=-1 if exception else number,arguments=args[:3] if exception else args,result=value if completed else None)
        if exception:row['event']='exception'
        events.append(row)
    trace=dict(kind='monitor-checkpoint',calls=events,end=dict(stop_code=result['reason'],pc=hex(result['pc'])),
               counters_consumed=result['counters'])
    (out/'calls.json').write_text(json.dumps(trace,indent=2)+'\n')
    uart=(out/'uart.bin').read_bytes();uart_match=uart==(image/'expected-uart.bin').read_bytes()
    comparison=compare(Path(oracle)/'calls.json',out/'calls.json') if oracle else None
    okay=result['status']==1 and uart_match and (comparison is None or comparison['matches'])
    if (result['status']==1)!=success:raise ValueError('unexpected RAM verification status: '+json.dumps(result))
    if success and not okay:raise ValueError('monitor execution/UART differs from oracle: '+json.dumps(dict(result=result,uart_match=uart_match,comparison=comparison)))
    report=dict(verified=okay,result=result,uart_matches=uart_match,oracle_comparison=comparison,
                image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),seconds=round(time.monotonic()-start,3),
                runtime_host_calls=False,semihosting=False,debugger_observation='entry and terminal boundary only; no per-event intervention',
                functional_model='QEMU cortex-a53',rtl_execution_verified=False,cycle_accuracy_verified=False)
    (out/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',required=True);p.add_argument('--oracle');p.add_argument('--out',required=True)
    p.add_argument('--timeout',type=int,default=90)
    p.add_argument('--code-log',help='optional translated-code listing, for conservative AOT coverage only')
    a=p.parse_args();r=run(a.image,a.out,a.oracle,a.timeout,code_log=a.code_log)
    print(json.dumps(dict(verified=r['verified'],events=r['result']['events'],counters=r['result']['counters'],uart=r['uart_matches'])))
