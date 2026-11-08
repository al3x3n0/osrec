#!/usr/bin/env python3
"""Dump the kernel's post-boot state at a selected SVC entry: all guest RAM plus the CPU state.

The full-machine checkpoint resumes under a gdbstub; the run stops at the synchronous lower-EL vector for the
selected call (as kernel_boundary_capture.py step 1). There, QMP `pmemsave` writes guest RAM (QEMU virt: RAM at
0x40000000, size from the recipe's -m) and the EL1 system registers, general-purpose and FP/SIMD registers are
recorded. This is the source the typed state walk (kernel_state_graph.py) reads; nothing here is kernel-specific
beyond the SVC contract.

Output: <out>/ram.bin, <out>/state.json.
"""
import argparse,hashlib,json,os
from pathlib import Path
from gdb_remote import Remote
import qemu_vm_checkpoint as machine
from svc_boundary import validate_contract,free_port
from kernel_boundary_capture import GPRS,SYSREGS

ROOT=Path(__file__).resolve().parents[1];FORMAT='osrec-kernel-state-dump-v1';RAM_BASE=0x40000000


def ram_size(spec):
    value=spec['arguments'][spec['arguments'].index('-m')+1]
    units={'K':1<<10,'M':1<<20,'G':1<<30}
    return int(value[:-1])*units[value[-1]] if value[-1] in units else int(value)<<20


def dump(checkpoint,contract,select,out,occurrence=1,timeout=300):
    checkpoint=Path(checkpoint).resolve();out=Path(out).resolve()
    if out.exists():raise FileExistsError(out)
    spec=machine.verify(checkpoint);c=validate_contract(json.loads(Path(contract).read_text()));out.mkdir(parents=True)
    size=ram_size(spec);port=free_port()
    with machine.Machine(checkpoint,'dump',incoming=True,timeout=timeout,execution_dir=out,observer=('-gdb','tcp:127.0.0.1:%d'%port)) as m:
        m.request('migrate-incoming',dict(uri='file:'+str(checkpoint/'vmstate.bin')));m.migration_complete()
        r=Remote(port,timeout=timeout);vbar=r.register(c['entry']['vector_base_register']);sync=vbar+c['entry']['synchronous_vector_offset']
        r.breakpoint(sync);r.resume();os.write(m.serial_in,spec['protocol']['continue_line'].encode());seen=0
        while True:
            pc=r.wait(timeout)
            if pc!=sync:raise ValueError('unexpected stop at 0x%x'%pc)
            regs=r.registers(GPRS);syndrome=r.register(c['entry']['syndrome_register'])
            call=dict(number=regs[c['number_register']],**{k:regs[k] for k in c['argument_registers']})
            if syndrome>>26==c['entry']['syndrome_class'] and all(call[k]==v for k,v in select.items()):
                seen+=1
                if seen==occurrence:break
            r.breakpoint(sync,False);r.step();r.breakpoint(sync);r.resume()
        r.breakpoint(sync,False)
        state=dict(pc=pc,sp=r.register('sp'),cpsr=r.register('cpsr'),gprs=regs,sysregs=r.registers(SYSREGS),
                   fp=dict(v={'v%d'%i:'%032x'%r.register('v%d'%i) for i in range(32)},fpsr=r.register('fpsr'),fpcr=r.register('fpcr')))
        # The gdbstub holds the vCPU stopped; pmemsave reads guest RAM as it is at this instruction.
        m.request('pmemsave',dict(val=RAM_BASE,size=size,filename=str(out/'ram.bin')))
        r.detach()
    data=(out/'ram.bin').read_bytes()
    if len(data)!=size:raise ValueError('RAM dump is %d bytes, expected %d'%(len(data),size))
    report=dict(format=FORMAT,checkpoint=dict(path=str(checkpoint),vmstate_sha256=hashlib.sha256((checkpoint/'vmstate.bin').read_bytes()).hexdigest()),
                selection=dict(select=select,occurrence=occurrence),call=call,ram=dict(base=RAM_BASE,size=size,sha256=hashlib.sha256(data).hexdigest()),
                cpu=state)
    (out/'state.json').write_text(json.dumps(report,indent=1)+'\n')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checkpoint',required=True);p.add_argument('--contract',default=str(ROOT/'integrations/linux_aarch64/svc-boundary.json'))
    p.add_argument('--select',action='append',required=True,help='number=N or REGISTER=VALUE');p.add_argument('--occurrence',type=int,default=1)
    p.add_argument('--out',required=True);p.add_argument('--timeout',type=int,default=300)
    a=p.parse_args();select={}
    for item in a.select:
        k,_,v=item.partition('=')
        if not v:p.error('--select requires KEY=VALUE')
        select[k]=int(v,0)
    r=dump(a.checkpoint,a.contract,select,a.out,a.occurrence,a.timeout)
    print(json.dumps(dict(call=r['call'],ram=r['ram'])))


if __name__=='__main__':main()
