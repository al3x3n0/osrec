#!/usr/bin/env python3
"""Replay a captured SVC boundary by executing the kernel's own machine code.

Input is a `kernel_boundary_capture.py` directory. The replay image holds every
captured page at its live physical address: the kernel instructions the call
executed, the data it touched and the kernel's own translation tables. A stub at
EL2, outside the EL1&0 translation regime, loads the captured EL1 system
registers, FP/SIMD and user registers and returns to EL0 at the trap
instruction. The CPU then takes the SVC itself, so everything from the vector to
the return to the user continuation is the kernel's code: nothing is modelled,
recompiled or skipped.

The replay is accepted when its instruction sequence and memory accesses equal
the live trace, it returns to the continuation in EL0 with the live user
registers, and every touched page equals its live post-state.
"""
import argparse,hashlib,json,os,shutil,struct,subprocess,tempfile,time
from pathlib import Path
from gdb_remote import Remote,Exited
from svc_boundary import free_port
from kernel_boundary_capture import PLUGIN,PAGE,GPRS,parse_trace,physical

ROOT=Path(__file__).resolve().parents[1];FORMAT='osrec-kernel-boundary-replay-v1'
RAM=(0x40000000,0x60000000)
# EL1 registers the stub restores (gdb name -> system register), in this order.
RESTORE=[('MAIR_EL1','mair_el1'),('AMAIR0','amair_el1'),('TCR_EL1','tcr_el1'),('TTBR0_EL1','ttbr0_el1'),('TTBR1_EL1','ttbr1_el1'),
         ('VBAR','vbar_el1'),('TPIDR_EL1','tpidr_el1'),('TPIDR_EL0','tpidr_el0'),('TPIDRRO_EL0','tpidrro_el0'),('SP_EL0','sp_el0'),
         ('CONTEXTIDR_EL1','contextidr_el1'),('CPACR','cpacr_el1'),('MDSCR_EL1','mdscr_el1'),('CNTKCTL','cntkctl_el1'),('PAR_EL1','par_el1'),
         ('AFSR0_EL1','afsr0_el1'),('AFSR1_EL1','afsr1_el1'),('ESR_EL1','esr_el1'),('FAR_EL1','far_el1'),('ELR_EL1','elr_el1'),('SPSR_EL1','spsr_el1'),
         ('CSSELR','csselr_el1'),('CNTV_CVAL_EL0','cntv_cval_el0'),('CNTV_CTL_EL0','cntv_ctl_el0'),('CNTP_CVAL_EL0','cntp_cval_el0'),('CNTP_CTL_EL0','cntp_ctl_el0'),
         ('SCTLR','sctlr_el1')]

def stub_source(capture):
    """EL2 entry: hypervisor controls, EL1 registers, FP/SIMD, then ERET to the user trap instruction."""
    e=capture['entry'];s=e['sysregs']
    words=[s[name] for name,_ in RESTORE]+[e['sp'],capture['trap']['site'],s['SPSR_EL1'],e['fp']['fpsr'],e['fp']['fpcr']]
    lines=['.section .text','.global _start','_start:',
        '    mov x0,#(1<<31)','    msr hcr_el2,x0',            # EL1 is AArch64; no traps to EL2
        '    mov x0,#3','    msr cnthctl_el2,x0','    msr cntvoff_el2,xzr',   # EL1 counter/timer access, live counter view
        '    mrs x0,midr_el1','    msr vpidr_el2,x0','    mrs x0,mpidr_el1','    msr vmpidr_el2,x0',
        '    mov x0,#0x33ff','    msr cptr_el2,x0','    msr hstr_el2,xzr','    isb',
        '    adr x1,registers']
    for i,(_,reg) in enumerate(RESTORE):lines+=['    ldr x0,[x1,#%d]'%(8*i),'    msr %s,x0'%reg]
    n=len(RESTORE)
    lines+=['    ldr x0,[x1,#%d]'%(8*n),'    msr sp_el1,x0',
            '    ldr x0,[x1,#%d]'%(8*(n+1)),'    msr elr_el2,x0',
            '    ldr x0,[x1,#%d]'%(8*(n+2)),'    msr spsr_el2,x0',
            '    ldr x0,[x1,#%d]'%(8*(n+3)),'    msr fpsr,x0',
            '    ldr x0,[x1,#%d]'%(8*(n+4)),'    msr fpcr,x0',
            '    adr x1,vectors_fp']
    lines+=['    ldp q%d,q%d,[x1,#%d]'%(i,i+1,32*(i//2)) for i in range(0,32,2)]
    lines+=['    tlbi vmalle1','    dsb sy','    isb','    adr x30,gprs']
    lines+=['    ldp x%d,x%d,[x30,#%d]'%(i,i+1,8*i) for i in range(0,30,2)]
    lines+=['    ldr x30,[x30,#240]','    eret','.balign 16','registers:']
    lines+=['    .quad 0x%x'%w for w in words]
    lines+=['.balign 16','vectors_fp:']
    for i in range(32):
        v=int(e['fp']['v']['v%d'%i],16);lines+=['    .quad 0x%x,0x%x'%(v&(1<<64)-1,v>>64)]
    lines+=['gprs:']+['    .quad 0x%x'%e['gprs']['x%d'%i] for i in range(31)]
    return '\n'.join(lines)+'\n'

def elf(segments,entry):
    """Build ELF64 PT_LOADs from (physical address, file bytes[, memory size])."""
    header_size,ph_size=64,56;offset=header_size+ph_size*len(segments);phdrs=[];body=[]
    for address,data,*extent in segments:
        size = extent[0] if extent else len(data)
        if size < len(data):
            raise ValueError('ELF segment memory size is smaller than its file data')
        pad = (address - offset) % PAGE
        offset += pad
        phdrs.append(struct.pack('<IIQQQQQQ',1,7,offset,address,address,len(data),size,PAGE))
        body.extend((bytes(pad),data));offset+=len(data)
    ident=b'\x7fELF'+bytes([2,1,1,0])+bytes(8)
    header=ident+struct.pack('<HHIQQQIHHHHHH',2,183,1,entry,header_size,0,0,header_size,ph_size,len(segments),64,0,0)
    return b''.join([header,*phdrs,*body])

def build(capture,pages,stage,llvm_bin):
    used=set(pages)
    stub=next(a for a in range(RAM[1]-2*PAGE,RAM[0],-PAGE) if a not in used and a+PAGE not in used)
    (stage/'stub.S').write_text(stub_source(capture))
    subprocess.run([str(llvm_bin/'clang'),'--target=aarch64-none-elf','-mcpu=cortex-a53','-nostdlib','-static','-fuse-ld=lld','-Wl,-Ttext=0x%x'%stub,'-Wl,-e,_start',
                    str(stage/'stub.S'),'-o',str(stage/'stub.elf')],check=True,capture_output=True,text=True,timeout=120)
    subprocess.run([str(llvm_bin/'llvm-objcopy'),'-O','binary','--only-section=.text',str(stage/'stub.elf'),str(stage/'stub.bin')],check=True,capture_output=True,text=True,timeout=60)
    code=(stage/'stub.bin').read_bytes()
    if len(code)>2*PAGE:raise ValueError('stub larger than its reserved pages')
    segments=[];run_start=None;run=b''
    for pa in sorted(pages):
        if run_start is not None and pa==run_start+len(run):run+=pages[pa]
        else:
            if run_start is not None:segments.append((run_start,run))
            run_start,run=pa,pages[pa]
    if run_start is not None:segments.append((run_start,run))
    segments.append((stub,code))
    image=elf(segments,stub);(stage/'replay.elf').write_bytes(image)
    return stub,len(segments)

def replay(capture_dir,out,llvm_bin,qemu,timeout=300):
    capture_dir=Path(capture_dir).resolve();out=Path(out).resolve()
    if out.exists():raise FileExistsError(out)
    capture=json.loads((capture_dir/'capture.json').read_text())
    pages={int(p.name.split('.')[0],16):p.read_bytes() for p in (capture_dir/'pages').glob('*.pre')}
    out.mkdir(parents=True);stub,segments=build(capture,pages,out,llvm_bin)
    port=free_port();trace_path=out/'trace.txt';continuation=capture['trap']['continuation'];vbar=capture['trap']['vector_base']
    command=[qemu,'-M','virt-9.2,secure=off,virtualization=on','-cpu','cortex-a53','-accel','tcg','-smp','1','-m','512M','-nodefaults','-display','none',
             '-monitor','none','-serial','none','-semihosting-config','enable=off','-device','loader,file=%s,cpu-num=0'%(out/'replay.elf'),
             '-plugin','file=%s,out=%s'%(PLUGIN,trace_path),'-S','-gdb','tcp:127.0.0.1:%d'%port]
    with (out/'qemu.stderr.log').open('wb') as err:
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=err)
        try:
            r=Remote(port,timeout=timeout)
            # Stop at the continuation, or at a kernel-mode exception vector entered more often than the live call entered
            # it: a fault or interrupt the live call did not take. One it took (a user-access page fault the kernel fixes
            # up) is followed; the instruction comparison still checks where and when it happens.
            vectors=[vbar+o for o in (0x200,0x280,0x300,0x380)]
            live_entries={v:0 for v in vectors}
            for line in (capture_dir/'trace.txt').read_text().splitlines():
                if line.startswith('I ') and int(line.split()[1],16) in live_entries:live_entries[int(line.split()[1],16)]+=1
            for s in [continuation]+vectors:r.breakpoint(s)
            start=time.time();entered={v:0 for v in vectors}
            r.resume();pc=r.wait(timeout)
            while pc in entered:
                entered[pc]+=1
                if entered[pc]>live_entries[pc]:break
                # Step off the vector's breakpoint (gdbstub would report it again), then run on.
                r.breakpoint(pc,insert=False);r.step();r.breakpoint(pc)
                pc=r.register('pc')
                if pc==continuation:break
                r.resume();pc=r.wait(timeout)
            seconds=time.time()-start
            mode=r.register('cpsr')&15
            returned=dict(gprs=r.registers(GPRS),sp_el0=r.register('SP_EL0'),tpidr_el0=r.register('TPIDR_EL0'))
            data=[int(p,16) for p in capture['pages']['data']]
            physical(r,True);post={pa:r.read(pa,PAGE) for pa in data};physical(r,False)
        finally:
            process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait()
    live_instructions,live_accesses=parse_trace((capture_dir/'trace.txt').read_text())
    instructions,accesses=parse_trace(trace_path.read_text())
    # The replay trace starts with the stub (EL2, physical addresses) and the user trap instruction.
    first=instructions.index(capture['trap']['vector'])
    kernel=instructions[first:];kernel_accesses=[dict(a,index=a['index']-first) for a in accesses if a['index']>=first]
    strip=lambda xs:[(a['index'],a['va'],a['pa'],a['size'],a['store']) for a in xs]
    differences=[]
    for pa in data:
        live=(capture_dir/'pages'/('%x.post'%pa)).read_bytes()
        if post[pa]!=live:differences.append(dict(page=hex(pa),bytes=[i for i in range(PAGE) if post[pa][i]!=live[i]][:32]))
    live_gprs=capture['returned']['gprs'];gpr_mismatch=sorted(k for k in GPRS if returned['gprs'][k]!=live_gprs[k])
    checks=dict(returned_to_continuation=pc==continuation and mode==0,same_instructions=kernel==live_instructions,same_accesses=strip(kernel_accesses)==strip(live_accesses),
                same_user_registers=not gpr_mismatch and returned['sp_el0']==capture['returned']['sp_el0'],same_pages=not differences)
    authentic=sum(1 for pc_ in kernel if pc_>>63)
    report=dict(format=FORMAT,status='equivalent' if all(checks.values()) else 'diverged',capture=str(capture_dir),call=capture['call'],
        result=dict(replay=returned['gprs']['x0'],live=live_gprs['x0']),checks=checks,stopped_at=hex(pc),mode=mode,
        kernel_instructions=dict(replay=len(kernel),live=len(live_instructions),from_kernel_image=authentic,authentic_share=authentic/len(kernel) if kernel else 0.0),
        page_differences=differences,register_differences=gpr_mismatch,image=dict(pages=len(pages),segments=segments,stub_address=hex(stub),
        sha256=hashlib.sha256((out/'replay.elf').read_bytes()).hexdigest()),seconds=round(seconds,2),qemu_command=command,
        claims=dict(kernel_code_executed='captured live kernel instructions only',models=None,recompiled_kernel_code=False,kernel_image_needed=False))
    (out/'report.json').write_text(json.dumps(report,indent=1)+'\n')
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--capture',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));p.add_argument('--qemu',default='qemu-system-aarch64');p.add_argument('--timeout',type=int,default=300)
    a=p.parse_args();r=replay(a.capture,a.out,a.llvm_bin,a.qemu,a.timeout)
    print(json.dumps({k:r[k] for k in ('status','call','result','checks','kernel_instructions','stopped_at','seconds')},indent=1))
    if r['status']!='equivalent':raise SystemExit(1)

if __name__=='__main__':main()
