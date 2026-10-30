#!/usr/bin/env python3
"""Capture one live SVC boundary for replay of the kernel's own machine code.

Three runs of the same full-machine checkpoint, all without kernel symbols or a
binding:

1. entry: a gdbstub stops at the selected synchronous lower-EL vector entry; the
   machine is saved there (an entry snapshot) with every EL1 system register,
   general-purpose and FP/SIMD register.
2. trace: the entry snapshot single-steps under a TCG plugin (tools/qemu_plugins/
   footprint.c) to the user continuation; stepping masks interrupts and timers. Every executed instruction and every
   memory access (virtual and physical address, size, load/store) is recorded;
   the post-state of each touched physical page and the user registers are read
   at the continuation.
3. pre-state: the entry snapshot, paused, supplies the pre-state of the same
   physical pages and of every page-table page the kernel's own translation
   tables use for the touched virtual pages (instruction and data).

The capture is the kernel's own code and data as the live call used them; a
replay that places these pages at their physical addresses executes authentic
kernel instructions only.
"""
import argparse,hashlib,json,os,re,shutil,time
from pathlib import Path
from gdb_remote import Remote
import qemu_vm_checkpoint as machine
from svc_boundary import validate_contract,free_port

ROOT=Path(__file__).resolve().parents[1];FORMAT='osrec-kernel-boundary-capture-v1'
# The footprint plugin (tools/qemu_plugins/footprint.c); CMake builds it as osrec_footprint.
PLUGIN=Path(os.environ.get('OSREC_FOOTPRINT_PLUGIN',ROOT/'build/qemu-plugins/libfootprint.dylib'))
PAGE=4096
GPRS=['x%d'%i for i in range(31)]
SYSREGS=['SCTLR','TCR_EL1','MAIR_EL1','AMAIR0','TTBR0_EL1','TTBR1_EL1','VBAR','TPIDR_EL1','TPIDR_EL0','TPIDRRO_EL0','SP_EL0','SP_EL1',
         'CONTEXTIDR_EL1','CPACR','MDSCR_EL1','CNTKCTL','PAR_EL1','AFSR0_EL1','AFSR1_EL1','ESR_EL1','FAR_EL1','ELR_EL1','SPSR_EL1',
         'ACTLR_EL1','CNTV_CTL_EL0','CNTV_CVAL_EL0','CNTP_CTL_EL0','CNTP_CVAL_EL0','CSSELR']
def sha(data):return hashlib.sha256(data).hexdigest()

def physical(remote,on):
    if remote.request('Qqemu.PhyMemMode:%d'%int(on))!='OK':raise ValueError('gdbstub has no physical memory mode')

def walk(remote,sysregs,va):
    """Translate a virtual address through the live EL1&0 tables: (physical page, [table pages], leaf descriptor)."""
    tcr=sysregs['TCR_EL1'];upper=va>>55&1
    size=(tcr>>16 if upper else tcr)&0x3f;granule=(tcr>>30 if upper else tcr>>14)&3
    if granule!=(2 if upper else 0):raise ValueError('only the 4 KiB granule is supported')
    # A VA of `bits` bits resolves 9 bits per level above the 12-bit page offset; the start
    # level takes whatever remains (e.g. 48 bits: levels 0-3, 39 bits: levels 1-3).
    bits=64-size;start=3-(bits-12-1)//9;level=start
    table=(sysregs['TTBR1_EL1' if upper else 'TTBR0_EL1']&((1<<48)-1))&~0xfff;tables=[]
    while True:
        shift=12+9*(3-level);index=(va>>shift)&((1<<(bits-shift if level==start else 9))-1)
        tables.append(table);descriptor=int.from_bytes(remote.read(table+8*index,8),'little')
        if not descriptor&1:raise ValueError('virtual address 0x%x is not mapped'%va)
        if level==3 or not descriptor&2:
            if level==3 and not descriptor&2:raise ValueError('reserved level-3 descriptor at 0x%x'%va)
            base=descriptor&((1<<48)-1)&~((1<<shift)-1)
            return base+(va&((1<<shift)-1)&~(PAGE-1)),tables,descriptor
        table=descriptor&((1<<48)-1)&~0xfff;level+=1

def parse_trace(text):
    """Instructions and memory accesses from the footprint plugin, in execution order."""
    instructions=[];accesses=[]
    for line in text.splitlines():
        part=line.split()
        if part[0]=='I':instructions.append(int(part[1],16))
        elif part[0]=='M':accesses.append(dict(index=len(instructions)-1,va=int(part[1],16),pa=None if part[2]=='-' else int(part[2],16),size=int(part[3]),store=part[4]=='S'))
    return instructions,accesses

def entry_bundle(checkpoint,out):
    """A bundle that resumes the same recipe from the entry snapshot."""
    out.mkdir();shutil.copyfile(checkpoint/'recipe.json',out/'recipe.json');(out/'assets').mkdir()
    for f in (checkpoint/'assets').iterdir():os.symlink(f.resolve(),out/'assets'/f.name)
    return out

def capture(checkpoint,contract,select,out,occurrence=1,timeout=300,limit=200000):
    checkpoint=Path(checkpoint).resolve();out=Path(out).resolve()
    if out.exists():raise FileExistsError(out)
    if not PLUGIN.exists():raise FileNotFoundError('build the footprint plugin first: '+str(PLUGIN))
    spec=machine.verify(checkpoint);c=validate_contract(json.loads(Path(contract).read_text()))
    out.mkdir(parents=True);bundle=entry_bundle(checkpoint,out/'entry')
    # 1. Entry: stop at the selected SVC, record registers, save the machine there.
    port=free_port()
    with machine.Machine(checkpoint,'entry',incoming=True,timeout=timeout,execution_dir=out,observer=('-gdb','tcp:127.0.0.1:%d'%port),debug_snapshot=True) as m:
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
        entry=dict(pc=pc,sp=r.register('sp'),cpsr=r.register('cpsr'),gprs=regs,sysregs=r.registers(SYSREGS),
                   fp=dict(v={'v%d'%i:'%032x'%r.register('v%d'%i) for i in range(32)},fpsr=r.register('fpsr'),fpcr=r.register('fpcr')))
        continuation=entry['sysregs']['ELR_EL1'];site=continuation-c['trap']['bytes']
        if int.from_bytes(r.read(site,4),'little')!=c['trap']['word']:raise ValueError('return address does not follow the contract trap instruction')
        m.request('migrate',dict(uri='file:'+str(bundle/'vmstate.bin')));m.migration_complete()
        r.detach()
    # 2. Trace: the entry snapshot runs to the continuation under the footprint plugin.
    port=free_port();trace_path=out/'trace.txt';raw_path=out/'trace.raw'
    with machine.Machine(bundle,'trace',incoming=True,timeout=timeout,execution_dir=out,observer=('-gdb','tcp:127.0.0.1:%d'%port),plugin=(PLUGIN,dict(out=raw_path))) as m:
        m.request('migrate-incoming',dict(uri='file:'+str(bundle/'vmstate.bin')));m.migration_complete()
        r=Remote(port,timeout=timeout)
        if r.register('pc')!=sync:raise ValueError('entry snapshot does not resume at the vector')
        # Single steps (QEMU masks interrupts and timers while stepping): the trace is the call's own
        # synchronous path, not a timer tick that came due while the snapshot was saved and restored.
        for steps in range(limit):
            r.step();pc=r.register('pc')
            if pc==continuation and r.register('cpsr')&15==0:break
        else:raise ValueError('kernel did not return to the continuation in EL0 within %d instructions'%limit)
        returned=dict(gprs=r.registers(GPRS),sp_el0=r.register('SP_EL0'),cpsr=r.register('cpsr'),tpidr_el0=r.register('TPIDR_EL0'))
        # The trace as of the stop: after the debugger detaches the guest runs on (into a due timer tick).
        text=raw_path.read_text();trace_path.write_text(text);instructions,accesses=parse_trace(text)
        if not instructions or instructions[0]!=sync:raise ValueError('trace does not start at the vector')
        io=[a for a in accesses if a['pa'] is None]
        if io:raise ValueError('the call accessed device memory at 0x%x'%io[0]['va'])
        data_pages=sorted({a['pa']&~(PAGE-1) for a in accesses}|{(a['pa']+a['size']-1)&~(PAGE-1) for a in accesses})
        physical(r,True);post={pa:r.read(pa,PAGE) for pa in data_pages};physical(r,False)
        r.detach()
    # 3. Pre-state: the paused entry snapshot supplies page contents and the translation tables.
    port=free_port()
    with machine.Machine(bundle,'pre',incoming=True,timeout=timeout,execution_dir=out,observer=('-gdb','tcp:127.0.0.1:%d'%port)) as m:
        m.request('migrate-incoming',dict(uri='file:'+str(bundle/'vmstate.bin')));m.migration_complete()
        r=Remote(port,timeout=timeout);physical(r,True)
        virtual_pages=sorted({va&~(PAGE-1) for va in instructions}|{a['va']&~(PAGE-1) for a in accesses}|{(a['va']+a['size']-1)&~(PAGE-1) for a in accesses}|{site&~(PAGE-1),continuation&~(PAGE-1)})
        walks={};tables=set()
        for va in virtual_pages:
            pa,path,descriptor=walk(r,entry['sysregs'],va);walks[va]=dict(pa=pa,tables=path,descriptor=descriptor);tables.update(path)
        for a in accesses:
            if walks[a['va']&~(PAGE-1)]['pa']!=a['pa']&~(PAGE-1):raise ValueError('table walk disagrees with the traced access at 0x%x'%a['va'])
        pages=sorted(set(data_pages)|{w['pa'] for w in walks.values()}|tables)
        pre={pa:r.read(pa,PAGE) for pa in pages};physical(r,False);r.detach()
    store=out/'pages';store.mkdir()
    for pa in pages:(store/('%x.pre'%pa)).write_bytes(pre[pa])
    for pa in data_pages:(store/('%x.post'%pa)).write_bytes(post[pa])
    report=dict(format=FORMAT,status='captured',checkpoint=dict(path=str(checkpoint),vmstate_sha256=sha((checkpoint/'vmstate.bin').read_bytes())),
        selection=dict(select=select,occurrence=occurrence),call=dict(number=call['number'],arguments=[call[k] for k in c['argument_registers']]),
        trap=dict(site=site,continuation=continuation,vector_base=vbar,vector=sync),entry=entry,returned=returned,
        trace=dict(instructions=len(instructions),accesses=len(accesses),loads=sum(not a['store'] for a in accesses),stores=sum(a['store'] for a in accesses),sha256=sha(trace_path.read_bytes())),
        pages=dict(data=[hex(p) for p in data_pages],code_and_data=[hex(p) for p in sorted({w['pa'] for w in walks.values()})],tables=[hex(p) for p in sorted(tables)],total=len(pages)),
        walks={hex(va):dict(pa=hex(w['pa']),tables=[hex(t) for t in w['tables']],descriptor=hex(w['descriptor'])) for va,w in walks.items()},
        claims=dict(kernel_symbols_used=False,binding_used=False,kernel_code_replaced=False))
    (out/'capture.json').write_text(json.dumps(report,indent=1)+'\n')
    shutil.rmtree(bundle/'assets');(bundle/'vmstate.bin').unlink();raw_path.unlink()
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--checkpoint',type=Path,required=True);p.add_argument('--contract',type=Path,default=ROOT/'integrations/linux_aarch64/svc-boundary.json')
    p.add_argument('--select',action='append',required=True,help='number=N or REGISTER=VALUE');p.add_argument('--occurrence',type=int,default=1)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--timeout',type=int,default=300);a=p.parse_args()
    select={}
    for item in a.select:
        k,_,v=item.partition('=')
        if not v:p.error('--select requires KEY=VALUE')
        select[k]=int(v,0)
    r=capture(a.checkpoint,a.contract,select,a.out,a.occurrence,a.timeout)
    print(json.dumps(dict(call=r['call'],instructions=r['trace']['instructions'],accesses=r['trace']['accesses'],pages=r['pages']['total'],result=r['returned']['gprs']['x0']),indent=1))

if __name__=='__main__':main()
