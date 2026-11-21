#!/usr/bin/env python3
"""Freestanding kernel image from post-boot state: the closure's own code, post-boot data, our own page tables.

build: from a state dump (kernel_state_dump.py), the kernel build (vmlinux) and a profile closure
(kernel_code_closure.py output), write an ELF image whose PT_LOAD segments are the data blob and whose
manifest lists every mapped page:

- kernel text: bytes of the closure's functions as the live kernel holds them after boot (its own build plus
  boot-time patching); every other text word is `hvc #1`, a trap into the image's EL2 stop handler;
- zero pages (the allocator's untouched memory among them) are mapped without blob bytes (RAM starts zeroed);
- data pages reachable from the closure's data roots (conservative pointer scan), all of vmemmap, the kernel
  image's data, the kernel stack, the live translation-table pages and the user pages are loaded as captured;
- any other page (non-zero, unreachable; MMIO) is unmapped: touching it is a kernel fault, which reaches trap
  code and stops the run.

Virtual and physical addresses stay those of the live kernel. Our own TTBR1 tables (outside the kernel's RAM)
map exactly these pages with the live attributes. The EL2 stub restores the captured EL1 and user state and
returns to the user SVC instruction; the application is the captured user process itself, continuing its own
call sequence.

run: execute the image (or the native checkpoint) under a gdbstub and record the syscall sequence: number,
arguments and result of every call, until the image stops (trap) or the call limit. compare: two recordings.
"""
import argparse,bisect,collections,hashlib,json,mmap,os,re,struct,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from kernel_source_verify import Elf
from kernel_boundary_replay import stub_source,elf as elf_image
from gdb_remote import Remote,Exited
from svc_boundary import free_port,validate_contract
import qemu_vm_checkpoint as machine

ROOT=Path(__file__).resolve().parents[1];FORMAT='osrec-source-image-v1';PAGE=4096
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
HVC=0xd4000022  # hvc #1
IMAGE_RAM_MB=1024;PRIVATE=0x70000000  # our tables and stub: above the kernel's 512 MiB, inside the image's RAM
# QEMU virt loads its device tree at the RAM base; blob pages there are staged above and copied by the stub.
DTB=(0x40000000,0x40100000);STAGE=0x78000000
ATTRS=((1<<12)-1)&~3|((0x3fff)<<50)   # descriptor attribute bits [11:2] and [63:50]
CONTIGUOUS=1<<52;NT=1<<16


class Ram:
    """A RAM dump and the live EL1&0 translation tables in it."""
    def __init__(self,dump):
        self.state=json.loads((Path(dump)/'state.json').read_text());self.base=self.state['ram']['base'];self.size=self.state['ram']['size']
        self.file=open(Path(dump)/'ram.bin','rb');self.ram=mmap.mmap(self.file.fileno(),0,access=mmap.ACCESS_READ)
        sr=self.state['cpu']['sysregs'];self.sysregs=sr;tcr=sr['TCR_EL1']
        self.bits={1:64-((tcr>>16)&0x3f),0:64-(tcr&0x3f)}
        self.roots={1:sr['TTBR1_EL1']&((1<<48)-1)&~0xfff,0:sr['TTBR0_EL1']&((1<<48)-1)&~0xfff}
    def page(self,pa):
        o=pa-self.base
        return self.ram[o:o+PAGE] if 0<=o and o+PAGE<=self.size else None
    def q(self,pa):
        o=pa-self.base
        return struct.unpack_from('<Q',self.ram,o)[0] if 0<=o<=self.size-8 else None
    def start(self,upper):return 3-(self.bits[upper]-12-1)//9
    def mappings(self,upper):
        """Every live leaf as 4 KiB pages: [(va, pa, leaf descriptor)] plus the table pages walked."""
        bits=self.bits[upper];start=self.start(upper);leaves=[];tables=[]
        def walk(table,level,prefix):
            tables.append(table);shift=12+9*(3-level)
            count=1<<(bits-shift) if level==start else 512
            for i in range(count):
                d=self.q(table+8*i)
                if d is None or not d&1:continue
                va=prefix|(i<<shift)
                if level<3 and d&2:walk(d&((1<<48)-1)&~0xfff,level+1,va);continue
                if level==3 and not d&2:continue
                base=d&((1<<48)-1)&~((1<<shift)-1)
                for k in range(0,1<<shift,PAGE):leaves.append((va+k,base+k,d))
        top=((1<<64)-(1<<bits)) if upper else 0
        walk(self.roots[upper],start,top);return leaves,tables


def text_ranges(vmlinux):
    """[(low, high)] of executable sections and the function extents of vmlinux."""
    e=Elf(vmlinux);SHF_EXECINSTR=4
    sections=[(s['addr'],s['addr']+s['size']) for s in e.sections if s['flags']&SHF_EXECINSTR and s['addr'] and not s['name'].startswith('.init')]
    return e,sections


def closure_extents(closure,e):
    """[(low, high, name)] of the closure's functions in vmlinux (st_size, or up to the next symbol)."""
    names=set(closure['closure']);syms=sorted(((s['value'],s) for s in e.symbols if s['value'] and s['shndx'] and s['type'] in (0,2) and s['name'] and not s['name'].startswith('$')),key=lambda x:x[0])
    starts=[a for a,_ in syms];out={}
    for i,(a,s) in enumerate(syms):
        if s['name'] not in names:continue
        end=a+s['size'] if s['type']==2 and s['size'] else next((b for b in starts[i+1:] if b>a),a+4)
        out[a]=max(out.get(a,a),end)
    return sorted((a,b) for a,b in out.items())


def reachable(ram,leaves,closure,e,extra_roots):
    """Physical pages reachable from the data roots by a conservative pointer scan (upper bound on the state)."""
    by_va={va:pa for va,pa,_ in leaves}
    pcpu=next((s for s in e.sections if s['name']=='.data..percpu'),None);tp=ram.sysregs['TPIDR_EL1']
    roots=[]
    for d in closure['data_roots']:
        a=d['address']
        if pcpu and pcpu['addr']<=a<pcpu['addr']+pcpu['size']:a+=tp
        roots+=range(a&~0xfff,a+max(d['size'],8),PAGE)
    roots+=[int(x,16) for x in closure['unnamed_data']]+extra_roots
    seen=set();queue=collections.deque()
    def add(va):
        pa=by_va.get(va&~0xfff)
        if pa is not None and pa not in seen:seen.add(pa);queue.append(pa)
    for r in roots:add(r)
    while queue:
        data=ram.page(queue.popleft())
        if data is None:continue
        for (w,) in struct.iter_unpack('<Q',data):
            if w>>48==0xffff:add(w)
    return seen


def boundary_extents(profile,e):
    """[(low, high, name)] of the functions the profile declares boundaries (they become trap code)."""
    patterns=[re.compile(x) for x in profile['boundaries'].values()]
    syms=sorted(((s['value'],s) for s in e.symbols if s['value'] and s['shndx'] and s['type'] in (0,2) and s['name'] and not s['name'].startswith('$')),key=lambda x:x[0])
    starts=[a for a,_ in syms];out=[]
    for i,(a,s) in enumerate(syms):
        if not any(p.fullmatch(s['name']) for p in patterns):continue
        end=a+s['size'] if s['type']==2 and s['size'] else next((b for b in starts[i+1:] if b>a),a+4)
        out.append((a,end,s['name']))
    return sorted(out)


def build(dump,vmlinux,profile_path,closure_path,out,state_mode,delta=0,dwarf_db=None,linear_offset=0,va_profile=None,kernel_shift=0,lower_linear=0):
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    ram=Ram(dump);e,text=text_ranges(vmlinux);profile=json.load(open(profile_path))
    leaves,live_tables=ram.mappings(1);user,user_tables=ram.mappings(0)
    def in_text(va):return any(lo<=va<hi for lo,hi in text)
    if closure_path:
        # Only the closure's functions: every other text word traps.
        closure=json.load(open(closure_path));ext=closure_extents(closure,e);starts=[a for a,_ in ext]
        def included(va):
            i=bisect.bisect_right(starts,va)-1;return i>=0 and va<ext[i][1]
        code_mode='closure'
    else:
        # The whole persistent kernel text; only the profile's boundary functions trap.
        closure=None;cuts=boundary_extents(profile,e);starts=[a for a,_,_ in cuts]
        def included(va):
            i=bisect.bisect_right(starts,va)-1;return not (i>=0 and va<cuts[i][1])
        code_mode='whole';ext=cuts
    sym=lambda n:next(s['value'] for s in e.symbols if s['name']==n)
    image=(sym('_text'),sym('_end'));init=(sym('__init_begin'),sym('__init_end'))
    vmemmap_start=0xfffffc0000000000
    sp=ram.state['cpu']['sp'];stack=list(range((sp-1)&~0x3fff,((sp-1)&~0x3fff)+0x4000,PAGE))
    if state_mode=='reachable' and closure is None:raise ValueError('reachable state needs a closure (its data roots)')
    reach=reachable(ram,leaves,closure,e,stack) if state_mode=='reachable' else None
    always=set(live_tables)|set(user_tables)|{pa for _,pa,_ in user}
    zero=bytes(PAGE);mapped=[];blob={};counts=collections.Counter()
    devices=[(int(x['pa'],16),int(x['pa'],16)+int(x['size'],16)) for x in profile.get('devices',[])]
    for va,pa,d in leaves:
        data=ram.page(pa)
        if data is None:
            # MMIO: unmapped (an access stops the run), except the profile's devices, which pass through to the
            # image machine's own device at the same physical address.
            if any(lo<=pa<hi for lo,hi in devices):counts['device (pass-through)']+=1;mapped.append((va,pa,d,'device'));continue
            counts['outside RAM (MMIO): unmapped']+=1;continue
        if image[0]<=va<image[1] and in_text(va):
            words=bytearray(data)
            for k in range(0,PAGE,4):
                if not included(va+k):words[k:k+4]=HVC.to_bytes(4,'little')
            blob[pa]=bytes(words);kind='text'
        elif image[0]<=va<image[1] and init[0]<=va<init[1]:counts['freed init image alias: unmapped']+=1;continue
        elif data==zero:kind='zero'
        elif image[0]<=va<image[1]:blob[pa]=data;kind='image data'
        elif va>=vmemmap_start:blob[pa]=data;kind='vmemmap'
        elif reach is None or pa in reach or pa in always or va in stack:blob.setdefault(pa,data);kind='data'
        else:counts['unreachable: unmapped']+=1;continue
        counts[kind]+=1;mapped.append((va,pa,d,kind))
    # Text pages are also visible through the linear map; there they keep the live bytes (data reads only).
    for pa in always:
        data=ram.page(pa)
        if data is not None and data!=zero:blob.setdefault(pa,data)
    def apply(patches):
        for pa,(old,new,why) in patches.items():
            page=pa&~0xfff
            if page not in blob:
                if ram.page(page)!=zero:raise ValueError('relocation patches an unloaded page at 0x%x (%s)'%(pa,why))
                blob[page]=zero
            b=bytearray(blob[page]);struct.pack_into('<Q',b,pa-page,new);blob[page]=bytes(b)
    # Moving the linear map (and vmemmap) by linear_offset (va_relocation.py): patch the state on the old layout;
    # pages are mapped at their moved virtual addresses below.
    va_move=lambda va:va;va_cpu={};va_relocation=None
    if linear_offset:
        if delta:raise ValueError('RAM and linear-map relocation are not combined yet')
        from va_relocation import relocate as relocate_va
        symbols={}
        for x in e.symbols:
            if x['value'] and x['name']:symbols.setdefault(x['name'],x['value'])
        from kernel_dwarf_db import load
        patches,va_move,va_cpu,va_relocation=relocate_va(ram,symbols,json.load(open(va_profile)),linear_offset,{pa for _,pa,_ in user},load(dwarf_db))
        apply(patches)
    elif kernel_shift or lower_linear:
        # The whole kernel address space moved by kernel_shift (va_shift.py): data, code constants, tables; or
        # lowered (va_shift.lower: the linear map moved off 0 by lower_linear, then every address + 2^48).
        if delta:raise ValueError('RAM relocation and a kernel shift are not combined yet')
        from va_shift import relocate as shift_kernel,lower as lower_kernel
        if lower_linear:shift_kernel=lambda r,sy,pr,_,up,db,tx:lower_kernel(r,sy,pr,lower_linear,up,db,tx);kernel_shift=1<<48
        from kernel_dwarf_db import load
        symbols={}
        for x in e.symbols:
            if x['value'] and x['name']:symbols.setdefault(x['name'],x['value'])
        patches,text_patches,va_move,va_cpu,va_relocation=shift_kernel(ram,symbols,json.load(open(va_profile)),kernel_shift,{pa for _,pa,_ in user},load(dwarf_db),text)
        apply(patches)
        for pa,(old,new,why) in text_patches.items():  # a word replaced by a boundary trap keeps the trap
            page=pa&~0xfff;cur=struct.unpack_from('<I',blob[page],pa-page)[0]
            if cur==old:b=bytearray(blob[page]);struct.pack_into('<I',b,pa-page,new);blob[page]=bytes(b)
    # Moving RAM by delta (ram_relocation.py): patch stored physical addresses on the old layout, then place every
    # RAM page at its physical address + delta. Virtual addresses do not change.
    in_ram=lambda pa:ram.base<=pa<ram.base+ram.size
    moved=lambda pa:pa+delta if delta and in_ram(pa) else pa
    relocation=None
    if delta:
        from ram_relocation import relocate
        from kernel_dwarf_db import load
        symbols={}
        for x in e.symbols:
            if x['value'] and x['name']:symbols.setdefault(x['name'],x['value'])
        patches,relocation=relocate(ram,symbols,load(dwarf_db),delta)
        apply(patches)
        blob={moved(pa):data for pa,data in blob.items()}
    # Our TTBR1 tables over exactly the mapped pages, with the live leaf attributes as 4 KiB page descriptors.
    bits=ram.bits[1];start=ram.start(1);tables={};next_table=[PRIVATE]
    def table(key):
        if key not in tables:tables[key]=(next_table[0],bytearray(PAGE));next_table[0]+=PAGE
        return tables[key]
    root=table(('root',))
    for va,pa,d,_ in mapped:
        va=va_move(va)
        if lower_linear and va>>48:continue  # not lowered (fixmap, PCI I/O): left unmapped
        node=root
        for level in range(start,3):
            shift=12+9*(3-level);i=(va>>shift)&((1<<(bits-shift))-1 if level==start else 511)
            child=table((level+1,va>>(shift)))
            struct.pack_into('<Q',node[1],8*i,child[0]|3);node=child
        leaf=(d&ATTRS&~CONTIGUOUS&~NT)|moved(pa)|3
        struct.pack_into('<Q',node[1],8*((va>>12)&511),leaf)
    ttbr1=(ram.sysregs['TTBR1_EL1']&~((1<<48)-1))|root[0]
    if lower_linear:
        # The lowered kernel lives in the user program's own TTBR0 top-level table, at slots the program does not
        # use; TTBR1 is never walked (TCR_EL1.EPD1), so an address the lowering missed faults.
        user_root=moved(ram.roots[0]);page=bytearray(blob.get(user_root) or ram.page(ram.roots[0]))
        for i in range(512):
            entry=struct.unpack_from('<Q',root[1],8*i)[0]
            if not entry:continue
            if struct.unpack_from('<Q',page,8*i)[0]:raise ValueError('user top-level slot %d is in use; the lowered kernel cannot go there'%i)
            struct.pack_into('<Q',page,8*i,entry)
        blob[user_root]=bytes(page)
    stub_at=next_table[0]+PAGE
    capture=dict(entry=ram.state['cpu'],trap=dict(site=ram.sysregs['ELR_EL1']-4))
    ttbr0=ram.sysregs['TTBR0_EL1'];ttbr0=(ttbr0&~((1<<48)-1)&~0xfff|ttbr0&0xfff)|moved(ram.roots[0])
    capture['entry']=dict(capture['entry'],sysregs=dict(capture['entry']['sysregs'],TTBR1_EL1=ttbr1,TTBR0_EL1=ttbr0))
    if va_cpu:capture['entry']=dict(capture['entry'],sp=va_cpu['sp'],sysregs=dict(capture['entry']['sysregs'],TPIDR_EL1=va_cpu['TPIDR_EL1'],VBAR=va_cpu.get('VBAR',ram.sysregs['VBAR'])))
    if lower_linear:capture['entry']['sysregs']=dict(capture['entry']['sysregs'],TCR_EL1=capture['entry']['sysregs']['TCR_EL1']|(1<<23))
    # The image machine's RAM (QEMU virt: from 0x40000000) must hold the moved RAM; our tables and stub stay outside it.
    top=max(moved(ram.base+ram.size-1)+1,PRIVATE+0x10000000);ram_mb=max(IMAGE_RAM_MB,(top-0x40000000+(1<<20)-1)>>20)
    if delta and moved(ram.base)<PRIVATE+0x10000000 and moved(ram.base+ram.size)>PRIVATE:raise ValueError('moved RAM overlaps the image tables at 0x%x'%PRIVATE)
    source=stub_source(capture)
    # EL2 stop handler: every EL2 vector records ESR/ELR/FAR in x0-x2 and the vector offset in x3, then stops.
    vectors=['.balign 2048','el2_vectors:']
    for k in range(16):vectors+=['.balign 128','    mov x3,#%d'%(k*0x80),'    b el2_stop']
    vectors+=['el2_stop:','    mrs x0,esr_el2','    mrs x1,elr_el2','    mrs x2,far_el2','.global el2_stopped','el2_stopped:','    b el2_stopped']
    source=source.replace('    mov x0,#(1<<31)\n','    adr x0,el2_vectors\n    msr vbar_el2,x0\n    mov x0,#(1<<31)\n',1)
    source=source.replace('.balign 16\nregisters:','\n'.join(vectors)+'\n.balign 16\nregisters:',1)
    staged=sorted(pa for pa in blob if DTB[0]<=pa<DTB[1])
    copy=['    adr x4,staged_pages','    mov x5,#%d'%len(staged),'1:  cbz x5,3f','    ldp x6,x7,[x4],#16','    mov x9,#512',
          '2:  ldr x10,[x6],#8','    str x10,[x7],#8','    subs x9,x9,#1','    b.ne 2b','    sub x5,x5,#1','    b 1b','3:  dc civac,xzr' if False else '3:']
    source=source.replace('    mov x0,#(1<<31)\n','\n'.join(copy)+'\n    mov x0,#(1<<31)\n',1)
    source+='.balign 16\nstaged_pages:\n'+''.join('    .quad 0x%x,0x%x\n'%(STAGE+i*PAGE,pa) for i,pa in enumerate(staged))
    (out/'stub.S').write_text(source)
    subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-mcpu=cortex-a53','-nostdlib','-static','-fuse-ld=lld','-Wl,-Ttext=0x%x'%stub_at,'-Wl,-e,_start',
                    str(out/'stub.S'),'-o',str(out/'stub.elf')],check=True,capture_output=True,text=True)
    subprocess.run([str(LLVM/'llvm-objcopy'),'-O','binary','--only-section=.text',str(out/'stub.elf'),str(out/'stub.bin')],check=True)
    nm=subprocess.run([str(LLVM/'llvm-nm'),str(out/'stub.elf')],capture_output=True,text=True,check=True).stdout
    stopped=int(next(l.split()[0] for l in nm.splitlines() if l.endswith(' el2_stopped')),16)
    pages={pa:data for pa,data in blob.items() if not DTB[0]<=pa<DTB[1]}
    for i,pa in enumerate(staged):pages[STAGE+i*PAGE]=blob[pa]
    for address,data in tables.values():pages[address]=bytes(data)
    code=(out/'stub.bin').read_bytes();code+=bytes(-len(code)%PAGE)
    for k in range(0,len(code),PAGE):pages[stub_at+k]=code[k:k+PAGE]
    segments=[];run_start=None;run=b''
    for pa in sorted(pages):
        if run_start is not None and pa==run_start+len(run):run+=pages[pa]
        else:
            if run_start is not None:segments.append((run_start,run))
            run_start,run=pa,pages[pa]
    segments.append((run_start,run))
    (out/'image.elf').write_bytes(elf_image(segments,stub_at))
    manifest=dict(format=FORMAT,dump=str(Path(dump).resolve()),vmlinux=str(Path(vmlinux).resolve()),profile=str(Path(profile_path).resolve()),
                  closure=str(Path(closure_path).resolve()) if closure_path else None,code=code_mode,state=state_mode,ram=ram.state['ram'],
                  functions=len(ext),mapped_pages=dict(counts),blob_pages=len(blob),table_pages=len(tables),ttbr1=hex(ttbr1),stub=hex(stub_at),stop=hex(stopped),
                  vector_base=hex(va_cpu.get('VBAR',ram.sysregs['VBAR'])),kernel_shift=hex(kernel_shift),image_ram_mb=ram_mb,relocation=relocation,va_relocation=va_relocation,
                  pages=[dict(va=hex(va),pa=hex(pa),kind=kind) for va,pa,_,kind in mapped if kind!='zero'],
                  zero_pages=sum(1 for *_,k in mapped if k=='zero'),
                  image_sha256=hashlib.sha256((out/'image.elf').read_bytes()).hexdigest())
    (out/'manifest.json').write_text(json.dumps(manifest,indent=1)+'\n')
    if code_mode=='whole':manifest['boundary_functions']=[n for _,_,n in ext]
    return {k:manifest[k] for k in ('code','state','functions','mapped_pages','blob_pages','table_pages','stop','image_ram_mb','relocation','va_relocation')}


SVC_OFFSET=0x400;GPRS=['x%d'%i for i in range(31)]


PT_REGS_OFFSET=0x150  # the EL0 vector's `sub sp, sp, #0x150`: pt_regs sit there below the entry stack pointer


def result_point(vmlinux):
    """The instruction after el0_svc's call of do_el0_svc: the syscall has finished, its result is in pt_regs and
    return-to-user work (signal delivery among it) has not started."""
    e=Elf(vmlinux);f={x['name']:x for x in e.symbols if x['type']==2}
    a=f['el0_svc'];target=f['do_el0_svc']['value'];code=e.read(a['value'],a['size'])
    for k in range(0,len(code),4):
        w,=struct.unpack_from('<I',code,k)
        if w&0xfc000000==0x94000000 and a['value']+k+4*(w&0x3ffffff)-(4<<26 if w&0x2000000 else 0)==target:return a['value']+k+4
    raise ValueError('el0_svc does not call do_el0_svc')


def svc_entry(r):
    """The call at an SVC vector stop (EL1, before kernel_entry), with the address of its pt_regs."""
    g=r.registers(GPRS[:9])
    return dict(number=g['x8'],arguments=[g['x%d'%i] for i in range(6)],regs=r.register('sp')-PT_REGS_OFFSET)


def record(r,svc_vector,stop,limit,timeout,symbols=None,counters=None,result_at=None,pending=None,shadow_pa=None,memory=False,context_pointer_pa=None,monitor_offset=0,memory_ram=None,progress=None,clock_sites=None,clock_events=None,mmio_sites=None,mmio_ranges=(),mmio_events=None,shared_root=False,callstacks=None):
    """Syscalls and user exceptions from the current point and how the run ended.

    A call is taken at the SVC vector; its result is read from pt_regs.regs[0] at `result_at`, before any signal
    is delivered, so calls made by signal handlers (rt_sigreturn among them) are recorded in order. `pending` is
    a call already entered when recording starts."""
    calls=[];r.breakpoint(svc_vector);r.breakpoint(result_at);counters=counters or {};counts={n:0 for n in counters}
    for a in counters.values():r.breakpoint(a)
    clock_sites=clock_sites or {}
    if clock_events is None:clock_events=[]
    if mmio_events is None:mmio_events=[]
    mmio_sites=mmio_sites or {};mmio_enabled=False
    for a in clock_sites:r.breakpoint(a)
    if stop is not None:r.breakpoint(stop)
    if callstacks:
        observed = {svc_vector, result_at, stop, *counters.values(), *clock_sites, *mmio_sites}
        for address in callstacks.locations.keys() - observed:
            r.breakpoint(address)
    end=None;spurious=0;spurious_pcs=[]
    def exception_state():
        if shadow_pa is None:return r.registers(['ESR_EL1','FAR_EL1','ELR_EL1'])
        # Actual EL1 registers describe the monitor trap; the captured kernel's
        # ELR/ESR/FAR live in the shadow, read independently of the current TTBR0.
        from kernel_boundary_capture import physical
        physical(r,True)
        try:elr,spsr,esr,far=struct.unpack('<4Q',r.read(shadow_pa+16,32))
        finally:physical(r,False)
        return dict(ESR_EL1=esr,FAR_EL1=far,ELR_EL1=elr)
    def memory_root():
        if shadow_pa is None:return r.register('TTBR0_EL1')
        from kernel_boundary_capture import physical
        physical(r,True)
        try:return r.u(shadow_pa+72)
        finally:physical(r,False)
    if memory:
        from source_image_memory import snapshot
        from kernel_replay_tables import KERNEL_BASE, TCR_EPD1
        memory_tcr=r.register('TCR_EL1') if pending else None
        if pending:pending['_memory_root']=memory_root()
    def step_over(pc):r.breakpoint(pc,False);r.step();r.breakpoint(pc);r.resume()
    if pending:step_over(svc_vector)
    else:r.resume()
    while True:
        try:pc=r.wait(timeout)
        except Exited:end=dict(reason='exited');break
        except Exception as error:end=dict(reason='timeout',detail=str(error));break
        if callstacks and callstacks.enabled(pc):
            callstacks.capture(r, pc)
        if stop is not None and pc==stop:
            g=r.registers(['x0','x1','x2','x3'])
            if shadow_pa is not None:
                reasons={1:'boundary',2:'unknown sysreg',3:'unsupported instruction',4:'missing site',5:'undefined instruction',6:'unhandled exception',7:'monitor fault',8:'user access to kernel address space'}
                reasons[9]='unclassified lowered-address operation'
                end=dict(reason='trap',stop_reason=reasons.get(g['x0'],'unknown stop'),stop_code=g['x0'],pc=hex(g['x1']),detail=hex(g['x2']),far=hex(g['x3']))
                from kernel_boundary_capture import physical
                physical(r,True)
                try:emulated,entries=struct.unpack('<2Q',r.read(shadow_pa+88,16))
                finally:physical(r,False)
                end['emulated_sites']=emulated;end['kernel_entries']=entries
                state_=exception_state()
                end['el1']={name:hex(state_[register]) for name,register in [('elr','ELR_EL1'),('esr','ESR_EL1'),('far','FAR_EL1')]}
            else:
                end=dict(reason='trap',esr_el2=hex(g['x0']),elr_el2=hex(g['x1']),far_el2=hex(g['x2']),vector=hex(g['x3']),
                         el1=dict(esr=hex(r.register('ESR_EL1')),far=hex(r.register('FAR_EL1')),elr=hex(r.register('ELR_EL1'))))
            if symbols:
                end['function']=symbols(g['x1'] if shadow_pa is not None else g['x1']-4)
                # Kernel backtrace by the AArch64 frame records (x29 chain); the first return address is x30.
                if context_pointer_pa is not None:
                    physical(r,True)
                    try:
                        pointer=r.u(context_pointer_pa)
                        if pointer and g['x0']!=7:
                            context=pointer+monitor_offset
                            fp,lr=struct.unpack('<2Q',r.read(context+29*8,16))
                            frames=[lr]
                        else:frames=[];fp=0
                    finally:physical(r,False)
                elif shadow_pa is not None:frames=[];fp=0
                else:frames=[r.register('x30')];fp=r.register('x29')
                from source_image_trace import frame_links
                from kernel_replay_tables import KERNEL_BASE
                stack_address = (lambda va: KERNEL_BASE <= va < 2*KERNEL_BASE) if shared_root else (lambda va: va >> 48 == 0xffff)
                frames.extend(frame_links(r, fp, stack_address))
                end['backtrace']=[symbols(f&((1<<64)-1 if f>>48==0xffff else 0) or f) for f in frames]
            break
        hit=next((n for n,a in counters.items() if a==pc),None)
        if hit:
            counts[hit]+=1;r.breakpoint(pc,False);r.step();r.breakpoint(pc);r.resume();continue
        if pc in clock_sites:
            word=clock_sites[pc];r.breakpoint(pc,False);r.step()
            value=r.register('x%d'%(word&31))
            clock_events.append((pc,(word>>5)&65535,value))
            r.breakpoint(pc);r.resume();continue
        if mmio_enabled and pc in mmio_sites:
            word=mmio_sites[pc];size=1<<(word>>30);rn=word>>5&31;rt=word&31;write=not bool(word&(1<<22))
            address=r.register('sp' if rn==31 else 'x%d'%rn)+(word>>10&4095)*size
            device=any(lo<=address and address+size<=hi for lo,hi in mmio_ranges)
            value=(0 if rt==31 else r.register('x%d'%rt))&((1<<(size*8))-1) if device and write else 0
            r.breakpoint(pc,False);r.step()
            if device:
                if not write:value=(0 if rt==31 else r.register('x%d'%rt))&((1<<(size*8))-1)
                mmio_events.append((pc,address,size,int(write),value))
            r.breakpoint(pc);r.resume();continue
        exception=exception_state() if pc==svc_vector else None
        if pc==svc_vector and exception['ESR_EL1']>>26!=0x15:
            # Not an SVC: a user exception (page fault) entering the same vector. Recorded as an event.
            calls.append(dict(event='exception',number=-1,arguments=[exception['ESR_EL1'],exception['FAR_EL1'],exception['ELR_EL1']],result=None))
            r.breakpoint(svc_vector,False);r.step();r.breakpoint(svc_vector);r.resume();continue
        if pc==svc_vector:
            if len(calls)>=limit:end=dict(reason='limit');break
            pending=svc_entry(r)
            if mmio_sites and not mmio_enabled and pending['number']==64 and pending['arguments'][0]==1:
                for a in mmio_sites:r.breakpoint(a)
                mmio_enabled=True
            if memory:
                pending['_memory_root']=memory_root();memory_tcr=r.register('TCR_EL1')
            step_over(pc);continue
        if pc==result_at:
            if pending:
                pending['result']=int.from_bytes(r.read(pending.pop('regs'),8),'little')
                if memory:
                    user_va_limit = KERNEL_BASE if memory_tcr & TCR_EPD1 and (memory_tcr & 63) == 17 else None
                    pending['memory']=snapshot(r,pending.pop('_memory_root'),memory_tcr,memory_ram,user_va_limit)
                calls.append(pending);pending=None
                if progress and len(calls)%100==0:progress(len(calls))
            step_over(pc);continue
        if callstacks and pc in callstacks.locations:
            r.breakpoint(pc, False)
            r.step()
            if callstacks.enabled(pc):
                r.breakpoint(pc)
            r.resume()
            continue
        # A stop at a user address with no breakpoint there (the gdbstub can report a just-removed breakpoint again
        # around an interrupt on the live machine): counted, stepped past and resumed.
        if pc>>48==0:
            spurious+=1;spurious_pcs.append(pc)
            if len(spurious_pcs)>=1000 and len(set(spurious_pcs[-1000:]))==1:end=dict(reason='stuck',pc=hex(pc),calls=len(calls));break
            # Make progress past it: drop any breakpoint left at this address, execute one instruction, go on.
            try:r.breakpoint(pc,False)
            except Exception:pass
            r.step();r.resume();continue
        end=dict(reason='unexpected stop',pc=hex(pc));break
    if pending:pending.pop('regs',None);pending.pop('_memory_root',None);calls.append(dict(pending,result=None))
    if counters:end['counts']=counts
    if spurious:end['spurious_stops']=spurious;end['spurious_pcs']=sorted({hex(p) for p in spurious_pcs})[:20]
    return calls,end


def qemu_boot_image(image_dir, manifest):
    image = image_dir / 'image.elf'
    if manifest.get('segment_only'):
        from source_image_load import check
        if check(image)['image_sha256'] != manifest['image_sha256']:
            raise ValueError('ELF differs from the source-image manifest')
        # virt's generic loader reserves a DTB at the start of RAM. Its ELF
        # kernel loader allows the complete PT_LOAD range to occupy that space.
        return ['-kernel', str(image)]
    return ['-device', f'loader,file={image},cpu-num=0']


def run_image(image_dir,out,limit,timeout,count=(),memory=False,clock_package=None,trace=(),trace_limit=32):
    image_dir=Path(image_dir).resolve();out=Path(out);out.mkdir(parents=True,exist_ok=False)
    m=json.load(open(image_dir/'manifest.json'));port=free_port()
    e=Elf(m['vmlinux']);kernel_base=next(s['value'] for s in e.symbols if s['name']=='_text')
    syms=sorted((s['value'],s['name']) for s in e.symbols if s['type'] in (0,2) and s['value']>=kernel_base and s['shndx'] and s['name'] and '$' not in s['name'])
    starts=[a for a,_ in syms]
    kshift=int(m.get('kernel_shift','0x0'),16)  # a shifted kernel runs at vmlinux's addresses + kernel_shift
    def symbol(a):
        if m.get('lowered') and a<0x800000000000:return hex(a)
        a=(a-kshift)&((1<<64)-1)
        i=bisect.bisect_right(starts,a)-1;return '%s+0x%x'%(syms[i][1],a-syms[i][0]) if i>=0 else hex(a)
    el0=m.get('execution')=='el0-minios'
    callstacks = None
    if trace:
        from source_image_trace import Callstacks
        callstacks = Callstacks(image_dir/'image.elf', m, trace, trace_limit)
    clock_sites={};clock_events=[];mmio_sites={};mmio_events=[];mmio_ranges=[]
    if clock_package:
        cp=Path(clock_package)
        if json.loads((cp/'manifest.json').read_text())['source_image_sha256']!=m['image_sha256']:
            raise ValueError('counter package and image identities differ')
        raw=(cp/'native.bin').read_bytes();h=struct.unpack_from('<10Q',raw)
        at=80+272+520+532584+16*h[5]
        clock_sites={pc:word for pc,word,_ in struct.iter_unpack('<QII',raw[at:at+16*h[6]])
                     if word&0xfff00000==0xd5300000 and (word>>5&65535) in (0xdf01,0xdf02)}
        for s in e.symbols:
            if s['type']==2 and s['size'] and s['name'].startswith('pl011_'):
                for off in range(0,s['size'],4):
                    word,=struct.unpack('<I',e.read(s['value']+off,4))
                    if word&0x3b000000==0x39000000 and not word&(1<<26) and (word>>22&3)<2:
                        mmio_sites[(s['value']+off+kshift)&((1<<64)-1)]=word
        mmio_ranges=[(int(p['va'],16),int(p['va'],16)+PAGE) for p in m['pages'] if p['kind']=='device']
    command=[QEMU,'-M','virt-9.2,secure=off,virtualization='+('off' if el0 else 'on'),'-cpu','cortex-a53','-accel','tcg','-smp','1','-m','%dM'%m['image_ram_mb'],'-nodefaults',
             '-display','none','-monitor','none','-serial','file:%s'%(out/'console.txt'),'-semihosting-config','enable=off',
             *qemu_boot_image(image_dir,m),'-S','-gdb','tcp:127.0.0.1:%d'%port]
    with open(out/'qemu.stderr.log','wb') as err:
        p=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=err)
        try:
            r=Remote(port,timeout=timeout);start=time.time()
            address={s['name']:(s['value']+kshift)&((1<<64)-1) for s in e.symbols if s['name'] in count}
            calls,end=record(r,int(m['vector_base'],16)+SVC_OFFSET,int(m['stop'],16),limit,timeout,symbol,{n:address[n] for n in count},(result_point(m['vmlinux'])+kshift)&((1<<64)-1),
                             shadow_pa=int(m['shadow_pa'],16) if el0 else None,memory=memory,
                             context_pointer_pa=int(m['context_pointer_pa'],16) if el0 and m.get('context_pointer_pa') else None,
                             monitor_offset=int(m['monitor_pa'],16)-int(m['monitor_va'],16) if el0 and m.get('monitor_va') else 0,
                             memory_ram=(m.get('ram',{}).get('base',0x40000000),m.get('ram',{}).get('base',0x40000000)+m.get('ram',{}).get('size',512<<20)),
                             progress=lambda n:(out/'progress.json').write_text(json.dumps(dict(events=n,seconds=round(time.time()-start,2)))+'\n'),
                             clock_sites=clock_sites,clock_events=clock_events,
                             mmio_sites=mmio_sites,mmio_ranges=mmio_ranges,mmio_events=mmio_events,
                             shared_root=m.get('shared_root', False),callstacks=callstacks)
            if end.get('function'):
                cut=next((label for label,pattern in json.load(open(m['profile']))['boundaries'].items() if re.fullmatch(pattern,end['function'].split('+')[0])),None)
                end['boundary']=cut
        finally:
            p.terminate();p.wait()
    report=dict(kind='image',image=str(image_dir),source_image_sha256=m['image_sha256'],calls=calls,end=end,seconds=round(time.time()-start,2))
    if callstacks:
        (out/'callstacks.json').write_text(json.dumps(callstacks.samples, indent=2) + '\n')
        report['callstack_samples'] = len(callstacks.samples)
    if clock_package:
        (out/'counters.bin').write_bytes(b''.join(struct.pack('<3Q',*v) for v in clock_events))
        report['counter_reads']=len(clock_events)
        (out/'mmio.bin').write_bytes(b''.join(struct.pack('<5Q',*v) for v in mmio_events))
        report['mmio_accesses']=len(mmio_events)
    (out/'calls.json').write_text(json.dumps(report,indent=1)+'\n');return report


def run_native(checkpoint,contract,select,occurrence,out,limit,timeout,vmlinux,memory=False):
    """The same recording on the live kernel, from the selected call of the checkpointed run."""
    checkpoint=Path(checkpoint).resolve();out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
    spec=machine.verify(checkpoint);c=validate_contract(json.loads(Path(contract).read_text()));port=free_port()
    with machine.Machine(checkpoint,'native',incoming=True,timeout=timeout,execution_dir=out,observer=('-gdb','tcp:127.0.0.1:%d'%port)) as mach:
        mach.request('migrate-incoming',dict(uri='file:'+str(checkpoint/'vmstate.bin')));mach.migration_complete()
        r=Remote(port,timeout=timeout);svc=r.register(c['entry']['vector_base_register'])+c['entry']['synchronous_vector_offset']
        r.breakpoint(svc);r.resume();os.write(mach.serial_in,spec['protocol']['continue_line'].encode());seen=0
        while True:
            pc=r.wait(timeout);g=r.registers(GPRS[:9])
            call=dict(number=g['x8'],**{'x%d'%i:g['x%d'%i] for i in range(6)})
            if all(call[k]==v for k,v in select.items()):
                seen+=1
                if seen==occurrence:break
            r.breakpoint(svc,False);r.step();r.breakpoint(svc);r.resume()
        # Stopped at the selected entry: it is the first call recorded.
        first=svc_entry(r);r.breakpoint(svc,False)  # record() inserts its own breakpoints once each
        from kernel_state_dump import RAM_BASE,ram_size
        calls,end=record(r,svc,None,limit,timeout,result_at=result_point(vmlinux),pending=first,memory=memory,
                         memory_ram=(RAM_BASE,RAM_BASE+ram_size(spec)))
        if end['reason']!='exited':r.detach()
    report=dict(kind='native',checkpoint=str(checkpoint),calls=calls,end=end)
    (out/'calls.json').write_text(json.dumps(report,indent=1)+'\n');return report


def compare(a,b):
    x=json.loads(Path(a).read_text())['calls'];y=json.loads(Path(b).read_text())['calls'];rows=[];first=None
    # A user exception repeated identically at once (the instruction retried after the kernel resolved it; the
    # live machine can also report the vector stop twice) has no further effect: consecutive duplicates collapse.
    def collapse(z):
        out=[]
        for c in z:
            if c.get('event') and out and out[-1].get('event') and out[-1]['arguments']==c['arguments']:continue
            out.append(c)
        return out,len(z)-len(out)
    (x,cx),(y,cy)=collapse(x),collapse(y)
    events=[sum(1 for c in z if c.get('event')) for z in (x,y)]
    memory_compared=0;memory_identical=0;first_memory_difference=None
    for i,(p,q) in enumerate(zip(x,y)):
        same=p['number']==q['number'] and p['arguments']==q['arguments'] and p['result']==q['result']
        if 'memory' in p or 'memory' in q:
            # Missing memory on one side is a failed comparison, never silently
            # accepted as coverage. Compare virtual pages, not their host PFNs.
            memory_compared+=1;memory_same='memory' in p and 'memory' in q and p['memory']==q['memory']
            memory_identical+=memory_same;same=bool(same and memory_same)
            if not memory_same and first_memory_difference is None:first_memory_difference=i
        if not same and first is None:first=i
        rows.append(same)
    if first is None and len(x)!=len(y):first=len(rows)
    return dict(compared=len(rows),identical=sum(rows),first_difference=first,lengths=[len(x),len(y)],exception_events=events,collapsed_repeats=[cx,cy],
                memory_compared=memory_compared,memory_identical=memory_identical,first_memory_difference=first_memory_difference,
                matches=first is None)


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    b=sub.add_parser('build');b.add_argument('--dump',required=True);b.add_argument('--vmlinux',required=True);b.add_argument('--profile',required=True)
    b.add_argument('--closure',help='restrict code to this closure (kernel_code_closure.py); default: whole kernel text minus boundaries')
    b.add_argument('--out',required=True);b.add_argument('--state',choices=['reachable','full'],default='full')
    b.add_argument('--relocate',type=lambda v:int(v,0),default=0,help='move RAM by this many bytes (a multiple of 128 MiB)')
    b.add_argument('--dwarf-db',help='kernel DWARF database (required for --relocate; optional EL0 CPU-data recovery)')
    b.add_argument('--relocate-linear',type=lambda v:int(v,0),default=0,help='move the linear map (and vmemmap) by this many bytes')
    b.add_argument('--va-profile',help='kernel_va_survey.py profile (needed with --relocate-linear)')
    b.add_argument('--shift-kernel',type=lambda v:int(v,0),default=0,help='move the whole kernel address space by this many bytes (va_shift.py)')
    b.add_argument('--lower-kernel',type=lambda v:int(v,0),default=0,help='lower the kernel into the user half; the value moves the linear map off address 0 first (va_shift.lower)')
    b.add_argument('--execution',choices=['el1','el0-minios'],default='el1',help='kernel execution runtime')
    b.add_argument('--el0-dispatch',choices=['traps','branches'],default='traps',help='EL0 architecture-edge dispatch; branches use stack-free shadow-register veneers where supported')
    b.add_argument('--segment-only',action='store_true',help='declare all required RAM in ELF PT_LOAD for shared-root EL0 images')
    r=sub.add_parser('run');r.add_argument('--image',required=True);r.add_argument('--out',required=True)
    r.add_argument('--limit',type=int,default=10000);r.add_argument('--timeout',type=int,default=120)
    r.add_argument('--count',action='append',default=[],help='kernel function whose entries are counted (e.g. __switch_to)')
    r.add_argument('--trace', action='append', default=[], help='record kernel callstacks at a checkpoint code symbol')
    r.add_argument('--trace-limit', type=int, default=32, help='maximum callstack samples per breakpoint address')
    r.add_argument('--memory',action='store_true',help='hash every accessible user page after each syscall')
    r.add_argument('--native-counters',help='matching native package: record ordered architecture counter inputs')
    n=sub.add_parser('native');n.add_argument('--checkpoint',required=True);n.add_argument('--contract',default=str(ROOT/'integrations/linux_aarch64/svc-boundary.json'))
    n.add_argument('--select',action='append',required=True);n.add_argument('--occurrence',type=int,default=1);n.add_argument('--out',required=True)
    n.add_argument('--limit',type=int,default=10000);n.add_argument('--timeout',type=int,default=120)
    n.add_argument('--vmlinux',default=str(ROOT/'build/linux-kernel-clang19-20261108/vmlinux'),help='the live kernel build (its el0_svc result point)')
    n.add_argument('--memory',action='store_true',help='hash every accessible user page after each syscall')
    c=sub.add_parser('compare');c.add_argument('a');c.add_argument('b')
    a=p.parse_args()
    if a.command=='build':
        if a.execution!='el0-minios' and a.el0_dispatch!='traps':p.error('--el0-dispatch requires --execution el0-minios')
        if a.segment_only and a.execution!='el0-minios':p.error('--segment-only requires --execution el0-minios')
        if a.execution=='el0-minios':
            if a.closure or a.state!='full' or a.relocate:p.error('el0-minios currently requires whole text, full state and no physical relocation')
            from source_image_el0 import build as build_el0
            print(json.dumps(build_el0(a.dump,a.vmlinux,a.profile,a.out,a.dwarf_db,a.lower_kernel,a.va_profile,a.el0_dispatch,
                                       segment_only=a.segment_only)))
        else:print(json.dumps(build(a.dump,a.vmlinux,a.profile,a.closure,a.out,a.state,a.relocate,a.dwarf_db,a.relocate_linear,a.va_profile,a.shift_kernel,a.lower_kernel)))
    elif a.command=='run':
        rep=run_image(a.image,a.out,a.limit,a.timeout,a.count,a.memory,a.native_counters,a.trace,a.trace_limit);print(json.dumps(dict(calls=len(rep['calls']),end=rep['end'],counter_reads=rep.get('counter_reads'),callstack_samples=rep.get('callstack_samples',0))))
    elif a.command=='native':
        select={k:int(v,0) for k,_,v in (x.partition('=') for x in a.select)}
        rep=run_native(a.checkpoint,a.contract,select,a.occurrence,a.out,a.limit,a.timeout,a.vmlinux,a.memory);print(json.dumps(dict(calls=len(rep['calls']),end=rep['end'])))
    else:
        result=compare(a.a,a.b);print(json.dumps(result))
        if not result['matches']:sys.exit(1)


if __name__=='__main__':main()
