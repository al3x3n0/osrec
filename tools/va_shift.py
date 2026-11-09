#!/usr/bin/env python3
"""Uniform shift of the kernel's address space by D (arm64 Linux): the machinery of lowering, testable in place.

Every region moves by the same D (linear map, modules, image and vmalloc, vmemmap); fixmap and PCI I/O sit at the
top and stay out: their pages are left unmapped, so any use stops. D is a multiple of the top-level entry size.
Lowering is the same transform with a D that lands the kernel in the lower half; keeping D small keeps every
value's top 16 bits, so all code sites re-encode in place and the result runs in the existing image.

What changes:
- stored pointers: values in the linear map, modules, image and vmalloc ranges (whole ranges: vmalloc
  bookkeeping keeps unmapped bounds), and in the used vmemmap, + D; per-CPU pointers into vmalloc chunks
  (ptr + __per_cpu_offset lands in a chunk) + D. Text, translation tables and the user program's pages are not
  scanned;
- formula variables: kimage_voffset + D; __per_cpu_offset[] and TPIDR_EL1 unchanged (differences of two
  shifted addresses), memstart_addr unchanged (a physical address);
- code: every layout-derived constant (va_constants.py) recomputed from the shifted parameters (PAGE_OFFSET,
  PAGE_END, MODULES_*, KIMAGE_VADDR, VMALLOC_*, VMEMMAP_START + D; VMEMMAP_END kept: shifting it would wrap,
  and the vmemmap range only gets shorter at its unused top); a site that cannot be re-encoded in place is an
  error;
- the kernel's own TTBR1 tables: top-level entries move by D / PGDIR_SIZE;
- address-keyed hash tables: rehashed (va_rehash.py);
- the CPU: the kernel stack pointer and VBAR_EL1 + D.
"""
import bisect,struct
from va_constants import sites,literal_sites,classify,evaluate,reencode,M64
from va_rehash import rehash

PAGE=4096
SHIFTED_PARAMS=('PAGE_OFFSET','PAGE_END','MODULES_VADDR','MODULES_END','KIMAGE_VADDR','VMALLOC_START','VMALLOC_END','VMEMMAP_START')


def relocate(ram,symbols,profile,D,user_pas,db,text_ranges,lower=False):
    """(data patches, text patches, VA map, CPU registers, summary); patches are {pa: (old, new, why)}."""
    from program_view import Layout
    params={k:int(v,16) for k,v in profile['parameters'].items()};top=params['PGDIR_SIZE']
    if D%top:raise ValueError('shift %#x is not a multiple of %#x'%(D,top))
    leaves,tables=ram.mappings(1);tables=set(tables);va2pa={va:pa for va,pa,_ in leaves}
    def pa(va):
        va&=M64;p=va2pa.get(va&~0xfff);return None if p is None else p+(va&0xfff)
    q=lambda a:ram.q(a)
    lin=(params['PAGE_OFFSET'],params['PAGE_END']);ksp=(params['MODULES_VADDR'],params['VMALLOC_END'])
    vmm=sorted(va for va,_,_ in leaves if params['VMEMMAP_START']<=va<params['VMEMMAP_END'])
    vmm=(vmm[0],vmm[-1]+PAGE+64)
    shifted=[lin,ksp,vmm]
    def inside(v):return any(a<=v<b for a,b in shifted)
    def move(va):return (va+D)&M64 if inside(va) else va
    for va,_,_ in leaves:
        if inside(va) and ((va+D)&M64)>>48!=(0 if lower else 0xffff):raise ValueError('shifted page %#x leaves the %s half'%(va,'lower' if lower else 'upper'))
    patches={};text_patches={}
    def put(a,new,why,where=patches):
        old=q(a)
        if old!=new:where[a]=(old,new,why)
    # Per-CPU: offsets stay; pointers into vmalloc chunks follow the chunks.
    lay=Layout(db);o_list,o_base=lay.offset('struct:pcpu_chunk','list'),lay.offset('struct:pcpu_chunk','base_addr')
    i32=lambda s:q(pa(symbols[s]))&0xffffffff;off0=q(pa(symbols['__per_cpu_offset']))
    unit_size=i32('pcpu_unit_size');unit0=q(pa(q(pa(symbols['pcpu_unit_offsets']))));lists=q(pa(symbols['pcpu_chunk_lists']));chunks=set()
    for i in range(i32('pcpu_nr_slots')+2):
        head=lists+16*i;node=q(pa(head));n=0
        while node and node!=head and n<10000:chunks.add(node-o_list);node=q(pa(node));n+=1
    for s in ('pcpu_first_chunk','pcpu_reserved_chunk'):
        c=q(pa(symbols[s]))
        if c:chunks.add(c)
    vm_chunks=sorted(((q(pa(c+o_base))+unit0)&M64,((q(pa(c+o_base))+unit0)&M64)+unit_size) for c in chunks)
    vm_chunks=[(a,b) for a,b in vm_chunks if not lin[0]<=a<lin[1]];starts=[a for a,_ in vm_chunks]
    def percpu_vm(v):
        x=(v+off0)&M64;i=bisect.bisect_right(starts,x)-1;return i>=0 and x<vm_chunks[i][1]
    keep={pa(symbols['__per_cpu_offset'])+8*i for i in range(max(1,i32('nr_cpu_ids')))}
    # Stored pointers.
    counts=dict(pointers=0,percpu_vmalloc=0);text_pages={va for va in va2pa if any(lo<=va<hi for lo,hi in text_ranges)};seen=set()
    for va,ppa,_ in leaves:
        if ppa in seen or ppa in tables or ppa in user_pas or va in text_pages:continue
        seen.add(ppa);data=ram.page(ppa)
        if data is None or data==bytes(PAGE):continue
        for k,(w,) in enumerate(struct.iter_unpack('<Q',data)):
            a=ppa+8*k
            if a in keep or not w:continue
            if w>>48==0xffff and inside(w):put(a,(w+D)&M64,'pointer');counts['pointers']+=1
            elif vm_chunks and percpu_vm(w):put(a,(w+D)&M64,'per-CPU pointer into a vmalloc chunk');counts['percpu_vmalloc']+=1
    a=pa(symbols['kimage_voffset']);put(a,(q(a)+D)&M64,'kimage_voffset')
    # Code: layout-derived constants from the shifted parameters.
    new_params=dict(params);
    for k in SHIFTED_PARAMS:new_params[k]=(params[k]+D)&M64
    words={}
    for lo,hi in text_ranges:
        for va in range(lo&~0xfff,hi,PAGE):
            p=va2pa.get(va);d=ram.page(p) if p is not None else None
            if d is None:continue
            for k in range(0,PAGE,4):
                if lo<=va+k<hi:words[va+k]=struct.unpack_from('<I',d,k)[0]
    def read8(va):
        p=pa(va);return None if p is None or ram.page(p&~0xfff) is None else q(p)
    found=[s for s in sites(words)+literal_sites(words,read8) if s['value']>>48 in (0xffff,1) or s['value']>>48==0 and s['value']>>32]
    code=dict(sites=0,literals=0);unencodable=[]
    for s,k in zip(found,classify(found,params,profile['derived'],words=words)):
        if not k or k[0]!='derived':continue
        expr=next(d['expr'] for d in profile['derived'] if d['name']==k[1])
        if k[1] in ('PCI_IO_START','PCI_IO_END','FIXADDR_TOP','FIXADDR_TOT_START','VMEMMAP_END'):continue  # not shifted
        nv=(evaluate(expr,new_params)+k[2])&M64
        if s['kind']=='literal':put(pa(s['literal']),nv,'derived literal %s'%k[1]);code['literals']+=1;continue
        new=reencode(s,nv)
        if new is None:
            unencodable.append(dict(va=hex(s['insns'][0][0]),formula=k[1],old=hex(s['value']),new=hex(nv)));continue
        for (va,w0),(_,w1) in zip(s['insns'],new):
            if w0!=w1:
                p=pa(va);text_patches[p]=(w0,w1,'derived %s'%k[1])
        code['sites']+=1
    # The kernel's own TTBR1 tables: top-level entries move by D / PGDIR_SIZE.
    root=ram.roots[1];shift=12+9*(3-ram.start(1));step=(D//top)%512  # a multiple of 2^48 moves no index
    used=sorted({(va>>shift)&511 for va,_,_ in leaves if inside(va)},reverse=step>0) if step else []
    for i in used:
        j=i+step
        if j>511:raise ValueError('top-level entry %d would move past the table'%i)
        if j not in used and q(root+8*j):raise ValueError('top-level entry %d is in use'%j)
        put(root+8*j,q(root+8*i),'TTBR1 top-level %d <- %d'%(j,i))
        if i-step not in used:put(root+8*i,0,'TTBR1 top-level %d cleared'%i)
    # Address-keyed hash tables, then the CPU.
    lookup=next((x[3] for x in db['variables'] if x[0]=='in_lookup_hashtable'),8192)//8
    rehashed=rehash(lambda a:ram.q(a),pa,move,lambda a,v,why:patches.__setitem__(a,(q(a),v,why)),lay,lambda n:symbols[n],lookup)
    cpu=dict(sp=move(ram.state['cpu']['sp']),TPIDR_EL1=ram.sysregs['TPIDR_EL1'],VBAR=move(ram.sysregs['VBAR']))
    code['unencodable']=len(unencodable)
    summary=dict(kernel_shift=hex(D),data=counts,code=code,unencodable_sites=unencodable,top_level_entries_moved=len(used),rehashed=rehashed,
                 percpu_vmalloc_chunks=[(hex(a),hex(b)) for a,b in vm_chunks],data_patches=len(patches),text_patches=len(text_patches),
                 left_out='fixmap and PCI I/O pages are unmapped; their constants are unchanged')
    return patches,text_patches,move,cpu,summary


class Overlay:
    """A RAM dump with patches applied (read side only), for composing transforms."""
    def __init__(self,ram,patches,cpu):
        self.__dict__.update({k:v for k,v in ram.__dict__.items()});self._ram=ram;self._p={a:v for a,(_,v,_) in patches.items()}
        state=dict(ram.state);state['cpu']=dict(state['cpu'],sp=cpu['sp']);self.state=state
        self.sysregs=dict(ram.sysregs,TPIDR_EL1=cpu['TPIDR_EL1'])
    def q(self,pa):return self._p.get(pa,self._ram.q(pa))
    def page(self,pa):
        data=self._ram.page(pa)
        if data is None:return None
        changed=self._pages.get(pa)
        if not changed:return data
        b=bytearray(data)
        for a in changed:struct.pack_into('<Q',b,a-pa,self._p[a])
        return bytes(b)
    def mappings(self,upper):return Ram_mappings(self,upper)
    def start(self,upper):return self._ram.start(upper)


def Ram_mappings(view,upper):
    """The live-table walk of source_image.Ram, reading through `view` (so moved table entries count)."""
    from source_image import Ram
    return Ram.mappings(view,upper)


def lower(ram,symbols,profile,linear_offset,user_pas,db,text_ranges):
    """Lowering: step A (the linear map off address 0, va_relocation.py), then every kernel address + 2^48 (mod
    2^64: the top 16 bits cleared). Returns the composed (data patches, text patches, VA map, CPU, summary)."""
    from va_relocation import relocate as move_linear
    pa_,move_a,cpu_a,sum_a=move_linear(ram,symbols,profile,linear_offset,user_pas,db)
    view=Overlay(ram,pa_,cpu_a);view._pages={}
    for a in pa_:view._pages.setdefault(a&~(PAGE-1),set()).add(a)
    D=1<<48
    pb,text,move_b,cpu_b,sum_b=relocate(view,symbols,profile,D,user_pas,db,text_ranges,lower=True)
    patches={a:(ram.q(a),v,why) for a,(_,v,why) in pa_.items()}
    for a,(_,v,why) in pb.items():patches[a]=(ram.q(a),v,why)
    move=lambda va:move_b(move_a(va))
    cpu=dict(sp=cpu_b['sp'],TPIDR_EL1=cpu_a['TPIDR_EL1'],VBAR=cpu_b['VBAR'])
    return patches,text,move,cpu,dict(step_a=sum_a,lowering=sum_b,kernel_shift=hex(D),linear_offset=hex(linear_offset))
