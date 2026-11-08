#!/usr/bin/env python3
"""Virtual relocation of a post-boot arm64 Linux state, step A: the linear map (and vmemmap with it).

The kernel derives linear addresses from a variable: VA = PA - memstart_addr + PAGE_OFFSET, and struct page
addresses as VMEMMAP_START - (memstart_addr >> PAGE_SHIFT) * sizeof(struct page) + pfn * sizeof(struct page). So
memstart_addr - OFFSET moves the whole linear map up by OFFSET and vmemmap by OFFSET / PAGE_SIZE * sizeof(struct
page), with no code change. What else must follow:

- per-CPU offsets (a linear address minus an image address): __per_cpu_offset[] and TPIDR_EL1, + OFFSET;
- stored pointers: every 8-byte value in the used linear map (one page past its end included: end pointers such as
  high_memory) + OFFSET, every value in the used vmemmap (one struct page past its end) + the vmemmap offset;
  scanned in all kernel data pages, never in text, translation tables or the user program's pages (user data);
- the kernel's own TTBR1 tables: OFFSET and the vmemmap offset must be multiples of the top-level entry size, so
  their top-level entries move as a whole;
- the CPU state: the kernel stack pointer (stacks are in the linear map without VMAP_STACK);
- per-CPU pointers into chunks the allocator placed in vmalloc space: every per-CPU address is ptr +
  __per_cpu_offset[cpu]; the offset grows by OFFSET for the first chunk (linear map), so a stored ptr whose old
  sum lands in a vmalloc-backed chunk is lowered by OFFSET and keeps addressing the same place. Chunks come from
  the allocator's own lists (pcpu_chunk_lists, base_addr, pcpu_unit_offsets, pcpu_unit_size; layouts from DWARF).

Values in a region but outside its used part are left and counted. Tables keyed by addresses (dentry, mount,
mountpoint and inode hashes) are rehashed by va_rehash.py; waiter tables must be empty.
"""
import struct

PAGE=4096


def plan(ram,symbols,profile,offset,struct_page=64):
    """Offsets, used extents and the VA map of step A."""
    p={k:int(v,16) for k,v in profile['parameters'].items()}
    top=p['PGDIR_SIZE'];vm_offset=offset//PAGE*struct_page
    if offset%top or vm_offset%top:raise ValueError('linear offset %#x: it and its vmemmap offset %#x must be multiples of %#x'%(offset,vm_offset,top))
    leaves,tables=ram.mappings(1)
    lin=sorted(va for va,_,_ in leaves if p['PAGE_OFFSET']<=va<p['PAGE_END'])
    vmm=sorted(va for va,_,_ in leaves if p['VMEMMAP_START']<=va<p['VMEMMAP_END'])
    extents=dict(linear=(lin[0],lin[-1]+2*PAGE),vmemmap=(vmm[0],vmm[-1]+PAGE+struct_page))
    if lin[-1]+offset>=p['PAGE_END'] or vmm[-1]+vm_offset>=p['VMEMMAP_END']:raise ValueError('relocated region leaves its range')
    def move(va):
        if p['PAGE_OFFSET']<=va<p['PAGE_END']:return va+offset
        if p['VMEMMAP_START']<=va<p['VMEMMAP_END']:return va+vm_offset
        return va
    return dict(offset=offset,vm_offset=vm_offset,extents=extents,move=move,leaves=leaves,tables=tables,top=top,params=p)


def relocate(ram,symbols,profile,offset,user_pas,db):
    """{physical address: (old, new, reason)} on the old layout, the VA map, new CPU registers, and a summary."""
    pl=plan(ram,symbols,profile,offset);patches={}
    p_lin=lambda va:pl['params']['PAGE_OFFSET']<=va<pl['params']['PAGE_END']
    leaves,tables=pl['leaves'],set(pl['tables']);va2pa={va:pa for va,pa,_ in leaves}
    def pa(va):
        va&=(1<<64)-1;p=va2pa.get(va&~0xfff);return None if p is None else p+(va&0xfff)
    def q(a):return ram.q(a)
    def put(a,new,why):
        old=q(a)
        if old!=new:patches[a]=(old,new,why)
    # Formula variables.
    a=pa(symbols['memstart_addr']);put(a,(q(a)-offset)&((1<<64)-1),'memstart_addr')
    pco=symbols['__per_cpu_offset'];ncpu=8 if 'nr_cpu_ids' not in symbols else max(1,ram.q(pa(symbols['nr_cpu_ids']))&0xffffffff)
    for i in range(ncpu):
        a=pa(pco+8*i);put(a,(q(a)+offset)&((1<<64)-1),'__per_cpu_offset[%d]'%i)
    # Per-CPU chunks in vmalloc space (the first chunk is in the linear map and moves with it).
    from program_view import Layout
    lay=Layout(db);o_list,o_base=lay.offset('struct:pcpu_chunk','list'),lay.offset('struct:pcpu_chunk','base_addr')
    def i32(sym):return q(pa(symbols[sym]))&0xffffffff
    unit_size=i32('pcpu_unit_size');unit0=q(pa(q(pa(symbols['pcpu_unit_offsets']))));off0=q(pa(pco))
    lists=q(pa(symbols['pcpu_chunk_lists']));chunks=set()
    for i in range(i32('pcpu_nr_slots')+2):
        head=lists+16*i;node=q(pa(head));steps=0
        while node and node!=head and steps<10000:chunks.add(node-o_list);node=q(pa(node));steps+=1
    for sym in ('pcpu_first_chunk','pcpu_reserved_chunk'):
        c=q(pa(symbols[sym]))
        if c:chunks.add(c)
    vm_chunks=[]
    for c in chunks:
        base=q(pa(c+o_base));lo=(base+unit0)&((1<<64)-1)
        if not p_lin(lo):vm_chunks.append((lo,lo+unit_size))
    vm_chunks.sort()
    text_lo,text_hi=symbols['_stext'],symbols['_etext']
    (l0,l1),(v0,v1)=pl['extents']['linear'],pl['extents']['vmemmap']
    counts=dict(linear=0,vmemmap=0,percpu_vmalloc_chunk=0,linear_outside_used=0,vmemmap_outside_used=0)
    import bisect
    vm_starts=[a for a,_ in vm_chunks]
    def in_vm_chunk(v):
        x=(v+off0)&((1<<64)-1);i=bisect.bisect_right(vm_starts,x)-1
        return i>=0 and x<vm_chunks[i][1]
    p=pl['params'];seen=set()
    for va,ppa,_ in leaves:
        if ppa in seen or ppa in tables or ppa in user_pas or text_lo<=va<text_hi:continue
        seen.add(ppa);data=ram.page(ppa)
        if data is None or data==bytes(PAGE):continue
        for k,(w,) in enumerate(struct.iter_unpack('<Q',data)):
            if w and vm_chunks and in_vm_chunk(w):
                put(ppa+8*k,(w-offset)&((1<<64)-1),'per-CPU pointer into a vmalloc chunk');counts['percpu_vmalloc_chunk']+=1;continue
            if w>>48!=0xffff:continue
            if l0<=w<l1:put(ppa+8*k,w+offset,'linear pointer');counts['linear']+=1
            elif v0<=w<v1:put(ppa+8*k,w+pl['vm_offset'],'vmemmap pointer');counts['vmemmap']+=1
            elif p['PAGE_OFFSET']<=w<p['PAGE_END']:counts['linear_outside_used']+=1
            elif p['VMEMMAP_START']<=w<p['VMEMMAP_END']:counts['vmemmap_outside_used']+=1
    # The kernel's own TTBR1 tables: move the top-level entries of both regions.
    root=ram.roots[1];shift=12+9*(3-ram.start(1));moved=0
    def index(va):return (va>>shift)&((1<<(ram.bits[1]-shift))-1)
    for lo,hi,off in ((l0,l1,offset),(v0,v1,pl['vm_offset'])):
        for i in sorted({index(va) for va in range(lo,hi,1<<shift)}|{index(hi-1)}):
            j=i+off//pl['top']
            if q(root+8*j) and root+8*j not in patches:raise ValueError('top-level entry %d is in use'%j)
            put(root+8*j,q(root+8*i),'TTBR1 top-level entry %d <- %d'%(j,i))
            if root+8*i not in patches:put(root+8*i,0,'TTBR1 top-level entry %d cleared'%i)
            moved+=1
    # Tables keyed by addresses that moved: rehashed (overriding the plain pointer shifts of their links).
    from va_rehash import rehash
    lookup=next((x[3] for x in db['variables'] if x[0]=='in_lookup_hashtable'),8192)//8
    rehashed=rehash(lambda a:ram.q(a),pa,pl['move'],lambda a,v,why:patches.__setitem__(a,(q(a),v,why)),lay,lambda n:symbols[n],lookup)
    cpu=dict(sp=pl['move'](ram.state['cpu']['sp']),TPIDR_EL1=(ram.sysregs['TPIDR_EL1']+offset)&((1<<64)-1))
    summary=dict(offset=hex(offset),vmemmap_offset=hex(pl['vm_offset']),pointers=counts,
                 percpu_vmalloc_chunks=[(hex(a),hex(b)) for a,b in vm_chunks],rehashed=rehashed,top_level_entries_moved=moved,patches=len(patches),
                 )
    return patches,pl['move'],cpu,summary
