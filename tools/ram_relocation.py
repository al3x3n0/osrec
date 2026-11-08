#!/usr/bin/env python3
"""Patches that move an arm64 Linux post-boot state's RAM by DELTA, without a typed walk.

Virtual addresses stay the live kernel's: memstart_addr + DELTA and kimage_voffset - DELTA keep the linear map,
the kernel image and vmemmap where they are. What changes is stored physical addresses and frame numbers, here
from a fixed list:

- translation tables, structurally: every descriptor reachable from TTBR1, TTBR0 and the kernel's static roots
  whose output address is in RAM;
- named variables (frame-number globals, the DMA limit, the highest present section);
- named records, field by field from DWARF: phys_addr_t/resource_size_t members (not sizes) and members named
  *pfn* in contig_page_data (with its zones), memblock and its regions, the iomem resource tree, the default
  swiotlb pool;
- the sparse sections: each present entry moves by DELTA's section count, its encoded memory map changes by
  -(DELTA >> 12) * sizeof(struct page).

A value is changed only when it lies in the old RAM range (end inclusive). DELTA must be a multiple of the section
size. Patches are (physical address, old value, new value, reason), all on old physical addresses.
"""
import struct

PHYS={'typedef:phys_addr_t','typedef:resource_size_t','typedef:dma_addr_t'};SECTION_BITS=27


class Patcher:
    def __init__(self,ram,symbols,db,delta):
        if delta%(1<<SECTION_BITS):raise ValueError('DELTA must be a multiple of the 128 MiB section size')
        self.ram=ram;self.sym=symbols;self.types=db['types'];self.delta=delta;self.patches={}
        leaves,_=ram.mappings(1);self.va2pa={va:pa for va,pa,_ in leaves}
        self.lo=ram.base;self.hi=ram.base+ram.size
    def pa(self,va):
        va&=(1<<64)-1;p=self.va2pa.get(va&~0xfff);return None if p is None else p+(va&0xfff)
    def q(self,pa):return self.ram.q(pa)
    def set(self,pa,new,why):
        old=self.q(pa)
        if old!=new:self.patches[pa]=(old,new,why)
    def shift(self,va,why,pfn=False):
        """Relocate one 8-byte value at a virtual address if it lies in RAM."""
        pa=self.pa(va)
        if pa is None:return
        v=self.q(pa);lo,hi,d=(self.lo>>12,self.hi>>12,self.delta>>12) if pfn else (self.lo,self.hi,self.delta)
        if v is not None and lo<=v<=hi:self.set(pa,v+d,why)
    # Translation tables.
    def tables(self,roots):
        seen=set()
        def walk(table,level):
            if table in seen or not self.lo<=table<self.hi:return
            seen.add(table)
            for i in range(512):
                d=self.q(table+8*i)
                if not d or not d&1:continue
                out=d&0x0000fffffffff000
                if level<3 and not d&2 and self.delta%(1<<(12+9*(3-level))):
                    raise ValueError('DELTA breaks the alignment of a level-%d block mapping'%level)
                if self.lo<=out<self.hi:self.set(table+8*i,d+self.delta,'table entry')
                if level<3 and d&2:walk(out,level+1)
        for r in roots:walk(r,0)
        return len(seen)
    # Records, from DWARF.
    def record(self,key):
        d=self.types.get(key)
        if not d:return None
        if 'definitions' in d:
            # Definitions that agree on size and member placement are one layout (nested keys may be spelled
            # differently in different units).
            defs=d['definitions'];shape=lambda x:(x['size'],[(m[0],m[1],m[2]) for m in x['members']])
            return defs[0] if all(shape(x)==shape(defs[0]) for x in defs) else None
        return d if 'members' in d else None
    def underlying(self,key):
        names=[]
        while key.startswith('typedef:'):
            names.append(key);d=self.types.get(key)
            if not d:break
            key=d['target']
        return names,key
    def size(self,key):
        names,key=self.underlying(key)
        if key.startswith(('base:','enum:')):return int(key.rsplit(':',1)[1])
        if key.startswith('ptr:'):return 8
        if key.startswith('array:'):
            inner,count=key[6:].rsplit(':',1);return self.size(inner)*int(count)
        r=self.record(key);return r['size'] if r else 0
    def fields(self,key,va,why):
        """Relocate phys-typed and *pfn* members of the record at va (embedded records and arrays included)."""
        names,base=self.underlying(key)
        if base.startswith('array:'):
            inner,count=base[6:].rsplit(':',1);step=self.size(inner)
            for i in range(int(count)):self.fields(inner,va+i*step,why)
            return
        r=self.record(base)
        if not r or r['kind']=='union':return
        for name,bits,width,mkey in r['members']:
            if width or bits%8:continue
            at=va+bits//8;mnames,mbase=self.underlying(mkey)
            if mbase.startswith(('struct:','anon:','array:')):self.fields(mkey,at,why+'.'+name);continue
            if self.size(mkey)!=8:continue
            if PHYS&set(mnames) and 'size' not in name and 'len' not in name:self.shift(at,why+'.'+name)
            elif 'pfn' in name and mbase.startswith('base:'):self.shift(at,why+'.'+name,pfn=True)
    def member(self,key,name):
        r=self.record(self.underlying(key)[1])
        return next((m for m in r['members'] if m[0]==name),None) if r else None


def relocate(ram,symbols,db,delta):
    """{old physical address: (old, new, reason)} and a summary."""
    p=Patcher(ram,symbols,db,delta);var={v[0]:v for v in db['variables']}
    s=lambda n:symbols[n]
    tables=p.tables([ram.roots[1],ram.roots[0]]+[p.pa(s(n)) for n in ('idmap_pg_dir','tramp_pg_dir','reserved_pg_dir') if n in symbols])
    p.set(p.pa(s('memstart_addr')),p.q(p.pa(s('memstart_addr')))+delta,'memstart_addr')
    p.set(p.pa(s('kimage_voffset')),(p.q(p.pa(s('kimage_voffset')))-delta)&((1<<64)-1),'kimage_voffset')
    # Scalar static variables: 8-byte integers named *pfn*, and phys_addr_t/resource_size_t/dma_addr_t scalars.
    for name,address,key,size in db['variables']:
        if size!=8 or not name:continue
        names,base=p.underlying(key)
        if not base.startswith('base:'):continue
        if PHYS&set(names) and 'size' not in name and 'len' not in name:p.shift(address,name)
        elif 'pfn' in name:p.shift(address,name,pfn=True)
    if '__highest_present_section_nr' in symbols:
        a=p.pa(s('__highest_present_section_nr'));p.set(a,p.q(a)+(delta>>SECTION_BITS),'__highest_present_section_nr')
    for n in ('contig_page_data','io_tlb_default_mem'):
        if n in var:p.fields(var[n][2],var[n][1],n)
    # memblock: the record, then each region of both types.
    mb=var['memblock'];p.fields(mb[2],mb[1],'memblock')
    region=p.record('struct:memblock_region')
    for t in ('memory','reserved'):
        m=p.member(mb[2],t);tkey=m[3];base=mb[1]+m[1]//8
        cnt=p.q(p.pa(base+p.member(tkey,'cnt')[1]//8))&0xffffffffffffffff
        regions=p.q(p.pa(base+p.member(tkey,'regions')[1]//8))
        for i in range(cnt):p.fields('struct:memblock_region',regions+i*region['size'],'memblock.%s[%d]'%(t,i))
    # The iomem resource tree (child and sibling links).
    rkey='struct:resource';child=p.member(rkey,'child')[1]//8;sibling=p.member(rkey,'sibling')[1]//8
    stack=[s('iomem_resource')];resources=0
    while stack:
        r=stack.pop()
        if not r or p.pa(r) is None:continue
        resources+=1;p.fields(rkey,r,'resource')
        stack+=[p.q(p.pa(r+child)),p.q(p.pa(r+sibling))]
    # Sparse sections (SPARSEMEM_EXTREME): move entries and re-encode their memory map.
    ms=p.record('struct:mem_section');page=p.size('struct:page');per_root=4096//ms['size']
    root_array=p.q(p.pa(s('mem_section')));moved=0
    shift=delta>>SECTION_BITS
    entries=[]
    for nr in range(p.lo>>SECTION_BITS,(p.hi-1>>SECTION_BITS)+1):
        root=p.q(p.pa(root_array+8*(nr//per_root)))
        entries.append((nr,root+(nr%per_root)*ms['size']))
    for nr,va in entries:
        new=nr+shift
        if new//per_root!=nr//per_root:raise ValueError('sections would move to another root array')
        target=va+shift*ms['size'];words=[p.q(p.pa(va+8*k)) for k in range(ms['size']//8)]
        words[0]=(words[0]-(delta>>12)*page)&((1<<64)-1)
        for k,w in enumerate(words):p.set(p.pa(target+8*k),w,'mem_section[%d] <- [%d]'%(new,nr))
    for nr,va in entries:
        if nr-shift<p.lo>>SECTION_BITS or nr-shift>(p.hi-1)>>SECTION_BITS:
            for k in range(ms['size']//8):p.set(p.pa(va+8*k),0,'mem_section[%d] cleared'%nr)
        moved+=1
    summary=dict(delta=hex(delta),table_pages=tables,resources=resources,sections_moved=moved,patches=len(p.patches),
                 by_reason={})
    for _,(_,_,why) in p.patches.items():
        k=why.split('[')[0].split('.')[0] if not why.startswith('memblock') else 'memblock';summary['by_reason'][k]=summary['by_reason'].get(k,0)+1
    return p.patches,summary
