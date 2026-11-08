#!/usr/bin/env python3
"""Program-view manifest: the captured user process as its kernel describes it.

In an executable checkpoint the program's memory is RAM pages the kernel already holds; the runtime maps each one
at its user virtual address as the kernel's own user page tables say. This tool reads that view from a state dump
(kernel_state_dump.py), the DWARF database (kernel_dwarf_db.py) and vmlinux:

- the task: `current` (the per-CPU __entry_task at the SVC entry), pid, comm, mm; mm->pgd checked against TTBR0;
- the VMAs: the mm's maple tree (mm_mt), each with range, flags, backing file and page offset;
- the pages: every valid user leaf of the TTBR0 tables, with its physical page, offset in the RAM image and EL0
  permissions (hardware read-only plus the software write bit: Linux maps clean writable pages read-only);
- the backing of each page from its struct page (found through the sparse section map): page cache (file),
  anonymous, or the shared zero page;
- checks: every mapped page lies in a VMA of its mm; VMAs with no mapped page yet are listed (they fault in later).

Layouts come from DWARF; a member offset is used only when every definition of its type agrees on it.
"""
import argparse,json,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from kernel_dwarf_db import load
from kernel_source_verify import Elf
from source_image import Ram

PAGE=4096
VM_FLAGS={0x1:'read',0x2:'write',0x4:'exec',0x8:'shared',0x100:'growsdown',0x800:'denywrite'}
PTE_VALID,PTE_AF,PTE_USER,PTE_RDONLY,PTE_DBM,PTE_UXN=1,1<<10,1<<6,1<<7,1<<51,1<<54


class Layout:
    """Member offsets from the DWARF database, through anonymous structs and unions."""
    def __init__(self,db):
        self.types=db['types']
    def definitions(self,key):
        d=self.types.get(key)
        if not d:raise KeyError('no type '+key)
        return d['definitions'] if 'definitions' in d else [d]
    def _find(self,record,name):
        for mname,bits,width,mkey in record['members']:
            if mname==name:return bits//8,mkey
            if mname=='' and (mkey.startswith('anon:') or mkey.startswith(('struct:','union:'))):
                inner=self.types.get(mkey)
                if not inner:continue
                for r in (inner['definitions'] if 'definitions' in inner else [inner]):
                    found=self._find(r,name)
                    if found:return bits//8+found[0],found[1]
        return None
    def offset(self,key,path):
        """Byte offset of a dotted member path; every definition of each record must agree."""
        total=0
        for name in path.split('.'):
            found=[f for f in (self._find(r,name) for r in self.definitions(key)) if f]
            offsets={off for off,_ in found}
            if len(offsets)!=1:raise ValueError('%s.%s: %s'%(key,name,'absent' if not found else 'definitions disagree on its offset'))
            # The member's type key may be spelled differently in different units (ptr:? for a recursive one).
            off=offsets.pop();key=next((k for _,k in found if '?' not in k),found[0][1]);total+=off
            while key.startswith('typedef:'):key=self.types[key]['target']
        return total
    def size(self,key):
        sizes={r['size'] for r in self.definitions(key)}
        if len(sizes)!=1:raise ValueError(key+': sizes disagree')
        return sizes.pop()


class Memory:
    """Kernel virtual memory of the dump, through the live TTBR1 tables."""
    def __init__(self,ram):
        self.ram=ram;leaves,_=ram.mappings(1);self.va2pa={va:pa for va,pa,_ in leaves}
    def pa(self,va):
        va&=(1<<64)-1;p=self.va2pa.get(va&~0xfff);return None if p is None else p+(va&0xfff)
    def read(self,va,n):
        pa=self.pa(va)
        if pa is None or (va&0xfff)+n>PAGE:raise ValueError('unmapped or page-crossing read at 0x%x'%va)
        o=pa-self.ram.base;return self.ram.ram[o:o+n]
    def q(self,va):return struct.unpack('<Q',self.read(va,8))[0]
    def i32(self,va):return struct.unpack('<i',self.read(va,4))[0]
    def cstring(self,va,limit=256):
        out=b''
        while len(out)<limit:
            chunk=self.read(va+len(out),min(16,PAGE-((va+len(out))&0xfff)))
            if b'\0' in chunk:return (out+chunk[:chunk.index(b'\0')]).decode(errors='replace')
            out+=chunk
        return out.decode(errors='replace')


def maple_entries(mem,lay,root):
    """[(first, last, entry)] of a maple tree's leaves (6.10 node formats, layouts from DWARF)."""
    r64_pivot=lay.offset('struct:maple_range_64','pivot');r64_slot=r64_pivot+15*8  # slot[16] follows pivot[15]
    a64_pivot=lay.offset('struct:maple_arange_64','pivot');a64_slot=lay.offset('struct:maple_arange_64','slot')
    out=[]
    def is_node(e):return e&3==2 and e>4096
    def walk(entry,lo,hi,depth):
        if depth>8:raise ValueError('maple tree deeper than expected')
        node=entry&~0xff;kind=(entry>>3)&0xf
        if kind in (1,2):pivots,slots,count=r64_pivot,r64_slot,16    # maple_leaf_64, maple_range_64
        elif kind==3:pivots,slots,count=a64_pivot,a64_slot,10        # maple_arange_64
        else:raise ValueError('unsupported maple node type %d'%kind)
        first=lo
        for i in range(count):
            pivot=mem.q(node+pivots+8*i) if i<count-1 else hi
            if i>0 and pivot==0:break
            last=min(pivot,hi);slot=mem.q(node+slots+8*i)
            if slot:
                if kind==1:out.append((first,last,slot))
                else:walk(slot,first,last,depth+1)
            if last>=hi:break
            first=last+1
    if not root:return out
    if is_node(root):walk(root,0,(1<<64)-1,0)
    else:out.append((0,0,root))
    return out


def build(dump,vmlinux,dwarf_db):
    ram=Ram(dump);mem=Memory(ram);lay=Layout(load(dwarf_db))
    e=Elf(vmlinux);sym={}
    for s in e.symbols:
        if s['value'] and s['name']:sym.setdefault(s['name'],s['value'])
    tp=ram.sysregs['TPIDR_EL1'];task=mem.q(sym['__entry_task']+tp)
    T='struct:task_struct'
    pid=mem.i32(task+lay.offset(T,'pid'));comm=mem.cstring(task+lay.offset(T,'comm'),16);mm=mem.q(task+lay.offset(T,'mm'))
    M='struct:mm_struct'
    pgd=mem.q(mm+lay.offset(M,'pgd'));pgd_pa=mem.pa(pgd)
    checks={'mm_pgd_matches_ttbr0':pgd_pa==ram.roots[0]}
    # VMAs from the maple tree.
    V='struct:vm_area_struct'
    o_start,o_end,o_flags=lay.offset(V,'vm_start'),lay.offset(V,'vm_end'),lay.offset(V,'vm_flags')
    o_file,o_pgoff,o_anon=lay.offset(V,'vm_file'),lay.offset(V,'vm_pgoff'),lay.offset(V,'anon_vma')
    o_dentry=lay.offset('struct:file','f_path.dentry');o_name=lay.offset('struct:dentry','d_name.name')
    o_ops,o_private=lay.offset(V,'vm_ops'),lay.offset(V,'vm_private_data')
    special_ops=sym.get('special_mapping_vmops');o_special_name=lay.offset('struct:vm_special_mapping','name')
    vmas=[]
    for first,last,vma in maple_entries(mem,lay,mem.q(mm+lay.offset(M,'mm_mt.ma_root'))):
        start,end,flags=mem.q(vma+o_start),mem.q(vma+o_end),mem.q(vma+o_flags)
        if (start,end-1)!=(first,last):checks.setdefault('vma_ranges_match_tree',True);checks['vma_ranges_match_tree']=False
        f=mem.q(vma+o_file);name=None
        special=None
        if f:name=mem.cstring(mem.q(mem.q(f+o_dentry)+o_name))
        elif special_ops and mem.q(vma+o_ops)==special_ops:special=mem.cstring(mem.q(mem.q(vma+o_private)+o_special_name))
        vmas.append(dict(special=special,start=start,end=end,flags=[n for b,n in VM_FLAGS.items() if flags&b],vm_flags=hex(flags),
                         file=name,pgoff=mem.q(vma+o_pgoff),anon_vma=bool(mem.q(vma+o_anon)),pages=0))
    checks.setdefault('vma_ranges_match_tree',True)
    starts=[v['start'] for v in vmas]
    # struct page of a physical page through the sparse sections (SPARSEMEM_EXTREME, vmemmap encoding).
    page_size=lay.size('struct:page');o_mapping=lay.offset('struct:page','mapping')
    ms_size=lay.size('struct:mem_section');roots=mem.q(sym['mem_section']);per_root=PAGE//ms_size
    zero_pfn=mem.q(sym['zero_pfn'])
    def struct_page(pa):
        pfn=pa>>12;nr=pa>>27;root=mem.q(roots+8*(nr//per_root))
        encoded=mem.q(root+(nr%per_root)*ms_size)&~0x3f
        return (encoded+pfn*page_size)&((1<<64)-1)
    import bisect
    leaves,_=ram.mappings(0);pages=[];kinds={}
    for va,pa,d in leaves:
        i=bisect.bisect_right(starts,va)-1;v=vmas[i] if i>=0 and va<vmas[i]['end'] else None
        if v:v['pages']+=1
        if pa>>12==zero_pfn:kind='zero page'
        else:
            mapping=mem.q(struct_page(pa)+o_mapping)
            kind='anonymous' if mapping&1 else 'file' if mapping else 'unattached'
        kinds[kind]=kinds.get(kind,0)+1
        hw_ro=bool(d&PTE_RDONLY)
        pages.append(dict(va=hex(va),pa=hex(pa),ram_offset=hex(pa-ram.base),
                          read=bool(d&PTE_USER),write=not hw_ro,sw_write=bool(d&PTE_DBM) or not hw_ro,exec=not d&PTE_UXN,
                          accessed=bool(d&PTE_AF),kind=kind,vma=i if v else None))
    checks['pages_in_vmas']=all(p['vma'] is not None for p in pages)
    summary=dict(task=hex(task),pid=pid,comm=comm,mm=hex(mm),ttbr0=hex(ram.roots[0]),vmas=len(vmas),pages=len(pages),
                 by_kind=kinds,vmas_without_pages=sum(1 for v in vmas if not v['pages']),checks=checks)
    for v in vmas:v['start'],v['end']=hex(v['start']),hex(v['end'])
    return dict(format='osrec-program-view-v1',dump=str(Path(dump).resolve()),summary=summary,vmas=vmas,pages=pages)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dump',required=True);p.add_argument('--vmlinux',required=True);p.add_argument('--dwarf-db',required=True)
    p.add_argument('--out',required=True)
    a=p.parse_args();view=build(a.dump,a.vmlinux,a.dwarf_db)
    Path(a.out).write_text(json.dumps(view,indent=1)+'\n')
    print(json.dumps(view['summary'],indent=1))
    for v in view['vmas']:print('  %s-%s %-28s %-10s pages=%d'%(v['start'],v['end'],'/'.join(v['flags']),v['file'] or v['special'] or ('anon' if v['anon_vma'] else '-'),v['pages']))
    for pg in view['pages']:print('  page %s -> pa %s  %s%s%s  %-9s vma %s'%(pg['va'],pg['pa'],'r' if pg['read'] else '-','w' if pg['sw_write'] else '-','x' if pg['exec'] else '-',pg['kind'],pg['vma']))


if __name__=='__main__':main()
