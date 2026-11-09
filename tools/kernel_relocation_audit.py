#!/usr/bin/env python3
"""List aligned RAM-address values not explained by physical-relocation patches.

This is a review inventory, not evidence of relocation completeness: an integer
that looks like an address can be a size, instruction bytes, or stale data. Each
physical page is listed once, with every mapped alias and every unexplained word.
"""
import argparse
import bisect
import collections
import json
import struct
from pathlib import Path


def inventory(ram, patches, symbols=()):
    aliases=collections.defaultdict(list)
    for upper in (0,1):
        for va,pa,_ in ram.mappings(upper)[0]:aliases[pa].append(va)
    objects=sorted((s['value'],s['value']+s['size'],s['name']) for s in symbols
                   if s.get('type')==1 and s['value'] and s.get('size'))
    starts=[lo for lo,_,_ in objects]
    pages=[];explained=0;unexplained=0
    for pa in range(ram.base,ram.base+ram.size,4096):
        words=[]
        for offset,(value,) in enumerate(struct.iter_unpack('<Q',ram.page(pa))):
            if not ram.base<=value<=ram.base+ram.size:continue
            at=pa+offset*8
            if at in patches:
                explained+=1;continue
            row=dict(offset=hex(offset*8),value=hex(value));owners=[]
            for alias in aliases[pa]:
                va=alias+offset*8;i=bisect.bisect_right(starts,va)-1
                if i>=0 and va<objects[i][1]:owners.append('%s+0x%x'%(objects[i][2],va-objects[i][0]))
            if owners:row['objects']=owners
            words.append(row)
        if words:
            unexplained+=len(words)
            pages.append(dict(pa=hex(pa),aliases=[hex(va) for va in aliases[pa]],words=words))
    return dict(format='osrec-relocation-review-v1',scope='8-byte aligned physical-address candidates; RAM end inclusive',
                explained_words=explained,unexplained_words=unexplained,unexplained_pages=len(pages),pages=pages)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dump',required=True);p.add_argument('--vmlinux',required=True);p.add_argument('--dwarf-db',required=True)
    p.add_argument('--delta',type=lambda s:int(s,0),default=0x40000000);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    from source_image import Ram
    from kernel_source_verify import Elf
    from kernel_dwarf_db import load
    from ram_relocation import relocate
    ram=Ram(a.dump);image=Elf(a.vmlinux)
    symbols={s['name']:s['value'] for s in image.symbols if s['value']}
    patches,summary=relocate(ram,symbols,load(a.dwarf_db),a.delta)
    result=inventory(ram,patches,image.symbols);result['relocation']=summary
    result['dump']=str(Path(a.dump).resolve());result['vmlinux']=str(Path(a.vmlinux).resolve())
    a.out.write_text(json.dumps(result,indent=1)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='pages'}))


if __name__=='__main__':main()
