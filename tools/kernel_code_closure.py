#!/usr/bin/env python3
"""Static code closure of kernel entry points over the linked AArch64 kernel (vmlinux).

Functions are vmlinux symbols (FUNC with st_size; assembler symbols extend to the next symbol). Edges are read
from the linked instructions themselves, so they are exact for direct control flow:

- `bl` targets (calls) and `b` targets outside the function (tail calls);
- `adrp` + `add`/`ldr` and `adr` address constants: a function start is an address-taken function (a candidate
  indirect-call target, not followed here); anything else names a data object the code references (a state root).

The report gives the closure from the roots (functions, bytes, translation units), the address-taken functions and
data roots it references, and for the largest subtrees how much of the closure each one alone accounts for (what
cutting it at the boundary would remove).
"""
import argparse,bisect,collections,json,re,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from kernel_source_verify import Elf

STT_FUNC,STT_OBJECT,STT_NOTYPE=2,1,0


def sign(v,bits):return v-(1<<bits) if v>>(bits-1)&1 else v


class Code:
    def __init__(self,vmlinux):
        self.elf=Elf(vmlinux)
        text=[s for s in self.elf.sections if s['name'] in ('.text',)][0]
        self.text=(text['addr'],text['addr']+text['size'])
        symbols=[s for s in self.elf.symbols if s['shndx'] and s['value'] and s['name'] and not s['name'].startswith('$')]
        funcs={}
        for s in symbols:
            if self.text[0]<=s['value']<self.text[1] and s['type'] in (STT_FUNC,STT_NOTYPE):
                if s['type']==STT_FUNC or s['value'] not in funcs:funcs[s['value']]=s
        self.starts=sorted(funcs);self.funcs=funcs
        self.data=sorted((s['value'],s['size'],s['name']) for s in symbols if s['type']==STT_OBJECT)
        self.data_starts=[d[0] for d in self.data]
        self.words=self.elf.read(self.text[0],self.text[1]-self.text[0])
    def extent(self,address):
        s=self.funcs[address];i=bisect.bisect_right(self.starts,address)
        end=self.starts[i] if i<len(self.starts) else self.text[1]
        return address,(address+s['size'] if s['type']==STT_FUNC and s['size'] else end)
    def name(self,address):return self.funcs[address]['name']
    def containing(self,address):
        i=bisect.bisect_right(self.starts,address)-1
        return self.starts[i] if i>=0 else None
    def data_object(self,address):
        """(address, size, name) of the data symbol holding `address`, or None."""
        i=bisect.bisect_right(self.data_starts,address)-1
        if i>=0:
            a,size,name=self.data[i]
            if a<=address<a+max(size,1):return self.data[i]
        return None
    def edges(self,address):
        """(calls, address-taken functions, data addresses) of one function."""
        low,high=self.extent(address);calls=set();taken=set();data=set();pages={}
        for pc in range(low,high,4):
            w,=struct.unpack_from('<I',self.words,pc-self.text[0])
            if w&0xfc000000 in (0x94000000,0x14000000):
                target=pc+4*sign(w&0x03ffffff,26)
                if w>>26==0x25 or not low<=target<high:
                    f=self.containing(target)
                    if f is not None and self.text[0]<=target<self.text[1]:calls.add(f)
            elif w&0x9f000000==0x90000000:  # adrp
                imm=sign((w>>29&3)|(w>>5&0x7ffff)<<2,21);pages[w&31]=(pc&~0xfff)+(imm<<12)
            elif w&0x9f000000==0x10000000:  # adr
                self.constant(pc+sign((w>>29&3)|(w>>5&0x7ffff)<<2,21),taken,data)
            elif w&0xff800000==0x91000000 and (w>>5&31) in pages:  # add Xd, Xn, #imm
                self.constant(pages[w>>5&31]+(w>>10&0xfff),taken,data)
            elif w&0x3b400000==0x39400000 and (w>>5&31) in pages:  # ldr/ldrb/... unsigned offset from an adrp base
                size=w>>30;self.constant(pages[w>>5&31]+((w>>10&0xfff)<<size),taken,data)
        return calls,taken,data
    def constant(self,address,taken,data):
        if self.text[0]<=address<self.text[1]:
            if address in self.funcs:taken.add(address)
        else:data.add(address)


def closure(graph,roots,cut=frozenset()):
    seen=set();stack=[r for r in roots if r not in cut]
    while stack:
        f=stack.pop()
        if f in seen:continue
        seen.add(f);stack+=[g for g in graph[f] if g not in seen and g not in cut]
    return seen


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--vmlinux',type=Path,required=True);p.add_argument('--root',action='append',required=True)
    p.add_argument('--cut',action='append',default=[],help='function treated as a boundary (not followed)')
    p.add_argument('--cut-pattern',action='append',default=[],help='regular expression: matching functions are boundaries')
    p.add_argument('--hubs',type=int,default=40);p.add_argument('--out',type=Path)
    a=p.parse_args()
    code=Code(a.vmlinux);by_name={}
    for addr,s in code.funcs.items():by_name.setdefault(s['name'],addr)
    missing=[r for r in a.root+a.cut if r not in by_name]
    if missing:p.error('unknown functions: '+', '.join(missing))
    graph={};taken={};data={};stack=[by_name[r] for r in a.root]
    while stack:
        f=stack.pop()
        if f in graph:continue
        calls,t,d=code.edges(f);graph[f]=calls;taken[f]=t;data[f]=d;stack+=[g for g in calls if g not in graph]
    roots=[by_name[r] for r in a.root]
    cut=frozenset({by_name[c] for c in a.cut}|{f for f in graph if any(re.fullmatch(x,code.name(f)) for x in a.cut_pattern)})
    full=closure(graph,roots,cut)
    size=lambda fs:sum(code.extent(f)[1]-code.extent(f)[0] for f in fs)
    # How much of the closure exists only through each function: closure size minus the closure with it cut.
    reach={f:len(closure(graph,[f],cut)) for f in full}
    candidates=sorted((f for f in full if f not in roots),key=lambda f:-reach[f])[:4*a.hubs]
    hubs=[]
    for f in candidates:
        rest=closure(graph,roots,cut|{f});only=full-rest
        hubs.append(dict(function=code.name(f),reach=reach[f],only_through=len(only),only_bytes=size(only)))
    hubs.sort(key=lambda h:-h['only_through']);hubs=hubs[:a.hubs]
    address_taken=set().union(*(taken[f] for f in full))
    data_roots={};unnamed=set()
    for f in full:
        for d in data[f]:
            o=code.data_object(d)
            if o:data_roots[o[0]]=dict(name=o[2],address=o[0],size=o[1])
            else:unnamed.add(d)
    report=dict(roots=a.root,cut=a.cut,functions=len(full),bytes=size(full),
                address_taken=len(address_taken),address_taken_outside=len(address_taken-full),data_objects=len(data_roots),
                unnamed_data_addresses=len(unnamed),hubs=hubs,closure=sorted(code.name(f) for f in full),cut_functions=sorted(code.name(f) for f in cut),
                address_taken_functions=sorted(code.name(f) for f in address_taken),
                data_roots=sorted(data_roots.values(),key=lambda d:d['address']),unnamed_data=sorted(hex(d) for d in unnamed))
    text=json.dumps(report,indent=1)
    if a.out:a.out.write_text(text+'\n')
    print(json.dumps({k:report[k] for k in ('functions','bytes','address_taken','address_taken_outside','data_objects','unnamed_data_addresses')}))
    for h in hubs:print('%-40s reach=%-6d only=%-6d bytes=%d'%(h['function'],h['reach'],h['only_through'],h['only_bytes']))


if __name__=='__main__':main()
