"""Construction-time address resolution and conservative user-code proofs.

No reference execution values or branch outcomes are used. Initial registers,
RAM and page tables belong to the checkpoint. Unknown abstract values lose an
optimization. Kernel returns must preserve the user registers assumed by this
analysis; the corresponding check runs at the architecture edge.
"""
from collections import deque
import bisect
import struct

from el0_flat_lower import *
from va_constants import bitmask

MASK=(1<<64)-1
PAGE_MASK=0x0000fffffffff000
LIMIT=32


def user_aliases(package,with_checks=False):
    bits=64-(package.h[4]&63)
    if package.h[4]>>14&3 or not 25<=bits<=48:raise ValueError('unsupported initial user tables')
    root=struct.unpack_from('<Q',package.shadow,72)[0]&PAGE_MASK
    leaves=[];checks={}
    table_mask=PAGE_MASK|3|(15<<59)
    leaf_mask=PAGE_MASK|0xfff|(3<<53)
    def walk(table,level,base,parent,ancestors,path):
        if table in ancestors:raise ValueError('cyclic captured page tables')
        if table<package.h[2] or table-package.h[2]>package.h[3]-4096:raise ValueError('page table outside RAM')
        shift=12+9*(3-level)
        entries=1<<(bits-shift) if level==3-(bits-13)//9 else 512
        for index in range(entries):
            d=struct.unpack_from('<Q',package.memory,table-package.h[2]+8*index)[0]
            if not d&1:continue
            va=base+(index<<shift)
            if level<3 and d&2:
                walk(d&PAGE_MASK,level+1,va,parent|d,ancestors|{table},path+[(table+8*index,table_mask,d)]);continue
            if level==0 or level==3 and not d&2:continue
            if not d&(1<<10) or not d&(1<<6) or parent&(1<<61):continue
            size=1<<shift;pa=(d&PAGE_MASK)&-size
            if pa<package.h[2] or size>package.h[3] or pa-package.h[2]>package.h[3]-size:continue
            if any(va<k+s and k<va+size for k,p,s,a in package.maps):continue
            if parent&(1<<62):d|=1<<7
            leaves.append(dict(va=va,pa=pa,bytes=size,attrs=d))
            raw=struct.unpack_from('<Q',package.memory,table-package.h[2]+8*index)[0]
            for at,mask,value in path+[(table+8*index,leaf_mask,raw)]:checks[at]=(at,mask,value)
    walk(root,3-(bits-13)//9,0,0,set(),[])
    aliases=sorted(leaves,key=lambda row:row['va'])
    return (aliases,[checks[at] for at in sorted(checks)]) if with_checks else aliases


class Bindings:
    def __init__(self,aliases,immutable):
        self.aliases=aliases;self.starts=[a['va'] for a in aliases];self.immutable=immutable
    def physical(self,va,size,write=False):
        i=bisect.bisect_right(self.starts,va)-1
        if i<0:return None
        row=self.aliases[i];off=va-row['va']
        if off<0 or size>row['bytes']-off or write and row['attrs']&(1<<7):return None
        pa=row['pa']+off
        if write and any(pa<lo+n and lo<pa+size for lo,n in self.immutable):return None
        return pa
    def constant(self,va,size):
        pa=self.physical(va,size)
        return pa is not None and any(lo<=pa and pa+size<=lo+n for lo,n in self.immutable)


def finite(values):
    if values is None:return None
    result=set()
    for value in values:
        result.add(value&MASK)
        if len(result)>LIMIT:return None
    return frozenset(result)


def product(a,b,operation):
    return None if a is None or b is None else finite(operation(x,y) for x in a for y in b)


def addresses(pc,op,state):
    info=op.info;base=info&31
    values=frozenset((pc,)) if info&(1<<44) else state[base]
    if info&POST:return values
    if info&REGISTER:
        rm=info>>5&31;offset=frozenset((0,)) if rm==31 else state[rm]
        extension,shift=info>>24&7,info>>27&7
        if offset is not None:
            offset=finite(((v&0xffffffff) if extension==2 else sign(v&0xffffffff,32) if extension==6 else v)<<shift for v in offset)
        return product(values,offset,lambda x,y:x+y)
    return None if values is None else finite(v+op.imm for v in values)


def user_proofs(words,initial,package,aliases,immutable,with_addresses=False,with_states=False):
    """Finite-set propagation; every unknown indirect edge observes all state."""
    binding=Bindings(aliases,immutable)
    seed=tuple(frozenset((v,)) for v in initial[:32]);entry=initial[32]
    states={entry:seed};queue=deque([entry]);queued={entry}
    unknown=tuple([None]*32)
    def put(pc,state):
        if pc not in words:return
        old=states.get(pc)
        merged=state if old is None else tuple(None if a is None or b is None else finite(a|b) for a,b in zip(old,state))
        if old!=merged:
            states[pc]=merged
            if pc not in queued:queue.append(pc);queued.add(pc)
    while queue:
        pc=queue.popleft();queued.remove(pc);state=states[pc];out=list(state)
        w=words[pc];op=decode(w);rd=w&31;rn=w>>5&31;rm=w>>16&31
        width=64 if w>>31 else 32;mask=(1<<width)-1;next_pc=pc+4
        source=lambda r,sp=False:state[r] if r<31 or sp else frozenset((0,))
        if w&0xfc000000 in (0x14000000,0x94000000):
            dest=(pc+4*sign(w&0x3ffffff,26))&MASK
            if w&0x80000000:
                put(dest,unknown);put(next_pc,unknown)
            else:put(dest,state)
            continue
        if w&0xff000010==0x54000000 or w&0x7e000000 in (0x34000000,0x36000000):
            bits=14 if w&0x7e000000==0x36000000 else 19
            put(pc+4*sign(w>>5&((1<<bits)-1),bits),state);put(next_pc,state);continue
        if op.kind==INDIRECT:
            targets=source(rn)
            if w&0xfffffc1f==0xd63f0000:
                for dest in targets or words:put(dest,unknown)
                put(next_pc,unknown)
            elif w&0xfffffc1f==0xd65f0000:
                for dest in targets or words:put(dest,unknown)
            else:
                for dest in targets or words:put(dest,state if targets is not None else unknown)
            continue
        if op.kind==SVC:
            out[0]=None # The boundary checks the other GPRs and SP on return.
        elif op.kind==MEMORY:
            ea=addresses(pc,op,state);info=op.info;size=1<<(info>>15&7)
            vector=bool(w&(1<<26));pair=bool(info&PAIR)
            if info&LOAD and not info&HINT and not vector:
                for dest,index in ((rd,0),((w>>10&31),1)) if pair else ((rd,0),):
                    if dest==31:continue
                    values=None
                    if ea is not None and all(binding.constant(a+index*size,size) for a in ea):
                        raw=[int.from_bytes(package.memory[binding.physical(a+index*size,size)-package.h[2]:binding.physical(a+index*size,size)-package.h[2]+size],'little') for a in ea]
                        signed_load=(pair and w>>30==1) or (not pair and w>>22&3>=2)
                        values=finite((sign(v,8*size)&(0xffffffff if not pair and w>>22&3==3 else MASK)) if signed_load else v for v in raw)
                    out[dest]=values
            if info&WB:out[rn]=None if state[rn] is None else finite(v+op.imm for v in state[rn])
        elif w&0x9f000000 in (0x10000000,0x90000000):
            delta=sign((w>>29&3)|((w>>5&0x7ffff)<<2),21)
            if rd!=31:out[rd]=finite([((pc&-4096)+(delta<<12)) if w>>31 else pc+delta])
        elif w&0x1f800000==0x12800000:
            opc=w>>29&3;shift=(w>>21&3)*16;value=(w>>5&65535)<<shift
            if rd!=31:
                out[rd]=finite([((~value) if opc==0 else value)&mask]) if opc in (0,2) else None if state[rd] is None else finite(((v&~(65535<<shift))|value)&mask for v in state[rd])
        elif w&0x1f800000==0x11000000:
            values=source(rn,True);imm=(w>>10&4095)<<(12 if w&(1<<22) else 0)
            if rd!=31 or not w&(1<<29):out[rd]=None if values is None else finite((v+(-imm if w&(1<<30) else imm))&mask for v in values)
        elif w&0x1f800000==0x12000000:
            immediate=bitmask(w>>22&1,w>>16&63,w>>10&63)&mask;opc=w>>29&3;values=source(rn)
            if rd!=31:
                if values is None and opc in (0,3) and immediate.bit_count()<=5:
                    positions=[i for i in range(width) if immediate>>i&1]
                    out[rd]=finite(sum(((v>>i)&1)<<p for i,p in enumerate(positions)) for v in range(1<<len(positions)))
                else:out[rd]=None if values is None else finite((v&immediate) if opc in (0,3) else (v|immediate) if opc==1 else (v^immediate) for v in values)
            elif opc!=3:out[31]=None
        elif w&0x1f000000==0x0a000000 or w&0x1f200000==0x0b000000:
            shift=w>>22&3;amount=w>>10&63;other=source(rm)
            if other is not None:
                other=finite(((v<<amount) if shift==0 else (v&mask)>>amount if shift==1 else sign(v&mask,width)>>amount if shift==2 else (((v&mask)>>amount)|((v&mask)<<(width-amount))))&mask for v in other)
            if rd!=31:
                if w&0x1f000000==0x0a000000:
                    if w&(1<<21) and other is not None:other=finite((~v)&mask for v in other)
                    opc=w>>29&3;out[rd]=product(source(rn),other,lambda x,y:((x&y) if opc in (0,3) else (x|y) if opc==1 else (x^y))&mask)
                else:out[rd]=product(source(rn),other,lambda x,y:(x-y if w&(1<<30) else x+y)&mask)
        elif op.kind==STACK:
            if op.info&DST_SP:out[31]=None
            if rd!=31:out[rd]=None
        elif op.kind in (SYSTEM,UNSUPPORTED):
            if op.kind==SYSTEM and w&0xfff00000==0xd5300000:
                if rd!=31:out[rd]=None
            else:out=list(unknown)
        elif w!=0xd503201f and w>>25&15 in (5,7,8,9,13,15):
            if rd!=31:out[rd]=None
        put(next_pc,tuple(out))
    proven={}
    for pc,state in states.items():
        op=decode(words[pc])
        if op.kind!=MEMORY or op.info&(USER|EXCLUSIVE|(1<<44)):continue
        ea=addresses(pc,op,state);size=(1<<(op.info>>15&7))*(2 if op.info&PAIR else 1)
        if ea is not None and all(binding.physical(a,size,not bool(op.info&LOAD)) is not None and
                                  (not op.info&ALIGNED or a%size==0) for a in ea):
            proven[pc]=dict(addresses=sorted(ea),physical=sorted({binding.physical(a,size,not bool(op.info&LOAD)) for a in ea}),bytes=size)
    result=proven if with_addresses else set(proven)
    return (result,states) if with_states else result


def native_group(pc,words,length,target):
    """Original exclusive instructions, with only local branch relocation."""
    prefix='.Lhw%x_insn'%pc;exits={};lines=[]
    for index in range(length):
        here=pc+4*index;w=words[here];lines.append(prefix+'%x:'%here)
        direct=w&0xfc000000==0x14000000
        conditional=w&0xff000010==0x54000000 or w&0x7e000000 in (0x34000000,0x36000000)
        if direct or conditional:
            bits=26 if direct else 14 if w&0x7e000000==0x36000000 else 19
            dest=here+4*(sign(w&0x3ffffff,26) if direct else sign(w>>5&((1<<bits)-1),bits))
            if pc<=dest<pc+4*length:to=prefix+'%x'%dest
            elif direct:to=target(dest)
            else:to=exits.setdefault(dest,'.Lhw%x_exit%x'%(pc,dest))
            lines.append('    b '+to if direct else local_conditional(w,to).rstrip())
        else:lines.append('    .inst 0x%08x'%w)
    lines.append('    b '+target(pc+4*length))
    for dest,to in exits.items():lines.extend([to+':','    b '+target(dest)])
    return '\n'.join(lines)+'\n'
