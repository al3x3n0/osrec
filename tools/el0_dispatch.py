"""Guarded, construction-resolved function-pointer tables for indirect calls.

Table layouts and initial bytes suggest a fast path; they never establish a
runtime target. Every use checks the complete live pointer before branching.
Unknown indices, changed pointers and non-admitted targets retain the existing
original-PC resolver, with all registers, flags and link state unchanged.
"""
import bisect
import struct
from dataclasses import dataclass

from el0_flat_lower import *
from el0_hardware import immediate

MASK=(1<<64)-1


@dataclass
class Dispatch:
    pc:int
    word:int
    load_pc:int
    index:int
    base:int
    object_name:str
    entries:tuple

    @property
    def table(self):return '.Ldispatch_table%x'%self.pc


def writes_register(word,register):
    op=decode(word)
    if op.kind==MEMORY:
        return bool(op.info&WB and op.info&31==register or
                    op.info&LOAD and not op.info&HINT and not word&(1<<26) and
                    (word&31==register or op.info&PAIR and word>>10&31==register))
    return word&31==register


def constant_before(pc,register,words,descriptions,limit=24):
    """Resolve only an uninterrupted ADR/ADRP plus immediate-add sequence."""
    delta=0
    for at in range(pc-4,pc-4*(limit+1),-4):
        w=words.get(at)
        if w is None or at in descriptions:return None
        op=decode(w)
        if op.kind in (INDIRECT,SVC,BOUNDARY,UNSUPPORTED,SYSTEM) or w&0x7c000000==0x14000000 or w&0xff000010==0x54000000 or w&0x7e000000 in (0x34000000,0x36000000):return None
        if w&31==register and w&0x9f000000 in (0x10000000,0x90000000):
            value=sign((w>>29&3)|((w>>5&0x7ffff)<<2),21)
            return ((((at&-4096)+(value<<12)) if w>>31 else at+value)+delta)&MASK
        if w&31==register and w&0xff800000 in (0x91000000,0xd1000000) and w>>5&31==register:
            value=(w>>10&4095)<<(12 if w&(1<<22) else 0)
            delta+=-value if w&(1<<30) else value
        elif writes_register(w,register):return None
    return None


def analyze_dispatch_tables(words,descriptions,groups,objects,read_pointer,domain=lambda pc:bool(pc>>47)):
    """Recognize LDR Xt,[Xbase,Windex,UXTW #3] followed by BR/BLR Xt.

    A self-clobbered AND index can use its surviving operand as a hint. No
    equality or alias assumption is made: the live target guard decides hits.
    """
    objects=sorted((base,size,name) for base,size,name in objects if size)
    starts=[row[0] for row in objects];result={}
    for pc,w in sorted(words.items()):
        if w&0xfffffc1f not in (0xd61f0000,0xd63f0000):continue
        entry=descriptions.get(pc)
        if entry is not None and (entry[0].kind!=INDIRECT or entry[1]):continue
        load_pc=pc-4;load=words.get(load_pc)
        if load is None or load_pc in descriptions or load_pc in groups:continue
        op=decode(load);info=op.info;rn=w>>5&31
        if (op.kind!=MEMORY or load&31!=rn or rn==31 or load&(1<<26) or
            not info&LOAD or not info&REGISTER or info&(PAIR|WB|HINT|USER|EXCLUSIVE|ALIGNED) or
            (info>>15&7)!=3 or (info>>24&7)!=2 or (info>>27&7)!=3):continue
        index=info>>5&31
        if index==rn:
            previous=words.get(load_pc-4,0)
            if load_pc-4 in descriptions or previous&0xffe0fc00!=0x0a000000 or previous&31!=index:continue
            left,right=previous>>5&31,previous>>16&31
            index=right if left==index else left if right==index else rn
            if index==rn:continue
        base=constant_before(load_pc,info&31,words,descriptions)
        if base is None or base&7:continue
        i=bisect.bisect_right(starts,base)-1
        if i<0:continue
        start,size,name=objects[i];count=(start+size-base)//8
        if base<start or not 1<=count<=4096:continue
        try:values=[read_pointer(base+8*n) for n in range(count)]
        except (ValueError,KeyError,IndexError):continue
        entries=tuple((value,value if value in words and domain(value)==domain(pc) else None) for value in values)
        if not any(target is not None for value,target in entries):continue
        result[pc]=Dispatch(pc,w,load_pc,index,base,name,entries)
    return result


def dispatch_path(plan,compact=False):
    """Use the matching kernel/user indirect-frame ABI on successful edges."""
    rn=plan.word>>5&31;slow='.Ldispatch%x_slow'%plan.pc
    save_offset,temp_offset=(0,16) if compact else (32,8)
    code=(['stp x16,x17,[sp,#-32]!'] if compact else ['sub sp,sp,#64','stp x16,x17,[sp,#32]'])+[
          'mov w16,%s'%('w%d'%plan.index if plan.index!=31 else 'wzr'),
          'sub x17,x16,#%d'%len(plan.entries),'tbz x17,#63,'+slow,
          'adrp x17,'+plan.table,'add x17,x17,:lo12:'+plan.table,
          'add x17,x17,x16,lsl #4','ldp x16,x17,[x17]']
    if rn in (16,17):
        code+=['str x17,[sp,#%d]'%temp_offset,'ldr x17,[sp,#%d]'%(save_offset+8*(rn-16)),
               'eor x16,x16,x17','cbnz x16,'+slow,'ldr x16,[sp,#%d]'%temp_offset,'cbz x16,'+slow]
    else:
        code+=['eor x16,x16,x%d'%rn,'cbnz x16,'+slow,'cbz x17,'+slow,'mov x16,x17']
    if plan.word&0xfffffc1f==0xd63f0000:code+=immediate(30,plan.pc+4)
    code+=['br x16',slow+':']+(['ldp x16,x17,[sp],#32'] if compact else ['ldp x16,x17,[sp,#32]','add sp,sp,#64'])
    return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)


def dispatch_data(plans):
    lines=['.pushsection .rodata,"a"','.balign 16',
           '.global flat_dispatch_site_count','flat_dispatch_site_count: .quad %d'%len(plans),
           '.global flat_dispatch_sites','flat_dispatch_sites:']
    for pc,plan in sorted(plans.items()):
        lines.append('.quad 0x%x,0x%x,%d,%d,%s'%(pc,plan.word,plan.index,len(plan.entries),plan.table))
    for pc,plan in sorted(plans.items()):
        lines+=['.balign 16',plan.table+':']
        lines+=['.quad 0x%x,%s'%(value,'.Li%x'%target if target is not None else '0') for value,target in plan.entries]
    return '\n'.join(lines+['.popsection'])+'\n'


def validate_dispatch_tables(elf,checked,manifest):
    """Bind immutable fast-path records to the admitted per-domain PC tables."""
    symbols={s['name']:s for s in elf.symbols if s['shndx']}
    flag=symbols.get('flat_dispatch_site_count')
    count=struct.unpack('<Q',elf.read(flag['value'],8))[0] if flag else 0
    if count!=manifest.get('indirect_dispatch_sites',0) or count>4096:
        raise ValueError('dispatch site count differs between ELF and manifest')
    if not count:return
    def readonly(address,size):
        section=next((s for s in elf.sections if s['addr']<=address and address+size<=s['addr']+s['size']),None)
        lo=address&-4096;hi=(address+size+4095)&-4096
        if section is None or section['flags']&1 or any(
                s['flags']&2 and lo<((s['address']+s['memory_bytes']+4095)&-4096) and
                (s['address']&-4096)<hi for s in checked['load_segments']):
            raise ValueError('dispatch contract or table is writable')
    readonly(flag['value'],8)
    sites=symbols['flat_dispatch_sites']['value'];readonly(sites,count*40)
    rows=list(struct.iter_unpack('<5Q',elf.read(sites,count*40)))
    total=0
    for pc,word,index,n,address in rows:
        if word&0xfffffc1f not in (0xd61f0000,0xd63f0000) or index>31 or not 1<=n<=4096:
            raise ValueError('invalid dispatch site descriptor')
        readonly(address,n*16);total+=n
        records=list(struct.iter_unpack('<2Q',elf.read(address,n*16)))
        values={value for value,native in records if native}
        # Only the branch site's existing domain can authorize a target.
        domain='flat_kernel_direct' if pc>>47 else 'flat_user_direct'
        size=struct.unpack('<Q',elf.read(symbols[domain+'_count']['value'],8))[0]
        table=elf.read(symbols[domain+'_pcs']['value'],size*16)
        expected={source:native for source,native in struct.iter_unpack('<2Q',table) if source in values}
        if any(native and expected.get(value)!=native for value,native in records):
            raise ValueError('dispatch native target differs from admitted PC table')
    if total!=manifest.get('indirect_dispatch_entries',0):
        raise ValueError('dispatch entry count differs between ELF and manifest')
