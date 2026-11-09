"""Lower a captured kernel into a disjoint 48-bit TTBR0 layout.

First use the existing, self-checking linear-map relocation. Then strip the
canonical upper bits, preserving physical addresses and relative displacements.
Per-CPU offsets and memstart_addr are differences, not absolute pointers.
Layout constants are recomputed from the kernel's layout expressions. Ambiguous
address constructions become named stops, rather than guessed rewrites.
"""
import bisect
import collections
import copy
import struct

from va_constants import sites, literal_sites, classify, evaluate, reencode
from va_relocation import relocate
from va_rehash import rehash
from program_view import Layout

MASK48=(1<<48)-1
M64=(1<<64)-1
LINEAR_SHIFT=32<<40
NOP=0xd503201f
BRK=0xd4200000|(0xf00<<5)
SITE_TEST=0x40000000
SITE_STOP=0x20000000
SITE_USER=0x80000000
VENEER_PA=0x73000000


def branch(pc,target):
    distance=target-pc
    if distance%4 or not -(1<<27)<=distance<(1<<27):raise ValueError('veneer is outside branch range')
    return 0x14000000|((distance//4)&0x3ffffff)


def logical_value(word):
    if word&0x9f800000!=0x92000000:return None
    n=word>>22&1;r=word>>16&63;s=word>>10&63
    length=((n<<6)|(~s&63)).bit_length()-1
    if length<1:return None
    width=1<<length;mask=(1<<width)-1;s&=width-1;r&=width-1
    if s==width-1:return None
    element=(1<<(s+1))-1
    element=((element>>r)|(element<<(width-r)))&mask
    return sum(element<<i for i in range(0,64,width))


_LOGICAL=None
def logical_word(word,value):
    global _LOGICAL
    if _LOGICAL is None:
        _LOGICAL={}
        for n in range(2):
            for r in range(64):
                for s in range(64):
                    fields=n<<22|r<<16|s<<10
                    v=logical_value(0x92000000|fields)
                    if v is not None:_LOGICAL.setdefault(v,fields)
    if value in _LOGICAL:return (word&~(0x1fff<<10))|_LOGICAL[value]
    rd=word&31;rn=word>>5&31;op=word>>29&3
    if value==0:
        if op in (1,2):return 0xaa0003e0|rn<<16|rd  # ORR/EOR #0 -> MOV
        if op==0:return 0xaa1f03e0|rd              # AND #0 -> MOV XZR
        return 0xea1f03e0|rd                      # ANDS #0, including NZCV
    return None


def intervals(pages):
    out=[]
    for va in sorted(set(pages)):
        if out and va==out[-1][1]:out[-1][1]+=4096
        else:out.append([va,va+4096])
    return out


def guard_exclusive_regions(words,code,extended):
    """A BRK must not destroy a reservation between an original LDXR/STXR.

    If a new check would do that, stop at the load instead. User-load veneers
    themselves execute the original LDXR after the guard, establishing the
    reservation normally.
    """
    count=0
    for va,word in words.items():
        if word&0x3f000000!=0x08000000 or not word&(1<<22):continue
        rn=word>>5&31;checks=[]
        for at in range(va+4,va+260,4):
            w=words.get(at)
            if w is None:break
            if w&0x3f000000==0x08000000 and not w&(1<<22) and w>>5&31==rn:
                if checks:code[va]=BRK;extended[va]=(word,SITE_STOP);count+=1
                break
            if code.get(at)==BRK:checks.append(at)
            if w&0xfffffc1f==0xd65f0000 or w&0xfc000000==0x94000000:break
    return count


def isolated_constant(site,words):
    """A veneer may materialize the final value early only if no partial value
    is consumed, and no branch can skip part of the original construction."""
    if site['kind']!='mov':return True
    own={va for va,_ in site['insns']};rd=site['rd']
    for va in range(site['insns'][0][0]+4,site['insns'][-1][0],4):
        if va in own:continue
        w=words.get(va)
        if w is None:return False
        if (w>>5&31)==rd or (w>>16&31)==rd:return False
        if w&0x3a000000==0x28000000 and not w&(1<<22) and (w>>10&31)==rd:return False
        if w&0x7e000000 in (0x34000000,0x36000000) or w&0xff000010==0x54000000:return False
        if w&0xfe000000==0xd6000000:return False
    return True


def lower_profile(profile):
    profile=copy.deepcopy(profile)
    for formula in profile['derived']:
        if formula['name']=='-PAGE_OFFSET':
            # ADD pointer, 2^48 removes the old canonical prefix. In contrast,
            # SUB 2^48, length computes TASK_SIZE-length in access_ok(); that
            # user bound must remain unchanged, even for a zero-length iovec.
            formula['uses']=['add']
    # The compiler also folds page_to_virt minus PAGE_OFFSET when testing the
    # linear-map range. Its old value has zero high bits, unlike a pointer.
    if not any(d['expr']=='-(VMEMMAP_START << 6)' for d in profile['derived']):
        profile['derived'].append(dict(name='page_to_linear_offset',expr='-(VMEMMAP_START << 6)',offsets=[0,4095],uses=['add','sub']))
    return profile


def plan(ram,image,profile,db,instruction_ranges,offset=LINEAR_SHIFT):
    profile=lower_profile(profile)
    symbols={s['name']:s['value'] for s in image.symbols if s['value']}
    upper,tables=ram.mappings(1);user,user_tables=ram.mappings(0)
    va2pa={va:pa for va,pa,_ in upper}
    def pa(va):
        p=va2pa.get(va&~4095)
        return None if p is None else p+(va&4095)
    stage_a,move_a,cpu_a,summary_a=relocate(ram,symbols,profile,offset,{p for _,p,_ in user},db)
    a_pages={move_a(va):p for va,p,_ in upper}
    def pa_a(va):
        p=a_pages.get(va&~4095)
        if p is None:raise ValueError('unmapped relocated address %#x'%va)
        return p+(va&4095)
    def q_a(p):return stage_a[p][1] if p in stage_a else ram.q(p)
    patches=dict(stage_a);counts=collections.Counter()
    def put(p,v,why):
        old=ram.q(p);v&=M64
        if v!=old:patches[p]=(old,v,why)
        else:patches.pop(p,None)
    regions=[(int(r['start'],16),int(r['end'],16)) for r in profile['regions']]
    def canonical(v):return v>>48==0xffff and any(lo<=v<=hi for lo,hi in regions)
    def lower(v):return v&MASK48 if canonical(v) else v
    def address(va):return lower(move_a(va))

    # Preserve scalar differences, including the deliberately negative physical
    # origin used to shift the linear map without changing its code formulas.
    skip={pa(symbols['memstart_addr'])}
    ncpu=(ram.q(pa(symbols['nr_cpu_ids']))&0xffffffff) if 'nr_cpu_ids' in symbols else 8
    skip.update(pa(symbols['__per_cpu_offset']+8*i) for i in range(max(1,ncpu)))
    text_pas={pa(va)&~4095 for lo,hi in instruction_ranges for va in range(lo&~4095,hi,4096) if pa(va) is not None}
    excluded=set(tables)|set(user_tables)|{p for _,p,_ in user}|text_pas
    seen=set()
    chunks=[(int(lo,16),int(hi,16)) for lo,hi in summary_a['percpu_vmalloc_chunks']]
    def percpu(v):
        actual=(v+cpu_a['TPIDR_EL1'])&M64
        return any(lo<=actual<hi for lo,hi in chunks)
    for va,p,_ in upper:
        if p in seen or p in excluded:continue
        seen.add(p);data=ram.page(p)
        if data is None or not any(data):continue
        for k,(old,) in enumerate(struct.iter_unpack('<Q',data)):
            at=p+8*k
            if at in skip:continue
            v=q_a(at)
            if v and percpu(v):
                put(at,(v+(1<<48))&M64,'lowered encoded per-CPU address');counts['encoded per-CPU addresses']+=1
            elif canonical(v):put(at,lower(v),'lowered stored address');counts['stored addresses']+=1
    # kimage_voffset is an address difference involving a physical address, so
    # only its virtual term moves in this step.
    at=pa(symbols['kimage_voffset']);put(at,q_a(at)&MASK48,'kimage_voffset')

    # Hash buckets depend on the final address, including its former high bits.
    lay=Layout(db)
    lookup=next((x[3] for x in db['variables'] if x[0]=='in_lookup_hashtable'),8192)//8
    rehashed=rehash(q_a,pa_a,lower,put,lay,lambda name:move_a(symbols[name]),lookup)

    words={}
    for lo,hi in instruction_ranges:
        for va in range(lo,hi,4):
            p=pa(va)
            if p is not None and ram.base<=p<ram.base+ram.size:
                words[va]=struct.unpack_from('<I',ram.ram,p-ram.base)[0]
    def read8(va):
        p=pa(va)
        return ram.q(p) if p is not None else None
    params={k:int(v,16) for k,v in profile['parameters'].items()}
    new_params={k:lower(v) for k,v in params.items()}
    expressions={d['name']:d['expr'] for d in profile['derived']}
    all_sites=sites(words)+literal_sites(words,read8)
    kinds=classify(all_sites,params,profile['derived'],words=words)
    code={};extended={};veneer=bytearray();origins=[]
    occupied={va&MASK48 for va,_,_ in upper}
    veneer_va=next(0x800000000000+v for v in range(0x84000000,0x87000000,0x100000)
                   if all(0x800000000000+v+k not in occupied for k in range(0,1<<20,4096)))
    def emit(original,first,second,value):
        index=len(origins);v=veneer_va+len(veneer)
        veneer.extend(struct.pack('<IIQ',first,second,value));origins.append(original&MASK48)
        return index,v
    handled=set()
    for s,kind in zip(all_sites,kinds):
        target=None
        if kind and kind[0]=='derived':target=(evaluate(expressions[kind[1]],new_params)+kind[2])&M64
        elif canonical(s['value']) and (s['value']&~4095) in va2pa:target=address(s['value'])
        if target is None:
            if canonical(s['value']):
                at,w=s['insns'][0];code[at]=BRK;extended[at]=(w,SITE_STOP);counts['unclassified constant stops']+=1
            continue
        if target==s['value']:continue
        if not isolated_constant(s,words):
            at,w=s['insns'][0];code[at]=BRK;extended[at]=(w,SITE_STOP);counts['partial constant stops']+=1
            continue
        if s['kind']=='literal':put(pa(s['literal']),target,'lowered code literal');counts['literal constants']+=1;continue
        new=reencode(s,target)
        if new is not None:
            code.update(new);counts['reencoded constants']+=1
        else:
            at,w=s['insns'][0];v=veneer_va+len(veneer)
            emit(at,0x58000000|(2<<5)|s['rd'],branch(v+4,(at+4)&MASK48),target)
            code[at]=branch(at&MASK48,v)
            for where,_ in s['insns'][1:]:code[where]=NOP
            counts['constant veneers']+=1
        handled.update(at for at,_ in s['insns'])
    for va,w in words.items():
        if va in handled or va in code:continue
        value=logical_value(w)
        if value is not None:
            hits=classify([dict(value=value)],params,profile['derived'])
            kind=hits[0]
            if kind and kind[0]=='derived':
                target=(evaluate(expressions[kind[1]],new_params)+kind[2])&M64
                new=logical_word(w,target)
                if new is None:code[va]=BRK;extended[va]=(w,SITE_STOP)
                elif new!=w:code[va]=new;counts['logical constants']+=1
            elif value>>48==0xffff and (w>>29&3) in (1,2):
                code[va]=BRK;extended[va]=(w,SITE_STOP);counts['unclassified logical stops']+=1
        if w&0x7e000000==0x36000000 and (((w>>31)<<5)|(w>>19&31)) in (55,63):
            code[va]=BRK;extended[va]=(w,SITE_TEST);counts['address tests']+=1

    # The kernel marks user accesses in its exception table. Keep the original
    # instruction in a veneer; faults are reflected at its original PC so the
    # kernel's own fixup table still applies. Never trap between LDXR and STXR.
    ex=next(s for s in image.sections if s['name']=='__ex_table')
    user_access={}
    for off in range(0,ex['size'],12):
        delta,fixup,kind,data=struct.unpack('<iiHH',image.bytes(ex,off,12))
        if kind==2:
            va=ex['addr']+off+delta
            if va in words:user_access[va]=words[va]
    for va,w in sorted(user_access.items()):
        exclusive=w&0x3f000000==0x08000000
        if exclusive and not w&(1<<22):
            rn=w>>5&31
            matches=[p for p,load in user_access.items() if va-64<=p<va and load&0x3f000000==0x08000000 and load&(1<<22) and load>>5&31==rn]
            if not matches:code[va]=BRK;extended[va]=(w,SITE_STOP)
            continue
        index=len(origins);v=veneer_va+len(veneer)
        emit(va,w,branch(v+4,(va+4)&MASK48),0)
        code[va]=BRK;extended[va]=(w,SITE_USER|index);counts['guarded user accesses']+=1

    counts['exclusive regions requiring stops']=guard_exclusive_regions(words,code,extended)

    cpu=copy.deepcopy(ram.state['cpu']);cpu['sp']=lower(cpu_a['sp'])
    sr=cpu['sysregs'];sr['VBAR']=lower(sr['VBAR']);sr['SP_EL1']=cpu['sp'];sr['TPIDR_EL1']=cpu_a['TPIDR_EL1']
    cpu['sysregs_all']=dict(cpu.get('sysregs_all',{}),VBAR=sr['VBAR'],SP_EL1=sr['SP_EL1'],TPIDR_EL1=sr['TPIDR_EL1'])
    return dict(patches=patches,code=code,extended=extended,cpu=cpu,move=address,
                veneer_va=veneer_va,veneer_pa=VENEER_PA,veneer=bytes(veneer),origins=origins,
                summary=dict(linear=summary_a,rehash=rehashed,code=dict(counts),patches=len(patches),
                             linear_offset=hex(offset),lowered=True))
