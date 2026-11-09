#!/usr/bin/env python3
"""Layout-derived constants in kernel code, and their re-encoding for new layout parameters.

The compiler folds the kernel's layout parameters into constants: PAGE_OFFSET itself, and expressions such as
page_to_virt's PAGE_OFFSET - (VMEMMAP_START << 6), often plus a field offset. Moving the kernel's virtual layout
means recomputing exactly those constants from the same expressions with new parameters, and leaving every other
constant alone. The profile lists the expressions ("derived": name, expression over the parameters, allowed
offsets); a site is derived when its value equals an expression plus an allowed offset.

Sites are extracted with their instructions: a movz/movn + movk sequence into one register, or a 64-bit literal
loaded with LDR (literal). Re-encoding keeps the same instructions and register; a new value that needs a 16-bit
chunk the original sequence does not set is reported, never forced.

check: classify the live text's sites, re-encode every derived site from the UNCHANGED parameters (it must
reproduce the original words), and list near-misses (a value within 64 KiB of an expression but outside its
allowed offsets) for review.
"""
import argparse,collections,json,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from source_image import Ram,text_ranges

M64=(1<<64)-1
MOVZ,MOVN,MOVK=0xd2800000,0x92800000,0xf2800000
ORR_IMM=0xb2000000  # ORR Xd, Xn, #bitmask (MOV Xd, #bitmask when Xn = XZR)


def bitmask(n,immr,imms):
    """The 64-bit value of an AArch64 logical immediate (DecodeBitMasks, element size from N:imms)."""
    combined=(n<<6)|((~imms)&0x3f);length=combined.bit_length()-1
    if length<1:return None
    esize=1<<length;levels=esize-1;s_=imms&levels;r=immr&levels
    if s_==levels:return None
    welem=(1<<(s_+1))-1;elem=((welem>>r)|(welem<<(esize-r)))&((1<<esize)-1)
    v=0
    for i in range(64//esize):v|=elem<<(i*esize)
    return v


def evaluate(expr,params):
    return eval(expr,{'__builtins__':{}},dict(params))&M64


def sites(words):
    """[{kind, insns:[(va, word)], rd, value}] of 64-bit constants in a {va: word} text map."""
    out=[];open_={}
    def close(r):
        s=open_.pop(r,None)
        if s:out.append(s)
    for va in sorted(words):
        w=words[va];rd=w&31;hw=(w>>21)&3;imm=(w>>5)&0xffff;top=w&0xff800000
        if top==ORR_IMM and (w>>5)&31==31:                                       # MOV Xd, #bitmask
            v=bitmask((w>>22)&1,(w>>16)&0x3f,(w>>10)&0x3f)
            if v is not None:close(rd);open_[rd]=dict(kind='mov',insns=[(va,w)],rd=rd,value=v);continue
        if top in (MOVZ,MOVN):
            close(rd);value=imm<<(16*hw) if top==MOVZ else (~(imm<<(16*hw)))&M64
            open_[rd]=dict(kind='mov',insns=[(va,w)],rd=rd,value=value);continue
        if top==MOVK and rd in open_ and open_[rd]['insns'][-1][0]>=va-64:
            s=open_[rd];m=0xffff<<(16*hw);s['value']=(s['value']&~m)|(imm<<(16*hw));s['insns'].append((va,w));continue
        for r in list(open_):
            if r==rd or w&0xfc000000 in (0x94000000,0x14000000) or va-open_[r]['insns'][-1][0]>64:close(r)
    for r in list(open_):close(r)
    return out


def literal_sites(words,read8):
    """LDR (literal, 64-bit) sites: the 8-byte word they load."""
    out=[]
    for va,w in words.items():
        if w&0xff000000==0x58000000:
            target=va+4*(((w>>5)&0x7ffff)-(1<<19 if w&(1<<23) else 0))
            if target&7==0:
                v=read8(target)
                if v is not None:out.append(dict(kind='literal',insns=[(va,w)],literal=target,value=v))
    return out


def reencode(site,value):
    """New words for a mov sequence that builds `value` (same instructions, same register), or None."""
    insns=site['insns'];first=insns[0][1];inverted=first&0xff800000==MOVN;logical=first&0xff800000==ORR_IMM
    if logical:
        base=bitmask((first>>22)&1,(first>>16)&0x3f,(first>>10)&0x3f);chunks={(w>>21)&3 for _,w in insns[1:]}
        for hw in range(4):
            if hw not in chunks and ((value^base)>>(16*hw))&0xffff:return None  # only movk chunks can change
        return [insns[0]]+[(va,(w&~(0xffff<<5))|(((value>>(16*((w>>21)&3)))&0xffff)<<5)) for va,w in insns[1:]]
    chunks={(w>>21)&3 for _,w in insns}
    base=0 if not inverted else M64
    for hw in range(4):
        part=(value>>(16*hw))&0xffff
        if hw not in chunks and part!=((base>>(16*hw))&0xffff):return None  # a chunk the sequence does not set
    new=[]
    for i,(va,w) in enumerate(insns):
        hw=(w>>21)&3;part=(value>>(16*hw))&0xffff
        if i==0 and inverted:part=(~part)&0xffff
        new.append((va,(w&~(0xffff<<5))|(part<<5)))
    return new


def consumer(words,site):
    """How the built register is first used: 'add', 'sub', 'compare', 'other' (within 24 instructions)."""
    if site['kind']!='mov':return 'other'
    rd=site['rd'];va=site['insns'][-1][0]
    for _ in range(24):
        va+=4;w=words.get(va)
        if w is None:return 'other'
        rn,rm=(w>>5)&31,(w>>16)&31
        if w&0x1f000000==0x0b000000 and rd in (rn,rm):                          # add/sub (shifted/extended register)
            if w&(1<<29) and w&31==31:return 'compare'                          # adds/subs into xzr: cmn/cmp
            return 'sub' if w&(1<<30) else 'add'
        if (w&31)==rd or (rd in (rn,rm) and w&0x1f000000 not in (0x0b000000,)):return 'other'
    return 'other'


def classify(all_sites,params,derived,review_window=0x10000,words=None):
    """Each site: ('derived', name, offset) | ('review', name, delta) | None. A formula listing "uses" applies
    only when the built register is first consumed by one of them (words needed)."""
    bases=[(d['name'],evaluate(d['expr'],params),d['offsets'][0],d['offsets'][1],d.get('uses')) for d in derived]
    out=[]
    for s in all_sites:
        v=s['value'];hit=None;near=None
        for name,base,lo,hi,uses in bases:
            d=(v-base)&M64;d=d if d<1<<63 else d-(1<<64)
            if lo<=d<=hi and uses and (words is None or consumer(words,s) not in uses):continue
            if lo<=d<=hi:hit=('derived',name,d);break
            if abs(d)<review_window and near is None:near=('review',name,d)
        out.append(hit or near)
    return out


def check(dump,vmlinux,profile):
    ram=Ram(dump);e,text=text_ranges(vmlinux);leaves,_=ram.mappings(1);va2pa={va:pa for va,pa,_ in leaves}
    words={}
    for lo,hi in text:
        for va in range(lo&~0xfff,hi,4096):
            pa=va2pa.get(va);d=ram.page(pa) if pa is not None else None
            if d is None:continue
            for k in range(0,4096,4):
                if lo<=va+k<hi:words[va+k]=struct.unpack_from('<I',d,k)[0]
    def read8(va):
        pa=va2pa.get(va&~0xfff);d=ram.page(pa) if pa is not None else None
        return None if d is None else struct.unpack_from('<Q',d,va&0xfff)[0]
    params={k:int(v,16) for k,v in profile['parameters'].items()}
    all_sites=[s for s in sites(words)+literal_sites(words,read8) if s['value']>>48 in (0xffff,1) or s['value']>>48==0 and s['value']>>32]
    kinds=classify(all_sites,params,profile['derived'],words=words)
    counts=collections.Counter();identity=collections.Counter();review=collections.Counter();examples={}
    for s,k in zip(all_sites,kinds):
        if not k:counts['other (left unchanged)']+=1;continue
        if k[0]=='review':review[(k[1],k[2])]+=1;continue
        counts[k[1]]+=1
        base=evaluate(next(d['expr'] for d in profile['derived'] if d['name']==k[1]),params)
        if s['kind']=='literal':identity['literal: value reproduced' if (base+k[2])&M64==s['value'] else 'literal: MISMATCH']+=1;continue
        new=reencode(s,(base+k[2])&M64)
        if new is None:identity['not re-encodable']+=1
        elif new==s['insns']:identity['reproduced exactly']+=1
        else:identity['MISMATCH']+=1;examples.setdefault('mismatch',hex(s['insns'][0][0]))
    return dict(sites=len(all_sites),derived=dict(counts),identity_check=dict(identity),
                review=[dict(formula=n,delta=d,sites=c) for (n,d),c in review.most_common()],examples=examples)


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    c=sub.add_parser('check');c.add_argument('--dump',required=True);c.add_argument('--vmlinux',required=True);c.add_argument('--profile',required=True)
    a=p.parse_args()
    print(json.dumps(check(a.dump,a.vmlinux,json.load(open(a.profile))),indent=1))


if __name__=='__main__':main()
