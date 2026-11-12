"""Conservative AArch64 lowering decisions for the full EL0 checkpoint.

Ordinary arithmetic/SIMD instructions remain native. Memory instructions are
redirected to checked canonical RAM with a scratch base. Unsupported encodings
produce explicit runtime boundaries. This decoder never substitutes syscalls.
"""
from dataclasses import dataclass

NATIVE,MEMORY,STACK,SYSTEM,INDIRECT,SVC,BOUNDARY,UNSUPPORTED,OBSERVE,COVERAGE=range(10)
LOAD=1<<19
PAIR=1<<18
WB=1<<21
POST=1<<22
USER=1<<23
REGISTER=1<<40
SRC_SP=1<<41
DST_SP=1<<42
HINT=1<<43
EXCLUSIVE=1<<45
ALIGNED=1<<46

def sign(v,bits):return v-(1<<bits) if v>>(bits-1)&1 else v

def local_conditional(word,to):
    if word&0xff000010==0x54000000:
        condition=('eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv')[word&15]
        return '    b.%s %s\n'%(condition,to)
    register=('x' if word>>31 else 'w')+str(word&31)
    if word&0x7e000000==0x34000000:
        return '    %s %s,%s\n'%('cbnz' if word&(1<<24) else 'cbz',register,to)
    return '    %s %s,#%d,%s\n'%('tbnz' if word&(1<<24) else 'tbz',register,((word>>31)<<5)|(word>>19&31),to)

@dataclass
class Op:
    kind:int
    word:int
    native:int=0
    info:int=0
    imm:int=0
    length:int=1

def temporary(used):
    return next((r for r in (16,17,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,18,19,20,21,22,23,24,25,26,27,28,29,30) if r not in used),None)

def memory(word):
    rn=word>>5&31;rt=word&31;v=bool(word&(1<<26));size=word>>30;opc=word>>22&3
    used={rn,rt};info=rn;imm=0;native=word;count=1;hint=False
    if word&0x3b000000 in (0x39000000,0x38000000):
        if v:
            if opc&2:
                if size:return None
                width=4
            else:width=size
            load=opc&1
        else:
            width=size;load=opc!=0;hint=size==3 and opc==2
            if opc==3 and size>=2 or opc==2 and size==3 and not hint:return None
        if word&0x3b000000==0x39000000:
            imm=(word>>10&4095)<<width;native&=~(4095<<10)
        elif not word&(1<<21):
            imm=sign(word>>12&511,9);mode=word>>10&3
            if mode in (1,3):info|=WB
            if mode==1:info|=POST
            if mode==2:info|=USER
            if mode in (1,3) and not v and rn==rt:return None
            native&=~((511<<12)|(3<<10))
        elif word>>10&3==2:
            rm=word>>16&31;extend=word>>13&7
            if extend not in (2,3,6,7):return None
            used.add(rm);info|=REGISTER|(rm<<5)|(extend<<24)|((width if word&(1<<12) else 0)<<27)
            native&=~((1<<21)|(31<<16)|(7<<13)|(1<<12)|(3<<10))
        else:return None
    elif word&0x3a000000==0x28000000:
        rt2=word>>10&31;used.add(rt2);load=bool(word&(1<<22));mode=word>>23&3
        if v:
            if size==3:return None
            width=size+2
        elif size==0:width=2
        elif size==2:width=3
        elif size==1 and load:width=2
        else:return None
        count=2;imm=sign(word>>15&127,7)<<width
        if mode in (1,3):
            info|=WB
            if not v and rn in (rt,rt2):return None
        if mode==1:info|=POST
        native&=~(127<<15)
        if mode in (1,3):native=(native&~(3<<23))|(2<<23)
    elif word&0x3b000000==0x18000000:
        imm=sign(word>>5&0x7ffff,19)*4;info=31;used={rt};load=True
        if v:
            if size==3:return None
            width=size+2;native=(0xbd400000,0xfd400000,0x3dc00000)[size]|rt
        else:
            width=(2,3,2,3)[size];hint=size==3
            native=(0xb9400000,0xf9400000,0xb9800000,0xf9800000)[size]|rt
        info|=1<<44 # PC-relative address, not logical SP
    elif word&0x3ffffc00 in (0x08dffc00,0x089ffc00):
        width=size;load=bool(word&(1<<22));info|=ALIGNED
    else:return None
    tmp=temporary(used)
    if tmp is None:return None
    info|=(tmp<<10)|(width<<15)|(PAIR if count==2 else 0)|(LOAD if load else 0)|(HINT if hint else 0)
    native=(native&~(31<<5))|(tmp<<5)
    return Op(MEMORY,word,native,info,imm)

def decode(word):
    if word&0xffe0001f==0xd4000001:return Op(SVC,word)
    if word&0xffe0001f==0xd4200000:return Op(BOUNDARY,word)
    if word&0xfffffc1f in (0xd61f0000,0xd63f0000,0xd65f0000):return Op(INDIRECT,word,info=word>>5&31)
    if word&0xff000000==0xd5000000 or word&0xffff0000==0xd69f0000:
        if word in (0xd503201f,0xd503203f,0xd503229f,0xd503241f,0xd503245f,0xd503249f,0xd50324df) or word&0xfffff0ff in (0xd50330bf,0xd503309f,0xd50330df,0xd503305f):return Op(NATIVE,word,word)
        if word&0xfff00000 in (0xd5300000,0xd5100000) and word>>5&65535 in (0xda10,0xda20,0xda21):return Op(NATIVE,word,word)
        return Op(SYSTEM,word)
    m=memory(word)
    if m:return m
    group=word>>25&15
    if group in (4,6,12,14):return Op(UNSUPPORTED,word)
    immediate=word&0x1f800000==0x11000000
    extended=word&0x1f200000==0x0b200000
    if immediate or extended:
        rn=word>>5&31;rd=word&31;s=bool(word&(1<<29));source=rn==31;dest=rd==31 and not s
        if source or dest:
            tmp=temporary({rn,rd,word>>16&31} if extended else {rn,rd})
            native=word
            if source:native=(native&~(31<<5))|(tmp<<5)
            if dest:native=(native&~31)|tmp
            return Op(STACK,word,native,(tmp<<10)|(SRC_SP if source else 0)|(DST_SP if dest else 0))
    if group in (5,7,8,9,13,15):return Op(NATIVE,word,word)
    return Op(UNSUPPORTED,word)

def atomic_group(words,pc):
    word=words.get(pc,0)
    pair=word&0x3fff0000==0x087f0000 and word>>30>=2
    if not pair and word&0x3fff7c00!=0x085f7c00:return None
    rn=word>>5&31;used=set()
    for n in range(1,17):
        w=words.get(pc+4*(n-1),0)
        used.update((w&31,w>>5&31,w>>10&31,w>>16&31))
        store=(w&0x3fe00000==0x08200000 if pair else w&0x3fe07c00==0x08007c00)
        if n>1 and store and w>>5&31==rn and w>>30==word>>30:
            tmp=temporary(used)
            if tmp is None:return None
            native=[]
            for k in range(n):
                v=words[pc+4*k]
                if k in (0,n-1):v=(v&~(31<<5))|(tmp<<5)
                native.append(v)
            return Op(MEMORY,word,info=rn|(tmp<<10)|((word>>30)<<15)|EXCLUSIVE|(PAIR if pair else 0),length=n),native
        conditional=w&0xff000010==0x54000000 or w&0x7e000000 in (0x34000000,0x36000000)
        direct=w&0xfc000000==0x14000000
        if n>1 and decode(w).kind!=NATIVE and not conditional and not direct:return None
    return None
