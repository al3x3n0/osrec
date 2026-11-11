#!/usr/bin/env python3
"""Derive kernel data-symbol addresses from a pinned arm64 Image and its kallsyms text dump.

A kernel without CONFIG_KALLSYMS_ALL lists only text symbols. A reviewed spec
names, per data symbol, instructions of listed functions that form its address:
an ADRP and a later ADD, LDR or STR (64-bit, unsigned 12-bit offset) on the
ADRP's register. The tool decodes each pair from the image bytes, rejects a
branch or a possible write of that register between them, and requires every
reference to give the same address inside the image's data (after init text).

The image base is checked, not assumed: at that base nearly every global text
symbol must start with a function-entry encoding (NOP padding, BTI or PACIASP).
The symbol's layout is reviewed source, not BTF (a static anonymous struct has
no BTF variable); `check_live` validates it against live kernel memory.
"""
import argparse,hashlib,json,re,struct
from pathlib import Path

FORMAT='osrec-kernel-data-symbols-v1';SPEC='osrec-kernel-data-symbol-review-v1'
# Function-entry encodings: NOP (patchable entry), BTI c/j/jc, PACIASP.
ENTRY={0xd503201f,0xd503245f,0xd503249f,0xd50324df,0xd503233f}
ROW=re.compile(r'([0-9a-f]{16}) ([A-Za-z]) (\S+)(?:\s+\[\w+\])?')
USES={'add':(0xffc00000,0x91000000,1),'ldr':(0xffc00000,0xf9400000,8),'str':(0xffc00000,0xf9000000,8)}

def sha(data):return hashlib.sha256(data).hexdigest()

def branch(w):
    """B/BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, or BR/BLR/RET (and their authenticated forms)."""
    return (w&0x7c000000)==0x14000000 or (w&0xff000010)==0x54000000 or (w&0x7e000000) in (0x34000000,0x36000000) or (w&0xfe000000)==0xd6000000

def adrp(w,pc):
    if (w&0x9f000000)!=0x90000000:return None
    imm=((w>>5)&0x7ffff)<<2|(w>>29)&3
    if imm&1<<20:imm-=1<<21
    return w&31,((pc&~0xfff)+(imm<<12))&(1<<64)-1

def use(w,form):
    """(base register, byte offset) of a 64-bit ADD/LDR/STR with an unsigned 12-bit immediate."""
    mask,value,scale=USES[form]
    if (w&mask)!=value:return None
    return (w>>5)&31,((w>>10)&0xfff)*scale

class Image:
    def __init__(self,path,base):
        self.data=Path(path).read_bytes();self.base=base
        if self.data[0x38:0x3c]!=b'ARMd':raise ValueError('not an arm64 Image (no ARMd magic)')
        self.text_offset,self.size=struct.unpack_from('<QQ',self.data,8)
        if self.text_offset:raise ValueError('Image text_offset is not zero')
        self.end=base+self.size
    def word(self,address):
        if not self.base<=address<=self.base+len(self.data)-4:raise ValueError('address outside the image file: %#x'%address)
        return struct.unpack_from('<I',self.data,address-self.base)[0]

def symbols(path):
    text=Path(path).read_text();head=text.splitlines()[0]
    m=re.fullmatch(r'# kernel sha256 ([0-9a-f]{64})',head)
    if not m:raise ValueError('kallsyms dump has no kernel sha256 header')
    rows={}
    for line in text.splitlines()[1:]:
        s=ROW.fullmatch(line)
        if s:rows.setdefault(s.group(3),(int(s.group(1),16),s.group(2)))
    return m.group(1),rows

def check_base(image,rows):
    """Fraction of global text symbols in [_stext,_etext) whose first word is a function-entry encoding."""
    start,end=rows['_stext'][0],rows['_etext'][0]
    names=[n for n,(a,k) in rows.items() if k=='T' and start<=a<end]
    hits=sum(image.word(rows[n][0]) in ENTRY for n in names)
    return hits,len(names)

def listing(image,rows,function,length=1024):
    """Every ADRP-formed address in a function with its ADD/LDR/STR uses, to help write a review."""
    start=rows[function][0];later=sorted(a for a,_ in rows.values() if a>start);stop=min(later[0] if later else start+length,start+length)
    found=[];pending={}
    for pc in range(start,stop,4):
        w=image.word(pc);p=adrp(w,pc)
        if p:pending[p[0]]=(pc,p[1]);continue
        for form in USES:
            u=use(w,form)
            if u and u[0] in pending:found.append(dict(adrp=pending[u[0]][0]-start,use=pc-start,form=form,address='%#x'%(pending[u[0]][1]+u[1])))
        if branch(w):pending={}
        elif w&31 in pending and not (w&0xffc00000)==0xf9000000:pending.pop(w&31)
    return found

def derive(image_path,kallsyms_path,spec_path):
    spec=json.loads(Path(spec_path).read_text())
    if spec.get('format')!=SPEC:raise ValueError('not a data-symbol review')
    # A per-CPU symbol's derived address is its per-CPU link address (a copy's address minus that CPU's offset).
    raw=Path(image_path).read_bytes();digest=sha(raw)
    kernel,rows=symbols(kallsyms_path)
    if digest!=kernel or digest!=spec['kernel_image_sha256']:raise ValueError('image, kallsyms dump and review name different kernels')
    image=Image(image_path,int(spec['image_base'],16))
    hits,total=check_base(image,rows)
    if total<1000 or hits*100<total*95:raise ValueError('image base %s is not confirmed: %d of %d text symbols start with an entry encoding'%(spec['image_base'],hits,total))
    floor=rows['_einittext'][0]
    out={}
    for name,item in spec['symbols'].items():
        addresses=set();proofs=[]
        if 'btf_percpu' in item:
            # A per-CPU variable with no reference of its own: its offset in .data..percpu (the image's BTF) plus
            # the section base that a reviewed, reference-derived per-CPU symbol fixes.
            from kernel_btf import BTF
            btf=BTF(raw);base=item['btf_percpu']['calibrate']
            if base not in out or not out[base].get('percpu'):raise ValueError('%s: calibration symbol %s must be a derived per-CPU symbol listed before it'%(name,base))
            known,_,_=btf.section_variable('.data..percpu',base);offset,size,_=btf.section_variable('.data..percpu',name)
            address=int(out[base]['address'],16)-known+offset
            if size!=item['layout']['size'] or not item.get('percpu'):raise ValueError('%s: BTF size %d differs from the review, or the symbol is not per-CPU'%(name,size))
            proofs.append(dict(kind='btf_percpu_offset',section='.data..percpu',offset=offset,calibrated_by=base,calibration_offset=known,address='%#x'%address))
            addresses.add(address)
        for ref in item.get('references',[]):
            start=rows[ref['function']][0];a_pc=start+ref['adrp'];u_pc=start+ref['use']
            if not 0<=ref['adrp']<ref['use']<=ref['adrp']+64:raise ValueError('%s: use must follow its ADRP within 16 instructions'%name)
            p=adrp(image.word(a_pc),a_pc);u=use(image.word(u_pc),ref['form'])
            if not p or not u:raise ValueError('%s: %s+%#x/%#x is not ADRP then %s'%(name,ref['function'],ref['adrp'],ref['use'],ref['form'].upper()))
            if u[0]!=p[0]:raise ValueError('%s: %s+%#x does not use the ADRP register x%d'%(name,ref['function'],ref['use'],p[0]))
            for pc in range(a_pc+4,u_pc,4):
                w=image.word(pc)
                # Conservative: any instruction with the register in Rd/Rt position (stores included) rejects.
                if branch(w) or (w&31)==p[0]:raise ValueError('%s: %s+%#x may branch or redefine x%d'%(name,ref['function'],pc-start,p[0]))
            address=p[1]+u[1]
            addresses.add(address);proofs.append(dict(ref,adrp_word='%08x'%image.word(a_pc),use_word='%08x'%image.word(u_pc),register='x%d'%p[0],page='%#x'%p[1],offset=u[1],address='%#x'%address))
        if len(addresses)!=1:raise ValueError('%s: references disagree: %s'%(name,', '.join(sorted('%#x'%a for a in addresses))))
        address=addresses.pop();size=item['layout']['size']
        # A per-CPU link address lies in the per-CPU section, not in loaded image data.
        if item.get('percpu') and 'btf_percpu' in item:
            out[name]=dict(address='%#x'%address,layout=item['layout'],source=item['source'],derivations=proofs,live_checks=item.get('live_checks',[]),percpu=True,
                **({'btf_record':item['btf_record']} if 'btf_record' in item else {}))
            from kernel_btf import BTF
            if 'btf_record' in item:
                btf=BTF(raw);record=btf.struct(item['btf_record'])
                for field,f in item['layout']['fields'].items():
                    at=0;kind=record
                    for part in field.split('.'):
                        m=__import__('re').fullmatch(r'(\w+)(?:\[(\d+)\])?',part);o,kind=btf.member(kind,m[1]);at+=o
                        if m[2] is not None:
                            t=btf.types[btf.strip(kind)];kind=t['element'];at+=int(m[2])*btf.sizeof(kind)
                    if at!=f['offset'] or btf.sizeof(kind)!=f['size']:raise ValueError('%s: BTF %s.%s differs from the review'%(name,item['btf_record'],field))
            continue
        # __ro_after_init data (kmalloc_caches) lies in its own section, after rodata starts and before init text.
        if item.get('section')=='ro_after_init':
            if not rows['__start_ro_after_init'][0]<=address<address+size<=rows['_sinittext'][0]:raise ValueError('%s: %#x is not in the ro_after_init section'%(name,address))
        elif 'section' in item:raise ValueError('%s: unknown section %s'%(name,item['section']))
        elif not floor<=address<address+size<=image.end:raise ValueError('%s: %#x is not in image data after init text'%(name,address))
        if address%item['layout'].get('align',1):raise ValueError('%s: %#x violates the reviewed alignment'%(name,address))
        if 'btf_record' in item:
            # The reviewed layout must agree with the image's own type record.
            from kernel_btf import BTF
            btf=BTF(raw);record=btf.struct(item['btf_record'])
            if btf.sizeof(record)!=size:raise ValueError('%s: BTF %s is %d bytes, review says %d'%(name,item['btf_record'],btf.sizeof(record),size))
            for field,f in item['layout']['fields'].items():
                at,kind=btf.member(record,field)
                if at!=f['offset'] or btf.sizeof(kind)!=f['size']:raise ValueError('%s: BTF %s.%s differs from the review'%(name,item['btf_record'],field))
        out[name]=dict(address='%#x'%address,layout=item['layout'],source=item['source'],derivations=proofs,live_checks=item.get('live_checks',[]),
            **({'percpu':True} if item.get('percpu') else {}),**({'section':item['section']} if 'section' in item else {}),**({'btf_record':item['btf_record']} if 'btf_record' in item else {}))
    return dict(format=FORMAT,kernel_image_sha256=digest,kallsyms_sha256=sha(Path(kallsyms_path).read_bytes()),review_sha256=sha(Path(spec_path).read_bytes()),
        image_base=spec['image_base'],image_end='%#x'%image.end,base_check=dict(entry_encodings=hits,global_text_symbols=total),symbols=out)

def offset(btf,record,path):
    total=0
    for name in path.split('.'):
        at,record=btf.member(record,name);total+=at
    return total

def check_live(symbol,btf,memory,page_offset):
    """Validate a derived symbol's reviewed layout against live kernel memory; return the evidence.

    Checks: `power_of_two` (a field), `linear_map` (a pointer field is a linear-map address with
    the given alignment) and `empty_lists` (each element of a counted array of a BTF record has its
    lock unlocked and, when its `counter` is zero, its list head pointing at itself). `memory`
    provides `u(address, size)` and `read(address, size)` over kernel virtual memory.
    """
    base=int(symbol['address'],16);fields=symbol['layout']['fields']
    get=lambda f:memory.u(base+fields[f]['offset'],fields[f]['size'])
    evidence={f:get(f) for f in fields}
    for c in symbol['live_checks']:
        if c['check']=='power_of_two':
            v=evidence[c['field']]
            if not v or v&(v-1) or v<c.get('minimum',1):raise ValueError('live %s=%d is not a power of two >= %d'%(c['field'],v,c.get('minimum',1)))
        elif c['check']=='linear_map':
            v=evidence[c['field']]
            if v<page_offset or v%c['align']:raise ValueError('live %s=%#x is not an aligned linear-map address'%(c['field'],v))
        elif c['check']=='empty_lists':
            record=btf.struct(c['record']);stride=btf.sizeof(record);array=evidence[c['array']];count=evidence[c['count']]
            if stride!=c['stride']:raise ValueError('BTF %s is %d bytes, review says %d'%(c['record'],stride,c['stride']))
            waiters,head,lock=(offset(btf,record,c[k]) for k in ('counter','list','lock'))
            # One read of the whole array; every element is checked from it.
            data=memory.read(array,count*stride);u=lambda at,n:int.from_bytes(data[at:at+n],'little')
            empty=0
            for i in range(count):
                at=i*stride
                if u(at+lock,4):raise ValueError('live bucket %d lock is held'%i)
                if u(at+waiters,4):continue
                if u(at+head,8)!=array+at+head or u(at+head+8,8)!=array+at+head:raise ValueError('live bucket %d has no waiters but a non-empty list'%i)
                empty+=1
            evidence['empty_%s'%c['record']]=empty
        else:raise ValueError('unknown live check '+c['check'])
    return evidence

def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--image',type=Path,required=True);p.add_argument('--kallsyms',type=Path,required=True)
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--review',type=Path,help='reviewed data-symbol spec');g.add_argument('--list',metavar='FUNCTION',help='print ADRP-formed addresses in a function')
    p.add_argument('--base',default='0xffff800080000000',help='image base for --list');p.add_argument('--out',type=Path)
    a=p.parse_args()
    if a.list:
        _,rows=symbols(a.kallsyms);print(json.dumps(listing(Image(a.image,int(a.base,16)),rows,a.list),indent=1));return
    result=derive(a.image,a.kallsyms,a.review);text=json.dumps(result,indent=2)+'\n'
    if a.out:a.out.write_text(text)
    else:print(text,end='')

if __name__=='__main__':main()
