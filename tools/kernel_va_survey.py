#!/usr/bin/env python3
"""Virtual-address regions of a kernel and what moving each one would touch (a survey, no patching).

profile: compiles a probe against the kernel's own headers with one of its compile commands (in the build
container) and records the layout constants (PAGE_OFFSET, PAGE_END, MODULES_*, KIMAGE_VADDR, VMALLOC_*,
VMEMMAP_*, FIXADDR_*, PCI_IO_*). The regions follow from them; the same probe works for any kernel whose headers
define its layout.

survey: on a state dump, per region:
- mapped pages (live TTBR1 leaves);
- stored 8-byte values in the data pages that lie in the region: in a mapped page (pointer candidates) or
  elsewhere in it (bounds, free ranges);
- code constants built by movz/movk/movn sequences and loaded from literal pools: an exact layout parameter,
  an address in a region (mapped or not), or another value with the top 16 bits set (mask-like);
- tests of bit 55 and bit 63, and the formula variables (kimage_voffset, __per_cpu_offset, TPIDR_EL1).
"""
import argparse,bisect,collections,json,shlex,struct,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from kernel_source_verify import Elf
from source_image import Ram,text_ranges

ROOT=Path(__file__).resolve().parents[1]
PARAMS=['PAGE_OFFSET','PAGE_END','VA_BITS','VA_BITS_MIN','MODULES_VADDR','MODULES_END','KIMAGE_VADDR','VMALLOC_START',
        'VMALLOC_END','VMEMMAP_START','VMEMMAP_END','FIXADDR_START','FIXADDR_TOP','FIXADDR_TOT_START','PCI_IO_START',
        'PCI_IO_END','PGDIR_SIZE','PUD_SIZE','PMD_SIZE','TASK_SIZE_64']
PROBE='''#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/memory.h>
#include <asm/pgtable.h>
#include <asm/fixmap.h>
const unsigned long osrec_layout[] __attribute__((used)) = { %s };
'''


def profile(build,work,volume,source,image,anchor='/arch/arm64/mm/mmu.c'):
    """Layout constants from the kernel's headers, compiled with the kernel's own flags."""
    work=Path(work).resolve();work.mkdir(parents=True,exist_ok=True)
    (work/'probe.c').write_text(PROBE%', '.join('(unsigned long)(%s)'%p for p in PARAMS))
    entry=next(e for e in json.load(open(Path(build)/'compile_commands.json')) if e['file'].endswith(anchor))
    args=shlex.split(entry['command']) if 'command' in entry else list(entry['arguments'])
    args[args.index('-o')+1]='/work/probe.o';args[-1]='/work/probe.c'
    args=[a for a in args if not a.startswith('-Wp,-MMD')]
    (work/'probe.sh').write_text('cd %s && %s\n'%(entry['directory'],' '.join(shlex.quote(a) for a in args)))
    subprocess.run(['docker','run','--rm','-v',volume+':/kbuild','-v',source+':'+source+':ro','-v',str(work)+':/work',image,'sh','/work/probe.sh'],
                   check=True,capture_output=True,text=True)
    e=Elf(work/'probe.o');s=next(x for x in e.symbols if x['name']=='osrec_layout')
    data=e.bytes(e.sections[s['shndx']],s['value'],8*len(PARAMS))
    v=dict(zip(PARAMS,struct.unpack('<%dQ'%len(PARAMS),data)))
    regions=[('linear map',v['PAGE_OFFSET'],v['PAGE_END']),('modules',v['MODULES_VADDR'],v['MODULES_END']),
             ('image and vmalloc',v['VMALLOC_START'],v['VMALLOC_END']),('vmemmap',v['VMEMMAP_START'],v['VMEMMAP_END']),
             ('PCI I/O',v['PCI_IO_START'],v['PCI_IO_END']),('fixmap',v['FIXADDR_TOT_START'],v['FIXADDR_TOP'])]
    return dict(format='osrec-kernel-va-profile-v1',parameters={k:hex(x) for k,x in v.items()},
                regions=[dict(name=n,start=hex(a),end=hex(b)) for n,a,b in regions])


def constants(text_words):
    """[(va, value, how)] of 64-bit constants: movz/movn + movk runs into one register, and literal-pool loads."""
    out=[];open_={}  # register -> [start va, value]
    def close(r):
        if r in open_:
            va,val=open_.pop(r);out.append((va,val,'mov sequence'))
    for va,w in text_words:
        rd=w&31;hw=(w>>21)&3;imm=(w>>5)&0xffff
        if w&0xff800000==0xd2800000:close(rd);open_[rd]=[va,imm<<(16*hw)]                          # movz (64-bit)
        elif w&0xff800000==0x92800000:close(rd);open_[rd]=[va,(~(imm<<(16*hw)))&((1<<64)-1)]        # movn (64-bit)
        elif w&0xff800000==0xf2800000 and rd in open_:                                             # movk (64-bit)
            m=0xffff<<(16*hw);open_[rd][1]=(open_[rd][1]&~m)|(imm<<(16*hw))
        else:
            for r in list(open_):
                if r==rd or w&0xfc000000 in (0x94000000,0x14000000):close(r)                       # overwritten or a branch
    for r in list(open_):close(r)
    return out


def survey(dump,vmlinux,prof):
    ram=Ram(dump);e,text=text_ranges(vmlinux);leaves,tables=ram.mappings(1)
    regions=[(r['name'],int(r['start'],16),int(r['end'],16)) for r in prof['regions']]
    params={int(v,16):k for k,v in prof['parameters'].items() if int(v,16)>>48==0xffff}
    def region(va):
        for n,a,b in regions:
            if a<=va<b:return n
        return None
    mapped={va:pa for va,pa,_ in leaves}
    pages=collections.Counter(region(va) or 'outside' for va in mapped)
    # Stored values in data pages (text and translation tables excluded).
    text_pages={va for va in mapped if any(lo<=va<hi for lo,hi in text)}
    table_pas=set(tables);seen=set();stored=collections.Counter();stored_unmapped=collections.Counter();top_other=0
    for va,pa in mapped.items():
        if va in text_pages or pa in table_pas or pa in seen:continue
        seen.add(pa);data=ram.page(pa)
        if data is None or data==bytes(4096):continue
        for (w,) in struct.iter_unpack('<Q',data):
            if w>>48!=0xffff:continue
            r=region(w)
            if r is None:top_other+=1
            elif (w&~0xfff) in mapped:stored[r]+=1
            else:stored_unmapped[r]+=1
    # Code constants from the live text.
    words=[]
    for lo,hi in text:
        for va in range(lo&~0xfff,hi,4096):
            pa=mapped.get(va);data=ram.page(pa) if pa is not None else None
            if data is None:continue
            words+=[(va+k,struct.unpack_from('<I',data,k)[0]) for k in range(0,4096,4) if lo<=va+k<hi]
    consts=constants(words)
    for va,w in words:                                                                             # LDR (literal), 64-bit
        if w&0xff000000==0x58000000:
            target=va+4*(((w>>5)&0x7ffff)-(1<<19 if w&(1<<23) else 0))
            pa=mapped.get(target&~0xfff);data=ram.page(pa) if pa is not None else None
            if data is not None and target&7==0:consts.append((va,struct.unpack_from('<Q',data,target&0xfff)[0],'literal pool'))
    code=collections.Counter();examples=collections.defaultdict(set)
    for va,val,how in consts:
        if val>>48!=0xffff:continue
        if val in params:k='parameter %s'%params[val]
        elif region(val):k='%s address (%s)'%(region(val),'mapped' if (val&~0xfff) in mapped else 'unmapped')
        else:k='other top-bits value'
        code[k]+=1;examples[k].add(hex(val))
    bits=collections.Counter()
    for va,w in words:
        if w&0x7e000000==0x36000000:
            b=((w>>31)<<5)|((w>>19)&31)
            if b in (55,63):bits['tbz/tbnz bit %d'%b]+=1
    sym={s['name']:s['value'] for s in e.symbols if s['value'] and s['name']}
    def q(va):
        pa=mapped.get(va&~0xfff);return struct.unpack_from('<Q',ram.page(pa),va&0xfff)[0] if pa is not None else None
    variables={'kimage_voffset':hex(q(sym['kimage_voffset'])),'__per_cpu_offset[0]':hex(q(sym['__per_cpu_offset'])),
               'TPIDR_EL1':hex(ram.sysregs['TPIDR_EL1']),'memstart_addr':hex(q(sym['memstart_addr']))}
    return dict(mapped_pages=dict(pages),stored_pointers_mapped=dict(stored),stored_in_region_unmapped=dict(stored_unmapped),
                stored_other_top_bits=top_other,code_constants=dict(code),
                code_constant_values={k:sorted(v)[:12] for k,v in examples.items()},bit_tests=dict(bits),formula_variables=variables)


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('profile');a.add_argument('--build',required=True);a.add_argument('--work',required=True);a.add_argument('--out',required=True)
    a.add_argument('--build-volume',default='osrec-kbuild-full');a.add_argument('--source-tree',default='/Volumes/osrec-linux-6.10.14')
    a.add_argument('--build-image',default='osrec-kbuild-clang19:latest')
    b=sub.add_parser('survey');b.add_argument('--dump',required=True);b.add_argument('--vmlinux',required=True);b.add_argument('--profile',required=True)
    b.add_argument('--out',required=True)
    x=p.parse_args()
    if x.command=='profile':
        r=profile(x.build,x.work,x.build_volume,x.source_tree,x.build_image)
    else:
        r=survey(x.dump,x.vmlinux,json.load(open(x.profile)))
    Path(x.out).write_text(json.dumps(r,indent=1)+'\n');print(json.dumps(r,indent=1))


if __name__=='__main__':main()
