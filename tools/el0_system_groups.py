"""Share scratch setup and counter updates across consecutive inert sysops.

Only operations already admitted by the aligned-header inline backend qualify.
Every original PC keeps its own entry; no platform call, branch, gateway or
potentially faulting guest access is crossed. All source-register aliases are
excluded from the shared scratch pair.
"""
from el0_flat_lower import SYSTEM,temporary
from el0_hardware import system_path


def system_groups(descriptions,limit=8):
    result={}
    def admitted(item):
        return item is not None and item[0].kind==SYSTEM and bool(system_path(item[0].word,item[1],page_offsets=True))
    for pc,item in sorted(descriptions.items()):
        if not admitted(item):continue
        words=[item[0].word]
        for i in range(1,limit):
            other=descriptions.get(pc+4*i)
            if not admitted(other):break
            candidate=words+[other[0].word];used={w&31 for w in candidate}
            first=temporary(used);second=temporary(used|{first})
            if first is None or second is None:break
            words=candidate
        if len(words)>1:result[pc]=tuple(words)
    return result


def system_group_path(pc,words,following):
    if not 2<=len(words)<=8 or any(not system_path(w,page_offsets=True) for w in words):
        raise ValueError('system group crosses an unsupported operation')
    used={w&31 for w in words};address=temporary(used);value=temporary(used|{address})
    if address is None or value is None:raise ValueError('no system group scratch pair')
    a,v='x%d'%address,'x%d'%value
    lines=['stp %s,%s,[sp,#-16]!'%(a,v),'adrp %s,flat_shadow'%a,
        'ldr %s,[%s,:lo12:flat_shadow+88]'%(v,a),'add %s,%s,#%d'%(v,v,len(words)),
        'str %s,[%s,:lo12:flat_shadow+88]'%(v,a)]
    daif_source=None
    for i,word in enumerate(words):
        lines+=['.Lsg%x_op%x:'%(pc,pc+4*i)]
        body=[line.strip() for line in system_path(word,page_offsets=True,registers=(address,value),body_only=True).splitlines()]
        # A preceding DAIF read/update already supplies the live value. Only
        # forward into the immediately following DAIF read-modify-write; no
        # guest instruction, rejection, branch or callback intervenes.
        daif_load='ldr %s,[%s,:lo12:flat_shadow+48]'%(v,a)
        daif_store='str %s,[%s,:lo12:flat_shadow+48]'%(v,a)
        if daif_source is not None and len(body)>=3 and body[0]==daif_load and body[-1]==daif_store:
            body=body[1:]
            operation,destination,source,mask=body[0].replace(' ',',',1).split(',')
            if operation not in ('orr','bic') or destination!=v or source!=v:
                raise ValueError('unexpected DAIF update body')
            body[0]='%s %s,%s,%s'%(operation,v,daif_source,mask)
        # Scratch V is still live after a write. A DAIF read instead leaves
        # the value in its destination, which cannot alias either scratch.
        daif_source=None
        if body and body[-1]==daif_store:daif_source=v
        elif word&~31==0xd53b4220 and word&31!=31:daif_source='x%d'%(word&31)
        # A separate instruction is required for each source-visit marker,
        # including emulated maintenance operations with no data effect.
        lines+=body or ['nop']
    lines+=['ldp %s,%s,[sp],#16'%(a,v),'b '+following]
    return ''.join(line+'\n' if line.endswith(':') else '    '+line.strip()+'\n' for line in lines)


def verify_compiled(image,annotated):
    """Check captured words, one shared count update, spills and continuations."""
    import hashlib,json,struct
    from pathlib import Path
    from export_el0_program import Package
    from el0_control import layout,gateway_sizes
    from el0_flat_lower import sign
    from kernel_source_verify import Elf
    image,annotated=Path(image).resolve(),Path(annotated).resolve()
    package=Package(Path(json.loads((image/'manifest.json').read_text())['package']))
    rows=json.loads((image/'system-groups.json').read_text())['groups']
    labels,_,size=layout(image/'program.S',gateway_sizes(Path(__file__).resolve().parents[1]/'runtime/el0_flat/gateway.inc'))
    base=None
    for line in (annotated/'checkpoint.map').open():
        if line.rstrip().endswith('program-asm.o:(.text)'):
            fields=line.split();base=int(fields[0],16)
            if int(fields[2],16)!=size:raise ValueError('system group compiled layout differs')
            break
    if base is None:raise ValueError('system group main section missing')
    elf=Elf(annotated/'checkpoint');symbols={s['name']:s['value'] for s in elf.symbols if s['shndx']}
    shadow=symbols['flat_shadow'];source=set()
    def read(at,n):return struct.unpack('<%dI'%n,elf.read(at,4*n))
    for row in rows:
        pc=row['pc'];words=row['words'];used={w&31 for w in words}
        for i,word in enumerate(words):
            at=pc+4*i;captured=package.word(at);metadata=0
            if captured==0xd421e000 and at in package.sites:captured,metadata=package.sites[at]
            if captured!=word or not system_path(captured,metadata,page_offsets=True):
                raise ValueError('system group source differs from admitted captured code')
            source.add(at)
        start=base+labels['.Lp%x'%pc];end=base+labels['.Lp%x'%(pc+4)]
        save,adrp,load,add,store=read(start,5);a,v=save&31,save>>10&31
        if a==v or a in used or v in used or 31 in (a,v) or save!=0xa9bf0000|(v<<10)|(31<<5)|a:
            raise ValueError('system group shared spill aliases a live operand')
        immediate=((adrp>>29&3)|((adrp>>5&0x7ffff)<<2))
        if adrp&0x9f00001f!=0x90000000|a or ((start+4)&-4096)+(sign(immediate,21)<<12)!=shadow&-4096:
            raise ValueError('system group shadow page differs')
        offset=((shadow+88)&4095)//8
        if (load!=0xf9400000|(offset<<10)|(a<<5)|v or add!=0x91000000|(len(words)<<10)|(v<<5)|v
                or store!=0xf9000000|(offset<<10)|(a<<5)|v):
            raise ValueError('system group does not update the counter exactly once')
        starts=[base+labels['.Lsg%x_op%x'%(pc,pc+4*i)] for i in range(len(words))]
        if starts[0]!=start+20 or not all(x<y for x,y in zip(starts,starts[1:])) or starts[-1]>=end-8:
            raise ValueError('system group source markers are not distinct and ordered')
        for word in read(start+20,(end-8-start-20)//4):
            if word&0xffc00000 in (0xf9000000,0xf9400000):
                address=(shadow&-4096)+8*(word>>10&4095)
                if word>>5&31!=a or address-shadow not in (0,8,16,24,32,40,48,56,64,72):
                    raise ValueError('system group body accesses outside the shadow fields')
                if word&0xffc00000==0xf9000000 and address==shadow+72:
                    raise ValueError('system group writes a read-only shadow field')
            elif (word&0x7c000000==0x14000000 or word&0xfe000000==0xd6000000 or
                    word&0xff000000==0xd5000000 and word!=0xd503201f):
                raise ValueError('system group crosses a branch or privileged operation')
        restore,branch=read(end-8,2)
        if restore!=0xa8c10000|(v<<10)|(31<<5)|a:raise ValueError('system group restore differs from shared spill')
        if branch&0xfc000000!=0x14000000 or end-4+4*sign(branch&0x3ffffff,26)!=base+labels['.Lp%x'%(pc+4*len(words))]:
            raise ValueError('system group continuation differs')
    report=dict(image_sha256=hashlib.sha256((image/'checkpoint').read_bytes()).hexdigest(),
        group_entries_verified=len(rows),distinct_source_operations=len(source),
        source_words_shared_counters_spills_fields_and_continuations_match=True)
    (image/'system-groups-compiled.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    import argparse,json
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True);parser.add_argument('--annotated',required=True)
    print(json.dumps(verify_compiled(**vars(parser.parse_args())),indent=2))
