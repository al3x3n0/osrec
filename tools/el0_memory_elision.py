"""Elide immutable literal checks and reuse immutable kernel-page admission.

No live user translation is cached. Page admission applies only to the fixed,
page-aligned hardware ranges constructed with the pretranslated backend.
"""
from el0_flat_lower import LOAD,USER,REGISTER,WB,EXCLUSIVE,ALIGNED,PAIR,HINT
from el0_hardware import PCREL
import struct


def literal_proof(pc,op,physical,read,immutable,ram_base,ram_bytes,read_ranges):
    if op.length!=1 or not op.info&PCREL or not op.info&LOAD or op.info&(USER|HINT|EXCLUSIVE):return None
    size=1<<(op.info>>15&7);address=pc+op.imm
    if not any(lo<=address and address+size<=hi for lo,hi in read_ranges):return None
    try:pa=physical(address)
    except (ValueError,IndexError):return None
    if pa<ram_base or size>ram_bytes or pa-ram_base>ram_bytes-size:return None
    if not any(lo<=pa and pa+size<=lo+length for lo,length in immutable):return None
    # Reject noncontiguous backing at the end and preserve the original bytes.
    try:
        if physical(address+size-1)!=pa+size-1:return None
        data=bytes(read(pa,size))
    except (ValueError,IndexError):return None
    if len(data)!=size:return None
    return dict(pc=pc,word=op.word,address=address,physical=pa,data=data)


def immutable_spans(pages):
    spans=[]
    for page in sorted(pages):
        if spans and spans[-1][0]+spans[-1][1]==page:spans[-1][1]+=4096
        else:spans.append([page,4096])
    return spans


def literal_path(proof,following):
    """The same literal load, relocated to an immutable local literal pool."""
    word=(proof['word']&~(0x7ffff<<5))|(2<<5)
    data=proof['data'];lines=['.inst 0x%08x'%word,'b '+following]
    lines+=['.word 0x%08x'%int.from_bytes(data[i:i+4],'little') for i in range(0,len(data),4)]
    return ''.join('    '+line+'\n' for line in lines)


def page_cache_eligible(op,native_sp):
    return (op.length==1 and bool(op.info&ALIGNED) and not op.info&(USER|PCREL|REGISTER|WB|EXCLUSIVE|PAIR|HINT)
            and not op.imm and (op.info&31!=31 or native_sp))


def page_cache_probe(pc,op,following,native_sp):
    """Flag-free hit: check mode, alignment and a full 64-bit page tag.

    The nonzero tag is VA|4095. Fill happens only after the original range
    admission succeeds. All endpoints must be page aligned, so an aligned
    single acquire/release access admits the entire containing page.
    """
    if not page_cache_eligible(op,native_sp):return ''
    cache='.Lmpc%x'%pc;miss=cache+'_miss';base=op.info&31
    lines=['stp x16,x17,[sp,#-16]!']
    lines+=['add x16,sp,#16'] if base==31 else ['mov x16,x%d'%base]
    lines+=['tbnz x16,#%d,%s'%(bit,miss) for bit in range(op.info>>15&7)]
    lines+=['adrp x17,flat_shadow','ldr x17,[x17,:lo12:flat_shadow+80]','cbz x17,'+miss,
            'orr x16,x16,#4095','adrp x17,'+cache,'ldr x17,[x17,:lo12:'+cache+']',
            'eor x16,x16,x17','cbnz x16,'+miss,'ldp x16,x17,[sp],#16',
            '.inst 0x%08x'%op.word,'b '+following,miss+':','ldp x16,x17,[sp],#16',
            '.pushsection .data,"aw"','.balign 8',cache+':','.quad 0','.popsection']
    return ''.join(line+'\n' if line.endswith(':') or line.startswith('.') and not line.startswith('.inst') else '    '+line+'\n' for line in lines)


def page_cache_fill(pc,address,pointer,work):
    cache='.Lmpc%x'%pc
    return ['orr x%d,x%d,#4095'%(work,address),'adrp x%d,%s'%(pointer,cache),
            'str x%d,[x%d,:lo12:%s]'%(work,pointer,cache)]


def user_load_groups(descriptions):
    """Consecutive explicit loads may share one fresh translation and guard.

    No store, branch, pointer write or context edge can intervene. Original
    per-instruction entries remain available for indirect entry and fallback.
    """
    result={}
    def admitted(op,metadata):
        return (op.length==1 and op.info&(USER|LOAD)==USER|LOAD and not op.word&(1<<26)
                and not op.info&(REGISTER|WB|EXCLUSIVE|ALIGNED|PAIR|HINT|PCREL)
                and not metadata&0x60000000)
    for pc,(op,metadata) in sorted(descriptions.items()):
        if not admitted(op,metadata):continue
        size=1<<(op.info>>15&7);base=op.info&31;address=op.info>>10&31;group=[op]
        for i in range(1,4):
            item=descriptions.get(pc+4*i)
            if item is None:break
            other,m=item
            if (not admitted(other,m) or other.info&31!=base or other.info>>15&7!=op.info>>15&7
                    or other.imm!=op.imm+size*i or other.word&31==address
                    or any(x.word&31==base for x in group)):break
            group.append(other)
        if len(group)>1:result[pc]=tuple(group)
    return result


def validate_page_cache_ranges(elf,checked,metadata):
    """Bind page admission to immutable, page-aligned range tables in the ELF."""
    symbols={s['name']:s for s in elf.symbols if s['shndx']}
    flag=symbols.get('flat_memory_page_cache_mode')
    mode=struct.unpack('<Q',elf.read(flag['value'],8))[0] if flag else 0
    config=metadata.get('fixed_page_memory_cache')
    if mode not in (0,1) or bool(mode)!=bool(config):raise ValueError('fixed page memory cache mode differs from metadata')
    if not mode:return
    if config.get('page_bytes')!=4096 or config.get('sites',0)<=0:
        raise ValueError('invalid fixed page memory cache geometry')
    def readonly(symbol,size):
        lo=symbol['value']&-4096;hi=(symbol['value']+size+4095)&-4096
        if elf.sections[symbol['shndx']]['flags']&1 or any(
                s['flags']&2 and lo<((s['address']+s['memory_bytes']+4095)&-4096) and
                (s['address']&-4096)<hi for s in checked['load_segments']):
            raise ValueError('fixed page memory cache admission is writable')
    readonly(flag,8)
    for name,key in (('flat_direct_read','read_ranges'),('flat_direct_write','write_ranges')):
        expected=metadata[key]
        if any(lo<=0 or lo>=hi or (lo|hi)&4095 or hi>1<<64 for lo,hi in expected):
            raise ValueError('fixed page memory cache ranges are not page aligned')
        symbol=symbols[name];size=16*(len(expected)+1);readonly(symbol,size)
        actual=list(struct.iter_unpack('<2Q',elf.read(symbol['value'],size)))
        if actual!=[tuple(row) for row in expected]+[(0,0)]:
            raise ValueError('fixed page memory cache ranges differ from metadata')


def verify_compiled(image,annotated):
    """Audit relocated literal bytes and coalesced native words in the ELF."""
    import hashlib,json
    from pathlib import Path
    from export_el0_program import Package
    from el0_flat_lower import decode,sign
    from el0_instruction_profile import MARKER
    from kernel_source_verify import Elf
    image,annotated=Path(image).resolve(),Path(annotated).resolve()
    proof=json.loads((image/'memory-elision.json').read_text())
    package=Package(Path(json.loads((image/'manifest.json').read_text())['package']))
    def original(pc):
        word=package.word(pc)
        return package.sites[pc] if word==0xd421e000 and pc in package.sites else (word,0)
    literals=proof['immutable_literals'];groups=proof['coalesced_user_loads']
    needed={'.Lp%x'%pc for row in literals for pc in (row['pc'],row['pc']+4)}
    needed|={'.Lhw%x_insn%x'%(row['pc'],row['pc']+4*i) for row in groups for i in range(len(row['words']))}
    markers={};pending=None
    with (annotated/'program.S').open() as stream:
        for line in stream:
            label=line.strip().removesuffix(':')
            if label in needed:pending=label
            elif pending is not None:
                if not label.startswith(MARKER):raise ValueError('memory audit marker missing at '+pending)
                markers[label]=pending;pending=None
    elf=Elf(annotated/'checkpoint')
    addresses={markers[s['name']]:s['value'] for s in elf.symbols if s['name'] in markers}
    if set(addresses)!=needed:raise ValueError('memory audit symbols missing')
    for row in literals:
        pc=row['pc'];word,metadata=original(pc);op=decode(word);data=bytes.fromhex(row['data'])
        if metadata or word!=row['word'] or pc+op.imm!=row['address'] or package.pa(row['address'])!=row['physical']:
            raise ValueError('literal source proof differs from captured code')
        offset=row['physical']-package.h[2]
        if package.memory[offset:offset+len(data)]!=data:raise ValueError('literal bytes differ from captured RAM')
        at=addresses['.Lp%x'%pc];actual,branch=struct.unpack('<2I',elf.read(at,8))
        if actual!=(word&~(0x7ffff<<5))|(2<<5) or elf.read(at+8,len(data))!=data:
            raise ValueError('compiled literal relocation or data differs')
        if branch&0xfc000000!=0x14000000 or at+4+4*sign(branch&0x3ffffff,26)!=addresses['.Lp%x'%(pc+4)]:
            raise ValueError('literal pool is not skipped by the original continuation')
    grouped_words=0
    for row in groups:
        pc=row['pc'];ops={}
        for i,word in enumerate(row['words']):
            source,metadata=original(pc+4*i)
            if source!=word:raise ValueError('coalesced source differs from captured code')
            op=decode(word)
            if metadata&0x80000000:op.info|=USER
            ops[pc+4*i]=(op,metadata)
        group=user_load_groups(ops).get(pc,())
        if len(group)!=len(row['words']):raise ValueError('coalesced source lacks a shared-translation proof')
        address=group[0].info>>10&31;previous=None
        for i,op in enumerate(group):
            at=addresses['.Lhw%x_insn%x'%(pc,pc+4*i)]
            word,=struct.unpack('<I',elf.read(at,4))
            if word!=(op.native&~(31<<5))|(address<<5):raise ValueError('coalesced native instruction differs')
            if previous is not None:
                step=op.imm-group[i-1].imm
                actual,=struct.unpack('<I',elf.read(previous+4,4))
                if at!=previous+8 or actual!=0x91000000|(step<<10)|(address<<5)|address:
                    raise ValueError('coalesced address increment differs')
            previous=at;grouped_words+=1
    for pc in proof['aligned_page_cache_sites']:
        word,metadata=original(pc)
        if metadata or not page_cache_eligible(decode(word),True):raise ValueError('invalid fixed-page cache site')
    report=dict(image_sha256=hashlib.sha256((image/'checkpoint').read_bytes()).hexdigest(),
        immutable_literals_verified=len(literals),coalesced_groups_verified=len(groups),
        coalesced_native_words_verified=grouped_words,fixed_page_sites_verified=len(proof['aligned_page_cache_sites']),
        original_literal_bytes_and_continuations_match=True,original_group_words_and_order_match=True)
    (image/'memory-compiled.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    import argparse,json
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True);parser.add_argument('--annotated',required=True)
    print(json.dumps(verify_compiled(**vars(parser.parse_args())),indent=2))
