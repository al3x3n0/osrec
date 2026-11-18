"""Conservative address dataflow for the admitted user-entry/return contract.

Unsigned intervals avoid enumerating dynamic indices. Every CFG predecessor is
joined; widening loses information rather than selecting observed loop values.
Only immutable memory supplies constants. A mapping origin is attached at the
memory use, where the complete address interval and access can be proved.
"""
from bisect import bisect_left, bisect_right
from collections import deque,Counter
from dataclasses import dataclass
from el0_flat_lower import *
from el0_pretranslate import Bindings
from va_constants import bitmask

MASK=(1<<64)-1
ANALYSIS_VERSION = 2


@dataclass(frozen=True)
class Bound:
    lo:int
    hi:int

    @staticmethod
    def constant(value):return Bound(value&MASK,value&MASK)


def join(a,b):
    return None if a is None or b is None else Bound(min(a.lo,b.lo),max(a.hi,b.hi))


def arithmetic(a,b,subtract=False,width=64):
    if a is None or b is None:return None
    mask=(1<<width)-1
    if a.lo==a.hi and b.lo==b.hi:
        return Bound.constant((a.lo-b.lo if subtract else a.lo+b.lo)&mask)
    lo=a.lo-b.hi if subtract else a.lo+b.lo
    hi=a.hi-b.lo if subtract else a.hi+b.hi
    return Bound(lo,hi) if 0<=lo<=hi<=mask else None


def shifted(value,shift):
    if value is None:return None
    return Bound(value.lo<<shift,value.hi<<shift) if value.hi<<shift<=MASK else None


def extended(value,extension,shift):
    if value is None:return None
    bits=(8,16,32,64)[extension&3];mask=(1<<bits)-1
    if value.lo==value.hi:
        raw=value.lo&mask
        return Bound.constant((sign(raw,bits) if extension&4 else raw)<<shift)
    if value.hi>mask:value=Bound(0,mask)
    if extension&4:
        if value.lo<1<<(bits-1)<=value.hi:return None
        if value.lo>=1<<(bits-1):return None
    return shifted(value,shift)


def unsigned_bitfield(value,rotate,last,width):
    """UBFM aliases: extract/LSR when last>=rotate, otherwise UBFIZ/LSL.

    Truncation is not monotonic across a field boundary. Only retain endpoint
    bounds when both endpoints lie within the same truncation bucket.
    """
    if not 0<=rotate<width or not 0<=last<width:return None
    if last>=rotate:
        bits=last-rotate+1;shift=0;drop=rotate
    else:
        bits=last+1;shift=width-rotate;drop=0
    mask=(1<<bits)-1
    if value is None:return Bound(0,mask<<shift)
    lo=value.lo>>drop;hi=value.hi>>drop
    if lo>>bits!=hi>>bits:return Bound(0,mask<<shift)
    return Bound((lo&mask)<<shift,(hi&mask)<<shift)


def effective(pc,op,state):
    info=op.info
    base=Bound.constant(pc) if info&(1<<44) else state[info&31]
    if info&POST:return base
    if info&REGISTER:
        rm=info>>5&31
        offset=Bound.constant(0) if rm==31 else state[rm]
        offset=extended(offset,info>>24&7,info>>27&7)
        return arithmetic(base,offset)
    return arithmetic(base,Bound.constant(abs(op.imm)),op.imm<0)


def mapping_span(binding,bound,size,write=False):
    if bound is None or bound.hi+size>1<<64:return None
    # Every possible byte lies in this contiguous initial binding. Checking
    # only the endpoints would miss holes, permissions, and intervening aliases.
    length=bound.hi-bound.lo+size
    pa=binding.physical(bound.lo,length,write)
    if pa is None:return None
    row=next(a for a in binding.aliases if a['va']<=bound.lo<a['va']+a['bytes'])
    return row,pa,length


def adjacent_comparisons(words, adapted_pcs):
    """Identify adjacent CMP-immediate and conditional-branch instructions."""
    comparisons={}
    for pc,w in words.items():
        previous=words.get(pc-4,0)
        if (pc not in adapted_pcs and pc-4 not in adapted_pcs and
                w&0xff000010==0x54000000 and
                previous&0x7f80001f==0x7100001f and previous>>5&31!=31):
            immediate = (previous >> 10 & 4095) << (12 if previous & (1 << 22) else 0)
            comparisons[pc] = (previous >> 5 & 31, immediate, 64 if previous >> 31 else 32)
    return comparisons


def constrain_comparison(state,comparison,condition):
    """Refine unsigned CMP predicates; None means the edge is impossible."""
    register,constant,width=comparison;mask=(1<<width)-1;bound=state[register]
    # A W comparison constrains only the low word, not the upper X bits.
    if width==32 and (bound is None or bound.hi>mask):return state
    bound=bound or Bound(0,mask);lo,hi=bound.lo,bound.hi
    if condition==0:lo=max(lo,constant);hi=min(hi,constant)
    elif condition==1:
        if lo==constant:lo+=1
        if hi==constant:hi-=1
    elif condition==2:lo=max(lo,constant)
    elif condition==3:hi=min(hi,constant-1)
    elif condition==8:lo=max(lo,constant+1)
    elif condition==9:hi=min(hi,constant)
    else:return state
    if lo>hi:return None
    result=list(state);result[register]=Bound(lo,hi)
    return tuple(result)


def analyze(words,initial,package,aliases,immutable,*,version=ANALYSIS_VERSION,adapted_pcs=()):
    from el0_pretranslate import user_proofs
    if version not in (1, ANALYSIS_VERSION):
        raise ValueError('unsupported dataflow analysis version')
    _,finite_states=user_proofs(words,initial,package,aliases,immutable,with_states=True)
    comparisons = adjacent_comparisons(words, adapted_pcs) if version >= 2 else {}
    thresholds = {0, MASK}
    for _, constant, _ in comparisons.values():
        thresholds.update(v for v in (constant-1, constant, constant+1) if 0 <= v <= MASK)
    thresholds = sorted(thresholds)
    binding=Bindings(aliases,immutable);unknown=(None,)*32
    entry=initial[32];states={entry:tuple(Bound.constant(x) for x in initial[:32])}
    bypassed_comparisons = {entry}
    pending=deque([entry]);queued={entry};expansions=Counter();widened=set()
    def put(pc,state,*,compared=False):
        if pc not in words:return
        # A later incoming edge can invalidate the compare even when it
        # supplies the same register bounds. Revisit the branch in that case.
        loses_comparison = pc in comparisons and not compared and pc not in bypassed_comparisons
        if loses_comparison:
            bypassed_comparisons.add(pc)
        # Intersect two independently conservative analyses. Finite facts keep
        # jump-table targets precise; intervals retain indices beyond LIMIT.
        facts=finite_states.get(pc)
        if facts is not None:
            refined=list(state)
            for r,values in enumerate(facts):
                if values:
                    bound=Bound(min(values),max(values));old_bound=refined[r]
                    if old_bound is None:refined[r]=bound
                    else:
                        lo=max(bound.lo,old_bound.lo);hi=min(bound.hi,old_bound.hi)
                        if lo>hi:raise ValueError('inconsistent address dataflow domains')
                        refined[r]=Bound(lo,hi)
            state=tuple(refined)
        old=states.get(pc)
        merged=list(state) if old is None else [join(a,b) for a,b in zip(old,state)]
        if old is not None:
            for r,(a,b) in enumerate(zip(old,merged)):
                if b!=a:
                    expansions[pc,r]+=1
                    if expansions[pc,r]>8:
                        if comparisons and a is not None and b is not None:
                            lo=thresholds[bisect_right(thresholds,b.lo)-1] if b.lo<a.lo else b.lo
                            hi=thresholds[bisect_left(thresholds,b.hi)] if b.hi>a.hi else b.hi
                            merged[r]=Bound(lo,hi)
                        else:merged[r]=None
                        widened.add((pc,r))
        merged=tuple(merged)
        if old!=merged or loses_comparison:
            states[pc]=merged
            if pc not in queued:pending.append(pc);queued.add(pc)
    while pending:
        pc=pending.popleft();queued.remove(pc);state=states[pc];out=list(state)
        w=words[pc];op=decode(w);rd=w&31;rn=w>>5&31;rm=w>>16&31
        width=64 if w>>31 else 32;mask=(1<<width)-1
        def source(r,sp=False):return state[r] if r<31 or sp else Bound.constant(0)
        if w&0xfc000000 in (0x14000000,0x94000000):
            target=(pc+4*sign(w&0x3ffffff,26))&MASK
            if w&0x80000000:put(target,unknown);put(pc+4,unknown)
            else:put(target,state)
            continue
        if w&0xff000010==0x54000000 or w&0x7e000000 in (0x34000000,0x36000000):
            bits=14 if w&0x7e000000==0x36000000 else 19
            taken=fallthrough=state
            if pc in comparisons and pc not in bypassed_comparisons:
                taken=constrain_comparison(state,comparisons[pc],w&15)
                fallthrough=constrain_comparison(state,comparisons[pc],(w&15)^1)
            if taken is not None:put(pc+4*sign(w>>5&((1<<bits)-1),bits),taken)
            if fallthrough is not None:put(pc+4,fallthrough)
            continue
        if op.kind==INDIRECT:
            targets=source(rn)
            finite_targets=finite_states.get(pc,unknown)[rn]
            selected=finite_targets if finite_targets is not None else words if targets is None else (dest for dest in words if targets.lo<=dest<=targets.hi)
            returns=w&0xfffffc1f in (0xd63f0000,0xd65f0000)
            for dest in selected:put(dest,unknown if returns or targets is None else state)
            if w&0xfffffc1f==0xd63f0000:put(pc+4,unknown)
            continue
        if op.kind==UNSUPPORTED:
            out=list(unknown)
        elif op.kind==SVC:
            out[0]=None # Same checked return-preservation contract as user_proofs.
        elif op.kind==MEMORY:
            ea=effective(pc,op,state);info=op.info;size=1<<(info>>15&7)
            if info&LOAD and not info&HINT and not w&(1<<26):
                for dest,index in ((rd,0),(w>>10&31,1)) if info&PAIR else ((rd,0),):
                    if dest==31:continue
                    signed=(bool(info&PAIR) and w>>30==1) or (not info&PAIR and w>>22&3>=2)
                    value=Bound(0,(1<<(8*size))-1) if size<8 and not signed else None
                    if ea is not None and ea.lo==ea.hi and binding.constant(ea.lo+index*size,size):
                        pa=binding.physical(ea.lo+index*size,size)-package.h[2]
                        raw=int.from_bytes(package.memory[pa:pa+size],'little')
                        result=sign(raw,8*size) if signed else raw
                        if not info&PAIR and w>>22&3==3:result&=0xffffffff
                        value=Bound.constant(result)
                    out[dest]=value
            if info&WB:out[rn]=arithmetic(state[rn],Bound.constant(abs(op.imm)),op.imm<0)
            if info&EXCLUSIVE:out=list(unknown)
        elif w&0x9f000000 in (0x10000000,0x90000000):
            delta=sign((w>>29&3)|((w>>5&0x7ffff)<<2),21)
            if rd!=31:out[rd]=Bound.constant((pc&-4096)+(delta<<12) if w>>31 else pc+delta)
        elif w&0x1f800000==0x12800000:
            opc=w>>29&3;shift=(w>>21&3)*16;value=(w>>5&65535)<<shift
            if rd!=31:
                if opc in (0,2):out[rd]=Bound.constant((~value if opc==0 else value)&mask)
                elif state[rd] is not None and state[rd].lo==state[rd].hi:
                    out[rd]=Bound.constant(((state[rd].lo&~(65535<<shift))|value)&mask)
                else:out[rd]=None
        elif w&0x1f800000==0x11000000:
            imm=(w>>10&4095)<<(12 if w&(1<<22) else 0)
            if rd!=31 or not w&(1<<29):out[rd]=arithmetic(source(rn,True),Bound.constant(imm),bool(w&(1<<30)),width)
        elif w&0x1f800000==0x12000000:
            imm=bitmask(w>>22&1,w>>16&63,w>>10&63)&mask;opc=w>>29&3;value=source(rn)
            if rd!=31:
                if value is not None and value.lo==value.hi:
                    x=value.lo&mask;out[rd]=Bound.constant(x&imm if opc in (0,3) else x|imm if opc==1 else x^imm)
                elif opc in (0,3):out[rd]=Bound(0,min(imm,value.hi) if value is not None and value.hi<=mask else imm)
                else:out[rd]=None
            elif opc!=3:out[31]=None
        elif w&0x7f800000==0x53000000 and (w>>22&1)==(w>>31):
            if rd!=31:out[rd]=unsigned_bitfield(source(rn),w>>16&63,w>>10&63,width)
        elif w&0x1f200000==0x0b000000:
            shift=w>>22&3;amount=w>>10&63;other=source(rm)
            if shift==0:other=shifted(other,amount)
            else:other=None
            if rd!=31:out[rd]=arithmetic(source(rn),other,bool(w&(1<<30)),width)
        elif w&0x1f200000==0x0b200000:
            other=extended(source(rm),w>>13&7,w>>10&7)
            if rd!=31 or not w&(1<<29):out[rd]=arithmetic(source(rn,True),other,bool(w&(1<<30)),width)
        elif w&0xffe0ffe0==0xaa0003e0: # MOV Xd,Xm (ORR with XZR)
            if rd!=31:out[rd]=source(rm)
        elif op.kind==STACK:
            if op.info&DST_SP:out[31]=None
            if rd!=31:out[rd]=None
        elif op.kind in (SYSTEM,UNSUPPORTED):
            out=list(unknown)
        elif w>>25&15 in (5,8,9,13):
            # Remaining scalar data-processing forms write Rd (or discard it
            # as XZR); they cannot change unrelated address registers or SP.
            if rd!=31:out[rd]=None
        elif w!=0xd503201f:
            # Unmodelled instructions do not receive invented register effects.
            out=list(unknown)
        put(pc+4,tuple(out),compared=pc+4 in comparisons)
    proofs={};rejected={}
    for pc,w in words.items():
        op=decode(w)
        if op.kind!=MEMORY:continue
        if pc not in states:rejected[pc]='unreachable from admitted entry';continue
        if op.info&(USER|EXCLUSIVE|HINT|WB|(1<<44)):
            rejected[pc]='transfer form not admitted';continue
        state=states[pc];ea=effective(pc,op,state)
        size=(1<<(op.info>>15&7))*(2 if op.info&PAIR else 1)
        span=mapping_span(binding,ea,size,not bool(op.info&LOAD))
        if span is None:rejected[pc]='unknown or non-admitted address interval';continue
        if op.info&ALIGNED and (ea.lo!=ea.hi or ea.lo%size):
            rejected[pc]='alignment not proved';continue
        # Native helper spills must not overwrite bytes observed by the payload,
        # including through a different alias of the same physical stack page.
        sp=state[31]
        if sp is None or sp.lo!=sp.hi or sp.lo%16:
            rejected[pc]='native stack alignment not proved';continue
        spill=None if sp is None or sp.lo<16 else mapping_span(binding,Bound(sp.lo-16,sp.hi-16),16,True)
        if spill is None:rejected[pc]='native stack spill span not proved';continue
        row,pa,length=span;_,stack_pa,stack_length=spill
        if pa<stack_pa+stack_length and stack_pa<pa+length:
            rejected[pc]='payload may alias native scratch spill';continue
        proofs[pc]=dict(bounds=[ea.lo,ea.hi],bytes=size,write=not bool(op.info&LOAD),
                        origin=dict(row),stack_bounds=[sp.lo,sp.hi])
    return dict(proofs=proofs,rejected=rejected,reachable=len(states),widened_registers=len(widened),
                comparison_edges=sum(pc not in bypassed_comparisons and pc in states for pc in comparisons),
                contract='initial user entry; checked syscall return preservation; initial resident bindings')


def access_path(pc,op,proof,ram_base,following):
    """Execute the live address with a statically selected affine conversion."""
    from el0_hardware import add_immediate,add_register_offset
    if op.kind!=MEMORY or op.length!=1 or op.info&(USER|EXCLUSIVE|HINT|WB|(1<<44)):
        raise ValueError('transfer form not admitted for dataflow lowering')
    address=op.info>>10&31;base=op.info&31
    used={address,base,op.word&31}
    if op.info&PAIR:used.add(op.word>>10&31)
    if op.info&REGISTER:used.add(op.info>>5&31)
    pointer=temporary(used);a,p='x%d'%address,'x%d'%pointer
    code=['stp %s,%s,[sp,#-16]!'%(a,p)]
    code+=['add %s,sp,#16'%a] if base==31 else ['mov %s,x%d'%(a,base)]
    if op.info&REGISTER:
        code+=add_register_offset(address,address,op.info>>5&31,op.info>>24&7,op.info>>27&7,pointer)
    elif op.imm:code+=add_immediate(address,address,op.imm,pointer)
    row=proof['origin'];target='flat_phys+0x%x'%(row['pa']-ram_base)
    code+=add_immediate(address,address,-row['va'],pointer)
    code+=['adrp %s,%s'%(p,target),'add %s,%s,:lo12:%s'%(p,p,target),
           'add %s,%s,%s'%(a,a,p),'.inst 0x%08x'%op.native,
           'ldp %s,%s,[sp],#16'%(a,p),'b '+following]
    return ''.join('    '+line+'\n' for line in code)


def report_image(image,*,version=ANALYSIS_VERSION):
    """Analyze the captured user CFG without changing the generated executor."""
    import hashlib,json,struct
    from pathlib import Path
    from export_el0_program import Package
    from kernel_source_verify import Elf
    from source_image_el0 import instruction_ranges
    from el0_pretranslate import user_aliases,user_proofs
    image=Path(image);manifest=json.loads((image/'manifest.json').read_text())
    if not (manifest['runtime_validation'] or manifest['trust_syscall_abi']):
        raise ValueError('dataflow requires the checked or explicitly trusted return contract')
    package=Package(Path(manifest['package']));user=Elf(manifest['user_elf'])
    try:
        state_hash=hashlib.sha256(package.data).hexdigest()
        user_hash=hashlib.sha256(user.data).hexdigest()
        if state_hash!=manifest['native_state_sha256']:raise ValueError('captured state identity mismatch')
        if user_hash!=json.loads((package.path/'manifest.json').read_text())['application']['user_elf_sha256']:
            raise ValueError('user ELF identity mismatch')
        words={};metadata={}
        for lo,hi in instruction_ranges(user,[(s['addr'],s['addr']+s['size']) for s in user.sections if s['flags']&4 and s['size']]):
            for pc in range(lo,hi,4):
                word=package.word(pc)
                if word==0xd421e000 and pc in package.sites:word,metadata[pc]=package.sites[pc]
                words[pc]=word
        immutable=set()
        for s in user.sections:
            if s['flags']&2 and not s['flags']&1 and s['size']:
                immutable.update(package.pa(va)&-4096 for va in range(s['addr']&-4096,(s['addr']+s['size']+4095)&-4096,4096))
        mapping=json.loads((image/'hardware-memory.json').read_text())
        spans=[(pa,4096) for pa in sorted(immutable)]+[(pa,4096) for pa in mapping['pretranslated_memory'].get('watched_pages',[])]
        initial=struct.unpack_from('<34Q',package.data,80);aliases=user_aliases(package)
        hook=int(json.loads((package.path/'manifest.json').read_text())['application']['result_hook'],0)
        result=analyze(words,initial,package,aliases,spans,version=version,adapted_pcs={hook}|{pc for pc,m in metadata.items() if m})
        for pc in list(result['proofs']):
            if metadata.get(pc,0):
                del result['proofs'][pc];result['rejected'][pc]='architecture metadata requires adapter'
        finite=user_proofs(words,initial,package,aliases,spans)
        result.update(native_state_sha256=state_hash,user_elf_sha256=user_hash,
                      scope='captured user CFG only',complete_static_relocation=False,
                      runtime_rewrites_enabled=bool(manifest.get('dataflow_memory')),finite_set_sites=len(finite),
                      new_sites=sorted(set(result['proofs'])-finite),
                      rejection_counts=dict(Counter(result['rejected'].values())))
        return result
    finally:
        package.memory.close();package.file.close()


def verify_compiled(image,compiler='/opt/homebrew/opt/llvm@16/bin/clang'):
    """Rebuild source proofs and independently assemble each linked rewrite."""
    import hashlib,json,subprocess,tempfile
    from pathlib import Path
    from export_el0_program import Package
    from kernel_source_verify import Elf
    from el0_compact_access import verify_compiled as verify_loads
    from el0_control import layout,gateway_sizes
    image=Path(image);manifest=json.loads((image/'manifest.json').read_text())
    if not manifest.get('dataflow_memory') or not manifest['runtime_validation']:
        raise ValueError('dataflow image requires runtime validation')
    verify_loads(image)
    version=manifest.get('dataflow_analysis_version',1)
    reconstructed=report_image(image,version=version)
    excluded={row['pc'] for row in json.loads((image/'compact-loads.json').read_text())['sites']}
    package=Package(Path(manifest['package']))
    try:
        hook=int(json.loads((package.path/'manifest.json').read_text())['application']['result_hook'],0)
        expected=[dict(pc=pc,**proof) for pc,proof in sorted(reconstructed['proofs'].items()) if pc not in excluded and pc!=hook]
        recorded=json.loads((image/'dataflow-memory.json').read_text())
        if recorded['sites']!=expected:raise ValueError('dataflow records differ from reconstructed proofs')
        if manifest['dataflow_memory_sites']!=len(expected):raise ValueError('dataflow site count mismatch')
        labels,_,size=layout(image/'program.S',gateway_sizes(Path(__file__).resolve().parents[1]/'runtime/el0_flat/gateway.inc'))
        bases=[]
        for line in (image/'checkpoint.map').read_text().splitlines():
            if line.rstrip().endswith('program-asm.o:(.text)'):
                fields=line.split()
                if int(fields[2],16)!=size:raise ValueError('generated text layout mismatch')
                bases.append(int(fields[0],16))
        if len(bases)!=1:raise ValueError('missing or ambiguous generated text')
        elf=Elf(image/'checkpoint');symbols={s['name']:s['value'] for s in elf.symbols if s['shndx']}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for row in expected:
                pc=row['pc'];at=bases[0]+labels['.Lp%x'%pc];next_at=bases[0]+labels['.Lp%x'%(pc+4)]
                word=package.word(pc)
                if word==0xd421e000:word=package.sites[pc][0]
                path=access_path(pc,decode(word),row,package.h[2],'destination')
                source='.text\n.global _start\n_start:\n'+path
                (root/'expected.S').write_text(source)
                assembled=subprocess.run([compiler,'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib',
                    '-Wl,-Ttext=0x%x,-e,_start,--build-id=none'%at,
                    '-Wl,--defsym=flat_phys=0x%x,--defsym=destination=0x%x'%(symbols['flat_phys'],next_at),
                    str(root/'expected.S'),'-o',str(root/'expected')],capture_output=True,text=True)
                if assembled.returncode:raise ValueError('dataflow audit assembly failed: '+assembled.stderr)
                reference=Elf(root/'expected').read(at,len(path.splitlines())*4)
                if elf.read(at,len(reference))!=reference:raise ValueError('linked dataflow rewrite mismatch at '+hex(pc))
        result=dict(sites=len(expected),image_sha256=hashlib.sha256(elf.data).hexdigest(),
                    source_proofs_reconstructed=True,linked_instructions_verified=True,complete_static_relocation=False)
        (image/'dataflow-memory-compiled.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
    finally:
        package.memory.close();package.file.close()


if __name__=='__main__':
    import argparse,json
    from pathlib import Path
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True)
    parser.add_argument('--out')
    parser.add_argument('--verify-compiled',action='store_true')
    args=parser.parse_args()
    if not args.verify_compiled and not args.out:parser.error('--out is required for an analysis report')
    result=verify_compiled(args.image) if args.verify_compiled else report_image(args.image)
    if args.out:Path(args.out).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:(len(v) if k in ('proofs','rejected') else v) for k,v in result.items()},indent=2))
