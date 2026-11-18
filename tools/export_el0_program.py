#!/usr/bin/env python3
"""AOT lower the captured user/kernel checkpoint, preserving native code flow.

Default coverage is a function closure seeded by the workload's syscall set.
--whole-kernel-text includes all resident persistent ELF-identified kernel code.
Unknown runtime targets stop with their source PC. Inputs never select paths.
"""
import argparse,bisect,collections,hashlib,json,mmap,re,struct
from pathlib import Path
from export_native_checkpoint import sparse_runs,expected_events
from kernel_code_closure import Code
from kernel_source_verify import Elf
from source_image_el0 import instruction_ranges
from el0_flat_lower import *
from el0_hardware import COMPACT_ACCESS_WIDTHS,COMPACT_WIDTH_BOUNDS,COMPACT_WIDTH_BOUNDS_ENCODING,compact_width_ranges

MASK48=(1<<48)-1
ROOT=Path(__file__).resolve().parents[1]

class Package:
    def __init__(self,path):
        self.path=Path(path);self.data=(self.path/'native.bin').read_bytes();self.h=struct.unpack_from('<10Q',self.data)
        if self.h[:2]!=(0x3145564954414e4c,1):raise ValueError('unsupported native checkpoint version')
        self.shadow=self.data[872:872+532584]
        at=872+532584;self.ranges=self.data[at:at+self.h[5]*16];at+=self.h[5]*16
        self.sites={pc:(w,k) for pc,w,k in struct.iter_unpack('<QII',self.data[at:at+self.h[6]*16])};at+=self.h[6]*16
        self.origins=self.data[at:at+self.h[8]*8];at+=self.h[8]*8
        self.maps=list(struct.iter_unpack('<4Q',self.data[at:]));self.starts=[v for v,p,s,a in self.maps]
        if len(self.maps)!=self.h[9] or self.starts!=sorted(self.starts):raise ValueError('invalid captured mapping table')
        self.file=(self.path/'memory.bin').open('rb');self.memory=mmap.mmap(self.file.fileno(),0,access=mmap.ACCESS_READ)
        if len(self.memory)!=self.h[3]:raise ValueError('captured RAM size mismatch')
    def pa(self,va):
        i=bisect.bisect_right(self.starts,va)-1
        if i>=0:
            v,p,s,a=self.maps[i]
            if va-v<s:return p+va-v
        table=struct.unpack_from('<Q',self.shadow,72)[0]&0x0000fffffffff000
        for shift in (39,30,21,12):
            d=struct.unpack_from('<Q',self.memory,table-self.h[2]+8*(va>>shift&511))[0]
            if not d&1:raise ValueError('unmapped captured VA '+hex(va))
            if shift>12 and d&2:table=d&0x0000fffffffff000;continue
            return (d&0x0000fffffffff000)&~((1<<shift)-1) | va&((1<<shift)-1)
        raise ValueError('invalid mapping')
    def word(self,va):return struct.unpack_from('<I',self.memory,self.pa(va)-self.h[2])[0]

def text_metadata(out,p,user_elf,extra_immutable=()):
    """Derive immutable physical text and admitted user executable mappings."""
    selected=set();missing=set()
    for line in (Path(out)/'program.S').open():
        match=re.match(r'\.Lp([0-9a-f]+):',line)
        if match:selected.add(int(match[1],16))
        match=re.match(r'    \.quad 0x([0-9a-f]+),0,0,0x[0-9a-f]+,0x0,9,',line)
        if match:missing.add(int(match[1],16))
    pages={pc&~4095 for pc in selected-missing}
    def merge(values):
        spans=[]
        for address in sorted(values):
            if spans and spans[-1][0]+spans[-1][1]==address:spans[-1][1]+=4096
            else:spans.append([address,4096])
        return spans
    physical=merge({p.pa(va)&~4095 for va in pages}|set(extra_immutable))
    user=Elf(user_elf);user_pages=set()
    for lo,hi in instruction_ranges(user,[(s['addr'],s['addr']+s['size']) for s in user.sections if s['flags']&4 and s['size']]):
        user_pages.update(range(lo&~4095,(hi+4095)&~4095,4096))
    data='#include "program.h"\nconst struct flat_text_span flat_immutable_text[]={\n'
    data+=''.join('{0x%x,0x%x},\n'%tuple(span) for span in physical)+'};\n'
    data+='const uint64_t flat_immutable_text_count=%d;\n'%len(physical)
    data+='const struct flat_execmap flat_user_text[]={\n'
    data+=''.join('{0x%x,0x%x,4096},\n'%(va,p.pa(va)) for va in sorted(user_pages))+'};\n'
    data+='const uint64_t flat_user_text_count=%d;\n'%len(user_pages)
    (Path(out)/'text.c').write_text(data)
    return physical

def captured_kernel_words(package, code, functions, executable, whole_kernel_text=False, absent=None):
    """Read live captured instructions, retaining ELF code/data boundaries."""
    starts=[a for a,b in executable]
    selected=executable if whole_kernel_text else [code.extent(f) for f in sorted(functions)]
    words={}
    for lo,hi in selected:
        for original in range(lo,hi,4):
            i=bisect.bisect_right(starts,original)-1
            if i<0 or original>=executable[i][1]:continue
            pc=original&MASK48
            try:words[pc]=package.word(pc)
            except ValueError:
                if whole_kernel_text:
                    if absent is None:raise ValueError('whole kernel text is absent from capture at '+hex(original))
                    if absent and absent[-1][1]==original:absent[-1][1]+=4
                    else:absent.append([original,original+4])
    return words


def export(package,vmlinux,user_elf,oracle,out,extra=(),coverage=None,hardware_memory=False,native_kernel_stack=False,pretranslated_memory=False,validation=True,trust_syscall_abi=False,track_pretranslated_writes=False,whole_kernel_text=False,compact_proven_loads=False,compact_dynamic_memory=False,dataflow_memory=False,alias_free_memory=False,elf_ram_initialization=False):
    if validation and trust_syscall_abi:raise ValueError('--trust-syscall-abi requires --no-validation')
    if track_pretranslated_writes and not pretranslated_memory:raise ValueError('--track-pretranslated-writes requires --pretranslated-memory')
    if elf_ram_initialization and not alias_free_memory:
        raise ValueError('--elf-ram-initialization requires --alias-free-memory')
    if dataflow_memory and (not compact_dynamic_memory or not validation):
        raise ValueError('--dataflow-memory requires --compact-dynamic-memory and runtime validation')
    if alias_free_memory:
        if not hardware_memory or pretranslated_memory or native_kernel_stack:
            raise ValueError('--alias-free-memory requires --hardware-memory and logical guest stacks')
        if compact_proven_loads or dataflow_memory:
            raise ValueError('--alias-free-memory does not support user proofs requiring pretranslation')
        compact_dynamic_memory=True
    elif compact_dynamic_memory:
        if not pretranslated_memory:raise ValueError('--compact-dynamic-memory requires --pretranslated-memory')
        compact_proven_loads=True
    compact_table_mode = COMPACT_WIDTH_BOUNDS if alias_free_memory else int(compact_dynamic_memory)
    if compact_proven_loads and not pretranslated_memory:raise ValueError('--compact-proven-loads requires --pretranslated-memory')
    if pretranslated_memory:native_kernel_stack=True
    if native_kernel_stack and not hardware_memory:raise ValueError('native kernel SP requires hardware aliases')
    p=Package(Path(package).resolve());out=Path(out).resolve();vmlinux=Path(vmlinux).resolve();oracle=Path(oracle).resolve()
    dczid=struct.unpack_from('<Q',p.shadow,104+8192+0xd807*8)[0]
    zero_bytes=4<<(dczid&15) if not dczid&16 and dczid&15<=9 else 0
    manifest=json.loads((p.path/'manifest.json').read_text());record=json.loads((oracle/'calls.json').read_text())
    if hashlib.sha256(Path(user_elf).read_bytes()).hexdigest()!=manifest['application']['user_elf_sha256']:raise ValueError('user ELF identity mismatch')
    source=record.get('source_image_sha256') or json.loads((Path(record['image'])/'manifest.json').read_text())['image_sha256']
    if source!=manifest['source_image_sha256']:raise ValueError('oracle identity mismatch')
    code=Code(vmlinux);symbols={s['name']:s for s in code.elf.symbols if s['shndx']}
    native_ranges=sorted([(s['addr']&MASK48,(s['addr']&MASK48)+s['size']) for s in code.elf.sections
                          if s['flags']&4 and s['size']]+[(p.h[7],p.h[7]+16*p.h[8])])
    native_starts=[lo for lo,hi in native_ranges]
    def native_pc(pc):
        i=bisect.bisect_right(native_starts,pc)-1
        return native_kernel_stack and i>=0 and pc<native_ranges[i][1]
    table=symbols['sys_call_table'];roots=set()
    for call in record['calls']:
        n=call['number']
        if 0<=n<table['size']//8:roots.add(code.containing(struct.unpack('<Q',code.elf.read(table['value']+8*n,8))[0]))
    for name in ('vectors','el0t_64_sync','el0_svc','ret_to_user'):roots.add(code.containing(symbols[name]['value']))
    for pc in extra:roots.add(code.containing(pc|0xffff000000000000))
    if coverage:
        # A translated-code listing broadens the static function set only.
        # Its instruction order, branch outcomes and values are never replayed.
        for line in Path(coverage).read_text().splitlines():
            match=re.match(r'0x([0-9a-fA-F]+):',line)
            if match:
                pc=int(match[1],16)
                if 0x800080000000<=pc<0x800082000000:roots.add(code.containing(pc|0xffff000000000000))
    functions=set();pending=list(code.starts if whole_kernel_text else roots)
    while pending:
        f=pending.pop()
        if f is None or f in functions:continue
        functions.add(f);calls,taken,data=code.edges(f);pending.extend((calls|taken)-functions)
    executable=instruction_ranges(code.elf,[(s['addr'],s['addr']+s['size']) for s in code.elf.sections if s['flags']&4 and s['addr'] and not s['name'].startswith('.init')])
    absent_kernel_text=[]
    words=captured_kernel_words(p,code,functions,executable,whole_kernel_text,absent_kernel_text);metadata={}
    user=Elf(user_elf);user_pcs=set()
    for lo,hi in instruction_ranges(user,[(s['addr'],s['addr']+s['size']) for s in user.sections if s['flags']&4 and s['size']]):
        for pc in range(lo,hi,4):words[pc]=p.word(pc);user_pcs.add(pc)
    # Existing address-lowering veneers are captured code too. Each slot has
    # two instructions followed by an eight-byte literal, never four opcodes.
    for index in range(p.h[8]):
        for offset in (0,4):
            pc=p.h[7]+16*index+offset;words[pc]=p.word(pc)
    # Decode the original operation at rewritten architecture/address sites.
    for pc in words:
        if words[pc]==0xd421e000 and pc in p.sites:words[pc],metadata[pc]=p.sites[pc]
    compact_loads={};flow_sites={};flow_report=None
    aliases_user=[];descriptor_checks=[];pretranslated_user=set();extra_immutable=set();device_sites=set();watched=[]
    if pretranslated_memory:
        from el0_pretranslate import Bindings,user_aliases,user_proofs
        aliases_user,descriptor_checks=user_aliases(p,with_checks=True)
        if track_pretranslated_writes:watched=[[pa,4096] for pa in sorted({at&-4096 for at,mask,value in descriptor_checks})]
        for s in user.sections:
            if s['flags']&2 and not s['flags']&1 and s['size']:
                for va in range(s['addr']&-4096,(s['addr']+s['size']+4095)&-4096,4096):extra_immutable.add(p.pa(va)&-4096)
        initial=struct.unpack_from('<34Q',p.data,80)
        immutable_user=[(pa,4096) for pa in sorted(extra_immutable)]+watched
        if initial[31]<64 or Bindings(aliases_user,immutable_user).physical(initial[31]-64,64,True) is None:
            raise ValueError('pretranslated execution requires resident writable user stack headroom')
        # These proofs propagate GPR/SP preservation across syscall returns.
        # Unchecked proofs require an explicit production ABI contract.
        if validation or trust_syscall_abi:
            address_proofs=user_proofs({pc:words[pc] for pc in user_pcs},initial,p,aliases_user,immutable_user,with_addresses=True)
            pretranslated_user=set(address_proofs)
            if compact_proven_loads:
                from el0_compact_access import compact_load_proof
                for pc,proof in address_proofs.items():
                    lowered=compact_load_proof(decode(words[pc]),proof,p.h[2],p.h[3])
                    if lowered and not metadata.get(pc,0):compact_loads[pc]=lowered
            if dataflow_memory:
                from el0_pointer_flow import ANALYSIS_VERSION,analyze
                hook_pc=int(manifest['application']['result_hook'],0)
                flow_report=analyze({pc:words[pc] for pc in user_pcs},initial,p,aliases_user,immutable_user,
                                    adapted_pcs={hook_pc}|{pc for pc in user_pcs if metadata.get(pc,0)})
                flow_sites={pc:proof for pc,proof in flow_report['proofs'].items()
                            if pc not in compact_loads and pc!=hook_pc and not metadata.get(pc,0)}
        device_sites={pc for pc,address,size,write,value in struct.iter_unpack('<5Q',(oracle/'mmio.bin').read_bytes())}
    def native_sp(pc):return native_pc(pc) or pretranslated_memory
    hook=int(manifest['application']['result_hook'],0)
    ops=[];descriptions={};groups={};skipped=set();counts=collections.Counter();native_stack_words=0;native_ram_words=0
    for pc in sorted(words):
        if pc in skipped:continue
        w=words[pc];m=metadata.get(pc,0)
        if validation and pc==hook:op=Op(OBSERVE,w)
        elif m&0x20000000:op=Op(UNSUPPORTED,w)
        elif m&0x40000000:op=Op(SYSTEM,w)
        elif w&0xfc000000 in (0x14000000,0x94000000) or w&0xff000010==0x54000000 or w&0x7e000000 in (0x34000000,0x36000000) or w&0x9f000000 in (0x10000000,0x90000000):
            op=Op(NATIVE,w,w)
        else:
            group=atomic_group(words,pc)
            if group:
                op,body=group
                if any(metadata.get(pc+4*k,0)&0x60000000 for k in range(op.length)):
                    op=Op(UNSUPPORTED,w)
                else:
                    groups[pc]=body;skipped.update(pc+4*k for k in range(1,op.length))
            else:op=decode(w)
            if m&0x80000000 and op.kind==MEMORY:op.info|=USER
        # The kernel owns actual SP in this backend. SP arithmetic and ordinary
        # SP-relative accesses keep their ORIGINAL instruction, including native
        # pre/post-index writeback. Explicit user accesses and exclusive windows
        # retain their existing checked paths.
        tracked_write=track_pretranslated_writes and (op.kind==MEMORY and not op.info&LOAD or w&~31==0xd50b7420)
        if pc not in compact_loads and not tracked_write and not (compact_dynamic_memory and op.kind==MEMORY) and native_sp(pc) and not m and (op.kind==STACK or
                (op.kind==MEMORY and op.length==1 and op.info&31==31 and not op.info&(USER|EXCLUSIVE|(1<<44)))):
            if native_pc(pc) or pc in pretranslated_user or op.kind==STACK:
                op=Op(NATIVE,w,w);native_stack_words+=1
        if pc not in compact_loads and not tracked_write and not compact_dynamic_memory and pretranslated_memory and not m and (
                pc in pretranslated_user or
                native_pc(pc) and pc not in device_sites and op.kind==MEMORY and not op.info&(USER|ALIGNED|(1<<44)) or
                native_pc(pc) and w&~31==0xd50b7420):
            if op.kind!=NATIVE:
                op=Op(NATIVE,w,w,length=op.length);native_ram_words+=1
        counts[op.kind]+=1
        if op.kind!=NATIVE:
            idx=len(ops);ops.append((pc,op,m));descriptions[pc]=(idx,op,m)
    pcs=sorted(set(words)-skipped);pc_set=set(pcs);missing=set();adapter_fallthrough=[]
    if compact_dynamic_memory:
        for pc in pcs:
            original=decode(words[pc])
            if (original.kind==MEMORY or words[pc]&~31==0xd50b7420) and pc not in descriptions:
                raise ValueError('unconverted native memory access at 0x%x'%pc)
    if track_pretranslated_writes:
        # Every decoded store (including SP writeback and exclusive groups)
        # must retain its checked adapter. Unknown memory opcodes already stop.
        for pc in pcs:
            op=decode(words[pc])
            if (op.kind==MEMORY and not op.info&LOAD or words[pc]&~31==0xd50b7420) and pc not in descriptions:
                raise ValueError('untracked native store at 0x%x'%pc)
    sys_groups={}
    if pretranslated_memory:
        from el0_system_groups import system_groups
        sys_groups=system_groups({pc:(op,m) for pc,op,m in ops})
    literal_proofs={};page_caches=set();memory_immutable=None;user_groups={}
    if pretranslated_memory:
        from el0_memory_elision import literal_proof,page_cache_eligible,immutable_spans
        from el0_hardware import direct_ranges
        memory_immutable=immutable_spans({p.pa(pc)&-4096 for pc in pcs}|extra_immutable)
        _,memory_reads,memory_writes=direct_ranges(p.maps,p.h[2],p.h[3],sorted(memory_immutable+watched))
        cache_ranges_aligned=all(not (lo|hi)&4095 for lo,hi in memory_reads+memory_writes)
        for pc,op,m in ops:
            if m or not native_pc(pc) or op.kind!=MEMORY:continue
            proof=literal_proof(pc,op,p.pa,lambda pa,size:p.memory[pa-p.h[2]:pa-p.h[2]+size],
                                memory_immutable,p.h[2],p.h[3],memory_reads)
            if proof:literal_proofs[pc]=proof
            elif not compact_dynamic_memory and cache_ranges_aligned and page_cache_eligible(op,native_sp(pc)):page_caches.add(pc)
        from el0_memory_elision import user_load_groups
        user_groups=user_load_groups({pc:(op,m) for pc,op,m in ops if op.kind==MEMORY})
    dispatch_plans={}
    native_syscall_sites=[];native_syscall_stack_range=None
    if pretranslated_memory and not validation:
        initial_kernel_sp=struct.unpack_from('<Q',p.shadow,8)[0]
        native_syscall_stack_range=next(((lo,hi) for lo,hi in memory_writes if lo+64<=initial_kernel_sp<=hi),None)
    if pretranslated_memory:
        from el0_dispatch import analyze_dispatch_tables
        dispatch_plans=analyze_dispatch_tables({pc:words[pc] for pc in pcs},
            {pc:(op,m) for pc,op,m in ops},groups,
            [(address&MASK48,size,name) for address,size,name in code.data],
            lambda address:struct.unpack_from('<Q',p.memory,p.pa(address)-p.h[2])[0],native_pc)
    call_copies={};call_plan=None
    if pretranslated_memory:
        from el0_call_analysis import analyze_call_trees
        call_plan=analyze_call_trees({pc:words[pc] for pc in pcs},
                                 {pc:(op,m) for pc,op,m in ops},groups,
                                 [(lo&MASK48,hi&MASK48) for lo,hi in (code.extent(f) for f in sorted(functions))])
        call_copies=call_plan.roots
    pc_indices={}
    if pretranslated_memory:
        from el0_hardware import pc_index_layout
        candidates=set(words)|{pc+4 for pc in words}
        for pc,w in words.items():
            if w&0xfc000000 in (0x14000000,0x94000000):
                candidates.add((pc+sign(w&0x3ffffff,26)*4)&((1<<64)-1))
            elif w&0xff000010==0x54000000 or w&0x7e000000 in (0x34000000,0x36000000):
                bits=14 if w&0x7e000000==0x36000000 else 19
                candidates.add((pc+sign(w>>5&((1<<bits)-1),bits)*4)&((1<<64)-1))
        for domain,is_kernel in [('flat_kernel_direct',True),('flat_user_direct',False)]:
            pc_indices[domain]=(domain+'_index',*pc_index_layout([pc for pc in candidates if native_pc(pc)==is_kernel]))
    def label(pc):
        if pc not in words or pc in skipped:missing.add(pc)
        return '.Lp%x'%pc
    def resume(pc):label(pc);return '.Lr%x'%pc
    def thunk(name,to,private=False):
        pc=int(re.search(r'([0-9a-f]+)$',name)[1],16)
        macro='flat_native_resume' if native_sp(pc) and not private else 'flat_resume'
        return '.pushsection .text.resumes,"ax"\n%s %s,%s,0\n.popsection\n'%(macro,name,to)
    def capture(pc,name,site_pc,word,kind,private=False):
        macro='flat_native_capture' if native_sp(pc) and not private else 'flat_capture'
        return '%s %s,0x%x,0x%x,%d\n'%(macro,name,site_pc,word,kind)
    for pc,o,m in ops:
        if o.kind in (MEMORY,STACK):resume(pc+o.length*4)
    def constant(reg,value):
        from el0_hardware import immediate
        return ''.join('    '+line+'\n' for line in immediate(reg,value))
    def copy_label(call,pc):return '.Lclone%x_p%x'%(call,pc)
    def control(pc,w,to=label,specialize=True):
        if w&0xfc000000 in (0x14000000,0x94000000):
            target=(pc+sign(w&0x3ffffff,26)*4)&((1<<64)-1)
            destination=copy_label(pc,target) if specialize and pc in call_copies else to(target)
            return (constant(30,pc+4) if w&(1<<31) else '')+'    b %s\n'%destination
        if w&0xff000010==0x54000000:
            target=pc+sign(w>>5&0x7ffff,19)*4;inv=(w&~(0x7ffff<<5))^1
            if w&15>=14:return '    b %s\n'%to(target)
            return '    .inst 0x%x\n    b %s\n'%((inv&~(0x7ffff<<5))|(2<<5),to(target))
        if w&0x7e000000 in (0x34000000,0x36000000):
            bits=14 if w&0x7e000000==0x36000000 else 19;mask=(1<<bits)-1
            target=pc+sign(w>>5&mask,bits)*4;inv=(w^(1<<24))&~(mask<<5)
            return '    .inst 0x%x\n    b %s\n'%(inv|(2<<5),to(target))
        return '    .inst 0x%08x\n'%w
    mmio=list(struct.iter_unpack('<5Q',(oracle/'mmio.bin').read_bytes()))
    uart_va=(min(a for pc,a,s,w,v in mmio)&~4095) if mmio else 0
    inline_uart=uart_va and not any(va<uart_va+4096 and uart_va<va+size for va,pa,size,attrs in p.maps)
    out.mkdir(parents=True,exist_ok=False)
    (out/'runtime-config.h').write_text(
        '/* Generated export/build contract. */\n'
        '#define OSREC_FLAT_VALIDATION %d\n'
        '#define OSREC_FLAT_IMMUTABLE_BITMAP %d\n' % (validation,pretranslated_memory))
    if track_pretranslated_writes:
        with (out/'runtime-config.h').open('a') as config:config.write('#define OSREC_TRACK_PRETRANSLATED_WRITES 1\n')
    with (out/'program.S').open('w') as stream:
        stream.write('#include "gateway.inc"\n.text\n')
        for pc in pcs:
            w=words[pc];stream.write('.Lp%x:\n'%pc)
            if pc not in descriptions:
                if pretranslated_memory and pc in groups:
                    from el0_pretranslate import native_group
                    stream.write(native_group(pc,words,len(groups[pc]),label))
                elif w&0x9f000000 in (0x10000000,0x90000000):
                    delta=sign((w>>29&3)|((w>>5&0x7ffff)<<2),21)
                    value=((pc&~4095)+(delta<<12)) if w&(1<<31) else pc+delta
                    stream.write(constant(w&31,value&((1<<64)-1)))
                else:stream.write(control(pc,w))
                if pc+4 not in words:stream.write('    b %s\n'%label(pc+4))
            else:
                idx,o,m=descriptions[pc]
                # A checked store may allocate the bytes below the old SP.
                # Its slow payload/post-capture must stay on the private stack
                # until C commits writeback, or a native capture overwrites it.
                private_store=(track_pretranslated_writes or compact_dynamic_memory) and native_sp(pc) and o.kind==MEMORY and not o.info&LOAD
                if pc in compact_loads:
                    from el0_compact_access import compact_load_path
                    stream.write(compact_load_path(compact_loads[pc],label(pc+4)))
                    stream.write(thunk('.Lnr%x'%pc,'.Lp%x'%pc))
                    stream.write(thunk('.Lr%x'%pc,'.Lp%x'%pc))
                    continue
                if pc in flow_sites:
                    from el0_pointer_flow import access_path
                    stream.write(access_path(pc,o,flow_sites[pc],p.h[2],label(pc+4)))
                    stream.write(thunk('.Lnr%x'%pc,'.Lp%x'%pc))
                    stream.write(thunk('.Lr%x'%pc,'.Lp%x'%pc))
                    continue
                if pc in sys_groups:
                    from el0_system_groups import system_group_path
                    stream.write(system_group_path(pc,sys_groups[pc],label(pc+4*len(sys_groups[pc]))))
                    stream.write(thunk('.Lr%x'%pc,'.Lp%x'%pc))
                    continue
                if pc in literal_proofs:
                    from el0_memory_elision import literal_path
                    stream.write(literal_path(literal_proofs[pc],label(pc+4)))
                    stream.write(thunk('.Lnr%x'%pc,'.Lp%x'%pc))
                    stream.write(thunk('.Lr%x'%pc,'.Lp%x'%pc))
                    continue
                inline=''
                if hardware_memory and o.kind in (STACK,SYSTEM):
                    from el0_hardware import stack_path,system_path
                    inline=stack_path(o) if o.kind==STACK else system_path(o.word,m,page_offsets=True)
                if inline:
                    stream.write(inline)
                    # These helpers cannot reject or carry an inline literal
                    # pool. Resume thunks occupy another section, so the next
                    # original PC is the next emitted instruction when present.
                    if pc+4 in pc_set:
                        adapter_fallthrough.append(dict(pc=pc,word=o.word,metadata=m,kind=o.kind))
                    else:stream.write('    b %s\n'%label(pc+4))
                    if o.kind==STACK:stream.write(thunk('.Lnr%x'%pc,'.Lp%x'%pc))
                    stream.write(thunk('.Lr%x'%pc,'.Lp%x'%pc))
                    continue
                if hardware_memory and o.kind==MEMORY:
                    from el0_hardware import memory_path
                    if pc in page_caches:
                        from el0_memory_elision import page_cache_probe
                        stream.write(page_cache_probe(pc,o,label(pc+4),native_sp(pc)))
                    if pc in user_pcs or o.info&USER:
                        from el0_user_memory import user_memory_path
                        if pc in user_groups:
                            stream.write(user_memory_path(pc,o,label(pc+4*len(user_groups[pc])),p.h[2],p.h[3],p.h[4],
                                native_sp=native_sp(pc),immutable_bitmap=True,accesses=user_groups[pc],exclusion_buckets=True))
                        stream.write(user_memory_path(pc,o,label(pc+o.length*4),p.h[2],p.h[3],p.h[4],native_sp=native_sp(pc),
                                                      immutable_bitmap=pretranslated_memory,exclusion_buckets=pretranslated_memory))
                    stream.write(memory_path(pc,o,label(pc+o.length*4),groups.get(pc),label,native_sp=native_sp(pc),
                                             page_cache=pc in page_caches,native_store=track_pretranslated_writes and not compact_dynamic_memory,compact=compact_table_mode))
                    if inline_uart and pc not in user_pcs and not o.info&USER:
                        from el0_uart import uart_path
                        stream.write(uart_path(pc,o,label(pc+o.length*4),uart_va,native_sp=native_sp(pc)))
                if hardware_memory and o.kind==INDIRECT:
                    if pc in dispatch_plans:
                        from el0_dispatch import dispatch_path
                        stream.write(dispatch_path(dispatch_plans[pc],compact=pretranslated_memory and native_pc(pc)))
                    from el0_hardware import indirect_path
                    domain='flat_kernel_direct' if native_pc(pc) else 'flat_user_direct'
                    stream.write(indirect_path(pc,o.word,table=domain+'_pcs' if native_kernel_stack else 'flat_direct_pcs',
                                               count=domain+'_count' if native_kernel_stack else 'flat_direct_pc_count',cache=True,
                                               index=pc_indices.get(domain),compact=pretranslated_memory and native_pc(pc)))
                if hardware_memory and o.kind==SYSTEM:
                    if pretranslated_memory and native_pc(pc):
                        from el0_return import user_return_path
                        stream.write(user_return_path(pc,o.word,m,pc_indices.get('flat_user_direct'),len(descriptor_checks),validation=validation,tracked=track_pretranslated_writes))
                    from el0_hardware import guarded_system_path,zero_path,lowered_branch_path,counter_path
                    stream.write(lowered_branch_path(pc,o.word,m,label))
                    stream.write(guarded_system_path(pc,o.word,m,label(pc+4)))
                    stream.write(counter_path(pc,o.word,m,label(pc+4)))
                    stream.write(zero_path(pc,o.word,m,label(pc+4),zero_bytes,compact=compact_table_mode))
                if hardware_memory and o.kind==SVC:
                    if pretranslated_memory and not validation:
                        from el0_syscall import native_syscall_path
                        inline=native_syscall_path(pc,o.word,m,pc_indices.get('flat_kernel_direct'),native_syscall_stack_range)
                        if inline:native_syscall_sites.append((pc,o.word))
                        stream.write(inline)
                    elif validation and not native_kernel_stack:
                        from el0_syscall import syscall_path
                        stream.write(syscall_path(pc,o.word,m))
                if hardware_memory and not alias_free_memory and o.kind==OBSERVE:
                    from el0_hardware import observe_path
                    stream.write(observe_path(pc,'.Ln%x'%pc))
                stream.write(capture(pc,'.Lc%x'%pc,pc,w,idx*2))
                if o.kind in (MEMORY,STACK):
                    stream.write('.Ln%x:\n'%pc)
                    if pc in groups:
                        exits={}
                        for k,v in enumerate(groups[pc]):
                            here=pc+4*k;stream.write('.La%x:\n'%here)
                            if v&0xff000010==0x54000000 or v&0x7e000000 in (0x34000000,0x36000000) or v&0xfc000000==0x14000000:
                                bits=26 if v&0xfc000000==0x14000000 else 14 if v&0x7e000000==0x36000000 else 19
                                dest=here+sign(v&0x3ffffff,26)*4 if bits==26 else here+sign(v>>5&((1<<bits)-1),bits)*4
                                if pc<=dest<pc+o.length*4:to='.La%x'%dest
                                else:exits[dest]='.Le%x_%x'%(pc,dest);to=exits[dest]
                                if bits==26:stream.write('    b %s\n'%to)
                                else:
                                    # Native conditional branch to a local island exit.
                                    stream.write(local_conditional(v,to))
                            else:stream.write('    .inst 0x%08x\n'%v)
                        stream.write('    b .Ld%x\n'%pc)
                        for dest,to in exits.items():
                            stream.write(to+':\n'+capture(pc,'.Lex%x_%x'%(pc,dest),dest,0,idx*2+1,private=private_store));label(dest)
                    else:stream.write('    .inst 0x%08x\n'%o.native)
                    if hardware_memory and o.kind==MEMORY and not private_store:
                        from el0_hardware import memory_finish_path
                        stream.write(memory_finish_path(pc,o,label(pc+4*o.length),native_sp=native_sp(pc)))
                    stream.write(capture(pc,'.Ld%x'%pc,pc+4*o.length,0,idx*2+1,private=private_store))
                    stream.write(thunk('.Lnr%x'%pc,'.Ln%x'%pc,private=private_store))
                elif o.kind==OBSERVE:
                    stream.write('.Ln%x:\n'%pc+control(pc,w))
                    stream.write(thunk('.Lnr%x'%pc,'.Ln%x'%pc))
            stream.write(thunk('.Lr%x'%pc,'.Lp%x'%pc))
        # Each copy has only one entry: its proven direct BL call site. It is
        # deliberately absent from the original-PC index and context resumes.
        if call_plan:
            from el0_call_analysis import write_call_trees
            write_call_trees(stream,call_plan,words,descriptions,label,constant,control,page_offsets=True)
        # Missing targets are real coverage boundaries, never replay-selected paths.
        for pc in sorted(missing):
            if pc in descriptions:continue
            idx=len(ops);o=Op(COVERAGE,words.get(pc,0));ops.append((pc,o,0));descriptions[pc]=(idx,o,0)
            stream.write('.Lp%x:\n'%pc+capture(pc,'.Lc%x'%pc,pc,0,idx*2))
            stream.write(thunk('.Lr%x'%pc,'.Lp%x'%pc))
        if dispatch_plans:
            from el0_dispatch import dispatch_data
            stream.write(dispatch_data(dispatch_plans))
        stream.write('.section .rodata,"a"\n.balign 8\n.global flat_pcs\nflat_pcs:\n')
        for pc in sorted(set(pcs)|missing):stream.write('    .quad 0x%x,%s\n'%(pc,resume(pc)))
        if hardware_memory:
            from el0_hardware import indirect_resume
            stream.write('.global flat_direct_pc_count\nflat_direct_pc_count:\n.quad %d\n'%(len(set(pcs)|missing)))
            stream.write('.global flat_direct_pcs\nflat_direct_pcs:\n')
            for pc in sorted(set(pcs)|missing):stream.write('    .quad 0x%x,.Li%x\n'%(pc,pc))
            if native_kernel_stack:
                for domain,selected in [('flat_kernel_direct',[pc for pc in sorted(set(pcs)|missing) if native_pc(pc)]),
                                        ('flat_user_direct',[pc for pc in sorted(set(pcs)|missing) if not native_pc(pc)])]:
                    stream.write('.global %s_count\n%s_count:\n.quad %d\n.global %s_pcs\n%s_pcs:\n'%(domain,domain,len(selected),domain,domain))
                    for pc in selected:stream.write('    .quad 0x%x,.Li%x\n'%(pc,pc))
            if pc_indices:
                from el0_hardware import pc_index_data
                stream.write('.global flat_pc_index_count\nflat_pc_index_count:\n.quad %d\n'%len(pc_indices))
                stream.write('.global flat_pc_indices\nflat_pc_indices:\n')
                for name,base,bits in pc_indices.values():stream.write('.quad 0x%x,0x%x,%s\n'%(base,1<<bits,name))
                for domain,(name,base,bits) in pc_indices.items():
                    selected=[pc for pc in sorted(set(pcs)|missing) if native_pc(pc)==(domain=='flat_kernel_direct')]
                    stream.write(pc_index_data(name,selected,(base,bits)))
            stream.write('.pushsection .text.resumes,"ax"\n')
            for pc in sorted(set(pcs)|missing):stream.write(indirect_resume('.Li%x'%pc,label(pc),compact=pretranslated_memory and native_pc(pc)))
            stream.write('.popsection\n')
        stream.write('.global flat_ops\nflat_ops:\n')
        for pc,o,m in ops:
            native='.Lnr%x'%pc if o.kind in (MEMORY,STACK,OBSERVE) else '0'
            following=resume(pc+o.length*4) if o.kind in (MEMORY,STACK) else '0'
            meta=o.length if o.kind in (MEMORY,STACK) else m
            stream.write('    .quad 0x%x,%s,%s,0x%x,0x%x,%d,0x%x,0x%x\n'%(pc,native,following,o.word,meta,o.kind,o.info,o.imm&((1<<64)-1)))
        stream.write('.section .note.GNU-stack,"",%progbits\n')
    if pretranslated_memory:
        (out/'adapter-fallthrough.json').write_text(json.dumps(dict(
            format='osrec-adapter-fallthrough-v1',sites=adapter_fallthrough),indent=2)+'\n')
        (out/'system-groups.json').write_text(json.dumps(dict(format='osrec-system-groups-v1',groups=[
            dict(pc=pc,words=list(group)) for pc,group in sorted(sys_groups.items())]),indent=2)+'\n')
        from el0_control import relax_branches
        control_proof=relax_branches(out/'program.S',ROOT/'runtime/el0_flat/gateway.inc')
        (out/'control-lowering.json').write_text(json.dumps(control_proof,indent=2)+'\n')
    immutable=text_metadata(out,p,user_elf,extra_immutable)
    if memory_immutable is not None:
        if immutable!=memory_immutable:raise ValueError('memory elision immutable proof differs from protected text')
        proof=dict(format='osrec-memory-elision-v1',immutable_literals=[dict(
            **{k:v for k,v in row.items() if k!='data'},data=row['data'].hex()) for row in literal_proofs.values()],
            aligned_page_cache_sites=sorted(page_caches),fixed_ranges_page_aligned=cache_ranges_aligned,
            coalesced_user_loads=[dict(pc=pc,words=[o.word for o in group]) for pc,group in sorted(user_groups.items())],
            rule='immutable literal bytes; aligned single accesses reuse only immutable kernel page admission; live mode and alignment checks remain')
        (out/'memory-elision.json').write_text(json.dumps(proof,indent=2)+'\n')
    if pretranslated_memory:
        from el0_user_memory import immutable_page_bitmap
        bitmap=immutable_page_bitmap(p.h[2],p.h[3],immutable+watched)
        (out/'immutable-pages.bin').write_bytes(bitmap)
    if hardware_memory:
        from el0_hardware import direct_ranges
        aliases,reads,writes=direct_ranges(p.maps,p.h[2],p.h[3],sorted(immutable+watched))
        if alias_free_memory:
            aliases,reads,writes=[],[],[]
        hardware=dict(format='osrec-el0-hardware-memory-v1',ram_base=p.h[2],ram_bytes=p.h[3],
                      native_zero_bytes=zero_bytes,shadow_header_alignment=128,
                      aliases=aliases,read_ranges=reads,write_ranges=writes,
                      translation='kernel VA -> flat_phys + captured PA - ram_base',
                      changing_user_mappings='checked software path',runtime_exception_level=0)
        if compact_dynamic_memory:
            from el0_hardware import compact_ranges
            compact_reads,compact_writes=compact_ranges(p.maps,p.h[2],p.h[3],sorted(immutable+watched))
            hardware['compact_dynamic_memory']=dict(read=compact_reads,write=compact_writes)
            if compact_table_mode==COMPACT_WIDTH_BOUNDS:
                hardware['compact_dynamic_memory']['encoding']=COMPACT_WIDTH_BOUNDS_ENCODING
        if alias_free_memory:
            hardware['alias_free_memory']=True
        if native_kernel_stack:
            hardware['native_kernel_stack']=dict(ranges=native_ranges,
                contract='kernel SP addresses writable static RAM; native stack faults stop at the model boundary')
        if pretranslated_memory:
            from el0_user_exclusion import exclusion_buckets
            from el0_user_memory import excluded_ranges
            bucket_maps=p.maps+([(uart_va,0x9000000,4096,0)] if mmio else [])
            bucket_data=exclusion_buckets(excluded_ranges(bucket_maps))
            (out/'user-exclusion-buckets.bin').write_bytes(bucket_data)
            hardware['user_exclusion_buckets']=dict(shift=39,entries=512,entry_bytes=16,sha256=hashlib.sha256(bucket_data).hexdigest())
            hardware['immutable_page_bitmap']=dict(bytes=len(bitmap),page_bytes=4096,sha256=hashlib.sha256(bitmap).hexdigest())
            if page_caches:hardware['fixed_page_memory_cache']=dict(sites=len(page_caches),page_bytes=4096)
            hardware['pretranslated_memory']=dict(user_aliases=aliases_user,device_sites=sorted(device_sites),
                user_native_sites=sorted(pretranslated_user),table_capacity=4<<20,
                descriptor_checks=descriptor_checks,
                contract='initial resident bindings are fixed; new demand mappings use checked accesses; native kernel RAM faults stop')
            if track_pretranslated_writes:hardware['pretranslated_memory']['watched_pages']=[pa for pa,size in watched]
            if native_syscall_sites:
                hardware['native_syscall_entry']=dict(stack_range=native_syscall_stack_range,
                    sites=[[pc,word] for pc,word in native_syscall_sites],
                    contract='live user mode/PSTATE/vector and 64-byte writable kernel stack admission; private 80-byte scratch; compact kernel resume; C fallback')
            if not validation:
                from el0_return import user_resume_ranges
                hardware['pretranslated_memory']['user_resume_ranges']=user_resume_ranges(aliases_user,immutable+watched)
        (out/'hardware-memory.json').write_text(json.dumps(hardware,indent=2)+'\n')
    # Pack nonzero pages once for startup copying or direct ELF initialization.
    extents=[]
    with (p.path/'memory.bin').open('rb') as src,(out/'ram.bin').open('wb') as dst:
        for lo,hi in sparse_runs(src,p.h[3]):
            offset=dst.tell();src.seek(lo);left=hi-lo
            while left:
                chunk=src.read(min(left,1<<20))
                if not chunk:raise ValueError('truncated captured RAM')
                dst.write(chunk);left-=len(chunk)
            extents.append((lo,hi-lo,offset))
    if elf_ram_initialization:
        hardware['elf_ram_initialization']=dict(initial_extents=extents,table_capacity=4<<20)
    if pretranslated_memory:
        hardware['pretranslated_memory']['initial_extents']=extents
    if elf_ram_initialization or pretranslated_memory:
        (out/'hardware-memory.json').write_text(json.dumps(hardware,indent=2)+'\n')
    if pretranslated_memory:
        bodies={body[0]:body for body in call_plan.nodes.values()}
        proof=dict(format='osrec-call-tree-specialization-v3',
                   rule='closed frame CFG or X30-preserving leaf prefix; unproven edges rejoin original code; direct BL entry only',
                   original_indirect_entries_preserved=True,
                   functions=[dict(entry=hex(entry),instructions=[[hex(pc),hex(words[pc])] for pc in body],
                                   nested_depth=call_plan.summaries[entry].depth if entry in call_plan.summaries else 0,
                                   partial=entry in call_plan.partial,
                                   original_exits=[hex(pc) for pc in call_plan.partial[entry].exits] if entry in call_plan.partial else [])
                              for entry,body in sorted(bodies.items())],
                   calls=[dict(context=hex(context),callee=hex(body[0]),
                               parent_context=hex(call_plan.returns[context][0]) if call_plan.returns[context][0] is not None else None,
                               continuation=hex(call_plan.returns[context][1]))
                          for context,body in call_plan.nodes.items()])
        (out/'call-specialization.json').write_text(json.dumps(proof,indent=2)+'\n')
    expected,count=expected_events(record['calls']) if validation else (b'',0)
    (out/'expected.bin').write_bytes(expected)
    (out/'counters.bin').write_bytes((oracle/'counters.bin').read_bytes());(out/'shadow.bin').write_bytes(p.shadow)
    (out/'initial.bin').write_bytes(p.data[80:872]+bytes(8))
    (out/'ranges.bin').write_bytes(p.ranges);(out/'origins.bin').write_bytes(p.origins)
    uart=bytes(v&255 for pc,a,s,w,v in mmio if w and a==uart_va) if validation else b''
    (out/'uart.bin').write_bytes(uart)
    maps=sorted(p.maps+([(uart_va,0x9000000,4096,(1<<10)|(1<<53)|(1<<54))] if mmio else []))
    (out/'maps.bin').write_bytes(b''.join(struct.pack('<4Q',*r) for r in maps))
    data='.section .data,"aw"\n'
    for name,file in [('flat_shadow','shadow.bin'),('flat_initial','initial.bin')]:
        align=128 if hardware_memory and name=='flat_shadow' else 16
        data+='.balign %d\n.global %s\n%s:\n.incbin "%s"\n'%(align,name,name,file)
    data+='.section .rodata,"a"\n'
    for name,file in [('flat_payload','ram.bin'),('flat_maps','maps.bin'),('flat_expected','expected.bin'),('flat_counters','counters.bin'),('flat_expected_uart','uart.bin'),('osrec_kernel_ranges','ranges.bin'),('osrec_veneer_origins','origins.bin')]:
        data+='.balign 16\n.global %s\n%s:\n.incbin "%s"\n'%(name,name,file)
    for name,value in [('osrec_kernel_range_count',p.h[5]),('osrec_veneer_count',p.h[8]),('osrec_veneer_base',p.h[7]),('flat_expected_uart_bytes',len(uart))]:data+='.global %s\n%s:\n.quad 0x%x\n'%(name,name,value)
    if hardware_memory:
        data+='.balign 8\n.global flat_shadow_header_alignment\nflat_shadow_header_alignment:\n.quad 128\n'
        from el0_user_memory import excluded_ranges
        excluded=excluded_ranges(maps)
        data+='.balign 16\n.global flat_user_excluded\nflat_user_excluded:\n.quad %d\n'%len(excluded)
        data+=''.join('.quad 0x%x,0x%x\n'%span for span in excluded)
        if zero_bytes:data+='.balign 8\n.global flat_hardware_zero_bytes\nflat_hardware_zero_bytes:\n.quad %d\n'%zero_bytes
        for name,ranges in [('flat_direct_read',reads),('flat_direct_write',writes)]:
            data+='.balign 16\n.global %s\n%s:\n'%(name,name)
            data+=''.join('.quad 0x%x,0x%x\n'%tuple(row) for row in ranges)+'.quad 0,0\n'
    if compact_dynamic_memory:
        data+='.balign 8\n.global flat_compact_memory_mode\nflat_compact_memory_mode:\n.quad %d\n'%compact_table_mode
        for access,rows in [('read',compact_reads),('write',compact_writes)]:
            if compact_table_mode==COMPACT_WIDTH_BOUNDS:
                for width in COMPACT_ACCESS_WIDTHS:
                    name = 'flat_compact_%s_%d' % (access,width)
                    data+='.balign 32\n.global %s\n%s:\n'%(name,name)
                    bounds = compact_width_ranges(rows,width)
                    # An empty table starts with an impossible interval so the
                    # direct probe always transfers to the search sentinel.
                    data+=''.join('.quad 0x%x,0x%x,flat_phys%+d\n'%(lo,last,offset-lo)
                                  for lo,last,offset in bounds) or '.quad 1,0,0\n'
                    data+='.quad 0,0,0\n'
            else:
                name='flat_compact_'+access
                data+='.balign 8\n.global %s\n%s:\n'%(name,name)
                data+=''.join('.quad 0x%x,0x%x,0x%x\n'%tuple(row) for row in rows)+'.quad 0,0,0\n'
    if alias_free_memory:
        data+='.balign 8\n.global flat_alias_free_memory_mode\nflat_alias_free_memory_mode:\n.quad 1\n'
    if native_kernel_stack:
        data+='.balign 8\n.global flat_native_kernel_stack\nflat_native_kernel_stack:\n.quad 1\n'
        data+='.global flat_native_stack_range_count\nflat_native_stack_range_count:\n.quad %d\n'%len(native_ranges)
        data+='.global flat_native_stack_ranges\nflat_native_stack_ranges:\n'
        data+=''.join('.quad 0x%x,0x%x\n'%span for span in native_ranges)
    if pretranslated_memory:
        if not validation:
            data+='.balign 16\n.global flat_user_resume_ranges\nflat_user_resume_ranges:\n'
            data+=''.join('.quad 0x%x,0x%x\n'%tuple(span) for span in hardware['pretranslated_memory']['user_resume_ranges'])
            data+='.quad 0,0\n'
        data+='.balign 8\n.global flat_user_exclusion_bucket_mode\nflat_user_exclusion_bucket_mode:\n.quad 1\n'
        data+='.balign 16\n.global flat_user_exclusion_buckets\nflat_user_exclusion_buckets:\n.incbin "user-exclusion-buckets.bin"\n'
        data+='.balign 8\n.global flat_memory_page_cache_mode\nflat_memory_page_cache_mode:\n.quad %d\n'%bool(page_caches)
        data+='.balign 16\n.global flat_immutable_page_bits\n.type flat_immutable_page_bits,%object\nflat_immutable_page_bits:\n.incbin "immutable-pages.bin"\n.size flat_immutable_page_bits,.-flat_immutable_page_bits\n'
        data+='.balign 8\n.global flat_pretranslated_memory\nflat_pretranslated_memory:\n.quad 1\n'
        data+='.global flat_pretranslated_binding_count\nflat_pretranslated_binding_count:\n.quad %d\n'%len(aliases_user)
        data+='.global flat_pretranslated_bindings\nflat_pretranslated_bindings:\n'
        data+=''.join('.quad 0x%x,0x%x,0x%x,0x%x\n'%(a['va'],a['pa'],a['bytes'],a['attrs']) for a in aliases_user)
        for name,value in [('flat_pretranslated_root',struct.unpack_from('<Q',p.shadow,72)[0]&0x0000fffffffff000),
                           ('flat_pretranslated_tcr',p.h[4]),('flat_pretranslated_check_count',len(descriptor_checks))]:
            data+='.global %s\n%s:\n.quad 0x%x\n'%(name,name,value)
        data+='.global flat_pretranslated_checks\nflat_pretranslated_checks:\n'
        data+=''.join('.quad flat_phys+0x%x,0x%x,0x%x\n'%(pa-p.h[2],mask,value) for pa,mask,value in descriptor_checks)
    if elf_ram_initialization:
        data+='.balign 8\n.global flat_elf_ram_initialization\nflat_elf_ram_initialization:\n.quad 1\n'
    if elf_ram_initialization or pretranslated_memory:
        data+='.balign 4096\n.global flat_embedded_page_tables\nflat_embedded_page_tables:\n.space %d\n'%(4<<20)
    data+='.section .note.GNU-stack,"",%progbits\n';(out/'state.S').write_text(data)
    s='#include "program.h"\nextern unsigned char flat_shadow[],flat_payload[],flat_maps[],flat_expected[],flat_counters[];\nextern const struct flat_pc flat_pcs[]; extern const struct flat_op flat_ops[];\n'
    s+='unsigned char flat_phys[%d] __attribute__((aligned(4096)));\n'%p.h[3]
    s+='unsigned char flat_uart_registers[4096],flat_uart[4096];\n'
    if validation:s+='struct flat_event flat_events[%d];\n'%(count+1024)
    s+='static const struct flat_ram ram[]={{0x%x,%d,flat_phys},{0x9000000,4096,flat_uart_registers}};\n'%(p.h[2],p.h[3])
    s+='struct flat_full_image flat_program={.memory={ram,2,(const struct flat_mapping *)flat_maps,%d,0x%x,0x%x},.shadow=(struct osrec_shadow *)flat_shadow,.pcs=flat_pcs,.pc_count=%d,.ops=flat_ops,.expected=(const struct flat_event *)flat_expected,.expected_count=%d,.counters=(const struct flat_counter *)flat_counters,.counter_count=%d,.stop_pc=%s,.uart_va=0x%x};\n'%(len(maps),struct.unpack_from('<Q',p.shadow,72)[0],p.h[4],len(set(pcs)|missing),count,len((oracle/'counters.bin').read_bytes())//24,record['end']['pc'],uart_va)
    s+='extern void *memcpy(void *,const void *,size_t); void flat_program_initialize(void){\n'
    if not (elf_ram_initialization or pretranslated_memory):
        s+=''.join('memcpy(flat_phys+%d,flat_payload+%d,%d);\n'%(lo,off,size) for lo,size,off in extents)
    s+='flat_uart_registers[0x18]=0x90;}\n';(out/'image.c').write_text(s)
    report=dict(format='osrec-el0-program-v1',functions=len(functions),source_instructions=len(pcs),adaptations=len(ops),decoded=dict(counts),
                runtime_validation=bool(validation),trust_syscall_abi=bool(trust_syscall_abi),
                specialized_calls=len(call_plan.nodes) if call_plan else 0,specialized_root_calls=len(call_copies),
                specialized_nested_calls=len(call_plan.nodes)-len(call_copies) if call_plan else 0,
                specialized_partial_calls=sum(body[0] in call_plan.partial for body in call_copies.values()) if call_plan else 0,
                specialized_source_words=sum(map(len,call_plan.nodes.values())) if call_plan else 0,
                static_missing=len(missing),initial_pc=hex(struct.unpack_from('<Q',p.data,80+256)[0]),expected_events=count,
                kernel=str(vmlinux),package=str(p.path),oracle=str(oracle),user_elf=str(Path(user_elf).resolve()),
                kernel_sha256=hashlib.sha256(vmlinux.read_bytes()).hexdigest(),
                native_state_sha256=hashlib.sha256(p.data).hexdigest(),source_image_sha256=source,
                coverage_sha256=hashlib.sha256(Path(coverage).read_bytes()).hexdigest() if coverage else None,
                whole_kernel_text=whole_kernel_text,compact_dynamic_memory=compact_dynamic_memory,
                alias_free_memory=alias_free_memory,
                elf_ram_initialization=elf_ram_initialization,
                absent_kernel_text=[[hex(lo),hex(hi)] for lo,hi in absent_kernel_text],
                scope=('all resident persistent ELF-identified kernel instructions and captured application' if whole_kernel_text else
                       'restored user checkpoint and actual kernel entry/dispatch/return, conservative code closure'),runtime_el=0,
                memory_backend='hardware-kernel' if hardware_memory else 'software',
                shadow_access_backend='page-offset' if hardware_memory else 'base',
                pc_lookup_backend='page-index' if pc_indices else 'binary-search',
                native_kernel_stack=native_kernel_stack,native_stack_instructions=native_stack_words,
                pretranslated_memory=pretranslated_memory,native_ram_instructions=native_ram_words,user_native_memory_instructions=len(pretranslated_user),
                hardware_memory_sha256=hashlib.sha256((out/'hardware-memory.json').read_bytes()).hexdigest() if hardware_memory else None)
    if compact_proven_loads:
        (out/'compact-loads.json').write_text(json.dumps(dict(format='osrec-compact-loads-v1',
            complete=False,rule='finite-set user address proof; single physical target; existing return/mapping contract',
            sites=[dict(pc=pc,**proof) for pc,proof in sorted(compact_loads.items())]),indent=2)+'\n')
        report['compact_load_sites']=len(compact_loads)
        report['complete_static_relocation']=False
    if dataflow_memory:
        report['dataflow_memory']=True
        report['dataflow_analysis_version']=ANALYSIS_VERSION
        report['dataflow_memory_sites']=len(flow_sites)
        (out/'dataflow-memory.json').write_text(json.dumps(dict(format='osrec-dataflow-memory-v1',
            complete=False,analysis=flow_report,sites=[dict(pc=pc,**proof) for pc,proof in sorted(flow_sites.items())]),indent=2)+'\n')
    report['indirect_dispatch_sites']=len(dispatch_plans)
    if native_syscall_sites:
        report['native_syscall_sites']=len(native_syscall_sites)
        report['syscall_backend']='inline-native'
    if pretranslated_memory:report['kernel_indirect_frame_bytes']=32
    report['indirect_dispatch_entries']=sum(len(plan.entries) for plan in dispatch_plans.values())
    dispatch_proof=dict(format='osrec-pretranslated-dispatch-v1',
        rule='bounded live index hint; full live original-pointer equality; immutable native entries; checked resolver fallback',
        sites=[dict(pc=hex(pc),word=hex(plan.word),load_pc=hex(plan.load_pc),index_register=plan.index,
                    object=plan.object_name,base=hex(plan.base),
                    entries=[[hex(value),hex(target) if target is not None else None] for value,target in plan.entries])
               for pc,plan in sorted(dispatch_plans.items())])
    if dispatch_plans:(out/'indirect-dispatch.json').write_text(json.dumps(dispatch_proof,indent=2)+'\n')
    (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');return report

if __name__=='__main__':
    a=argparse.ArgumentParser(description=__doc__)
    for name in ('package','vmlinux','user-elf','oracle','out'):a.add_argument('--'+name,required=True)
    a.add_argument('--extra-pc',action='append',type=lambda s:int(s,0),default=[])
    a.add_argument('--coverage',help='optional QEMU in_asm listing; static function coverage seed only')
    a.add_argument('--dataflow-memory',action='store_true',help='experimental checked dataflow lowering of user memory accesses; requires compact dynamic memory')
    a.add_argument('--alias-free-memory',action='store_true',help='inline compact RAM conversion with logical guest stacks and no original VA mappings; requires hardware memory')
    a.add_argument('--elf-ram-initialization',action='store_true',help='load RAM and model page tables directly from the ELF; requires alias-free memory and post-link finalization')
    a.add_argument('--compact-dynamic-memory',action='store_true',help='convert live kernel memory operands to compact backing; user mappings stay live; implies compact proven loads')
    a.add_argument('--compact-proven-loads',action='store_true',help='rewrite statically proven single-target integer user loads to ELF backing; partial relocation only')
    a.add_argument('--whole-kernel-text',action='store_true',help='include every resident persistent ELF-identified kernel instruction; report absent ranges; not a completeness claim for unknown executable dump pages')
    a.add_argument('--hardware-memory',action='store_true',help='inline static kernel RAM accesses; requires the generated hardware page-table load plan')
    a.add_argument('--native-kernel-stack',action='store_true',help='execute kernel SP instructions directly; hardware aliases and mapped native kernel stacks required')
    a.add_argument('--pretranslated-memory',action='store_true',help='embed resolved mappings and RAM into ELF; requires post-link tools/pretranslate_el0_image.py')
    a.add_argument('--track-pretranslated-writes',action='store_true',help='experimental: guard all native stores and cache descriptor validation until watched writes')
    a.add_argument('--no-validation',action='store_true',help='execution-only production image: omit event/result validation and saved-return context comparisons')
    a.add_argument('--trust-syscall-abi',action='store_true',help='with --no-validation, retain direct user-memory proofs under the captured syscall/fault return ABI')
    p=a.parse_args()
    if p.trust_syscall_abi and not p.no_validation:a.error('--trust-syscall-abi requires --no-validation')
    print(json.dumps(export(p.package,p.vmlinux,p.user_elf,p.oracle,p.out,p.extra_pc,p.coverage,p.hardware_memory,p.native_kernel_stack,p.pretranslated_memory,validation=not p.no_validation,trust_syscall_abi=p.trust_syscall_abi,track_pretranslated_writes=p.track_pretranslated_writes,whole_kernel_text=p.whole_kernel_text,compact_proven_loads=p.compact_proven_loads,compact_dynamic_memory=p.compact_dynamic_memory,dataflow_memory=p.dataflow_memory,alias_free_memory=p.alias_free_memory,elf_ram_initialization=p.elf_ram_initialization),indent=2))
