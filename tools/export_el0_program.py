#!/usr/bin/env python3
"""AOT lower the captured user/kernel checkpoint, preserving native code flow.

Coverage is a complete function closure seeded by the workload's syscall set;
unknown runtime targets stop with their source PC. Inputs never select paths.
"""
import argparse,bisect,collections,hashlib,json,mmap,re,struct
from pathlib import Path
from export_native_checkpoint import sparse_runs,expected_events
from kernel_code_closure import Code
from kernel_source_verify import Elf
from source_image_el0 import instruction_ranges
from el0_flat_lower import *

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

def text_metadata(out,p,user_elf):
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
    physical=merge({p.pa(va)&~4095 for va in pages})
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

def export(package,vmlinux,user_elf,oracle,out,extra=(),coverage=None,hardware_memory=False):
    p=Package(Path(package).resolve());out=Path(out).resolve();vmlinux=Path(vmlinux).resolve();oracle=Path(oracle).resolve()
    dczid=struct.unpack_from('<Q',p.shadow,104+8192+0xd807*8)[0]
    zero_bytes=4<<(dczid&15) if not dczid&16 and dczid&15<=9 else 0
    manifest=json.loads((p.path/'manifest.json').read_text());record=json.loads((oracle/'calls.json').read_text())
    if hashlib.sha256(Path(user_elf).read_bytes()).hexdigest()!=manifest['application']['user_elf_sha256']:raise ValueError('user ELF identity mismatch')
    source=record.get('source_image_sha256') or json.loads((Path(record['image'])/'manifest.json').read_text())['image_sha256']
    if source!=manifest['source_image_sha256']:raise ValueError('oracle identity mismatch')
    code=Code(vmlinux);symbols={s['name']:s for s in code.elf.symbols if s['shndx']}
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
    functions=set();pending=list(roots)
    while pending:
        f=pending.pop()
        if f is None or f in functions:continue
        functions.add(f);calls,taken,data=code.edges(f);pending.extend((calls|taken)-functions)
    executable=instruction_ranges(code.elf,[(s['addr'],s['addr']+s['size']) for s in code.elf.sections if s['flags']&4 and s['addr'] and not s['name'].startswith('.init')])
    starts=[a for a,b in executable]
    def insn(pc):
        i=bisect.bisect_right(starts,pc)-1;return i>=0 and pc<executable[i][1]
    words={};metadata={}
    for f in sorted(functions):
        lo,hi=code.extent(f)
        for original in range(lo,hi,4):
            if not insn(original):continue
            pc=original&MASK48
            try:w=p.word(pc)
            except ValueError:continue
            words[pc]=w
    user=Elf(user_elf)
    for lo,hi in instruction_ranges(user,[(s['addr'],s['addr']+s['size']) for s in user.sections if s['flags']&4 and s['size']]):
        for pc in range(lo,hi,4):words[pc]=p.word(pc)
    # Existing address-lowering veneers are captured code too. Each slot has
    # two instructions followed by an eight-byte literal, never four opcodes.
    for index in range(p.h[8]):
        for offset in (0,4):
            pc=p.h[7]+16*index+offset;words[pc]=p.word(pc)
    # Decode the original operation at rewritten architecture/address sites.
    for pc in words:
        if words[pc]==0xd421e000 and pc in p.sites:words[pc],metadata[pc]=p.sites[pc]
    hook=int(manifest['application']['result_hook'],0)
    ops=[];descriptions={};groups={};skipped=set();counts=collections.Counter()
    for pc in sorted(words):
        if pc in skipped:continue
        w=words[pc];m=metadata.get(pc,0)
        if pc==hook:op=Op(OBSERVE,w)
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
        counts[op.kind]+=1
        if op.kind!=NATIVE:
            idx=len(ops);ops.append((pc,op,m));descriptions[pc]=(idx,op,m)
    pcs=sorted(set(words)-skipped);missing=set()
    def label(pc):
        if pc not in words or pc in skipped:missing.add(pc)
        return '.Lp%x'%pc
    def resume(pc):label(pc);return '.Lr%x'%pc
    def thunk(name,to):
        return '.pushsection .text.resumes,"ax"\nflat_resume %s,%s,0\n.popsection\n'%(name,to)
    for pc,o,m in ops:
        if o.kind in (MEMORY,STACK):resume(pc+o.length*4)
    def constant(reg,value):
        return ''.join('    %s x%d,#0x%x%s\n'%('movz' if k==0 else 'movk',reg,(value>>(16*k))&65535,',lsl #%d'%(16*k) if k else '') for k in range(4))
    def control(pc,w):
        if w&0xfc000000 in (0x14000000,0x94000000):
            target=(pc+sign(w&0x3ffffff,26)*4)&((1<<64)-1)
            return (constant(30,pc+4) if w&(1<<31) else '')+'    b %s\n'%label(target)
        if w&0xff000010==0x54000000:
            target=pc+sign(w>>5&0x7ffff,19)*4;inv=(w&~(0x7ffff<<5))^1
            if w&15>=14:return '    b %s\n'%label(target)
            return '    .inst 0x%x\n    b %s\n'%((inv&~(0x7ffff<<5))|(2<<5),label(target))
        if w&0x7e000000 in (0x34000000,0x36000000):
            bits=14 if w&0x7e000000==0x36000000 else 19;mask=(1<<bits)-1
            target=pc+sign(w>>5&mask,bits)*4;inv=(w^(1<<24))&~(mask<<5)
            return '    .inst 0x%x\n    b %s\n'%(inv|(2<<5),label(target))
        return '    .inst 0x%08x\n'%w
    out.mkdir(parents=True,exist_ok=False)
    with (out/'program.S').open('w') as stream:
        stream.write('#include "gateway.inc"\n.text\n')
        for pc in pcs:
            w=words[pc];stream.write('.Lp%x:\n'%pc)
            if pc not in descriptions:
                if w&0x9f000000 in (0x10000000,0x90000000):
                    delta=sign((w>>29&3)|((w>>5&0x7ffff)<<2),21)
                    value=((pc&~4095)+(delta<<12)) if w&(1<<31) else pc+delta
                    stream.write(constant(w&31,value&((1<<64)-1)))
                else:stream.write(control(pc,w))
                if pc+4 not in words:stream.write('    b %s\n'%label(pc+4))
            else:
                idx,o,m=descriptions[pc]
                inline=''
                if hardware_memory and o.kind in (STACK,SYSTEM):
                    from el0_hardware import stack_path,system_path
                    inline=stack_path(o) if o.kind==STACK else system_path(o.word,m)
                if inline:
                    stream.write(inline)
                    stream.write('    b %s\n'%label(pc+4))
                    if o.kind==STACK:stream.write(thunk('.Lnr%x'%pc,'.Lp%x'%pc))
                    stream.write(thunk('.Lr%x'%pc,'.Lp%x'%pc))
                    continue
                if hardware_memory and o.kind==MEMORY:
                    from el0_hardware import memory_path
                    stream.write(memory_path(pc,o,label(pc+o.length*4),groups.get(pc),label))
                if hardware_memory and o.kind==INDIRECT:
                    from el0_hardware import indirect_path
                    stream.write(indirect_path(pc,o.word))
                if hardware_memory and o.kind==SYSTEM:
                    from el0_hardware import guarded_system_path,zero_path,lowered_branch_path
                    stream.write(lowered_branch_path(pc,o.word,m,label))
                    stream.write(guarded_system_path(pc,o.word,m,label(pc+4)))
                    stream.write(zero_path(pc,o.word,m,label(pc+4),zero_bytes))
                if hardware_memory and o.kind==OBSERVE:
                    from el0_hardware import observe_path
                    stream.write(observe_path(pc,'.Ln%x'%pc))
                stream.write('flat_capture .Lc%x,0x%x,0x%x,%d\n'%(pc,pc,w,idx*2))
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
                            stream.write('%s:\nflat_capture .Lex%x_%x,0x%x,0,%d\n'%(to,pc,dest,dest,idx*2+1));label(dest)
                    else:stream.write('    .inst 0x%08x\n'%o.native)
                    if hardware_memory and o.kind==MEMORY:
                        from el0_hardware import memory_finish_path
                        stream.write(memory_finish_path(pc,o,label(pc+4*o.length)))
                    stream.write('flat_capture .Ld%x,0x%x,0,%d\n'%(pc,pc+4*o.length,idx*2+1))
                    stream.write(thunk('.Lnr%x'%pc,'.Ln%x'%pc))
                elif o.kind==OBSERVE:
                    stream.write('.Ln%x:\n'%pc+control(pc,w))
                    stream.write(thunk('.Lnr%x'%pc,'.Ln%x'%pc))
            stream.write(thunk('.Lr%x'%pc,'.Lp%x'%pc))
        # Missing targets are real coverage boundaries, never replay-selected paths.
        for pc in sorted(missing):
            if pc in descriptions:continue
            idx=len(ops);o=Op(COVERAGE,words.get(pc,0));ops.append((pc,o,0));descriptions[pc]=(idx,o,0)
            stream.write('.Lp%x:\nflat_capture .Lc%x,0x%x,0,%d\n'%(pc,pc,pc,idx*2))
            stream.write(thunk('.Lr%x'%pc,'.Lp%x'%pc))
        stream.write('.section .rodata,"a"\n.balign 8\n.global flat_pcs\nflat_pcs:\n')
        for pc in sorted(set(pcs)|missing):stream.write('    .quad 0x%x,%s\n'%(pc,resume(pc)))
        if hardware_memory:
            from el0_hardware import indirect_resume
            stream.write('.global flat_direct_pc_count\nflat_direct_pc_count:\n.quad %d\n'%(len(set(pcs)|missing)))
            stream.write('.global flat_direct_pcs\nflat_direct_pcs:\n')
            for pc in sorted(set(pcs)|missing):stream.write('    .quad 0x%x,.Li%x\n'%(pc,pc))
            stream.write('.pushsection .text.resumes,"ax"\n')
            for pc in sorted(set(pcs)|missing):stream.write(indirect_resume('.Li%x'%pc,label(pc)))
            stream.write('.popsection\n')
        stream.write('.global flat_ops\nflat_ops:\n')
        for pc,o,m in ops:
            native='.Lnr%x'%pc if o.kind in (MEMORY,STACK,OBSERVE) else '0'
            following=resume(pc+o.length*4) if o.kind in (MEMORY,STACK) else '0'
            meta=o.length if o.kind in (MEMORY,STACK) else m
            stream.write('    .quad 0x%x,%s,%s,0x%x,0x%x,%d,0x%x,0x%x\n'%(pc,native,following,o.word,meta,o.kind,o.info,o.imm&((1<<64)-1)))
        stream.write('.section .note.GNU-stack,"",%progbits\n')
    immutable=text_metadata(out,p,user_elf)
    if hardware_memory:
        from el0_hardware import direct_ranges
        aliases,reads,writes=direct_ranges(p.maps,p.h[2],p.h[3],immutable)
        hardware=dict(format='osrec-el0-hardware-memory-v1',ram_base=p.h[2],ram_bytes=p.h[3],
                      native_zero_bytes=zero_bytes,
                      aliases=aliases,read_ranges=reads,write_ranges=writes,
                      translation='kernel VA -> flat_phys + captured PA - ram_base',
                      changing_user_mappings='checked software path',runtime_exception_level=0)
        (out/'hardware-memory.json').write_text(json.dumps(hardware,indent=2)+'\n')
    # Sparse initial bytes are copied into one zero-backed canonical RAM store.
    extents=[]
    with (p.path/'memory.bin').open('rb') as src,(out/'ram.bin').open('wb') as dst:
        for lo,hi in sparse_runs(src,p.h[3]):
            offset=dst.tell();src.seek(lo);left=hi-lo
            while left:
                chunk=src.read(min(left,1<<20))
                if not chunk:raise ValueError('truncated captured RAM')
                dst.write(chunk);left-=len(chunk)
            extents.append((lo,hi-lo,offset))
    expected,count=expected_events(record['calls']);(out/'expected.bin').write_bytes(expected)
    (out/'counters.bin').write_bytes((oracle/'counters.bin').read_bytes());(out/'shadow.bin').write_bytes(p.shadow)
    (out/'initial.bin').write_bytes(p.data[80:872]+bytes(8))
    (out/'ranges.bin').write_bytes(p.ranges);(out/'origins.bin').write_bytes(p.origins)
    mmio=list(struct.iter_unpack('<5Q',(oracle/'mmio.bin').read_bytes()));uart_va=(min(a for pc,a,s,w,v in mmio)&~4095) if mmio else 0
    uart=bytes(v&255 for pc,a,s,w,v in mmio if w and a==uart_va);(out/'uart.bin').write_bytes(uart)
    maps=sorted(p.maps+([(uart_va,0x9000000,4096,(1<<10)|(1<<53)|(1<<54))] if mmio else []))
    (out/'maps.bin').write_bytes(b''.join(struct.pack('<4Q',*r) for r in maps))
    data='.section .data,"aw"\n'
    for name,file in [('flat_shadow','shadow.bin'),('flat_initial','initial.bin')]:data+='.balign 16\n.global %s\n%s:\n.incbin "%s"\n'%(name,name,file)
    data+='.section .rodata,"a"\n'
    for name,file in [('flat_payload','ram.bin'),('flat_maps','maps.bin'),('flat_expected','expected.bin'),('flat_counters','counters.bin'),('flat_expected_uart','uart.bin'),('osrec_kernel_ranges','ranges.bin'),('osrec_veneer_origins','origins.bin')]:
        data+='.balign 16\n.global %s\n%s:\n.incbin "%s"\n'%(name,name,file)
    for name,value in [('osrec_kernel_range_count',p.h[5]),('osrec_veneer_count',p.h[8]),('osrec_veneer_base',p.h[7]),('flat_expected_uart_bytes',len(uart))]:data+='.global %s\n%s:\n.quad 0x%x\n'%(name,name,value)
    if hardware_memory:
        if zero_bytes:data+='.balign 8\n.global flat_hardware_zero_bytes\nflat_hardware_zero_bytes:\n.quad %d\n'%zero_bytes
        for name,ranges in [('flat_direct_read',reads),('flat_direct_write',writes)]:
            data+='.balign 16\n.global %s\n%s:\n'%(name,name)
            data+=''.join('.quad 0x%x,0x%x\n'%tuple(row) for row in ranges)+'.quad 0,0\n'
    data+='.section .note.GNU-stack,"",%progbits\n';(out/'state.S').write_text(data)
    s='#include "program.h"\nextern unsigned char flat_shadow[],flat_payload[],flat_maps[],flat_expected[],flat_counters[];\nextern const struct flat_pc flat_pcs[]; extern const struct flat_op flat_ops[];\n'
    s+='unsigned char flat_phys[%d] __attribute__((aligned(4096)));\n'%p.h[3]
    s+='unsigned char flat_uart_registers[4096],flat_uart[4096];struct flat_event flat_events[%d];\n'%(count+1024)
    s+='static const struct flat_ram ram[]={{0x%x,%d,flat_phys},{0x9000000,4096,flat_uart_registers}};\n'%(p.h[2],p.h[3])
    s+='struct flat_full_image flat_program={.memory={ram,2,(const struct flat_mapping *)flat_maps,%d,0x%x,0x%x},.shadow=(struct osrec_shadow *)flat_shadow,.pcs=flat_pcs,.pc_count=%d,.ops=flat_ops,.expected=(const struct flat_event *)flat_expected,.expected_count=%d,.counters=(const struct flat_counter *)flat_counters,.counter_count=%d,.stop_pc=%s,.uart_va=0x%x};\n'%(len(maps),struct.unpack_from('<Q',p.shadow,72)[0],p.h[4],len(set(pcs)|missing),count,len((oracle/'counters.bin').read_bytes())//24,record['end']['pc'],uart_va)
    s+='extern void *memcpy(void *,const void *,size_t); void flat_program_initialize(void){\n'
    s+=''.join('memcpy(flat_phys+%d,flat_payload+%d,%d);\n'%(lo,off,size) for lo,size,off in extents)
    s+='flat_uart_registers[0x18]=0x90;}\n';(out/'image.c').write_text(s)
    report=dict(format='osrec-el0-program-v1',functions=len(functions),source_instructions=len(pcs),adaptations=len(ops),decoded=dict(counts),
                static_missing=len(missing),initial_pc=hex(struct.unpack_from('<Q',p.data,80+256)[0]),expected_events=count,
                kernel=str(vmlinux),package=str(p.path),oracle=str(oracle),user_elf=str(Path(user_elf).resolve()),
                kernel_sha256=hashlib.sha256(vmlinux.read_bytes()).hexdigest(),
                native_state_sha256=hashlib.sha256(p.data).hexdigest(),source_image_sha256=source,
                coverage_sha256=hashlib.sha256(Path(coverage).read_bytes()).hexdigest() if coverage else None,
                scope='restored user checkpoint and actual kernel entry/dispatch/return, conservative code closure',runtime_el=0,
                memory_backend='hardware-kernel' if hardware_memory else 'software',
                hardware_memory_sha256=hashlib.sha256((out/'hardware-memory.json').read_bytes()).hexdigest() if hardware_memory else None)
    (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');return report

if __name__=='__main__':
    a=argparse.ArgumentParser(description=__doc__)
    for name in ('package','vmlinux','user-elf','oracle','out'):a.add_argument('--'+name,required=True)
    a.add_argument('--extra-pc',action='append',type=lambda s:int(s,0),default=[])
    a.add_argument('--coverage',help='optional QEMU in_asm listing; static function coverage seed only')
    a.add_argument('--hardware-memory',action='store_true',help='inline static kernel RAM accesses; requires the generated hardware page-table load plan')
    p=a.parse_args();print(json.dumps(export(p.package,p.vmlinux,p.user_elf,p.oracle,p.out,p.extra_pc,p.coverage,p.hardware_memory),indent=2))
