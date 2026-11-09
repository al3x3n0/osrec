#!/usr/bin/env python3
"""Export the first bounded EL0-only captured-kernel native checkpoint.

The current admitted root is __arm64_sys_umask. Its ordinary instructions,
including its complete exclusive sequence, execute in linked native islands.
No original SVC/BRK, real MMIO or privileged operation executes. Logical memory
is backed by writable linked RAM; software translation preserves aliases.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from export_native_checkpoint import sparse_runs
from kernel_source_verify import Elf

ROOT=Path(__file__).resolve().parents[1]
MASK48=(1<<48)-1


def export(package,vmlinux,out):
    package,vmlinux,out=map(lambda p:Path(p).resolve(),(package,vmlinux,out))
    native=(package/'native.bin').read_bytes();h=struct.unpack_from('<10Q',native)
    if h[0]!=0x3145564954414e4c or h[1]!=1:raise ValueError('unsupported native package')
    at=80+272+520;shadow=native[at:at+532584]
    if len(shadow)!=532584:raise ValueError('truncated shadow state')
    mappings_at=at+532584+16*h[5]+16*h[6]+8*h[8]
    mappings=list(struct.iter_unpack('<4Q',native[mappings_at:]))
    if len(mappings)!=h[9]:raise ValueError('invalid mapping table')
    site_at=at+532584+16*h[5]
    sites={pc:(word,kind) for pc,word,kind in struct.iter_unpack('<QII',native[site_at:site_at+16*h[6]])}
    kernel=Elf(vmlinux);symbols={s['name']:s for s in kernel.symbols if s['shndx'] and s['value']}
    function=symbols['__arm64_sys_umask'];pc=function['value'];entry=pc&MASK48
    words=list(struct.unpack('<15I',kernel.read(pc,60)))
    # Bind this small first lowering to the actual instruction shape. Unsupported
    # builds reject; this is not a hand-written substitute for the kernel body.
    if function['size']!=60 or words[3]&0xffffffe0!=0xd5384100 or words[4]!=0xb9400009 or words[5]!=0xf9431d08 or\
       words[8]!=0xf9800111 or words[9]!=0x885f7d0b or words[10]!=0x880afd09 or\
       words[11]!=0x35ffffca or words[12]!=0xd5033bbf or words[14]!=0xd65f03c0:
        raise ValueError('unsupported umask instruction shape')
    def physical(va):
        for start,pa,size,attrs in mappings:
            if start<=va<start+size:return pa+va-start
        raise ValueError('missing captured function mapping')
    patched=[]
    trace_start=symbols['__start_mcount_loc']['value'];trace_end=symbols['__stop_mcount_loc']['value']
    ftrace={v for v, in struct.iter_unpack('<Q',kernel.read(trace_start,trace_end-trace_start))}
    with (package/'memory.bin').open('rb') as memory:
        for i,word in enumerate(words):
            address=entry+4*i;memory.seek(physical(address)-h[2]);captured=struct.unpack('<I',memory.read(4))[0]
            if i==3:
                if sites.get(address)!=(word,0):raise ValueError('captured MRS differs from source build')
            elif captured!=word:
                if i!=1 or word!=0xd503201f or captured!=0xaa1e03e9 or pc-8 not in ftrace:
                    raise ValueError('captured ordinary instruction differs outside admitted ftrace patch')
                words[i]=captured;patched.append(dict(offset=4*i,source=hex(word),captured=hex(captured),kind='ftrace CALL_OPS entry'))
    task_offset=struct.unpack_from('<Q',shadow,104+8192+0xc684*8)[0]
    task_slot=(symbols['__entry_task']['value']+task_offset)&MASK48
    regs=struct.unpack_from('<Q',shadow,8)[0]-0x150
    out.mkdir(parents=True,exist_ok=False)
    (out/'shadow.bin').write_bytes(shadow)
    (out/'initial.bin').write_bytes(native[80:80+272+520]+bytes(8))
    (out/'mappings.bin').write_bytes(native[mappings_at:])
    extents=[]
    with (package/'memory.bin').open('rb') as memory,(out/'ram.bin').open('wb') as ram:
        if memory.seek(0,2)!=h[3]:raise ValueError('physical store size mismatch')
        for lo,hi in sparse_runs(memory,h[3]):
            offset=ram.tell();memory.seek(lo);left=hi-lo
            while left:
                data=memory.read(min(left,1<<20))
                if not data:raise ValueError('truncated RAM')
                ram.write(data);left-=len(data)
            extents.append((h[2]+lo,hi-lo,offset))
    source='#include "el0_flat_image.h"\n'
    source+='extern unsigned char flat_payload[],flat_shadow[],flat_initial[],flat_mappings[];\n'
    source+='static const struct flat_ram ram[] = {\n'
    source+=''.join(' {%d,%d,flat_payload+%d},\n'%r for r in extents)+'};\n'
    # The initial frame is copied in the target, avoiding a C constant initializer
    # containing state bytes, and retaining one auditable binary representation.
    source+='struct flat_image flat_image = { .memory={ram,%d,(const struct flat_mapping *)flat_mappings,%d,0x%x,0x%x},\n'%(len(extents),len(mappings),struct.unpack_from('<Q',shadow,72)[0],h[4])
    source+=' .shadow=(struct osrec_shadow *)flat_shadow, .task_slot=0x%x, .entry=0x%x, .regs=0x%x };\n'%(task_slot,entry,regs)
    source+='void flat_image_initialize(void) { unsigned char *d=(void *)&flat_image.initial; for(unsigned i=0;i<800;i++)d[i]=flat_initial[i]; }\n'
    (out/'image.c').write_text(source)
    source='.section .data.flat_state,"aw",%progbits\n'
    for symbol,file,alignment in [('flat_shadow','shadow.bin',16),('flat_initial','initial.bin',16),('flat_mappings','mappings.bin',16),('flat_payload','ram.bin',4096)]:
        source+='.balign %d\n.global %s\n%s:\n.incbin "%s"\n'%(alignment,symbol,symbol,file)
    source+='.section .note.GNU-stack,"",%progbits\n';(out/'image.S').write_text(source)
    source='#include "gateway.inc"\n.text\n'
    def instructions(lo,hi):return ''.join('    .inst 0x%08x\n'%w for w in words[lo:hi])
    for name,lo,hi,kind in [('entry',0,3,1),('load_arg',4,5,2),('load_fs',5,6,3),('arithmetic',6,8,4),('atomic',8,13,5),('tail',13,14,6)]:
        source+='umask_%s_body:\n'%name+instructions(lo,hi)+'    b umask_%s_capture\n'%name
        site=entry+4*hi
        source+='flat_capture umask_%s_capture,0x%x,0x%x,%d\n'%(name,site,words[hi],kind)
        source+='flat_resume umask_%s,umask_%s_body\n'%(name,name)
    source+='.section .note.GNU-stack,"",%progbits\n';(out/'kernel.S').write_text(source)
    manifest=dict(format='osrec-el0-flat-umask-v1',root='__arm64_sys_umask',scope='bounded native kernel function, not full user-checkpoint continuation',
                  package=str(package),kernel_sha256=hashlib.sha256(vmlinux.read_bytes()).hexdigest(),
                  native_package_sha256=hashlib.sha256(native).hexdigest(),function_sha256=hashlib.sha256(kernel.read(pc,60)).hexdigest(),
                  captured_function_sha256=hashlib.sha256(struct.pack('<15I',*words)).hexdigest(),boot_patches=patched,
                  function_address=hex(entry),native_instructions=13,adapted_instructions=2,
                  exclusive_sequence='original PRFM/LDXR/STLXR/CBNZ/DMB, contiguous; no runtime call inside',
                  ram_data_bytes=(out/'ram.bin').stat().st_size,ram_extents=len(extents),
                  runtime_el=0,libc=False,runtime_host_calls='terminal exit only',host_signals=False,real_mmio=False,
                  guest_sp='logical RAM state; all actual SP accesses use private runtime stacks',
                  memory='software stage-1 translation, canonical sparse RAM, no OS mappings; missing RAM and cross-page operations stop',
                  build='make -C runtime/el0_flat CC=clang-19 IMAGE=ABSOLUTE_DIRECTORY checkpoint',
                  rtl_execution_verified=False,cycle_accuracy_verified=False)
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package',required=True);p.add_argument('--vmlinux',required=True);p.add_argument('--out',required=True)
    a=p.parse_args();print(json.dumps(export(a.package,a.vmlinux,a.out),indent=2))
