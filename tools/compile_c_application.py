#!/usr/bin/env python3
"""Compile a freestanding C user ELF and derive its syscall checkpoint metadata.

Applications define osrec_application_main() and use osrec_application.h.
The expected dynamic call count is supplied; it is checked during replay.
"""
import argparse
import json
import re
from pathlib import Path
from export_syscall_slices import validate_port
from freestanding_armv7 import run
from import_application_checkpoint import FORMAT, digest, elf_layout, integer

def wrappers(port,site_names=('default',)):
    abi=port['application_abi']
    text='#ifndef OSREC_APPLICATION_H\n#define OSREC_APPLICATION_H\n#include <stdint.h>\n#include <stddef.h>\nint64_t osrec_app_syscall(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);\n'
    for root in port['roots']:
        count=len(root['arguments'])
        args=','.join('uint64_t a'+str(i) for i in range(count)) or 'void'
        values=['a'+str(i) if i<count else '0' for i in range(6)]
        text+='static inline int64_t osrec_app_'+root['function']+'('+args+'){return osrec_app_syscall(UINT64_C('+str(root['number'])+'),'+','.join(values)+');}\n'
    text+='#endif\n'
    assembly=''.join(wrapper_assembly(abi,name) for name in site_names)
    for name in site_names:
        if name!='default':text=text.replace('#endif\n','int64_t osrec_app_syscall_'+name+'(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);\n#endif\n')
    return text,assembly

def wrapper_assembly(abi,name):
    function='osrec_app_syscall'+('' if name=='default' else '_'+name)
    site='osrec_application_svc'+('' if name=='default' else '_'+name)
    assembly='''.arch armv8-a
.section .osrec_syscall,"ax"
.global '''+function+','+site+'\n'+function+''':
    stp x0,x1,[sp,#-160]!
    stp x2,x3,[sp,#16]
    stp x4,x5,[sp,#32]
    str x6,[sp,#48]
'''
    for i in range(6): assembly+='    stp x'+str(19+2*i)+',x'+str(20+2*i)+',[sp,#'+str(64+16*i)+']\n'
    assembly+='    ldr x'+str(abi['number_register'])+',[sp]\n'
    for i,r in enumerate(abi['argument_registers']):assembly+='    ldr x'+str(r)+',[sp,#'+str(8+8*i)+']\n'
    assembly+=site+':\n    svc #0\n    mov x0,x'+str(abi['result_register'])+'\n'
    for i in range(6):assembly+='    ldp x'+str(19+2*i)+',x'+str(20+2*i)+',[sp,#'+str(64+16*i)+']\n'
    assembly+='    add sp,sp,#160\n    ret\n'
    return assembly

def compile_application(sources,port,out,llvm_bin,spec=None,calls=32,entry=0x41000000,syscall=0x41010000,data=0x41020000):
    sources=[Path(p) for p in sources];port=Path(port);out=Path(out);spec=spec or {}
    if out.exists():raise FileExistsError(out)
    if not sources:raise ValueError('no C application sources')
    calls=integer(calls,'expected syscall count')
    if not 0<calls<=65536:raise ValueError('expected syscall count is out of range')
    if any(type(a) is not int or a<=0 or a&4095 for a in (entry,syscall,data)) or not entry<syscall<data:raise ValueError('application segment addresses must be increasing and page aligned')
    config=json.loads(port.read_text());validate_port(config)
    if 'application_abi' not in config:raise ValueError('port has no application register ABI')
    call_sites=spec.get('call_sites',['default']*calls)
    if not isinstance(call_sites,list) or len(call_sites)!=calls or any(not isinstance(n,str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}',n) for n in call_sites):raise ValueError('call_sites must name one valid wrapper per expected call')
    site_names=sorted(set(call_sites),key=lambda n:(n!='default',n))
    header,assembly=wrappers(config,site_names)
    out.mkdir(parents=True);stage=out/'sources';stage.mkdir()
    (stage/'osrec_application.h').write_text(header);(stage/'syscall.S').write_text(assembly)
    (stage/'start.S').write_text('''.arch armv8-a
.section .text.entry,"ax"
.global osrec_application_entry,osrec_application_exit
osrec_application_entry:
    bl osrec_application_main
osrec_application_exit:
    nop
    b osrec_application_exit
.section .bss.stack,"aw",%nobits
.balign 16
    .space 4096
.global osrec_application_stack_top
osrec_application_stack_top:
''')
    (stage/'application.ld').write_text('''ENTRY(osrec_application_entry)
PHDRS {main PT_LOAD FLAGS(5);syscall PT_LOAD FLAGS(5);data PT_LOAD FLAGS(6);}
SECTIONS {
. = '''+hex(entry)+''';.text : {KEEP(*(.text.entry)) *(.text*) . = ALIGN(4);} :main
ASSERT(. <= '''+hex(syscall)+''', "application text overlaps syscall segment")
. = '''+hex(syscall)+''';.syscall : {*(.osrec_syscall) . = ALIGN(4);} :syscall
ASSERT(. <= '''+hex(data)+''', "syscall segment overlaps application data")
. = '''+hex(data)+''';.data : {*(.rodata*) *(.data*)} :data
.bss (NOLOAD) : {*(.bss*) *(COMMON) . = ALIGN(16);} :data
/DISCARD/ : {*(.comment*) *(.eh_frame*)}
}
''')
    compiler=[llvm_bin/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align','-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-I'+str(stage)]
    objects=[]
    for i,source in enumerate(sources):
        copied=stage/('application-'+str(i)+'.c');copied.write_bytes(source.read_bytes())
        obj=stage/('application-'+str(i)+'.o');run([*compiler,'-c',copied,'-o',obj]);objects.append(obj)
    for filename in ('start','syscall'):
        obj=stage/(filename+'.o');run([*[f for f in compiler if f!='-mgeneral-regs-only'],'-c',stage/(filename+'.S'),'-o',obj]);objects.append(obj)
    elf=out/'application.elf'
    run([*compiler,'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(stage/'application.ld'),*objects,'-o',elf])
    layout=elf_layout(elf.read_bytes())
    symbols={r.split()[0]:int(r.split()[2],16) for r in run([llvm_bin/'llvm-nm','--defined-only','--format=posix',elf]).stdout.splitlines() if len(r.split())>=3}
    def resolve(item):
        item=dict(item)
        if 'symbol' in item:
            name=item.pop('symbol')
            if name not in symbols:raise ValueError('unknown application checkpoint symbol: '+name)
            item['address']=symbols[name]+integer(item.pop('offset',0),'symbol offset')
        return item
    frame=dict(spec.get('frame',{}));frame.setdefault('sp',symbols['osrec_application_stack_top'])
    checkpoint=dict(format=FORMAT,elf_sha256=digest(elf.read_bytes()),frame=frame,calls=[dict(pc=symbols['osrec_application_svc'+('' if n=='default' else '_'+n)]) for n in call_sites],exit=dict(pc=symbols['osrec_application_exit'],original='1f2003d5'))
    for key in ('objects','snapshots','assertions','extra_memory'):checkpoint[key]=[resolve(item) for item in spec.get(key,[])]
    (out/'checkpoint.json').write_text(json.dumps(checkpoint,indent=2)+'\n')
    manifest=dict(format='osrec-compiled-c-application-v1',elf_sha256=checkpoint['elf_sha256'],checkpoint_sha256=digest((out/'checkpoint.json').read_bytes()),port=config,port_sha256=digest(port.read_bytes()),entry=layout['entry'],expected_calls=calls,syscall_pc=symbols.get('osrec_application_svc'),source_hashes={str(p.relative_to(stage)):digest(p.read_bytes()) for p in stage.iterdir() if p.is_file()},compiler_version=run([llvm_bin/'clang','--version']).stdout.splitlines()[0],runtime_host_interaction=False)
    if 'call_sites' in spec:manifest.update(call_sites=call_sites,syscall_pcs={n:symbols['osrec_application_svc'+('' if n=='default' else '_'+n)] for n in site_names})
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return checkpoint

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,action='append',required=True);parser.add_argument('--port',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);parser.add_argument('--calls',type=int,required=True)
    parser.add_argument('--spec',type=Path);parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    args=parser.parse_args();compile_application(args.source,args.port,args.out,args.llvm_bin,json.loads(args.spec.read_text()) if args.spec else {},args.calls)
if __name__=='__main__':main()
