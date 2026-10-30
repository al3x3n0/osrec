#!/usr/bin/env python3
"""Build a separate EL0 application ELF for the captured 32-call OHOS file profile.

This is a generated test application, not a recorder-format importer. All buffer
preparation, return checking and continuation instructions execute in EL0.
"""
import argparse
import json
import struct
from pathlib import Path
from freestanding_armv7 import run
from import_application_checkpoint import FORMAT, digest

def build(library, out, llvm_bin):
    library, out = Path(library), Path(out)
    if out.exists(): raise FileExistsError(out)
    capture=json.loads((library/'checkpoint.json').read_text())
    port=json.loads((library/'manifest.json').read_text())['port']
    roots={r['number']:r for r in port['roots']}
    calls=capture['calls']; out.mkdir(parents=True)
    assembly='''.arch armv8-a
.section .text.entry,"ax"
.global app_entry,app_exit
app_entry:
    mov x19,#0
    ldr x20,=app_before
    ldr x21,=app_witness
    ldr x22,=app_arguments
    ldr x23,=app_returns
    ldr x24,=app_after
    ldr x25,=app_count
    ldr x26,=app_marker
    ldr x9,[x26]
    cmp x9,#42
    cset x27,ne
    ldr x9,[x23]
    orr x27,x27,x9
    ldr x9,[x25]
    orr x27,x27,x9
1:
    mov x28,#0
2:
    ldr x9,[x20,x28]
    str x9,[x21,x28]
    add x28,x28,#8
    cmp x28,#192
    b.ne 2b
    ldr x8,[x22]
    ldp x0,x1,[x22,#8]
    ldp x2,x3,[x22,#24]
    ldp x4,x5,[x22,#40]
    bl app_syscall
    str x0,[x23,x19,lsl #3]
    ldr x9,[x22,#56]
    cmp x0,x9
    cset x10,ne
    orr x27,x27,x10
    mov x28,#0
3:
    ldr x9,[x21,x28]
    ldr x10,[x24,x28]
    eor x9,x9,x10
    orr x27,x27,x9
    add x28,x28,#8
    cmp x28,#192
    b.ne 3b
    add x19,x19,#1
    add x20,x20,#192
    add x24,x24,#192
    add x22,x22,#64
    cmp x19,#32
    b.ne 1b
    str x19,[x25]
    str x19,[sp,#-16]
    ldr x9,[x26]
    add x9,x9,#1
    str x9,[x26]
    ldr x9,=app_failed
    str x27,[x9]
    ldr x10,=app_cpu
    umov x9,v31.d[1]
    str x9,[x10]
    mrs x9,tpidr_el0
    str x9,[x10,#8]
    mrs x9,tpidrro_el0
    str x9,[x10,#16]
app_exit:
    nop
    b app_exit
.section .text.syscall,"ax"
.global app_syscall
app_syscall:
    svc #0
    ret
.section .rodata,"a"
.balign 8
app_main: .asciz "/dev/shm/osrec-file.bin"
app_missing: .asciz "/dev/shm/osrec-missing.bin"
.balign 8
app_before:
'''
    def byte_lines(data): return '\n'.join('.byte '+','.join(str(v) for v in data[i:i+32]) for i in range(0,len(data),32))+'\n'
    for c in calls: assembly+=byte_lines(bytes.fromhex(c['buffer_before']))
    assembly+='app_after:\n'
    for c in calls: assembly+=byte_lines(bytes.fromhex(c['buffer_after']))
    assembly+='.balign 8\napp_arguments:\n'
    for c in calls:
        arguments=[]
        for j, kind in enumerate(roots[c['number']]['arguments']):
            v=c['args'][j]
            if kind=='buffer': v='app_witness' if v==1 else '0xdead00000000' if v==2 else '0'
            elif kind=='path': v='app_main' if v==1 else 'app_missing' if v==2 else '0xdead00000000' if v==3 else '0'
            arguments.append(str(v))
        arguments+=['0']*(6-len(arguments))
        raw=c['raw_bits']; raw=raw if raw<0x80000000 else raw-0x100000000
        assembly+='.quad '+','.join([str(c['number']),*arguments,str(raw)])+'\n'
    assembly+='''.section .bss,"aw",%nobits
.balign 16
.global app_witness,app_returns,app_marker,app_count,app_failed,app_stack_top,app_cpu
app_witness: .space 192
app_returns: .space 256
app_marker: .space 8
app_count: .space 8
app_failed: .space 8
app_cpu: .space 24
.balign 16
app_stack: .space 4096
app_stack_top:
'''
    (out/'app.S').write_text(assembly)
    (out/'app.ld').write_text('''ENTRY(app_entry)
PHDRS {main PT_LOAD FLAGS(5);syscall PT_LOAD FLAGS(5);data PT_LOAD FLAGS(6);}
SECTIONS {
. = 0x41000000; .entry : {*(.text.entry)} :main
. = 0x41010000; .syscall : {*(.text.syscall)} :syscall
. = 0x41020000; .rodata : {*(.rodata)} :data
.bss (NOLOAD) : {*(.bss)} :data
/DISCARD/ : {*(.comment*)}
}
''')
    elf=out/'application.elf'
    run([llvm_bin/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(out/'app.ld'),out/'app.S','-o',elf])
    symbols={r.split()[0]:int(r.split()[2],16) for r in run([llvm_bin/'llvm-nm','--defined-only','--format=posix',elf]).stdout.splitlines() if len(r.split())>=3}
    cpu=[0xfedcba9876543210,0x1234567890,0xabcdef0123]
    document=dict(format=FORMAT,elf_sha256=digest(elf.read_bytes()),frame=dict(sp=symbols['app_stack_top'],tpidr_el0=cpu[1],tpidrro_el0=cpu[2],v=[[i,cpu[0] if i==31 else 100+i] for i in range(32)]),calls=[dict(pc=symbols['app_syscall']) for _ in calls],exit=dict(pc=symbols['app_exit'],original='1f2003d5'),snapshots=[dict(address=symbols['app_marker'],data=struct.pack('<Q',42).hex())],objects=[dict(address=symbols['app_witness'],bytes=192,id=1)],assertions=[dict(address=symbols['app_returns'],data=b''.join(struct.pack('<Q',c['raw_bits'] if c['raw_bits']<0x80000000 else (c['raw_bits']-0x100000000)&0xffffffffffffffff) for c in calls).hex()),dict(address=symbols['app_marker'],data=struct.pack('<QQQ',43,32,0).hex()),dict(address=symbols['app_cpu'],data=struct.pack('<3Q',*cpu).hex()),dict(address=symbols['app_stack_top']-16,data=struct.pack('<Q',32).hex())])
    (out/'checkpoint.json').write_text(json.dumps(document,indent=2)+'\n')
    return document

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--slices',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    a=parser.parse_args();build(a.slices,a.out,a.llvm_bin)
if __name__=='__main__':main()
