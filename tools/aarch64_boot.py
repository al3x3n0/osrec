"""Build a standalone, stackless EL3 -> nonsecure EL1 replay boot shim."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import struct

BOOT_ADDRESS=0x43f00000
BOOT_BYTES=4096


def expected_payload(entry):
    """Reviewed baseline instructions; only four MOV immediates vary with entry."""
    if type(entry) is not int or not 0<=entry<1<<64 or entry%4:
        raise ValueError('boot replay entry must be an aligned unsigned address')
    words=[0xd5034fdf,0xd2808620,0xd51e1100,0xd5033fdf,0xd51e115f,
        0xd51e133f,0xd2b00000,0xd51c1100,0xd2867fe0,0xd51c1140,
        0xd51c113f,0xd510025f,0xd5381000,0xd28200a1,0xf2a04001,
        0x8a210000,0xd5181000,0xd28078a0,0xd51e4000]
    words += [(0xd2800000 if half==0 else 0xf2800000)|(half<<21)|(((entry>>(16*half))&0xffff)<<5) for half in range(4)]
    words += [0xd51e4020,0xd5033fdf,0xd69f03e0]
    return struct.pack('<'+str(len(words))+'I',*words)


def load_plan(layout,address):
    raw=expected_payload(layout['entry'])
    return {'format':'osrec-aarch64-el3-boot-v1','entry':address,'replay_entry':layout['entry'],
        'required_start':'AArch64 EL3 reset, EL2 and EL3 implemented, EL3 MMU/caches off, physical RAM accessible',
        'transition':'EL3 to nonsecure AArch64 EL1h with DAIF masked',
        'reserved_range':{'address':address,'bytes':BOOT_BYTES},
        'payload':{'file':'boot.bin','address':address,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},
        'runtime_host_interaction':False,'rtl_execution_verified':False}


def verify(layout,directory):
    """Re-derive the plan and instruction bytes; never follow manifest paths."""
    directory=Path(directory);document=json.loads((directory/'boot-plan.json').read_text())
    if not isinstance(document,dict):raise ValueError('invalid boot plan')
    address=document.get('entry');validate(layout,address)
    expected=load_plan(layout,address)
    if json.dumps(document,sort_keys=True)!=json.dumps(expected,sort_keys=True):
        raise ValueError('boot plan differs from derived entry contract')
    if (directory/'boot.bin').read_bytes()!=expected_payload(layout['entry']):
        raise ValueError('boot payload differs from reviewed instruction template')
    return expected


def check_loaded(layout,directory,ram,dumps):
    from image_memory import compare_physical_memory,require_coverage
    directory=Path(directory);plan=verify(layout,directory)
    require_coverage([plan['reserved_range']],ram)
    comparison=compare_physical_memory([{**plan['payload'],'file':directory/'boot.bin','offset':0,
        'purpose':'EL3 boot instructions'}],dumps,ram)
    return {'format':'osrec-aarch64-loaded-boot-verification-v1','status':'verified',
        'boot_plan':plan,'initial_memory_verification':comparison,'model_boot_memory_verified':True,
        'scope':'exact boot payload bytes in supplied physical dumps; reserved padding is unconstrained',
        'snapshot_phase_verified':False,'snapshot_backend':'caller-supplied physical dumps',
        'cpu_state_verified':False,'runtime_host_interaction':False,'rtl_execution_verified':False}


def validate(layout,address=BOOT_ADDRESS):
    from image_memory import memory_contract
    if layout['isa']!='AArch64':raise ValueError('EL3 boot requires AArch64')
    if type(address) is not int or address%4096 or not 0x40000000<=address<=0x44000000-BOOT_BYTES:
        raise ValueError('boot address must be page aligned inside QEMU RAM')
    ranges=memory_contract(layout)['required_ranges']
    start=layout['raw_image_load_address']
    end=max(s['address']+s['file_bytes'] for s in layout['load_segments'] if s['file_bytes'])
    ranges=ranges+[{'address':start,'bytes':end-start}]
    for span in ranges:
        if address<span['address']+span['bytes'] and span['address']<address+BOOT_BYTES:
            raise ValueError('boot shim overlaps replay memory')


def build(layout,out,llvm=Path('/opt/homebrew/opt/llvm@16/bin'),address=BOOT_ADDRESS):
    validate(layout,address);out=Path(out);out.mkdir(parents=True,exist_ok=False)
    entry=layout['entry']
    source=f''' .section .text.boot,"ax"
.global _boot
_boot:
    msr daifset, #15
    mov x0, #0x431
    msr scr_el3, x0
    isb
    msr cptr_el3, xzr
    msr mdcr_el3, xzr
    mov x0, #0x80000000
    msr hcr_el2, x0
    mov x0, #0x33ff
    msr cptr_el2, x0
    msr mdcr_el2, xzr
    msr mdscr_el1, xzr
    mrs x0, sctlr_el1
    mov x1, #0x1005
    movk x1, #0x200, lsl #16
    bic x0, x0, x1
    msr sctlr_el1, x0
    mov x0, #0x3c5
    msr spsr_el3, x0
    movz x0, #{entry&0xffff}
    movk x0, #{(entry>>16)&0xffff}, lsl #16
    movk x0, #{(entry>>32)&0xffff}, lsl #32
    movk x0, #{(entry>>48)&0xffff}, lsl #48
    msr elr_el3, x0
    isb
    eret
'''
    (out/'boot.S').write_text(source)
    (out/'boot.ld').write_text(f'ENTRY(_boot)\nSECTIONS {{ . = {address}; .text : {{ *(.text.boot) }} }}\n')
    subprocess.run([str(llvm/'clang'),'--target=aarch64-none-elf','-c',str(out/'boot.S'),'-o',str(out/'boot.o')],check=True)
    subprocess.run([str(llvm/'ld.lld'),'-T',str(out/'boot.ld'),str(out/'boot.o'),'-o',str(out/'boot.elf')],check=True)
    subprocess.run([str(llvm/'llvm-objcopy'),'-O','binary',str(out/'boot.elf'),str(out/'boot.bin')],check=True)
    raw=(out/'boot.bin').read_bytes()
    if raw!=expected_payload(entry):raise ValueError('assembled boot differs from reviewed instruction template')
    disassembly=subprocess.check_output([str(llvm/'llvm-objdump'),'--no-show-raw-insn','-d',str(out/'boot.elf')],text=True)
    (out/'boot.disassembly').write_text(disassembly)
    import re
    if re.search(r'^\s*[0-9a-f]+:\s+(svc|hvc|smc|brk|hlt)\b',disassembly,re.M):raise ValueError('boot contains a service trap')
    plan=load_plan(layout,address)
    (out/'boot-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    return plan


if __name__=='__main__':
    from freestanding_elf import describe
    parser=argparse.ArgumentParser(description=__doc__)
    from check_image_memory import ram_region,memory_dump
    parser.add_argument('image',type=Path);parser.add_argument('--out',type=Path)
    parser.add_argument('--verify-directory',type=Path,help='verify an existing boot plan and canonical payload instead of building')
    parser.add_argument('--ram',type=ram_region,action='append')
    parser.add_argument('--memory-dump',type=memory_dump,action='append',help='also compare physical boot bytes; requires --ram and --verify-directory')
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--address',type=lambda s:int(s,0),default=BOOT_ADDRESS)
    args=parser.parse_args()
    if args.verify_directory:
        if args.out:parser.error('--out is only for building')
        if args.memory_dump and not args.ram:parser.error('--memory-dump requires --ram')
        report=check_loaded(describe(args.image),args.verify_directory,args.ram,args.memory_dump) if args.memory_dump else verify(describe(args.image),args.verify_directory)
    else:
        if not args.out or args.memory_dump or args.ram:parser.error('building requires --out; dump checks require --verify-directory')
        report=build(describe(args.image),args.out,args.llvm_bin,args.address)
    print(json.dumps(report,indent=2))
