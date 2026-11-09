#!/usr/bin/env python3
"""Build a host-independent, self-checking EL1 monitor checkpoint image.

The captured application/kernel run at EL0. UART is the sole mapped device;
timer reads use a small linked input list. There are no host runtime calls.
The model initializes RAM from the load plan and observes a RAM result block.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from export_native_checkpoint import expected_events
from kernel_source_verify import Elf
from kernel_boundary_replay import elf as physical_elf
from source_image_el0 import MONITOR_PA,MONITOR_SIZE,TABLE_PA,BRK_SITE,instruction_ranges
from source_image import LLVM,ROOT,result_point,text_ranges

PAGE=4096
MASK=(1<<48)-PAGE


def audit_monitor(path):
    """Check executable instructions only, excluding literal/data records."""
    image=Elf(path)
    if any(s['name'] and not s['shndx'] for s in image.symbols):raise ValueError('monitor has unresolved dependencies')
    sections=[(s['addr'],s['addr']+s['size']) for s in image.sections if s['flags']&4 and s['size']]
    instructions=0
    for lo,hi in instruction_ranges(image,sections):
        for pc in range(lo,hi,4):
            word,=struct.unpack('<I',image.read(pc,4));instructions+=1
            if word&0xffe0001f in (0xd4000001,0xd4000002,0xd4000003,0xd4400000):
                raise ValueError('monitor contains a syscall, hypercall or semihosting instruction at '+hex(pc))
    return dict(instructions=instructions,host_call_instructions=0,undefined_symbols=0)


class Memory:
    def __init__(self,data):
        self.pages={}
        phoff,=struct.unpack_from('<Q',data,32);stride,count=struct.unpack_from('<HH',data,54)
        for i in range(count):
            kind,flags,offset,va,pa,size,memsize,align=struct.unpack_from('<IIQQQQQQ',data,phoff+i*stride)
            if kind!=1:continue
            if pa%PAGE or size%PAGE or size!=memsize or offset+size>len(data):raise ValueError('unsupported physical segment')
            for k in range(0,size,PAGE):
                if pa+k in self.pages:raise ValueError('overlapping physical segments')
                self.pages[pa+k]=bytearray(data[offset+k:offset+k+PAGE])
    def read(self,pa,size):
        out=bytearray()
        while size:
            n=min(size,PAGE-(pa&4095));out+=self.pages.get(pa&~4095,bytes(PAGE))[pa&4095:(pa&4095)+n]
            pa+=n;size-=n
        return bytes(out)
    def word(self,pa):return struct.unpack('<I',self.read(pa,4))[0]
    def write_word(self,pa,word):struct.pack_into('<I',self.pages[pa&~4095],pa&4095,word)
    def leaf(self,root,va):
        table=root
        for shift in (39,30,21):
            d,=struct.unpack('<Q',self.read(table+8*(va>>shift&511),8))
            if d&3!=3:raise ValueError('expected existing monitor page tables')
            table=d&MASK
        address=table+8*(va>>12&511)
        d,=struct.unpack('<Q',self.read(address,8))
        if d&3!=3:raise ValueError('expected existing monitor leaf')
        return address,d
    def map_alias(self,root,va,pa):
        address,old=self.leaf(root,va)
        # EL1 RW, EL0 inaccessible, PXN/UXN; use the monitor's memory type.
        attrs=(old&~MASK)&~((1<<6)|(1<<7));attrs|=(1<<53)|(1<<54)
        struct.pack_into('<Q',self.pages[address&~4095],address&4095,pa|attrs)
    def segments(self):
        segments=[];start=None;run=bytearray()
        for pa,page in sorted(self.pages.items()):
            if start is not None and pa!=start+len(run):segments.append((start,bytes(run)));run=bytearray()
            if not run:start=pa
            run+=page
        if run:segments.append((start,bytes(run)))
        return segments


def export(image,oracle,out):
    image,oracle,out=map(lambda p:Path(p).resolve(),(image,oracle,out))
    m=json.loads((image/'manifest.json').read_text());raw=(image/'image.elf').read_bytes()
    if m.get('execution')!='el0-minios' or not m.get('lowered') or m.get('branch_sites'):
        raise ValueError('requires a validated lowered EL0 image with trap dispatch')
    if hashlib.sha256(raw).hexdigest()!=m['image_sha256']:raise ValueError('source image hash mismatch')
    calls=json.loads((oracle/'calls.json').read_text())
    observed=calls.get('source_image_sha256')
    if not observed:
        source=Path(calls['image'])/'manifest.json'
        observed=json.loads(source.read_text())['image_sha256']
    if observed!=m['image_sha256']:raise ValueError('oracle belongs to another image')
    if calls['end'].get('stop_code')!=1 or calls['end'].get('function')!='kernel_power_off+0x0':
        raise ValueError('oracle did not reach kernel_power_off')
    expected,count=expected_events(calls['calls']);counters=(oracle/'counters.bin').read_bytes()
    if len(counters)%24 or len(counters)//24!=calls.get('counter_reads'):raise ValueError('invalid timer inputs')
    for pc,key,value in struct.iter_unpack('<3Q',counters):
        if pc%4 or key not in (0xdf01,0xdf02):raise ValueError('unsupported timer read')
    memory=Memory(raw);sites={pc:(word,kind) for pc,word,kind in struct.iter_unpack('<QII',(image/'sites.bin').read_bytes())}
    kernel,sections=text_ranges(m['vmlinux'])
    physical={int(p['original_va'],16):int(p['pa'],16) for p in m['pages'] if p['kind']=='text'}
    clock_sites={}
    for lo,hi in instruction_ranges(kernel,sections):
        for pc in range(lo,hi,4):
            page=physical.get(pc&~4095)
            if page is None:continue
            at=page+(pc&4095);word=memory.word(at)
            if word&0xfff00000==0xd5300000 and (word>>5&65535) in (0xdf01,0xdf02):
                lower=pc&((1<<48)-1);sites[lower]=(word,0);clock_sites[lower]=(word>>5)&65535
                memory.write_word(at,BRK_SITE)
    if any(clock_sites.get(pc)!=key for pc,key,value in struct.iter_unpack('<3Q',counters)):
        raise ValueError('timer input does not identify a counter instruction')
    hook_original=result_point(m['vmlinux']);hook=hook_original&((1<<48)-1)
    def text_word(pc):
        page=physical.get(pc&~4095)
        if page is None:raise ValueError('result hook is not captured kernel text')
        return page+(pc&4095)
    hook_pa,post_pa=text_word(hook_original),text_word(hook_original+4)
    hook_word,post_word=memory.word(hook_pa),memory.word(post_pa)
    if hook_word&0xfc000000!=0x94000000:raise ValueError('result observation must replace a BL')
    monitor_va=int(m['monitor_va'],16);alias=monitor_va+MONITOR_SIZE-2*PAGE
    for name in ('ttbr1','ttbr1_user'):
        root=int(m[name],16)
        memory.map_alias(root,alias,hook_pa&~4095);memory.map_alias(root,alias+PAGE,post_pa&~4095)
    devices=[p for p in m['pages'] if p['kind']=='device']
    if not devices or any(int(p['pa'],16)!=0x9000000 for p in devices):raise ValueError('only PL011 UART is admitted')
    out.mkdir(parents=True,exist_ok=False)
    for name in ('shadow.bin','fp.bin','monitor.ld'):(out/name).write_bytes((image/name).read_bytes())
    (out/'sites.bin').write_bytes(b''.join(struct.pack('<QII',pc,word,kind) for pc,(word,kind) in sorted(sites.items())))
    (out/'expected.bin').write_bytes(expected);(out/'counters.bin').write_bytes(counters)
    data=(image/'data.S').read_text().replace(str(image),str(out))
    data,n=re.subn(r'(osrec_site_count:\n\s*\.quad )0x[0-9a-f]+',lambda match:match[1]+hex(len(sites)),data)
    if n!=1:raise ValueError('cannot locate monitor site-count declaration')
    config=[hook,hook_word,post_word,alias,int(calls['end']['pc'],0),1,count,len(counters)//24,count+1024]
    data+='\n.section .rodata,"a"\n.balign 16\n.global osrec_checkpoint_config\nosrec_checkpoint_config:\n'
    data+=''.join('    .quad 0x%x\n'%v for v in config)
    for symbol,filename in [('osrec_checkpoint_expected','expected.bin'),('osrec_checkpoint_counters','counters.bin')]:
        data+='\n.balign 16\n.global %s\n%s:\n    .incbin "%s"\n'%(symbol,symbol,out/filename)
    data+='\n.section .bss,"aw",@nobits\n.balign 16\n.global osrec_checkpoint_events\nosrec_checkpoint_events:\n    .space %d\n'%((count+1024)*80)
    (out/'data.S').write_text(data)
    runtime=ROOT/'runtime/el0'
    command=[str(LLVM/'clang'),'--target=aarch64-none-elf','-mcpu=cortex-a53','-O2','-g','-mgeneral-regs-only',
             '-Wall','-Wextra','-Werror','-ffreestanding','-fno-stack-protector','-fno-builtin','-nostdlib','-static','-fuse-ld=lld',
             '-DOSREC_LOWERED','-DOSREC_CHECKPOINT','-Wl,-T,'+str(out/'monitor.ld'),'-Wl,--build-id=none',
             '-Wl,-Map,'+str(out/'monitor.map')]
    command+=list(map(str,[runtime/'minios.S',runtime/'minios.c',runtime/'emulate.c',runtime/'lower.c',
                           runtime/'lower_mmu.c',runtime/'checkpoint.c',out/'data.S']))
    subprocess.run(command+['-o',str(out/'monitor.elf')],check=True)
    monitor=Elf(out/'monitor.elf');symbols={s['name']:s['value'] for s in monitor.symbols if s['shndx']}
    if symbols['osrec_monitor_end']>alias:raise ValueError('monitor overlaps its private hook-write aliases')
    audit=audit_monitor(out/'monitor.elf')
    subprocess.run([str(LLVM/'llvm-objcopy'),'-O','binary',str(out/'monitor.elf'),str(out/'monitor.bin')],check=True)
    # Explicit monitor BSS in the load image; captured zero holes are specified
    # by the load plan's initial zero-fill requirement for the whole RAM bank.
    code=(out/'monitor.bin').read_bytes();code+=bytes((symbols['osrec_monitor_end']-monitor_va+4095)//4096*4096-len(code))
    memory.pages={pa:page for pa,page in memory.pages.items() if not MONITOR_PA<=pa<MONITOR_PA+MONITOR_SIZE}
    for k in range(0,len(code),PAGE):memory.pages[MONITOR_PA+k]=bytearray(code[k:k+PAGE])
    for pa in memory.pages:
        if not 0x40000000<=pa<0x80000000:raise ValueError('image exceeds the declared physical RAM bank')
    (out/'image.elf').write_bytes(physical_elf(memory.segments(),MONITOR_PA))
    # Keep the UART expectation out of execution: validation observes the actual
    # device's emitted bytes. No 209-entry MMIO transcript is linked into RAM.
    mmio=(oracle/'mmio.bin').read_bytes()
    if len(mmio)%40:raise ValueError('truncated UART observation')
    uart=bytes(v&255 for pc,a,size,write,v in struct.iter_unpack('<5Q',mmio)
               if write and any(a==int(d['va'],16) for d in devices))
    if not uart:raise ValueError('missing UART output observation')
    (out/'expected-uart.bin').write_bytes(uart)
    manifest=dict(format='osrec-monitor-checkpoint-v1',source_image_sha256=m['image_sha256'],
                  image_sha256=hashlib.sha256((out/'image.elf').read_bytes()).hexdigest(),
                  image_bytes=(out/'image.elf').stat().st_size,execution='el0-under-el1-monitor',
                  runtime_host_calls=False,libc=False,semihosting=False,monitor_audit=audit,
                  entry=hex(MONITOR_PA),stop=hex(symbols['osrec_stopped']),
                  ram=[dict(address=0x40000000,bytes=1<<30)],
                  initialization='zero the entire RAM bank, then load every ELF PT_LOAD at its physical address',
                  entry_requirements=dict(exception_level=1,mmu_enabled=False,interrupts_masked=True,cpu='cortex-a53 contract'),
                  hardware=dict(uart=dict(kind='PL011',physical_address='0x9000000',bytes=4096),
                                timer=dict(mode='linked ordered counter inputs',reads=len(counters)//24,interrupts=False),
                                other_devices=False),
                  result=dict(physical_address=hex(symbols['osrec_checkpoint_result']-monitor_va+MONITOR_PA),bytes=128,
                              status=dict(running=0,passed=1,failed=2)),
                  trace=dict(physical_address=hex(symbols['osrec_checkpoint_events']-monitor_va+MONITOR_PA),stride=80,capacity=count+1024),
                  expected_events=count,timer_sites=len(clock_sites),
                  stop_pc=calls['end']['pc'],stop_reason=1,uart_bytes=len(uart),
                  monitor_sha256=hashlib.sha256((out/'monitor.elf').read_bytes()).hexdigest(),
                  checks='event results, exact boundary and full timer input consumption in RAM; UART checked by the model harness',
                  measurement=dict(start_pc=hex(struct.unpack('<Q',monitor.read(symbols['osrec_start_context']+256,8))[0]),
                                   start_el=0,end_pc=hex(symbols['osrec_platform_stop']),
                                   scope='transformed user/kernel workload plus monitor overhead; exclude startup and post-stop verification',
                                   microarchitectural_state='not captured; model cache/TLB initialization must be declared'),
                  rtl_execution_verified=False)
    (out/'load-plan.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('image','oracle','out'):p.add_argument('--'+name,required=True)
    a=p.parse_args();m=export(a.image,a.oracle,a.out)
    print(json.dumps({k:m[k] for k in ('image_bytes','entry','result','expected_events','hardware')},indent=2))
