#!/usr/bin/env python3
"""Link a complete, self-verifying arm64 Linux checkpoint into one executable.

Generation needs an accepted native package and independent QEMU recording.
Runtime uses only linked assets. Nonzero RAM pages are packed into sorted
extents, preserving zero holes without embedding the logical RAM file's size.
"""
import argparse
import errno
import hashlib
import json
import mmap
import os
from pathlib import Path
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[1]
HOST_BASE=0x600000000000
MASK64=(1<<64)-1
PAGE=4096


def sparse_runs(file,size):
    """Yield nonzero page runs; SEEK_DATA is an optimization, never a contract."""
    if size%PAGE:raise ValueError('physical store must contain complete pages')
    allocated=[]
    try:
        at=0
        while at<size:
            try:start=os.lseek(file.fileno(),at,os.SEEK_DATA)
            except OSError as error:
                if error.errno==errno.ENXIO:break
                raise
            end=os.lseek(file.fileno(),start,os.SEEK_HOLE)
            if end<=start or end>size:raise ValueError('invalid filesystem sparse extent')
            allocated.append((start//PAGE*PAGE,min(size,(end+PAGE-1)//PAGE*PAGE)))
            at=end
    except (AttributeError,OSError):allocated=[(0,size)]
    # Merge rounded filesystem ranges before scanning; no page is stored twice.
    merged=[]
    for lo,hi in allocated:
        if merged and lo<=merged[-1][1]:merged[-1]=(merged[-1][0],max(hi,merged[-1][1]))
        else:merged.append((lo,hi))
    zero=bytes(PAGE);start=None;end=None
    with mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ) as memory:
        for lo,hi in merged:
            for at in range(lo,hi,PAGE):
                if memory[at:at+PAGE]==zero:continue
                if end==at:end+=PAGE
                else:
                    if start is not None:yield start,end
                    start,end=at,at+PAGE
        if start is not None:yield start,end


def expected_events(calls):
    rows=[];previous=None
    for call in calls:
        exception=bool(call.get('event'))
        if exception and previous and previous.get('event') and previous['arguments']==call['arguments']:continue
        args=call['arguments'];length=3 if exception else 6
        if len(args)!=length:raise ValueError('invalid oracle argument count')
        result=call['result'];completed=result is not None
        row=[int(exception),int(call['number'])&MASK64,*[int(v)&MASK64 for v in args],*[0]*(6-length),
             int(result)&MASK64 if completed else 0,int(completed)]
        rows.append(struct.pack('<10Q',*row));previous=call
    if not rows or len(rows)>998976:raise ValueError('oracle event count exceeds checkpoint trace bounds')
    return b''.join(rows),len(rows)


def export(package,oracle,out):
    package,oracle,out=map(lambda p:Path(p).resolve(),(package,oracle,out))
    source=json.loads((package/'manifest.json').read_text())
    observed=json.loads((oracle/'calls.json').read_text())
    if not source.get('application'):raise ValueError('whole-application package required')
    image=observed.get('image');observed_sha=observed.get('source_image_sha256')
    if not observed_sha and image:
        candidates=[Path(image)/'manifest.json',ROOT/'build'/Path(image).name/'manifest.json']
        found=next((path for path in candidates if path.is_file()),None)
        if found:observed_sha=json.loads(found.read_text())['image_sha256']
    if observed_sha!=source['source_image_sha256']:
        raise ValueError('oracle and package image identities differ')
    end=observed['end']
    if end.get('stop_code')!=1 or end.get('function')!='kernel_power_off+0x0':
        raise ValueError('oracle must finish at the declared kernel_power_off boundary')
    stop_pc=int(end['pc'],0)
    if stop_pc<0 or stop_pc>MASK64 or stop_pc%4:raise ValueError('invalid completion PC')
    expected,count=expected_events(observed['calls'])
    native=(package/'native.bin').read_bytes()
    if len(native)<80:raise ValueError('truncated native header')
    header=struct.unpack_from('<10Q',native)
    if header[0]!=0x3145564954414e4c or header[1]!=1:raise ValueError('unsupported native package header')
    size=(package/'memory.bin').stat().st_size
    if size!=header[3] or size!=source['memory_size']:raise ValueError('physical store size mismatch')
    assets={name:(package/(name+'.bin')).read_bytes() for name in ('application','vma')}
    assets.update(native=native,counters=(oracle/'counters.bin').read_bytes(),mmio=(oracle/'mmio.bin').read_bytes(),expected=expected)
    if len(assets['counters'])%24 or len(assets['mmio'])%40:raise ValueError('truncated hardware transcript')
    if observed.get('counter_reads')!=len(assets['counters'])//24 or observed.get('mmio_accesses')!=len(assets['mmio'])//40:
        raise ValueError('oracle hardware event counts differ from their transcripts')
    out.mkdir(parents=True,exist_ok=False)
    positions={};extents=[];stored=0
    with (out/'payload.bin').open('wb') as payload:
        def append(name,data):
            payload.write(bytes(-payload.tell()%16));positions[name]=(payload.tell(),len(data));payload.write(data)
        for name,data in assets.items():append(name,data)
        memory_hash=hashlib.sha256()
        with (package/'memory.bin').open('rb') as memory:
            for lo,hi in sparse_runs(memory,size):
                payload.write(bytes(-payload.tell()%16));offset=payload.tell()
                memory.seek(lo);left=hi-lo
                while left:
                    chunk=memory.read(min(left,1<<20))
                    if not chunk:raise ValueError('physical store changed while packing')
                    payload.write(chunk);memory_hash.update(chunk);left-=len(chunk)
                extents.append((lo,hi-lo,offset));stored+=hi-lo
        provenance=dict(format='osrec-native-executable-v1',target='aarch64-linux',link='static',host_base=hex(HOST_BASE),
                        source_image_sha256=source['source_image_sha256'],application=source['application'],
                        memory_size=size,stored_memory_bytes=stored,extent_count=len(extents),
                        memory_data_sha256=memory_hash.hexdigest(),extents=[[lo,length] for lo,length,_ in extents],
                        asset_sha256={name:hashlib.sha256(data).hexdigest() for name,data in assets.items()},
                        events=count,counter_reads=len(assets['counters'])//24,mmio_accesses=len(assets['mmio'])//40,
                        stop_pc=hex(stop_pc),stop_reason=1,
                        runtime='native user and captured-kernel code; recorded architecture inputs; linked acceptance checks')
        identity=hashlib.sha256(json.dumps(provenance,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        provenance['identity']=identity
        append('provenance',(json.dumps(provenance,indent=2)+'\n').encode())
    (out/'image.S').write_text('.section .rodata.osrec_checkpoint,"a",%progbits\n.balign 16\n.global osrec_checkpoint_payload\nosrec_checkpoint_payload:\n.incbin "payload.bin"\n.section .note.GNU-stack,"",%progbits\n')
    def blob(name):
        offset,length=positions[name];return '{osrec_checkpoint_payload+%d,%d}'%(offset,length)
    lines=['#include "linuxkernel_embedded.h"','extern const unsigned char osrec_checkpoint_payload[];',
           'static const struct lk_el0_extent extents[] = {']
    lines+=['    {%d,{osrec_checkpoint_payload+%d,%d}},'%(lo,offset,length) for lo,length,offset in extents]
    if not extents:lines.append('    {0,{0,0}},')
    lines+=['};','const struct checkpoint_bundle osrec_checkpoint = {','    .image = { .abi=LK_EL0_IMAGE_ABI,',
            '        .native=%s, .application=%s, .vma=%s,'%(blob('native'),blob('application'),blob('vma')),
            '        .memory_size=%d, .extents=extents, .extent_count=%d,'%(size,len(extents)),
            '        .counters=%s, .mmio=%s },'%(blob('counters'),blob('mmio')),
            '    .expected=(const struct checkpoint_expected_event *)(osrec_checkpoint_payload+%d),'%positions['expected'][0],
            '    .event_count=%d, .stop_pc=0x%xull, .stop_reason=1,'%(count,stop_pc),
            '    .provenance=%s, .identity="%s"'%(blob('provenance'),identity),'};','']
    (out/'image.c').write_text('\n'.join(lines))
    report=dict(provenance,payload_size=(out/'payload.bin').stat().st_size,
                payload_sha256=hashlib.sha256((out/'payload.bin').read_bytes()).hexdigest(),asset_offsets=positions)
    (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def verify_elf(path):
    data=Path(path).read_bytes()
    if data[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<HH',data,16)!=(2,183):
        raise ValueError('checkpoint must be an arm64 little-endian ET_EXEC')
    phoff,=struct.unpack_from('<Q',data,32);stride,count=struct.unpack_from('<HH',data,54)
    for i in range(count):
        kind,flags,offset,va,pa,size,memsize,align=struct.unpack_from('<IIQQQQQQ',data,phoff+i*stride)
        if kind in (2,3):raise ValueError('checkpoint unexpectedly requires dynamic linking')
        if kind==1 and not HOST_BASE<=va<=va+memsize<=HOST_BASE+(1<<32):
            raise ValueError('host ELF is outside its separate address window')
    return dict(executable_size=len(data),executable_sha256=hashlib.sha256(data).hexdigest(),static=True)


def verify_standalone(path):
    """Audit the libc-free build, including every linker input, not just DT_NEEDED.

    A static libc executable also has no imports: the link map must show only
    our explicit objects, and the ELF must enter our own startup without TLS.
    The map is a build-time audit artifact, not a runtime dependency.
    """
    from kernel_source_verify import Elf
    path=Path(path);report=verify_elf(path);elf=Elf(path)
    phoff,=struct.unpack_from('<Q',elf.data,32);stride,count=struct.unpack_from('<HH',elf.data,54)
    for i in range(count):
        if struct.unpack_from('<I',elf.data,phoff+i*stride)[0]==7:raise ValueError('standalone executor has TLS')
    if any(s['name'] and not s['shndx'] for s in elf.symbols):raise ValueError('standalone executor has undefined symbols')
    if any(s['type']==6 for s in elf.symbols):raise ValueError('standalone executor has TLS symbols')
    entry,=struct.unpack_from('<Q',elf.data,24)
    start=[s for s in elf.symbols if s['name']=='_start' and s['value']==entry]
    if len(start)!=1:raise ValueError('standalone executor does not enter its own startup')
    required={'lk_host_start','lk_host_sigreturn','lk_syscall6','lk_setjmp','lk_longjmp'}
    if not required.issubset({s['name'] for s in elf.symbols if s['shndx']}):raise ValueError('standalone host edge is missing')
    link_map=path.with_name(path.name+'.map').read_text()
    inputs=[line[5:].strip() for line in link_map.splitlines() if line.startswith('LOAD ') and line!='LOAD linker stubs']
    expected={'entry.o','emulate.o','lower.o','native.o','veneer.o','standalone.o','standalone_start.o'}
    generated={'checkpoint-main.o','image-descriptor.o','image-payload.o'}
    objects=[]
    for name in inputs:
        base=Path(name).name
        if base in expected and Path(name).parent.name=='standalone':objects.append(base)
        elif base in generated:objects.append(base)
        else:raise ValueError('unexpected standalone linker input: '+name)
    if set(objects)!=expected|generated or len(objects)!=len(expected|generated):
        raise ValueError('incomplete standalone linker input audit')
    report.update(libc=False,crt=False,compiler_runtime=False,tls=False,undefined_symbols=0,
                  entry=hex(entry),linker_inputs=inputs,link_map_sha256=hashlib.sha256(link_map.encode()).hexdigest())
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package',required=True);p.add_argument('--oracle',required=True);p.add_argument('--out',required=True)
    p.add_argument('--build',action='store_true',help='build on arm64 Linux using the native library Makefile')
    p.add_argument('--cc',default='clang-19');p.add_argument('--ar',default='llvm-ar-19')
    a=p.parse_args();report=export(a.package,a.oracle,a.out)
    if a.build:
        subprocess.run(['make','-C',str(ROOT/'runtime/linuxkernel_el0'),'CC='+a.cc,'AR='+a.ar,
                        'IMAGE='+str(Path(a.out).resolve()),'standalone-checkpoint'],check=True)
        report.update(verify_standalone(Path(a.out)/'user-checkpoint'))
        (Path(a.out)/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('identity','memory_size','stored_memory_bytes','payload_size','events','counter_reads','mmio_accesses')},indent=2))
