"""Static admission audit for the complete, self-contained EL0 executor."""
import hashlib
import struct
from kernel_source_verify import Elf
from source_image_el0 import instruction_ranges


def audit(binary):
    image=Elf(binary);data=image.data
    if struct.unpack_from('<HH',data,16)!=(2,183):raise ValueError('requires an arm64 ET_EXEC')
    symbols={s['name']:s for s in image.symbols if s['shndx']}
    if any(s['name'] and not s['shndx'] for s in image.symbols):raise ValueError('unresolved image dependency')
    if any(s['type']==6 for s in image.symbols):raise ValueError('TLS dependency')
    phoff,=struct.unpack_from('<Q',data,32);stride,count=struct.unpack_from('<HH',data,54)
    loads=[]
    for i in range(count):
        kind,flags,off,va,pa,size,mem,align=struct.unpack_from('<IIQQQQQQ',data,phoff+i*stride)
        if kind in (2,3,7):raise ValueError('dynamic loader or TLS dependency')
        if kind==1:
            if va!=pa or off+size>len(data) or size>mem:raise ValueError('invalid flat ELF load')
            loads.append(dict(address=va,file_offset=off,file_bytes=size,memory_bytes=mem,flags=flags))
    entry,=struct.unpack_from('<Q',data,24)
    if entry!=symbols['_start']['value']:raise ValueError('incorrect entry')
    end=symbols['flat_completed']['value'];exit_pc=end+4
    if struct.unpack('<I',image.read(end,4))[0]!=0xd2800ba8:raise ValueError('terminal exit must select syscall 93')
    ranges=[(s['addr'],s['addr']+s['size']) for s in image.sections if s['flags']&4 and s['size']]
    if max(hi for lo,hi in ranges)-min(lo for lo,hi in ranges)>=1<<27:
        raise ValueError('code span permits branch veneers that could clobber guest registers')
    allowed={0xda10,0xda20,0xda21};exit_sites=[];system=[];instructions=0
    for lo,hi in instruction_ranges(image,ranges):
        for pc in range(lo,hi,4):
            word,=struct.unpack('<I',image.read(pc,4));instructions+=1
            trap=word&0xffe0001f
            if trap in (0xd4000001,0xd4000002,0xd4000003,0xd4200000,0xd4400000):
                if word!=0xd4000001 or pc!=exit_pc:raise ValueError('unexpected trap/service instruction at '+hex(pc))
                exit_sites.append(pc)
            if word&0xffff0000==0xd69f0000:raise ValueError('privileged exception return')
            if word&0xff000000!=0xd5000000:continue
            family=word&0xfff00000
            if family in (0xd5300000,0xd5100000):
                key=word>>5&65535
                if key not in allowed:raise ValueError('privileged/non-RAM system register at '+hex(pc))
                system.append(key)
            elif word not in (0xd503201f,0xd503203f,0xd503229f,0xd503241f,0xd503245f,0xd503249f,0xd50324df) and\
                 word&0xfffff0ff not in (0xd50330bf,0xd503309f,0xd50330df,0xd503305f):
                raise ValueError('unsupported system instruction at '+hex(pc))
    if exit_sites!=[exit_pc]:raise ValueError('exactly one terminal exit required')
    result=symbols['flat_full_result']
    return dict(image_sha256=hashlib.sha256(data).hexdigest(),image_bytes=len(data),entry=hex(entry),terminal_pc=hex(end),
                result_address=hex(result['value']),result_bytes=result['size'],
                load_segments=loads,runtime_el=0,libc=False,tls=False,undefined_symbols=0,
                instructions= instructions,terminal_exit_sites=[hex(exit_pc)],
                memory_backend='hardware-kernel' if 'flat_direct_read' in symbols else 'software',
                system_registers=sorted(set(map(hex,system))),exclusive_sequence_intact=None,
                real_mmio=False,host_signals=False)
