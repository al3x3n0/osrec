"""Describe transparent entry sites of the captured, statically linked application.

The native loader applies these patches only for whole-application execution.
All ordinary instructions stay native. SVC becomes a single B to a BRK veneer
that changes no registers, flags, stack bytes, or FP/SIMD state before capture.
"""
import hashlib
import json
import mmap
import struct
from pathlib import Path

MAGIC = 0x315050414b4c # LKAPP1


def build(image, package, user_elf):
    from kernel_source_verify import Elf
    from source_image_el0 import instruction_ranges
    from source_image import result_point
    from source_image_calls import branch
    image, package, user_elf = map(Path, (image, package, user_elf))
    m=json.loads((image/'manifest.json').read_text())
    app=Elf(user_elf)
    if struct.unpack_from('<H',app.data,16)[0]!=2:
        raise ValueError('native application currently requires a static ET_EXEC ELF')
    phoff,=struct.unpack_from('<Q',app.data,32)
    stride,count=struct.unpack_from('<HH',app.data,54)
    if any(struct.unpack_from('<I',app.data,phoff+i*stride)[0]==3 for i in range(count)):
        raise ValueError('native application does not yet load an ELF interpreter')
    sections=[(s['addr'],s['addr']+s['size']) for s in app.sections if s['flags']&4 and s['size']]
    if not sections:raise ValueError('application has no executable sections')
    sites=[]
    native=(package/'native.bin').read_bytes();h=struct.unpack_from('<10Q',native)
    root=struct.unpack_from('<Q',native,80+272+520+72)[0]&0x0000fffffffff000
    def physical_word(memory,pc):
        table=root
        bits=64-(h[4]&63);start=3-(bits-13)//9
        for level in range(start,4):
            shift=12+9*(3-level)
            d,=struct.unpack_from('<Q',memory,table-h[2]+8*(pc>>shift&511))
            if not d&1:raise ValueError('application text is not resident at '+hex(pc))
            if level<3 and d&2:table=d&0x0000fffffffff000;continue
            pa=(d&0x0000fffffffff000)&~((1<<shift)-1)
            return struct.unpack_from('<I',memory,pa-h[2]+(pc&((1<<shift)-1)))[0]
        raise ValueError('invalid application translation')
    with (package/'memory.bin').open('rb') as file, mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ) as memory:
        for lo,hi in instruction_ranges(app,sections):
            for pc in range(lo,hi,4):
                if physical_word(memory,pc)!=struct.unpack('<I',app.read(pc,4))[0]:
                    raise ValueError('application ELF differs from captured instruction at '+hex(pc))
    for lo,hi in instruction_ranges(app,sections):
        for pc in range(lo,hi,4):
            word,=struct.unpack('<I',app.read(pc,4))
            if word&0xffe0001f==0xd4000001:kind=0
            elif word&0xfff00000 in (0xd5300000,0xd5100000) and word>>5&65535 in (0xde82,0xde83,0xdf01,0xdf02,0xd807,0xd801):kind=1
            elif word in (0xd503233f,0xd50323bf,0xd503237f,0xd50323ff):kind=2
            else:continue
            sites.append((pc,word,kind))
    if not any(kind==0 for _,_,kind in sites):raise ValueError('no application syscall sites')
    # Put the register-free entry veneers clear of all ELF load sections/BSS,
    # within direct-B range of this static application. Fixed mappings are still
    # checked against host mappings and live guest PTEs by the loader.
    end=max(s['addr']+s['size'] for s in app.sections if s['flags']&2)
    base=(end+(16<<20)-1)&~((16<<20)-1)
    size=(4*len(sites)+4095)&~4095
    rows=[]
    for i,(pc,word,kind) in enumerate(sites):
        target=base+4*i
        if kind==0:branch(pc,target) # range/alignment check
        rows.append(struct.pack('<QIIQ',pc,word,kind,target))
    hook=result_point(m['vmlinux'])&((1<<48)-1)
    e=Elf(m['vmlinux']);word,=struct.unpack('<I',e.read(hook|0xffff000000000000,4))
    if word&0xfc000000!=0x94000000:raise ValueError('syscall observation point must be BL')
    offset=word&0x3ffffff
    if offset&(1<<25):offset-=1<<26
    target=hook+4*offset
    text_lo=min(lo for lo,_ in sections)&~4095
    text_hi=(max(hi for _,hi in sections)+4095)&~4095
    header=struct.pack('<10Q',MAGIC,2,len(sites),base,size,hook,word,target,text_lo,text_hi)
    (package/'application.bin').write_bytes(header+b''.join(rows))
    # Bind the live VMA tree, including regions with no PTE yet. The native
    # process must reserve these holes before application instructions resume.
    from source_image import Ram
    from program_view import Layout,Memory
    from kernel_dwarf_db import load
    lay=Layout(load(Path(m['vmlinux']).parent/'dwarf-db.json.gz'))
    ram=Ram(m['dump']);mem=Memory(ram);kernel=Elf(m['vmlinux'])
    symbols={s['name']:s['value'] for s in kernel.symbols if s['value']}
    task=mem.q(symbols['__entry_task']+ram.sysregs['TPIDR_EL1'])
    mm=mem.q(task+lay.offset('struct:task_struct','mm'))
    moved={int(p['original_va'],16):int(p['va'],16) for p in m['pages']}
    root=moved[mm&~4095]+(mm&4095)+lay.offset('struct:mm_struct','mm_mt.ma_root')
    r_pivot=lay.offset('struct:maple_range_64','pivot')
    vma=struct.pack('<10Q',0x31414d564b4c,1,root,
                    lay.offset('struct:vm_area_struct','vm_start'),lay.offset('struct:vm_area_struct','vm_end'),
                    lay.offset('struct:vm_area_struct','vm_flags'),r_pivot,r_pivot+15*8,
                    lay.offset('struct:maple_arange_64','pivot'),lay.offset('struct:maple_arange_64','slot'))
    (package/'vma.bin').write_bytes(vma)
    report=dict(user_elf_sha256=hashlib.sha256(user_elf.read_bytes()).hexdigest(),
                user_sites=len(sites),syscall_sites=sum(k==0 for _,_,k in sites),
                gateway_base=hex(base),gateway_size=size,result_hook=hex(hook),
                vma_layout_sha256=hashlib.sha256(vma).hexdigest())
    p=package/'manifest.json';manifest=json.loads(p.read_text());manifest['application']=report
    p.write_text(json.dumps(manifest,indent=2)+'\n')
    return report
