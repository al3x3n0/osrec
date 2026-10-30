"""ELF-derived physical loading contract; no fixed target memory addresses."""
import struct
from pathlib import Path
from klee_liteos import ROOT

def describe(image):
    raw=Path(image).read_bytes()
    if raw[:4]!=b'\x7fELF' or raw[5:6]!=b'\x01' or raw[4] not in (1,2):
        raise ValueError('expected little-endian ELF executable')
    wide=raw[4]==2
    if len(raw)<(64 if wide else 52):raise ValueError('truncated ELF header')
    kind,machine=struct.unpack_from('<HH',raw,16)
    if kind!=2 or machine!=(183 if wide else 40):raise ValueError('expected ARM/AArch64 executable')
    entry,phoff,shoff=struct.unpack_from('<QQQ' if wide else '<III',raw,24)
    phsize,phcount,shsize,shcount=struct.unpack_from('<HHHH',raw,54 if wide else 42)
    if phsize!=(56 if wide else 32) or phoff+phcount*phsize>len(raw):raise ValueError('invalid ELF program header table')
    if shsize!=(64 if wide else 40) or shoff+shcount*shsize>len(raw):raise ValueError('invalid ELF section header table')
    if entry%4:raise ValueError('ELF entry requires instruction alignment')
    segments=[]
    for i in range(phcount):
        fields=struct.unpack_from('<IIQQQQQQ' if wide else '<8I',raw,phoff+i*phsize)
        if wide:typ,flags,offset,virtual,physical,size,mem,align=fields
        else:typ,offset,virtual,physical,size,mem,flags,align=fields
        if typ in (2,3):raise ValueError('image contains a dynamic loader dependency')
        if typ!=1:continue
        if size>mem or offset+size>len(raw) or physical+mem>1<<(64 if wide else 32):raise ValueError('invalid ELF segment bounds')
        if virtual!=physical:raise ValueError('MMU-off image requires matching virtual and physical addresses')
        if any(physical<s['address']+s['memory_bytes'] and s['address']<physical+mem for s in segments):
            raise ValueError('overlapping ELF load segments')
        segments.append({'address':physical,'file_offset':offset,'file_bytes':size,'memory_bytes':mem,'flags':flags})
    if not any(s['flags']&1 and s['address']<=entry<s['address']+s['file_bytes'] for s in segments):
        raise ValueError('ELF entry is outside executable segment')
    sections=[struct.unpack_from('<IIQQQQIIQQ' if wide else '<10I',raw,shoff+i*shsize) for i in range(shcount)]
    result=None;symbols={}
    for section in sections:
        if section[1]!=2:continue
        if section[6]>=len(sections) or section[9]!=(24 if wide else 16) or section[5]%section[9] or section[4]+section[5]>len(raw):raise ValueError('invalid ELF symbol table')
        strings=sections[section[6]]
        if strings[1]!=3 or strings[4]+strings[5]>len(raw):raise ValueError('invalid ELF symbol strings')
        table=raw[strings[4]:strings[4]+strings[5]]
        for pos in range(section[4],section[4]+section[5],section[9]):
            if wide:name,info,other,index,value,size=struct.unpack_from('<IBBHQQ',raw,pos)
            else:name,value,size,info,other,index=struct.unpack_from('<IIIBBH',raw,pos)
            if name>=len(table):raise ValueError('invalid ELF symbol name')
            symbol=table[name:].split(b'\0',1)[0]
            if index and symbol in (b'osrec_result',b'__stack_bottom',b'__stack_top',b'__bss_start',b'__bss_end'):
                if symbol in symbols and symbols[symbol]!=(value,size):raise ValueError('conflicting ELF startup symbols')
                symbols[symbol]=(value,size)
            if symbol==b'osrec_result' and index:result=(value,size)
    from entry_state_result import MAX_CALLS,LEGACY_CALLS,HEADER_BYTES,RECORD_BYTES
    if result is None or not (result[1]==HEADER_BYTES or
        HEADER_BYTES+RECORD_BYTES*(LEGACY_CALLS+1)<=result[1]<=HEADER_BYTES+RECORD_BYTES*MAX_CALLS and
        (result[1]-HEADER_BYTES)%RECORD_BYTES==0):raise ValueError('ELF must declare a bounded osrec_result symbol')
    if not any(s['flags']&2 and s['address']<=result[0] and result[0]+result[1]<=s['address']+s['memory_bytes'] for s in segments):
        raise ValueError('result record is outside writable ELF segment')
    try:
        top=symbols[b'__stack_top'][0];bottom=symbols.get(b'__stack_bottom',(top-16384,0))[0]
        bss_start=symbols[b'__bss_start'][0];bss_end=symbols[b'__bss_end'][0]
    except KeyError as error:raise ValueError('ELF is missing replay startup memory symbols') from error
    if top-bottom!=16384 or top%16 or bottom%16:raise ValueError('invalid replay stack range/alignment')
    step=8 if wide else 4
    if bss_start%step or bss_end%step or not bss_start<=bottom<top<=bss_end:raise ValueError('invalid startup BSS clearing range')
    from image_memory import require_coverage
    writable=[{'address':s['address'],'bytes':s['memory_bytes']} for s in segments if s['flags']&2 and s['memory_bytes']]
    require_coverage([{'address':bottom,'bytes':top-bottom,'purpose':'stack'}],writable)
    owners=[s['address']+s['memory_bytes'] for s in segments if s['flags']&2 and s['address']<=bss_start<=s['address']+s['memory_bytes']]
    if not owners:raise ValueError('startup BSS is outside writable ELF segments')
    writable_end=max(owners);alignment=16 if wide else 4
    if bss_end>(writable_end+alignment-1)//alignment*alignment:raise ValueError('startup BSS clearing exceeds writable segment and alignment padding')
    tail=max(0,bss_end-writable_end)
    return {'isa':'AArch64' if wide else 'ARMv7-A A32','entry':entry,'load_segments':segments,
            'result_address':result[0],'result_bytes':result[1],
            'raw_image_load_address':min(s['address'] for s in segments if s['file_bytes']),
            'stack_range':{'address':bottom,'bytes':top-bottom},
            'startup_zero_range':{'address':bss_start,'bytes':bss_end-bss_start},
            'startup_zero_tail_bytes':tail}

def add_target_arguments(parser):
    parser.add_argument('--arch',choices=('aarch64','armv7'),default='aarch64')
    parser.add_argument('--entry-address',type=lambda v:int(v,0),default=0x40200000)
    parser.add_argument('--result-address',type=lambda v:int(v,0),default=0x40180000)

MMU_MODES=(None,'identity')
MMU_TEXT='.text : { KEEP(*(.text.boot)) *(.text*) }'

def prepare_target(args,sources,mmu=None):
    """Startup code and linker script. `mmu='identity'` (AArch64) starts with start_mmu.S, which
    maps RAM as Normal memory before the replay; .text, which then also holds Linux's exception
    entry sections, is page-aligned for its read-only pages."""
    arch=getattr(args,'arch','aarch64')
    if mmu not in MMU_MODES or (mmu and arch!='aarch64'):raise ValueError('unsupported target MMU mode')
    target=ROOT/'integrations'/('rtl_aarch64' if arch=='aarch64' else 'rtl_armv7')
    (sources/'start.S').write_bytes((target/('start_mmu.S' if mmu else 'start.S')).read_bytes())
    linker=(target/'image.ld').read_text()
    linker=linker.replace('0x40010000',hex(getattr(args,'entry_address',0x40200000 if arch=='aarch64' else 0x40010000)))
    linker=linker.replace('0x40000000',hex(getattr(args,'result_address',0x40180000 if arch=='aarch64' else 0x40000000)))
    if mmu:
        if linker.count(MMU_TEXT)!=1:raise ValueError('linker script lacks the reviewed .text rule')
        linker=linker.replace(MMU_TEXT,'.text : { __text_start = .; KEEP(*(.text.boot)) *(.text*) *(.entry.text) *(.entry.tramp.text) . = ALIGN(4096); __text_end = .; }\n'
            '  ASSERT(__text_start % 4096 == 0, "identity-mapped text must start on a page")\n'
            '  ASSERT((__text_end - 1) / 0x200000 - __text_start / 0x200000 < 4, "text exceeds the level-3 tables of start_mmu.S")\n'
            '  ASSERT(__text_end <= 0x80000000, "text is outside the identity-mapped RAM")')
    (sources/'image.ld').write_text(linker)
    return (['--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align'] if arch=='aarch64'
            else ['--target=arm-none-eabi','-mcpu=cortex-a7','-marm','-mfloat-abi=soft'])

def target_metadata(inspection,version,mmu=None):
    from image_memory import memory_contract
    return {key:inspection[key] for key in ('isa','entry','load_segments','result_address','result_bytes','raw_image_load_address')} | {
        'endianness':'little','result_abi_version':version,'stack_bytes':16384,
        'privileged_start':True,'initial_exception_level':1 if inspection['isa']=='AArch64' else None,
        'mmu_enabled':bool(mmu),'interrupts_enabled':False,'memory_contract':memory_contract(inspection)}|(
        {'mmu':{'mode':mmu,'enabled_by':'start code, after clearing .bss','ram':'Normal Non-cacheable','text':'read-only, executable at EL1 and EL0','caches':False}} if mmu else {})
