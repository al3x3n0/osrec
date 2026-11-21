#!/usr/bin/env python3
"""Prepare a supplied static ELF with libkernel and export one EL0 executable.

The kernel subcommand creates a reusable code/state capsule. Build runs real
captured-kernel execveat during construction, records a native reference, and
uses the existing EL0 AOT exporter. No host loader enters the delivery image.
"""
import argparse,hashlib,json,mmap,platform,shlex,shutil,struct,subprocess,sys,uuid
from pathlib import Path
from export_el0_program import Package,export
from export_native_checkpoint import sparse_runs
from kernel_source_verify import Elf
from source_image_el0 import instruction_ranges
from source_image import result_point

ROOT=Path(__file__).resolve().parents[1]
MASK48=(1<<48)-1
FORMAT='osrec-libkernel-v1'
UART=0x80008000e000

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        while chunk:=f.read(1<<20):h.update(chunk)
    return h.hexdigest()

def write_json(path,value):Path(path).write_text(json.dumps(value,indent=2)+'\n')

def constructor_abi(path):
    image=Elf(path)
    if struct.unpack_from('<HH',image.data,16)!=(2,183):raise ValueError('constructor must be a static AArch64 ET_EXEC')
    entry,phoff=struct.unpack_from('<QQ',image.data,24);stride,count=struct.unpack_from('<HH',image.data,54)
    if stride!=56 or phoff>len(image.data) or count>(len(image.data)-phoff)//stride:
        raise ValueError('invalid constructor program headers')
    if any(struct.unpack_from('<I',image.data,phoff+i*stride)[0] in (2,3) for i in range(count)):
        raise ValueError('constructor must be statically linked')
    marker=next((s for s in image.symbols if s['name']=='osrec_prepare_application_abi' and s['shndx']),None)
    if marker is None:return 1 # legacy prepare/record helper; no Linux baseline capability
    if marker['size']!=8:raise ValueError('invalid constructor ABI marker')
    abi=struct.unpack('<Q',image.read(marker['value'],8))[0]
    if abi not in (1,2):raise ValueError('unsupported constructor ABI')
    return abi

def inspect_user(path):
    data=Path(path).read_bytes()
    if len(data)<64 or len(data)>16<<20 or data[:7]!=b'\x7fELF\x02\x01\x01':
        raise ValueError('requires a little-endian static ELF64, at most 16 MiB')
    if struct.unpack_from('<HH',data,16)!=(2,183):raise ValueError('requires AArch64 ET_EXEC')
    entry,phoff=struct.unpack_from('<QQ',data,24);stride,count=struct.unpack_from('<HH',data,54)
    if stride!=56 or not 0<count<=128 or phoff>len(data) or count>(len(data)-phoff)//stride:
        raise ValueError('invalid ELF program headers')
    segments=[]
    for i in range(count):
        kind,flags,offset,va,pa,size,memory,align=struct.unpack_from('<IIQQQQQQ',data,phoff+i*stride)
        if kind in (2,3):raise ValueError('dynamic loading and ELF interpreters are unsupported')
        if kind!=1:continue
        if size>memory or offset>len(data) or size>len(data)-offset or va>=1<<40 or memory>(1<<40)-va:
            raise ValueError('invalid or out-of-range PT_LOAD; initial ABI uses addresses below 1 TiB')
        if align>1 and (align&(align-1) or offset%align!=va%align):raise ValueError('invalid PT_LOAD alignment')
        if flags&3==3:raise ValueError('writable executable segments are unsupported')
        if memory:segments.append(dict(va=va,bytes=memory,flags=flags,offset=offset,file_bytes=size))
    if entry%4 or not any(s['flags']&1 and s['va']<=entry<s['va']+s['file_bytes'] for s in segments):
        raise ValueError('ELF entry is outside file-backed executable code')
    try:
        elf=Elf(path)
        code=instruction_ranges(elf,[(s['addr'],s['addr']+s['size']) for s in elf.sections if s['flags']&4 and s['size']])
    except (IndexError,KeyError,struct.error,UnicodeError,ValueError) as error:
        raise ValueError('ELF requires valid sections and AArch64 code/data mapping symbols') from error
    if not code:raise ValueError('ELF has no described executable instructions')
    if any(lo%4 or hi%4 or not any(s['flags']&1 and s['va']<=lo<hi<=s['va']+s['file_bytes'] for s in segments) for lo,hi in code):
        raise ValueError('instruction metadata lies outside file-backed executable segments')
    if not any(struct.unpack('<I',elf.read(pc,4))[0]&0xffe0001f==0xd4000001 for lo,hi in code for pc in range(lo,hi,4)):
        raise ValueError('ELF contains no described SVC sites')
    return dict(entry=entry,segments=segments,code=code,sha256=hashlib.sha256(data).hexdigest())

def scalar_count_sites(kernel,package):
    """Review the compiled -MAX_ARG_STRINGS count loops, never pointer constants.

    The original count is zero, decremented by one and compared with the exact
    Linux MAX_ARG_STRINGS limit. Bind to the named function and instruction
    pattern. Any different build retains its conservative lowering boundary.
    """
    f=next((s for s in kernel.symbols if s['name']=='do_execveat_common' and s['shndx']),None)
    if not f:return []
    lo=f['value']&MASK48;sites=[]
    for pc,(word,kind) in package.sites.items():
        if not (lo<=pc<lo+f['size'] and word==0xb26187fb and kind==0x20000000):continue
        read=lambda offset:struct.unpack('<I',kernel.read((pc+offset)|0xffff000000000000,4))[0]
        if read(0)!=word or (read(-8),read(20),read(96))!=(0xaa1f03f8,0xd1000718,0xeb1b031f):continue
        if package.word(pc) not in (0xd421e000,word):raise ValueError('scalar review site differs from captured build')
        sites.append(dict(pc=pc,word=word,reason='fs/exec.c argument count limit -MAX_ARG_STRINGS; zero/decrement/compare pattern'))
    return sites

def scalar_flag_sites(kernel,package):
    """Review do_mmap's scalar unsupported-flags mask, not an address."""
    f=next((s for s in kernel.symbols if s['name']=='do_mmap' and s['shndx']),None)
    if not f:return []
    lo=f['value']&MASK48;sites=[]
    for pc,(word,kind) in package.sites.items():
        if not (lo<=pc<lo+f['size'] and word==0x929f266a and kind==0x20000000):continue
        read=lambda offset:struct.unpack('<I',kernel.read((pc+offset)|0xffff000000000000,4))[0]
        if (read(0),read(4),read(8),read(20),read(28))!=(word,0x92400f2b,0xf2b07e0a,0xb26d014c,0x9a8a0189):continue
        if package.word(pc) not in (0xd421e000,word):raise ValueError('scalar flag-mask review differs from captured build')
        sites.append(dict(pc=pc,word=word,reason='mm/mmap.c unsupported mapping flags; scalar MOVN/MOVK, MAP_TYPE and conditional mask pattern'))
    return sites

def scalar_bitmap_sites(kernel,package):
    """Review the 24-CPU CID bitmap mask followed by first-zero-bit search."""
    f=next((s for s in kernel.symbols if s['name']=='mm_cid_get' and s['shndx']),None)
    if not f:return []
    lo=f['value']&MASK48;sites=[]
    for pc,(word,kind) in package.sites.items():
        if not (lo<=pc<lo+f['size'] and word==0xb2689d08 and kind==0x20000000):continue
        read=lambda offset:struct.unpack('<I',kernel.read((pc+offset)|0xffff000000000000,4))[0]
        # ORR x8,x8,#(~0UL << 24), then invert, test, reverse and count bits.
        if read(0)!=word or read(8)!=0xb100051f:continue
        if (read(4),read(12),read(16)) not in ((0xaa2803e9,0xdac00129,0xdac0112a),(0xaa2803ea,0xdac0014a,0xdac0114a)):continue
        if package.word(pc) not in (0xd421e000,word):raise ValueError('scalar bitmap review differs from captured build')
        sites.append(dict(pc=pc,word=word,reason='kernel/sched CID first-zero-bit search; 24-bit bitmap ORR/MVN/CMN/RBIT/CLZ pattern'))
    return sites

def sparse_copy(source,target):
    size=Path(source).stat().st_size
    with Path(source).open('rb') as src,Path(target).open('xb') as dst:
        dst.truncate(size)
        for lo,hi in sparse_runs(src,size):
            src.seek(lo);dst.seek(lo)
            for _ in range((hi-lo+(1<<20)-1)//(1<<20)):
                chunk=src.read(min(1<<20,hi-src.tell()))
                if not chunk:raise ValueError('truncated physical store')
                dst.write(chunk)

def shared_directory_aliases(package,root):
    """Recover unmoved leaves sharing a directory with relocated vmemmap.

    Moving a whole PGD slot can clear the original slot even when a vmalloc
    fringe still uses it. Retain a child-table alias only when exactly one
    existing directory reproduces every captured PA/permission in that slot.
    This changes the kernel's RAM table view, not the delivery's fixed mappings.
    """
    mask=0x0000fffffffff000;permissions=(1<<6)|(1<<7)|(1<<10)|(1<<53)|(1<<54)
    def q(pa):
        if pa<package.h[2] or pa+8>package.h[2]+package.h[3]:raise ValueError('page table outside captured RAM')
        return struct.unpack_from('<Q',package.memory,pa-package.h[2])[0]
    def walk(directory,va):
        d=directory;parent=0
        for shift in (30,21,12):
            if not d&1 or not d&2:return None
            parent|=d;d=q((d&mask)+8*(va>>shift&511))
            if not d&1:return None
            if shift==12 or not d&2:
                if parent&(1<<59):d|=1<<53
                if parent&(1<<60):d|=1<<54
                if parent&(1<<61):d&=~(1<<6)
                if parent&(1<<62):d|=1<<7
                return ((d&mask)&~((1<<shift)-1))+(va&((1<<shift)-1)),d&permissions
        return None
    expected={}
    for va,pa,size,attrs in package.maps:
        for offset in range(0,size,4096):expected.setdefault((va+offset)>>39&511,[]).append((va+offset,pa+offset,attrs&permissions))
    directories=[q(root+8*i) for i in range(512)];repairs=[]
    for slot,pages in sorted(expected.items()):
        if directories[slot]&1:continue
        matches=[]
        for source,descriptor in enumerate(directories):
            if descriptor&3!=3:continue
            try:same=all(walk(descriptor,va)==(pa,attrs) for va,pa,attrs in pages)
            except ValueError:same=False
            if same:matches.append((source,descriptor))
        descriptors={descriptor for source,descriptor in matches}
        if len(descriptors)==1:
            source,descriptor=matches[0]
            repairs.append(dict(root_pa=root,slot=slot,source_slot=source,descriptor=descriptor,pages=len(pages),
                                reason='retain nonrelocated mappings sharing a moved top-level directory'))
    return repairs

def kernel_capsule(package,vmlinux,dwarf_db,constructor,out,coverage=None,counter_base=None,uart=UART):
    from kernel_dwarf_db import load
    from program_view import Layout
    package,vmlinux,constructor,out=map(lambda p:Path(p).resolve(),(package,vmlinux,constructor,out))
    abi=constructor_abi(constructor)
    p=Package(package);kernel=Elf(vmlinux);symbols={s['name']:s['value'] for s in kernel.symbols if s['shndx']}
    database=load(Path(dwarf_db));lay=Layout(database);tp=struct.unpack_from('<Q',p.shadow,104+8192+0xc684*8)[0]
    offsets=dict(task_slot=(symbols['__entry_task']+tp)&MASK48,task_mm=lay.offset('struct:task_struct','mm'),
                 mm_mt=lay.offset('struct:mm_struct','mm_mt.ma_root'),
                 vma_start=lay.offset('struct:vm_area_struct','vm_start'),vma_end=lay.offset('struct:vm_area_struct','vm_end'),
                 vma_flags=lay.offset('struct:vm_area_struct','vm_flags'),r_pivot=lay.offset('struct:maple_range_64','pivot'),
                 a_pivot=lay.offset('struct:maple_arange_64','pivot'),a_slot=lay.offset('struct:maple_arange_64','slot'))
    if counter_base is None:
        variable=next(v for v in database['variables'] if v[0]=='tk_core' and v[1]==symbols['tk_core'])
        offset=lay.offset(variable[2],'timekeeper.tkr_mono.cycle_last')
        counter_base=struct.unpack_from('<Q',p.memory,p.pa((symbols['tk_core']+offset)&MASK48)-p.h[2])[0]+1024
    reviewed=scalar_count_sites(kernel,p)+scalar_flag_sites(kernel,p)+scalar_bitmap_sites(kernel,p);stop=symbols['do_exit']&MASK48
    mm_pgd=lay.offset('struct:mm_struct','pgd')
    pgd=struct.unpack_from('<Q',p.memory,p.pa((symbols['init_mm']+mm_pgd)&MASK48)-p.h[2])[0]
    aliases=shared_directory_aliases(p,p.pa(pgd))
    out.mkdir(parents=True,exist_ok=False);template=out/'template';template.mkdir()
    (template/'native.bin').write_bytes(p.data);sparse_copy(package/'memory.bin',template/'memory.bin')
    with (template/'memory.bin').open('r+b') as f:
        for site in reviewed:f.seek(p.pa(site['pc'])-p.h[2]);f.write(struct.pack('<I',site['word']))
        for alias in aliases:f.seek(alias['root_pa']+8*alias['slot']-p.h[2]);f.write(struct.pack('<Q',alias['descriptor']))
        f.seek(p.pa(stop)-p.h[2]);f.write(struct.pack('<I',0xd421e020))
    shutil.copyfile(vmlinux,out/'kernel.elf');shutil.copyfile(constructor,out/'prepare-application');(out/'prepare-application').chmod(0o755)
    names=['template/native.bin','template/memory.bin','kernel.elf','prepare-application']
    if coverage:shutil.copyfile(coverage,out/'coverage.log');names.append('coverage.log')
    manifest=dict(format=FORMAT,architecture='aarch64',state_abi=1,constructor_abi=abi,process_layout=offsets,
                  parent_source_image_sha256=json.loads((package/'manifest.json').read_text())['source_image_sha256'],
                  result_hook=result_point(str(vmlinux))&MASK48,stop_pc=stop,termination='captured do_exit entry',
                  hardware=dict(uart_va=uart,counter_base=counter_base,counter_step=1024,mode='deterministic RAM inputs'),
                  reviewed_scalar_sites=reviewed,retained_kernel_table_aliases=aliases,assets={name:digest(out/name) for name in names})
    write_json(out/'libkernel.json',manifest);return manifest

def load_kernel(path):
    path=Path(path).resolve();m=json.loads((path/'libkernel.json').read_text())
    if m.get('format')!=FORMAT or m.get('architecture')!='aarch64' or m.get('constructor_abi') not in (1,2) or m.get('state_abi')!=1:
        raise ValueError('unsupported libkernel capsule')
    def integer(v,limit):return type(v) is int and 0<=v<limit
    layout=m.get('process_layout',{});hardware=m.get('hardware',{})
    offsets=('task_mm','mm_mt','vma_start','vma_end','vma_flags','r_pivot','a_pivot','a_slot')
    if (not integer(layout.get('task_slot'),1<<48) or any(not integer(layout.get(k),1<<20) for k in offsets) or
        any(not integer(m.get(k),1<<48) or m[k]%4 for k in ('result_hook','stop_pc')) or
        any(not integer(hardware.get(k),1<<64) for k in ('counter_base','counter_step','uart_va')) or
        not hardware['counter_step'] or hardware['uart_va']%4096 or
        not isinstance(m.get('parent_source_image_sha256'),str) or len(m['parent_source_image_sha256'])!=64):
        raise ValueError('invalid libkernel process/hardware metadata')
    required={'template/native.bin','template/memory.bin','kernel.elf','prepare-application'}
    if not required<=m.get('assets',{}).keys():raise ValueError('incomplete libkernel capsule')
    for name,sha in m['assets'].items():
        target=(path/name).resolve()
        if not target.is_relative_to(path) or digest(target)!=sha:raise ValueError('libkernel asset identity mismatch: '+name)
    return path,m

def linux_baseline(kernel,user,args,reference,out,expect_exit,timeout=180):
    """Compare program exit/stdout with an unmodified ELF on the Linux host.

    Linux host state differs from captured state. This checks program-visible
    results, not per-syscall or kernel-state equality. Only terminal CRLF is
    normalized, to account for captured TTY output versus the host pipe.
    """
    destination=out/'linux-baseline';destination.mkdir()
    container='osrec-user-baseline-'+uuid.uuid4().hex
    command=['docker','run','--rm','--name',container,'--network','none','--read-only',
             '--mount','type=bind,src='+str(kernel/'prepare-application')+',dst=/runner,readonly',
             '--mount','type=bind,src='+str(user)+',dst=/user,readonly',
             '--mount','type=bind,src='+str(destination)+',dst=/report',
             '--entrypoint','/runner','alpine:3','baseline','/user','/report/process.json',*args]
    try:result=subprocess.run(command,capture_output=True,timeout=timeout)
    except subprocess.TimeoutExpired as error:
        try:cleanup=subprocess.run(['docker','rm','--force',container],capture_output=True,timeout=30)
        except subprocess.TimeoutExpired as cleanup_error:
            raise ValueError('Linux user baseline timed out; container cleanup unconfirmed: '+container) from cleanup_error
        if cleanup.returncode and b'No such container' not in cleanup.stderr:
            raise ValueError('Linux user baseline timed out; container cleanup failed: '+container) from error
        (destination/'stdout.bin').write_bytes(error.stdout or b'');(destination/'stderr.bin').write_bytes(error.stderr or b'')
        raise ValueError('Linux user baseline timed out; its container was stopped') from error
    (destination/'stdout.bin').write_bytes(result.stdout);(destination/'stderr.bin').write_bytes(result.stderr)
    if result.returncode:raise ValueError('Linux user baseline runner failed; see linux-baseline/stderr.bin')
    report=json.loads((destination/'process.json').read_text())
    if report.get('format')!='osrec-linux-user-baseline-v1':raise ValueError('invalid Linux user baseline report')
    console=(reference/'console.txt').read_bytes().replace(b'\r\n',b'\n')
    report.update(stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),user_sha256=digest(user),
                  arguments=['program',*args],environment={},expected_exit=expect_exit,
                  stdout_matches=result.stdout==console,
                  comparison='program exit status and stdout; captured UART CRLF normalized to LF',
                  scope='unmodified user ELF using Linux host syscalls; host process state differs from captured state')
    report['verified']=(report.get('machine')=='aarch64' and report.get('exec_errno')==0 and
                        report.get('signal')==0 and report.get('exit_status')==expect_exit and report['stdout_matches'])
    write_json(destination/'validation.json',report)
    if not report['verified']:raise ValueError('Linux user baseline differs from captured execution: '+json.dumps(report))
    return report

def run_constructor(kernel,arguments,mounts,out,label):
    command=['docker','run','--rm','--network','none','--read-only',
             '--mount','type=bind,src='+str(kernel/'prepare-application')+',dst=/prepare,readonly']
    for source,target,writable in mounts:
        command+=['--mount','type=bind,src='+str(source)+',dst='+target+('' if writable else ',readonly')]
    command+=['--entrypoint','/prepare','alpine:3',*map(str,arguments)]
    result=subprocess.run(command,capture_output=True,text=True,timeout=180)
    (out/(label+'.stdout')).write_text(result.stdout);(out/(label+'.stderr')).write_text(result.stderr)
    if result.returncode:raise ValueError(label+' failed: '+result.stderr[-4000:]+result.stdout[-1000:])
    return json.loads(result.stdout)

def describe_process(package,user,info,kernel):
    p=Package(package);elf=Elf(user);sites=[]
    for lo,hi in info['code']:
        for pc in range(lo,hi,4):
            word=struct.unpack('<I',elf.read(pc,4))[0]
            if p.word(pc)!=word:raise ValueError('kernel-loaded ELF code differs at '+hex(pc))
            if word&0xffe0001f==0xd4000001:kind=0
            elif word&0xfff00000 in (0xd5300000,0xd5100000) and word>>5&65535 in (0xde82,0xde83,0xdf01,0xdf02,0xd807,0xd801):kind=1
            elif word in (0xd503233f,0xd50323bf,0xd503237f,0xd50323ff):kind=2
            else:continue
            sites.append((pc,word,kind))
    base=(max(s['va']+s['bytes'] for s in info['segments'])+(16<<20)-1)&~((16<<20)-1)
    size=(4*len(sites)+4095)&~4095;rows=[]
    for index,(pc,word,kind) in enumerate(sites):
        target=base+4*index
        if kind==0 and not -(1<<27)<=target-pc<(1<<27):raise ValueError('SVC gateway is out of range')
        rows.append(struct.pack('<QIIQ',pc,word,kind,target))
    hook=kernel['result_hook'];image=Elf(Path(kernel['_directory'])/'kernel.elf')
    try:
        hook_bytes=image.read(hook,4)  # Low-linked kernels already use the recorded VA.
    except ValueError:
        hook_bytes=image.read(hook|0xffff000000000000,4)
    word=struct.unpack('<I',hook_bytes)[0]
    if word&0xfc000000!=0x94000000:raise ValueError('invalid syscall observation hook')
    displacement=word&0x3ffffff
    if displacement&(1<<25):displacement-=1<<26
    lo=min(a for a,b in info['code'])&~4095;hi=(max(b for a,b in info['code'])+4095)&~4095
    (package/'application.bin').write_bytes(struct.pack('<10Q',0x315050414b4c,2,len(sites),base,size,hook,word,hook+4*displacement,lo,hi)+b''.join(rows))
    return dict(user_elf_sha256=info['sha256'],user_sites=len(sites),syscall_sites=sum(k==0 for pc,w,k in sites),
                gateway_base=hex(base),gateway_size=size,result_hook=hex(hook),vma_layout_sha256=digest(package/'vma.bin'))

def lower_application(package,reference,kernel,user,out,toolchain,validate,*,macos_cc=None,extra_pcs=(),kernel_slice=False,
                      merge_segments=False,macos_native=False,macos_direct_memory=False):
    """Link the resident kernel, or expand an explicitly requested slice.

    Every attempt starts from the same prepared RAM and input records. No
    observed result or control-flow trace supplies runtime computation.
    """
    from check_el0_program import run,run_qemu
    from kernel_code_closure import Code
    coverage=kernel/'coverage.log' if kernel_slice else None;extra=set(extra_pcs);attempts=[];code=None
    export_options = (dict(hardware_memory=True, alias_free_memory=True, elf_ram_initialization=True,
                           no_model_page_tables=True) if macos_cc else {})
    if macos_direct_memory:
        export_options = dict(macos_direct_memory=True)
    if not kernel_slice:
        export_options['whole_kernel_text']=True
    for attempt in range(12 if kernel_slice else 1):
        image=out/('program-attempt-%d'%attempt)
        runtime=out/('runtime-attempt-%d'%attempt)
        exported=export(package,kernel/'kernel.elf',user,reference,image,extra=sorted(extra),
                        coverage=coverage if coverage and coverage.is_file() else None,**export_options)
        if macos_cc:
            command=['make','-C',str(ROOT/'runtime/el0_flat'),'CC='+shlex.quote(macos_cc)+' --target=aarch64-none-elf',
                     'OUT='+str(runtime),'IMAGE='+str(image),'LTO=1','PRETRANSLATE=1','program']
            if macos_native:
                command.append('MACOS_NATIVE=1')
            if merge_segments:
                command.append('MERGE_SEGMENTS=1')
        else:
            command=['docker','run','--rm','--network','none','--mount','type=bind,src='+str(ROOT)+',dst=/src,readonly',
                     '--mount','type=bind,src='+str(out)+',dst=/out','-w','/src/runtime/el0_flat',toolchain,'make','CC=clang-19',
                     'OUT=/out/'+runtime.name,'IMAGE=/out/'+image.name,'program','observer']
        print('Building EL0 code coverage attempt %d'%attempt,file=sys.stderr,flush=True)
        with (out/('build-%d.log'%attempt)).open('wb') as log:
            subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=900 if kernel_slice else 3600)
        verification={}
        if validate:
            if macos_cc:
                if macos_native:
                    from el0_macos_native import run as run_macos
                else:
                    from el0_macos import run as run_macos
                checked=run_macos(image/'checkpoint',out/('macos-validation-%d'%attempt),
                                  user_elf=user,reference=reference/'calls.json')
                verification['macos']=checked
            else:
                checked=run(image,out/('native-validation-%d'%attempt),runtime/'flat-observe')
                verification['native']=checked
            if not checked['verified']:
                result=checked.get('result',{})
                if not kernel_slice or result.get('reason')!=0x100:
                    raise ValueError('EL0 continuation stopped: '+json.dumps(checked))
                pc=result['missing_pc'];code=code or Code(kernel/'kernel.elf');original=pc|0xffff000000000000
                f=code.containing(original)
                if pc%4 or pc in extra or f is None or not code.text[0]<=original<code.text[1] or not original<code.extent(f)[1]:
                    raise ValueError('EL0 native continuation stopped: '+json.dumps(result))
                attempts.append(dict(attempt=attempt,missing_pc=hex(pc),function=code.name(f)))
                write_json(out/'coverage-expansions.json',attempts);extra.add(pc)
                print('Including captured function '+code.name(f)+' at '+hex(pc),file=sys.stderr,flush=True)
                continue
            if not macos_cc:
                verification['qemu']=run_qemu(image,out/'qemu-validation')
            else:
                (out/('macos-validation-%d'%attempt)).rename(out/'macos-validation')
        else:
            from audit_el0_image import audit
            from check_el0_program import load_plan
            checked=audit(image/'checkpoint');write_json(out/'audit.json',checked)
            if not macos_cc:
                load_plan(image,checked)
        image.rename(out/'program')
        runtime.rename(out/'runtime')
        return exported,verification,attempts
    raise ValueError('kernel code coverage did not converge in 12 complete attempts; see coverage-expansions.json')

def build_application(libkernel,user_elf,out,args=(),expect_exit=0,toolchain='osrec-kbuild-clang19:latest',validate=True,baseline=False,
                      *,macos_cc=None,extra_pcs=(),kernel_slice=False,merge_segments=False,macos_native=False,
                      macos_direct_memory=False):
    # Complete preflight before opening an output directory or running the ELF.
    info=inspect_user(user_elf);kernel,m=load_kernel(libkernel);user=Path(user_elf).resolve();out=Path(out).resolve()
    if len(args)>128 or any('\0' in a or len(a.encode())>65536 for a in args):raise ValueError('invalid program arguments')
    if not 0<=expect_exit<=255:raise ValueError('expected exit status must be in 0..255')
    if baseline and m['constructor_abi']<2:raise ValueError('--linux-baseline requires a capsule rebuilt with constructor ABI 2')
    if extra_pcs and not kernel_slice:raise ValueError('--extra-pc requires --kernel-slice')
    if macos_native and macos_cc is None:raise ValueError('native macOS delivery requires a cross compiler')
    if macos_direct_memory and (not macos_native or not validate):
        raise ValueError('--macos-direct-memory requires a validated --macos-native-cc build')
    if merge_segments and macos_cc is None:raise ValueError('--merge-segments requires a macOS cross compiler for ELF RAM initialization')
    if macos_cc is not None:
        if sys.platform!='darwin' or platform.machine()!='arm64':
            raise ValueError('macOS delivery requires Apple Silicon macOS')
        compiler=shutil.which(macos_cc)
        if not compiler:
            raise ValueError('macOS cross compiler is not executable: '+macos_cc)
        macos_cc=compiler
        if validate:
            loader='native-loader' if macos_native else 'loader'
            subprocess.run(['make','-C',str(ROOT/'runtime/el0_macos'),loader],check=True,timeout=60)
    p=Package(kernel/'template')
    if any(s['va']<hi and lo<s['va']+s['bytes'] for s in info['segments'] for lo,hi in struct.iter_unpack('<QQ',p.ranges)):
        raise ValueError('user ELF overlaps captured kernel address space')
    out.mkdir(parents=True,exist_ok=False);package=out/'state';package.mkdir();reference=out/'reference';reference.mkdir()
    layout=m['process_layout'];hw=m['hardware'];m['_directory']=str(kernel)
    prepared=run_constructor(kernel,['prepare','/template','/user','/state',layout['task_slot'],layout['task_mm'],layout['mm_mt'],hw['uart_va'],hw['counter_base'],*args],
                             [(kernel/'template','/template',False),(user,'/user',False),(package,'/state',True)],out,'prepare')
    root=int(prepared['vma_root'],0)
    (package/'vma.bin').write_bytes(struct.pack('<10Q',0x31414d564b4c,1,root,layout['vma_start'],layout['vma_end'],layout['vma_flags'],
                                               layout['r_pivot'],layout['r_pivot']+15*8,layout['a_pivot'],layout['a_slot']))
    app=describe_process(package,user,info,m)
    identity=hashlib.sha256(bytes.fromhex(digest(package/'native.bin'))+bytes.fromhex(digest(package/'memory.bin'))).hexdigest()
    write_json(package/'manifest.json',dict(format='osrec-native-package-v1',source_image_sha256=identity,
               identity_kind='prepared-process-checkpoint',parent_source_image_sha256=m['parent_source_image_sha256'],application=app))
    start=hw['counter_base']+prepared['counter_reads']*hw['counter_step']
    recorded=run_constructor(kernel,['record','/state','/reference',start,hw['counter_step'],hw['uart_va'],m['stop_pc']],
                             [(package,'/state',False),(reference,'/reference',True)],out,'reference')
    calls=json.loads((reference/'calls.json').read_text());calls['source_image_sha256']=identity
    calls['end']['function']='do_exit+0x0';write_json(reference/'calls.json',calls)
    last=next((c for c in reversed(calls['calls']) if not c.get('event')),None)
    if not last or last['number'] not in (93,94) or last['arguments'][0]&255!=expect_exit:
        raise ValueError('user program did not terminate with expected exit status '+str(expect_exit))
    baseline_report=linux_baseline(kernel,user,args,reference,out,expect_exit) if baseline else None
    exported,verification,attempts=lower_application(package,reference,kernel,user,out,toolchain,validate,
                                                     macos_cc=macos_cc,extra_pcs=extra_pcs,kernel_slice=kernel_slice,
                                                     merge_segments=merge_segments,macos_native=macos_native,
                                                     macos_direct_memory=macos_direct_memory)
    target='macos-native' if macos_native else 'macos-flat' if macos_cc else 'linux'
    report=dict(format='osrec-el0-user-application-v1',user_sha256=info['sha256'],arguments=list(args),expected_exit=expect_exit,
                prepared_state_sha256=identity,kernel_assets=m['assets'],
                linux_baseline=baseline_report,
                initialization='captured-kernel execveat plus executable-page population; user starts at ELF entry',
                prepared=prepared,reference=recorded,code=exported,coverage_expansions=attempts,executable='program/checkpoint',
                coverage_seed_pcs=[hex(pc) for pc in extra_pcs],delivery_target=target,
                verified=bool(verification) and all(v['verified'] for v in verification.values()),
                reference_kind='native captured-kernel execution with deterministic RAM inputs; not a fresh live-Linux oracle',
                delivery_execution_level=0)
    write_json(out/'application.json',report);return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest='command',required=True)
    k=commands.add_parser('kernel',help='make a reusable libkernel code/state capsule')
    for name in ('package','vmlinux','dwarf-db','constructor','out'):k.add_argument('--'+name,required=True)
    k.add_argument('--coverage');k.add_argument('--counter-base',type=lambda v:int(v,0));k.add_argument('--uart-va',type=lambda v:int(v,0),default=UART)
    b=commands.add_parser('build',help='initialize a new static user ELF and produce a standalone EL0 executable')
    for name in ('libkernel','user-elf','out'):b.add_argument('--'+name,required=True)
    b.add_argument('--arg',action='append',default=[]);b.add_argument('--expect-exit',type=int,default=0)
    b.add_argument('--toolchain',default='osrec-kbuild-clang19:latest');b.add_argument('--no-validate',action='store_true')
    b.add_argument('--linux-baseline',action='store_true',help='also compare unmodified user ELF exit/stdout on the Linux host')
    macos=b.add_mutually_exclusive_group()
    macos.add_argument('--macos-flat-cc',help='AArch64 ELF cross compiler for flat macOS delivery and validation')
    macos.add_argument('--macos-native-cc',help='AArch64 ELF cross compiler for native macOS process delivery and validation')
    b.add_argument('--macos-direct-memory',action='store_true',
                   help='use fixed native host data aliases for compatible captured mappings')
    b.add_argument('--merge-segments',action='store_true',help='cluster the preloaded ELF RAM segments in the flat build')
    b.add_argument('--kernel-slice',action='store_true',help='select a workload-specific kernel closure instead of all resident kernel text')
    b.add_argument('--extra-pc',action='append',type=lambda value:int(value,0),default=[],
                   help='include the whole captured kernel function containing this PC')
    options=parser.parse_args()
    if options.command=='kernel':result=kernel_capsule(options.package,options.vmlinux,options.dwarf_db,options.constructor,options.out,options.coverage,options.counter_base,options.uart_va)
    else:result=build_application(options.libkernel,options.user_elf,options.out,options.arg,options.expect_exit,options.toolchain,
                                  not options.no_validate,options.linux_baseline,
                                  macos_cc=options.macos_native_cc or options.macos_flat_cc,
                                  extra_pcs=options.extra_pc,kernel_slice=options.kernel_slice,
                                  merge_segments=options.merge_segments,macos_native=options.macos_native_cc is not None,
                                  macos_direct_memory=options.macos_direct_memory)
    print(json.dumps({key:result[key] for key in ('format','verified','executable','architecture') if key in result},indent=2))
