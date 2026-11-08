#!/usr/bin/env python3
"""Replay a captured SVC boundary with kernel code built from source (address-faithful, AArch64).

The live kernel is our own build (vmlinux, System.map and compile_commands.json from
integrations/linux_aarch64/full-kernel/build.sh). The capture (`kernel_boundary_capture.py`) supplies the
data the call touched, at its live physical addresses, and the kernel's own translation tables; pages it
did not touch are absent, so any access the live call did not make faults.

Code pages are not taken from the capture. Each captured kernel text page is rebuilt:

- every byte comes from the build (vmlinux);
- bytes inside a boot-time patch site take the kernel's own patch result: ftrace's patchable entries
  (`mcount_loc`: the ops literal and entry instructions), alternatives (`.altinstructions`: the original
  range) and static branches (`__jump_table`: the branch or nop). These sites are listed by the kernel's
  own tables; the patched words are read from the live page;
- any other difference from the live page rejects the replay.

Each function the call executed is also checked against a fresh compile of its translation unit
(`kernel_source_verify.py`, in the build container): every instruction word matches outside relocated
fields, and every traced kernel PC must fall inside one of those verified functions. The rebuilt pages then replay through `kernel_boundary_replay.py`.
"""
import argparse,bisect,collections,json,shutil,struct,subprocess,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1];FORMAT='osrec-source-kernel-replay-v1';PAGE=4096
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')


class Kernel:
    """vmlinux, its symbols and its boot-time patch sites."""
    def __init__(self,build):
        self.build=Path(build);self.vmlinux=self.build/'vmlinux'
        out=subprocess.run([str(LLVM/'llvm-readelf'),'-SWl',str(self.vmlinux)],capture_output=True,text=True,check=True).stdout
        self.sections=[]
        for line in out.splitlines():
            if ']' not in line:continue
            parts=line.split(']',1)[1].split()
            if len(parts)>=6 and parts[1] in ('PROGBITS','NOBITS'):self.sections.append((parts[0],int(parts[2],16),int(parts[3],16),int(parts[4],16),parts[1]))
        self.text=next(s for s in self.sections if s[0]=='.text')
        self.symbols={};functions=[]
        for line in open(self.build/'System.map'):
            address,kind,name=line.split()[:3];address=int(address,16)
            self.symbols.setdefault(name,address)
            if kind in 'tTwW':functions.append((address,name))
        functions.sort();self.functions=functions;self.function_addresses=[a for a,_ in functions]
        self.file=open(self.vmlinux,'rb')
        # The kernel image's virtual base and its load address on QEMU virt (no KASLR: the trace's addresses are
        # System.map's).
        self.vbase=self.symbols['_text'];self.pbase=0x40200000
        self.sites=self.patch_sites()
    def read(self,va,n):
        for name,address,offset,size,kind in self.sections:
            if address and address<=va and va+n<=address+size and kind=='PROGBITS':
                self.file.seek(offset+va-address);return self.file.read(n)
        return None
    def function(self,pc):
        i=bisect.bisect_right(self.function_addresses,pc)-1
        return self.functions[i] if i>=0 else None
    def table(self,start,stop):
        a,b=self.symbols[start],self.symbols[stop];return a,self.read(a,b-a)
    def patch_sites(self):
        """[(low, high, kind)] byte ranges the kernel patches at boot, from its own tables."""
        sites=[]
        _,data=self.table('__start_mcount_loc','__stop_mcount_loc')
        # arm64 CALL_OPS: each record is 8 bytes before its function; the ops literal and entry nops follow.
        for (ip,) in struct.iter_unpack('<Q',data):sites.append((ip,ip+16,'ftrace'))
        base,data=self.table('__alt_instructions','__alt_instructions_end')
        for k in range(0,len(data)-11,12):
            orig,_alt,_cap,orig_len,_alt_len=struct.unpack_from('<iiHBB',data,k)
            sites.append((base+k+orig,base+k+orig+orig_len,'alternative'))
        base,data=self.table('__start___jump_table','__stop___jump_table')
        for k in range(0,len(data)-15,16):
            code,=struct.unpack_from('<i',data,k);sites.append((base+k+code,base+k+code+4,'jump_label'))
        sites.sort();return sites
    def site(self,va):
        i=bisect.bisect_right(self.sites,(va,1<<64,''))-1
        while i>=0 and self.sites[i][0]>va-64:
            low,high,kind=self.sites[i]
            if low<=va<high:return kind
            i-=1
        return None


def rebuild_text(capture,kernel):
    """Rebuilt kernel text pages {physical page: bytes} and a per-page account; raises on an unexplained word."""
    data=json.load(open(capture/'capture.json'));pages={};account=[];kinds=collections.Counter()
    _,tva,_,tsize,_=kernel.text
    for page in data['pages']['code_and_data']:
        pa=int(page,16);va=pa-kernel.pbase+kernel.vbase
        if not (kernel.vbase<=va<tva+tsize):continue
        built=bytearray(kernel.read(va,PAGE));live=(capture/'pages'/('%x.pre'%pa)).read_bytes()
        patched=collections.Counter()
        for offset in range(0,PAGE,4):
            if built[offset:offset+4]==live[offset:offset+4]:continue
            kind=kernel.site(va+offset)
            if kind is None:raise ValueError('live text differs from the build outside any patch site at %x'%(va+offset))
            built[offset:offset+4]=live[offset:offset+4];patched[kind]+=1
        pages[pa]=bytes(built);kinds.update(patched);account.append(dict(page=hex(pa),virtual=hex(va),patched_words=dict(patched)))
    return pages,account,dict(kinds)


def traced_pcs(capture):
    return [int(l.split()[1],16) for l in open(capture/'trace.txt') if l.startswith('I ')]


def unverified_pcs(pcs,checks):
    """Traced kernel PCs outside every function range the source check found identical."""
    ranges=sorted((c['address'],c['address']+4*c['words']) for c in checks if c['status']=='identical')
    starts=[a for a,_ in ranges]
    def covered(pc):
        i=bisect.bisect_right(starts,pc)-1;return i>=0 and pc<ranges[i][1]
    return sorted({pc for pc in pcs if not covered(pc)})


def executed_functions(capture,kernel):
    pcs=traced_pcs(capture)
    counts=collections.Counter(kernel.function(p) for p in pcs)
    return [dict(function=name,address=address,instructions=n) for (address,name),n in counts.most_common()]


def translation_unit(kernel,address):
    """(absolute source path, path relative to the kernel tree) of the compile unit holding `address`, from DWARF."""
    out=subprocess.run([str(LLVM/'llvm-dwarfdump'),'--lookup=0x%x'%address,str(kernel.vmlinux)],capture_output=True,text=True).stdout
    unit=False
    for line in out.splitlines():
        if 'DW_TAG_compile_unit' in line:unit=True;continue
        if unit and 'DW_AT_name' in line:
            path=line.split('(',1)[1].rstrip(')').strip('"')
            return path,(path.split('/linux-6.10.14/',1)[1] if '/linux-6.10.14/' in path else path)
    return None,None


def verify_source(functions,kernel,image,volume,source,work):
    requests=[]
    for f in functions:
        path,tu=translation_unit(kernel,f['address']);f['translation_unit']=tu
        if path:requests.append(dict(tu=tu,source=path,function=f['function'],address=f['address']))
    (work/'verify-request.json').write_text(json.dumps(requests))
    command=['docker','run','--rm','-v',volume+':/kbuild','-v',source+':'+source+':ro','-v',str(ROOT/'tools')+':/tools:ro','-v',str(work)+':/work',
             image,'python3','/tools/kernel_source_verify.py','/work/verify-request.json','/kbuild']
    result=subprocess.run(command,capture_output=True,text=True)
    if result.returncode:raise ValueError('source verification failed: '+result.stderr[-2000:])
    return json.loads(result.stdout)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture',type=Path,required=True);p.add_argument('--kernel',type=Path,required=True,help='kernel build artifacts (vmlinux, System.map)')
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--build-volume',default='osrec-kbuild-full');p.add_argument('--build-image',default='osrec-kbuild-clang19:latest')
    p.add_argument('--source-tree',default='/Volumes/osrec-linux-6.10.14')
    p.add_argument('--skip-source-check',action='store_true')
    a=p.parse_args()
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False);kernel=Kernel(a.kernel)
    pages,account,kinds=rebuild_text(a.capture,kernel)
    functions=executed_functions(a.capture,kernel)
    checks=[] if a.skip_source_check else verify_source(functions,kernel,a.build_image,a.build_volume,a.source_tree,out)
    # The replayed capture: the capture with its kernel text pages replaced by the rebuilt ones.
    staged=out/'capture';shutil.copytree(a.capture,staged)
    for pa,data in pages.items():(staged/'pages'/('%x.pre'%pa)).write_bytes(data)
    replay=subprocess.run([sys.executable,str(ROOT/'tools/kernel_boundary_replay.py'),'--capture',str(staged),'--out',str(out/'replay')],capture_output=True,text=True)
    (out/'replay.log').write_text(replay.stdout+replay.stderr)
    replayed=json.loads((out/'replay/report.json').read_text()) if (out/'replay/report.json').exists() else {}
    unverified=[c for c in checks if c['status']!='identical']
    # Every executed instruction must lie inside a verified function (its symbol's st_size bytes).
    uncovered=[] if a.skip_source_check else unverified_pcs(traced_pcs(a.capture),checks)
    status='equivalent' if replayed.get('status')=='equivalent' and not unverified and not uncovered and (checks or a.skip_source_check) else 'rejected'
    report=dict(format=FORMAT,status=status,capture=str(a.capture.resolve()),kernel=str(a.kernel.resolve()),
                text_pages=len(pages),patched_words=kinds,pages=account,functions=functions,source_checks=checks,
                source_unverified=len(unverified),pcs_outside_verified=[hex(pc) for pc in uncovered[:64]],replay_status=replayed.get('status'))
    (out/'report.json').write_text(json.dumps(report,indent=1)+'\n')
    print(json.dumps(dict(status=status,text_pages=len(pages),patched_words=kinds,functions=len(functions),
                          source_identical=sum(c['status']=='identical' for c in checks),source_unverified=len(unverified),pcs_outside_verified=len(uncovered),replay=replayed.get('status'))))


if __name__=='__main__':main()
