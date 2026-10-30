#!/usr/bin/env python3
"""Check that a kernel binary's record layouts match Clang on the configured source.

For every compile unit in the binary's DWARF that has a compile command, the
records the unit defines are probed in that same translation unit: `sizeof` and
the offset of each named, byte-addressable member are evaluated by Clang under
the unit's own command and compared with DWARF. Agreement shows that the source
tree and build configuration reproduce the binary's data layout for those
records; it says nothing about code. Records a probe cannot name (for example
function-local types) are reported as excluded, never as matching.
"""
import argparse,json,re,shlex,subprocess,tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from kernel_dwarf import DWARF

FORMAT='osrec-layout-correspondence-v1'
PROBE='osrec_layout_probe'

def command_for(entry):
    args=entry.get('arguments') or shlex.split(entry['command'])
    source=str((Path(entry.get('directory','.'))/entry['file']).resolve())
    return args,source

def probe_args(args,source,directory,probe,extra=()):
    out=[];skip=False
    for a in args[1:]:
        if skip:skip=False;continue
        if a in ('-c','-MD','-MMD','-MP'):continue
        if a in ('-o','-MF','-MT','-MQ'):skip=True;continue
        if a.startswith(('-o','-MF')) and len(a)>3:continue
        if not a.startswith('-') and str((Path(directory)/a).resolve())==source:continue
        out.append(a)
    return [args[0],*out,*extra,'-w','-Wno-error','-fsyntax-only','-Xclang','-ast-dump=json','-Xclang','-ast-dump-filter','-Xclang',PROBE,str(probe)]

def probes(dwarf,records):
    """(record, member or None for sizeof, DWARF value, C expression) rows."""
    rows=[]
    for name,spelling,i in records:
        t=dwarf.types[i];rows.append((name,None,t['value'],'sizeof(%s)'%spelling))
        for member,_,bits,width in t['members']:
            if member and not width and bits%8==0:rows.append((name,member,bits//8,'__builtin_offsetof(%s,%s)'%(spelling,member)))
    return rows

def evaluate(args,source,rows,directory,stage,extra=()):
    """Evaluate probe expressions; drop records whose probe lines fail and retry.

    Returns (values, evaluated rows, excluded records, error)."""
    active=list(rows);excluded={}
    for attempt in range(6):
        if not active:return [],[],excluded,None
        probe=stage/('probe-%d.c'%attempt);lines=['#include "%s"'%source,'enum %s {'%PROBE]
        lines+=['  osrec_layout_%d = (%s),'%(k,e) for k,(_,_,_,e) in enumerate(active)]+['};']
        probe.write_text('\n'.join(lines)+'\n')
        r=subprocess.run(probe_args(args,source,directory,probe,extra),cwd=directory,capture_output=True,text=True,timeout=300)
        if r.returncode==0:
            values={};decoder=json.JSONDecoder();text=r.stdout;at=0
            while (at:=text.find('{',at))>=0:
                node,at=decoder.raw_decode(text,at)
                for c in node.get('inner',[]):
                    m=re.fullmatch(r'osrec_layout_(\d+)',c.get('name',''))
                    found=[x for x in walk(c) if x.get('kind')=='ConstantExpr' and 'value' in x]
                    if m and found:values[int(m.group(1))]=int(found[0]['value'])
            return [values.get(k) for k in range(len(active))],active,excluded,None
        bad=set()
        for line in re.findall(re.escape(str(probe))+r':(\d+):\d+: error',r.stderr):
            index=int(line)-3
            if 0<=index<len(active):bad.add(active[index][0])
        if not bad:return None,active,excluded,r.stderr[-2000:]
        for name in bad:excluded[name]='probe does not compile in this unit'
        active=[row for row in active if row[0] not in bad]
    return None,active,excluded,'probe retries exhausted'

def walk(node):
    yield node
    for c in node.get('inner',[]):yield from walk(c)

def check_unit(dwarf,unit,entry,extra=()):
    args,source=command_for(entry);records=dwarf.unit_records(unit);rows=probes(dwarf,records)
    with tempfile.TemporaryDirectory(prefix='osrec-layout-') as name:
        values,active,excluded,error=evaluate(args,source,rows,entry.get('directory','.'),Path(name),extra)
    if values is None:return dict(source=source,status='probe-failed',error=error,records=len(records))
    mismatches=[]
    for k,(record,member,expected,_) in enumerate(active):
        if values[k]!=expected:mismatches.append(dict(record=record,member=member,dwarf=expected,clang=values[k]))
    return dict(source=source,status='mismatch' if mismatches else 'match',records=len({r[0] for r in active}),checks=len(active),mismatches=mismatches,excluded=excluded,
        bitfields_skipped=sum(1 for _,_,i in records for m in dwarf.types[i]['members'] if m[3]))

def correspond(elf,database,dwarfdump,jobs=4,extra=(),units=None):
    dwarf=DWARF(elf,dwarfdump);entries={}
    for e in json.loads(Path(database).read_text()):entries[command_for(e)[1]]=e
    selected=[(u,dwarf.unit_source(u)) for u in dwarf.units]
    if units:selected=[(u,s) for u,s in selected if s and re.search(units,s)]
    work=[(u,entries[s]) for u,s in selected if s in entries]
    with ThreadPoolExecutor(jobs) as pool:results=list(pool.map(lambda w:check_unit(dwarf,*w,extra),work))
    counts={k:sum(r['status']==k for r in results) for k in ('match','mismatch','probe-failed')}
    return dict(format=FORMAT,binary=str(Path(elf).resolve()),units_in_binary=len(dwarf.units),units_without_command=sorted(s or '?' for u,s in selected if s not in entries),
        units_checked=len(results),counts=counts,checks=sum(r.get('checks',0) for r in results),mismatching_records=sorted({(m['record']) for r in results for m in r.get('mismatches',[])}),
        extra_flags=list(extra),results=results,scope='data layout of records each unit defines; not code or semantic correspondence')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf',type=Path,required=True);p.add_argument('--compile-commands',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--dwarfdump',default='/opt/homebrew/opt/llvm@22/bin/llvm-dwarfdump');p.add_argument('--jobs',type=int,default=4)
    p.add_argument('--units',help='regex selecting unit source paths');p.add_argument('--extra-flag',action='append',default=[],help='append a compiler flag (negative controls)')
    a=p.parse_args();r=correspond(a.elf,a.compile_commands,a.dwarfdump,a.jobs,a.extra_flag,a.units)
    a.out.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({k:r[k] for k in ('units_in_binary','units_checked','counts','checks','mismatching_records')}|{'units_without_command':len(r['units_without_command'])},indent=2))
if __name__=='__main__':main()
