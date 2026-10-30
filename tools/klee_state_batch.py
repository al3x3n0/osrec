#!/usr/bin/env python3
"""Rerun KLEE state discovery and validation for a manifest of captured boundaries.

The manifest lists, for each boundary, the observation file and its SHA-256,
the discovery arguments, a tier, and the expected result: whether exploration
completed, the required inputs, the inputs that only chose between paths with
equal outputs, the split inputs, the validation status and the required inputs
the validation could not demonstrate. Every selected entry is discovered
(`klee_state_discovery.py`) and validated (`klee_state_validation.py`) into
WORK/NAME and WORK/NAME-validation, and its result is compared with the
expectation. An entry passes only when every expected item is equal; a changed
boundary, a missing input or a tool failure is reported as such.

With --reuse, an entry whose WORK/NAME holds a finished discovery of the same
boundary with the same arguments is reanalyzed from its KQuery and KTest files
instead of rerun, so changes to the analysis are checked without KLEE.
With --record, the observed results replace the expectations of the entries
that ran (the manifest is rewritten; review the change before keeping it).
"""
import argparse,hashlib,json,shutil,subprocess,sys,time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

FORMAT='osrec-klee-state-batch-v1'
TOOLS=Path(__file__).resolve().parent
EXPECT=('complete','required','control_without_effect','split_inputs','validation','not_demonstrated')
ENTRY_KEYS={'name','boundary','boundary_sha256','tier','args','expect'}

def load(path):
    """A manifest, checked for shape: unique names, known keys and complete expectations."""
    manifest=json.loads(Path(path).read_text())
    if manifest.get('format')!=FORMAT:raise ValueError('unsupported batch manifest')
    names=[e['name'] for e in manifest['entries']]
    if len(set(names))!=len(names):raise ValueError('duplicate entry names')
    for e in manifest['entries']:
        if set(e)-ENTRY_KEYS or not {'name','boundary','boundary_sha256','tier'}<=set(e):raise ValueError('entry %s has unexpected or missing keys'%e.get('name'))
        if 'expect' in e and set(e['expect'])!=set(EXPECT):raise ValueError('entry %s expectation must list exactly %s'%(e['name'],', '.join(EXPECT)))
    return manifest

def discovery_args(entry,defaults,root):
    """Discovery command-line arguments for an entry: manifest defaults, then the entry's own."""
    path=lambda p:str(Path(root,p))
    args=['--boundary',path(entry['boundary']),'--slice',path(defaults['slice']),'--binding',path(defaults['binding'])]
    if defaults.get('contracts'):args+=['--contracts',path(defaults['contracts'])]
    args+=['--max-time',str(defaults.get('max_time',120))]
    return args+list(entry.get('args',[]))

def observed(report,validation):
    """The compared result of one discovery report and its validation report."""
    return dict(complete=report['klee']['exploration_complete'],required=report['required'],
        control_without_effect=report.get('control_without_effect',[]),split_inputs=report.get('split_inputs',[]),
        validation=validation['status'] if validation else None,not_demonstrated=validation['necessity']['not_demonstrated'] if validation else None)

def compare(expect,result):
    """Expected items that differ, as {item: [expected, observed]}; lists compare as sets."""
    norm=lambda v:sorted(v) if isinstance(v,list) else v
    return {k:[expect[k],result.get(k)] for k in EXPECT if norm(expect[k])!=norm(result.get(k))}

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def run_entry(entry,defaults,root,work,tools,reuse):
    """Discover, validate and compare one entry; returns its summary record."""
    start=time.time();out=work/entry['name'];val=work/(entry['name']+'-validation');boundary=Path(root,entry['boundary'])
    record=dict(name=entry['name'],tier=entry['tier'])
    def done(status,**more):record.update(status=status,seconds=round(time.time()-start,1),**more);return record
    if not boundary.exists():return done('missing',detail='no boundary at %s'%boundary)
    if sha(boundary)!=entry['boundary_sha256']:return done('stale',detail='boundary differs from the manifest')
    args=discovery_args(entry,defaults,root)+[x for kv in tools.items() if kv[0]!='--qemu' for x in kv]
    stamp=out/'batch-args.json';reused=False
    if reuse and (out/'report.json').exists() and stamp.exists() and json.loads(stamp.read_text())==args:
        step=subprocess.run([sys.executable,str(TOOLS/'klee_state_discovery.py'),'--reanalyze',str(out)],capture_output=True,text=True);reused=True
    else:
        if out.exists():shutil.rmtree(out)
        step=subprocess.run([sys.executable,str(TOOLS/'klee_state_discovery.py'),*args,'--out',str(out)],capture_output=True,text=True)
        if step.returncode==0:stamp.write_text(json.dumps(args)+'\n')
    if step.returncode!=0:return done('failed',detail='discovery: '+(step.stderr or step.stdout)[-400:])
    report=json.loads((out/'report.json').read_text())
    if val.exists():shutil.rmtree(val)
    # The validator exits non-zero for an inconsistent result; its report still records why.
    vargs=['--discovery',str(out),'--boundary',str(boundary),'--slice',str(Path(root,defaults['slice'])),'--binding',str(Path(root,defaults['binding'])),'--out',str(val)]
    vtools=[x for k in ('--llvm-bin','--qemu') if k in tools for x in (k,tools[k])]
    step=subprocess.run([sys.executable,str(TOOLS/'klee_state_validation.py'),*vargs,*vtools],capture_output=True,text=True)
    validation=json.loads((val/'report.json').read_text()) if (val/'report.json').exists() else None
    result=observed(report,validation)
    if validation is None:return done('failed',reused=reused,observed=result,detail='validation: '+(step.stderr or step.stdout)[-400:])
    if 'expect' not in entry:return done('unrecorded',reused=reused,observed=result)
    differences=compare(entry['expect'],result)
    return done('differs' if differences else 'match',reused=reused,observed=result,differences=differences)

def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--work',type=Path,required=True)
    p.add_argument('--root',type=Path,default=TOOLS.parent,help='directory manifest paths are relative to (default: the repository)')
    p.add_argument('--tier',action='append',default=[],help='run only entries of this tier (repeatable; default: all)')
    p.add_argument('--only',action='append',default=[],help='run only this entry (repeatable)')
    p.add_argument('--jobs',type=int,default=4);p.add_argument('--reuse',action='store_true');p.add_argument('--record',action='store_true')
    p.add_argument('--llvm-bin',type=Path);p.add_argument('--klee',type=Path);p.add_argument('--klee-include',type=Path);p.add_argument('--qemu')
    a=p.parse_args()
    manifest=load(a.manifest);entries=[e for e in manifest['entries'] if (not a.tier or e['tier'] in a.tier) and (not a.only or e['name'] in a.only)]
    unknown=set(a.only)-{e['name'] for e in manifest['entries']}
    if unknown:p.error('no such entries: '+', '.join(sorted(unknown)))
    if not entries:p.error('no entries selected')
    tools={'--'+k.replace('_','-'):str(getattr(a,k)) for k in ('llvm_bin','klee','klee_include','qemu') if getattr(a,k)}
    a.work.mkdir(parents=True,exist_ok=True)
    with ThreadPoolExecutor(a.jobs) as pool:
        futures=[pool.submit(run_entry,e,manifest['defaults'],a.root,a.work,tools,a.reuse) for e in entries]
        records=[]
        for f in futures:
            r=f.result();records.append(r)
            print('%-24s %-10s %6.0fs%s'%(r['name'],r['status'],r['seconds'],' (reanalyzed)' if r.get('reused') else ''),flush=True)
            for k,(want,got) in r.get('differences',{}).items():print('    %s: expected %s, observed %s'%(k,json.dumps(want),json.dumps(got)))
            if r.get('detail'):print('    '+r['detail'].strip().replace('\n','\n    '))
    counts={s:sum(r['status']==s for r in records) for s in dict.fromkeys(r['status'] for r in records)}
    (a.work/'summary.json').write_text(json.dumps(dict(format=FORMAT,manifest=str(a.manifest),counts=counts,entries=records),indent=2)+'\n')
    print(' '.join('%s %d'%kv for kv in counts.items()))
    if a.record:
        results={r['name']:r['observed'] for r in records if r.get('observed') and r['status']!='failed'}
        for e in manifest['entries']:
            if e['name'] in results:e['expect']={k:results[e['name']][k] for k in EXPECT}
        a.manifest.write_text(json.dumps(manifest,indent=1)+'\n');print('recorded %d expectations in %s'%(len(results),a.manifest));return
    if any(r['status']!='match' for r in records):raise SystemExit(1)

if __name__=='__main__':main()
