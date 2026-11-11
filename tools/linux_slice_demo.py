#!/usr/bin/env python3
"""Live demo: one Linux system call, captured from a running kernel and replayed two ways.

For one call of the fd-control state checkpoint (by default a 9-segment writev,
which kmallocs and kfrees its iovec array), the demo runs, live:

1. Inputs: the full-machine checkpoint, the source-slice port and the derived
   data symbols, identified by hash.
2. Capture: the call's whole kernel execution, from the SVC vector to the
   return to user mode (kernel_boundary_capture.py).
3. Binary replay: the kernel's own machine code in a minimal image of the
   captured pages, compared instruction by instruction (kernel_boundary_replay.py).
4. Live state: the kernel objects the slice needs, read through the BTF binding
   at entry and after return (svc_boundary.py).
5. Source-slice replay: the original Linux source of the call, its footprint
   derived by the entry-state analysis, run on the live pre-state and compared
   with the post-state (reduced_boundary_replay.py).
6. Authenticity: how much of the live call's execution the source slice runs
   as original kernel code (kernel_authenticity.py).

Each step prints what it did and what was checked; the run ends with a summary.
Outputs go to a fresh directory under build/ (or --out).
"""
import argparse,hashlib,json,os,re,subprocess,sys,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CHECKPOINT=ROOT/'build/linux-svc-machine-checkpoint-state-20261105f'
PORT=ROOT/'build/linux-fd-control-port-20261105f'
SYMBOLS=ROOT/'build/linux-data-symbols-d196f8248abdddab-f.json'
KALLSYMS=ROOT/'build/linux-kallsyms-d196f8248abdddab.txt'
FD=ROOT/'integrations/linux_aarch64/fd-control'
PLUGIN=ROOT/'build/qemu-plugins/libfootprint.dylib'
# Calls of init-state.c's post-checkpoint sequence the demo can select (the observer picks the first match).
CALLS={
    'writev-nine':(dict(number=66,x2=9),'writev of 9 one-byte segments: more than UIO_FASTIOV, so SLUB kmallocs and kfrees the iovec array'),
    'writev':(dict(number=66,x2=2),'writev of 2 segments at the shared file position'),
    'pread':(dict(number=67,x0=4),'pread64 of 4 bytes at offset 2 through the duplicated descriptor'),
    'pwrite':(dict(number=68,x2=2),'pwrite64 of 2 bytes at offset 6'),
    'fcntl-dupfd':(dict(number=25,x1=0,x2=6),'fcntl F_DUPFD from 6'),
    'futex-wake':(dict(number=98,x1=129),'futex FUTEX_WAKE_PRIVATE with no waiter'),
}
NAMES={25:'fcntl',62:'lseek',63:'read',64:'write',66:'writev',67:'pread64',68:'pwrite64',98:'futex'}

COLOR=sys.stdout.isatty() and not os.environ.get('NO_COLOR')
def paint(code,text):return '\033[%sm%s\033[0m'%(code,text) if COLOR else text
def step(number,title):print('\n'+paint('1;36','[%d/6] %s'%(number,title)))
def fact(label,value):print('  %-26s %s'%(label,value))
def ok(text):print('  '+paint('32','✓ '+text))
def fail(text):print('  '+paint('31','✗ '+text));raise SystemExit(1)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]

def run(command,log,env=None):
    """Run a tool; its full output goes to `log`, a failure prints the log's tail."""
    started=time.time()
    with open(log,'w') as out:r=subprocess.run([str(c) for c in command],cwd=ROOT,stdout=out,stderr=subprocess.STDOUT,env=env)
    if r.returncode:
        print(Path(log).read_text()[-2000:]);fail('%s failed (log: %s)'%(Path(str(command[1])).name,log))
    return time.time()-started

def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--call',choices=sorted(CALLS),default='writev-nine')
    p.add_argument('--out',type=Path,help='output directory (default: build/linux-slice-demo-<call>-<time>)')
    a=p.parse_args()
    select,story=CALLS[a.call]
    out=(a.out or ROOT/('build/linux-slice-demo-%s-%s'%(a.call,time.strftime('%Y%m%d-%H%M%S')))).resolve()
    if out.exists():fail('output exists: %s'%out)
    out.mkdir(parents=True)
    summary={}
    print(paint('1','OSREC: a Linux system call from a running kernel, replayed as machine code and as original source'))
    print('  call: %s (%s)'%(a.call,story))
    print('  output: %s'%out.relative_to(ROOT) if out.is_relative_to(ROOT) else out)

    step(1,'Inputs')
    for path in (CHECKPOINT/'checkpoint/manifest.json',PORT/'kernel/manifest.json',SYMBOLS,KALLSYMS,PLUGIN):
        if not path.exists():fail('missing input %s'%path)
    report=json.loads((CHECKPOINT/'report.json').read_text())
    fact('kernel',report['ready'].split()[-1]+'  (arm64 Image %s)'%sha(CHECKPOINT/'checkpoint/assets/kernel'))
    fact('checkpoint',CHECKPOINT.name+'  (QEMU virt, paused after OSREC_VM_READY)')
    fact('workload oracle',report['baseline_result'][:60]+'…')
    manifest=json.loads((PORT/'kernel/manifest.json').read_text())
    fact('source-slice port',PORT.name+'  (%d pinned Linux v6.10 definitions across its roots)'%len(json.loads((FD/'source-identity.json').read_text())['definitions']))
    fact('data symbols',SYMBOLS.name+'  (derived from the image: %s)'%', '.join(json.loads(SYMBOLS.read_text())['symbols']))
    ok('inputs present; the kernel is the unmodified linuxkit 6.10.14 Image')

    step(2,'Capture the call from the live kernel')
    capture=out/'capture'
    args=['python3','tools/kernel_boundary_capture.py','--checkpoint',CHECKPOINT/'checkpoint','--out',capture]
    for k,v in select.items():args+=['--select','%s=%d'%(k,v)]
    seconds=run(args,out/'capture.log',env={**os.environ,'OSREC_FOOTPRINT_PLUGIN':str(PLUGIN)})
    c=json.loads((capture/'capture.json').read_text())
    pages=len(list((capture/'pages').glob('*'))) if (capture/'pages').is_dir() else c.get('pages')
    instructions=sum(1 for line in (capture/'trace.txt').open() if line.startswith('I '))
    accesses=sum(1 for line in (capture/'trace.txt').open() if line.startswith('M '))
    fact('selected',NAMES.get(c['call']['number'],c['call']['number'])+'('+', '.join(hex(x) if x>4096 else str(x) for x in c['call']['arguments'][:4])+')')
    fact('kernel instructions',instructions)
    fact('memory accesses',accesses)
    fact('result (x0)',c['returned']['gprs']['x0'])
    ok('captured from the SVC vector to the return to EL0 in %.0f s, no kernel symbols used'%seconds)
    summary['instructions']=instructions

    step(3,'Replay the kernel\'s own machine code')
    seconds=run(['python3','tools/kernel_boundary_replay.py','--capture',capture,'--out',out/'binary-replay'],out/'binary-replay.log')
    r=json.loads((out/'binary-replay/report.json').read_text())
    k=r['kernel_instructions']
    fact('image','captured pages at their physical addresses + an EL2 stub (no kernel image file)')
    for name,value in r['checks'].items():fact(name.replace('_',' '),'yes' if value else paint('31','no'))
    fact('authentic instructions','%d of %d (%.0f%%)'%(k['from_kernel_image'],k['live'],100*k['authentic_share']))
    if r['status']!='equivalent':fail('binary replay %s'%r['status'])
    ok('equivalent: same instructions, memory accesses, registers and pages (%.0f s)'%seconds)
    summary['binary']=r['status']

    step(4,'Read the live kernel state the source slice needs')
    observe=out/'observe'
    args=['python3','tools/svc_boundary.py','--checkpoint',CHECKPOINT/'checkpoint','--contract','integrations/linux_aarch64/svc-boundary.json','--binding',FD/'live-binding.json',
          '--port',FD/'port-template.json','--kernel-config',CHECKPOINT/'kernel.config','--data-symbols',SYMBOLS,'--out',observe]
    for k_,v in select.items():args+=['--select','%s=%d'%(k_,v)]
    seconds=run(args,out/'observe.log')
    o=json.loads((observe/'boundary.json').read_text());pre=o['kernel_pre'];post=o['kernel_post']
    bound=len(pre['scalars'])+len(pre.get('pointers',{}))
    changed=sorted(f for f in pre['scalars'] if post['scalars'].get(f)!=pre['scalars'][f])
    fact('bound kernel fields','%d (through the image\'s BTF, from `current` in SP_EL0)'%bound)
    fact('changed by the call',', '.join(changed[:6])+(' … (+%d)'%(len(changed)-6) if len(changed)>6 else ''))
    if 'kmalloc' in pre.get('evidence',{}):
        e=pre['evidence']['kmalloc'];fact('slab object','%#x in slab page %#x (kmalloc-192, tid %d → %d)'%(e['object'],e['slab'],pre['scalars']['kmalloc_cpu.tid'],post['scalars']['kmalloc_cpu.tid']))
    ok('observed at entry and at the next kernel entry; the guest still produced its oracle (%.0f s)'%seconds)

    step(5,'Replay the original Linux source of the call')
    seconds=run(['python3','tools/reduced_boundary_replay.py','--boundary',observe/'boundary.json','--slice',PORT/'kernel','--binding',FD/'live-binding.json',
                 '--contracts',FD/'analysis-contracts.json','--out',out/'source-replay'],out/'source-replay.log',env={**os.environ,'OSREC_FOOTPRINT_TIMEOUT':'600'})
    x=json.loads((out/'source-replay/report.json').read_text());f=x['footprint'];cmp=x['comparison']
    fields=sorted({re.sub(r'\[\d+\]','[]',e['field']) for e in f['entry_reads'] if not e['field'].startswith('argument:')})
    fact('root',x['root'])
    fact('entry state discovered','%d schema fields read at entry; %d uncovered; blockers: %s'%(len(fields),len(f['uncovered']),f['blockers'] or 'none'))
    fact('assumptions checked','%d state ranges, %d argument ranges on the live states'%(len(f.get('state_range_checks',[])),len(f.get('argument_range_checks',[]))))
    if f.get('allocation_summaries'):fact('allocation','kmalloc_array → %s (fresh memory, written before read)'%f['allocation_summaries'][0]['element_type'])
    fact('result','reduced %d / live %d'%(cmp['result']['reduced'],cmp['result']['full_vm']))
    fact('kernel fields compared','%d before and after; mismatches %d; model faults %d'%(x['bound_fields'],len(cmp['restore_mismatches'])+len(cmp['post_mismatches']),cmp['model_fault']))
    fact('user memory','identical' if cmp['user_objects']['reduced']==cmp['user_objects']['full_vm'] else paint('31','differs'))
    if x['status']!='equivalent':fail('source replay %s'%x['status'])
    ok('equivalent: original source on the live pre-state reproduces the live post-state (%.0f s)'%seconds)
    summary['source']=x['status']

    step(6,'How much of the live call ran as original source')
    text=subprocess.run(['python3','tools/kernel_authenticity.py','--capture',capture,'--symbols',KALLSYMS,'--slice-sources',PORT/'kernel/sources','--functions'],cwd=ROOT,capture_output=True,text=True,check=True).stdout
    (out/'authenticity.txt').write_text(text)
    rows=[m.groups() for m in (re.match(r'\s*(\d+)\s+(original|model|absent)\s+(\S+)',line) for line in text.splitlines()) if m]
    totals={k_:sum(int(n) for n,kind,_ in rows if kind==k_) for k_ in ('original','model','absent')};all_=sum(totals.values()) or 1
    for kind in ('original','model','absent'):fact(kind+' code','%5.1f%%  (%d instructions)'%(100*totals[kind]/all_,totals[kind]))
    top=sorted(rows,key=lambda r:-int(r[0]))
    fact('largest original functions',', '.join('%s %s'%(name,n) for n,kind,name in top if kind=='original')[:110]+' …')
    slab=[(name,n,kind) for n,kind,name in rows if re.search(r'kmalloc|kfree|slab',name)]
    if slab:fact('SLUB in this call',', '.join('%s %s (%s)'%(name,n,kind) for name,n,kind in slab))
    others=[(name,n,kind) for n,kind,name in top if kind!='original']
    if others:fact('not original',', '.join('%s %s (%s)'%(name,n,kind) for name,n,kind in others))
    ok('every instruction attributed to its kernel function through /proc/kallsyms')
    summary['original']=100*totals['original']/all_

    print('\n'+paint('1','Summary'))
    print('  %s: %d live kernel instructions'%(a.call,summary['instructions']))
    print('  machine-code replay: %s (100%% the kernel\'s own instructions)'%summary['binary'])
    print('  original-source replay: %s, %.1f%% of the live execution as original Linux code'%(summary['source'],summary['original']))
    print('  artifacts and logs: %s'%(out.relative_to(ROOT) if out.is_relative_to(ROOT) else out))

if __name__=='__main__':main()
