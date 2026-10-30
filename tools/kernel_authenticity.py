#!/usr/bin/env python3
"""How much of a live system call's kernel execution a replay runs as authentic kernel code.

The reference is the live call itself: the instruction trace a
`kernel_boundary_capture.py` run recorded, from the SVC vector to the return to
the user continuation. Each instruction is attributed to a kernel function
through a kallsyms dump (`linux_kallsyms.py`).

- A source slice (its `syscalls.c` and `models.c`) covers an instruction with
  authentic code when its function's original body is in the slice and the
  slice root of that call (`linux_NAME` for `__arm64_sys_NAME`) can reach it
  through the slice's static call graph. A function the slice replaces with a
  reviewed model, leaves out (syscall entry/exit, everything under a model), or
  holds only for other calls' roots does not count.
- The architecture's system call entry (`el0t_64_sync_handler` on arm64) is a
  root too when the slice holds it and the live call ran it. Its traversal
  stops at other calls' roots: the system call table reaches every root, but a
  call runs only its own. The original entry assembly around it (`vectors`,
  `el0t_64_sync`, `ret_to_user` from entry.S) counts with it when the slice
  assembles it.
- Original assembly the slice assembles verbatim (`linux-*.S`, such as arm64
  `memset.S`) counts the same way: every name its `SYM_FUNC_START` and
  `SYM_FUNC_ALIAS` lines define is original, and reachable when a reachable
  slice function calls one of them by name.
- A binary replay (`kernel_boundary_replay.py`) runs authentic code when it
  executes the captured kernel instructions themselves and is equivalent.

Function names match after the slice prefix is removed, `__arm64_sys_NAME`
corresponds to the slice root `linux_NAME`, and compiler suffixes
(`.constprop.0`, `.isra.0`, `.part.0`) are ignored. Functions the kernel
inlined count under their caller.
"""
import argparse,json,re
from collections import Counter,OrderedDict
from pathlib import Path
from kernel_boundary_capture import parse_trace
from linux_kallsyms import Symbols

def slice_functions(sources):
    """Original (syscalls.c) and model (models.c) function names defined in a slice port, and its call graph."""
    calls={};assembly={}
    for path in sorted(Path(sources).glob('linux-*.S')):
        text=path.read_text()
        group=set(re.findall(r'SYM_FUNC_START\((\w+)\)',text))|set(re.findall(r'SYM_FUNC_ALIAS(?:_WEAK)?\((\w+),',text))
        # entry.S also defines code with SYM_CODE_START and per-vector entry_handler stubs.
        group|=set(re.findall(r'SYM_CODE_START(?:_LOCAL)?(?:_NOALIGN)?\((\w+)\)',text))
        group|={'el%s%s_%s_%s'%m for m in re.findall(r'^\s*entry_handler\s+(\d+),\s*(\w+),\s*(\d+),\s*(\w+)',text,re.M)}
        for n in group:assembly[n]=group;calls.setdefault(n,set())
    def defined(name):
        text=(Path(sources)/name).read_text();names=set()
        for m in re.finditer(r'^[A-Za-z_][\w \t\*]*?\bosrec_kernel_(\w+)\s*\([^;{]*\)\s*\{',text,re.M):
            depth=0;start=m.end()-1
            for b in re.finditer(r'[{}]',text[start:]):
                depth+=1 if b.group()=='{' else -1
                if not depth:break
            body=text[start:start+b.end()]
            names.add(m.group(1));calls.setdefault(m.group(1),set()).update(re.findall(r'\bosrec_kernel_(\w+)\s*\(',body))
            for n,group in assembly.items():
                if re.search(r'\b%s\s*\('%n,body):calls[m.group(1)].update(group)
        return names
    return defined('syscalls.c')|set(assembly),defined('models.c'),calls

# Entry root -> the entry assembly that calls it on the way in and returns on the way out.
ENTRY_ROOTS={'el0t_64_sync_handler':('vectors','el0t_64_sync','ret_to_user')}

def reachable(calls,root,exclude=()):
    seen=set();todo=[root]
    while todo:
        f=todo.pop()
        if f in seen or f not in calls or f in exclude:continue
        seen.add(f);todo+=calls[f]
    return seen

def base(symbol):return re.sub(r'\.(constprop|isra|part|cold)\.\d+','',re.sub(r'^__arm64_sys_','linux_',symbol))

def attribute(instructions,symbols,original=(),models=()):
    """Per-function instruction counts in first-execution order, and their kind against a slice."""
    functions=OrderedDict()
    for pc in instructions:
        name=symbols(pc);functions[name]=functions.get(name,0)+1
    kinds={f:'original' if base(f) in original else 'model' if base(f) in models else 'absent' for f in functions}
    return functions,kinds

def measure(capture,symbols,sources=None,replay=None):
    instructions,_=parse_trace((Path(capture)/'trace.txt').read_text());total=len(instructions)
    original,models=set(),set()
    if sources:
        original,models,calls=slice_functions(sources)
        ran={base(symbols(pc)) for pc in instructions};call_roots={f for f in calls if f.startswith('linux_')}
        roots=ran&call_roots
        live=set().union(*(reachable(calls,r) for r in roots)) if roots else set()
        for entry in ran&set(ENTRY_ROOTS):
            reached=reachable(calls,entry,call_roots-roots)
            if entry in reached:live|=reached|set(ENTRY_ROOTS[entry])
        original&=live;models&=live
    functions,kinds=attribute(instructions,symbols,original,models)
    result=dict(capture=str(capture),call=json.loads((Path(capture)/'capture.json').read_text())['call'],live_instructions=total,
        functions=[dict(function=f,instructions=n,kind=kinds[f]) for f,n in functions.items()])
    if sources:
        shares=Counter()
        for f,n in functions.items():shares[kinds[f]]+=n
        result['source_slice']=dict(sources=str(sources),**{k:dict(instructions=shares[k],share=shares[k]/total) for k in ('original','model','absent')})
    if replay:
        r=json.loads((Path(replay)/'report.json').read_text());k=r['kernel_instructions']
        result['binary_replay']=dict(replay=str(replay),status=r['status'],instructions=k['replay'],from_kernel_image=k['from_kernel_image'],
            authentic_share=k['from_kernel_image']/total if r['status']=='equivalent' else 0.0)
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--capture',type=Path,required=True);p.add_argument('--symbols',type=Path,required=True)
    p.add_argument('--slice-sources',type=Path);p.add_argument('--replay',type=Path);p.add_argument('--functions',action='store_true')
    a=p.parse_args();r=measure(a.capture,Symbols(a.symbols),a.slice_sources,a.replay)
    line='%s: %d live kernel instructions'%(r['capture'],r['live_instructions'])
    if 'source_slice' in r:s=r['source_slice'];line+='; source slice original %.0f%%, model %.0f%%, absent %.0f%%'%tuple(100*s[k]['share'] for k in ('original','model','absent'))
    if 'binary_replay' in r:b=r['binary_replay'];line+='; binary replay %s, authentic %.1f%%'%(b['status'],100*b['authentic_share'])
    print(line)
    if a.functions:
        for f in r['functions']:print('  %6d  %-8s %s'%(f['instructions'],f['kind'],f['function']))

if __name__=='__main__':main()
