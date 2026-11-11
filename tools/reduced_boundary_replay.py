#!/usr/bin/env python3
"""Replay one observed SVC boundary through a reduced kernel slice and compare it.

Input is a `svc_boundary.py` observation and a published callable-slice port. The
Clang entry-state analyzer re-derives the root's footprint from the slice
sources under the profile's analysis contracts (external-memory boundaries and
declared field ranges); the footprint must have no blockers, every discovered
entry read must land on a schema field that the live binding supplies, and every
field range the proof used is checked against the captured pre- and post-state. The live pre-state is compiled into a freestanding AArch64
image together with the original slice bodies. QEMU runs it without a kernel,
disk or host service, and the slice's return value, user-object bytes and every
bound kernel field are compared with the full-machine observation.
"""
import argparse,hashlib,json,os,re,shutil,subprocess,tempfile
from pathlib import Path
from gdb_remote import Remote
from svc_boundary import FORMAT as OBSERVATION,free_port

ROOT=Path(__file__).resolve().parents[1];FORMAT='osrec-reduced-boundary-replay-v1'
INPUTS=('syscalls.c','models.c','model.h','slice_context.h','slice_dispatch.h','slice_runtime.c','slice_bytes.c','start.S','image.ld','checkpoint-policy.json','osrec/syscall_slice.h')
def sha(data):return hashlib.sha256(data).hexdigest()
def run(command,**kw):
    r=subprocess.run([str(c) for c in command],capture_output=True,text=True,timeout=kw.pop('timeout',300),**kw)
    if r.returncode:raise ValueError('command failed: '+' '.join(map(str,command[:3]))+'\n'+r.stderr[-4000:])
    return r

def node(policy,field):
    """Return the schema policy node for a dotted field, e.g. files.fdtab.fd[] (a descriptor slot).

    Below a transient leaf (a lock word, a model object, a pointer) the leaf itself is returned.
    """
    n=None
    for p in field.split('.'):
        name=re.sub(r'(\[\d*\])+$','',p)
        if n is None:n=policy['fields'][name]
        else:
            while n['policy']=='elements':n=n['element']
            if n['policy']=='transient':return n
            n=n['members'][name]
        for _ in re.findall(r'\[\d*\]',p):
            if n['policy']=='elements':n=n['element']
    return n

def normalize(path,policy,references=None):
    """Map an analyzer path such as `*(argument:ctx->a->b[0])` to the schema field it reads.

    `references` maps a bound pointer field (`kmalloc_caches[0][1]`) to the slice object the observed state
    binds it to: a reference whose policy admits several targets follows that one.

    Plain syscall arguments become `argument:NAME` (supplied by contract registers);
    anything else that cannot be placed in the schema ends in `?` and is uncovered. A read
    below a transient leaf keeps its sub-path (`inode_wb.list_lock`): it reads part of that leaf.
    """
    m=re.fullmatch(r'\*\((.*)\)',path)
    if m:return normalize(m.group(1),policy,references)
    if re.fullmatch(r'argument:[A-Za-z_]\w*',path) and path!='argument:ctx':return path
    if not path.startswith('argument:ctx->'):return path+'?'
    parts=re.split(r'->|\.',path[len('argument:ctx->'):]);field=n=None;concrete=None
    for i,p in enumerate(parts):
        # An array of arrays (kmalloc_caches[0][2]) has one subscript per dimension.
        name=re.sub(r'(\[\d+\])+$','',p);dims=len(re.findall(r'\[\d+\]',p[len(name):]))
        if field is None:
            if name not in policy['fields']:return path+'?'
            field=name;n=policy['fields'][name];concrete=p
        else:
            # Unwrap array elements and follow references until a record is reached:
            # a descriptor slot (elements of context references) leads into the file pool.
            while n['policy'] in ('elements','self_reference','context_reference'):
                if n['policy']=='elements':n=n['element'];field+='[]'
                elif n['policy']=='self_reference':field=n['target'];n=node(policy,field)
                else:
                    # Several targets are acceptable only as elements of one pool.
                    pools={re.sub(r'\[\d+\]','[]',t) for t in n['targets']}
                    bound=(references or {}).get(concrete)
                    if len(pools)!=1 and bound in n['targets']:pools={bound}
                    if len(pools)!=1:return field+'->*?'
                    field=pools.pop();n=node(policy,field);concrete=field
            if n['policy']=='transient':return field+''.join('.'+re.sub(r'\[\d+\]','[]',q) for q in parts[i:])
            if n.get('policy')!='members' or name not in n['members']:return field+'.'+p+'?'
            field+='.'+name;n=n['members'][name];concrete=(concrete or '')+'.'+p
        for _ in range(dims):
            field+='[]'
            if n['policy']=='elements':n=n['element']
    return field

def bound_fields(state,binding):
    fields=set(state['scalars'])|set(state['transient'])|{e['field'] for e in binding.get('embedded',[])}|set(state.get('references',{}))|set(state.get('pointers',{}))
    pool=binding['descriptors']['pool'];members=[*binding['descriptors']['members'],'object_id']
    fields|={pool+'[].'+m for m in members}|{binding['descriptors']['slots']+'[]'}
    related=binding['descriptors'].get('related',{})
    fields|=set(related.get('members',{}))|{l['field'] for l in related.get('links',[])}
    # A binding can bind the file size as a related member (`size_field`) instead of file_data.size.
    if 'file_data' in state:fields|={'file_data.bytes','file_data.bytes[]'}|(set() if binding['file_data'].get('size_field') else {'file_data.size'})
    # A union member that overlays bound members (SLUB's freelist_tid over freelist and tid) is bound with them.
    from live_kernel_binding import kmalloc_specs,kmalloc_field
    k=binding.get('kmalloc')
    for _,names,_ in (kmalloc_specs(k) if k else []):
        for overlay,members in k.get('overlays',{}).items():
            members=[kmalloc_field(m,names) for m in members]
            if set(members)<=fields|{f for f in state.get('pointers',{})}:fields.add(kmalloc_field(overlay,names))
    return {re.sub(r'\[\d+\]','[]',f) for f in fields}

def held_fields(state,binding):
    """(field, mask, value) of each schema field a live-checked precondition holds, per live class.

    The capture already rejected a live state where the precondition fails; the replay image
    checks that the model's value of the field, under the same mask, is the precondition's.
    """
    held=[]
    for item in binding['descriptors'].get('related',{}).get('preconditions',[]):
        if 'field' not in item:continue
        for i,o in enumerate(state['pool']):
            if o is not None and item.get('class',i+1)==i+1:held.append((item['field'].replace('[]','[%d]'%i),item.get('mask',(1<<64)-1),item['equals']&(1<<64)-1))
    return held

def covered(field,n,policy,sources):
    """The source ('live', 'held' or 'model') covering a schema field read, or None.

    A read below a covered leaf (a transient lock word or pointer) reads part of its value, and
    declared model state may name a whole object; a record read is covered when each of its
    leaves is, and a self reference is fixed structure.
    """
    for source,fields in sources:
        if field in fields:return source
    parts=field.split('.')
    for k in range(1,len(parts)):
        prefix='.'.join(parts[:k])
        for source,fields in sources:
            if prefix in fields and (source=='model' or node(policy,prefix)['policy'] not in ('members','elements')):return source
    if n['policy']=='self_reference':return 'live'
    if n['policy'] in ('members','elements'):
        children=[(field+'.'+k,m) for k,m in n['members'].items()] if n['policy']=='members' else [(field+'[]',n['element'])]
        found={covered(f,m,policy,sources) for f,m in children}
        if None in found:return None
        return 'model' if 'model' in found else 'held' if 'held' in found else 'live'
    return None

def check_ranges(assumptions,states,binding=None):
    """Each declared range the analyzer relied on must hold in the live states.

    A range is tied to bound live fields (`live state field F`, `live state fields F, G`; `pool[]`
    names every live entry) or to an unmasked precondition that holds a field (`live precondition
    F`): the capture checked it on each live object of its class, and its evidence is in the state.
    """
    # A record member (`files.fdtab.max_fds`) or a top-level array's elements (`kmalloc_size_index[]`).
    name=r'[A-Za-z_]\w*(?:\[\d*\](?:\.[A-Za-z_]\w*(?:\[\d*\])?)*|(?:\[\d*\])?(?:\.[A-Za-z_]\w*(?:\[\d*\])?)+)'
    checked=[]
    preconditions=[c for c in (binding or {}).get('descriptors',{}).get('related',{}).get('preconditions',[]) if 'field' in c]
    for a in assumptions:
        m=re.match(r'live state fields? (%s(?:, %s)*)|live precondition (%s)$'%(name,name,name),a['validated_by'])
        if not m:raise ValueError('state range is not tied to a live field: %s.%s'%(a['record'],a['field']))
        for label,state in states:
            if m.group(1):
                values=[]
                for f in m.group(1).split(', '):
                    live=[(k,v) for k,v in state['scalars'].items() if re.sub(r'\[\d+\]','[]',k)==f] if '[]' in f else [(f,state['scalars'].get(f))]
                    values+=live or [(f,None)]
            else:
                found=[c for c in preconditions if re.sub(r'\[\d+\]','[]',c['field'])==m.group(2)]
                if len(found)!=1 or 'mask' in found[0]:raise ValueError('range %s.%s needs one unmasked precondition holding %s'%(a['record'],a['field'],m.group(2)))
                c=found[0];values=[]
                for i,o in enumerate(state['pool']):
                    if o is None or c.get('class',i+1)!=i+1:continue
                    evidence=state.get('evidence',{}).get('precondition class %d %s'%(i+1,c['path']))
                    values.append((c['field'].replace('[]','[%d]'%i),evidence and evidence['raw']))
                if not values:raise ValueError('%s state has no live object for the precondition holding %s'%(label,m.group(2)))
            for field,value in values:
                low,high=a['min'],a['max']
                index=re.search(r'\[(\d+)\]$',field)
                for r in a.get('element_ranges',[]):
                    if index and r['indices'][0]<=int(index[1])<=r['indices'][1]:low,high=r['min'],r['max']
                if value is None or not low<=value<=high:
                    raise ValueError('%s state violates the analysis range %s.%s in [%d, %d]: %r'%(label,a['record'],a['field'],a['min'],a['max'],value))
                checked.append(dict(record=a['record'],field=a['field'],live=field,state=label,value=value,bounds=[low,high]))
    return checked

def check_arguments(assumptions,names,arguments):
    """Each root-argument range the analysis assumed must hold for the observed call (contract registers)."""
    checked=[];registers=[n for n in names if n!='ctx']
    for a in assumptions:
        if a['parameter'] not in registers:raise ValueError('argument range names no root argument: '+a['parameter'])
        value=arguments[registers.index(a['parameter'])]
        if not a['min']<=value<=a['max']:raise ValueError('observed argument %s=%d violates the analysis range [%d, %d]'%(a['parameter'],value,a['min'],a['max']))
        checked.append(dict(parameter=a['parameter'],value=value,bounds=[a['min'],a['max']]))
    return checked

def footprint(sources,root,policy,state,binding,clang,stage,contracts=None):
    database=[dict(directory=str(sources),file=str(sources/n),arguments=[str(clang),'--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-std=c11','-ffreestanding','-fno-builtin','-I'+str(sources),'-c',str(sources/n)]) for n in ('syscalls.c','models.c')]
    (stage/'compile_commands.json').write_text(json.dumps(database))
    # The analysis is a function of the root, the contracts and every source it parses; identical
    # inputs (boundaries of one root from one checkpoint) reuse one result. Large closures can take
    # longer than the default bound: OSREC_FOOTPRINT_TIMEOUT raises it.
    parsed=sorted(p for p in sources.rglob('*') if p.is_file() and (p.suffix=='.h' or p.name in ('syscalls.c','models.c')))
    key=sha(json.dumps([root,sha(Path(contracts).read_bytes()) if contracts else None,str(clang),*[sha(t.read_bytes()) for t in sorted((ROOT/'tools').glob('entry_state*.py'))],
        *[(str(p.relative_to(sources)),sha(p.read_bytes())) for p in parsed]]).encode())
    cache=ROOT/'build/footprint-cache'/(key+'.json')
    if cache.exists():shutil.copyfile(cache,stage/'entry-state.json')
    else:
        # Whole-syscall closures (the page cache under pread64) exceed the default call-context
        # and alias budgets, and a futex hash index selects one of 256 buckets (GUP-fast's walk, one of a
        # page table's 512 descriptors); all remain bounded, and exceeding them still blocks.
        run(['python3',ROOT/'tools/entry_state.py','--compile-commands',stage/'compile_commands.json','--source',sources/'syscalls.c','--closure-source',sources/'models.c','--root',root,'--clang',clang,'--out',stage/'entry-state.json',
             '--max-contexts','4000','--max-alias-paths','1024','--max-range-elements','512',
             *(['--boundaries',Path(contracts).resolve()] if contracts else [])],cwd=ROOT/'tools',timeout=int(os.environ.get('OSREC_FOOTPRINT_TIMEOUT','300')))
        cache.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(stage/'entry-state.json',cache)
    plan=json.loads((stage/'entry-state.json').read_text())['plans'][0];rows=[]
    # Fields the live binding supplies, fields a live-checked precondition holds at the model's
    # value, and reviewed model state the binding declares unobservable.
    sources=[('live',bound_fields(state,binding)),('held',{re.sub(r'\[\d+\]','[]',f) for f,_,_ in held_fields(state,binding)}),
             ('model',{re.sub(r'\[\d+\]','[]',f) for f in binding.get('model_state',{})})]
    from entry_state import fixed_global_read
    for read in plan['entry_reads']:
        # Reads of program constants (validated const-global evidence) are not entry state.
        if fixed_global_read(read,plan):continue
        field=normalize(read['path'],policy,{f:q['target'] for f,q in state.get('pointers',{}).items() if q.get('target')})
        if field.startswith('argument:'):rows.append(dict(path=read['path'],field=field,kind='register',covered=True,source='register'));continue
        n=None if field.endswith('?') else node(policy,field)
        kind='reference' if n and n['policy'] in ('self_reference','context_reference') else 'value'
        source=n and covered(field,n,policy,sources)
        rows.append(dict(path=read['path'],field=field,kind=kind,covered=bool(source),source=source))
    unique={(r['path'],r['field']):r for r in rows}.values()
    from collections import Counter
    return dict(root=root,entry_reads=sorted(unique,key=lambda r:r['path']),uncovered=sorted({r['field'] for r in unique if not r['covered']}),
        held=sorted({r['field'] for r in unique if r['source']=='held'}),model_state=sorted({r['field'] for r in unique if r['source']=='model'}),
        blockers=dict(Counter(b['kind'] for b in plan['blockers'])),state_range_assumptions=plan.get('state_range_assumptions',[]),
        argument_range_assumptions=plan.get('argument_range_assumptions',[]),allocation_summaries=plan.get('allocation_summaries',[]),
        root_arguments=[a['name'] for a in plan.get('arguments',[])],
        external_memory=sorted({x['path'] for x in plan.get('external_memory_accesses',[])}),
        proofs={k:len(plan.get(k,[])) for k in ('null_guard_proofs','masked_pointer_proofs','local_index_proofs','pointer_initialization_proofs')},
        minimality_proven=plan['minimality_proven'],completeness_proven=plan['completeness_proven'])

def c_value(value):return 'UINT64_C(%d)'%value
def state_source(state,binding):
    """C statements binding a live state into `ctx`, the exported field order and their export statements."""
    pool=binding['descriptors']['pool'];slots=binding['descriptors']['slots'];members=[*binding['descriptors']['members']]
    lines=[];exported=[]
    def assign(field,value):lines.append('    ctx->%s=(__typeof__(ctx->%s))%s;'%(field,field,c_value(value)))
    for field,value in state['scalars'].items():assign(field,value);exported.append(field)
    for field,value in state['transient'].items():assign(field,value)
    for e in binding.get('embedded',[]):lines.append('    ctx->%s=&ctx->%s;'%(e['field'],e['target']))
    # A global's array pointer names the slice pool the live array was bound into.
    for field,target in state.get('references',{}).items():lines.append('    ctx->%s=&ctx->%s;'%(field,target))
    # Related objects follow the pool's class layout, live or released.
    for link in binding['descriptors'].get('related',{}).get('links',[]):
        for i in range(len(state['pool'])):
            if link.get('class',i+1)==i+1:lines.append('    ctx->%s=&ctx->%s;'%(link['field'].replace('[]','[%d]'%i),link['target'].replace('[]','[%d]'%i)))
    for i,o in enumerate(state['pool']):
        for m in [*members,'object_id']:
            if o is None:assign('%s[%d].%s'%(pool,i,m),i+1 if m=='object_id' else 0)
            else:assign('%s[%d].%s'%(pool,i,m),o[m])
            exported.append('%s[%d].%s'%(pool,i,m))
    for fd in range(binding['descriptors']['capacity']):
        cls=state['slots'][fd] if fd<len(state['slots']) else 0
        lines.append('    ctx->%s[%d]=%s;'%(slots,fd,'&ctx->%s[%d]'%(pool,cls-1) if cls else '0'));exported.append('%s[%d]'%(slots,fd))
    data=bytes.fromhex(state['file_data']['bytes']) if state.get('file_data') else b''
    separate_size=not binding.get('file_data',{}).get('size_field')
    if data:
        if separate_size:assign('file_data.size',state['file_data']['size'])
        lines+=['    ctx->file_data.bytes[%d]=%d;'%(i,b) for i,b in enumerate(data)]
    if separate_size:exported.append('file_data.size')
    # Pointers that name a slice object (the kmalloc cache, its per-CPU copy, the freelist head and its slab)
    # point at that object when the live value is its live address and keep the raw value otherwise.
    pointers=state.get('pointers',{})
    for field,q in pointers.items():
        lines.append('    ctx->%s=%s;'%(field,'(__typeof__(ctx->%s))(void *)&ctx->%s'%(field,q['target']) if q['target'] is not None and q['value']==q['live'] else '(__typeof__(ctx->%s))(uintptr_t)%s'%(field,c_value(q['value']))));exported.append(field)
    export=[]
    # A slab object's word holding an address inside that object (a list head linked to itself) is the live address.
    objects={q['target']:q['live'] for q in pointers.values() if q['target'] is not None and '.' not in q['target'] and any(f.startswith(q['target']+'.words[') for f in exported)}
    for i,field in enumerate(exported):
        word=re.fullmatch(r'([A-Za-z_]\w*)\.words\[\d+\]',field)
        if word and word[1] in objects:
            o=word[1];export.append('    out[%d]=ctx->%s>=(uint64_t)(uintptr_t)&ctx->%s && ctx->%s<(uint64_t)(uintptr_t)(&ctx->%s+1) ? %s+(ctx->%s-(uint64_t)(uintptr_t)&ctx->%s) : ctx->%s;'%(i,field,o,field,o,c_value(objects[o]),field,o,field));continue
        if field in pointers and pointers[field]['target'] is None:export.append('    out[%d]=(uint64_t)(uintptr_t)ctx->%s;'%(i,field))
        elif field in pointers:
            q=pointers[field];export.append('    out[%d]=(uintptr_t)ctx->%s==(uintptr_t)&ctx->%s ? %s : (uint64_t)(uintptr_t)ctx->%s;'%(i,field,q['target'],c_value(q['live']),field))
        elif field.startswith(slots+'['):export.append('    out[%d]=ctx->%s ? (uint64_t)(ctx->%s-ctx->%s)+1 : 0;'%(i,field,field,pool))
        else:export.append('    osrec_live_put(&out[%d],&ctx->%s,sizeof(ctx->%s));'%(i,field,field))
    return lines,exported,export

def capture_header(state):
    scalars=state['scalars'];flags=[o['f_flags'] if o else 0 for o in state['pool']]
    # Credential identifiers are plain integers or kuid_t/kgid_t values (creds.uid.val).
    scalars={**{k[:-4]:v for k,v in scalars.items() if k.startswith('creds.') and k.endswith('.val')},**scalars}
    return '#ifndef OSREC_LIVE_CAPTURE_H\n#define OSREC_LIVE_CAPTURE_H\n/* Restore defaults for model.c, bound from the live boundary pre-state. */\n'+''.join('#define LINUX_INITIAL_%s %dU\n'%(k,v) for k,v in (
        ('UMASK',scalars['fs.umask']),('UID',scalars['creds.uid']),('EUID',scalars['creds.euid']),('SUID',scalars['creds.suid']),('GID',scalars['creds.gid']),('EGID',scalars['creds.egid']),('SGID',scalars['creds.sgid']),
        ('PID',scalars['task.pid']),('TGID',scalars['task.tgid']),('PPID',scalars['parent.tgid']),('FILE_FLAGS_0',flags[0]),('FILE_FLAGS_1',flags[1])))+'#endif\n'

def generate(state,binding,boundary,objects):
    lines,exported,export=state_source(state,binding)
    # Held fields keep the model's value; the image exports it under the precondition's mask.
    for field,mask,_ in held_fields(state,binding):
        export.append('    out[%d]=(uint64_t)(uintptr_t)ctx->%s&UINT64_C(%d);'%(len(exported),field,mask));exported.append(field)
    blob=b''.join(bytes.fromhex(o['bytes']) for o in objects)
    regions=',\n'.join('    {UINT64_C(%d),osrec_live_memory+%d,%d,%d,%d}'%(o['address'],sum(p['size'] for p in objects[:i]),o['size'],o['permissions'],o['object_id']) for i,o in enumerate(objects))
    source='''#include "slice_context.h"
#include "slice_dispatch.h"
/* Generated from one live SVC boundary observation; values are the bound pre-state. */
#define OSREC_LIVE_FIELDS %d
#define OSREC_LIVE_BYTES %d
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
volatile uint32_t osrec_model_fault;
uint64_t osrec_live_pre[OSREC_LIVE_FIELDS],osrec_live_post[OSREC_LIVE_FIELDS];
unsigned char osrec_live_memory[OSREC_LIVE_BYTES ? OSREC_LIVE_BYTES : 1]={%s};
unsigned char osrec_live_file_pre[64],osrec_live_file_post[64];
static struct osrec_kernel_context context;
static const struct osrec_user_region regions[%d]={
%s
};
static const uint64_t arguments_in[6]={%s};
__attribute__((__noinline__)) void osrec_boundary_done(void){for(;;)__asm__ volatile("wfe");}
__attribute__((__noinline__)) void replay_fault(void){osrec_result[2]=3;osrec_boundary_done();}
static void osrec_live_put(uint64_t *out,const void *p,size_t n){uint64_t v=0;for(size_t i=0;i<n && i<8;++i)v|=(uint64_t)((const unsigned char *)p)[i]<<(8*i);*out=v;}
static void bind(struct osrec_kernel_context *ctx)
{
%s
}
static void export(const struct osrec_kernel_context *ctx,uint64_t *out,unsigned char *file)
{
%s
    for(unsigned i=0;i<64;++i)file[i]=ctx->file_data.bytes[i];
}
/* Analyses start at the root: a slice that enters through its system call entry also provides a direct root dispatch. */
#ifndef OSREC_ROOT_DISPATCH
#define OSREC_ROOT_DISPATCH osrec_kernel_dispatch
#endif
void replay_main(void)
{
    osrec_result[0]=0x4f535243;osrec_result[1]=40;osrec_result[2]=1;
    osrec_context_restore(&context);bind(&context);export(&context,osrec_live_pre,osrec_live_file_pre);
    context.active_memory=(struct osrec_user_memory){regions,%d};
    uintptr_t arguments[6];for(unsigned i=0;i<6;++i)arguments[i]=(uintptr_t)arguments_in[i];
    int64_t raw=OSREC_ROOT_DISPATCH(&context,UINT64_C(%d),arguments);
    context.active_memory=(struct osrec_user_memory){0};
    /* A reviewed model that saw a broken invariant flags it; such a run is never equivalent. */
    osrec_model_fault=(uint32_t)context.model_fault;
    export(&context,osrec_live_post,osrec_live_file_post);
    osrec_result[4]=(uint32_t)raw;osrec_result[5]=(uint32_t)((uint64_t)raw>>32);osrec_result[2]=2;
    osrec_boundary_done();
}
'''%(len(exported),len(blob),','.join(map(str,blob)) or '0',max(len(objects),1),regions or '    {0}',','.join(c_value(a) for a in boundary['call']['arguments'][:6]+[0]*(6-len(boundary['call']['arguments']))),
        '\n'.join(lines),'\n'.join(export),len(objects),boundary['call']['number'])
    return source,capture_header(state),exported

def expected(state,exported,binding):
    """Live values per exported field; None marks fields of released (unobservable) objects."""
    pool=binding['descriptors']['pool'];slots=binding['descriptors']['slots'];values=[]
    # A held field of a class this state has released is unobservable.
    held={f:v for f,_,v in held_fields(state,binding)};every={f for f,_,_ in held_fields(dict(state,pool=[{}]*len(state['pool'])),binding)}
    for field in exported:
        if field in every:values.append(held.get(field))
        elif field.startswith(slots+'['):i=int(field[len(slots)+1:-1]);values.append(state['slots'][i] if i<len(state['slots']) else 0)
        elif field.startswith(pool+'['):
            i=int(field[len(pool)+1]);m=field.split('.',1)[1];o=state['pool'][i]
            values.append({'object_id':i+1,'f_count':0}.get(m) if o is None else o[m])
        elif field=='file_data.size':values.append(state['file_data']['size'] if state.get('file_data') else None)
        elif field in state.get('pointers',{}):values.append(state['pointers'][field]['value'])
        # A related object of a class released by the call is unobservable afterwards.
        else:values.append(state['scalars'].get(field))
    return values

def mismatches(exported,got,want):
    return [dict(field=f,reduced=g,full_vm=w) for f,g,w in zip(exported,got,want) if w is not None and g!=(w&(1<<64)-1)]
def file_mismatch(file_bytes,state):
    return [] if not state.get('file_data') or file_bytes.hex()==state['file_data']['bytes'] else [dict(field='file_data.bytes',reduced=file_bytes.hex(),full_vm=state['file_data']['bytes'])]

def execute(elf,qemu,llvm_bin,timeout,collect,stops=None):
    """Run a freestanding image to osrec_boundary_done. `stops(symbols)` may return extra
    breakpoint addresses with handlers called on each hit (the image then steps on)."""
    symbols={row.split()[0]:int(row.split()[2],16) for row in run([llvm_bin/'llvm-nm','--defined-only','--format=posix',elf]).stdout.splitlines() if len(row.split())>=3}
    port=free_port();command=[str(qemu),'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53','-accel','tcg','-smp','1','-m','64M','-nodefaults','-display','none','-monitor','none','-serial','none','-semihosting-config','enable=off','-device','loader,file=%s,cpu-num=0'%elf,'-S','-gdb','tcp:127.0.0.1:%d'%port]
    process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        r=Remote(port,timeout=timeout);r.breakpoint(symbols['osrec_boundary_done'])
        handlers=stops(symbols) if stops else {}
        for address in handlers:r.breakpoint(address)
        while True:
            r.resume();pc=r.wait(timeout)
            if pc==symbols['osrec_boundary_done']:break
            if pc not in handlers:raise ValueError('reduced image stopped elsewhere')
            handlers[pc](r);r.step()
        result=[r.u(symbols['osrec_result']+4*i,4) for i in range(6)]
        if result[0]!=0x4f535243 or result[1]!=40 or result[2]!=2:raise ValueError('reduced image did not complete: status %d'%result[2])
        collected=collect(r,symbols);r.socket.close()
        return dict(command=command,raw=result[4]|result[5]<<32,**collected)
    finally:
        process.kill();process.wait()

def replay(boundary,slice_dir,binding,out,llvm_bin,qemu,timeout=120,contracts=None):
    out=Path(out).resolve()
    if out.exists():raise FileExistsError(out)
    obs=json.loads(Path(boundary).read_text());binding_raw=Path(binding).read_bytes();b=json.loads(binding_raw)
    if obs.get('format')!=OBSERVATION:raise ValueError('unsupported boundary observation')
    if sha(binding_raw)!=obs['binding_sha256']:raise ValueError('binding differs from the one used for observation')
    slice_dir=Path(slice_dir).resolve();manifest=json.loads((slice_dir/'manifest.json').read_text())
    if manifest.get('kernel_image_sha256')!=obs['checkpoint']['kernel_sha256']:raise ValueError('slice port was not built against the observed kernel image')
    for n in INPUTS:
        if sha((slice_dir/'sources'/n).read_bytes())!=manifest['source_hashes'].get(n):raise ValueError('slice source differs from its manifest: '+n)
    roots={r['number']:r['function'] for r in manifest['port']['roots']}
    if obs['call']['number'] not in roots:raise ValueError('observed syscall has no slice root')
    root='osrec_kernel_'+roots[obs['call']['number']];policy=json.loads((slice_dir/'sources/checkpoint-policy.json').read_text())
    pre=obs['kernel_pre'];post=obs['kernel_post'];objects=obs['pre']['user_objects']
    with tempfile.TemporaryDirectory(prefix='osrec-reduced-boundary-') as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir()
        for n in INPUTS:(sources/n).parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(slice_dir/'sources'/n,sources/n)
        source,header,exported=generate(pre,b,obs,objects)
        (sources/'boundary_driver.c').write_text(source);(sources/'capture.h').write_text(header)
        found=footprint(sources,root,policy,pre,b,llvm_bin/'clang',stage,contracts)
        if found['blockers']:raise ValueError('footprint analysis is blocked: '+json.dumps(found['blockers']))
        if found['uncovered']:raise ValueError('discovered footprint has unbound fields: '+', '.join(found['uncovered']))
        found['state_range_checks']=check_ranges(found['state_range_assumptions'],[('pre',pre),('post',post)],b)
        found['argument_range_checks']=check_arguments(found['argument_range_assumptions'],found['root_arguments'],obs['call']['arguments'])
        if contracts:found['contracts_sha256']=sha(Path(contracts).read_bytes())
        # Automatics are initialized as the port's kernel initializes them (CONFIG_INIT_STACK_ALL_ZERO:
        # zero). A port that declares none gets a pattern, so a summarized array read before its
        # element is defined sees 0xAA bytes, not a stale value that could happen to match the capture.
        stack_init=manifest['port'].get('stack_init','none')
        flags=['--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align','-std=c11','-O1','-ftrivial-auto-var-init='+(stack_init if stack_init!='none' else 'pattern'),'-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-I'+str(sources)]
        elf=stage/'boundary.elf'
        run([llvm_bin/'clang',*flags,'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),*[sources/n for n in ('start.S','boundary_driver.c','syscalls.c','models.c','slice_runtime.c','slice_bytes.c')],'-o',elf])
        def collect(r,symbols):
            words=lambda name:[r.u(symbols[name]+8*i) for i in range(len(exported))]
            return dict(pre=words('osrec_live_pre'),post=words('osrec_live_post'),model_fault=r.u(symbols['osrec_model_fault'],4),memory=r.read(symbols['osrec_live_memory'],sum(o['size'] for o in objects)) if objects else b'',
                file_pre=r.read(symbols['osrec_live_file_pre'],64),file_post=r.read(symbols['osrec_live_file_post'],64))
        x=execute(elf,qemu,llvm_bin,timeout,collect)
        live_pre,live_post,memory,file_pre,file_post=x['pre'],x['post'],x['memory'],x['file_pre'],x['file_post']
        want_pre=expected(pre,exported,b);want_post=expected(post,exported,b)
        returned=b''.join(bytes.fromhex(o['bytes']) for o in obs['returned']['user_objects'])
        comparison=dict(result=dict(reduced=x['raw'],full_vm=obs['returned']['result']&(1<<64)-1),model_fault=x['model_fault'],
            restore_mismatches=mismatches(exported,live_pre,want_pre)+file_mismatch(file_pre,pre),
            post_mismatches=mismatches(exported,live_post,want_post)+file_mismatch(file_post,post),
            user_objects=dict(reduced=memory.hex(),full_vm=returned.hex()),
            changed_fields=[f for f,a,c in zip(exported,want_pre,want_post) if a!=c])
        comparison['equivalent']=not x['model_fault'] and comparison['result']['reduced']==comparison['result']['full_vm'] and not comparison['restore_mismatches'] and not comparison['post_mismatches'] and memory==returned
        publish=stage/'published';publish.mkdir();shutil.copytree(sources,publish/'sources');shutil.copyfile(elf,publish/'boundary.elf');shutil.copyfile(stage/'entry-state.json',publish/'entry-state.json')
        report=dict(format=FORMAT,status='equivalent' if comparison['equivalent'] else 'diverged',root=root,call=obs['call'],boundary_sha256=sha(Path(boundary).read_bytes()),
            slice=dict(path=str(slice_dir),port=manifest['port']['name'],manifest_sha256=sha((slice_dir/'manifest.json').read_bytes())),
            footprint=found,bound_fields=len(exported),comparison=comparison,elf_sha256=sha(elf.read_bytes()),qemu_command=x['command'],
            claims=dict(original_slice_bodies=True,kernel_image_needed=False,host_services=False,live_fields_from_btf=True,reviewed_models_retained=True,footprint_unblocked=True,automatic_initialization=stack_init if stack_init!='none' else 'pattern',
                standalone_application=False,joint_user_continuation=False,minimality_proven=False))
        (publish/'report.json').write_text(json.dumps(report,indent=2)+'\n');shutil.copytree(publish,out)
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--boundary',type=Path,required=True);p.add_argument('--slice',type=Path,required=True,help='published callable-slice directory (manifest.json, sources/)')
    p.add_argument('--binding',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--contracts',type=Path,help='analysis contracts: external-memory boundaries and live-checked field ranges')
    p.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));p.add_argument('--qemu',default='qemu-system-aarch64');p.add_argument('--timeout',type=int,default=120);a=p.parse_args()
    r=replay(a.boundary,a.slice,a.binding,a.out,a.llvm_bin,a.qemu,a.timeout,a.contracts)
    print(json.dumps(dict(status=r['status'],root=r['root'],result=r['comparison']['result'],changed_fields=r['comparison']['changed_fields'],uncovered=r['footprint']['uncovered']),indent=2))
    if r['status']!='equivalent':raise SystemExit(1)
if __name__=='__main__':main()
