#!/usr/bin/env python3
"""Check a KLEE state-discovery result by concrete replay of the reduced slice.

Input is a `klee_state_discovery.py` output directory and the boundary, slice
and binding it was computed from. Variants of the captured pre-state run, one
after another, in one freestanding AArch64 image under QEMU (original slice
bodies, reviewed models, no kernel image):

- sufficiency: every symbolic input the discovery found unused is randomized
  at once. Outputs with recorded dependencies must equal the full-machine
  observation; every other field must keep its (variant) pre-state value.
- KTest cross-check: each in-domain KLEE test, with the driver's domain shaping
  applied, must produce the result, model fault and outputs KLEE computed for
  it, so KLEE's host-bitcode semantics agree with the compiled AArch64 code.
- necessity: each required input alone takes values from the in-domain KTests
  and boundary/random values; it is demonstrated when some variant diverges
  from the observation. An input the observed call left unchanged is expected
  to keep its varied value, so reappearing in its own output demonstrates
  nothing. A required input that is not demonstrated is reported,
  not failed: requirements are the union over all in-domain paths, and the
  observed path need not reach the others.

When the exploration stopped with partial paths, `required` is a lower bound and
no input is proven unused, so no sufficiency variants run and every observed
output may change. The other checks still run, and status `partial` means they
agree.
"""
import argparse,json,random,re,shutil,tempfile
from copy import deepcopy
from pathlib import Path
from reduced_boundary_replay import INPUTS,state_source,capture_header,execute,run,sha
from klee_state_discovery import ktest_values
from svc_boundary import FORMAT as OBSERVATION

FORMAT='osrec-klee-state-validation-v1'

def field_sizes(directory,names):
    """Byte size of every symbolic input and observed output, from a KTest (it lists every object)."""
    objects=ktest_values(next(Path(directory).glob('test*.ktest')))
    return {(k[0],v):len(objects[k]) for k,v in names.items() if k in objects}

def file_of(state):
    """A state's file data; a variant that varies a released file's fields starts them at zero."""
    return state.get('file_data') or dict(size=0,bytes='00'*64)

def set_input(state,objects,field,value):
    """Write one discovery input (scalar, pool member, file data, user object or argument) into a state copy."""
    m=re.fullmatch(r'(\w+)\[(\d+)\]\.(\w+(?:\.\w+)*)',field)
    if field.startswith('argument:'):state['_arguments'][int(field.split(':')[1])]=value
    elif m and m.group(1)!='files' and field not in state['scalars']:state['pool'][int(m.group(2))][m.group(3)]=value
    elif field=='file_data.bytes':state['file_data']['bytes']=value.hex()
    elif field=='file_data.size':state['file_data']['size']=value
    elif field.startswith('user_object.'):
        o=next(o for o in objects if o['object_id']==int(field.split('.')[1]));o['bytes']=value.hex()
    else:state['scalars'][field]=value

def get_input(state,objects,field):
    m=re.fullmatch(r'(\w+)\[(\d+)\]\.(\w+(?:\.\w+)*)',field)
    if field.startswith('argument:'):return state['_arguments'][int(field.split(':')[1])]
    if m and m.group(1)!='files' and field not in state['scalars']:return state['pool'][int(m.group(2))][m.group(3)]
    if field=='file_data.bytes':return bytes.fromhex(file_of(state)['bytes'])
    if field=='file_data.size':return file_of(state)['size']
    if field.startswith('user_object.'):return bytes.fromhex(next(o for o in objects if o['object_id']==int(field.split('.')[1]))['bytes'])
    return state['scalars'][field]

def shaping_of(report):
    """The driver's shaping steps per input, in its order: fold into a range, then max(v, low)."""
    steps={}
    for field,(low,high) in report['ranged_inputs'].items():
        if field not in report['fixed_by_binding']:steps.setdefault(field,[]).append(('range',low,high))
    for item in report['invariants']['assumed']:
        m=re.fullmatch(r'(\S+)>=(-?\d+)',item)
        if m:steps.setdefault(m.group(1),[]).append(('min',int(m.group(2))))
    for i,(low,high) in report.get('symbolic_arguments',{}).items():steps['argument:%s'%i]=[('range',low,high)]
    return steps

def shaped(field,raw,size,shaping):
    """The value the KLEE driver gave the code for a raw KTest input."""
    if field.startswith(('user_object.','file_data.bytes')):return raw
    v=int.from_bytes(raw,'little');bits=8*size;mask=(1<<bits)-1
    for step in shaping.get(field,()):
        if step[0]=='range':
            low,high=step[1],step[2]
            if not low<=v<=high:v=(low+v%(high-low+1))&mask
        else:
            signed=v-(1<<bits) if v>>(bits-1)&1 else v
            if signed<step[1]:v=step[1]&mask
    return v&mask

def ktest_inputs(values,names):
    """KTest objects by input field. Outputs share field names, so only `s` arrays are inputs."""
    return {v:values[k] for k,v in names.items() if k.startswith('s') and k in values}

def random_value(rng,size,field,domains):
    if field.startswith(('user_object.','file_data.bytes')):return bytes(rng.randrange(256) for _ in range(size))
    bits=8*size;choices=[0,1,2,(1<<bits)-1,1<<(bits-1),(1<<(bits-1))-1,rng.randrange(1<<bits),rng.randrange(1,256)]
    v=rng.choice(choices)
    if field in domains:
        low,high,signed=domains[field]
        if high is None:v=rng.choice([low,low+1,low+rng.randrange(1,1<<min(bits-2,30)),(1<<(bits-1))-1 if signed else (1<<bits)-1])
        else:v=rng.randrange(low,high+1)
    return v

def domains_of(report):
    out={'argument:%s'%i:(low,high,False) for i,(low,high) in report.get('symbolic_arguments',{}).items()}
    for item in report['invariants']['assumed']:
        m=re.fullmatch(r'(\S+)>=(-?\d+)',item)
        if m:out[m.group(1)]=(int(m.group(2)),None,True)
    for field,(low,high) in report['ranged_inputs'].items():
        if field in report['fixed_by_binding']:continue
        if field in out:low=max(low,out[field][0])
        out[field]=(low,high,False)
    return out

def generate(variants,binding,boundary,objects):
    """One image: restore, bind variant v, dispatch, export; repeated for every variant."""
    exported=None;binds=[];exports=None
    for i,(state,memory) in enumerate(variants):
        lines,fields,export=state_source(state,binding)
        if exported is None:exported,exports=fields,export
        elif fields!=exported:raise ValueError('variant changes the exported field list')
        binds.append('static void bind_%d(struct osrec_kernel_context *ctx)\n{\n%s\n}\n'%(i,'\n'.join(lines)))
    size=sum(o['size'] for o in objects);count=len(variants)
    regions=',\n'.join('    {UINT64_C(%d),osrec_live_memory+%d,%d,%d,%d}'%(o['address'],sum(p['size'] for p in objects[:i]),o['size'],o['permissions'],o['object_id']) for i,o in enumerate(objects))
    memory_in=',\n'.join('    {%s}'%(','.join(map(str,m)) or '0') for _,m in variants)
    arguments_in=',\n'.join('    {%s}'%','.join('UINT64_C(%d)'%(a&(1<<64)-1) for a in state['_arguments']) for state,_ in variants)
    return '''#include "slice_context.h"
#include "slice_dispatch.h"
/* Generated validation variants of one live SVC boundary pre-state. */
#define FIELDS %d
#define VARIANTS %d
#define BYTES %d
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
uint64_t osrec_post[VARIANTS][FIELDS];
unsigned char osrec_memory_out[VARIANTS][BYTES ? BYTES : 1],osrec_file_post[VARIANTS][64];
int64_t osrec_raw[VARIANTS];
uint32_t osrec_fault[VARIANTS];
unsigned char osrec_live_memory[BYTES ? BYTES : 1];
static const unsigned char memory_in[VARIANTS][BYTES ? BYTES : 1]={
%s
};
static struct osrec_kernel_context context;
static const struct osrec_user_region regions[%d]={
%s
};
static const uint64_t arguments_in[VARIANTS][6]={
%s
};
__attribute__((noinline)) void osrec_boundary_done(void){for(;;)__asm__ volatile("wfe");}
__attribute__((noinline)) void replay_fault(void){osrec_result[2]=3;osrec_boundary_done();}
static void osrec_live_put(uint64_t *out,const void *p,size_t n){uint64_t v=0;for(size_t i=0;i<n && i<8;++i)v|=(uint64_t)((const unsigned char *)p)[i]<<(8*i);*out=v;}
%s
static void (*const binds[VARIANTS])(struct osrec_kernel_context *)={%s};
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
    for(unsigned v=0;v<VARIANTS;++v){
        osrec_result[3]=v;
        osrec_context_restore(&context);binds[v](&context);
        for(unsigned i=0;i<BYTES;++i)osrec_live_memory[i]=memory_in[v][i];
        context.active_memory=(struct osrec_user_memory){regions,%d};
        uintptr_t arguments[6];for(unsigned i=0;i<6;++i)arguments[i]=(uintptr_t)arguments_in[v][i];
        osrec_raw[v]=OSREC_ROOT_DISPATCH(&context,UINT64_C(%d),arguments);
        context.active_memory=(struct osrec_user_memory){0};
        export(&context,osrec_post[v],osrec_file_post[v]);
        for(unsigned i=0;i<BYTES;++i)osrec_memory_out[v][i]=osrec_live_memory[i];
        osrec_fault[v]=(uint32_t)context.model_fault;
    }
    osrec_result[4]=0;osrec_result[5]=0;osrec_result[2]=2;
    osrec_boundary_done();
}
'''%(len(exported),count,size,memory_in,max(len(objects),1),regions or '    {0}',arguments_in,
        ''.join(binds),','.join('bind_%d'%i for i in range(count)),'\n'.join(exports),len(objects),boundary['call']['number']),exported

class Setup:
    """Checked inputs shared by validation and fault-site discovery."""
    def __init__(self,discovery,boundary,slice_dir,binding):
        self.discovery=discovery=Path(discovery);self.report=report=json.loads((discovery/'report.json').read_text())
        self.names=json.loads((discovery/'names.json').read_text())
        self.obs=obs=json.loads(Path(boundary).read_text());binding_raw=Path(binding).read_bytes();self.binding=json.loads(binding_raw)
        if obs.get('format')!=OBSERVATION:raise ValueError('unsupported boundary observation')
        if sha(Path(boundary).read_bytes())!=report['boundary_sha256']:raise ValueError('discovery was computed from another boundary')
        if sha(binding_raw)!=obs['binding_sha256']:raise ValueError('binding differs from the one used for observation')
        self.slice_dir=slice_dir=Path(slice_dir).resolve();manifest=json.loads((slice_dir/'manifest.json').read_text())
        if sha((slice_dir/'manifest.json').read_bytes())!=report['slice']['manifest_sha256']:raise ValueError('discovery was computed from another slice')
        for n in INPUTS:
            if sha((slice_dir/'sources'/n).read_bytes())!=manifest['source_hashes'].get(n):raise ValueError('slice source differs from its manifest: '+n)
        self.pre=obs['kernel_pre'];self.post=obs['kernel_post'];self.objects=obs['pre']['user_objects'];self.returned=obs['returned']
        self.sizes=field_sizes(discovery/'klee',self.names);self.domains=domains_of(report);self.shaping=shaping_of(report);self.inputs=report['symbolic_inputs']
    def variant(self,changes):
        state=deepcopy(self.pre);objs=deepcopy(self.objects)
        state['_arguments']=list(self.obs['call']['arguments'][:6])+[0]*(6-len(self.obs['call']['arguments']))
        pool=self.binding['descriptors']['pool']
        for field in changes:
            # A released file still has context fields, restored as zeros (object_id is the
            # entry's own class); KLEE varies them, so a variant spells those values out.
            m=re.fullmatch(re.escape(pool)+r'\[(\d+)\]\.\w+(?:\.\w+)*',field)
            if m and state['pool'][int(m.group(1))] is None:
                i=int(m.group(1));state['pool'][i]={**{k:0 for k in self.binding['descriptors']['members']},'object_id':i+1}
            if field.startswith('file_data.') and not state.get('file_data'):state['file_data']=dict(size=0,bytes='00'*64)
        for field,value in changes.items():set_input(state,objs,field,value)
        return state,objs
    def ktest_changes(self,test):
        """The driver's (shaped) input values of one KLEE test."""
        by_field=ktest_inputs(ktest_values(self.discovery/'klee'/(test+'.ktest')),self.names)
        return {f:shaped(f,by_field[f],self.sizes[('s',f)],self.shaping) for f in self.inputs if f in by_field}
    def run(self,built,llvm_bin,qemu,timeout,keep=None,debug=False,stops=None):
        """Build one image over the variants, run it under QEMU and collect per-variant outcomes."""
        memory_of=lambda objs:b''.join(bytes.fromhex(o['bytes']) for o in objs)
        with tempfile.TemporaryDirectory(prefix='osrec-klee-validation-') as name:
            stage=Path(name);sources=stage/'sources';sources.mkdir()
            for n in INPUTS:(sources/n).parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(self.slice_dir/'sources'/n,sources/n)
            source,exported=generate([(s,memory_of(o)) for s,o in built],self.binding,self.obs,self.objects)
            (sources/'validation_driver.c').write_text(source);(sources/'capture.h').write_text(capture_header(self.pre))
            # Diagnostics build at -O0 with debug lines so every model call is a real, symbolizable call.
            flags=['--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align','-std=c11','-O0' if debug else '-O1',*(['-g'] if debug else []),
                '-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-I'+str(sources)]
            elf=stage/'validation.elf'
            run([llvm_bin/'clang',*flags,'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),*[sources/n for n in ('start.S','validation_driver.c','syscalls.c','models.c','slice_runtime.c','slice_bytes.c')],'-o',elf])
            size=sum(o['size'] for o in self.objects);count=len(built);fields=len(exported)
            def collect(r,symbols):
                def block(name,n):return r.read(symbols[name],n)
                words=block('osrec_post',8*count*fields)
                return dict(post=[[int.from_bytes(words[8*(v*fields+i):8*(v*fields+i)+8],'little') for i in range(fields)] for v in range(count)],
                    memory=[block('osrec_memory_out',count*max(size,1))[v*max(size,1):v*max(size,1)+size] for v in range(count)],
                    file=[block('osrec_file_post',count*64)[64*v:64*v+64] for v in range(count)],
                    results=[int.from_bytes(block('osrec_raw',8*count)[8*v:8*v+8],'little') for v in range(count)],
                    fault=[int.from_bytes(block('osrec_fault',4*count)[4*v:4*v+4],'little') for v in range(count)])
            x=execute(elf,qemu,llvm_bin,timeout,collect,stops)
            x['elf_sha256']=sha(elf.read_bytes());x['exported']=exported
            if keep:
                keep.mkdir(parents=True)
                for n in ('validation_driver.c',):shutil.copyfile(sources/n,keep/n)
                shutil.copyfile(elf,keep/'validation.elf')
            return x

def symbolize(llvm_bin,elf,addresses):
    """Function, file and line for each code address (llvm-symbolizer)."""
    r=run([llvm_bin/'llvm-symbolizer','--obj='+str(elf),'--functions=linkage','--no-inlines',*['0x%x'%a for a in addresses]])
    blocks=[b for b in r.stdout.strip().split('\n\n')]
    out={}
    for a,block in zip(addresses,blocks):
        lines=block.splitlines();function=lines[0] if lines else '?';where=lines[1] if len(lines)>1 else '?'
        m=re.match(r'(.*):(\d+):(\d+)$',where)
        out[a]=dict(function=function,file=Path(m.group(1)).name if m else where,line=int(m.group(2)) if m else None)
    return out

def kept_outputs(per_path,observed,result):
    """Observed outputs that every in-domain path with the observed result leaves unchanged.

    Sufficiency variants vary only inputs no in-domain condition reads, so they follow the observed
    path: such an output keeps its variant value, even where other paths write it. A path with
    data-dependent outputs (or a data-dependent result) may change anything.
    """
    def result_of(p):
        v=(p.get('outputs') or {}).get('result')
        return None if v in (None,'unchanged') else int.from_bytes(bytes.fromhex(v),'little')
    matching=[p for p in per_path if p.get('analyzed',True) and p.get('fault')=='never' and not p['errors']
              and result_of(p) in (None,result&(1<<64)-1)]
    return {f for f in observed if matching and all((p.get('outputs') or {}).get(f)=='unchanged' for p in matching)}

def validate(discovery,boundary,slice_dir,binding,out,llvm_bin,qemu,variants=24,seed=1,timeout=300):
    out=Path(out).resolve()
    if out.exists():raise FileExistsError(out)
    s=Setup(discovery,boundary,slice_dir,binding);discovery=s.discovery;report=s.report;names=s.names;obs=s.obs;b=s.binding
    pre,post,objects,returned,sizes,domains,inputs=s.pre,s.post,s.objects,s.returned,s.sizes,s.domains,s.inputs
    rng=random.Random(seed)
    # Split inputs are not decided by the discovery: they are neither randomized as unused nor
    # assumed required, and the necessity check below decides them.
    required=set(report['required'])|set(report.get('split_inputs',[]));unused=[f for f in inputs if f not in required]
    observed=set(report['observed_post_fields']);unchanged=set(report['unchanged_outputs'])
    # A stopped path may read any input and write any output: nothing is proven unused or kept.
    incomplete=bool(report.get('required_is_lower_bound'))
    kept=set() if incomplete else kept_outputs(report['per_path'],observed,returned['result'])
    if incomplete:unchanged=set()
    # An observed output that may change takes the observed post value; any other field keeps its pre value.
    may_change=lambda field:field in observed and field not in unchanged and field not in kept
    pool=b['descriptors']['pool'];slots=b['descriptors']['slots']
    plan=[]
    # Variant 0 is the observation itself.
    plan.append(dict(kind='observed',changes={}))
    for _ in range(0 if incomplete else variants):
        plan.append(dict(kind='sufficiency',changes={f:random_value(rng,sizes[('s',f)],f,domains) for f in unused}))
    inside=[p['test'] for p in report['per_path'] if p.get('analyzed',True) and p.get('fault')=='never' and not p['errors']]
    tests={}
    for test in inside:
        changes=s.ktest_changes(test);tests[test]=changes;plan.append(dict(kind='ktest',test=test,changes=changes))
    base,_=s.variant({})
    for f in sorted(required):
        seen=set();candidates=[]
        for test in inside:
            v=tests[test][f]
            key=v if isinstance(v,int) else bytes(v)
            if key!=(get_input(base,objects,f) if not isinstance(v,int) else get_input(base,objects,f)&((1<<8*sizes[('s',f)])-1)) and key not in seen:seen.add(key);candidates.append(v)
        if not f.startswith(('user_object.','file_data.bytes')):
            bits=8*sizes[('s',f)];low,high,signed=domains.get(f,(0,None,False))
            for v in ((1<<(bits-1))-1 if signed else (1<<bits)-1,low if low is not None else 0):
                if (high is None or v<=high) and v not in candidates:candidates.insert(0,v)
        for _ in range(64):
            if len(candidates)>=8:break
            v=random_value(rng,sizes[('s',f)],f,domains)
            if v not in candidates:candidates.append(v)
        for v in candidates[:12]:plan.append(dict(kind='necessity',field=f,changes={f:v}))
    built=[s.variant(p['changes']) for p in plan]
    x=s.run(built,llvm_bin,qemu,timeout,keep=out)
    elf_sha=x['elf_sha256'];exported=x['exported']
    # Expected values per variant.
    def mask(field,value):
        s=sizes.get(('o',field)) or sizes.get(('s',field))
        return value&((1<<8*s)-1) if s and isinstance(value,int) else value
    def live_post(field):
        if field.startswith(slots+'['):i=int(field[len(slots)+1:-1]);return post['slots'][i] if i<len(post['slots']) else 0
        if field.startswith(pool+'['):
            i=int(field[len(pool)+1]);m=field.split('.',1)[1];o=post['pool'][i]
            return {'object_id':i+1,'f_count':0}.get(m) if o is None else o[m]
        if field=='file_data.size':return file_of(post)['size']
        return post['scalars'].get(field)
    def pre_value(state,field):
        if field.startswith(slots+'['):i=int(field[len(slots)+1:-1]);return state['slots'][i] if i<len(state['slots']) else 0
        if field.startswith(pool+'['):
            i=int(field[len(pool)+1]);m=field.split('.',1)[1];o=state['pool'][i]
            return {'object_id':i+1,'f_count':0}.get(m) if o is None else o[m]
        if field=='file_data.size':return file_of(state)['size']
        return state['scalars'][field]
    live_bytes=b''.join(bytes.fromhex(o['bytes']) for o in returned['user_objects'])
    def predicted(state,objs):
        """Observation-based prediction for a variant on the observed path."""
        values=[mask(f,live_post(f) if may_change(f) else pre_value(state,f)) for f in exported]
        file=bytes.fromhex(file_of(post)['bytes']) if may_change('file_data.bytes') else bytes.fromhex(file_of(state)['bytes'])
        memory=b''.join(bytes.fromhex(r['bytes']) if may_change('user_object.%d'%o['object_id']) else bytes.fromhex(o['bytes']) for o,r in zip(objs,returned['user_objects']))
        return dict(raw=returned['result']&(1<<64)-1,fault=0,post=values,file=file.ljust(64,b'\0')[:64],memory=memory)
    def from_ktest(test,state,objs):
        """KLEE's own outputs for a KTest; fields KLEE did not observe keep their pre value."""
        values=ktest_values(discovery/'klee'/(test+'.ktest'));outs={v:values[k] for k,v in names.items() if k.startswith('o') and k in values}
        word=lambda f:int.from_bytes(outs[f],'little')
        post_values=[mask(f,word(f)) if f in outs else mask(f,pre_value(state,f)) for f in exported]
        file=outs['file_data.bytes'] if 'file_data.bytes' in outs else bytes.fromhex(file_of(state)['bytes'])
        memory=b''.join(outs.get('user_object.%d'%o['object_id'],bytes.fromhex(o['bytes'])) for o in objs)
        return dict(raw=word('result')&(1<<64)-1,fault=word('model_fault'),post=post_values,file=bytes(file).ljust(64,b'\0')[:64],memory=memory)
    def differences(want,v):
        got=dict(raw=x['results'][v],fault=x['fault'][v],post=x['post'][v],file=x['file'][v],memory=x['memory'][v]);out=[]
        for key in ('raw','fault','file','memory'):
            if want[key]!=got[key]:out.append(dict(field=key,expected=want[key].hex() if isinstance(want[key],bytes) else want[key],replayed=got[key].hex() if isinstance(got[key],bytes) else got[key]))
        for f,w,g in zip(exported,want['post'],got['post']):
            if w is not None and w&((1<<64)-1)!=g:out.append(dict(field=f,expected=w,replayed=g))
        return out
    def untouched(want,field,state,objs):
        """A varied input the observed call left unchanged is expected to keep its varied value:
        reappearing in its own output is no evidence that the call uses it."""
        if field=='file_data.bytes':
            if file_of(pre)['bytes']==file_of(post)['bytes']:want['file']=bytes.fromhex(file_of(state)['bytes']).ljust(64,b'\0')[:64]
        elif field.startswith('user_object.'):
            parts=[bytes.fromhex(r['bytes']) for r in returned['user_objects']]
            for i,(o,v) in enumerate(zip(objects,objs)):
                if 'user_object.%d'%o['object_id']==field and o['bytes']==returned['user_objects'][i]['bytes']:parts[i]=bytes.fromhex(v['bytes'])
            if may_change(field):want['memory']=b''.join(parts)
        elif field in exported and pre_value(base,field)==live_post(field):
            want['post'][exported.index(field)]=mask(field,pre_value(state,field))
        return want
    rows=[]
    for v,(p,(state,objs)) in enumerate(zip(plan,built)):
        want=from_ktest(p['test'],state,objs) if p['kind']=='ktest' else predicted(state,objs)
        if p['kind']=='necessity':want=untouched(want,p['field'],state,objs)
        found=differences(want,v)
        # Without file data (the file was released), the context keeps the restore's defaults:
        # nothing observed them, so, as in the reduced replay, they are not compared.
        if not state.get('file_data'):found=[d for d in found if d['field'] not in ('file','file_data.size')]
        rows.append(dict(index=v,kind=p['kind'],field=p.get('field'),test=p.get('test'),differences=found))
    necessity={}
    for r in rows:
        if r['kind']=='necessity':
            d=necessity.setdefault(r['field'],dict(variants=0,diverging=0));d['variants']+=1;d['diverging']+=bool(r['differences'])
    summary=dict(observed_equivalent=not rows[0]['differences'],
        sufficiency=dict(variants=sum(1 for r in rows if r['kind']=='sufficiency'),diverging=sum(1 for r in rows if r['kind']=='sufficiency' and r['differences']),randomized_inputs=unused),
        ktest=dict(tests=len(inside),diverging=sum(1 for r in rows if r['kind']=='ktest' and r['differences'])),
        necessity=dict(fields=necessity,demonstrated=sorted(f for f,d in necessity.items() if d['diverging']),not_demonstrated=sorted(f for f,d in necessity.items() if not d['diverging'])))
    if incomplete:summary['sufficiency']['skipped']='exploration incomplete: unused inputs are not proven unused'
    ok=summary['observed_equivalent'] and not summary['sufficiency']['diverging'] and not summary['ktest']['diverging']
    result=dict(format=FORMAT,status=('partial' if incomplete else 'consistent') if ok else 'inconsistent',discovery=str(discovery.resolve()),discovery_report_sha256=sha((discovery/'report.json').read_bytes()),
        call=obs['call'],seed=seed,elf_sha256=elf_sha,**summary,variants=rows,
        scope='one observed boundary; sufficiency and necessity are tested on concrete variants, not proven')
    (out/'report.json').write_text(json.dumps(result,indent=2)+'\n')
    return result

def fault_sites(discovery,boundary,slice_dir,binding,out,llvm_bin,qemu,timeout=300):
    """Which reviewed-model assertion ends each always-faulting KLEE path.

    Every such KTest is replayed in one -O0 debug image; a breakpoint on
    osrec_kernel_linux_assert records the call site of the first failing
    assertion per variant, symbolized to the slice source line.
    """
    out=Path(out).resolve()
    if out.exists():raise FileExistsError(out)
    s=Setup(discovery,boundary,slice_dir,binding)
    tests=[p['test'] for p in s.report['per_path'] if p.get('fault')=='always']
    if not tests:raise ValueError('the discovery has no always-faulting paths')
    changes=[s.ktest_changes(t) for t in tests];built=[s.variant(c) for c in changes];first={}
    def stops(symbols):
        status=symbols['osrec_result']
        def on_assert(r):
            if r.register('x1')&0xffffffff:
                v=r.u(status+12,4)
                if v not in first:first[v]=r.register('x30')-4
        return {symbols['osrec_kernel_linux_assert']:on_assert}
    x=s.run(built,llvm_bin,qemu,timeout,keep=out,debug=True,stops=stops)
    where=symbolize(llvm_bin,out/'validation.elf',sorted(set(first.values())))
    source={n:(s.slice_dir/'sources'/n).read_text().splitlines() for n in ('models.c','syscalls.c')}
    groups={}
    for v,test in enumerate(tests):
        site=where.get(first.get(v)) if v in first else None
        key=(site['function'],site['file'],site['line']) if site else ('none','',None)
        g=groups.setdefault(key,dict(function=key[0],file=key[1],line=key[2],tests=[],replayed_fault=0))
        g['tests'].append(test);g['replayed_fault']+=x['fault'][v]==1
    for g in groups.values():
        lines=source.get(g['file']);g['source']=lines[g['line']-1].strip()[:240] if lines and g['line'] else None
        # Input values on the paths that reach this site: constant fields are listed, varying ones as ranges.
        values={}
        for test in g['tests']:
            for f,v in changes[tests.index(test)].items():
                if isinstance(v,int):values.setdefault(f,set()).add(v)
        live=lambda f:get_input(s.pre,s.objects,f)
        g['inputs']={f:(sorted(vs) if len(vs)<=4 else dict(min=min(vs),max=max(vs),distinct=len(vs))) for f,vs in sorted(values.items())
            if not (len(vs)==1 and next(iter(vs))==(live(f)&((1<<8*s.sizes[('s',f)])-1)))}
    result=dict(format=FORMAT+'-fault-sites',discovery=str(s.discovery.resolve()),call=s.obs['call'],faulting_paths=len(tests),
        unattributed=[t for v,t in enumerate(tests) if v not in first],replay_disagrees=[t for v,t in enumerate(tests) if x['fault'][v]!=1],
        sites=sorted(groups.values(),key=lambda g:-len(g['tests'])),elf_sha256=x['elf_sha256'])
    (out/'fault-sites.json').write_text(json.dumps(result,indent=2)+'\n')
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--discovery',type=Path,required=True,help='klee_state_discovery.py output directory')
    p.add_argument('--boundary',type=Path,required=True);p.add_argument('--slice',type=Path,required=True);p.add_argument('--binding',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--variants',type=int,default=24);p.add_argument('--seed',type=int,default=1)
    p.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));p.add_argument('--qemu',default='qemu-system-aarch64');p.add_argument('--timeout',type=int,default=300)
    p.add_argument('--fault-sites',action='store_true',help='attribute always-faulting KLEE paths to the model assertion that ends them')
    a=p.parse_args()
    if a.fault_sites:
        r=fault_sites(a.discovery,a.boundary,a.slice,a.binding,a.out,a.llvm_bin,a.qemu,a.timeout)
        print(json.dumps(dict(faulting_paths=r['faulting_paths'],unattributed=len(r['unattributed']),replay_disagrees=len(r['replay_disagrees']),
            sites=[dict(at='%s:%s %s'%(g['file'],g['line'],g['function']),paths=len(g['tests']),source=g['source']) for g in r['sites']]),indent=2));return
    r=validate(a.discovery,a.boundary,a.slice,a.binding,a.out,a.llvm_bin,a.qemu,a.variants,a.seed,a.timeout)
    print(json.dumps({k:r[k] for k in ('status','observed_equivalent','sufficiency','ktest','necessity')},indent=2))
    if r['status']=='inconsistent':raise SystemExit(1)

if __name__=='__main__':main()
