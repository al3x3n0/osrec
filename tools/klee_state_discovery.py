#!/usr/bin/env python3
"""Discover which bound kernel state a slice root depends on, by symbolic execution.

Input is a `svc_boundary.py` observation and a published callable-slice port.
The live pre-state fixes the object graph (descriptor slots and embedded links);
every bound scalar field, the file bytes and the admitted user bytes become KLEE
symbolic inputs. Syscall arguments stay as observed unless `--symbolic-arg`
widens them. Each output (result, every bound post-state field, file and user
bytes) is observed through a fresh symbolic value constrained to equal it, so a
path's KQuery holds its path condition and its output expressions.

An input is required when it occurs in any constraint of any explored path that
stays inside the reviewed model domain: in a path condition (control dependence)
or an output equality (data dependence, including values copied unchanged).
Paths on which a reviewed model's domain assertion fired are reported apart.
Results hold for the observed object graph and the explored argument domain; a
bounded exploration that does not complete is reported as such.
"""
import argparse,json,re,shutil,subprocess,tempfile
from pathlib import Path
from reduced_boundary_replay import state_source,capture_header,INPUTS,normalize,footprint,sha
from svc_boundary import FORMAT as OBSERVATION

ROOT=Path(__file__).resolve().parents[1];FORMAT='osrec-klee-state-discovery-v1'

def run(command,**kw):
    r=subprocess.run([str(c) for c in command],capture_output=True,text=True,timeout=kw.pop('timeout',600),**kw)
    if r.returncode:raise ValueError('command failed: '+' '.join(map(str,command[:3]))+'\n'+r.stderr[-4000:])
    return r

def separate_members(header,members):
    """slice_context.h for the KLEE build, with each named context member in its own object.

    KLEE models one C object as one array: a store at a symbolic index (a file write
    at f_pos + i) makes every later read of the object an array query over all of its
    bytes. Moved out, the member becomes `T *osrec_separate_M` pointing at a separate
    global, and `#define M osrec_separate_M[0]` keeps every `ctx->M` access unchanged.
    The restore re-points it after zeroing the context. The layout differs only in the
    KLEE build; replaying the KTests on the original layout checks the results.
    """
    for m in members:
        found=re.search(r'^(\s*)((?:struct\s+)?\w+)\s+%s;$'%re.escape(m),header,re.M)
        if not found:raise ValueError('context member not found: '+m)
        indent,kind=found.group(1),found.group(2)
        header=header[:found.start()]+'%s%s *osrec_separate_%s;'%(indent,kind,m)+header[found.end():]
        end=header.index('};',found.start())+2
        header=header[:end]+'\nextern %s osrec_separate_%s_object;\n#define %s osrec_separate_%s[0]'%(kind,m,m,m)+header[end:]
        zero='((unsigned char *)ctx)[osrec_i]=0;'
        if zero not in header:raise ValueError('context restore does not zero the context')
        at=header.index(zero)+len(zero)
        header=header[:at]+'\n    ctx->osrec_separate_%s=&osrec_separate_%s_object;for(size_t osrec_j=0;osrec_j<sizeof(osrec_separate_%s_object);++osrec_j)((unsigned char *)&osrec_separate_%s_object)[osrec_j]=0;'%(m,m,m,m)+header[at:]
    return header

def slot_words(state,capacity):
    """Bit masks of the installed descriptor slots, one per 64-slot word."""
    words=[0]*max(1,(capacity+63)//64)
    for i,c in enumerate(state['slots'][:capacity]):
        if c:words[i//64]|=1<<(i%64)
    return words

def graph_invariants(contracts,binding,states):
    """Fields the observed descriptor graph determines or bounds (Linux fdtable invariants).

    Kinds: `slot_mask` (the open bitmap word equals the installed slots), `full_slot_words`
    (bit w set iff word w of the slot mask is full) and `at_most_first_free_slot` (a value
    bounded by the first free slot). Returns (fixed fields with reasons, upper bounds); every
    invariant must hold in every observed state, evaluated on that state's own slots.
    (close_on_exec has no such invariant: close leaves its bit set until the number is reused.)
    """
    capacity=binding['descriptors']['capacity'];fixed={};bounds={}
    for item in contracts.get('graph_invariants',[]):
        field,kind=item['field'],item['kind'];word=int(re.search(r'\[(\d+)\]$',field).group(1)) if field.endswith(']') else 0
        for label,state in states:
            words=slot_words(state,capacity);value=state['scalars'].get(field)
            free=next((i for i,c in enumerate(state['slots'][:capacity]) if not c),capacity)
            expected={'slot_mask':lambda:words[word]==value,'full_slot_words':lambda:value==sum(1<<w for w,x in enumerate(words) if x==(1<<64)-1),
                'at_most_first_free_slot':lambda:0<=value<=free}.get(kind)
            if expected is None:raise ValueError('unknown graph invariant kind: '+kind)
            if value is None or not expected():raise ValueError('%s state violates the graph invariant %s (%s): %r'%(label,field,kind,value))
        free=next((i for i,c in enumerate(states[0][1]['slots'][:capacity]) if not c),capacity)
        if kind in ('slot_mask','full_slot_words'):fixed[field]=item['reason']
        else:bounds[field]=(0,free)
    return dict(fixed=fixed,bounds=bounds)

def driver(state,binding,boundary,objects,symbolic_args,ranges=None,written=None,split=(),split_fields=None,separate=(),graph=None):
    """KLEE driver source, the symbolic-name table and the fields held concrete by binding preconditions.

    Binding `require`/`equals` scalars are preconditions of the reviewed model,
    not state to discover, so they stay concrete. Declared field ranges bound the
    corresponding symbolic inputs.
    """
    lines,exported,_=state_source(state,binding)
    slots=binding['descriptors']['slots'];names={};inputs=[];outputs=[];ranges=ranges or {}
    fixed=sorted(f for f,v in binding['scalars'].items() if 'require' in v or 'equals' in v)
    def name(kind,label):
        key='%s%d'%(kind,len(names));names[key]=label;return key
    def schema(field):return re.sub(r'\[\d+\]','[]',field)
    # A descriptor-table reference holds a file reference: referenced pool objects have f_count >= 1.
    pool=binding['descriptors']['pool'];referenced={c-1 for c in state['slots'] if c}
    invariants=['%s[%d].f_count>=1'%(pool,i) for i in sorted(referenced) if 'f_count' in binding['descriptors']['members']]
    for field in exported:
        if field.startswith(slots+'['):continue # pointer graph stays concrete
        if field not in fixed and field not in (graph or {}).get('fixed',{}):
            inputs.append('    symbolic_copy(&ctx->%s,sizeof(ctx->%s),"%s");'%(field,field,name('s',field)))
            # Domains are shaped by expressions, not assumptions, so no constraint mentions an
            # input unless the code under analysis uses it.
            if field in ranges:
                low,high=ranges[field]
                # Identity inside [low, high] and folded into it outside, without forking.
                inputs.append('    {uint64_t v=(uint64_t)ctx->%s,inside=v-UINT64_C(%d)<=UINT64_C(%d);ctx->%s=(__typeof__(ctx->%s))(v*inside+(UINT64_C(%d)+v%%UINT64_C(%d))*(1-inside));}'
                    %(field,low,high-low,field,field,low,high-low+1))
            if field+'>=1' in invariants:
                # Branch-free max(x, 1): a comparison value, not a fork.
                inputs.append('    ctx->%s+=(__typeof__(ctx->%s))(ctx->%s<1)*(1-ctx->%s);'%(field,field,field,field))
            if field in (split_fields or {}):
                # One path per value in [low, high], as for split arguments: an index computed
                # from the field (a file position) is then concrete, and KLEE never turns the
                # whole context into one symbolic update list. Other values stay symbolic.
                low,high=split_fields[field]
                inputs.append('    {uint64_t v=(uint64_t)ctx->%s;for(uint64_t c=UINT64_C(%d);c<=UINT64_C(%d);++c)if(v==c){ctx->%s=(__typeof__(ctx->%s))c;break;}}'%(field,low,high,field,field))
        # Fields outside the static write set cannot change (its writes are a sound over-approximation).
        if written is None or schema(field) in written:
            outputs.append('    observe(&ctx->%s,sizeof(ctx->%s),"%s");'%(field,field,name('o',field)))
    for slot in range(binding['descriptors']['capacity']):
        if written is not None and schema('%s[%d]'%(slots,slot)) not in written:continue
        field='%s[%d]'%(slots,slot)
        outputs.append('    {uint64_t v=ctx->%s ? (uint64_t)(ctx->%s-ctx->%s)+1 : 0;observe(&v,8,"%s");}'%(field,field,binding['descriptors']['pool'],name('o',field)))
    if state.get('file_data'):
        inputs.append('    symbolic_copy(ctx->file_data.bytes,sizeof(ctx->file_data.bytes),"%s");'%name('s','file_data.bytes'))
        if written is None or 'file_data.bytes[]' in written or 'file_data.bytes' in written:
            outputs.append('    observe(ctx->file_data.bytes,sizeof(ctx->file_data.bytes),"%s");'%name('o','file_data.bytes'))
    blob=b''.join(bytes.fromhex(o['bytes']) for o in objects)
    offset=0
    for o in objects:
        inputs.append('    symbolic_copy(memory+%d,%d,"%s");'%(offset,o['size'],name('s','user_object.%d'%o['object_id'])))
        outputs.append('    observe(memory+%d,%d,"%s");'%(offset,o['size'],name('o','user_object.%d'%o['object_id'])));offset+=o['size']
    arguments=list(boundary['call']['arguments'][:6])+[0]*(6-len(boundary['call']['arguments']))
    argument_lines=[]
    for index,(low,high) in symbolic_args.items():
        argument_lines+=['    symbolic_copy(&arguments[%d],sizeof(arguments[%d]),"%s");'%(index,index,name('s','argument:%d'%index)),
                         # Identity inside [low, high], like every other input domain.
                         '    {uint64_t v=arguments[%d],inside=v-UINT64_C(%d)<=UINT64_C(%d);arguments[%d]=v*inside+(UINT64_C(%d)+v%%UINT64_C(%d))*(1-inside);}'
                         %(index,low,high-low,index,low,high-low+1)]
        if index in split:
            # One path per value: the comparisons stay in the path condition (a control
            # dependence on the argument) and the call then runs with a concrete value, so
            # an index such as a descriptor is not a symbolic offset into the context.
            argument_lines.append('    {uint64_t v=arguments[%d];for(uint64_t c=UINT64_C(%d);c<=UINT64_C(%d);++c)if(v==c){arguments[%d]=c;break;}}'%(index,low,high,index))
    regions=',\n'.join('    {UINT64_C(%d),memory+%d,%d,%d,%d}'%(o['address'],sum(p['size'] for p in objects[:i]),o['size'],o['permissions'],o['object_id']) for i,o in enumerate(objects))
    source='''#include <klee/klee.h>
#include "slice_context.h"
#include "slice_dispatch.h"
/* Generated KLEE driver: live object graph, symbolic bound scalars, observed outputs. */
static struct osrec_kernel_context context;
%sstatic unsigned char memory[%d];
static const struct osrec_user_region regions[%d]={
%s
};
/* KLEE makes whole objects symbolic: each input and observation is its own exactly-sized object. */
static void symbolic_copy(void *p,size_t n,const char *name)
{
    unsigned char *value=__builtin_alloca(n);klee_make_symbolic(value,n,name);
    for(size_t i=0;i<n;++i)((unsigned char *)p)[i]=value[i];
}
static void observe(const void *p,size_t n,const char *name)
{
    /* One assumption per 8-byte word keeps the solver work per path small. */
    unsigned char *seen=__builtin_alloca(n);klee_make_symbolic(seen,n,name);
    for(size_t i=0;i<n;i+=8){
        uint64_t a=0,b=0;size_t m=n-i<8 ? n-i : 8;
        for(size_t j=0;j<m;++j){a|=(uint64_t)seen[i+j]<<(8*j);b|=(uint64_t)((const unsigned char *)p)[i+j]<<(8*j);}
        klee_assume(a==b);
    }
}
static void bind(struct osrec_kernel_context *ctx)
{
%s
}
static void symbolic(struct osrec_kernel_context *ctx)
{
%s
}
static void outputs(struct osrec_kernel_context *ctx)
{
%s
}
/* Analyses start at the root: a slice that enters through its system call entry also provides a direct root dispatch. */
#ifndef OSREC_ROOT_DISPATCH
#define OSREC_ROOT_DISPATCH osrec_kernel_dispatch
#endif
int main(void)
{
    osrec_context_restore(&context);bind(&context);symbolic(&context);
    context.active_memory=(struct osrec_user_memory){regions,%d};
    uint64_t arguments[6]={%s};
%s
    uintptr_t passed[6];for(unsigned i=0;i<6;++i)passed[i]=(uintptr_t)arguments[i];
    int64_t raw=OSREC_ROOT_DISPATCH(&context,UINT64_C(%d),passed);
    context.active_memory=(struct osrec_user_memory){0};
    observe(&raw,sizeof raw,"%s");
    {int fault=context.model_fault;observe(&fault,sizeof fault,"%s");}
    outputs(&context);
    return 0;
}
'''%(''.join('__typeof__(*((struct osrec_kernel_context *)0)->osrec_separate_%s) osrec_separate_%s_object;\n'%(m,m) for m in separate),
        max(len(blob),1),max(len(objects),1),regions or '    {0}','\n'.join(lines),'\n'.join(inputs),'\n'.join(outputs),len(objects),
        ','.join('UINT64_C(%d)'%(a&(1<<64)-1) for a in arguments),'\n'.join(argument_lines),boundary['call']['number'],name('o','result'),name('o','model_fault'))
    return source,names,fixed,invariants

def ktest_values(path,max_objects=4096):
    """Objects of a KTest v1-v3 file (big-endian framing), allowing many named objects."""
    import struct
    data=Path(path).read_bytes();at=5
    if data[:5]!=b'KTEST' or len(data)>16<<20:raise ValueError('unsupported KTest')
    def take(n):
        nonlocal at
        if n>len(data)-at:raise ValueError('truncated KTest')
        at+=n;return data[at-n:at]
    integer=lambda:struct.unpack('>I',take(4))[0]
    version=integer()
    if version not in (1,2,3):raise ValueError('unsupported KTest version')
    for _ in range(integer()):take(integer())
    if version>=2:integer();integer()
    count=integer()
    if count>max_objects:raise ValueError('too many KTest objects')
    objects={}
    for _ in range(count):
        name=take(integer()).decode('utf-8');objects[name]=take(integer())
    return objects

TOKEN=re.compile(r'\(|\)|\[|\]|=|,|@|:|[A-Za-z_][\w.]*|-?\d+')

class KQuery:
    """Parse KLEE KQuery constraint lists (labels, update lists, reads) into tuples."""
    def __init__(self,text):
        self.tokens=TOKEN.findall(text);self.at=0;self.labels={};self.updates={};self.tails={}
    def peek(self,offset=0):return self.tokens[self.at+offset] if self.at+offset<len(self.tokens) else None
    def take(self,expected=None):
        token=self.tokens[self.at];self.at+=1
        if expected is not None and token!=expected:raise ValueError('KQuery: expected %s, found %s'%(expected,token))
        return token
    def constraints(self):
        while self.peek() is not None and not (self.peek()=='(' and self.peek(1)=='query'):self.at+=1
        self.take('(');self.take('query');self.take('[');out=[]
        while self.peek()!=']':out.append(self.expression())
        return out
    def expression(self):
        token=self.peek()
        if re.fullmatch(r'-?\d+',token):self.take();return ('num',int(token))
        if token in ('true','false'):self.take();return ('num',int(token=='true'),1)
        if re.fullmatch(r'N\d+',token):
            self.take()
            if self.peek()==':':self.take();node=self.expression();self.labels[token]=node;return node
            return self.labels[token]
        self.take('(');op=self.take()
        if re.fullmatch(r'w\d+',op):
            value=self.expression();self.take(')') # (w32 5)
            return ('num',value[1],int(op[1:])) if value[0]=='num' else value
        args=[]
        if op in ('Read','ReadLSB','ReadMSB'):
            width=int(self.take()[1:]);index=self.expression();updates=self.update_list();self.take(')')
            return ('read',width,index,updates,op)
        while self.peek()!=')':
            if re.fullmatch(r'w\d+',self.peek()):args.append(('width',int(self.take()[1:])))
            else:args.append(self.expression())
        self.take(')');return ('op',op,args)
    def entries(self):
        self.take('[');out=[]
        while self.peek()!=']':
            index=self.expression();self.take('=');value=self.expression();out.append((index,value))
            if self.peek()==',':self.take()
        self.take(']');return out
    def update_list(self):
        """(entries newest first, base array); a version may extend another: [..] @ U2.

        `tails` keeps, per version, its own entry count and the version it extends,
        so a printer can print each version once.
        """
        if self.peek()=='[':
            # Unlabeled update list: [i=v, ...] @ version
            entries=self.entries();self.take('@');tail=self.update_list()
            out=(entries+tail[0],tail[1]);self.tails[id(out)]=(len(entries),tail);return out
        token=self.take()
        if re.fullmatch(r'U\d+',token):
            if self.peek()==':':
                self.take();entries=self.entries();self.take('@');tail=self.update_list()
                self.updates[token]=out=(entries+tail[0],tail[1]);self.tails[id(out)]=(len(entries),tail)
            return self.updates[token]
        return ([],token)

def candidates(node,limit=64):
    """Finite set of values an index expression can take, or None."""
    kind=node[0]
    if kind=='num':return {node[1]}
    if kind!='op':return None
    op,args=node[1],[a for a in node[2] if a[0]!='width'];width=next((a[1] for a in node[2] if a[0]=='width'),64)
    mask=(1<<width)-1
    if op=='Select' and len(args)==3:
        a,b=candidates(args[1],limit),candidates(args[2],limit)
        return a|b if a is not None and b is not None and len(a|b)<=limit else None
    if op in ('Add','Sub') and len(args)==2:
        a,b=candidates(args[0],limit),candidates(args[1],limit)
        if a is None or b is None or len(a)*len(b)>limit:return None
        return {((x+y) if op=='Add' else (x-y))&mask for x in a for y in b}
    if op in ('ZExt','SExt','Extract') and args:
        value=candidates(args[-1],limit);return {v&mask for v in value} if value is not None else None
    return None

def dependencies(node,imprecise,refine=None,memo=None):
    """Symbolic arrays an expression can depend on; reads use only update entries their index can hit.

    For an index with no finite candidate set, `refine(read)` may return the
    positions of update entries the index can reach under the path constraints
    (a solver query); otherwise every entry counts and the read is imprecise.
    Shared subexpressions are visited once per memo.
    """
    if memo is None:memo={}
    key=id(node)
    if key not in memo:memo[key]=_dependencies(node,imprecise,refine,memo)
    return memo[key]

def hit_entries(node,refine=None,memo=None):
    """Positions of the update entries a read can return, or None when any can (entries are newest first).

    With constant indices a byte is answered by the newest entry that surely stores
    it; symbolic indices use `refine` (positions reachable under the path constraints).
    `memo` keeps each update list's position index (keyed by the entry list, kept alive).
    """
    _,width,index,(entries,_),_=node;base=candidates(index)
    if not entries:return None
    if memo is None:memo={}
    if id(entries) not in memo:
        # Position -> [(entry, stores it surely)], newest first; None when an entry index is symbolic.
        by_position={}
        for n,(i,_) in enumerate(entries):
            where=candidates(i)
            if where is None:by_position=None;break
            for position in where:by_position.setdefault(position,[]).append((n,len(where)==1))
        memo[id(entries)]=(entries,by_position)
    by_position=memo[id(entries)][1]
    if base is None or by_position is None:
        reachable=refine(node) if refine is not None else None
        return None if reachable is None else set(reachable)
    out=set()
    for start in base:
        for position in range(start,start+max(1,width//8)):
            for n,definite in by_position.get(position,()):
                out.add(n)
                if definite:break
    return out

def _dependencies(node,imprecise,refine,memo):
    kind=node[0]
    deps=lambda n:dependencies(n,imprecise,refine,memo)
    if kind=='num':return set()
    if kind=='op':return set().union(*(deps(a) for a in node[2] if a[0]!='width'))
    _,width,index,(entries,array),_=node;out=set(deps(index));base=candidates(index)
    def symbolic(name):return {name} if re.fullmatch(r'[so]\d+',name) else set()
    if entries and (base is None or any(candidates(i) is None for i,_ in entries)):
        reachable=refine(node) if refine is not None else None
        if reachable is None:imprecise.append(array)
        for position,(i,v) in enumerate(entries):
            if reachable is None or position in reachable:out|=deps(i)|deps(v)
        return out|symbolic(array)
    if base is None:return out|symbolic(array)
    for start in base:
        for position in range(start,start+max(1,width//8)):
            for i,v in entries:
                where=candidates(i)
                if position in where:
                    out|=deps(v)
                    if len(where)==1:break
            else:out|=symbolic(array)
    return out

class Printer:
    """Print parsed expressions back as KQuery, naming labelled nodes and versions as the source did.

    By default labels refer to definitions in the path's constraint list. A
    standalone printer instead defines each label at its first use, so the
    expression can be asked without that list. With `prune` (read -> update
    positions it can return, or None), a read prints only those entries: equal
    to the read wherever `prune` holds. A canonical standalone printer numbers
    labels in order of definition, so equal expressions from different paths
    print the same text; `alias` maps source labels to printed ones.
    """
    def __init__(self,query,standalone=False,prune=None,canonical=False):
        self.nodes={id(n):k for k,n in query.labels.items()};self.versions={id(v):k for k,v in query.updates.items()}
        self.standalone=standalone;self.defined=set();self.prune=prune;self.canonical=canonical and standalone;self.alias={}
        self.tails=getattr(query,'tails',{})
    def name(self,label):
        if label not in self.alias:self.alias[label]='%s%d'%(label[0],len(self.alias)) if self.canonical else label
        return self.alias[label]
    def __call__(self,node,width=None):
        if node[0]=='num':
            if len(node)==3:return ('true' if node[1] else 'false') if node[2]==1 else '(w%d %d)'%(node[2],node[1])
            return '(w%d %d)'%(width,node[1]) if width else str(node[1])
        label=self.nodes.get(id(node))
        if label and (not self.standalone or label in self.defined):return self.name(label)
        if label:self.defined.add(label)
        if node[0]=='read':
            # The index prints first: labels are defined at their first textual use.
            _,bits,index,updates,op=node;at=self(index,32);kept=self.prune(node) if self.prune and updates[0] else None
            if kept is not None and len(kept)<len(updates[0]):
                entries=[e for n,e in enumerate(updates[0]) if n in kept]
                version='[%s] @ %s'%(', '.join('%s=%s'%(self(i,32),self(v,8)) for i,v in entries),updates[1]) if entries else updates[1]
            else:version=self.version(updates)
            text='(%s w%d %s %s)'%(op,bits,at,version)
        else:text='(%s %s)'%(node[1],' '.join('w%d'%a[1] if a[0]=='width' else self(a) for a in node[2]))
        return self.name(label)+':'+text if label else text
    def version(self,updates):
        label=self.versions.get(id(updates))
        if label and (not self.standalone or label in self.defined):return self.name(label)
        if label:self.defined.add(label)
        entries,array=updates
        if not entries:return array
        if label:self.name(label)
        own,tail=self.tails.get(id(updates),(len(entries),([],array)))
        # A version that extends another prints its own entries, then the version it extends.
        text='[%s] @ '%', '.join('%s=%s'%(self(i,32),self(v,8)) for i,v in entries[:own])
        text+=self.version(tail) if tail[0] else tail[1]
        return self.name(label)+':'+text if label else text

def word(array,offset,size):
    return '(Read w8 %d %s)'%(offset,array) if size==1 else '(ReadLSB w%d %d %s)'%(8*size,offset,array)

_POOL=None
def solver_pool():
    """Shared pool of solver processes for every path under analysis."""
    global _POOL
    if _POOL is None:
        import os
        from concurrent.futures import ThreadPoolExecutor
        _POOL=ThreadPoolExecutor(max(2,os.cpu_count() or 4))
    return _POOL

_ANSWERS={};_ANSWERS_LOCK=None

def top_level(text):
    """Split a KQuery constraint list into its top-level expressions (labelled, bare or constant)."""
    out=[];depth=0;start=None
    for i,c in enumerate(text):
        if start is None:
            if c.isspace():continue
            start=i
        if c=='(':depth+=1
        elif c==')':depth-=1
        if depth==0 and (c==')' or i+1==len(text) or text[i+1].isspace()):
            if c!=')' and i+1<len(text) and text[i+1]=='(':continue
            out.append(text[start:i+1]);start=None
    return out

class Stp:
    """Validity questions about one path, answered by KLEE's kleaver (STP).

    A question carries only the path constraints connected to its claim through shared
    input arrays (KQuery labels are scoped to one query, so the slice is printed standalone).
    Dropping constraints can only turn a valid answer into an invalid one, which every caller
    reads as the conservative outcome; feasibility (a claim naming no array) is asked under
    everything. Before `focus`, constraints are connected syntactically, which through the
    shared context update list usually keeps them all. Answers are cached by question text
    across paths.
    """
    def __init__(self,text,kleaver,timeout=1800):
        start=text.index('(query [');end=text.rindex(']')
        if not re.fullmatch(r'\]\s*false\s*\)\s*',text[end:]):raise ValueError('unexpected KQuery query form')
        self.header=text[:start];self.constraints=text[start+len('(query ['):end];self.kleaver=kleaver;self.timeout=timeout
        self.sizes={m.group(1):int(m.group(2)) for m in re.finditer(r'array (\w+)\[(\d+)\]',self.header)}
        self.symbolic={m.group(1) for m in re.finditer(r'array (\w+)\[\d+\][^=\n]*=\s*symbolic',self.header)}
        self.memo={};self.scanned={}
        self.items=top_level(self.constraints);self.components=self.connect(self.items);self.query=None
        self.calls=0;self.unknown=0;self.cached=0
    def focus(self,query,constraints,arrays,refine=None):
        """Slice later questions by each constraint's input arrays (as `dependencies` finds them).

        Path questions print each read with only the update entries it can return
        (`hit_entries`, with `refine` for symbolic indices). That holds under the path
        constraints, so questions asked without them print every entry.
        """
        self.refine=refine
        # An observed output (o*) is a fresh array that only its own observation constrains:
        # that constraint holds for any inputs, so it joins a question only through the
        # outputs the claim names. Path conditions connect through shared inputs.
        parent={}
        def find(a):
            while parent.setdefault(a,a)!=a:parent[a]=parent[parent[a]];a=parent[a]
            return a
        self.outputs={}
        for n,used in enumerate(arrays):
            observed=sorted(a for a in used if a.startswith('o'));inputs=sorted(a for a in used if not a.startswith('o'))
            if observed:
                for a in observed:self.outputs.setdefault(a,[]).append(n)
                continue
            for a in inputs[1:]:parent[find(a)]=find(inputs[0])
        groups={}
        for n,used in enumerate(arrays):
            inputs=[a for a in used if not a.startswith('o')]
            if inputs and not any(a.startswith('o') for a in used):groups.setdefault(find(inputs[0]),[]).append(n)
        self.query=query;self.nodes=constraints;self.inputs=[{a for a in used if not a.startswith('o')} for used in arrays]
        self.owner={a:groups.get(find(a),[]) for a in list(parent)}
    def names(self,text):
        """(symbolic arrays, labels defined, labels used) in a piece of KQuery text."""
        if text in self.scanned:return self.scanned[text]
        arrays=set();defined=set();used=set()
        for m in re.finditer(r'\b([A-Za-z_]\w*)(:?)',text):
            word=m.group(1)
            if word in self.symbolic:arrays.add(word)
            elif re.fullmatch(r'[NU]\d+',word):(defined if m.group(2) else used).add(word)
        self.scanned[text]=found=(frozenset(arrays),frozenset(defined),frozenset(used))
        return found
    def connect(self,items):
        """Key (array or label) -> component of constraint indices."""
        parent=list(range(len(items)))
        def find(i):
            while parent[i]!=i:parent[i]=parent[parent[i]];i=parent[i]
            return i
        owner={};uses=[]
        for n,item in enumerate(items):
            arrays,defined,used=self.names(item);uses.append(used)
            for key in arrays|defined:
                if key in owner:parent[find(n)]=find(owner[key])
                else:owner[key]=n
        for n,used in enumerate(uses):
            for label in used:
                if label in owner:parent[find(n)]=find(owner[label])
        groups={}
        for n in range(len(items)):groups.setdefault(find(n),[]).append(n)
        return {key:groups[find(n)] for key,n in owner.items()}
    def context(self,claim,assumptions,path):
        """(constraints, assumptions, claim) for one question."""
        arrays,defined,used=self.names(claim)
        if not arrays and not used:return (self.constraints if path else ''),list(assumptions),claim
        if self.query is not None:return self.focused(claim,arrays,defined,used,assumptions,path)
        chosen=set()
        if path:
            for key in arrays|used:chosen.update(self.components.get(key,()))
        keep=set(arrays)
        for n in chosen:keep|=self.names(self.items[n])[0]
        # Each domain assumption bounds one input array.
        extra=[a for a in assumptions if self.names(a)[0]<=keep]
        return ' '.join(self.items[n] for n in sorted(chosen)),extra,claim
    def focused(self,claim,arrays,defined,used,assumptions,path):
        # Reachable entries hold under the path constraints; constant indices hold anywhere.
        # Canonical labels unless the claim defines its own (their names must not collide).
        show=Printer(self.query,standalone=True,prune=lambda read:hit_entries(read,self.refine if path else None,self.memo),canonical=not defined)
        def definition(label,printer):
            return printer(self.query.labels[label]) if label in self.query.labels else printer.version(self.query.updates[label])
        outside=used-defined
        for label in outside:arrays=arrays|self.names(definition(label,Printer(self.query,standalone=True)))[0]
        chosen=set()
        if path:
            observations={n for a in arrays for n in self.outputs.get(a,())};chosen|=observations
            for a in set(arrays).union(*(self.inputs[n] for n in observations)):chosen.update(self.owner.get(a,()))
        context=' '.join(show(self.nodes[n]) for n in sorted(chosen))
        # Path labels the claim names are defined at their first use unless the slice defined them.
        def label(m):
            name=m.group(1)
            if name not in outside:return name
            return show.alias[name] if name in show.defined else definition(name,show)
        claim=re.sub(r'\b([NU]\d+)\b(?!:)',label,claim)
        keep=self.names(context+' '+claim)[0]
        return context,[a for a in assumptions if self.names(a)[0]<=keep],claim
    def valid(self,claims,assumptions=(),path=True):
        """[True (valid), False (invalid) or None (undecided)] for each claim under the path constraints
        (or, with path=False, under the assumptions alone)."""
        if not claims:return []
        if not self.kleaver:self.unknown+=len(claims);return [None]*len(claims)
        global _ANSWERS_LOCK
        if _ANSWERS_LOCK is None:
            import threading
            _ANSWERS_LOCK=threading.Lock()
        def ask(claim):
            context,extra,claim=self.context(claim,assumptions,path)
            # Without the path and without any assumption on its inputs, a claim is valid only
            # as a tautology; KLEE does not branch on those. Not proven is the conservative reading.
            if not path and not extra and self.names(claim)[0]:return False
            text='%s(query [%s %s] %s)\n'%(self.header,context,' '.join(extra),claim)
            from concurrent.futures import Future
            with _ANSWERS_LOCK:
                pending=_ANSWERS.get(text)
                if pending is None:_ANSWERS[text]=mine=Future();self.calls+=1
                else:self.cached+=1
            # The same question asked concurrently waits for the first asker.
            if pending is not None:return pending.result()
            answer=None
            try:
                # One process per question: kleaver slows down sharply over a long batch.
                with tempfile.TemporaryDirectory() as tmp:
                    question=Path(tmp)/'question.kquery';question.write_text(text)
                    r=subprocess.run([str(self.kleaver),'--max-solver-time=60s',str(question)],capture_output=True,text=True,timeout=self.timeout)
                m=re.search(r'^Query 0:\s+(VALID|INVALID)\s*$',r.stdout,re.M)
                answer=m.group(1)=='VALID' if m else None
            except subprocess.TimeoutExpired:pass
            finally:
                mine.set_result(answer)
                # Undecided answers are not kept: a later asker tries again.
                if answer is None:
                    with _ANSWERS_LOCK:_ANSWERS.pop(text,None)
            return answer
        answers=list(solver_pool().map(ask,claims))
        self.unknown+=sum(1 for a in answers if a is None);return answers
    def domain(self,array,low,high,signed):
        # An input this path never reads is not declared in its KQuery and needs no assumption.
        if array not in self.sizes:return []
        size=self.sizes[array];value=word(array,0,size);mask=(1<<8*size)-1;out=[]
        if low is not None:out.append('(%s (w%d %d) %s)'%('Sle' if signed else 'Ule',8*size,low&mask,value))
        if high is not None:out.append('(%s %s (w%d %d))'%('Sle' if signed else 'Ule',value,8*size,high&mask))
        return out

def overlap_runs(read):
    """Update entries a read may hit: (positions decided syntactically, runs left for the solver).

    Entries at single constant indices form runs (a run ends where the index jumps
    or the stored value comes from another array, i.e. a field boundary); entries
    at symbolic indices are runs of their own.
    """
    _,bits,index,(entries,_),_=read;span=max(1,bits//8);base=candidates(index);known=set();single=[];runs=[]
    def source(value):
        found=set()
        def walk(node):
            if node[0]=='read':found.add(node[3][1]);walk(node[2])
            elif node[0]=='op':[walk(x) for x in node[2] if x[0]!='width']
        walk(value);return frozenset(found)
    for n,(i,v) in enumerate(entries):
        c=candidates(i)
        if c is not None and base is not None:
            if any(b<=p<b+span for b in base for p in c):known.add(n)
        elif c is not None and len(c)==1:single.append((next(iter(c)),n,source(v)))
        else:runs.append(('expr',i,[n]))
    current=None
    for value,n,origin in sorted(single):
        if current and value==current[2]+1 and origin==current[4]:current[2]=value;current[3].append(n)
        else:current=['range',value,value,[n],origin];runs.append(current)
    return known,runs

def overlap_claim(read,runs,show):
    """KQuery claim: the read's bytes overlap one of the runs."""
    _,bits,index,_,_=read;span=max(1,bits//8);at=show(index,32);parts=[]
    for run in runs:
        if run[0]=='range':parts.append('(And (Ule %s (w32 %d)) (Ule (w32 %d) (Add w32 %s (w32 %d))))'%(at,run[2],run[1],at,span-1))
        else:
            target=show(run[1],32);parts.append('(And (Ule %s %s) (Ule %s (Add w32 %s (w32 %d))))'%(at,target,target,at,span-1))
    claim=parts[0]
    for part in parts[1:]:claim='(Or %s %s)'%(claim,part)
    return claim

class Model:
    """Evaluate parsed expressions under a path's KTest assignment (a model of its constraints)."""
    COMPARE={'Eq':lambda a,b:a==b,'Ne':lambda a,b:a!=b,'Ult':lambda a,b:a<b,'Ule':lambda a,b:a<=b,'Ugt':lambda a,b:a>b,'Uge':lambda a,b:a>=b}
    def __init__(self,header,values):
        self.arrays={k:bytes(v) for k,v in values.items()}
        for m in re.finditer(r'array (\w+)\[(\d+)\] : w32 -> w8 = \[([^\]]*)\]',header):
            self.arrays[m.group(1)]=bytes(int(x)&255 for x in m.group(3).split())
        self.memo={}
    @staticmethod
    def width(node):
        if node[0]=='num':return node[2] if len(node)==3 else None
        if node[0]=='read':return node[1]
        if node[1] in Model.COMPARE or node[1] in ('Slt','Sle','Sgt','Sge'):return 1
        return next((a[1] for a in node[2] if a[0]=='width'),None)
    def __call__(self,node):
        key=id(node)
        if key not in self.memo:self.memo[key]=self.evaluate(node)
        return self.memo[key]
    def byte(self,updates,position):
        entries,array=updates
        for i,v in entries:
            if self(i)&0xffffffff==position:return self(v)&255
        return self.arrays[array][position]
    def evaluate(self,node):
        if node[0]=='num':return node[1]
        if node[0]=='read':
            _,bits,index,updates,op=node;at=self(index)&0xffffffff;data=[self.byte(updates,at+k) for k in range(max(1,bits//8))]
            if op=='ReadMSB':data.reverse()
            return sum(b<<(8*k) for k,b in enumerate(data))
        op=node[1];w=self.width(node);args=[a for a in node[2] if a[0]!='width'];mask=(1<<w)-1 if w else None
        values=[self(a) for a in args]
        if op in self.COMPARE:return int(self.COMPARE[op](*values))
        if op in ('Slt','Sle','Sgt','Sge'):
            size=next((self.width(a) for a in args if self.width(a)),64)
            x,y=(v-(1<<size) if v>>(size-1)&1 else v for v in values)
            return int({'Slt':x<y,'Sle':x<=y,'Sgt':x>y,'Sge':x>=y}[op])
        if op in ('And','Or','Xor') and w is None:return {'And':all,'Or':any,'Xor':lambda v:sum(map(bool,v))%2}[op](values) and 1 or 0
        if op=='Not':return (~values[0])&mask if mask else int(not values[0])
        if op=='Select':return (values[1] if values[0] else values[2])&mask
        if op=='Extract':return (values[1]>>values[0])&mask
        if op=='ZExt':return values[0]&mask
        if op=='SExt':
            size=self.width(args[0]) or 1;v=values[0]
            return (v-(1<<size) if v>>(size-1)&1 else v)&mask
        if op=='Concat':
            out=0
            for a,v in zip(args,values):out=(out<<self.width(a))|v
            return out&mask
        x,y=values;signed=lambda v:v-(1<<w) if v>>(w-1)&1 else v
        if op in ('UDiv','URem','SDiv','SRem') and y==0:raise ZeroDivisionError
        result={'Add':lambda:x+y,'Sub':lambda:x-y,'Mul':lambda:x*y,'UDiv':lambda:x//y,'URem':lambda:x%y,
            'SDiv':lambda:int(signed(x)/signed(y)),'SRem':lambda:signed(x)-int(signed(x)/signed(y))*signed(y),
            'And':lambda:x&y,'Or':lambda:x|y,'Xor':lambda:x^y,'Shl':lambda:x<<y if y<w else 0,
            'LShr':lambda:x>>y if y<w else 0,'AShr':lambda:signed(x)>>min(y,w-1)}[op]()
        return result&mask

def reachable_entries(reads,stp,show,model=None):
    """For each read (by id): update positions its index can reach.

    Each distinct symbolic index (of a read or of an update entry) is first
    confined: the field run it hits under the path's KTest model is a
    candidate, and one query proves the index never leaves it. Confined
    indices are then decided by interval overlap without further queries.
    Unconfined ones are bisected over runs.
    """
    out={};pending=[];plans=[]
    def range_runs(runs):return [r for r in runs if r[0]=='range']
    # Candidate confinement per distinct symbolic index: (node, span, low, high of the start position).
    candidates_by_id={}
    # Keyed by (index, span): a start proven inside a field for one access width says
    # nothing about a wider access starting at the same index.
    def propose(node,span,runs):
        if model is None or (id(node),span) in candidates_by_id:return
        try:at=model(node)&0xffffffff
        except (KeyError,IndexError,ZeroDivisionError,TypeError):return
        run=next((r for r in range_runs(runs) if r[1]<=at and at+span-1<=r[2]),None)
        if run:candidates_by_id[(id(node),span)]=(node,span,run[1],run[2]-span+1)
    fields={}
    for read in reads:
        known,runs=overlap_runs(read);out[id(read)]=set(known);span=max(1,read[1]//8)
        # Field runs of the whole update list, whatever this read's own index is.
        updates=read[3]
        if id(updates) not in fields:fields[id(updates)]=overlap_runs(('read',8,('op','Unknown',[]),updates,'Read'))[1]
        if candidates(read[2]) is None:propose(read[2],span,fields[id(updates)])
        for run in runs:
            if run[0]=='expr':propose(run[1],1,fields[id(updates)])
        plans.append((read,runs))
    items=list(candidates_by_id.values())
    answers=stp.valid(['(And (Ule (w32 %d) %s) (Ule %s (w32 %d)))'%(low,show(node,32),show(node,32),high) for node,_,low,high in items])
    confined={(id(node),span):(low,high) for (node,span,low,high),valid in zip(items,answers) if valid}
    for read,runs in plans:
        span=max(1,read[1]//8);base=candidates(read[2])
        if base is not None:starts=[(b,b) for b in base]
        elif (id(read[2]),span) in confined:starts=[confined[(id(read[2]),span)]]
        else:starts=None
        rest=[]
        for run in runs:
            if run[0]=='range':where=(run[1],run[2])
            elif (id(run[1]),1) in confined:where=confined[(id(run[1]),1)]
            elif run[1] is not None and candidates(run[1]) is not None:where=(min(candidates(run[1])),max(candidates(run[1])))
            else:where=None
            if starts is None or where is None:rest.append(run);continue
            # Interval overlap of [start, start+span-1] with the run: may hit (counted) or cannot.
            if any(low<=where[1] and where[0]<=high+span-1 for low,high in starts):
                out[id(read)].update(run[-2] if run[0]=='range' else run[2])
        if rest and model is not None and starts is None:
            try:
                at=model(read[2])&0xffffffff
                hit=lambda run:run[1]<=at+span-1 and at<=run[2] if run[0]=='range' else at<=model(run[1])&0xffffffff<at+span
                witnessed=[run for run in rest if hit(run)]
            except (KeyError,IndexError,ZeroDivisionError,TypeError):witnessed=[]
            for run in witnessed:out[id(read)].update(run[-2] if run[0]=='range' else run[2])
            rest=[run for run in rest if not any(run is w for w in witnessed)]
        if rest:pending.append((read,rest))
    while pending:
        answers=stp.valid(['(Eq false %s)'%overlap_claim(read,runs,show) for read,runs in pending]);following=[]
        for (read,runs),infeasible in zip(pending,answers):
            if infeasible:continue
            if infeasible is None or len(runs)==1:
                # Undecided groups count as reachable.
                for run in runs:out[id(read)].update(run[-2] if run[0]=='range' else run[2])
            else:half=len(runs)//2;following+=[(read,runs[:half]),(read,runs[half:])]
        pending=following
    return out

def analyze_path(kquery,names,domains,kleaver):
    test=kquery.name.split('.')[0];errors=sorted(p.name.split('.',1)[1] for p in kquery.parent.glob(test+'.*.err'))
    text=kquery.read_text();query=KQuery(text);constraints=query.constraints()
    inputs={v:k for k,v in names.items() if k.startswith('s')};show=Printer(query)
    fault=next((k for k,v in names.items() if v=='model_fault'),None)
    try:stp=Stp(text,kleaver)
    except ValueError:stp=Stp('(query [] false)',None)
    # First pass: reads whose reachable update entries need the solver. Until those are
    # decided, questions are sliced as if such reads hit no entry: any slice is sound, a
    # proof it misses only costs precision.
    unbounded=[];first={};optimistic={}
    for c in constraints:dependencies(c,[],unbounded.append,first);dependencies(c,[],lambda read:set(),optimistic)
    if stp.kleaver:stp.focus(query,constraints,[optimistic[id(c)] for c in constraints])
    # Questions about outputs assume every shaped input inside its domain; a contradiction
    # among those assumptions would make every claim valid, so feasibility is asked too.
    assumptions=[a for f,(low,high,signed) in sorted(domains.items()) if f in inputs for a in stp.domain(inputs[f],low,high,signed)]
    # The path's KTest is a model of its constraints: when its raw inputs lie inside every
    # domain it also witnesses feasibility, and its fault value excludes one outcome.
    values=None
    if kquery.with_suffix('.ktest').exists():
        try:values=ktest_values(kquery.with_suffix('.ktest'))
        except ValueError:values=None
    def inside(field,low,high,signed):
        raw=values.get(inputs[field]) if values else None
        if raw is None:return False
        v=int.from_bytes(raw,'little')
        if signed and v>>(8*len(raw)-1)&1:v-=1<<8*len(raw)
        return (low is None or low<=v) and (high is None or v<=high)
    witnessed=values is not None and all(inside(f,*d) for f,d in domains.items() if f in inputs)
    # KLEE stopped this state before it returned (max time, memory): its KQuery is a path
    # prefix with no outputs observed, so it only shows which inputs the prefix branches on.
    partial=kquery.with_suffix('.early').exists()
    result=dict(test=test,errors=errors,fault='partial' if partial else None)
    if errors:
        # Outside the reviewed model domain: dependencies are not used, so not computed.
        return dict(result,analyzed=False,control=[],data={},unchanged=[],imprecise_reads=0,solver_calls=stp.calls,solver_cached=stp.cached,solver_unknown=stp.unknown)
    zero='(Eq (w%d 0) %s)'%(8*stp.sizes[fault],word(fault,0,stp.sizes[fault])) if fault and fault in stp.sizes and not partial else None
    seen=int.from_bytes(values[fault],'little') if zero and witnessed and fault in values else None
    # A path that no in-domain input reaches never runs, so a vacuous "always" is harmless.
    # Asked first under the early slice: a proof there holds on the whole path, and an
    # always-faulting path then needs no reachability work.
    if zero and seen!=0 and stp.valid(['(Eq false %s)'%zero],assumptions)[0]:
        return dict(result,fault='always',analyzed=False,control=[],data={},unchanged=[],imprecise_reads=0,solver_calls=stp.calls,solver_cached=stp.cached,solver_unknown=stp.unknown)
    model=None
    if unbounded and kquery.with_suffix('.ktest').exists():
        try:model=Model(stp.header,ktest_values(kquery.with_suffix('.ktest')))
        except ValueError:model=None
    reachable=reachable_entries(unbounded,stp,show,model) if unbounded else {}
    control=set();words={};imprecise=[];memo={};conditions=[];refined=[]
    def refine(read):return reachable.get(id(read))
    for c in constraints:
        used=dependencies(c,imprecise,refine,memo);refined.append(used);observed=[a for a in used if a.startswith('o')];read={a for a in used if a.startswith('s')}
        if observed:
            for o in observed:
                if o!=fault:words.setdefault(o,set()).update(read)
        elif read:conditions.append((c,read))
    # Later questions are sliced by the reads' reachable entries, so a store at a symbolic
    # index (a file write) is kept only where the path lets it alias, e.g. the fault flag.
    if stp.kleaver and unbounded:stp.focus(query,constraints,refined,refine)
    decided=None;feasible=None
    if zero:
        always=stp.valid(['(Eq false %s)'%zero],assumptions)[0] if seen!=0 else False
        if always:decided='always'
        else:
            feasible=witnessed or stp.valid(['false'],assumptions)[0] is False
            never=stp.valid([zero],assumptions)[0] if not seen else False
            decided='never' if feasible and never else 'undecided'
        result['fault']=decided
    if feasible is None:feasible=witnessed or stp.valid(['false'],assumptions)[0] is False
    if decided=='always':
        return dict(result,analyzed=False,control=[],data={},unchanged=[],imprecise_reads=0,solver_calls=stp.calls,solver_cached=stp.cached,solver_unknown=stp.unknown)
    # A path condition that the input domains alone imply selects nothing (e.g. f_count != 0
    # under f_count >= 1): its inputs are not control dependencies.
    # Printed standalone, with only syntactically reachable update entries (no path facts).
    texts=[Printer(query,standalone=True,canonical=True,prune=lambda read:hit_entries(read,None,stp.memo))(c) for c,_ in conditions]
    implied=stp.valid(texts,assumptions,path=False) if assumptions else [False]*len(conditions)
    branches=[]
    for (c,read),text,answer in zip(conditions,texts,implied):
        if answer is not True:
            control|={names[s] for s in read}
            # Content keys let summarize pair sibling paths that split on this condition.
            inner=text[len('(Eq false '):-1] if text.startswith('(Eq false ') else None
            branches.append(dict(key=sha(text.encode())[:16],negates=sha(inner.encode())[:16] if inner else None,fields=sorted(names[s] for s in read)))
    if partial:
        return dict(result,analyzed=False,control=[],prefix_control=sorted(control),data={},unchanged=[],
            imprecise_reads=len(imprecise),solver_calls=stp.calls,solver_cached=stp.cached,solver_unknown=stp.unknown)
    questions=[];owners=[]
    for o in sorted(words):
        source=inputs.get(names[o])
        if source and stp.sizes.get(o)==stp.sizes.get(source):
            # One question per output: every 8-byte word equals the same word of its input.
            parts=['(Eq %s %s)'%(word(o,offset,min(8,stp.sizes[o]-offset)),word(source,offset,min(8,stp.sizes[o]-offset))) for offset in range(0,stp.sizes[o],8)]
            claim=parts[0]
            for part in parts[1:]:claim='(And %s %s)'%(claim,part)
            questions.append(claim);owners.append(o)
    proven={o:feasible and answer is True for o,answer in zip(owners,stp.valid(questions,assumptions))}
    unchanged=sorted(names[o] for o in words if proven.get(o))
    data={}
    for o,read in words.items():
        if names[o] not in unchanged:data.setdefault(names[o],set()).update(names[s] for s in read)
    return dict(result,analyzed=True,control=sorted(control),data={k:sorted(v) for k,v in sorted(data.items()) if v},
        unchanged=unchanged,outputs=path_outputs(stp,names,words,unchanged,fault,values,assumptions,feasible) if decided in (None,'never') else None,branches=branches,
        domain_implied_conditions=sum(1 for a in implied if a is True),imprecise_reads=len(imprecise),solver_calls=stp.calls,solver_cached=stp.cached,solver_unknown=stp.unknown)

def path_outputs(stp,names,words,unchanged,fault,values,assumptions,feasible):
    """Output name -> 'unchanged' or the constant (hex) it takes on every input of this path; None otherwise.

    An output that reads no input holds one value on the whole path: its KTest value,
    proven by one question. Paths with equal outputs compute the same function of the
    entry state, so conditions choosing between them select nothing (see summarize).
    """
    observed=[k for k,v in names.items() if k.startswith('o') and k!=fault]
    if not feasible or values is None or any(o not in words or (words[o] and names[o] not in unchanged) for o in observed):return None
    constant=[o for o in sorted(observed) if names[o] not in unchanged]
    if any(o not in values or o not in stp.sizes for o in constant):return None
    claims=['(Eq (w%d %d) %s)'%(8*min(8,stp.sizes[o]-at),int.from_bytes(values[o][at:at+8],'little'),word(o,at,min(8,stp.sizes[o]-at)))
            for o in constant for at in range(0,stp.sizes[o],8)]
    if claims and not all(a is True for a in stp.valid(claims,assumptions)):return None
    return {names[o]:'unchanged' if names[o] in unchanged else bytes(values[o]).hex() for o in observed}

def default_kleaver(klee=None):
    found=Path(klee).with_name('kleaver') if klee else None
    return found if found and found.exists() else shutil.which('kleaver')

def input_domains(invariants,ranges,fixed,arguments=None):
    """Input field -> (low, high, signed): the values on which the driver's shaping is the identity."""
    out={'argument:%s'%i:(low,high,False) for i,(low,high) in (arguments or {}).items()}
    for item in invariants:
        m=re.fullmatch(r'(\S+)>=(-?\d+)',item)
        if m:out[m.group(1)]=(int(m.group(2)),None,True)
    for field,(low,high) in ranges.items():
        if field in fixed:continue
        if field in out:
            # Both shapings apply: the domain is their intersection (non-negative, so signedness agrees).
            low=max(low,out[field][0])
        out[field]=(low,high,False)
    return out

def analyze_paths(directory,names,domains=None,kleaver=None,jobs=4):
    """Per-path control and data dependencies.

    An output proven equal to its own input on a path (under the path condition,
    with every shaped input inside its domain) is unchanged there and adds no
    data dependency; otherwise every input its expression reads is a dependency,
    including its own. The model-fault output is decided per path: never, always
    or undecided. Questions go to STP through kleaver; without it every
    unbounded read is imprecise and nothing is proven unchanged.
    """
    from concurrent.futures import ThreadPoolExecutor
    tests=sorted(Path(directory).glob('test*.kquery'))
    with ThreadPoolExecutor(max(1,jobs)) as pool:
        return list(pool.map(lambda k:analyze_path(k,names,domains or {},kleaver),tests))

def status(path):
    """error, partial (stopped before returning), never (inside the model domain), always (model fault) or undecided."""
    if path['errors']:return 'error'
    if path.get('fault'):return path['fault']
    return 'always' if path['model_fault'] else 'never'

def control_regions(inside):
    """Merge sibling paths that split on one condition and compute the same outputs.

    Two in-domain paths whose conditions differ only in c and (Eq false c), with equal
    `outputs` (unchanged or the same constants), cover their common prefix with one
    result: c selects nothing. Merging repeats to a fixpoint. With complete exploration
    the remaining regions partition the model domain, so inputs named by no remaining
    condition (and by no output) cannot change the outcome, including whether it faults.
    Returns [(outputs or None, branches)] per region.
    """
    regions=[(p.get('outputs'),{b['key']:b for b in p.get('branches',[])}) for p in inside]
    changed=True
    while changed:
        changed=False
        for i in range(len(regions)):
            for j in range(i+1,len(regions)):
                (out,a),(other,b)=regions[i],regions[j]
                if out is None or out!=other:continue
                left,right=a.keys()-b.keys(),b.keys()-a.keys()
                if len(left)!=1 or len(right)!=1:continue
                x,y=a[next(iter(left))],b[next(iter(right))]
                if x['negates']!=y['key'] and y['negates']!=x['key']:continue
                regions[i]=(out,{k:v for k,v in a.items() if k in b});del regions[j];changed=True;break
            if changed:break
    return [(out,list(branches.values())) for out,branches in regions]

def summarize(paths,names,static_fields,split=(),complete=True):
    """Dependency summary over paths that can stay in the model domain, compared with the static footprint.

    Paths whose model fault is undecided count as inside, so their dependencies are kept.
    A split input reaches the code as a constant on each path: the only conditions naming it
    are the driver's own value comparisons and no output depends on it as data, so the paths
    cannot show whether it is needed. Split inputs are listed apart (`split_inputs`) and left
    to concrete replay.
    """
    inside=[p for p in paths if status(p) in ('never','undecided')]
    control=sorted(set().union(*(set(p['control']) for p in inside)) if inside else set())
    if complete and all('branches' in p for p in inside) and not any(status(p) in ('error','partial') for p in paths):
        merged=control_regions(inside)
        kept=set().union(*(set(f for b in branches for f in b['fields']) for _,branches in merged)) if merged else set()
        without_effect=sorted(set(control)-kept-set(split));control=sorted(kept)
    else:without_effect=[]
    data_by_output={}
    for p in inside:
        for o,ins in p['data'].items():data_by_output.setdefault(o,set()).update(ins)
    observed=sorted({v for k,v in names.items() if k.startswith('o')}-{'model_fault'})
    # Unchanged on every inside path: compared against the observation, not needed to compute it.
    # A stopped (partial) path may still write any output, so an incomplete exploration proves none unchanged.
    stopped=any(status(p)=='partial' for p in paths)
    unchanged=sorted(o for o in observed if inside and not stopped and all(o in p.get('unchanged',()) for p in inside))
    required=sorted((set(control)|set().union(*data_by_output.values()) if data_by_output else set(control))-set(split))
    control=sorted(set(control)-set(split))
    inputs=sorted(v for k,v in names.items() if k.startswith('s'))
    schema=lambda field:re.sub(r'\[\d+\]','[]',field)
    # A whole-array input (file_data.bytes) is the static footprint's element form (file_data.bytes[]).
    required_schema=sorted({schema(f)+'[]' if schema(f)+'[]' in static_fields else schema(f) for f in required if not f.startswith(('user_object.','argument:'))})
    count=lambda s:sum(1 for p in paths if status(p)==s)
    # Inputs that stopped path prefixes branch on but no complete inside path uses: candidates
    # the incomplete exploration may be missing (a prefix may lead only to model faults).
    prefix=set().union(*(set(p.get('prefix_control',())) for p in paths))
    return dict(paths=dict(total=len(paths),in_domain=count('never'),model_fault_undecided=count('undecided'),model_domain_faults=count('always'),errors=count('error'),partial=count('partial')),
        required=required,split_inputs=sorted(split),control_without_effect=without_effect,required_is_lower_bound=count('partial')>0,prefix_control_not_required=sorted(prefix-set(required)),control_dependencies=control,data_dependencies={k:sorted(v) for k,v in sorted(data_by_output.items())},
        unchanged_outputs=unchanged,imprecise_reads=sum(p['imprecise_reads'] for p in inside),
        solver=dict(calls=sum(p.get('solver_calls',0) for p in paths),cached=sum(p.get('solver_cached',0) for p in paths),undecided=sum(p.get('solver_unknown',0) for p in paths)),
        unused_inputs=sorted(set(inputs)-set(required)),
        comparison=dict(static_footprint=static_fields,required_schema_fields=required_schema,
            required_not_in_static=sorted(set(required_schema)-set(static_fields)),
            static_not_required=sorted(set(static_fields)-set(required_schema))),
        per_path=paths)

def model_faults(directory,names,paths):
    fault=[k for k,v in names.items() if v=='model_fault'][0]
    for p in paths:p['model_fault']=int.from_bytes(ktest_values(Path(directory)/(p['test']+'.ktest')).get(fault,b'\0\0\0\0')[:4],'little')

def reanalyze(out):
    """Recompute dependencies of an existing run from its KQuery/KTest files."""
    out=Path(out);report=json.loads((out/'report.json').read_text());names=json.loads((out/'names.json').read_text())
    domains=input_domains(report['invariants']['assumed'],report['ranged_inputs'],report['fixed_by_binding'],report.get('symbolic_arguments'))
    paths=analyze_paths(out/'klee',names,domains,default_kleaver(report['klee']['command'][0]));model_faults(out/'klee',names,paths)
    split=['argument:%s'%i for i in report.get('split_arguments',[])]+list(report.get('split_fields',{}))
    report.pop('passthrough',None);report.update(summarize(paths,names,report['comparison']['static_footprint'],split,report['klee']['exploration_complete']))
    (out/'report.json').write_text(json.dumps(report,indent=2,default=sorted)+'\n');return report

def input_ranges(contracts,binding,states):
    """Bounded input domains: contract state ranges, binding class values and declared Linux invariants.

    `input_domains` entries name a field (`pool[]` expands to every pool entry), bounds and the
    reason the kernel guarantees them. Every bound must hold in the observed states.
    """
    pool=binding['descriptors']['pool'];count=len(states[0][1]['pool']);ranges={};provenance=[]
    def add(field,low,high,source):
        old=ranges.get(field);ranges[field]=(max(low,old[0]),min(high,old[1])) if old else (low,high)
        provenance.append(dict(field=field,min=low,max=high,source=source))
    for item in contracts.get('state_ranges',[]):
        m=re.fullmatch(r'live state field (\S+)',item['validated_by'])
        if m:add(m.group(1),item['min'],item['max'],'contract state range: '+item['reason'])
    values=[int(v) for v in binding['descriptors'].get('class',{}).get('values',{}).values()]
    if values and sorted(values)==list(range(min(values),max(values)+1)):
        # object_id is the binding's classification of the file: only its class values occur.
        for i in range(count):add('%s[%d].object_id'%(pool,i),min(values),max(values),'binding class values')
    for item in contracts.get('input_domains',[]):
        fields=['%s[%d].%s'%(pool,i,item['field'].split('].',1)[1]) for i in range(count)] if item['field'].startswith(pool+'[]') else [item['field']]
        for field in fields:add(field,item['min'],item['max'],'declared: '+item['reason'])
    for field,(low,high) in ranges.items():
        m=re.fullmatch(r'%s\[(\d+)\]\.(\w+(?:\.\w+)*)'%re.escape(pool),field)
        for label,state in states:
            if m:
                o=state['pool'][int(m.group(1))]
                if o is None:continue
                value=int(m.group(1))+1 if m.group(2)=='object_id' and 'object_id' not in o else o[m.group(2)]
            else:value=state['scalars'].get(field)
            if value is None or not low<=value<=high:raise ValueError('%s state violates the input domain %s in [%d, %d]: %r'%(label,field,low,high,value))
    return ranges,provenance

def discover(boundary,slice_dir,binding,out,llvm_bin,klee,klee_include,symbolic_args=None,max_time=120,contracts=None,resume=False,split=(),klee_args=(),split_fields=None,separate=()):
    """Run (or, with resume, publish an already finished run in OUT/work) and write OUT/report.json."""
    out=Path(out).resolve();stage=out/'work';sources=stage/'sources'
    if resume:
        if not (stage/'klee'/'info').exists():raise FileNotFoundError(stage/'klee'/'info')
    elif out.exists():raise FileExistsError(out)
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
    pre=obs['kernel_pre'];objects=obs['pre']['user_objects'];symbolic_args=symbolic_args or {}
    if not resume:
        # Work in the output directory so a bounded or interrupted run keeps its tests.
        out.mkdir(parents=True);stage.mkdir();sources.mkdir()
        for n in INPUTS:(sources/n).parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(slice_dir/'sources'/n,sources/n)
        # The static footprint parses models.c, which includes the captured defaults.
        (sources/'capture.h').write_text(capture_header(pre))
    for n in INPUTS:
        if sha((sources/n).read_bytes())!=manifest['source_hashes'].get(n):raise ValueError('work source differs from the slice: '+n)
    ranges,provenance=input_ranges(json.loads(Path(contracts).read_text()) if contracts else {},b,[('pre',pre),('post',obs['kernel_post'])])
    graph=graph_invariants(json.loads(Path(contracts).read_text()) if contracts else {},b,[('pre',pre),('post',obs['kernel_post'])])
    for field,(low,high) in graph['bounds'].items():
        old=ranges.get(field);ranges[field]=(max(low,old[0]),min(high,old[1])) if old else (low,high)
        provenance.append(dict(field=field,min=low,max=high,source='graph invariant: at most the first free slot'))
    static=footprint(sources,root,policy,pre,b,llvm_bin/'clang',stage,contracts)
    plan=json.loads((stage/'entry-state.json').read_text())['plans'][0]
    # A blocked footprint can miss writes through the accesses it could not resolve, so every
    # bound field is observed; its reads are then a lower bound for the comparison.
    written=None if static['blockers'] else {normalize(w['path'],policy) for w in plan['state_writes']}
    # pool[] expands to every pool entry, as in the contracts.
    pool=b['descriptors']['pool'];expanded={}
    for field,bounds in (split_fields or {}).items():
        for f in (['%s[%d].%s'%(pool,i,field.split('].',1)[1]) for i in range(len(pre['pool']))] if field.startswith(pool+'[]') else [field]):expanded[f]=bounds
    # Members the contracts keep in their own KLEE object, plus any given on the command line.
    declared=[item['member'] for item in (json.loads(Path(contracts).read_text()).get('klee_separate_members',[]) if contracts else [])]
    separate=list(dict.fromkeys(declared+list(separate)))
    source,names,fixed,invariants=driver(pre,b,obs,objects,symbolic_args,ranges,written,split,expanded,separate,graph)
    # A solver option given with --klee-arg replaces the default per-query limit (which forks a solver per query).
    limit=[] if any(x.startswith(('--max-solver-time','--use-forked-solver')) for x in klee_args) else ['--max-solver-time=%ds'%max(5,max_time//10)]
    command=[str(klee),'--libc=none','--external-calls=none','--write-kqueries','--max-time=%ds'%max_time,
        *limit,'--max-memory=2048',*klee_args,'--output-dir='+str(stage/'klee'),str(stage/'slice.bc')]
    if resume:
        # Published results must describe the program KLEE actually ran.
        if (sources/'klee_driver.c').read_text()!=source or (sources/'capture.h').read_text()!=capture_header(pre):
            raise ValueError('regenerated driver differs from the one in the interrupted run')
        if json.loads((stage/'names.json').read_text())!=names:raise ValueError('symbolic names differ from the interrupted run')
    else:
        (sources/'klee_driver.c').write_text(source);(stage/'names.json').write_text(json.dumps(names,indent=1)+'\n')
        bitcode=[];build=sources
        if separate:
            # A copy: quoted includes search the including file's directory first.
            build=stage/'klee-sources'
            if build.exists():shutil.rmtree(build)
            shutil.copytree(sources,build)
            (build/'slice_context.h').write_text(separate_members((sources/'slice_context.h').read_text(),separate))
        for n in ('syscalls.c','models.c','slice_runtime.c','slice_bytes.c','klee_driver.c'):
            target=stage/(n+'.bc')
            run([llvm_bin/'clang','-emit-llvm','-c','-g','-O0','-Xclang','-disable-O0-optnone','-std=c11','-fno-builtin','-w','-I'+str(build),'-I'+str(klee_include),build/n,'-o',target])
            bitcode.append(target)
        run([llvm_bin/'llvm-link',*bitcode,'-o',stage/'slice.bc'])
        # KLEE exits non-zero when paths end in errors; outcomes are read from its output directory.
        with (stage/'klee.log').open('w') as log:
            process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
            try:process.wait(timeout=max_time+120)
            except subprocess.TimeoutExpired:process.kill();process.wait();(stage/'killed').write_text('')
    killed=(stage/'killed').exists()
    text=(stage/'klee.log').read_text()+((stage/'klee'/'info').read_text() if (stage/'klee'/'info').exists() else '')
    completed=re.search(r'KLEE: done: completed paths = (\d+)',text)
    partial=re.search(r'KLEE: done: partially completed paths = (\d+)',text)
    halted=killed or 'HaltTimer invoked' in text or 'halting execution' in text.lower()
    paths=analyze_paths(stage/'klee',names,input_domains(invariants,ranges,fixed,symbolic_args),default_kleaver(klee))
    # A path left the reviewed model domain when its observed model_fault is non-zero (read from its KTest).
    model_faults(stage/'klee',names,paths)
    static_fields=sorted({r['field'] for r in static['entry_reads']})
    complete=bool(completed) and not halted and not killed and int(partial.group(1) if partial else 0)==0
    summary=summarize(paths,names,static_fields,['argument:%s'%i for i in sorted(split)]+sorted(expanded),complete)
    report=dict(format=FORMAT,root=root,call=obs['call'],boundary_sha256=sha(Path(boundary).read_bytes()),
        slice=dict(path=str(slice_dir),manifest_sha256=sha((slice_dir/'manifest.json').read_bytes())),
        klee=dict(version=subprocess.run([str(klee),'--version'],capture_output=True,text=True).stdout.splitlines()[0],command=command[:-1],
            completed_paths=int(completed.group(1)) if completed else None,partial_paths=int(partial.group(1)) if partial else None,
            halted=halted,killed=killed,exploration_complete=complete,max_time_seconds=max_time),
        symbolic_inputs=sorted(v for k,v in names.items() if k.startswith('s')),symbolic_arguments={str(k):list(v) for k,v in symbolic_args.items()},split_arguments=sorted(split),split_fields={k:list(v) for k,v in sorted(expanded.items())},separate_members=list(separate),
        fixed_by_binding=fixed,fixed_by_graph=graph['fixed'],ranged_inputs={k:list(v) for k,v in ranges.items()},input_domains=provenance,
        invariants=dict(assumed=invariants,reason='a descriptor-table slot holds a reference to its file (Linux fd_install/get_file); released pool entries are unconstrained'),
        observed_post_fields=sorted(v for k,v in names.items() if k.startswith('o')),static_write_set=sorted(written) if written is not None else None,
        **summary,static_blockers=static['blockers'],
        scope='bound scalar state and user bytes for the observed object graph; argument domain as listed; bounded exploration')
    for n in ('klee_driver.c','capture.h'):shutil.copyfile(sources/n,out/n)
    shutil.copyfile(stage/'names.json',out/'names.json');shutil.copyfile(stage/'klee.log',out/'klee.log')
    shutil.copytree(stage/'klee',out/'klee',ignore=shutil.ignore_patterns('*.bc','assembly.ll'),dirs_exist_ok=resume)
    shutil.rmtree(stage)
    (out/'report.json').write_text(json.dumps(report,indent=2,default=sorted)+'\n')
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reanalyze',type=Path,help='recompute dependencies of an existing output directory and exit')
    p.add_argument('--boundary',type=Path);p.add_argument('--slice',type=Path);p.add_argument('--binding',type=Path)
    p.add_argument('--out',type=Path);p.add_argument('--contracts',type=Path)
    p.add_argument('--symbolic-arg',action='append',default=[],help='INDEX:LOW:HIGH[:split] makes syscall argument INDEX symbolic in [LOW, HIGH]; split forks one path per value')
    p.add_argument('--max-time',type=int,default=120)
    p.add_argument('--split-field',action='append',default=[],help='FIELD:LOW:HIGH forks one path per value of a symbolic state field in [LOW, HIGH] (pool[] expands)')
    p.add_argument('--separate-member',action='append',default=[],help='context member KLEE keeps in its own object (e.g. file_data)')
    p.add_argument('--klee-arg',action='append',default=[],help='extra KLEE option (repeatable), e.g. --klee-arg=--search=dfs')
    p.add_argument('--resume',action='store_true',help='publish a finished run left in OUT/work (same arguments as the original run)')
    p.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));p.add_argument('--klee',type=Path,default=Path('/opt/homebrew/bin/klee'))
    p.add_argument('--klee-include',type=Path,default=Path('/opt/homebrew/opt/klee/include'));a=p.parse_args()
    if a.reanalyze:
        r=reanalyze(a.reanalyze)
        print(json.dumps(dict(paths=r['paths'],required=r['required'],imprecise_reads=r['imprecise_reads'],comparison={k:v for k,v in r['comparison'].items() if k!='static_footprint'}),indent=2));return
    if not (a.boundary and a.slice and a.binding and a.out):p.error('--boundary, --slice, --binding and --out are required')
    args={};split=set()
    for spec in a.symbolic_arg:
        parts=spec.split(':')
        if len(parts)==4 and parts[3]=='split':split.add(int(parts[0],0));parts=parts[:3]
        if len(parts)!=3:p.error('--symbolic-arg takes INDEX:LOW:HIGH[:split]')
        index,low,high=(int(x,0) for x in parts);args[index]=(low,high)
    fields={}
    for spec in a.split_field:
        field,low,high=spec.rsplit(':',2);fields[field]=(int(low,0),int(high,0))
    r=discover(a.boundary,a.slice,a.binding,a.out,a.llvm_bin,a.klee,a.klee_include,args,a.max_time,a.contracts,a.resume,split,a.klee_arg,fields,a.separate_member)
    print(json.dumps(dict(root=r['root'],klee=r['klee'],paths=r['paths'],required=len(r['required']),unused_inputs=len(r['unused_inputs']),
        static_not_required=r['comparison']['static_not_required'],required_not_in_static=r['comparison']['required_not_in_static']),indent=2))
if __name__=='__main__':main()
