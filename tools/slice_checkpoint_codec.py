"""Generate a bounded field codec from reviewed policy and target Clang layout.
Every context field must have a policy. Persistent leaves are integer/byte
arrays; references are explicit self references or bounded object IDs. No raw context padding or
invocation pointers are included in the wire payload.
"""
import json,re,subprocess
from pathlib import Path
from contextify_slice import walk
from import_application_checkpoint import digest

SCALAR=re.compile(r'(?:u?int(?:8|16|32|64)_t|unsigned long|unsigned int|int|unsigned char|char)(?:\[\d+\])?$')
NAME=re.compile(r'[A-Za-z_]\w*$')
PATH=re.compile(r'[A-Za-z_]\w*(?:\[\d+\]|\.[A-Za-z_]\w*)*$')
ARRAY=re.compile(r'(.+)\[(\d+)\]$')
REFERENCES=('context_reference','context_buffer_reference')
def generate(sources,clang,contract,identity):
    policy=json.loads(Path(contract).read_text())
    if policy.get('format')!='osrec-slice-checkpoint-schema-v1':raise ValueError('unsupported checkpoint field policy')
    probe=sources/'slice_codec_probe.c';probe.write_text('#include "slice_context.h"\n')
    def ast():
        p=subprocess.run([str(clang),'--target=aarch64-none-elf','-ffreestanding','-std=c11','-I'+str(sources),'-Xclang','-ast-dump=json','-fsyntax-only',str(probe)],capture_output=True,text=True,timeout=60)
        if p.returncode:raise ValueError('checkpoint target layout failed: '+p.stderr)
        return list(walk(json.loads(p.stdout)))
    nodes=ast();byid={n['id']:n for n in nodes if 'id' in n}
    context=next(n for n in nodes if n['kind']=='RecordDecl' and n.get('name')=='osrec_kernel_context' and n.get('completeDefinition'))
    def record(t):
        candidates=[n for n in nodes if n['kind']=='TypedefDecl' and n.get('name')==t]
        if t.startswith('struct '):return next(n for n in nodes if n['kind']=='RecordDecl' and n.get('name')==t[7:] and n.get('completeDefinition'))
        refs=[n for c in candidates for n in walk(c) if n['kind']=='RecordType']
        if len(refs)!=1:raise ValueError('unsupported checkpoint aggregate '+t)
        return byid[refs[0]['decl']['id']]
    def plain(t,depth=0):
        # Integer bytes: a scalar, an integer typedef (pteval_t), an array of plain values, or a record of only plain
        # members (pud_t, a page table's descriptor); no pointer, so the bytes persist as they are.
        t=t.strip()
        if SCALAR.fullmatch(t):return True
        if depth>8 or '*' in t:return False
        array=ARRAY.fullmatch(t)
        if array:return plain(array[1],depth+1)
        typedefs=[n for n in nodes if n['kind']=='TypedefDecl' and n.get('name')==t]
        if len(typedefs)==1 and not t.startswith('struct '):
            under=typedefs[0].get('type',{}).get('qualType','')
            if under!=t and not under.startswith('struct {') and plain(under,depth+1):return True
        try:rec=record(t)
        except (ValueError,StopIteration):return False
        fields=[n for n in rec.get('inner',[]) if n['kind']=='FieldDecl']
        return rec.get('tagUsed')!='union' and bool(fields) and all(n.get('name') and plain(n['type']['qualType'],depth+1) for n in fields)
    leaves=[];objects={}
    def value(path,t,spec):
        if len(objects)>=8192 or len(leaves)>=4096:raise ValueError('checkpoint field expansion exceeds bounded codec')
        if not isinstance(spec,dict) or spec.get('type')!=t:raise ValueError('checkpoint field type changed: '+path)
        kind=spec.get('policy');objects[path]=dict(type=t,policy=kind)
        if kind=='members':
            rec=record(t)
            if rec.get('tagUsed')=='union':raise ValueError('checkpoint union requires an explicit adapter: '+path)
            visit(rec,spec.get('members'),path+'.');return
        if kind=='elements':
            # The first subscript is the outer dimension: T[4][14] has 4 elements of T[14].
            array=re.fullmatch(r'(.+?)\[(\d+)\]((?:\[\d+\])*)',t)
            if not array or not 0<int(array[2])<=512:raise ValueError('checkpoint elements need a bounded array: '+path)
            for i in range(int(array[2])):value(path+'['+str(i)+']',array[1].strip()+array[3],spec.get('element'))
            return
        if kind=='persist' and not plain(t):raise ValueError('persistent field is not a plain integer/byte leaf: '+path)
        if kind=='self_reference':
            target=spec.get('target','')
            if not NAME.fullmatch(target) or target not in policy['fields'] or '*' not in t:raise ValueError('invalid self reference '+path)
        elif kind in REFERENCES:
            targets=spec.get('targets');nullable=spec.get('nullable',False)
            if '*' not in t or 'volatile' in t or not isinstance(targets,list) or not 1<=len(targets)<=256 or any(not isinstance(p,str) or not PATH.fullmatch(p) for p in targets) or len(set(targets))!=len(targets) or type(nullable) is not bool:raise ValueError('invalid bounded context reference '+path)
            if kind=='context_buffer_reference' and type(spec.get('allow_one_past',False)) is not bool:raise ValueError('invalid buffer end policy '+path)
        elif kind not in ('persist','transient'):raise ValueError('invalid field policy '+path)
        leaves.append(dict(path=path,**spec))
    def named(rec,prefix):
        # Members of an anonymous struct or union are members of the enclosing record (C11 6.7.2.1).
        # An anonymous union persists one member; its other members must be transient aliases.
        out={};groups=[];inner=rec.get('inner',[])
        for k,n in enumerate(inner):
            if n['kind']!='FieldDecl':continue
            if n.get('name'):out[n['name']]=n;continue
            anonymous=inner[k-1] if k and inner[k-1]['kind']=='RecordDecl' and not inner[k-1].get('name') else None
            if anonymous is None or not anonymous.get('completeDefinition'):raise ValueError('unsupported unnamed checkpoint field: '+prefix)
            sub=named(anonymous,prefix);out.update(sub[0]);groups+=sub[1]
            if anonymous.get('tagUsed')=='union':groups.append([list(named(c,prefix)[0]) if not c.get('name') else [c['name']] for c in [inner_field_records(anonymous)][0]])
        return out,groups
    def inner_field_records(union):
        # Each member of a union: a named field, or an anonymous record standing for its fields.
        members=[];inner=union.get('inner',[])
        for k,n in enumerate(inner):
            if n['kind']!='FieldDecl':continue
            members.append(n if n.get('name') else inner[k-1])
        return members
    def visit(rec,pol,prefix=''):
        fields,unions=named(rec,prefix)
        if not isinstance(pol,dict):raise ValueError('missing checkpoint member policy: '+prefix)
        for union in unions:
            if sum(any(pol.get(n,{}).get('policy')!='transient' for n in member) for member in union)>1:raise ValueError('an anonymous union persists more than one member: '+prefix)
        if fields.keys()!=pol.keys():raise ValueError('checkpoint policy does not cover context fields: '+prefix)
        for name,f in fields.items():
            path=prefix+name
            if not NAME.fullmatch(name) or f.get('isBitfield'):raise ValueError('checkpoint field type changed: '+path)
            value(path,f['type']['qualType'],pol[name])
    visit(context,policy['fields'])
    references=[(i,f) for i,f in enumerate(leaves) if f['policy'] in REFERENCES]
    if len(leaves)>4096:raise ValueError('checkpoint field expansion exceeds bounded codec')
    enums={}
    for i,f in enumerate(leaves):
        enums['OFFSET_'+str(i)]='offsetof(struct osrec_kernel_context,'+f['path']+')'
        enums['BYTES_'+str(i)]='sizeof(((struct osrec_kernel_context *)0)->'+f['path']+')'
        if f['policy'] in REFERENCES:
            for j,target in enumerate(f['targets']):
                if target not in objects or objects[target]['policy']=='transient':raise ValueError('reference target is outside persistent context: '+target)
                buffer=f['policy']=='context_buffer_reference'
                if buffer and (objects[target]['policy']!='persist' or not ARRAY.fullmatch(objects[target]['type']) or not SCALAR.fullmatch(objects[target]['type']) or int(ARRAY.fullmatch(objects[target]['type'])[2])==0):raise ValueError('buffer reference requires a persistent scalar array: '+target)
                suffix=str(i)+'_'+str(j)
                enums['TARGET_OFFSET_'+suffix]='offsetof(struct osrec_kernel_context,'+target+')'
                enums['TARGET_BYTES_'+suffix]='sizeof(((struct osrec_kernel_context *)0)->'+target+')'
                element=target+('[0]' if buffer else '')
                # An untyped object pointer (SLUB's void **freelist) may name any persistent object.
                if f['type'] in ('void *','void **'):enums['TARGET_TYPE_'+suffix]='1';continue
                enums['TARGET_TYPE_'+suffix]='__builtin_types_compatible_p(__typeof__(*(((struct osrec_kernel_context *)0)->'+f['path']+')),__typeof__(((struct osrec_kernel_context *)0)->'+element+'))'
                if buffer:enums['TARGET_ELEMENT_BYTES_'+suffix]='sizeof(((struct osrec_kernel_context *)0)->'+element+')'
    probe.write_text('#include "slice_context.h"\nenum{'+','.join(k+'='+v for k,v in enums.items())+'};\n')
    values={}
    for n in ast():
        if n['kind']=='EnumConstantDecl' and n.get('name') in enums:
            c=[x for x in walk(n) if x['kind']=='ConstantExpr' and 'value' in x]
            if len(c)!=1:raise ValueError('nonconstant checkpoint layout')
            values[n['name']]=int(c[0]['value'])
    if values.keys()!=enums.keys():raise ValueError('missing checkpoint target offsets')
    cursor=0
    for i,f in enumerate(leaves):
        f.update(offset=values['OFFSET_'+str(i)],bytes=values['BYTES_'+str(i)])
        if f['policy']=='persist':f['wire_offset']=cursor;cursor+=f['bytes']
        elif f['policy'] in REFERENCES:
            if f['bytes']!=8:raise ValueError('context reference requires AArch64 pointer width')
            f['wire_offset']=cursor;f['wire_bytes']=16 if f['policy']=='context_buffer_reference' else 8;cursor+=f['wire_bytes'];f['reference_objects']=[]
            for j,target in enumerate(f['targets']):
                suffix=str(i)+'_'+str(j)
                if values['TARGET_TYPE_'+suffix]!=1:raise ValueError('context reference target type mismatch: '+f['path']+' -> '+target)
                f['reference_objects'].append(dict(id=j+1,path=target,type=objects[target]['type'],offset=values['TARGET_OFFSET_'+suffix],bytes=values['TARGET_BYTES_'+suffix]))
                if f['policy']=='context_buffer_reference':f['reference_objects'][-1]['element_bytes']=values['TARGET_ELEMENT_BYTES_'+suffix]
            if f['policy']=='context_buffer_reference':
                # An allowed end pointer must identify one buffer uniquely,
                # including when a second array immediately follows the first.
                for j,obj in enumerate(f['reference_objects']):
                    end=obj['offset']+obj['bytes']-(0 if f.get('allow_one_past',False) else obj['element_bytes'])
                    for other in f['reference_objects'][:j]:
                        other_end=other['offset']+other['bytes']-(0 if f.get('allow_one_past',False) else other['element_bytes'])
                        if obj['offset']<=other_end and other['offset']<=end:raise ValueError('buffer reference targets have ambiguous ranges: '+f['path'])
    if not 0<cursor<=65536:raise ValueError('checkpoint payload exceeds bounded codec')
    report=dict(format='osrec-slice-checkpoint-codec-v1',wire_isa='AArch64 little endian',header_bytes=64,payload_bytes=cursor,record_bytes=64+cursor,fields=leaves,identity=identity,policy_sha256=digest(Path(contract).read_bytes()))
    if references:report['context_reference_encoding']='bounded-object-id-v1; null=0; ids are field-local'
    if any(f['policy']=='context_buffer_reference' for _,f in references):report['context_buffer_reference_encoding']='bounded-buffer-offset-v1; field-local id:u64, byte-offset:u64; null=(0,0)'
    schema=digest(json.dumps(report,sort_keys=True,separators=(',',':')).encode());report['schema_sha256']=schema
    source='#include "slice_context.h"\n#include "osrec/slice_checkpoint.h"\nextern uint32_t osrec_kernel_checkpoint_check(const void *,uint64_t);\n'
    if references:
        source+='static uint64_t read_reference(const unsigned char *p){uint64_t v=0;for(unsigned i=0;i<8;++i)v|=(uint64_t)p[i]<<(8*i);return v;}\nstatic void write_reference(unsigned char *p,uint64_t v){for(unsigned i=0;i<8;++i)p[i]=(unsigned char)(v>>(8*i));}\n'
        for i,f in references:
            source+='static uint64_t reference_'+str(i)+'(const struct osrec_kernel_context *ctx){if(!ctx->'+f['path']+')return 0;\n'
            for j,obj in enumerate(f['reference_objects']):
                target=obj['path']
                if f['policy']=='context_buffer_reference':
                    limit=obj['bytes']-(0 if f.get('allow_one_past',False) else obj['element_bytes'])
                    source+='{uintptr_t p=(uintptr_t)ctx->'+f['path']+',base=(uintptr_t)&ctx->'+target+'[0];if(p>=base && p-base<='+str(limit)+' && (p-base)%'+str(obj['element_bytes'])+'==0)return '+str(j+1)+';}\n'
                else:source+='if((const void *)ctx->'+f['path']+'==(const void *)&ctx->'+target+')return '+str(j+1)+';\n'
            source+='return UINT64_MAX;}\n'
            if f['policy']=='context_buffer_reference':
                source+='static uint64_t reference_offset_'+str(i)+'(const struct osrec_kernel_context *ctx){switch(reference_'+str(i)+'(ctx)){\n'
                for obj in f['reference_objects']:source+='case '+str(obj['id'])+':return (uintptr_t)ctx->'+f['path']+'-(uintptr_t)&ctx->'+obj['path']+'[0];\n'
                source+='default:return 0;}}\n'
        source+='static uint32_t check(const void *state,uint64_t next){const struct osrec_kernel_context *ctx=state;\n'
        for i,f in references:source+='{uint64_t id=reference_'+str(i)+'(ctx);if(id==UINT64_MAX'+(' || !id' if not f.get('nullable',False) else '')+')return OSREC_SLICE_BAD_INPUT;}\n'
        source+='return osrec_kernel_checkpoint_check(state,next);}\n'
    source+='static void encode(const void *state,unsigned char *p){const struct osrec_kernel_context *ctx=state;\n'
    for i,f in enumerate(leaves):
        if f['policy']=='persist':source+='{const unsigned char *v=(const unsigned char *)&ctx->'+f['path']+';for(size_t i=0;i<'+str(f['bytes'])+';++i)p['+str(f['wire_offset'])+'+i]=v[i];}\n'
        elif f['policy'] in REFERENCES:
            source+='write_reference(p+'+str(f['wire_offset'])+',reference_'+str(i)+'(ctx));\n'
            if f['policy']=='context_buffer_reference':source+='write_reference(p+'+str(f['wire_offset']+8)+',reference_offset_'+str(i)+'(ctx));\n'
    source+='}\nstatic void decode(void *state,const unsigned char *p){struct osrec_kernel_context *ctx=state;osrec_kernel_adapter.restore(ctx);\n'
    for f in leaves:
        if f['policy']=='persist':source+='{unsigned char *v=(unsigned char *)&ctx->'+f['path']+';for(size_t i=0;i<'+str(f['bytes'])+';++i)v[i]=p['+str(f['wire_offset'])+'+i];}\n'
        elif f['policy']=='self_reference':source+='ctx->'+f['path']+'=&ctx->'+f['target']+';\n'
        elif f['policy'] in REFERENCES:
            source+='switch(read_reference(p+'+str(f['wire_offset'])+')){\n'
            for obj in f['reference_objects']:
                target=obj['path']
                if f['policy']=='context_buffer_reference':target+='[read_reference(p+'+str(f['wire_offset']+8)+')/'+str(obj['element_bytes'])+']'
                source+='case '+str(obj['id'])+':ctx->'+f['path']+'=(__typeof__(ctx->'+f['path']+'))(void *)&ctx->'+target+';break;\n'
            source+='default:ctx->'+f['path']+'=NULL;break;}\n'
    source+='}\nstatic uint32_t validate(const unsigned char *p,uint64_t next){\n'
    for i,f in references:
        source+='{uint64_t id=read_reference(p+'+str(f['wire_offset'])+');if(id>'+str(len(f['targets']))+(' || !id' if not f.get('nullable',False) else '')+')return OSREC_SLICE_BAD_INPUT;\n'
        if f['policy']=='context_buffer_reference':
            source+='uint64_t offset=read_reference(p+'+str(f['wire_offset']+8)+');switch(id){case 0:if(offset)return OSREC_SLICE_BAD_INPUT;break;\n'
            for obj in f['reference_objects']:
                limit=obj['bytes']-(0 if f.get('allow_one_past',False) else obj['element_bytes'])
                source+='case '+str(obj['id'])+':if(offset>'+str(limit)+' || offset%'+str(obj['element_bytes'])+')return OSREC_SLICE_BAD_INPUT;break;\n'
            source+='default:return OSREC_SLICE_BAD_INPUT;}\n'
        source+='}\n'
    check='check' if references else 'osrec_kernel_checkpoint_check'
    # The candidate state is decoded into static storage, not the stack: a context can outgrow the image's 16 KiB stack.
    source+='static struct osrec_kernel_context temporary;decode(&temporary,p);return '+check+'(&temporary,next);}\n'
    source+='const struct osrec_slice_checkpoint_codec osrec_kernel_checkpoint_codec={OSREC_SLICE_CHECKPOINT_ABI,{'+','.join(str(v) for v in bytes.fromhex(schema))+'},'+str(cursor)+',&osrec_kernel_adapter,'+check+',encode,validate,decode};\n'
    (sources/'slice_codec.c').write_text(source);(sources/'slice_checkpoint_schema.json').write_text(json.dumps(report,indent=2)+'\n')
    return report
