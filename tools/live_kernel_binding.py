#!/usr/bin/env python3
"""Project live kernel objects onto a slice checkpoint schema through reviewed BTF paths.

The binding names which kernel field supplies each schema field. Member offsets,
widths and pointer types come from the running kernel's BTF. Nothing here infers
semantic correspondence; unbound or ambiguous objects are rejected.
"""
import re
from kernel_btf import resolve

FORMAT='osrec-live-kernel-binding-v1'
FIELD=re.compile(r'[A-Za-z_][A-Za-z_0-9]*(\[\d+\])?(\.[A-Za-z_][A-Za-z_0-9]*(\[\d+\])?)*')

def validate(binding):
    if binding.get('format')!=FORMAT or binding.get('type_source')!='embedded-btf':raise ValueError('unsupported live kernel binding')
    anchor=binding.get('anchor',{})
    if not re.fullmatch(r'[A-Za-z_]\w*',anchor.get('name','')) or not re.fullmatch(r'[A-Za-z_]\w*',anchor.get('record','')):raise ValueError('binding anchor missing')
    fields=[*binding['scalars'],*binding['transient'],*(e['field'] for e in binding.get('embedded',[]))]
    if any(not FIELD.fullmatch(f) for f in fields) or len(set(fields))!=len(fields):raise ValueError('invalid or duplicate bound schema field')
    for item in binding['scalars'].values():
        if set(item)-{'path','equals','mask','require'} or not isinstance(item.get('path'),str):raise ValueError('invalid scalar binding')
    d=binding['descriptors']
    if not FIELD.fullmatch(d['slots']) or not FIELD.fullmatch(d['pool']) or type(d['capacity']) is not int or not 0<d['capacity']<=1024:raise ValueError('invalid descriptor binding')
    if sorted(d['class']['values'].values())!=list(range(1,len(d['class']['values'])+1)):raise ValueError('object classes must number pool slots 1..N')
    related=d.get('related',{})
    classes=set(d['class']['values'].values())
    for field,item in related.get('members',{}).items():
        # A member read from one class's object (`class`) may bind a field outside the per-class pools.
        if not FIELD.fullmatch(field.replace('[]','[0]')) or ('[]' not in field and 'class' not in item) or set(item)-{'path','equals','mask','class'} or not isinstance(item.get('path'),str) or item.get('class',1) not in classes:raise ValueError('invalid related member binding')
    for item in related.get('preconditions',[]):
        if set(item)-{'path','equals','mask','class','reason'} or not isinstance(item.get('path'),str) or type(item.get('equals')) is not int or not item.get('reason') or item.get('class',1) not in classes:raise ValueError('invalid related precondition')
    for link in related.get('links',[]):
        if set(link)-{'field','target','path','same_as'} or not all(FIELD.fullmatch(link[k].replace('[]','[0]')) for k in ('field','target')):raise ValueError('invalid related link binding')
        # Each class's object links to the target at its own index, or to one shared target.
        if '[]' not in link['field'] or ('same_as' in link and 'path' not in link):raise ValueError('a related link is set per class')
    for item in binding.get('preconditions',[]):
        if set(item)!={'path','equals','reason'} or not isinstance(item['path'],str) or type(item['equals']) is not int:raise ValueError('invalid binding precondition')
    x=binding.get('external')
    if x is not None and (type(x.get('descriptor_argument')) is not int or not all(type(n) is int for n in x.get('descriptor_numbers',[])) or not set(x.get('classes',[]))<=set(d['class']['values'].values())):raise ValueError('invalid external-call rule')
    return binding

def check_config(binding,config_text):
    config={}
    for line in config_text.splitlines():
        m=re.fullmatch(r'(CONFIG_\w+)=(.*)',line.strip()) or re.fullmatch(r'# (CONFIG_\w+) is not set',line.strip())
        if m:config[m.group(1)]=m.group(2).strip('"') if m.lastindex==2 else None
    for key,value in binding.get('kernel_config',{}).items():
        if config.get(key)!=value:raise ValueError('kernel configuration differs from binding: %s=%r'%(key,config.get(key)))

def pointee(btf,kind):
    t=btf.types[btf.strip(kind)]
    if t['kind']!='ptr':raise ValueError('expected a pointer type')
    return t['value']

def project(binding,btf,memory,anchor):
    """Return bound scalar fields, pool objects and descriptor slots below `anchor`.

    `memory.u(address,size)` reads a little-endian integer and `memory.read`
    returns bytes; both must see kernel virtual memory.
    """
    record=binding['anchor']['record'];read=memory.u
    def value(path,base=anchor,base_record=record):
        place,kind=resolve(btf,read,base,base_record,path);return read(place,btf.scalar(kind))
    state={'scalars':{},'evidence':{}}
    for field,item in binding['scalars'].items():
        raw=value(item['path']);state['evidence'][field]=dict(path=item['path'],raw=raw)
        if 'mask' in item:raw&=item['mask']
        if 'require' in item and raw!=item['require']:raise ValueError('live %s=%d differs from the slice model requirement %d'%(field,raw,item['require']))
        if 'equals' in item:raw=int(raw==item['equals'])
        state['scalars'][field]=raw
    # Live values a reviewed model holds constant: a state where one differs is outside the model.
    for item in binding.get('preconditions',[]):
        raw=value(item['path']);state['evidence']['precondition '+item['path']]=dict(raw=raw)
        if raw!=item['equals']:raise ValueError('live %s=%d differs from the model constant %d: %s'%(item['path'],raw,item['equals'],item['reason']))
    for item in binding.get('embedded',[]):
        pointer=value(item['pointer']);place,_=resolve(btf,read,anchor,record,item['object'])
        if pointer!=place:raise ValueError('live pointer is not the embedded object required by '+item['field'])
        state['evidence'][item['field']]=dict(pointer=pointer,object=place)
    d=binding['descriptors'];place,kind=resolve(btf,read,anchor,record,d['table']);width=btf.sizeof(kind);table=read(place,width)
    count=value(d['count']) if 'count' in d else d['capacity']
    if count>d['capacity']:raise ValueError('live descriptor table exceeds slice capacity')
    pool={};slots=[]
    file_record=btf.types[btf.strip(pointee(btf,pointee(btf,kind)))]['name']
    for fd in range(count):
        address=read(table+width*fd,width)
        if not address:slots.append(0);continue
        mode=value(d['class']['path'],address,file_record)&d['class']['mask']
        cls=d['class']['values'].get(str(mode))
        if cls is None:raise ValueError('live descriptor %d has an unbound object class 0%o'%(fd,mode))
        if cls in pool and pool[cls]['address']!=address:raise ValueError('more than one live object for slice pool class %d'%cls)
        if cls not in pool:
            members={}
            for name,item in d['members'].items():
                raw=value(item['path'],address,file_record);members[name]=raw&item['mask'] if 'mask' in item else raw
                if 'mask' in item:members[name+'_native']=raw
            pool[cls]=dict(address=address,object_id=cls,**members)
        slots.append(cls)
    state['pool']=[pool.get(c) for c in range(1,len(d['class']['values'])+1)];state['slots']=slots
    # Objects reached from a live file (its dentry and inode) sit at the file's class index in their
    # pools. Released classes have none: their fields are unobservable and left out.
    related=d.get('related',{})
    for i,o in enumerate(state['pool']):
        if o is None:continue
        for item in related.get('preconditions',[]):
            if item.get('class',i+1)!=i+1:continue
            raw=value(item['path'],o['address'],file_record)
            if 'mask' in item:raw&=item['mask']
            state['evidence']['precondition class %d %s'%(i+1,item['path'])]=dict(raw=raw)
            if raw!=item['equals']:raise ValueError('live class %d %s=%d differs from the model constant %d: %s'%(i+1,item['path'],raw,item['equals'],item['reason']))
        for field,item in related.get('members',{}).items():
            if item.get('class',i+1)!=i+1:continue
            raw=value(item['path'],o['address'],file_record);field=field.replace('[]','[%d]'%i)
            if 'mask' in item:raw&=item['mask']
            if 'equals' in item:raw=int(raw==item['equals'])
            state['scalars'][field]=raw;state['evidence'][field]=dict(path=item['path'],object=o['address'])
        for link in related.get('links',[]):
            if 'path' not in link:continue
            pointer=value(link['path'],o['address'],file_record)
            if not pointer:raise ValueError('live %s is null'%link['field'].replace('[]','[%d]'%i))
            if 'same_as' in link and pointer!=value(link['same_as'],o['address'],file_record):raise ValueError('live %s differs from %s'%(link['path'],link['same_as']))
            state['evidence'][link['field'].replace('[]','[%d]'%i)]=dict(pointer=pointer)
    f=binding.get('file_data')
    if f:
        owner=pool.get(f['class'])
        if owner is None:
            # Released objects have no live address; their bytes are unobservable, not zero.
            state['file_data']=None;state['transient']=dict(binding['transient']);return state
        size=value(f['size'],owner['address'],file_record);pages=value(f['pages'],owner['address'],file_record)
        if not 0<=size<=f['bytes']:raise ValueError('live file size exceeds slice store')
        data=bytes(f['bytes'])
        if size:
            head=value(f['head'],owner['address'],file_record)
            if pages!=1 or head&3 or head<f['vmemmap_start']:raise ValueError('live page cache is not one direct page entry')
            stride=btf.sizeof(btf.struct(f['page_record']))
            if (head-f['vmemmap_start'])%stride:raise ValueError('page-cache entry is not a page descriptor')
            linear=f['page_offset']+(((head-f['vmemmap_start'])//stride)<<f['page_shift'])
            data=memory.read(linear,f['bytes']);state['evidence']['file_data']=dict(head=head,linear=linear,pages=pages)
            if any(data[size:]):raise ValueError('live page bytes beyond i_size are not zero')
        state['file_data']=dict(size=size,bytes=data.hex())
    state['transient']=dict(binding['transient'])
    return state
