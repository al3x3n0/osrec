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
        if not FIELD.fullmatch(field.replace('[]','[0]')) or ('[]' not in field and 'class' not in item) or set(item)-{'path','equals','mask','class','percpu'} or not isinstance(item.get('path'),str) or item.get('class',1) not in classes:raise ValueError('invalid related member binding')
        # `percpu`: `path` reaches a per-CPU pointer; the member is read at `record` `path` of this CPU's copy,
        # or (`width`) the copy is a scalar of that many bytes.
        if 'percpu' in item and (set(item['percpu']) not in ({'record','path'},{'width'}) or item['percpu'].get('width',4) not in (1,2,4,8) or 'percpu' not in binding):raise ValueError('invalid per-CPU member binding')
    for item in related.get('preconditions',[]):
        if set(item)-{'path','equals','mask','class','reason','field'} or not isinstance(item.get('path'),str) or type(item.get('equals')) is not int or not item.get('reason') or item.get('class',1) not in classes:raise ValueError('invalid related precondition')
        # `field` names the schema field whose model value the precondition holds (per class with `[]`).
        if 'field' in item and (not FIELD.fullmatch(item['field'].replace('[]','[0]')) or ('[]' not in item['field'] and 'class' not in item)):raise ValueError('invalid related precondition')
    for link in related.get('links',[]):
        if set(link)-{'field','target','path','same_as','object','class'} or not all(FIELD.fullmatch(link[k].replace('[]','[0]')) for k in ('field','target')):raise ValueError('invalid related link binding')
        # Each class's object links to the target at its own index, or to one shared target; a link
        # of one class (`class`) names its field and target in full.
        if ('[]' not in link['field'])==('class' not in link) or (('same_as' in link or 'object' in link) and 'path' not in link) or link.get('class',1) not in classes:raise ValueError('a related link is set per class')
    u=binding.get('user_page')
    if u is not None and (set(u)-{'tables'}!={'review','number','argument','command_argument','command_mask','command_value','translation_register','memstart','page_offset','vmemmap_start','page_shift','page_record','folio_record','address_field','members','pointers'} or
            not all(FIELD.fullmatch(f) for f in [u['address_field'],*u['members'],*u['pointers']]) or 'percpu' not in binding):raise ValueError('invalid user page binding')
    # `tables`: the walked translation tables themselves (the setup pins them), for an original GUP-fast walk.
    t=(u or {}).get('tables')
    if t is not None and (set(t)!={'review','mm','mm_record','pgd_path','entries','addresses','mm_field','pfn_field'} or len(t['entries'])!=4 or len(t['addresses'])!=3 or
            not all(FIELD.fullmatch(f) for f in [t['mm'],t['mm_field'],t['pfn_field'],*(e.replace('[]','[0]') for e in t['entries']),*t['addresses']]) or not all(e.count('[]')==1 for e in t['entries']) or not t['review']):raise ValueError('invalid user page table binding')
    # `opaque_pointers`: a live pointer the slice carries as a value (tested, compared) and never dereferences.
    for field,item in binding.get('opaque_pointers',{}).items():
        if not FIELD.fullmatch(field) or set(item)-{'object'}!={'path','review'} or not isinstance(item['path'],str) or not item['review']:raise ValueError('invalid opaque pointer binding')
    for field,reason in binding.get('model_state',{}).items():
        if not FIELD.fullmatch(field.replace('[]','[0]')) or not isinstance(reason,str) or not reason:raise ValueError('invalid model-state declaration')
    for item in binding.get('preconditions',[]):
        # `equals_symbol`: the value is the address of a derived data symbol (current->nsproxy->time_ns is &init_time_ns).
        if set(item) not in ({'path','equals','reason'},{'path','equals_symbol','reason'}) or not isinstance(item['path'],str) or ('equals' in item and type(item['equals']) is not int) or ('equals_symbol' in item and not re.fullmatch(r'[A-Za-z_]\w*',item['equals_symbol'])):raise ValueError('invalid binding precondition')
    for g in binding.get('globals',[]):
        a=g.get('array',{})
        if (set(g)-{'symbol','page_offset','scalars','array'} or not re.fullmatch(r'[A-Za-z_]\w*',g.get('symbol','')) or type(g.get('page_offset')) is not int or
            any(not FIELD.fullmatch(f) or not isinstance(m,str) for f,m in g.get('scalars',{}).items()) or
            a and (set(a)-{'pointer','count','field','pool','capacity','record','members','transient','empty_lists'} or not FIELD.fullmatch(a.get('field','')) or not FIELD.fullmatch(a.get('pool','')) or
                   type(a.get('capacity')) is not int or not 0<a['capacity']<=256 or any(set(i)!={'path'} for i in a.get('members',{}).values()) or any(set(i)!={'path','reason'} for i in a.get('empty_lists',{}).values()) or
                   any(type(v) is not int for v in a.get('transient',{}).values()))):raise ValueError('invalid global binding')
    k=binding.get('kmalloc')
    if k is not None:
        if any(set(e)!={'index','names','words'} or set(e['names'])!=set(BASE_KMALLOC_NAMES) or type(e['words']) is not int or not 0<e['words']<=64 or type(e['index']) is not int for e in k.get('extra_caches',[])):raise ValueError('invalid extra kmalloc cache binding')
        if (set(k)-{'overlays','extra_caches'}!={'review','caches','size_index','type_row','index','cache','cpu','object','slab','page_offset','vmemmap_start','page_shift','page_record'} or not isinstance(k['review'],str) or
            any(not FIELD.fullmatch(f) or not isinstance(m,list) or not m or any(not FIELD.fullmatch(x) for x in m) for f,m in k.get('overlays',{}).items()) or
            any(not re.fullmatch(r'[A-Za-z_]\w*',k[n]) for n in ('caches','size_index','type_row','page_record')) or type(k['index']) is not int or
            any(not FIELD.fullmatch(f) for part in ('cache','cpu','slab') for f in k[part]['members']) or not FIELD.fullmatch(k['object']['field']) or
            type(k['object']['words']) is not int or not 0<k['object']['words']<=64 or 'percpu' not in binding):raise ValueError('invalid kmalloc binding')
    if 'percpu' in binding and (set(binding['percpu'])!={'offset_register'} or not re.fullmatch(r'[A-Za-z_]\w*',binding['percpu']['offset_register'])):raise ValueError('invalid per-CPU offset')
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

def project(binding,btf,memory,anchor,symbols=None,call=None,pinned=None):
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
    for field,item in binding.get('opaque_pointers',{}).items():
        raw=value(item['path']);state['evidence'][field]=dict(path=item['path'],raw=raw)
        state.setdefault('pointers',{})[field]=dict(target=None,live=raw,value=raw)
    # Live values a reviewed model holds constant: a state where one differs is outside the model.
    for item in binding.get('preconditions',[]):
        raw=value(item['path']);state['evidence']['precondition '+item['path']]=dict(raw=raw)
        if 'equals_symbol' in item:
            if symbols is None or item['equals_symbol'] not in symbols.get('symbols',{}):raise ValueError('binding needs the derived data symbol '+item['equals_symbol'])
            want=int(symbols['symbols'][item['equals_symbol']]['address'],16)
        else:want=item['equals']
        if raw!=want:raise ValueError('live %s=%#x differs from the model constant %#x: %s'%(item['path'],raw,want,item['reason']))
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
            if 'percpu' in item:
                # A per-CPU pointer plus this CPU's offset (arm64: TPIDR_EL1) addresses this CPU's copy.
                copy=(raw+percpu_offset(binding,memory,state))&(1<<64)-1
                if 'width' in item['percpu']:raw=read(copy,item['percpu']['width'])
                else:place,kind=resolve(btf,read,copy,item['percpu']['record'],item['percpu']['path']);raw=read(place,btf.scalar(kind))
            if 'mask' in item:raw&=item['mask']
            if 'equals' in item:raw=int(raw==item['equals'])
            state['scalars'][field]=raw;state['evidence'][field]=dict(path=item['path'],object=o['address'])
        for link in related.get('links',[]):
            if 'path' not in link or link.get('class',i+1)!=i+1:continue
            pointer=value(link['path'],o['address'],file_record)
            if not pointer:raise ValueError('live %s is null'%link['field'].replace('[]','[%d]'%i))
            if 'same_as' in link and pointer!=value(link['same_as'],o['address'],file_record):raise ValueError('live %s differs from %s'%(link['path'],link['same_as']))
            # An embedded target: the pointer is the address of that member of the live object.
            if 'object' in link and pointer!=resolve(btf,read,o['address'],file_record,link['object'])[0]:raise ValueError('live %s is not %s'%(link['path'],link['object']))
            state['evidence'][link['field'].replace('[]','[%d]'%i)]=dict(pointer=pointer)
    f=binding.get('file_data')
    if f:
        owner=pool.get(f['class'])
        if owner is None:
            # Released objects have no live address; their bytes are unobservable, not zero.
            state['file_data']=None;state['transient']=dict(binding['transient']);project_globals(binding,btf,memory,symbols,state);project_kmalloc(binding,btf,memory,symbols,state,pinned);return state
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
    project_globals(binding,btf,memory,symbols,state)
    project_kmalloc(binding,btf,memory,symbols,state,pinned)
    project_user_page(binding,btf,memory,symbols,state,call)
    return state

def project_user_page(binding,btf,memory,symbols,state,call):
    """Bind the folio behind a call's user word (`user_page`), as GUP-fast finds it.

    Only a call of `number` whose command argument, masked, equals `command_value` (a shared futex) has one:
    the word's page is walked from the translation register (4 KiB granule, 48-bit VA, four levels) and must be
    a valid user page that pte_write() admits (PTE_WRITE, the DBM bit). Its struct page is the vmemmap entry of
    (pa - memstart_addr) >> page_shift, and the folio is that page or its compound head. Any other call, or a
    word without such a page, binds address 0: the slice's get_user_pages_fast then faults.
    """
    u=binding.get('user_page')
    if u is None:return
    address=0;folio=None;tables=None;t=u.get('tables')
    if call is not None and call['number']==u['number'] and call['arguments'][u['command_argument']]&u['command_mask']==u['command_value']:
        if symbols is None or u['memstart'] not in symbols.get('symbols',{}):raise ValueError('binding needs the derived data symbol '+u['memstart'])
        memstart=memory.u(int(symbols['symbols'][u['memstart']]['address'],16))
        va=call['arguments'][u['argument']];linear=lambda pa:u['page_offset']+pa-memstart
        table=memory.register(u['translation_register'])&0x0000fffffffffffe;desc=0;walked=[]
        for level,shift in enumerate((39,30,21,12)):
            walked.append(table)
            desc=memory.u(linear(table+((va>>shift)&511)*8))
            if desc&3!=3:desc=0;break
            table=desc&0x0000fffffffff000
        # AP[1] (bit 6): EL0 access; PTE_WRITE (bit 51): pte_write().
        if desc and desc&1<<6 and desc&1<<51:
            pa=desc&0x0000fffffffff000;stride=btf.sizeof(btf.struct(u['page_record']))
            page=u['vmemmap_start']+((pa-memstart)>>u['page_shift'])*stride
            compound=memory.u(resolve(btf,memory.u,page,u['page_record'],'.compound_head')[0])
            folio=compound-1 if compound&1 else page;address=va&~((1<<u['page_shift'])-1)
            state['evidence']['user_page']=dict(va=va,pte=desc,pa=pa,page=page,folio=folio)
            if t is not None:
                # The slice walks these four pages as GUP-fast does: mm->pgd must be TTBR0's table (ASID bits
                # aside), and its __va of each next-level address is that page.
                mm=state['scalars'][t['mm']]
                pgd=memory.u(resolve(btf,memory.u,mm,t['mm_record'],t['pgd_path'])[0])
                if pgd!=linear(walked[0]):raise ValueError('live mm->pgd is not the translation table')
                tables=dict(mm=mm,pa=walked,pfn=pa>>u['page_shift'])
    if t is not None:
        state['scalars'][t['mm_field']]=tables['mm'] if tables else 0
        state['scalars'][t['pfn_field']]=tables['pfn'] if tables else 0
        for i,field in enumerate(t['addresses']):state['scalars'][field]=tables['pa'][i+1] if tables else 0
        for i,field in enumerate(t['entries']):
            data=memory.read(linear(tables['pa'][i]),4096) if tables else bytes(4096)
            # `field` names one descriptor with `[]` for its index (osrec_pud_table.entries[].pud).
            for j in range(512):state['scalars'][field.replace('[]','[%d]'%j)]=int.from_bytes(data[8*j:8*j+8],'little')
        if tables:state['evidence']['user_page_tables']=dict(mm=tables['mm'],pa=tables['pa'])
    state['scalars'][u['address_field']]=address
    for field,path in u['members'].items():
        state['scalars'][field]=0 if folio is None else memory.u(*(lambda p:(p[0],btf.scalar(p[1])))(resolve(btf,memory.u,folio,u['folio_record'],path)))
    for field,path in u['pointers'].items():
        raw=0 if folio is None else memory.u(resolve(btf,memory.u,folio,u['folio_record'],path)[0])
        state.setdefault('pointers',{})[field]=dict(target=None,live=raw,value=raw)

def percpu_offset(binding,memory,state):
    """This CPU's per-CPU offset, read once from the binding's register in kernel mode."""
    if 'percpu_offset' not in state['evidence']:state['evidence']['percpu_offset']=memory.register(binding['percpu']['offset_register'])
    return state['evidence']['percpu_offset']

def project_globals(binding,btf,memory,symbols,state):
    """Bind kernel data symbols the task does not reach (`globals`), from a derived symbol source.

    Each symbol's reviewed layout is checked against live memory first (kernel_data_symbols.check_live).
    Its `scalars` name layout fields; its `array` is the counted array a pointer field holds, bound
    element by element into a slice pool of exactly that many elements, whose reference field
    (`field`) then names the pool's first element.
    """
    from kernel_data_symbols import check_live
    for g in binding.get('globals',[]):
        if symbols is None or g['symbol'] not in symbols.get('symbols',{}):raise ValueError('binding needs the derived data symbol '+g['symbol'])
        symbol=symbols['symbols'][g['symbol']]
        # A per-CPU symbol is bound at this CPU's copy.
        if symbol.get('percpu'):symbol=dict(symbol,address='%#x'%((int(symbol['address'],16)+percpu_offset(binding,memory,state))&(1<<64)-1))
        evidence=check_live(symbol,btf,memory,g['page_offset'])
        state['evidence']['global '+g['symbol']]=dict(address=symbol['address'],**evidence)
        for field,member in g.get('scalars',{}).items():state['scalars'][field]=evidence[member]
        a=g.get('array')
        if not a:continue
        count=evidence[a['count']];array=evidence[a['pointer']]
        if count!=a['capacity']:raise ValueError('live %s.%s=%d differs from the slice pool of %d'%(g['symbol'],a['count'],count,a['capacity']))
        record=btf.struct(a['record']);stride=btf.sizeof(record);data=memory.read(array,count*stride)
        members={}
        for name,item in a['members'].items():
            place,kind=resolve(btf,memory.u,array,a['record'],item['path'])
            if not 0<=place-array<stride:raise ValueError('array member path leaves its element: '+item['path'])
            members[name]=(place-array,btf.scalar(kind))
        # A list head the slice never links (an empty_lists path) must be empty in every element: next and prev are its own address.
        heads={}
        for name,item in a.get('empty_lists',{}).items():
            place,_=resolve(btf,memory.u,array,a['record'],item['path'])
            if not 0<=place-array<=stride-16:raise ValueError('array list path leaves its element: '+item['path'])
            heads[name]=place-array
        for i in range(count):
            for name,offset in heads.items():
                head=array+i*stride+offset;links=[int.from_bytes(data[i*stride+offset+k:i*stride+offset+k+8],'little') for k in (0,8)]
                if links!=[head,head]:raise ValueError('live %s[%d].%s is not empty'%(a['pool'],i,name))
            for name,(offset,width) in members.items():state['scalars']['%s[%d].%s'%(a['pool'],i,name)]=int.from_bytes(data[i*stride+offset:i*stride+offset+width],'little')
            for name,value in a.get('transient',{}).items():state['transient']['%s[%d].%s'%(a['pool'],i,name)]=value
        state.setdefault('references',{})[a['field']]=a['pool']+'[0]'

BASE_KMALLOC_NAMES=dict(cache='kmalloc_cache',cpu='kmalloc_cpu',object='kmalloc_object',slab='kmalloc_object_slab')
def kmalloc_specs(k):
    """(index, slice object names, object words) of each bound cache: the `kmalloc` one, then its `extra_caches`."""
    return [(k['index'],BASE_KMALLOC_NAMES,k['object']['words'])]+[(e['index'],e['names'],e['words']) for e in k.get('extra_caches',[])]
def kmalloc_field(field,names):
    """A schema field of the base cache's objects, renamed to another cache's (kmalloc_cpu.tid -> kmalloc96_cpu.tid)."""
    for role,base in BASE_KMALLOC_NAMES.items():
        if field==base or field.startswith(base+'.') or field.startswith(base+'['):return names[role]+field[len(base):]
    return field

def project_kmalloc(binding,btf,memory,symbols,state,pinned=None):
    """Bind kmalloc caches, this CPU's slab of each and the object at the head of its per-CPU freelist (`kmalloc`).

    Each cache is kmalloc_caches[type_row][index] from the derived data symbols, with the size index
    table: the `kmalloc` cache, and any `extra_caches` (another index, its own slice objects and object
    size). Pointer fields that name a slice object (a cache, its per-CPU copy, the freelist head and
    its slab) become `pointers`: the replay binds each to that object when the live value is the
    object's live address and keeps the raw value otherwise, and exports it back the same way. A
    freelist head must be a linear-map object inside the cache's per-CPU slab, a slab head page of
    that cache, with its free pointer inside the object; the object's words are bound.

    `pinned` (the pre-state's object addresses, by slice object) keeps a post-state on the same memory: a call
    that allocated the head object leaves the freelist at another object, and the slice object is still the
    allocated one. The freelist pointer is then compared as a value.
    """
    k=binding.get('kmalloc')
    if not k:return
    if symbols is None or not {k['caches'],k['size_index']}<=set(symbols.get('symbols',{})):raise ValueError('binding needs the derived data symbols %s and %s'%(k['caches'],k['size_index']))
    from kernel_data_symbols import check_live
    read=memory.u
    def value(record,path,base):
        place,kind=resolve(btf,read,base,record,path);return read(place,btf.scalar(kind))
    index=check_live(symbols['symbols'][k['size_index']],btf,memory,k['page_offset'])
    caches=check_live(symbols['symbols'][k['caches']],btf,memory,k['page_offset'])
    sizes=[index['i%d'%i] for i in range(24)];row=[caches['%s_%d'%(k['type_row'],i)] for i in range(14)]
    for i,v in enumerate(sizes):state['scalars']['kmalloc_size_index[%d]'%i]=v
    specs=kmalloc_specs(k);live={}
    for at,names,_ in specs:
        if not row[at]:raise ValueError('live kmalloc_caches[%s][%d] is null'%(k['type_row'],at))
        live[at]=(names,row[at])
    pointers={}
    # Each row entry names the slice cache at its index; the others keep their live values.
    for i,v in enumerate(row):
        names,cache=live.get(i,live[specs[0][0]]);pointers['kmalloc_caches[0][%d]'%i]=dict(target=names['cache'],live=cache,value=v)
    state['evidence']['kmalloc']={};heads={}
    for at,names,words in specs:
        cache=row[at];rename=lambda f:kmalloc_field(f,names)
        for field,path in k['cache']['members'].items():state['scalars'][rename(field)]=value(k['cache']['record'],path,cache)
        for path,want in k['cache'].get('require',{}).items():
            got=value(k['cache']['record'],path,cache)
            if got!=want:raise ValueError('live kmalloc cache %s=%d differs from the slice model %d'%(path,got,want))
        size=value(k['cache']['record'],'.object_size',cache);offset=value(k['cache']['record'],'.offset',cache)
        if size!=8*words:raise ValueError('live kmalloc cache object size %d is not the slice object of %d bytes'%(size,8*words))
        if offset%8 or offset+8>size:raise ValueError('live kmalloc cache keeps its free pointer outside the object')
        raw_cpu=value(k['cache']['record'],k['cache']['cpu'],cache);cpu=(raw_cpu+percpu_offset(binding,memory,state))&(1<<64)-1
        pointers[names['cache']+'.cpu_slab']=dict(target=names['cpu'],live=raw_cpu,value=raw_cpu)
        for field,path in k['cpu']['members'].items():state['scalars'][rename(field)]=value(k['cpu']['record'],path,cpu)
        head=value(k['cpu']['record'],k['cpu']['freelist'],cpu);slab=value(k['cpu']['record'],k['cpu']['slab'],cpu)
        current=head;head=(pinned or {}).get(names['object'],head)
        if not head or not slab:raise ValueError('live per-CPU kmalloc freelist or slab is empty (the slow path is outside the slice)')
        if head<k['page_offset'] or head%8:raise ValueError('live freelist head is not a linear-map object')
        stride=btf.sizeof(btf.struct(k['page_record']))
        page=k['vmemmap_start']+((head-k['page_offset'])>>k['page_shift'])*stride
        compound=value(k['page_record'],'.compound_head',page);folio=compound-1 if compound&1 else page
        if folio!=slab:raise ValueError('live freelist head %#x is not in the per-CPU slab %#x'%(head,slab))
        page_type=value(k['page_record'],'.page_type',folio)
        # include/linux/page-flags.h: PageType(page, PG_slab) with PAGE_TYPE_BASE 0xf0000000 and PG_slab 0x1000.
        if page_type&(0xf0000000|0x1000)!=0xf0000000:raise ValueError('live per-CPU slab page has no slab type: %#x'%page_type)
        if value(k['slab']['record'],k['slab']['cache'],folio)!=cache:raise ValueError('live per-CPU slab belongs to another cache')
        for field,path in k['slab']['members'].items():state['scalars'][rename(field)]=value(k['slab']['record'],path,folio)
        heads[names['object']]=head
        pointers[names['cpu']+'.freelist']=dict(target=names['object'],live=head,value=current)
        pointers[names['cpu']+'.slab']=dict(target=names['slab'],live=slab,value=slab)
        pointers[names['slab']+'.slab_cache']=dict(target=names['cache'],live=cache,value=cache)
        data=memory.read(head,size)
        for i in range(words):state['scalars']['%s[%d]'%(rename(k['object']['field']),i)]=int.from_bytes(data[8*i:8*i+8],'little')
        for field,v in k['cache'].get('transient',{}).items():state['transient'][rename(field)]=v
        evidence=dict(cache=cache,cpu=cpu,object=head,slab=slab,page=page,page_type=page_type)
        if at==specs[0][0]:state['evidence']['kmalloc'].update(evidence)
        else:state['evidence']['kmalloc'][names['object']]=evidence
    state.setdefault('pointers',{}).update(pointers)
    # An opaque pointer may name a slab object: it is that object when it holds the object's live address.
    for field,item in binding.get('opaque_pointers',{}).items():
        if 'object' in item and field in state['pointers']:
            if item['object'] not in heads:raise ValueError('opaque pointer names an unbound slab object '+item['object'])
            state['pointers'][field]=dict(state['pointers'][field],target=item['object'],live=heads[item['object']])
