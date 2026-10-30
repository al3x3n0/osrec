"""Resident physical RAM and initialization requirements for MMU-off replay images.

Validates declared/startup ranges and optional loader snapshots, not every
possible dynamic pointer access.
"""

def _range(address,size):
    if type(address) is not int or type(size) is not int or address<0 or size<=0 or address+size>1<<64:
        raise ValueError('RAM ranges require integer addresses and positive bounded sizes')
    return address,address+size

def merged_ranges(regions):
    intervals=sorted(_range(r['address'],r['bytes']) for r in regions)
    merged=[]
    for start,end in intervals:
        if merged and start<=merged[-1][1]:merged[-1]=(merged[-1][0],max(end,merged[-1][1]))
        else:merged.append((start,end))
    return merged

def require_coverage(required,ram):
    available=merged_ranges(ram)
    for region in required:
        start,end=_range(region['address'],region['bytes'])
        if not any(a<=start and end<=b for a,b in available):
            raise ValueError(f"RAM does not cover {region.get('purpose','required range')} [0x{start:x},0x{end:x})")
    return available

def memory_contract(layout):
    required=[];zero=[]
    for i,segment in enumerate(layout['load_segments']):
        if segment['memory_bytes']:
            required.append({'address':segment['address'],'bytes':segment['memory_bytes'],'purpose':f'ELF load segment {i}'})
        if segment['memory_bytes']>segment['file_bytes']:
            zero.append({'address':segment['address']+segment['file_bytes'],'bytes':segment['memory_bytes']-segment['file_bytes']})
    startup=layout['startup_zero_range'];stack=layout['stack_range']
    required.extend([{**startup,'purpose':'startup BSS clearing'}, {**stack,'purpose':'stack'},
        {'address':layout['result_address'],'bytes':layout['result_bytes'],'purpose':'RAM result record'}])
    resident=[{'address':a,'bytes':b-a} for a,b in merged_ranges(required)]
    return {'format':'osrec-resident-physical-memory-v1','address_space':'physical','mmu_enabled_at_entry':False,
        'required_ranges':required,'resident_ram_ranges':resident,'loader_zero_fill_ranges':zero,
        'startup_zero_range':startup,'stack_range':stack,
        'raw_payload_range':{'address':layout['raw_image_load_address'],'bytes':max(s['address']+s['file_bytes'] for s in layout['load_segments'] if s['file_bytes'])-layout['raw_image_load_address']},
        'raw_loading_requires_entire_payload_range':True,
        'startup_zero_tail_outside_load_segments_bytes':layout['startup_zero_tail_bytes'],
        'initialization':'load ELF file bytes at physical addresses and zero each memory tail; raw loading requires the same zero-fill plan',
        'residency':'all required RAM remains accessible for the complete run; no demand paging or host fault service',
        'dynamic_access_coverage_proven':False,'rtl_execution_verified':False}

def validate_raw(binary,elf,layout):
    payload=binary.read_bytes();source=elf.read_bytes();base=layout['raw_image_load_address']
    backed=[s for s in layout['load_segments'] if s['file_bytes']]
    extent=max(s['address']+s['file_bytes'] for s in backed)-base
    if len(payload)!=extent:raise ValueError('raw image extent differs from ELF file-backed segments')
    for segment in backed:
        start=segment['address']-base;size=segment['file_bytes'];offset=segment['file_offset']
        if payload[start:start+size]!=source[offset:offset+size]:raise ValueError('raw image bytes differ from ELF load segment')
    return {'address':base,'bytes':len(payload)}


def _overlay(spans,new):
    """Overlay an initialization operation without allocating its contents."""
    start,end=_range(new['address'],new['bytes']);result=[]
    for span in spans:
        a,b=_range(span['address'],span['bytes'])
        if end<=a or b<=start:result.append(span);continue
        if a<start:result.append({**span,'bytes':start-a})
        if end<b:
            tail={**span,'address':end,'bytes':b-end}
            if span['file'] is not None:tail['offset']+=end-a
            result.append(tail)
    result.append(new)
    return sorted(result,key=lambda span:span['address'])


def initialization_spans(image,layout,binary=None):
    """Final loader contents: payload first, ELF bytes and zero-fill tails after."""
    spans=[]
    if binary is not None:
        payload=validate_raw(binary,image,layout)
        spans=[{**payload,'file':binary,'offset':0,'purpose':'raw payload'}]
    for i,segment in enumerate(layout['load_segments']):
        if segment['file_bytes']:
            spans=_overlay(spans,{'address':segment['address'],'bytes':segment['file_bytes'],
                'file':image,'offset':segment['file_offset'],'purpose':f'ELF segment {i} file bytes'})
        if segment['memory_bytes']>segment['file_bytes']:
            spans=_overlay(spans,{'address':segment['address']+segment['file_bytes'],
                'bytes':segment['memory_bytes']-segment['file_bytes'],'file':None,'offset':0,
                'purpose':f'ELF segment {i} zero-fill'})
    return spans


def verify_loaded_memory(image,layout,dumps,ram,binary=None):
    report=compare_physical_memory(initialization_spans(image,layout,binary),dumps,ram)
    return {**report,'format':'osrec-loaded-memory-verification-v1',
        'snapshot_phase':'after loading and zero-fill, before the first instruction',
        'loading_mode':'raw payload plus ELF zero-fill' if binary is not None else 'ELF segments',
        'initial_contents_verified':True,'dynamic_access_coverage_proven':False,
        'runtime_host_interaction':False,'rtl_execution_verified':False}


def compare_physical_memory(spans,dumps,ram):
    """Verify captured physical bytes after loading, before the first instruction.

    Files may be split across adjacent banks. Reads/hashes are streamed; unrelated
    RAM bytes are hashed for provenance but have no expected-value requirement.
    """
    import hashlib
    from pathlib import Path
    from contextlib import ExitStack
    if not dumps:raise ValueError('loaded memory verification requires dump files')
    views=[]
    for dump in dumps:
        path=Path(dump['file']);size=path.stat().st_size
        start,end=_range(dump['address'],size)
        views.append({'address':start,'bytes':size,'file':path,'end':end})
    views.sort(key=lambda view:view['address'])
    if any(a['end']>b['address'] for a,b in zip(views,views[1:])):
        raise ValueError('physical memory dumps overlap')
    require_coverage(views,ram)
    require_coverage(spans,views)
    records=[];verified=0
    with ExitStack() as stack:
        handles={path:stack.enter_context(path.open('rb')) for path in {v['file'] for v in views} | {s['file'] for s in spans if s['file'] is not None}}
        for span in spans:
            address=span['address'];remaining=span['bytes'];consumed=0
            while remaining:
                view=next(v for v in views if v['address']<=address<v['end'])
                size=min(remaining,view['end']-address,65536)
                actual_file=handles[view['file']];actual_file.seek(address-view['address']);actual=actual_file.read(size)
                if span['file'] is None:expected=bytes(size)
                else:
                    source=handles[span['file']];source.seek(span['offset']+consumed);expected=source.read(size)
                if len(actual)!=size or len(expected)!=size:raise ValueError('memory dump or source changed/truncated during verification')
                if actual!=expected:
                    mismatch=next(i for i,(a,b) in enumerate(zip(actual,expected)) if a!=b)
                    raise ValueError(f"loaded memory differs at 0x{address+mismatch:x} ({span['purpose']})")
                address+=size;consumed+=size;remaining-=size;verified+=size
        for view in views:
            handle=handles[view['file']];handle.seek(0);hasher=hashlib.sha256();total=0
            while block:=handle.read(65536):hasher.update(block);total+=len(block)
            if total!=view['bytes']:raise ValueError('memory dump changed size during verification')
            records.append({'address':view['address'],'bytes':view['bytes'],'file':str(view['file']),
                'sha256':hasher.hexdigest()})
    return {'format':'osrec-physical-memory-comparison-v1',
        'verified_bytes':verified,'verified_ranges':[{k:span[k] for k in ('address','bytes','purpose')} for span in spans],
        'dump_files':records}
