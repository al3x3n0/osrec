"""Reviewed four-call UID/GID query contracts with ordered output-copy effects."""
from entry_state_continuity import canonical_state
from entry_state_lifetimes import validate_lifetimes
from getgroups_capture import output_bytes

PROFILES={
 'getresuid':{'fields':('userID','effUserID'),'values':(6001,6002),'number':209,'prefix':'RESUID'},
 'getresgid':{'fields':('gid','effGid'),'values':(7001,7002),'number':211,'prefix':'RESGID'},
}

def output_offsets(bundle,kind):
    version=bundle.get('format')
    if version=='osrec-live-'+kind+'-v1':
        if 'output_offsets' in bundle:raise ValueError(kind+' legacy output geometry differs')
        return [0,4,8]
    offsets=bundle.get('output_offsets')
    if version not in ('osrec-live-'+kind+'-v2','osrec-live-'+kind+'-v3') or not isinstance(offsets,list) or len(offsets)!=3 or any(type(v) is not int or not 0<=v<=12 for v in offsets) or (version.endswith('-v2') and offsets==[0,4,8]):
        raise ValueError(kind+' output offsets differ')
    return offsets

def credential_values(bundle,kind):
    fixture=bundle.get('credential_fixture')
    if not isinstance(fixture,dict) or set(fixture)!={'real','effective','scope'} or fixture['scope']!='selected syscall only; native fields restored afterward' or any(type(fixture[k]) is not int or not 0<=fixture[k]<=0xffffffff for k in ('real','effective')):
        raise ValueError(kind+' credential fixture differs')
    values=[fixture['real'],fixture['effective']]
    custom=bundle.get('format')=='osrec-live-'+kind+'-v3'
    if custom:
        if values==list(PROFILES[kind]['values']) or bundle.get('entry_state_generation')!='configured-clang-fields-v1':raise ValueError(kind+' custom credential profile differs')
    elif values!=list(PROFILES[kind]['values']):raise ValueError(kind+' legacy credential fixture differs')
    return values

def credential_state(frame,kind='getresuid'):
    names=PROFILES[kind]['fields']
    if frame.get('format')!='osrec-entry-snapshot-v1' or len(frame['objects'])!=2 or len(frame['roots'])!=1 or len(frame['fields'])!=3:
        raise ValueError(kind+' footprint differs')
    if any('address' in r for r in frame['objects']):raise ValueError(kind+' addresses forbidden')
    objects,roots,fields=canonical_state(frame)
    if set(roots)!={'OsCurrProcessGet()'}:raise ValueError(kind+' provider differs')
    process=roots['OsCurrProcessGet()'];edge=fields.get((process,'user'))
    if not edge or edge[0]!='edge' or not edge[1]:raise ValueError(kind+' user edge missing')
    user=edge[1]
    if objects!={process:'LosProcessCB',user:'User'} or set(fields)!={(process,'user'),(user,names[0]),(user,names[1])}:
        raise ValueError(kind+' object graph differs')
    values=[]
    for name in names:
        row=fields[user,name]
        if row[:2]!=('scalar',4) or len(row[2])!=4:raise ValueError(kind+' field width differs')
        values.append(int.from_bytes(row[2],'little'))
    return values,(objects,roots,fields)

def validate_credential_query(bundle,lifetimes,kind):
    profile=PROFILES[kind];values_expected=credential_values(bundle,kind)
    offsets=output_offsets(bundle,kind)
    if 'entry_state_generation' in bundle and bundle['entry_state_generation']!='configured-clang-fields-v1':raise ValueError(kind+' entry field generation differs')
    if len(bundle['calls'])!=4:
        raise ValueError(kind+' capture profile differs')
    area=bundle.get('output_region')
    if area!={'id':301,'offset':0,'bytes':16} or any(type(v) is not int for v in area.values()):raise ValueError(kind+' output witness differs')
    calls=bundle['calls'];validate_lifetimes(lifetimes,[c[k] for c in calls for k in ('entry','exit')])
    previous=None;prior_output=None
    for i,c in enumerate(calls):
        args=[None if i==j+1 else {'id':301,'offset':offsets[j],'bytes':4} for j in range(3)]
        for refs in (c['arguments'],c['entry']['arguments'],c['exit']['arguments']):
            if not isinstance(refs,list) or len(refs)!=3:raise ValueError(kind+' pointer count differs')
            for ref in refs:
                if ref is not None and (not isinstance(ref,dict) or set(ref)!={'id','offset','bytes'} or any(type(v) is not int for v in ref.values())):raise ValueError(kind+' pointer schema differs')
        if c['arguments']!=args or c['invocation']!=i or type(c['invocation']) is not int or type(c['raw']) is not int or c['raw']!=(0 if i==0 else 0xfffffff2):raise ValueError(kind+' arguments/return differ')
        for key in ('entry','exit'):
            f=c[key]
            if any(type(f[n]) is not int for n in ('syscall','invocation','raw')) or 'allocation_attempts' in f or f['syscall']!=profile['number'] or f['invocation']!=i or f['arguments']!=args or f['raw']!=c['raw']:raise ValueError(kind+' frame differs')
        values,state=credential_state(c['entry'],kind);after_values,after_state=credential_state(c['exit'],kind)
        if values!=values_expected or values!=after_values or state!=after_state or (previous is not None and state!=previous):raise ValueError(kind+' credential continuity differs')
        if 301 in state[0] or any(e['id']==301 for e in lifetimes['events']):raise ValueError(kind+' output aliases kernel objects')
        start=c['entry']['lifetime_cursor'];end=c['exit']['lifetime_cursor']
        if start!=end or c.get('events')!=[]:raise ValueError(kind+' unexpected lifetime effect')
        before=output_bytes(c['entry']);after=output_bytes(c['exit'])
        if prior_output is not None and before!=prior_output:raise ValueError(kind+' output continuity differs')
        expected=bytearray(before);attempts=[]
        for j in range(i if i else 3):
            value=values[j!=0];failure=args[j] is None
            attempts.append({'position':j,'value':value,'size':4,'result':4 if failure else 0})
            if not failure:expected[offsets[j]:offsets[j]+4]=value.to_bytes(4,'little')
        for key in ('entry','exit'):
            for row in c[key]['user_copy_attempts']:
                if not isinstance(row,dict) or set(row)!={'position','value','size','result'} or any(type(v) is not int for v in row.values()):raise ValueError(kind+' copy schema differs')
        if after!=expected or c['entry']['user_copy_attempts']!=attempts or c['exit']['user_copy_attempts']!=attempts:raise ValueError(kind+' ordered copy effects differ')
        previous=state;prior_output=after
    return calls

def validate_getresuid(bundle,lifetimes):
    return validate_credential_query(bundle,lifetimes,'getresuid')

def validate_getresgid(bundle,lifetimes):
    return validate_credential_query(bundle,lifetimes,'getresgid')
