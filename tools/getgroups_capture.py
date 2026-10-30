"""Reviewed three-call SysGetGroups output contract; not generic copy analysis."""
from entry_state_continuity import canonical_state
from entry_state_lifetimes import validate_lifetimes

def credential_state(frame):
    if frame.get('format')!='osrec-entry-snapshot-v1' or len(frame['objects'])!=2 or len(frame['roots'])!=1:
        raise ValueError('getgroups snapshot shape differs')
    if any('address' in r for r in frame['objects']) or len({r['id'] for r in frame['objects']})!=2:
        raise ValueError('getgroups object identity schema differs')
    objects,roots,fields=canonical_state(frame)
    if set(roots)!={'OsCurrProcessGet()'}:raise ValueError('getgroups provider differs')
    process=roots['OsCurrProcessGet()'];edge=fields.get((process,'user'))
    if not edge or edge[0]!='edge' or not edge[1]:raise ValueError('getgroups user edge missing')
    user=edge[1]
    if objects!={process:'LosProcessCB',user:'User'}:raise ValueError('getgroups object types differ')
    count_field=fields.get((user,'groupNumber'))
    if not count_field or count_field[:2]!=('scalar',4) or len(count_field[2])!=4:raise ValueError('getgroups count width differs')
    count=int.from_bytes(count_field[2],'little')
    if count not in (1,2,3):raise ValueError('getgroups credential count unsupported')
    names=('userID','effUserID','gid','effGid','groupNumber')+tuple('groups['+str(i)+']' for i in range(count))
    values=[]
    for name in names:
        row=fields.get((user,name))
        if not row or row[:2]!=('scalar',4) or len(row[2])!=4:raise ValueError('getgroups credential width differs')
        values.append(int.from_bytes(row[2],'little'))
    if values[4]!=count or set(fields)!={(process,'user')}|{(user,n) for n in names} or len(frame['fields'])!=len(names)+1:
        raise ValueError('getgroups footprint differs')
    return user,values,(objects,roots,fields)

def output_bytes(frame):
    data=frame.get('output_data')
    if type(data) is not str or len(data)!=32:raise ValueError('getgroups output width differs')
    value=bytes.fromhex(data)
    if len(value)!=16:raise ValueError('getgroups output width differs')
    return value

def null_output_profile(bundle):
    if bundle.get('format') in ('osrec-live-getgroups-v5','osrec-live-getgroups-v6','osrec-live-getgroups-v7','osrec-live-getgroups-v8','osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12'):
        profile=bundle.get('null_output_profile')
        allowed=('none','short','boundaries','negative-sizes') if bundle['format'] in ('osrec-live-getgroups-v6','osrec-live-getgroups-v7','osrec-live-getgroups-v8','osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12') else ('none','short','boundaries')
        if profile not in allowed or type(bundle.get('null_output_case')) is not bool or bundle['null_output_case']!=(profile!='none'):raise ValueError('getgroups null-output profile differs')
        return profile
    if bundle.get('format')=='osrec-live-getgroups-v4':
        if type(bundle.get('null_output_case')) is not bool:raise ValueError('getgroups null-output contract differs')
        return 'short' if bundle['null_output_case'] else 'none'
    return 'none'

def validate_getgroups(bundle,lifetimes):
    if bundle.get('format') not in ('osrec-live-getgroups-v1','osrec-live-getgroups-v2','osrec-live-getgroups-v3','osrec-live-getgroups-v4','osrec-live-getgroups-v5','osrec-live-getgroups-v6','osrec-live-getgroups-v7','osrec-live-getgroups-v8','osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12') or len(bundle['calls'])!=3:raise ValueError('unsupported getgroups capture')
    outcome=bundle.get('copy_outcome','success') if bundle['format']!='osrec-live-getgroups-v1' else 'success'
    if outcome not in (('partial',) if bundle['format']=='osrec-live-getgroups-v11' else ('success','none','half')):raise ValueError('unsupported getgroups copy outcome')
    allocation_failure=bundle.get('allocation_fault_injected',False) if bundle['format'] in ('osrec-live-getgroups-v3','osrec-live-getgroups-v4','osrec-live-getgroups-v5','osrec-live-getgroups-v6','osrec-live-getgroups-v7','osrec-live-getgroups-v8','osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12') else False
    if type(allocation_failure) is not bool or (allocation_failure and outcome!='success'):raise ValueError('getgroups allocation injection contract differs')
    group_count=bundle.get('group_count') if bundle['format'] in ('osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12') else 3
    if type(group_count) is not int or group_count not in ((1,2,3) if bundle['format'] in ('osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12') else (1,3)):raise ValueError('getgroups group count contract differs')
    width=4*group_count
    if outcome=='partial':
        copied=bundle.get('copy_bytes')
        if type(copied) is not int or not 0<=copied<width:raise ValueError('getgroups copy prefix contract differs')
    else:
        if 'copy_bytes' in bundle:raise ValueError('legacy getgroups capture cannot claim copy prefix')
        copied=0 if allocation_failure else {'success':width,'none':0,'half':width//2}[outcome]
    profile=null_output_profile(bundle)
    if profile!='none' and ((group_count!=3 and bundle['format']!='osrec-live-getgroups-v12') or allocation_failure or outcome!='success'):raise ValueError('getgroups null-output contract differs')
    if bundle['format']=='osrec-live-getgroups-v12' and (profile=='none' or group_count not in (1,2)):raise ValueError('getgroups counted argument profile differs')
    output_size=bundle.get('output_size') if bundle['format'] in ('osrec-live-getgroups-v7','osrec-live-getgroups-v8','osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12') else 4
    if type(output_size) is not int or not group_count<=output_size<=2147483647 or (profile!='none' and output_size!=4):raise ValueError('getgroups output size contract differs')
    output_offset=bundle.get('output_offset') if bundle['format'] in ('osrec-live-getgroups-v8','osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12') else 0
    if type(output_offset) is not int or not 0<=output_offset<=4 or (profile!='none' and output_offset):raise ValueError('getgroups output offset contract differs')
    has_witness=bundle['format'] in ('osrec-live-getgroups-v4','osrec-live-getgroups-v5','osrec-live-getgroups-v6','osrec-live-getgroups-v7','osrec-live-getgroups-v8','osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12')
    witness=bundle.get('output_region') if has_witness else None
    if has_witness and (not isinstance(witness,dict) or set(witness)!={'id','offset','bytes'} or any(type(v) is not int for v in witness.values()) or not 0<witness['id']<=0xffffffff or witness['offset']!=0 or witness['bytes']!=16):raise ValueError('getgroups output witness differs')
    calls=bundle['calls'];validate_lifetimes(lifetimes,[c[k] for c in calls for k in ('entry','exit')])
    previous=None;previous_output=None;region=None
    for i,call in enumerate(calls):
        args=call['arguments'];area=args.get('list')
        size=0 if profile=='boundaries' and i==1 else group_count-1 if i==1 else 2*i
        if i==2 and profile=='none':size=output_size
        if profile=='negative-sizes':size=(0,-1,-2147483648)[i]
        null_output=(profile=='negative-sizes' and i==2) or (profile=='short' and i==1) or (profile=='boundaries' and i>0)
        final_output=i==2 and not null_output and size>=group_count
        if set(args)!={'size','list'} or type(args['size']) is not int or args['size']!=size:
            raise ValueError('getgroups argument schema differs')
        if null_output:
            if area is not None:raise ValueError('getgroups null output pointer differs')
            area=witness
        offset=output_offset if final_output else 0
        if not isinstance(area,dict) or set(area)!={'id','offset','bytes'} or any(type(area[k]) is not int for k in area) or not 0<area['id']<=0xffffffff or area['offset']!=offset or area['bytes']!=16-offset:
            raise ValueError('getgroups output region differs')
        base={'id':area['id'],'offset':0,'bytes':16}
        if witness is not None and base!=witness:raise ValueError('getgroups output witness identity differs')
        if region is None:region=base
        if base!=region:raise ValueError('getgroups output identity continuity differs')
        expected_raw=group_count if size==0 else 0xfffffff2 if null_output else 0xffffffea if size<group_count else 0xfffffff4 if allocation_failure else 0xfffffff2 if outcome!='success' else group_count
        if type(call['invocation']) is not int or call['invocation']!=i or type(call['raw']) is not int or call['raw']!=expected_raw:
            raise ValueError('getgroups return differs')
        for key in ('entry','exit'):
            f=call[key]
            if f['syscall']!=205 or f['invocation']!=i or f['arguments']!=args or f['raw']!=call['raw']:raise ValueError('getgroups frame invocation differs')
        before=credential_state(call['entry']);after=credential_state(call['exit'])
        if before[1][4]!=group_count:raise ValueError('getgroups captured group count differs')
        if area['id'] in before[2][0] or any(e['id']==area['id'] for e in lifetimes['events']):raise ValueError('getgroups output identity aliases kernel objects')
        if before!=after or (previous is not None and before!=previous):raise ValueError('getgroups changes credentials')
        old=output_bytes(call['entry']);new=output_bytes(call['exit'])
        if previous_output is not None and old!=previous_output:raise ValueError('getgroups output continuity differs')
        expected=old[:offset]+b''.join(v.to_bytes(4,'little') for v in before[1][5:])[:copied]+old[offset+copied:] if final_output else old
        if new!=expected:raise ValueError('getgroups output effect differs')
        attempts=call['entry'].get('allocation_attempts');copies=call['entry'].get('user_copy_attempts')
        if not isinstance(attempts,list) or attempts!=call['exit'].get('allocation_attempts') or len(attempts)!=int(final_output):raise ValueError('getgroups allocation outcomes differ')
        if not isinstance(copies,list) or copies!=call['exit'].get('user_copy_attempts') or len(copies)!=int(final_output and not allocation_failure):raise ValueError('getgroups user-copy outcomes differ')
        start=call['entry']['lifetime_cursor'];end=call['exit']['lifetime_cursor'];events=lifetimes['events'][start:end]
        expected_events=[]
        if attempts:
            a=attempts[0]
            if not isinstance(a,dict) or set(a)!={'size','id','reuse'} or type(a['size']) is not int or a['size']!=width or type(a['id']) is not int or not (0 if allocation_failure else 1)<=a['id']<=0xffffffff or type(a['reuse']) is not bool:raise ValueError('getgroups allocation schema differs')
            if allocation_failure:
                if a['id'] or a['reuse']:raise ValueError('getgroups null allocation outcome differs')
            else:
                expected_events=[{'ordinal':start,'id':a['id'],'kind':'allocate','size':width},{'ordinal':start+1,'id':a['id'],'kind':'release','size':0}]
                c=copies[0]
                expected_copy={'source_id':a['id'],'destination_id':area['id'],'size':width,'result':width-copied,'bytes_copied':copied}
                if bundle['format'] in ('osrec-live-getgroups-v8','osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12'):expected_copy['destination_offset']=offset
                if not isinstance(c,dict) or any(type(v) is not int for v in c.values()) or c!=expected_copy:raise ValueError('getgroups copy schema differs')
        if end!=start+len(expected_events) or events!=expected_events or call['events']!=events:raise ValueError('getgroups lifetime effects differ')
        previous=after;previous_output=new
    return calls
