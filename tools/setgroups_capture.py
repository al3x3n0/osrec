"""Reviewed bounded live SysSetGroups capture contracts, not generic analysis."""
from entry_state_continuity import canonical_state
from entry_state_lifetimes import validate_lifetimes

def input_values(arguments):
    if set(arguments)!={'size','list'} or type(arguments['size']) is not int or not 0<=arguments['size']<=2:
        raise ValueError('unsupported setgroups arguments')
    size=arguments['size'];region=arguments['list']
    if not size:
        if region is not None:raise ValueError('zero-size list must be null')
        return []
    if not isinstance(region,dict) or set(region)!={'id','offset','bytes','data'} or type(region['id']) is not int or region['id']<=0 or type(region['offset']) is not int or region['offset']!=0 or type(region['bytes']) is not int or region['bytes']!=4*size:
        raise ValueError('setgroups input region differs')
    data=bytes.fromhex(region['data'])
    if len(data)!=4*size:raise ValueError('setgroups input width differs')
    values=[int.from_bytes(data[i:i+4],'little') for i in range(0,len(data),4)]
    if any(value>0x7fffffff for value in values):raise ValueError('negative group outside bounded capture contract')
    return values

def validate_setgroups(bundle,lifetimes):
    if bundle.get('format') not in ('osrec-live-setgroups-v1','osrec-live-setgroups-v2','osrec-live-setgroups-v3','osrec-live-setgroups-v4','osrec-live-setgroups-v5'):raise ValueError('unsupported setgroups capture')
    calls=bundle['calls']
    if len(calls)!=3:raise ValueError('setgroups call sequence differs')
    validate_lifetimes(lifetimes,[call[key] for call in calls for key in ('entry','exit')])
    previous=None;process_identity=None;input_ids=set()
    base_names=('userID','effUserID','gid','effGid','groupNumber')
    for invocation,call in enumerate(calls):
        inputs=input_values(call['arguments'])
        allowed=(0,0xfffffff4,0xfffffff2) if bundle['format'] in ('osrec-live-setgroups-v4','osrec-live-setgroups-v5') else (0,0xfffffff4) if bundle['format']=='osrec-live-setgroups-v3' else (0,)
        if type(call['invocation']) is not int or call['invocation']!=invocation or type(call['raw']) is not int or call['raw'] not in allowed:
            raise ValueError('unsupported setgroups invocation')
        if inputs:
            identity=call['arguments']['list']['id']
            if identity in input_ids:raise ValueError('setgroups input identity reused without alias contract')
            input_ids.add(identity)
        states=[]
        for key in ('entry','exit'):
            frame=call[key]
            if frame.get('format')!='osrec-entry-snapshot-v1' or len(frame['objects'])!=2 or len(frame['roots'])!=1:
                raise ValueError('setgroups snapshot shape differs')
            if len({r['id'] for r in frame['objects']})!=2 or any('address' in r for r in frame['objects']):
                raise ValueError('setgroups object identity schema differs')
            if type(frame.get('allocation_address_reused')) is not bool:raise ValueError('setgroups reuse observation missing')
            if frame['syscall']!=206 or frame['invocation']!=invocation or frame['arguments']!=call['arguments'] or frame['raw']!=call['raw']:
                raise ValueError('setgroups snapshot invocation differs')
            objects,roots,fields=canonical_state(frame)
            if set(roots)!={'OsCurrProcessGet()'}:raise ValueError('setgroups provider differs')
            process=roots['OsCurrProcessGet()'];edge=fields.get((process,'user'))
            if not edge or edge[0]!='edge' or not edge[1]:raise ValueError('setgroups user edge missing')
            user=edge[1]
            if objects!={process:'LosProcessCB',user:'User'}:raise ValueError('setgroups object schema differs')
            values={}
            for name in base_names:
                row=fields.get((user,name))
                if not row or row[:2]!=('scalar',4) or len(row[2])!=4:raise ValueError('setgroups field width differs')
                values[name]=int.from_bytes(row[2],'little')
            count=values['groupNumber']
            if not 1<=count<=3:raise ValueError('setgroups group range differs')
            groups=[]
            for i in range(count):
                row=fields.get((user,f'groups[{i}]'))
                if not row or row[:2]!=('scalar',4) or len(row[2])!=4:raise ValueError('setgroups group field missing or malformed')
                groups.append(int.from_bytes(row[2],'little'))
            names=set(base_names)|{f'groups[{i}]' for i in range(count)}
            if set(fields)!={(process,'user')}|{(user,name) for name in names} or len(frame['fields'])!=len(names)+1:
                raise ValueError('setgroups footprint differs')
            states.append((process,user,values,groups,(objects,roots,fields)))
        before,after=states
        if process_identity is None:process_identity=before[0]
        if before[0]!=process_identity or after[0]!=process_identity:raise ValueError('setgroups process identity differs')
        if previous is not None and before[4]!=previous:raise ValueError('setgroups state continuity differs')
        gid=before[2]['gid'];groups=inputs if gid in inputs else inputs+[gid]
        if call['raw']==0:
            if before[1]==after[1] or after[2]!={**before[2],'groupNumber':len(groups)} or after[3]!=groups:raise ValueError('setgroups credential effect differs')
        elif after[4]!=before[4]:raise ValueError('failed setgroups changes credential state')
        start=call['entry']['lifetime_cursor'];end=call['exit']['lifetime_cursor']
        events=lifetimes['events'][start:end];size=len(inputs);list_size=size-int(gid in inputs)
        expected=[]
        def event(identity,kind,bytes_):
            expected.append({'ordinal':start+len(expected),'id':identity,'kind':kind,'size':bytes_})
        if bundle['format'] in ('osrec-live-setgroups-v3','osrec-live-setgroups-v4','osrec-live-setgroups-v5'):
            attempts=call['entry'].get('allocation_attempts')
            if not isinstance(attempts,list) or attempts!=call['exit'].get('allocation_attempts'):raise ValueError('allocation outcome transcript differs')
            requests=([4*size] if size else [])+([] if call['raw']==0xfffffff2 else [24+4*list_size])
            if not 1<=len(attempts)<=len(requests):raise ValueError('allocation attempt count differs')
            for i,attempt in enumerate(attempts):
                if set(attempt)!={'size','id','reuse'} or type(attempt['size']) is not int or attempt['size']!=requests[i] or type(attempt['id']) is not int or attempt['id']<0 or type(attempt['reuse']) is not bool:
                    raise ValueError('allocation outcome schema differs')
                if not attempt['id']:
                    if attempt['reuse'] or i!=len(attempts)-1 or call['raw']!=0xfffffff4:raise ValueError('allocation failure outcome differs')
                else:event(attempt['id'],'allocate',attempt['size'])
            if call['raw']==0:
                if len(attempts)!=len(requests) or not all(a['id'] for a in attempts) or attempts[-1]['id']!=after[1]:raise ValueError('credential allocation outcome differs')
                event(before[1],'release',0)
            elif call['raw']==0xfffffff4 and attempts[-1]['id']:raise ValueError('ENOMEM without failed allocation')
            elif call['raw']==0xfffffff2 and (not size or len(attempts)!=1 or not attempts[0]['id']):raise ValueError('EFAULT without temporary allocation')
            if bundle['format'] in ('osrec-live-setgroups-v4','osrec-live-setgroups-v5'):
                copies=call['entry'].get('user_copy_attempts')
                if not isinstance(copies,list) or copies!=call['exit'].get('user_copy_attempts'):raise ValueError('user-copy outcome transcript differs')
                expected_count=int(bool(size and attempts[0]['id']))
                if len(copies)!=expected_count:raise ValueError('user-copy attempt count differs')
                if copies:
                    row=copies[0]
                    keys={'source_id','destination_id','size','result','bytes_copied'}
                    if bundle['format']=='osrec-live-setgroups-v5':keys.update(('destination_data','suffix_unchanged'))
                    if set(row)!=keys or any(type(row[k]) is not int for k in keys-{'destination_data','suffix_unchanged'}):raise ValueError('user-copy outcome schema differs')
                    failed=call['raw']==0xfffffff2
                    copied=(2*size if bundle['format']=='osrec-live-setgroups-v5' and bundle.get('partial_copy_fault_injected') else 0) if failed else 4*size
                    expected_copy={'source_id':call['arguments']['list']['id'],'destination_id':attempts[0]['id'],'size':4*size,'result':4*size-copied,'bytes_copied':copied}
                    if bundle['format']=='osrec-live-setgroups-v5':
                        expected_copy['destination_data']=call['arguments']['list']['data'][:2*copied]
                        expected_copy['suffix_unchanged']=True
                        if row['suffix_unchanged'] is not True:raise ValueError('user-copy suffix preservation differs')
                    if row!=expected_copy:raise ValueError('user-copy outcome differs')
                elif call['raw']==0xfffffff2:raise ValueError('EFAULT without copy attempt')
            if size and attempts[0]['id']:event(attempts[0]['id'],'release',0)
        else:
            if size and not events:raise ValueError('setgroups allocation/release effects differ')
            temp=events[0]['id'] if size else 0
            if size:event(temp,'allocate',4*size)
            event(after[1],'allocate',24+4*list_size);event(before[1],'release',0)
            if size:event(temp,'release',0)
        if events!=expected:raise ValueError('setgroups allocation/release effects differ')
        if bundle['format'] in ('osrec-live-setgroups-v2','osrec-live-setgroups-v3','osrec-live-setgroups-v4','osrec-live-setgroups-v5'):
            if call.get('events')!=events:raise ValueError('setgroups per-call event transcript differs')
            for key in ('entry','exit'):
                reuses=call[key].get('allocation_reuses')
                if not isinstance(reuses,list) or len(reuses)!=(2 if size else 1) or any(type(v) is not bool for v in reuses):raise ValueError('setgroups allocation reuse transcript differs')
            if call['entry']['allocation_reuses']!=call['exit']['allocation_reuses']:raise ValueError('setgroups reuse observations differ')
            if bundle['format'] in ('osrec-live-setgroups-v3','osrec-live-setgroups-v4','osrec-live-setgroups-v5'):
                reuse_values=[a['reuse'] for a in attempts]+[False]*((2 if size else 1)-len(attempts))
                if call['exit']['allocation_reuses']!=reuse_values or call['entry']['allocation_address_reused']!=call['exit']['allocation_address_reused'] or call['exit']['allocation_address_reused']!=(attempts[-1]['reuse'] if call['raw']==0 else False):
                    raise ValueError('setgroups reuse summary differs from allocation outcomes')
        previous=after[4]
    if bundle['format'] in ('osrec-live-setgroups-v3','osrec-live-setgroups-v4','osrec-live-setgroups-v5'):
        if type(bundle.get('fault_injected')) is not bool or (bundle['fault_injected'] and not any(c['raw'] for c in calls)):raise ValueError('fault injection provenance differs')
    if bundle['format'] in ('osrec-live-setgroups-v4','osrec-live-setgroups-v5'):
        if type(bundle.get('copy_fault_injected')) is not bool or (bundle['copy_fault_injected'] and (not bundle['fault_injected'] or [c['raw'] for c in calls]!=[0,0xfffffff2,0xfffffff2])):raise ValueError('copy fault injection provenance differs')
        if any(c['raw']==0xfffffff2 for c in calls) and not bundle['copy_fault_injected']:raise ValueError('natural copy failures outside reviewed contract')
    if bundle['format']=='osrec-live-setgroups-v5':
        if type(bundle.get('partial_copy_fault_injected')) is not bool or (bundle['partial_copy_fault_injected'] and not bundle['copy_fault_injected']):raise ValueError('partial copy injection provenance differs')
    return calls
