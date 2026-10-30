"""Validate address-free lifetime events and snapshot-time object identities.

This checks the recorded scope; it cannot establish allocator-hook coverage.
"""
def validate_lifetimes(bundle,frames):
    if bundle.get('format')!='osrec-object-lifetimes-v1':raise ValueError('unsupported lifetime format')
    live=set();seen=set();states=[frozenset()];previous_id=0
    events=bundle['events']
    for ordinal,event in enumerate(events):
        if set(event)!={'ordinal','id','kind','size'}:raise ValueError('lifetime event schema differs')
        if any(type(event[key]) is not int for key in ('ordinal','id','size')) or event['ordinal']!=ordinal or event['id']<=0 or event['size']<0:
            raise ValueError('invalid lifetime event values')
        identity=event['id'];kind=event['kind']
        if kind in ('existing','allocate'):
            if identity in seen or identity<=previous_id:raise ValueError('lifetime ID reused or reordered')
            if (kind=='existing' and event['size']!=0) or (kind=='allocate' and event['size']==0):raise ValueError('lifetime event size differs')
            live.add(identity);seen.add(identity);previous_id=identity
        elif kind=='release':
            if identity not in live or event['size']!=0:raise ValueError('release of an unknown or retired identity')
            live.remove(identity)
        else:raise ValueError('unsupported lifetime event kind')
        states.append(frozenset(live))
    for frame in frames:
        cursor=frame.get('lifetime_cursor')
        if type(cursor) is not int or not 0<=cursor<=len(events):raise ValueError('invalid snapshot lifetime cursor')
        ids=[row.get('session_id') for row in frame['objects']]
        if any(type(identity) is not int or identity<=0 for identity in ids) or len(set(ids))!=len(ids):
            raise ValueError('invalid snapshot lifetime identities')
        if not set(ids)<=states[cursor]:raise ValueError('snapshot refers to an unborn or retired identity')
    return states
