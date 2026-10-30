"""Validate continuous sessions using capture-scoped logical identities.

Pointer rebinding relaxes edge values only; the reconstructor separately checks
each change against the typed write footprint and fixes entry/post identities.
"""

def canonical_state(frame):
    ids={row['id']:row.get('session_id') for row in frame['objects']}
    if any(type(value) is not int or value<=0 for value in ids.values()) or len(set(ids.values()))!=len(ids):
        raise ValueError('continuous replay requires unique positive capture-scoped session IDs')
    def identity(oid):
        if oid==0:return 0
        if oid not in ids:raise ValueError('continuous state has an unknown object reference')
        return ids[oid]
    objects={ids[row['id']]:row['type'] for row in frame['objects']}
    roots={row['name']:identity(row['object_id']) for row in frame['roots']}
    fields={}
    for row in frame['fields']:
        key=(identity(row['object_id']),row['name'])
        if key in fields:raise ValueError('duplicate continuous state field')
        if row['kind']=='edge':fields[key]=('edge',identity(row['target_id']))
        elif row['kind']=='scalar':fields[key]=('scalar',row['bytes'],bytes.fromhex(row['data']))
        else:raise ValueError('unsupported continuous field kind')
    return objects,roots,fields


def validate_continuity(frames,post_states,pointer_rebinding=False):
    if not frames or post_states is None or len(frames)!=len(post_states):
        raise ValueError('continuous replay requires an entry and post-state for every invocation')
    incoming=[canonical_state(frame) for frame in frames]
    outgoing=[canonical_state(frame) for frame in post_states]
    objects,roots,fields=incoming[0]
    def field_shape(rows):
        return {key:row[:2] if row[0]=='scalar' else row[:1] if pointer_rebinding else row for key,row in rows.items()}
    shape=field_shape(fields)
    for state in incoming+outgoing:
        other_objects,other_roots,other_fields=state
        other_shape=field_shape(other_fields)
        if other_objects!=objects or other_roots!=roots or other_shape!=shape:
            raise ValueError('continuous replay requires a fixed object graph and complete field footprint')
    for index in range(1,len(frames)):
        if incoming[index]!=outgoing[index-1]:
            raise ValueError('continuous entry differs from previous post-state at invocation '+str(index))
    return incoming
