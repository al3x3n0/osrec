"""Validate a capture adapter's writes through the real process parent edge."""
import json
import struct
from collections import Counter

PARENT_CONTRACT={'format':'osrec-parent-argument-session-v1','edge':'parentProcess',
    'distinct_parent':True,'stable_parent_lifetime':True,'parent_field_restored_after_batch':True,
    'capture_site':'child-first-getppid'}

def validate_capture(frames,posts,plan,witness):
    from live_argument_state import profile_settings
    from live_argument_effects import SESSION_SIGNALS
    from automated_entry_state import validate_snapshot,effect_plan
    from reconstruct_entry_state import reconstruction_header
    s=profile_settings('parent-exit-signal-session');root='osrec_argument_processCB()'
    policy=json.loads(s['policy'].read_text())['argument_objects'][s['helper']]['processCB']
    expected_reads=Counter([(root+'->parentProcess','struct ProcessCB *',True),
                            (root+'->parentProcess->exitCode','unsigned int',False)])
    shape=lambda rows:Counter((r['path'],r['type'],r['pointer_edge']) for r in rows)
    if (plan['root']!=s['helper'] or plan['blockers'] or
        plan['arguments']!=[{'name':'processCB','type':'LosProcessCB *','pointer':True},
                            {'name':'signal','type':'unsigned int','pointer':False}] or
        plan['object_providers']!=[{'function':'osrec_argument_processCB','return_type':'LosProcessCB *',
            'contract':policy,'binding_kind':'root_argument','argument':'processCB','argument_index':0}] or
        shape(plan['entry_reads'])!=expected_reads or
        shape(plan['state_writes'])!=Counter([(root+'->parentProcess->exitCode','unsigned int',False)]) or
        len(plan['call_sites'])!=1 or (plan['call_sites'][0].get('callee') or '').split(':')[-1]!=s['source_helper'] or
        plan['call_sites'][0]['boundary'] is not None):
        raise ValueError('parent argument discovery contract differs')
    sequence=list(enumerate([s['route']]*6))
    if (len(witness)!=116 or [(f.get('invocation'),f.get('syscall')) for f in frames]!=sequence or
        [(f.get('invocation'),f.get('syscall')) for f in posts]!=sequence):
        raise ValueError('parent argument entry/post/witness sequence differs')
    calls=[];identities=set()
    for i,(frame,post) in enumerate(zip(frames,posts)):
        validate_snapshot(frame,plan);validate_snapshot(post,effect_plan(plan))
        if (len(frame['objects'])!=2 or len(frame['roots'])!=1 or
            post['objects']!=frame['objects'] or post['roots']!=frame['roots']):
            raise ValueError('parent argument requires two stable process objects')
        objects={r['id']:r for r in frame['objects']};oid=frame['roots'][0]['object_id']
        if oid not in objects:raise ValueError('parent argument root must be nonnull')
        fields={(f['object_id'],f['name']):f for f in frame['fields']}
        edge=fields.get((oid,'parentProcess'),{})
        parent=edge.get('target_id')
        if (objects[oid]['type']!='LosProcessCB' or edge.get('kind')!='edge' or not parent or parent==oid or
            objects[parent]['type']!='struct ProcessCB'):
            raise ValueError('parent argument edge must reach a distinct process')
        pair=tuple(objects[k].get('session_id') for k in (oid,parent))
        if any(type(v) is not int or v<=0 for v in pair) or pair[0]==pair[1]:
            raise ValueError('parent argument lifetime identities differ')
        identities.add(pair);values=[]
        for state in (frame,post):
            rows={(f['object_id'],f['name']):f for f in state['fields']}
            if set(rows)!={(oid,'parentProcess'),(parent,'exitCode')} or rows[oid,'parentProcess']!=edge:
                raise ValueError('parent argument field footprint or edge differs')
            scalar=rows[parent,'exitCode']
            if scalar['kind']!='scalar' or scalar['bytes']!=4:
                raise ValueError('parent argument scalar schema differs')
            values.append(int.from_bytes(bytes.fromhex(scalar['data']),'little'))
        arguments=[{'name':'signal','bytes':4,'data':SESSION_SIGNALS[i].to_bytes(4,'little').hex()}]
        if frame.get('arguments')!=arguments or post.get('arguments')!=arguments:
            raise ValueError('parent argument signal recipe differs')
        ordinal,signal,before,after=struct.unpack_from('<4I',witness,i*16)
        if (ordinal,signal)!=(i,SESSION_SIGNALS[i]) or values!=[before,after] or after!=before|(signal&127):
            raise ValueError('parent argument native write witness differs')
        calls.append(dict(number=s['route'],raw_bits=0,signal=signal,before=before,after=after))
    if len(identities)!=1:raise ValueError('parent argument capture-scoped identities changed')
    initial,final,restored,root_pid,parent_pid=struct.unpack_from('<5I',witness,96)
    if (initial,final,restored)!=(calls[0]['before'],calls[-1]['after'],calls[0]['before']):
        raise ValueError('parent argument session restoration differs')
    if not 1<root_pid<0xffffffff or parent_pid!=1:
        raise ValueError('parent argument native process identity witness differs')
    reconstruction_header(frames,[plan]*6,post_states=posts,scalar_arguments=True,continuous=True)
    return calls
