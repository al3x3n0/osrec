"""Validate controlled native helper writes against discovered entry/post state."""
import json
import re
import struct

from klee_liteos import digest
from live_argument_state import profile_settings,prepare_source

PROFILE='exit-signal-write'
SIGNALS=(0,1,127,128,0x80000001,0xffffffff)
SESSION_PROFILE='exit-signal-session'
SESSION_SIGNALS=(1,2,128,4,0x80000008,16)


def validate_capture(frames,post_states,plan,witness,profile=PROFILE):
    from automated_entry_state import validate_snapshot,effect_plan
    from reconstruct_entry_state import reconstruction_header
    s=profile_settings(profile)
    if not s.get('effects'):raise ValueError('argument write profile required')
    if s.get('nested'):
        from live_parent_argument import validate_capture as validate_parent
        return validate_parent(frames,post_states,plan,witness)
    continuous=s.get('continuous',False);signals=SESSION_SIGNALS if continuous else SIGNALS
    policy=json.loads(s['policy'].read_text())['argument_objects'][s['helper']]['processCB']
    path='osrec_argument_processCB()->exitCode'
    if (plan['root']!=s['helper'] or plan['blockers'] or
        plan['arguments']!=[{'name':'processCB','type':'LosProcessCB *','pointer':True},
                            {'name':'signal','type':'unsigned int','pointer':False}] or
        plan['object_providers']!=[{'function':'osrec_argument_processCB','return_type':'LosProcessCB *',
            'contract':policy,'binding_kind':'root_argument','argument':'processCB','argument_index':0}] or
        any(len(plan.get(key,[]))!=1 or plan[key][0]['path']!=path or plan[key][0]['type']!='unsigned int' or
            plan[key][0]['pointer_edge'] for key in ('entry_reads','state_writes'))):
        raise ValueError('live argument write discovery contract differs')
    sequence=list(enumerate([s['route']]*6))
    if (len(witness)!=(6*16+12 if continuous else 6*20) or [(f.get('invocation'),f.get('syscall')) for f in frames]!=sequence or
        [(f.get('invocation'),f.get('syscall')) for f in post_states]!=sequence):
        raise ValueError('live argument entry/post/witness sequence differs')
    calls=[];sessions=set()
    for i,(frame,post) in enumerate(zip(frames,post_states)):
        validate_snapshot(frame,plan);validate_snapshot(post,effect_plan(plan))
        if (len(frame['objects'])!=1 or frame['objects'][0]['type']!='LosProcessCB' or
            post['objects']!=frame['objects'] or post['roots']!=frame['roots']):
            raise ValueError('live argument write process graph differs')
        obj=frame['objects'][0];oid=obj['id'];session=obj.get('session_id')
        if type(session) is not int or session<=0:raise ValueError('live argument write process lifetime is missing')
        sessions.add(session)
        if frame['roots']!=[{'name':'osrec_argument_processCB()','object_id':oid}]:
            raise ValueError('live argument write root differs')
        values=[]
        for state in (frame,post):
            if len(state['fields'])!=1:raise ValueError('live argument write field footprint differs')
            field=state['fields'][0]
            if field['name']!='exitCode' or field['kind']!='scalar' or field['bytes']!=4:
                raise ValueError('live argument write field schema differs')
            values.append(int.from_bytes(bytes.fromhex(field['data']),'little'))
        arguments=[{'name':'signal','bytes':4,'data':signals[i].to_bytes(4,'little').hex()}]
        if frame.get('arguments')!=arguments or post.get('arguments')!=arguments:
            raise ValueError('live argument signal differs from the capture recipe')
        if continuous:
            ordinal,signal,before,after=struct.unpack_from('<4I',witness,i*16)
        else:
            ordinal,signal,before,after,restored=struct.unpack_from('<5I',witness,i*20)
        if (ordinal!=i or signal!=signals[i] or values!=[before,after] or
            after!=(before|(signal&127)) or (not continuous and restored!=before)):
            raise ValueError('live argument write snapshot, effect or restoration differs')
        call={'number':s['route'],'raw_bits':0,'signal':signal,'before':before,'after':after}
        if not continuous:call['restored']=restored
        calls.append(call)
    if len(sessions)!=1:raise ValueError('live argument write process identity changed')
    if continuous:
        initial,final,restored=struct.unpack_from('<3I',witness,6*16)
        if (initial,final,restored)!=(calls[0]['before'],calls[-1]['after'],calls[0]['before']):
            raise ValueError('argument session initial/final/restoration boundary differs')
    reconstruction_header(frames,[plan]*6,post_states=post_states,scalar_arguments=True,continuous=continuous)
    return calls


def parse_capture(text,plan,profile=PROFILE):
    entries=[json.loads(v) for v in re.findall(r'^OSREC_ARGUMENT_ENTRY (.+)\r?$',text,re.M)]
    effects=[json.loads(v) for v in re.findall(r'^OSREC_ARGUMENT_EFFECT (.+)\r?$',text,re.M)]
    rows=re.findall(r'^OSREC_ARGUMENT_KERNEL ([0-9a-f]+)\r?$',text,re.M)
    if len(rows)!=1:raise ValueError('live argument write witness missing or duplicated')
    witness=bytes.fromhex(rows[0]);validate_capture(entries,effects,plan,witness,profile)
    return entries,effects,witness


def load_capture(capture,kernel_root):
    from reconstruct_entry_state import load_reconstruction
    report=json.loads((capture/'report.json').read_text());metadata=report.get('argument_entry_capture',{})
    profile=metadata.get('profile');s=profile_settings(profile)
    if not s.get('effects'):raise ValueError('argument write profile required')
    continuous=s.get('continuous',False);source,identity=prepare_source(kernel_root,profile)
    if (metadata.get('function')!=s['helper'] or metadata.get('calls')!=6 or
        metadata.get('controlled_restore') is not True or metadata.get('source_identity')!=identity):
        raise ValueError('live argument write source/capture metadata differs')
    if continuous and metadata.get('session_contract')!={
            'format':'osrec-locked-argument-session-v1','route':s['route'],'calls':6,
            'single_lock_region':True,'restoration':'after_batch','entry_inherits_previous_post':True}:
        raise ValueError('argument session capture contract differs')
    if s.get('nested'):
        from live_parent_argument import PARENT_CONTRACT
        if metadata.get('parent_contract')!=PARENT_CONTRACT:raise ValueError('parent argument capture contract differs')
    bundle=json.loads((capture/'entry-state-plan.json').read_text())
    if bundle.get('argument_boundary_policy_sha256')!=digest(s['policy'].read_bytes()):raise ValueError('argument write policy changed')
    plans=[p for p in bundle['plans'] if p['root']==s['helper']]
    if len(plans)!=1:raise ValueError('argument write plan missing or duplicated')
    witness=(capture/'argument-entry-kernel.bin').read_bytes()
    if digest(witness)!=metadata.get('sha256'):raise ValueError('argument write witness hash differs')
    header,entries,hashes=load_reconstruction(capture,{s['route']:s['helper']},[s['route']]*6,effects=True,continuous=continuous)
    effects=[f for f in json.loads((capture/'entry-state-effects.json').read_text())['snapshots'] if f['syscall']==s['route']]
    calls=validate_capture(entries,effects,plans[0],witness,profile)
    log=(capture/'boot.log').read_bytes()
    if digest(log)!=report['boot_log_sha256']:raise ValueError('argument write boot log hash differs')
    logged_entries,logged_effects,logged_witness=parse_capture(log.decode(),plans[0],profile)
    if (entries,effects,witness)!=(logged_entries,logged_effects,logged_witness):
        raise ValueError('argument write capture differs from native log')
    if s.get('nested'):
        task_rows=re.findall(rb'^OSREC_TASK_KERNEL ([0-9a-f]+)\r?$',log,re.M)
        if len(task_rows)!=1:raise ValueError('parent argument native task witness missing or duplicated')
        task=bytes.fromhex(task_rows[0].decode());root_pid,parent_pid=struct.unpack_from('<2I',witness,108)
        if len(task)!=96 or any(struct.unpack_from('<2I',task,i*24+4)!=(root_pid,parent_pid) for i in range(4)):
            raise ValueError('parent argument process IDs differ from native task observations')
    return header,entries,calls,hashes,source,identity
