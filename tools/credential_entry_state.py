"""Explicit provider bridge for Clang-discovered credential-query footprints."""
import copy
from collections import Counter
from getresuid_capture import PROFILES
QUERY_ROOTS={'getresuid':'SysGetRealEffSaveUserID','getresgid':'SysGetRealEffSaveGroupID'}
COPY_MODEL={'kind':'memory_model','reads':[1],'reason':'credential query copies are validated against the reviewed bounded output witness, ordered source values and native NULL failures','implementation':'reviewed credential_output_adapter; external copy semantics are not inferred by Clang'}
GENERATION='configured-clang-fields-v1'

def capture_plan(plan,process_provider):
    kind=next((k for k,v in QUERY_ROOTS.items() if v==plan['root']),None)
    if kind is None:raise ValueError('unknown credential query root')
    fields=PROFILES[kind]['fields']
    expected=Counter({'OsCurrUserGet()->'+fields[0]:1,'OsCurrUserGet()->'+fields[1]:2})
    providers=plan['object_providers']
    # The copied sources are the call's own automatic scalars (one element each); they are not entry state.
    local=lambda r:r.get('pointer_provenance',{}).get('storage_kind')=='automatic_scalar' and all(p.startswith('local:') for p in r['paths'])
    sources=[p for r in plan['memory_ranges'] if local(r) for p in r['paths']]
    if len(sources)!=3 or len(set(sources))!=3 or any(r['elements']!=1 for r in plan['memory_ranges']):
        raise ValueError('credential query copy sources differ')
    if plan['blockers'] or plan['state_writes'] or not all(map(local,plan['memory_ranges'])) or Counter(r['path'] for r in plan['entry_reads'])!=expected:
        raise ValueError('credential query discovered footprint differs')
    if len(providers)!=1 or providers[0]['function']!='OsCurrUserGet' or providers[0]['return_type']!='User *':raise ValueError('credential query provider differs')
    if len(plan['arguments'])!=3 or any(r['type']!='int *' for r in plan['arguments']):raise ValueError('credential query arguments differ')
    calls=Counter(c['callee'].split(':',1)[-1] if c['callee'] else None for c in plan['call_sites'])
    if calls!=Counter({'OsCurrUserGet':3,'LOS_ArchCopyToUser':3,'LOS_SpinLockSave':1,'LOS_SpinUnlockRestore':1}):raise ValueError('credential query dependency closure differs')
    if any(c['boundary'] is None for c in plan['call_sites']):raise ValueError('credential query dependency model missing')
    if process_provider['function']!='OsCurrProcessGet' or process_provider['return_type']!='LosProcessCB *' or process_provider['contract'].get('snapshot_safe') is not True:raise ValueError('credential query process bridge differs')
    projected=copy.deepcopy(plan);projected['root']='credential_'+plan['root'];projected['object_providers']=[copy.deepcopy(process_provider)]
    projected['memory_ranges']=[]
    # This provider equivalence is an explicit reviewed binding, not inferred code.
    projected['provider_bridge']={'from':'OsCurrUserGet()','to':'OsCurrProcessGet()->user','kind':'reviewed_current_user_binding'}
    reads=[]
    for row in plan['entry_reads']:
        r=copy.deepcopy(row);r['path']=r['path'].replace('OsCurrUserGet()','OsCurrProcessGet()->user');reads.append(r)
    edge=copy.deepcopy(reads[0]);edge.update(path='OsCurrProcessGet()->user',type='User *',pointer_edge=True)
    projected['entry_reads']=[edge,*reads]
    return projected
