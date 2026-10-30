"""Generate target-native objects from typed plans and pointer-free snapshots.

The surrounding replay supplies the reviewed semantic types/provider contracts.
Frame IDs are local; continuous replay uses explicit capture-scoped identities.
"""
import re
from automated_entry_state import validate_snapshot

IDENTIFIER=re.compile(r'^[A-Za-z_][A-Za-z_0-9]*$')
FIELD=re.compile(r'^[A-Za-z_][A-Za-z_0-9]*(?:\[[0-9]+\])*$')

def reconstruction_header(frames, plans, post_states=None, scalar_arguments=False, continuous=False):
    from automated_entry_state import effect_plan
    if len(frames)!=len(plans) or not frames:raise ValueError('entry state/plan count differs')
    if post_states is not None and len(post_states)!=len(frames):raise ValueError('post-state count differs')
    if continuous:
        from entry_state_continuity import validate_continuity
        validate_continuity(frames,post_states,pointer_rebinding=True)
    providers={};declarations=[];cases=[];checks=[];arguments=[];entry_checks=[];declared=set()
    writable=any(p.get('state_writes') for p in plans)
    for index,(frame,plan) in enumerate(zip(frames,plans)):
        from entry_state import snapshot_providers,object_pointee,entry_accesses
        bound_providers=snapshot_providers(plan)
        if plan['blockers']:raise ValueError('blocked entry-state plan')
        writes=plan.get('state_writes',[])
        if writes and post_states is None:raise ValueError('write-effect replay requires an adapter or captured post-state')
        bound_arguments={p['argument'] for p in bound_providers if p.get('binding_kind')=='root_argument'}
        expected_arguments=[(i,a) for i,a in enumerate(plan['arguments']) if a['name'] not in bound_arguments];values=frame.get('arguments',[])
        if expected_arguments:
            if not scalar_arguments:raise ValueError('argument reconstruction is not supported')
            if len(values)!=len(expected_arguments):raise ValueError('captured argument count differs')
            for (_,expected),value in zip(expected_arguments,values):
                if expected['pointer'] or expected['type'] not in ('unsigned int','int'):
                    raise ValueError('only 32-bit integer arguments are supported')
                if value['name']!=expected['name'] or value['bytes']!=4 or len(bytes.fromhex(value['data']))!=4:
                    raise ValueError('captured argument schema differs')
            arguments.append('case '+str(index)+': switch(argument){'+''.join('case '+str(i)+': return UINT32_C('+str(int.from_bytes(bytes.fromhex(value['data']),'little'))+');' for (i,_),value in zip(expected_arguments,values))+'default:return 0;}')
        elif values:raise ValueError('unexpected captured arguments')
        validate_snapshot(frame,plan)
        footprint=effect_plan(plan) if post_states is not None else plan
        for item in entry_accesses(footprint):
            if item['volatile'] or item['bitfield'] or item.get('storage_const'):raise ValueError('unsupported field storage')
            if not all(FIELD.fullmatch(p) for p in item['path'].split('->')[1:]):raise ValueError('unsupported field path')
        for write in writes:
            parts=write['path'].split('->')
            if len(parts)<2:
                raise ValueError('write effects require object field paths')
            if write['pointer_edge']:
                if len(parts)!=2:
                    raise ValueError('pointer write effects require direct provider fields')
                if not continuous or not re.fullmatch(r'(?:struct )?[A-Za-z_][A-Za-z_0-9]* \*',write['type']):
                    raise ValueError('pointer writes require continuous replay and a single object pointer type')
            elif write['type'].startswith(('struct ','union ')):
                raise ValueError('write effects require scalar or object pointer fields')
        for provider in bound_providers:
            name=provider['function'];typ=provider['return_type']
            if not IDENTIFIER.fullmatch(name) or object_pointee(typ) is None:raise ValueError('unsupported provider type')
            if name in providers and providers[name]!=typ:raise ValueError('provider type conflict')
            providers[name]=typ
        bindings={r['name']:r['object_id'] for r in frame['roots']}
        fields={(r['object_id'],r['name']):r for r in frame['fields']}
        expressions={};used=set()
        for name,oid in bindings.items():
            if oid:expressions.setdefault(oid,'osrec_bound_'+name[:-2])
        for read in entry_accesses(plan):
            root,*parts=read['path'].split('->');owner=bindings[root];expression='osrec_bound_'+root[:-2]
            for part in parts:
                if not owner:break
                used.add((owner,part));row=fields[owner,part];expression+='->'+part
                if row['kind']=='edge':
                    owner=row['target_id']
                    if owner:expressions.setdefault(owner,expression)
        if used!=set(fields) or set(expressions)!={r['id'] for r in frame['objects']}:
            raise ValueError('snapshot contains fields or objects outside the discovered footprint')
        expected=fields
        if post_states is not None:
            post=post_states[index];validate_snapshot(post,footprint)
            if {r['name']:r['object_id'] for r in post['roots']}!=bindings or {r['id']:r['type'] for r in post['objects']}!={r['id']:r['type'] for r in frame['objects']}:
                raise ValueError('post-state object graph identity differs')
            if continuous and {r['id']:r['session_id'] for r in post['objects']}!={r['id']:r['session_id'] for r in frame['objects']}:
                raise ValueError('post-state capture-scoped identity differs')
            expected={(r['object_id'],r['name']):r for r in post['fields']}
            write_keys=set();write_prefixes=set()
            for write in writes:
                root,*parts=write['path'].split('->');owner=bindings[root]
                # Resolve the destination against entry state only. A prefix
                # that can itself be written makes this owner ambiguous even
                # when the captured entry/post edge values happen to agree.
                for part in parts[:-1]:
                    if not owner:break
                    key=(owner,part);write_prefixes.add(key)
                    row=fields.get(key)
                    if row is None or row['kind']!='edge':
                        raise ValueError('nested write requires captured entry pointer edges')
                    owner=row['target_id']
                if owner:write_keys.add((owner,parts[-1]))
            if write_prefixes & write_keys:
                raise ValueError('nested write traverses a writable pointer edge')
            if set(expected)!=set(fields)|write_keys:raise ValueError('post-state footprint differs')
            for key,row in fields.items():
                after=expected[key]
                if key not in write_keys and row!=after:raise ValueError('post-state changes an unwritten field')
                if row['kind']!=after['kind'] or row.get('bytes')!=after.get('bytes'):raise ValueError('post-state scalar width differs')
        session_ids={row['id']:row.get('session_id') for row in frame['objects']}
        names={oid:f'osrec_session_object_{session_ids[oid]}' if continuous else f'osrec_frame_{index}_object_{oid}' for oid in expressions}
        for oid,expression in expressions.items():
            if names[oid] not in declared:
                # C's conditional operand conversion removes only the object's
                # top-level const view. Declared member qualifiers are retained.
                declarations.append(f'static __typeof__(0 ? *({expression}) : *({expression})) {names[oid]};');declared.add(names[oid])
        # This dead assignment is type-checked even for unrecorded members:
        # structs containing const subobjects cannot be cleared bytewise safely.
        assignments=[f'if(0) {name}=(__typeof__({name})){{0}}; for(unsigned osrec_byte=0;osrec_byte<sizeof({name});++osrec_byte) ((volatile unsigned char *)&{name})[osrec_byte]=0;' for name in names.values()]
        assertions=[];incoming_assertions=[]
        for rows,output in ((fields,assignments),(expected,assertions),(fields,incoming_assertions)):
            for (oid,field),row in rows.items():
                dest=names[oid]+'.'+field
                if row['kind']=='edge':
                    value='&'+names[row['target_id']] if row['target_id'] else '0'
                    if row['target_id']:
                        output.append(f'_Static_assert(__builtin_types_compatible_p(__typeof__(*({dest})),__typeof__(*({value}))),"captured pointer target type differs");')
                    output.append(f'{dest}={value};' if output is assignments else f'if({dest}!={value}) return 0;')
                else:
                    data=bytes.fromhex(row['data'])
                    output.append(f'_Static_assert(sizeof({dest})=={len(data)},"captured scalar width differs");')
                    for byte,value in enumerate(data):
                        expression=f'((unsigned char *)&{dest})[{byte}]'
                        output.append(f'{expression}={value};' if output is assignments else f'if({expression}!={value}) return 0;')
        for provider in providers:
            oid=bindings.get(provider+'()',0);value='&'+names[oid] if oid else '0'
            assignments.append(f'osrec_bound_{provider}={value};')
            incoming_assertions.append(f'if(osrec_bound_{provider}!={value}) return 0;')
        if not continuous or index==0:cases.append(f'case {index}: {{'+''.join(assignments)+' return 1;}')
        if continuous:entry_checks.append(f'case {index}: {{'+''.join(incoming_assertions)+' return 1;}')
        checks.append(f'case {index}: {{'+''.join(assertions)+' return 1;}')
    clear=''.join(f'osrec_bound_{name}=0;' for name in providers)
    header='/* Generated normalized entry and post-state verification. No captured addresses. */\n#include <stdint.h>\n'
    from entry_state_constants import extent_assertions
    assertions=extent_assertions(plans)
    if assertions:header+='\n'.join(assertions)+'\n'
    header+='#define OSREC_CONTINUOUS_REPLAY '+str(int(continuous))+'\n'
    header+='#define OSREC_HAS_WRITE_EFFECTS '+str(int(writable))+'\n'
    # A parameter's top-level pointer const does not qualify the pointee. The
    # binding slot must be assignable when switching invocation frames.
    header+='\n'.join(f'static {typ.removesuffix("const") if typ.endswith("*const") else typ} osrec_bound_{name};' for name,typ in providers.items())+'\n'
    header+='\n'.join(declarations)+'\n'
    header+='static int osrec_restore(unsigned invocation) {if(invocation>='+str(len(frames))+(' || invocation!=0' if continuous else '')+') return 0;'+clear+'switch(invocation){'+''.join(cases)+'default:return 0;}}\n'
    check_name='osrec_state_matches' if writable else 'osrec_state_unchanged'
    header+='static int '+check_name+'(unsigned invocation) {switch(invocation){'+''.join(checks)+'default:return 0;}}\n'
    if continuous:header+='static int osrec_entry_matches(unsigned invocation){switch(invocation){'+''.join(entry_checks)+'default:return 0;}}\n'
    if not writable:header+='#define osrec_state_matches osrec_state_unchanged\n'
    if arguments:header+='static uint32_t osrec_argument(unsigned invocation,unsigned argument){switch(invocation){'+''.join(arguments)+'default:return 0;}}\n'
    return header


def load_reconstruction(capture, roots, sequence, effects=False, continuous=False):
    """Validate capture provenance and generate selected invocation states."""
    import json
    from pathlib import Path
    from klee_liteos import ROOT,digest
    report=json.loads((capture/'report.json').read_text())
    hashes=report['automated_capture_hashes']
    for key,file in [('plan','entry-state-plan.json'),('snapshots','entry-state-snapshots.json'),('generated_hooks','entry-state-capture.h')]:
        if digest((capture/file).read_bytes())!=hashes[key]:raise ValueError('automated capture hash differs: '+key)
    bundle=json.loads((capture/'entry-state-plan.json').read_text())
    if bundle['format']!='osrec-entry-state-plan-v1':raise ValueError('unsupported plan format')
    if bundle['capture_abi']!={'endianness':'little','pointer_bits':32,'address_serialization':False}:
        raise ValueError('unsupported capture ABI')
    if bundle['boundary_policy_sha256']!=digest((ROOT/'integrations/liteos_a/entry-state-boundaries.json').read_bytes()):
        raise ValueError('entry-state boundary policy changed')
    for source in bundle['source_identities']:
        for file,expected in {source['source']:source['source_sha256'],**source['dependencies']}.items():
            if digest(Path(file).read_bytes())!=expected:raise ValueError('analysis source changed: '+file)
    plans={p['root']:p for p in bundle['plans']}
    snapshots=json.loads((capture/'entry-state-snapshots.json').read_text())
    if snapshots['format']!='osrec-live-entry-state-v1':raise ValueError('unsupported snapshot bundle')
    frames=[f for f in snapshots['snapshots'] if f['syscall'] in roots]
    if [(f['invocation'],f['syscall']) for f in frames]!=list(enumerate(sequence)):
        raise ValueError('snapshot sequence differs')
    if continuous:
        contract=report.get('automated_session_identity',{})
        if contract.get('format')!='osrec-capture-scoped-object-ids-v1' or not set(sequence)<=set(contract.get('stable_lifetimes_for_syscalls',[])):
            raise ValueError('continuous replay requires an explicit stable-lifetime capture contract')
    post_states=None
    if effects:
        file=capture/'entry-state-effects.json'
        if digest(file.read_bytes())!=hashes['effects']:raise ValueError('effect capture hash differs')
        bundle=json.loads(file.read_text())
        if bundle['format']!='osrec-live-entry-effects-v1':raise ValueError('unsupported effect bundle')
        post_states=[f for f in bundle['snapshots'] if f['syscall'] in roots]
        if [(f['invocation'],f['syscall']) for f in post_states]!=list(enumerate(sequence)):raise ValueError('effect sequence differs')
    if 'lifetimes' in hashes:
        from entry_state_lifetimes import validate_lifetimes
        file=capture/'entry-state-lifetimes.json'
        if digest(file.read_bytes())!=hashes['lifetimes']:raise ValueError('lifetime capture hash differs')
        validate_lifetimes(json.loads(file.read_text()),frames+(post_states or []))
    header=reconstruction_header(frames,[plans[roots[f['syscall']]] for f in frames],post_states=post_states,scalar_arguments=effects,continuous=continuous)
    return header,frames,hashes
