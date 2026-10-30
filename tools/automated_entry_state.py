#!/usr/bin/env python3
"""Generate typed plans and normalized snapshot hooks for the configured live kernel."""
import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from klee_liteos import ROOT
from prepare_entry_state import prepare as compile_commands
from entry_state import Analyzer,load_ast,capture_header,digest
from entry_state_program import merge_translation_units
ROOTS={'syscall/process_syscall.c':['SysGetPPID','SysGetTid','SysGetEffUserID','SysGetEffGID','SysGetProcessPriority'],
       'fs/vfs/operation/vfs_other.c':['SysUmask']}

def effect_plan(plan):
    """Post-state footprint includes all captured reads and possible writes."""
    return {**plan,'entry_reads':plan['entry_reads']+plan.get('state_writes',[])}

def generate(tree,llvm_bin,out,boundary_file=None,credential_queries=(),argument_entry=False,shared_mixed=False):
    boundary_file=boundary_file or ROOT/'integrations/liteos_a/entry-state-boundaries.json'
    policy=json.loads(boundary_file.read_text())
    if policy['format']!='osrec-entry-state-boundaries-v1':raise ValueError('unsupported boundary policy')
    from credential_entry_state import QUERY_ROOTS,COPY_MODEL,capture_plan
    if len(credential_queries)>1 or any(root not in QUERY_ROOTS.values() for root in credential_queries):raise ValueError('select one reviewed credential query')
    if credential_queries:policy['boundaries']['LOS_ArchCopyToUser']=COPY_MODEL
    roots_by_source={source:list(roots) for source,roots in ROOTS.items()}
    roots_by_source['syscall/process_syscall.c']+=list(credential_queries)
    argument_objects={}
    if argument_entry:
        from live_argument_state import profile_settings
        settings=profile_settings(argument_entry if isinstance(argument_entry,str) else 'exit-code')
        HELPER=settings['helper'];ARGUMENT_POLICY=settings['policy']
        argument_objects=json.loads(ARGUMENT_POLICY.read_text())['argument_objects']
        roots_by_source['syscall/process_syscall.c'].append(HELPER)
        if shared_mixed:
            if argument_entry!='exit-signal-session':raise ValueError('mixed shared capture requires the current-process signal session')
            query=profile_settings('exit-code')
            argument_objects.update(json.loads(query['policy'].read_text())['argument_objects'])
            roots_by_source['syscall/process_syscall.c'].append(query['helper'])
    out.mkdir(parents=True,exist_ok=True);plans=[];identities=[];units=[]
    for index,(source,roots) in enumerate(roots_by_source.items()):
        database=out/('compile_commands_'+str(index)+'.json')
        compile_commands(SimpleNamespace(tree=tree,llvm_bin=llvm_bin,source=Path(source),out=database))
        if argument_entry and settings.get('adapter') and source=='syscall/process_syscall.c':
            records=json.loads(database.read_text())
            records[0]['arguments']+=['-include',str(tree/'kernel/liteos_a/kernel/base/include/los_process_pri.h'),
                                      '-include',str(settings['adapter'])]
            database.write_text(json.dumps(records,indent=2)+'\n')
        ast,identity=load_ast(database,tree/'kernel/liteos_a'/source)
        identities.append(identity);units.append((ast,identity))
    ast,program=merge_translation_units(units)
    program={k:v for k,v in program.items() if k!='source_identities'}
    for roots in roots_by_source.values():
        for root in roots:
            analyzer=Analyzer(ast,policy['boundaries'],argument_objects=argument_objects)
            internal='tu0:'+root if 'tu0:'+root in analyzer.functions else root
            plan=analyzer.analyze(internal);plan['root']=root;plans.append(plan)
    capture_plans=list(plans)
    if credential_queries:
        process_provider=next(p for plan in plans for p in plan['object_providers'] if p['function']=='OsCurrProcessGet')
        capture_plans=[capture_plan(p,process_provider) if p['root'] in credential_queries else p for p in plans]
    header=capture_header(capture_plans)
    effects=[{**effect_plan(p),'root':'effects_'+p['root']} for p in plans if p.get('state_writes')]
    if effects:header+='\n'+capture_header(effects)
    report={'format':'osrec-entry-state-plan-v1','source_identities':identities,
        'boundary_policy_sha256':digest(boundary_file.read_bytes()),'plans':plans,'program':program,
        'snapshot_generation':'generated','capture_header_sha256':digest(header.encode()),
        'capture_abi':{'endianness':'little','pointer_bits':32,'address_serialization':False}}
    if credential_queries:report.update(credential_queries=list(credential_queries),capture_plans=capture_plans,additional_boundary_models={'LOS_ArchCopyToUser':COPY_MODEL})
    if argument_entry:report['argument_boundary_policy_sha256']=digest(ARGUMENT_POLICY.read_bytes())
    if shared_mixed:report['shared_query_boundary_policy_sha256']=digest(query['policy'].read_bytes())
    (out/'capture.h').write_text(header);(out/'plan.json').write_text(json.dumps(report,indent=2)+'\n')
    return report,header

def validate_snapshot(frame,plan):
    from entry_state import snapshot_providers,entry_accesses
    providers=snapshot_providers(plan)
    if frame.get('format')!='osrec-entry-snapshot-v1':raise ValueError('unsupported snapshot format')
    objects={row['id']:row for row in frame['objects']}
    if len(objects)!=len(frame['objects']) or any(not isinstance(i,int) or i<=0 for i in objects):raise ValueError('invalid object IDs')
    bindings={row['name']:row['object_id'] for row in frame['roots']}
    if len(bindings)!=len(frame['roots']):raise ValueError('duplicate root bindings')
    if set(bindings)!={p['function']+'()' for p in providers}:raise ValueError('snapshot provider set differs from plan')
    fields={}
    if any('address' in row for row in frame['objects']):raise ValueError('object addresses must not be serialized')
    for row in frame['fields']:
        if row['object_id'] not in objects:raise ValueError('field owner is missing')
        key=(row['object_id'],row['name'])
        if key in fields:raise ValueError('duplicate field snapshot')
        fields[key]=row
        if row['kind']=='edge':
            if row['target_id'] and row['target_id'] not in objects:raise ValueError('edge target is missing')
            if 'data' in row:raise ValueError('pointer edge must not contain address bytes')
        elif row['kind']=='scalar':
            if not 0<row['bytes']<=16 or len(bytes.fromhex(row['data']))!=row['bytes']:raise ValueError('scalar width differs')
        else:raise ValueError('unknown field kind')
    for root in bindings.values():
        if root and root not in objects:raise ValueError('root object is missing')
    for read in entry_accesses(plan):
        name,*parts=read['path'].split('->');owner=bindings[name]
        for index,part in enumerate(parts):
            if not owner:break
            if (owner,part) not in fields:raise ValueError('planned field missing: '+read['path'])
            row=fields[owner,part]
            last=index==len(parts)-1
            expected='edge' if not last or read['pointer_edge'] else 'scalar'
            if row['kind']!=expected:raise ValueError('planned field kind differs')
            if row['kind']=='edge':owner=row['target_id']
    return frame

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree',type=Path,default=ROOT/'build/ohos')
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--credential-query',choices=('getresuid','getresgid'),help='also generate the selected query through its reviewed current-user binding and copy model')
    parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    from credential_entry_state import QUERY_ROOTS
    queries=[QUERY_ROOTS[args.credential_query]] if args.credential_query else []
    report,_=generate(args.tree.resolve(),args.llvm_bin.resolve(),args.out.resolve(),credential_queries=queries)
    print(json.dumps({'roots':len(report['plans']),'capture_header':str(args.out/'capture.h'),
        'plan':str(args.out/'plan.json'),'read_fields':sum(len(p['entry_reads']) for p in report['plans'])},indent=2))
if __name__=='__main__':main()
