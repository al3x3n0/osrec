#!/usr/bin/env python3
"""Expand configured call bodies from a verified kernel survey; invent no models."""
import argparse
from collections import Counter,defaultdict
from concurrent.futures import ThreadPoolExecutor,as_completed
import json
import os
from pathlib import Path
import subprocess
import sys
from entry_state import Analyzer,children,digest,load_ast,capture_header,compiler_arguments,DEFAULT_MAX_ALIAS_PATHS
from entry_state_program import merge_translation_units
from discover_kernel_state import write


class DefinitionIndex:
    def __init__(self,definitions,source_evidence=None,data_loader=None):
        self.definitions={name:sorted(set(sources)) for name,sources in definitions.items()}
        self.source_evidence=source_evidence or {}
        self.data_loader=data_loader;self.data_index=None

    def data_sources(self,name):
        if self.data_index is None:
            self.data_index=self.data_loader() if self.data_loader else {'symbols':{},'evidence':{}}
        return self.data_index['symbols'].get(name,[]),self.data_index['evidence']

    @classmethod
    def from_survey(cls,survey,database):
        survey=survey.resolve();report=json.loads((survey/'report.json').read_text())
        if report.get('format')!='osrec-kernel-state-discovery-v1':raise ValueError('unsupported survey format')
        if digest(database.read_bytes())!=report['compilation_database_sha256']:raise ValueError('compilation database differs from survey')
        definitions=defaultdict(list);evidence={};dependencies={}
        for row in report['units']:
            path=(survey/row['report']).resolve()
            if not path.is_relative_to(survey):raise ValueError('unit report escapes survey')
            if digest(path.read_bytes())!=row['report_sha256']:raise ValueError('unit report changed: '+str(path))
            unit=json.loads(path.read_text());identity=unit.get('identity')
            if not identity:continue
            if identity['source']!=row['source']:raise ValueError('unit source identity differs')
            if identity['compilation_database_sha256']!=report['compilation_database_sha256']:raise ValueError('unit database identity differs')
            evidence[row['source']]=identity
            for filename,expected in identity['dependencies'].items():
                if filename in dependencies and dependencies[filename]!=expected:raise ValueError('inconsistent survey dependency: '+filename)
                dependencies[filename]=expected
            for root in unit.get('roots',[]):
                if root['linkage']=='external':definitions[root['name']].append(row['source'])
        for filename,expected in dependencies.items():
            if digest(Path(filename).read_bytes())!=expected:raise ValueError('survey dependency changed: '+filename)
        for source,identity in evidence.items():
            if digest(Path(source).read_bytes())!=identity['source_sha256']:raise ValueError('survey source changed: '+source)
        manifest=survey/'objects.json'
        manifest_hash=digest(manifest.read_bytes()) if manifest.exists() else None
        def data_loader():
            if manifest_hash is None:return {'symbols':{},'evidence':{}}
            if digest(manifest.read_bytes())!=manifest_hash:raise ValueError('object manifest changed')
            rows=json.loads(manifest.read_text());objects={};symbols=defaultdict(list)
            for row in rows:
                obj=Path(row['object'])
                if str(obj) in objects:raise ValueError('duplicate configured object')
                raw=obj.read_bytes()
                if digest(raw)!=row['object_sha256']:raise ValueError('configured object changed: '+str(obj))
                if not raw.startswith(b'\x7fELF'):raise ValueError('data discovery requires ELF objects')
                if row.get('source') and digest(Path(row['source']).read_bytes())!=row['source_sha256']:
                    raise ValueError('object source changed: '+row['source'])
                if row.get('dependency_file_sha256') and digest(obj.with_suffix('.d').read_bytes())!=row['dependency_file_sha256']:
                    raise ValueError('object dependency file changed: '+str(obj))
                objects[str(obj)]=row
            first=next(iter(evidence),None)
            if first is None:raise ValueError('no verified compiler for object index')
            compiler,_,_=compiler_arguments(database,Path(first))
            nm=Path(compiler).resolve().with_name('llvm-nm')
            output=subprocess.check_output([str(nm),'--defined-only','--extern-only','--format=posix','--print-file-name',*objects],text=True)
            for line in output.splitlines():
                if not line.strip():continue
                path,sep,rest=line.partition(': ');parts=rest.split()
                if not sep or path not in objects or len(parts) not in (3,4):raise ValueError('unsupported object symbol output')
                name,kind=parts[:2];row=objects[path]
                # Keep every external definition, including weak/assembly and
                # non-data symbols, so none can silently win symbol precedence.
                symbols[name].append({'source':row.get('source'),'object':path,'symbol_type':kind,
                    'eligible':kind in ('R','D') and row.get('language')=='c' and row.get('source') in evidence})
            return {'symbols':dict(symbols),'evidence':{'objects_sha256':manifest_hash,
                'symbol_output_sha256':digest(output.encode()),'objects':len(objects),'tool':str(nm),'tool_sha256':digest(nm.read_bytes())}}
        return cls(definitions,evidence,data_loader)


def abi_identity(identity):
    args=identity['compile_arguments']
    target='compiler-default';flags={}
    for i,s in enumerate(args):
        if s.startswith('--target='):target=s.split('=',1)[1]
        elif s in ('-target','--target') and i+1<len(args):target=args[i+1]
        if s=='-arch' and i+1<len(args):flags['arch']=args[i+1]
        elif s.startswith(('-mabi=','-mfloat-abi=')):flags[s.split('=',1)[0]]=s
        elif s.startswith(('-fpack-struct','-fno-pack-struct')):flags['pack']=s
        elif s in ('-fshort-enums','-fno-short-enums'):flags['enums']=s
        elif s in ('-fshort-wchar','-fno-short-wchar'):flags['wchar']=s
        elif s in ('-m32','-m64'):flags['width']=s
        elif s in ('-funsigned-char','-fsigned-char'):flags['char']=s
    return target,identity['compiler'],tuple(sorted(flags.items()))


def eligible_roots(survey,index):
    """Select missing-body-only roots fairly across source groups, without models."""
    return selected_roots(survey,index,mixed=False)


def mixed_roots(survey,index):
    """Select other blocked roots with at least one uniquely available C body."""
    return selected_roots(survey,index,mixed=True)


def selected_roots(survey,index,mixed=False):
    report=json.loads((survey/'report.json').read_text());active=None;inputs={}
    if (survey/'objects.json').exists() and (survey/'module-ownership.json').exists():
        objects=json.loads((survey/'objects.json').read_text())
        owners=json.loads((survey/'module-ownership.json').read_text())['objects']
        active={r['source'] for r in objects if r.get('language')=='c' and r['object'] in owners}
        inputs={name:digest((survey/name).read_bytes()) for name in ('objects.json','module-ownership.json')}
    common=Path(os.path.commonpath(list(index.source_evidence))) if index.source_evidence else survey
    if common.is_file():common=common.parent
    groups=defaultdict(list);excluded_eligible=0
    for row in report['units']:
        if row['status']!='analyzed' or (active is not None and row['source'] not in active):continue
        unit=json.loads((survey/row['report']).read_text())
        for root in unit.get('roots',[]):
            missing=root.get('unresolved_direct_calls',[])
            known=[name for name in missing if len(index.definitions.get(name,[]))==1]
            eligible=(set(root.get('blocker_counts',{}))=={'unmodeled_external'} and
                      bool(missing) and len(known)==len(missing))
            if mixed:
                if eligible:excluded_eligible+=1;continue
                if root.get('status')!='blocked' or not known:continue
            elif not eligible:continue
            parts=Path(row['source']).relative_to(common).parts
            group='/'.join(parts[:3]) if len(parts)>3 else str(Path(*parts[:-1]))
            request={'source':row['source'],'root':root['name'],'selection_group':group}
            if mixed:request.update(available_callees=sorted(known),
                unavailable_callees=sorted(name for name in missing if not index.definitions.get(name)),
                ambiguous_callees=sorted(name for name in missing if len(index.definitions.get(name,[]))>1),
                baseline_blockers=sorted(root['blocker_counts']))
            groups[group].append((len({index.definitions[name][0] for name in known}),row['source'],root['name'],request))
    queues={name:sorted(rows,key=lambda r:r[:3]) for name,rows in groups.items()};requests=[]
    for i in range(max((len(rows) for rows in queues.values()),default=0)):
        for name,rows in sorted(queues.items()):
            if i<len(rows):requests.append(rows[i][3])
    info={'kind':'mixed_blockers_or_missing_bodies_with_available_external_definitions' if mixed else
                 'missing_body_only_with_unique_external_definitions','active_module_filter':active is not None,
          'groups':{name:len(rows) for name,rows in sorted(queues.items())},'selection_input_sha256':inputs}
    if mixed:info['excluded_eligible_roots']=excluded_eligible
    return requests,info


def select_batch(requests,start=0,maximum=None):
    if start<0 or (maximum is not None and maximum<1):raise ValueError('invalid batch range')
    if start>=len(requests):raise ValueError('batch starts beyond available roots')
    return requests[start:start+maximum if maximum is not None else None]


def aggregate_batches(survey,index,batches,cohort='eligible'):
    """Account for recorded results without using them as analysis/cache proofs."""
    if cohort not in ('eligible','mixed'):raise ValueError('unknown coverage cohort')
    if not batches:raise ValueError('coverage requires at least one batch')
    eligible,selection=(mixed_roots if cohort=='mixed' else eligible_roots)(survey,index)
    expected={(r['source'],r['root']) for r in eligible};seen={};inputs=[];budgets=None;rows=[]
    for directory in batches:
        directory=directory.resolve();path=directory/'report.json';batch=json.loads(path.read_text())
        if batch.get('format')!='osrec-call-closure-batch-v1':raise ValueError('unsupported batch format')
        if batch['survey_sha256']!=digest((survey/'report.json').read_bytes()) or batch['compilation_database_sha256']!=digest((survey/'compile_commands.json').read_bytes()):
            raise ValueError('batch survey/database identity differs')
        options=batch['options'];limits=tuple(options[k] for k in ('max_translation_units','max_contexts','root_timeout'))+(options.get('max_alias_paths'),)
        if (options.get('all_mixed') and cohort!='mixed') or (options.get('all_eligible') and cohort!='eligible'):
            raise ValueError('batch cohort differs from coverage cohort')
        if options.get('all_mixed') and options.get('all_eligible'):raise ValueError('conflicting batch cohort flags')
        if budgets is not None and budgets!=limits:raise ValueError('batch analysis limits differ')
        budgets=limits
        requests=json.loads((directory/'requests.json').read_text())
        if options.get('all_eligible') or options.get('all_mixed'):
            selected=select_batch(eligible,options.get('start_root',0),options.get('max_roots'))
            if selected!=requests:raise ValueError('batch selection differs from verified survey')
        requested={(r['source'],r['root']) for r in requests}
        if len(requested)!=len(requests):raise ValueError('duplicate requested roots')
        reported={(r['source'],r['root']) for r in batch['roots']}
        if reported!=requested or len(batch['roots'])!=len(requests):raise ValueError('batch omits or duplicates requested roots')
        if not requested<=expected:raise ValueError('batch contains roots outside eligible inventory')
        for row in batch['roots']:
            key=row['source'],row['root']
            if key in seen:raise ValueError('overlapping batch root: '+str(key))
            result_path=(directory/row['report']).resolve()
            if not result_path.is_relative_to(directory):raise ValueError('root report escapes batch')
            if digest(result_path.read_bytes())!=row['sha256']:raise ValueError('root report hash differs')
            result=json.loads(result_path.read_text())
            if (result['source'],result['root'])!=key or result['status']!=row['status']:raise ValueError('root result identity/status differs')
            if result['status'] not in ('candidate','blocked','failed'):raise ValueError('incomplete root result')
            if result['status']!='failed':
                if not result['limits'].get('function_reference_slicing'):raise ValueError('batch did not use function-reference slicing')
                if result['status']!=('blocked' if result['plan']['blockers'] else 'candidate'):raise ValueError('root plan status differs')
                for identity in result['program']['source_identities']:
                    prior=index.source_evidence.get(identity['source'])
                    if prior is None or identity['source_sha256']!=prior['source_sha256'] or identity['dependencies']!=prior['dependencies']:
                        raise ValueError('root source identity differs from survey')
            seen[key]=row['status']
            rows.append(row|{'batch':str(directory),'result_file':str(result_path)})
        inputs.append({'directory':str(directory),'report_sha256':digest(path.read_bytes()),
                       'requests_sha256':digest((directory/'requests.json').read_bytes()),
                       'analysis_sources_sha256':batch.get('analysis_sources_sha256'),
                       'analysis_source_stability_recorded':batch.get('analysis_sources_stable')})
    missing=[r for r in eligible if (r['source'],r['root']) not in seen]
    return {'format':'osrec-call-closure-coverage-v1','survey_sha256':digest((survey/'report.json').read_bytes()),
            'compilation_database_sha256':digest((survey/'compile_commands.json').read_bytes()),'selection':selection,
            'limits':{'translation_units':budgets[0],'contexts':budgets[1],'root_seconds':budgets[2],
                      'recorded_results_only':True,'runtime_validated':False,'completeness_proven':False},
            'summary':{('mixed_roots' if cohort=='mixed' else 'eligible_roots'):len(eligible),'requested_roots':len(seen),'unrequested_roots':len(missing),
                       'status':dict(Counter(seen.values())),'capture_schema_candidates':sum(r.get('capture_schema_accepted',False) for r in rows)},
            'batches':inputs,'roots':sorted(rows,key=lambda r:(r['source'],r['root'])),'unrequested':missing}


def analysis_sources():
    directory=Path(__file__).resolve().parent
    names=('discover_call_closure.py','discover_kernel_state.py','entry_state.py','entry_state_program.py',
           'entry_state_loops.py','entry_state_constants.py','entry_state_dominance.py')
    return {name:digest((directory/name).read_bytes()) for name in names}


def discover(database,source,root,index,max_units=4,max_contexts=100,analysis_options=None,checkpoint=None,slice_functions=True,cache_merge_syntax=True):
    if max_units<1:raise ValueError('translation-unit limit must be positive')
    source=source.resolve();units=[];loaded=set();attempted=set();data_attempted=set();events=[];history=[];plan=None;program=None
    syntax_cache={} if cache_merge_syntax else None
    def load(path):
        path=str(Path(path).resolve())
        tree,identity=load_ast(database,Path(path))
        prior=index.source_evidence.get(path)
        if prior and (identity['source_sha256']!=prior['source_sha256'] or identity['dependencies']!=prior['dependencies']):
            raise ValueError('fresh parse differs from survey identity: '+path)
        if units and abi_identity(identity)!=abi_identity(units[0][1]):raise ValueError('incompatible compiler target or ABI options: '+path)
        units.append((tree,identity));loaded.add(path)
    load(source)
    node=next((n for n in children(units[0][0]) if n.get('kind')=='FunctionDecl' and n.get('name')==root and
               any(c.get('kind')=='CompoundStmt' for c in children(n))),None)
    if node is None:raise ValueError('root has no configured body: '+root)
    merged_root='tu0:'+root if node.get('storageClass')=='static' or node.get('inline') else root
    while True:
        try:
            tree,new_program=merge_translation_units(units,roots=[merged_root] if slice_functions else None,syntax_cache=syntax_cache)
            analyzer=Analyzer(tree,max_contexts=max_contexts,**(analysis_options or {}))
            new_plan=analyzer.analyze(merged_root)
        except (ValueError,RecursionError) as error:
            events.append({'kind':'merge_or_analysis_failed','detail':str(error)})
            break
        plan,program=new_plan,new_program
        missing=sorted({c['callee'] for c in plan['call_sites'] if c['callee'] and not c['boundary'] and not c.get('intrinsic') and c['callee'] not in analyzer.functions})
        missing_records=analyzer.missing_constant_records(plan)
        missing_data=analyzer.missing_constant_data(plan)
        history.append({'translation_units':len(units),'sources':[identity['source'] for _,identity in units],
                        'missing_bodies':missing,'missing_constant_records':missing_records,'missing_constant_data':missing_data,'blocker_counts':dict(Counter(b['kind'] for b in plan['blockers'])),
                        'entry_paths':sorted({r['path'] for r in plan['entry_reads']}),
                        'write_paths':sorted({r['path'] for r in plan['state_writes']})})
        if checkpoint:write(checkpoint,{'status':'in_progress','source':str(source),'root':root,'history':history,'events':events})
        additions=defaultdict(list)
        data_additions=defaultdict(list)
        for name in missing:
            if name in attempted:continue
            attempted.add(name);sources=index.definitions.get(name,[])
            if len(sources)>1:events.append({'kind':'ambiguous_definition','callee':name,'sources':sources})
            elif not sources:events.append({'kind':'body_unavailable','callee':name})
            elif sources[0] in loaded:events.append({'kind':'body_not_resolved_in_loaded_unit','callee':name,'source':sources[0]})
            else:additions[sources[0]].append(name)
        for name in missing_data:
            if name in data_attempted:continue
            data_attempted.add(name)
            try:
                definitions,evidence=index.data_sources(name)
                event={'object_name':name,'definitions':definitions,'index_evidence':evidence}
                if len(definitions)>1:events.append(event|{'kind':'ambiguous_data_definition'})
                elif not definitions:events.append(event|{'kind':'data_definition_unavailable'})
                elif not definitions[0]['eligible']:events.append(event|{'kind':'unsupported_data_definition'})
                elif definitions[0]['source'] in loaded:events.append(event|{'kind':'data_not_resolved_in_loaded_unit'})
                else:
                    path=definitions[0]['source'];data_additions[path].append(name)
                    additions.setdefault(path,[])
                    events.append(event|{'kind':'data_source_selected'})
            except (ValueError,OSError,subprocess.SubprocessError) as error:
                events.append({'kind':'data_index_failed','object_name':name,'detail':str(error)})
        if not additions:break
        if len(units)>=max_units:
            events.append({'kind':'translation_unit_limit','remaining':dict(additions),'remaining_data':dict(data_additions),'limit':max_units});break
        changed=False
        for path,names in sorted(additions.items()):
            if len(units)>=max_units:
                events.append({'kind':'translation_unit_limit','source':path,'callees':names,'data_objects':data_additions.get(path,[]),'limit':max_units});continue
            try:
                load(path);changed=True
                events.append({'kind':'body_source_loaded' if names else 'data_source_loaded','source':path,'callees':names,'data_objects':data_additions.get(path,[])})
            except (ValueError,OSError,subprocess.SubprocessError) as error:
                events.append({'kind':'body_source_failed' if names else 'data_source_failed','source':path,'callees':names,'data_objects':data_additions.get(path,[]),'detail':str(error)})
        if not changed:break
    if plan is None:raise ValueError('no valid merged plan: '+json.dumps(events))
    schema=False;schema_error=None
    if not plan['blockers']:
        try:capture_header([plan]);schema=True
        except ValueError as error:schema_error=str(error)
    return {'format':'osrec-discovered-call-closure-v1','status':'candidate' if not plan['blockers'] else 'blocked',
            'source':str(source),'root':root,'merged_root':merged_root,'plan':plan,'program':program,'history':history,'events':events,
            'capture_schema_accepted':schema,'capture_schema_error':schema_error,
            'limits':{'max_translation_units':max_units,'max_contexts':max_contexts,
                      'max_alias_paths':plan['analysis_limits']['max_alias_paths'],
                      'alias_path_limit_observed':plan['analysis_limits']['alias_path_limit_observed'],'boundary_models_invented':False,
                      'function_reference_slicing':slice_functions,'record_type_slicing':False,
                      'runtime_validated':False,'completeness_proven':False,'definition_resolution':'unique external C bodies and verified ELF numeric const data; no weak/linker-symbol precedence'}} 


def main():
    if len(sys.argv)>1 and sys.argv[1]=='--worker':
        survey,database,source,root,out,maximum,contexts,*alias_budget=sys.argv[2:]
        index=DefinitionIndex.from_survey(Path(survey),Path(database))
        write(Path(out),discover(Path(database),Path(source),root,index,int(maximum),int(contexts),
            analysis_options={'max_alias_paths':int(alias_budget[0]) if alias_budget else DEFAULT_MAX_ALIAS_PATHS},checkpoint=Path(out)));return
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--survey',type=Path,required=True)
    selection=parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--roots',type=Path);selection.add_argument('--all-eligible',action='store_true')
    selection.add_argument('--all-mixed',action='store_true',help='other blocked roots with at least one uniquely indexed external C body')
    selection.add_argument('--aggregate-batches',type=Path,nargs='+')
    parser.add_argument('--coverage-cohort',choices=('eligible','mixed'),default='eligible',help='cohort denominator for aggregation only')
    parser.add_argument('--max-roots',type=int)
    parser.add_argument('--start-root',type=int,default=0,help='zero-based offset into the deterministic root sequence')
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--max-translation-units',type=int,default=4)
    parser.add_argument('--max-contexts',type=int,default=100);parser.add_argument('--root-timeout',type=float,default=60)
    parser.add_argument('--max-alias-paths',type=int,default=DEFAULT_MAX_ALIAS_PATHS)
    parser.add_argument('--jobs',type=int,default=2);args=parser.parse_args()
    if min(args.jobs,args.max_contexts,args.max_translation_units,args.root_timeout,args.max_alias_paths)<=0:parser.error('resource limits must be positive')
    if args.max_roots is not None and args.max_roots<1:parser.error('--max-roots must be positive')
    if args.start_root<0:parser.error('--start-root must be nonnegative')
    survey=args.survey.resolve();database=survey/'compile_commands.json';index=DefinitionIndex.from_survey(survey,database)
    if args.aggregate_batches:
        if args.start_root or args.max_roots is not None:parser.error('batch ranges do not apply to aggregation')
        report=aggregate_batches(survey,index,args.aggregate_batches,args.coverage_cohort)
        args.out.mkdir(parents=True,exist_ok=False);write(args.out/'report.json',report)
        print(json.dumps(report['summary'],indent=2));return
    if args.coverage_cohort!='eligible':parser.error('--coverage-cohort applies only to aggregation')
    if args.all_eligible:requests,selection_info=eligible_roots(survey,index)
    elif args.all_mixed:requests,selection_info=mixed_roots(survey,index)
    else:requests=json.loads(args.roots.read_text());selection_info={'kind':'explicit_roots'}
    if not isinstance(requests,list) or not requests:raise ValueError('roots must be a nonempty array of source/root objects')
    selection_info['available_roots']=len(requests)
    requests=select_batch(requests,args.start_root,args.max_roots)
    if any(not isinstance(r,dict) or not all(isinstance(r.get(k),str) and r[k] for k in ('source','root')) for r in requests):
        raise ValueError('each root requires nonempty source and root strings')
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False);(out/'roots').mkdir();write(out/'requests.json',requests)
    source_hashes=analysis_sources()
    def execute(pair):
        number,request=pair;path=out/'roots'/f'{number:04d}.json'
        cmd=[sys.executable,str(Path(__file__).resolve()),'--worker',str(survey),str(database),request['source'],request['root'],str(path),str(args.max_translation_units),str(args.max_contexts),str(args.max_alias_paths)]
        try:
            result=subprocess.run(cmd,capture_output=True,text=True,timeout=args.root_timeout)
            if result.returncode:raise ValueError(result.stderr[-20000:])
            value=json.loads(path.read_text())
            if not isinstance(value,dict) or value.get('status') not in ('candidate','blocked'):
                raise ValueError('worker did not produce a completed result object')
        except (OSError,ValueError,subprocess.SubprocessError) as error:
            try:
                value=json.loads(path.read_text()) if path.exists() else {}
                if not isinstance(value,dict):raise ValueError('checkpoint is not a JSON object')
            except (OSError,ValueError) as checkpoint_error:
                if path.exists():os.replace(path,path.with_suffix('.invalid-checkpoint'))
                value={'checkpoint_error':str(checkpoint_error)}
            value.update(status='failed',source=request['source'],root=request['root'],error=str(error),capture_schema_accepted=False);write(path,value)
        return {'source':request['source'],'root':request['root'],'status':value['status'],'report':str(path.relative_to(out)),
                'sha256':digest(path.read_bytes()),'rounds':len(value.get('history',[])),
                'capture_schema_accepted':value.get('capture_schema_accepted',False)}
    rows=[]
    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        for future in as_completed([executor.submit(execute,p) for p in enumerate(requests)]):
            row=future.result();rows.append(row);print(row['root'],row['status'],'rounds',row['rounds'],flush=True)
    rows.sort(key=lambda r:(r['source'],r['root']))
    report={'format':'osrec-call-closure-batch-v1','survey':str(survey),'survey_sha256':digest((survey/'report.json').read_bytes()),
            'compilation_database_sha256':digest(database.read_bytes()),'selection':selection_info,
            'analysis_sources_sha256':source_hashes,'analysis_sources_stable':source_hashes==analysis_sources(),
            'options':vars(args)|{'survey':str(survey),'roots':str(args.roots) if args.roots else None,'out':str(out)},
            'summary':{'roots':len(rows),'status':dict(Counter(r['status'] for r in rows)),
                       'capture_schema_candidates':sum(r['capture_schema_accepted'] for r in rows)},'roots':rows}
    write(out/'report.json',report);print(json.dumps(report['summary'],indent=2))
if __name__=='__main__':main()
