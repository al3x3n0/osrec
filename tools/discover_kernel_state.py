#!/usr/bin/env python3
"""Inventory configured build objects and survey every available C function body.

This is a translation-unit coverage baseline, not a whole-program proof. Unknown
calls, failed units, assembly and missing source provenance remain visible.
"""
import argparse
from collections import Counter,defaultdict
from concurrent.futures import ThreadPoolExecutor,as_completed
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
from entry_state import Analyzer,children,digest,load_ast,capture_header,type_of,DEFAULT_MAX_ALIAS_PATHS
from prepare_entry_state import compile_record,make_configuration


def write(path,value):
    data=json.dumps(value,indent=2,sort_keys=True)+'\n';temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path.parent,prefix=path.name+'.',suffix='.tmp',delete=False) as stream:
            temporary=Path(stream.name);stream.write(data)
        os.replace(temporary,path)
    finally:
        if temporary is not None:temporary.unlink(missing_ok=True)


def built_objects(tree):
    """Use existing artifacts as a denominator, without claiming link membership."""
    tree=tree.resolve();rows=[]
    for obj in sorted((tree/'out/obj').rglob('*.o')):
        row={'object':str(obj),'object_sha256':digest(obj.read_bytes())}
        dep=obj.with_suffix('.d')
        try:
            raw=dep.read_bytes();row['dependency_file_sha256']=digest(raw)
            words=shlex.split(raw.decode().replace('\\\n',' ').split(':',1)[1])
            source=Path(words[0]);source=source if source.is_absolute() else tree/source
            source=source.resolve()
            if not source.is_file() or not source.is_relative_to(tree):raise ValueError('missing or outside-tree dependency source')
            row.update(source=str(source),source_sha256=digest(source.read_bytes()),
                       language='c' if source.suffix=='.c' else 'assembly' if source.suffix in ('.S','.s') else 'unsupported')
        except (OSError,ValueError,IndexError) as error:row.update(language='unknown',error=str(error))
        rows.append(row)
    if not rows:raise ValueError('no existing objects under tree/out/obj')
    return rows


def main_definition(node,source,directory=None):
    loc=node.get('loc',{});loc=loc.get('expansionLoc',loc)
    if loc.get('includedFrom'):return False
    path=Path(loc.get('file',source))
    if not path.is_absolute():path=(directory or source.parent)/path
    return path.resolve()==source.resolve()


def configured_owners(tree,llvm_bin,out):
    """Query active Make modules, including libraries outside source directories."""
    query=out/'module-query.mk'
    query.write_text('include $(OSREC_MODULE)/Makefile\n.PHONY: osrec_inventory_variables\nosrec_inventory_variables:\n\t@echo OSREC_MODULES $(LIB_SUBDIRS)\n\t@echo OSREC_OBJECTS $(LOCAL_OBJS)\n')
    def variables(module):
        command=['make','-s','-C',str(module),'-f',str(query),'osrec_inventory_variables',
                 'OSREC_MODULE='+str(module),*make_configuration(tree,llvm_bin)]
        result=subprocess.run(command,capture_output=True,text=True,timeout=60)
        if result.returncode:raise ValueError(result.stderr)
        return {line.split()[0]:line.split()[1:] for line in result.stdout.splitlines() if line.startswith(('OSREC_MODULES','OSREC_OBJECTS'))}
    kernel=tree/'kernel/liteos_a';top=variables(kernel);owners={};failures=[]
    for name in top.get('OSREC_MODULES',[]):
        module=Path(name);module=module if module.is_absolute() else kernel/module
        module=module.resolve()
        try:
            for obj in variables(module).get('OSREC_OBJECTS',[]):owners[str(Path(obj).resolve())]=module
        except (ValueError,OSError,subprocess.SubprocessError) as error:failures.append({'module':str(module),'error':str(error)})
    write(out/'module-ownership.json',{'objects':{key:str(value) for key,value in owners.items()},'query_failures':failures})
    return owners


class RootTimeout(Exception):pass


def survey_unit(database,source,max_contexts,root_timeout=1,checkpoint=None,max_alias_paths=DEFAULT_MAX_ALIAS_PATHS):
    tree,identity=load_ast(database,source);index=Analyzer(tree,max_contexts=max_contexts,max_alias_paths=max_alias_paths)
    roots=[]
    inventory=[{'name':name,'type':type_of(node),'linkage':'internal' if node.get('storageClass')=='static' else 'external',
                'location':Analyzer.location(node),'status':'not_analyzed'} for name,node in sorted(index.functions.items())
               if main_definition(node,source,Path(identity['compile_directory']))]
    if checkpoint:write(checkpoint,{'status':'parsed','identity':identity,'roots':inventory})
    def timeout(signum,frame):raise RootTimeout('root wall-time budget exceeded')
    previous=signal.signal(signal.SIGALRM,timeout)
    for name,node in sorted(index.functions.items()):
        if not main_definition(node,source,Path(identity['compile_directory'])):continue
        row={'name':name,'type':type_of(node),'linkage':'internal' if node.get('storageClass')=='static' else 'external',
             'location':Analyzer.location(node)}
        try:
            signal.setitimer(signal.ITIMER_REAL,root_timeout)
            plan=index.fresh().analyze(name);kinds=Counter(b['kind'] for b in plan['blockers'])
            examples=defaultdict(list)
            for blocker in plan['blockers']:
                if len(examples[blocker['kind']])<3:examples[blocker['kind']].append(blocker)
            schema=False;schema_error=None
            if not kinds:
                try:capture_header([plan]);schema=True
                except ValueError as error:schema_error=str(error)
            row.update(status='blocked' if kinds else 'candidate',blocker_counts=dict(kinds),blocker_examples=dict(examples),
                       analysis_limits=plan['analysis_limits'],
                       entry_paths=sorted({r['path'] for r in plan['entry_reads']}),
                       write_paths=sorted({r['path'] for r in plan['state_writes']}),
                       calls=sorted({r['callee'] for r in plan['call_sites'] if r['callee']}),
                       unresolved_direct_calls=sorted({r['callee'] for r in plan['call_sites'] if r['callee'] and not r.get('intrinsic') and r['callee'] not in index.functions}),
                       capture_schema_accepted=schema,capture_schema_error=schema_error)
        except (ValueError,KeyError,IndexError,RecursionError,TypeError,RootTimeout) as error:
            row.update(status='analysis_failed',error=type(error).__name__+': '+str(error))
        finally:signal.setitimer(signal.ITIMER_REAL,0)
        roots.append(row)
    signal.signal(signal.SIGALRM,previous)
    return {'status':'analyzed','identity':identity,'available_bodies_including_headers':len(index.functions),'roots':roots}


def summarize(units,objects,symbols=()):
    roots=[(u['source'],r) for u in units for r in u.get('roots',[])]
    definitions=defaultdict(list)
    for source,root in roots:
        if root['linkage']=='external':definitions[root['name']].append(source)
    blockers=Counter();calls=defaultdict(set);families=defaultdict(set)
    for source,root in roots:
        for kind in root.get('blocker_counts',{}):blockers[kind]+=1
        for name in root.get('unresolved_direct_calls',[]):calls[name].add((source,root['name']))
        for path in root.get('entry_paths',[]):families[path.split('->',1)[0]].add((source,root['name']))
    return {
        'objects':len(objects),'object_languages':dict(Counter(o['language'] for o in objects)),
        'translation_units':len(units),'unit_status':dict(Counter(u['status'] for u in units)),
        'function_bodies':len(roots),'function_status':dict(Counter(r['status'] for _,r in roots)),
        'capture_schema_candidates':sum(r.get('capture_schema_accepted',False) for _,r in roots),
        'blockers_by_affected_roots':dict(blockers.most_common()),
        'unresolved_calls':[{'callee':name,'affected_roots':len(users),'definition_sources_in_inventory':sorted(set(definitions.get(name,[]))),
                            'resolution':'cross_translation_unit_body_available' if definitions.get(name) else 'no_external_body_in_inventory'}
                           for name,users in sorted(calls.items(),key=lambda pair:(-len(pair[1]),pair[0]))],
        'state_path_origins':[{'origin':name,'affected_roots':len(users)} for name,users in sorted(families.items(),key=lambda pair:(-len(pair[1]),pair[0]))],
        'linked_text_symbols':len(symbols),
        'symbol_name_correspondence':[{'name':s['name'],'address':s['address'],'size':s['size'],
            'definition_sources':sorted({source for source,r in roots if r['name']==s['name']}),
            'matching':'name_only_not_link_provenance'} for s in symbols]}


def survey(args):
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False);(out/'units').mkdir()
    objects=[];recovery=[]
    if args.liteos_tree:
        objects=built_objects(args.liteos_tree);write(out/'objects.json',objects)
        owners=configured_owners(args.liteos_tree,args.llvm_bin,out)
        source_owners={r['source']:owners.get(r['object']) for r in objects if r['language']=='c'}
        sources=sorted({r['source'] for r in objects if r['language']=='c'})
        def recover(source):
            try:return source,compile_record(args.liteos_tree,Path(source),args.llvm_bin,source_owners.get(source)),None
            except (ValueError,OSError,subprocess.SubprocessError) as error:return source,None,str(error)
        records=[]
        with ThreadPoolExecutor(max_workers=args.jobs) as executor:
            for source,record,error in executor.map(recover,sources):
                if record:records.append(record)
                else:recovery.append({'source':source,'status':'command_failed','error':error})
        database=out/'compile_commands.json';write(database,records)
        print('Recovered',len(records),'of',len(sources),'C commands;',len(objects),'objects accounted for',flush=True)
    else:
        database=args.compile_commands.resolve();write(out/'compile_commands.json',json.loads(database.read_text()));database=out/'compile_commands.json'
        records=json.loads(database.read_text())
    sources=sorted({str((Path(r['directory'])/r['file']).resolve()) for r in records})
    units=list(recovery)
    def execute(pair):
        number,source=pair;path=out/'units'/f'{number:04d}.json'
        command=[sys.executable,str(Path(__file__).resolve()),'--worker',str(database),source,str(path),str(args.max_contexts),str(args.root_timeout),str(getattr(args,'max_alias_paths',DEFAULT_MAX_ALIAS_PATHS))]
        try:
            result=subprocess.run(command,capture_output=True,text=True,timeout=args.unit_timeout)
            if result.returncode:raise ValueError('worker exit '+str(result.returncode)+': '+result.stderr[-20000:])
            value=json.loads(path.read_text())
        except (OSError,ValueError,subprocess.SubprocessError) as error:
            value=json.loads(path.read_text()) if path.exists() else {}
            value.update(status='unit_failed',source=source,error=str(error));write(path,value)
        value['source']=source;value['report']=str(path.relative_to(out));value['report_sha256']=digest(path.read_bytes())
        return value
    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures=[executor.submit(execute,pair) for pair in enumerate(sources)]
        for future in as_completed(futures):
            units.append(future.result())
            if len(units)%10==0 or len(units)==len(sources)+len(recovery):print('Surveyed',len(units),'/',len(sources)+len(recovery),'units',flush=True)
    units.sort(key=lambda u:u['source']);symbols=[]
    binary=args.liteos_tree/'out/liteos' if args.liteos_tree else None
    if binary and binary.is_file():
        text=subprocess.check_output([str(args.llvm_bin/'llvm-nm'),'--defined-only','--print-size','--format=posix',str(binary)],text=True)
        for line in text.splitlines():
            parts=line.split()
            if len(parts)==4 and parts[1] in ('t','T'):symbols.append({'name':parts[0],'address':int(parts[2],16),'size':int(parts[3],16)})
    summary=summarize(units,objects,symbols)
    report={'format':'osrec-kernel-state-discovery-v1','phase':'translation_unit_baseline','summary':summary,
            'compilation_database_sha256':digest(database.read_bytes()),
            'build_binary':{'path':str(binary),'sha256':digest(binary.read_bytes())} if binary and binary.is_file() else None,
            'options':{'max_contexts':args.max_contexts,'max_alias_paths':getattr(args,'max_alias_paths',DEFAULT_MAX_ALIAS_PATHS),'unit_timeout':args.unit_timeout,'root_timeout':args.root_timeout,'jobs':args.jobs,'boundary_models':False},
            'scope':'Existing build artifacts, not all configurations or exact linked-object membership; analyze primary-source C definitions using available same-TU bodies and headers.',
            'limits':{'whole_program_call_closure':False,'assembly_analyzed':False,'runtime_validated':False,'minimality_proven':False,'completeness_proven':False,
                      'symbol_matching':'names only; duplicate static names and linker elimination prevent provenance claims',
                      'failures':'Command, unit and root failures remain in the denominator. No models or object contracts are invented.'},
            'units':[{k:v for k,v in u.items() if k not in ('roots','identity')} for u in units]}
    write(out/'report.json',report)
    print(json.dumps({k:v for k,v in summary.items() if k not in ('unresolved_calls','symbol_name_correspondence','state_path_origins')},indent=2),flush=True)
    return report


def main():
    if len(sys.argv)>1 and sys.argv[1]=='--worker':
        database,source,out,maximum,*budget=sys.argv[2:]
        write(Path(out),survey_unit(Path(database),Path(source),int(maximum),float(budget[0]) if budget else 1,Path(out),int(budget[1]) if len(budget)>1 else DEFAULT_MAX_ALIAS_PATHS));return
    parser=argparse.ArgumentParser(description=__doc__);group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--liteos-tree',type=Path);group.add_argument('--compile-commands',type=Path)
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--jobs',type=int,default=2)
    parser.add_argument('--max-contexts',type=int,default=100);parser.add_argument('--unit-timeout',type=int,default=180)
    parser.add_argument('--root-timeout',type=float,default=1)
    parser.add_argument('--max-alias-paths',type=int,default=DEFAULT_MAX_ALIAS_PATHS)
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    args=parser.parse_args()
    if min(args.jobs,args.max_contexts,args.unit_timeout,args.root_timeout,args.max_alias_paths)<=0:parser.error('resource limits must be positive')
    if args.liteos_tree:args.liteos_tree=args.liteos_tree.resolve()
    survey(args)
if __name__=='__main__':main()
