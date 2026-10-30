#!/usr/bin/env python3
"""Generate typed caller adapters for numeric roots with scalar pointer payloads."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from entry_state import Analyzer,arithmetic_scalar,children,compiler_arguments,digest,load_ast,type_of,walk,capture_header
from discover_call_closure import DefinitionIndex,discover,analysis_sources
from discover_kernel_state import write
from automated_entry_state import effect_plan

IDENTIFIER=re.compile(r'[A-Za-z_][A-Za-z_0-9]*\Z')
CONTRACT=dict(kind='object_argument',reason='caller owns one complete initialized generated carrier for the call',
    implementation='typed carrier with embedded one-element numeric arrays; separate fields do not alias',snapshot_safe=True)


def semantic_tree(value):
    """Compare configured declarations with stable identities for Clang references."""
    identities={}
    def collect(v):
        if isinstance(v,list):
            for item in v:collect(item)
        elif isinstance(v,dict):
            if 'id' in v and v['id'] not in identities:identities[v['id']]=len(identities)
            for key,item in v.items():
                if key not in ('loc','range'):collect(item)
    collect(value)
    def normalize(v):
        if isinstance(v,list):return [normalize(item) for item in v]
        if isinstance(v,dict):
            ignored={'id','loc','range','previousDecl','typeAliasDeclId','isUsed','isReferenced'}
            return {k:normalize(item) for k,item in v.items() if k not in ignored and not k.startswith('_')}
        if isinstance(v,str) and v in identities:return {'clang_reference':identities[v]}
        return v
    return normalize(value)


def macro_location(node):
    return any('expansionLoc' in location or 'spellingLoc' in location for location in
        [node.get('loc',{}),node.get('range',{}).get('begin',{}),node.get('range',{}).get('end',{})])


def ordinary_parameter(parameter):
    loc=parameter.get('loc',{});end=parameter.get('range',{}).get('end',{})
    return (bool(parameter.get('name')) and 'offset' in loc and loc.get('offset')==end.get('offset') and
            loc.get('tokLen')==end.get('tokLen')==len(parameter['name']))


def schema(tree,root,wrapper=None):
    """Resolve configured numeric types; never infer a pointer extent from use."""
    wrapper=wrapper or 'numeric_'+root
    if not IDENTIFIER.fullmatch(root) or not IDENTIFIER.fullmatch(wrapper) or wrapper.startswith('osrec_') or root==wrapper:
        raise ValueError('root and adapter require distinct plain C names outside the reserved osrec_ prefix')
    functions=[n for n in children(tree) if n.get('kind')=='FunctionDecl' and n.get('name')==root and any(c.get('kind')=='CompoundStmt' for c in children(n))]
    if len(functions)!=1:raise ValueError('root needs exactly one configured C definition')
    function=functions[0];signature=type_of(function)
    if '...' in signature:raise ValueError('variadic roots are unsupported')
    result=signature.split(' (',1)[0];resolver=Analyzer(tree)
    def numeric(typ,node):
        resolved=resolver.numeric_element_type(typ,node.get('_translation_unit'))
        if resolved is None or not arithmetic_scalar(resolved):raise ValueError('requires a nonvolatile numeric C type: '+typ)
        return resolved.removeprefix('const ')
    result_storage=None if result=='void' else numeric(result,function)
    params=[n for n in children(function) if n.get('kind')=='ParmVarDecl']
    if len(params)>16:raise ValueError('adapter supports at most sixteen original parameters')
    fields=[]
    for parameter in params:
        name=parameter.get('name','');typ=type_of(parameter)
        if not IDENTIFIER.fullmatch(name) or not ordinary_parameter(parameter):
            raise ValueError('requires ordinary named parameter declarators; array bounds and hidden declarator effects are unsupported')
        pointer='*' in typ
        if pointer:
            if typ.count('*')!=1 or any(c in typ for c in '()[]'):raise ValueError('only pointers to one numeric scalar are supported')
            pointee,qualifiers=typ.split('*')
            if set(qualifiers.split())-{'const','restrict'}:raise ValueError('unsupported pointer-variable qualifiers')
            storage=numeric(pointee.strip(),parameter)
        else:storage=numeric(typ,parameter)
        fields.append(dict(parameter=name,original_type=typ,field='arg_'+name,storage_type=storage,pointer=pointer,elements=1 if pointer else None))
    if not any(f['pointer'] for f in fields):raise ValueError('adapter requires at least one numeric pointer parameter')
    tag=wrapper+'_state'
    if any(n.get('name') in (wrapper,tag) for n in walk(tree) if n.get('kind') in ('FunctionDecl','VarDecl','TypedefDecl','RecordDecl','EnumConstantDecl')):
        raise ValueError('generated adapter or carrier name collides with configured declarations')
    return dict(original_root=root,original_signature=signature,return_type=result,return_storage_type=result_storage,
        adapter_root=wrapper,carrier_type='struct '+tag,parameter='state',fields=fields,result_field='result' if result_storage else None,
        status_values=dict(success=0,null_carrier=1),pointer_payload_elements=1,
        domain='Caller-owned complete initialized carrier. Pointer payloads are distinct embedded one-element arrays; no null pointer payloads, overlapping payloads, or arbitrary extents are represented.',
        original_root_abi_changed=False,original_function_body_changed=False,counted_as_original_kernel_root=False)


def render(description):
    lines=['/* Generated numeric entry carrier. Original pointer ABI is unchanged. */','#ifndef '+description['adapter_root'].upper()+'_MODEL_H','#define '+description['adapter_root'].upper()+'_MODEL_H',description['carrier_type']+' {']
    for f in description['fields']:lines.append('  '+f['storage_type']+' '+f['field']+('[1]' if f['pointer'] else '')+';')
    if description['result_field']:lines.append('  '+description['return_storage_type']+' '+description['result_field']+'[1];')
    lines+=['};','unsigned '+description['adapter_root']+'('+description['carrier_type']+' *state);','#endif']
    args=','.join('state->'+f['field'] for f in description['fields'])
    call=description['original_root']+'('+args+')'
    body='unsigned '+description['adapter_root']+'('+description['carrier_type']+' *state) {\n  if (!state) return 1;\n  '
    body+=('state->'+description['result_field']+'[0] = ' if description['result_field'] else '')+call+';\n  return 0;\n}\n'
    return '\n'.join(lines)+'\n',body


def prepare(database,source,root,out,index,wrapper=None,max_units=8,max_contexts=100,max_alias_paths=256):
    """Materialize an explicit caller interface and analyze it using existing models."""
    database=Path(database).resolve();source=Path(source).resolve();out=Path(out).resolve()
    tree,identity=load_ast(database,source)
    expected=index.source_evidence.get(str(source))
    if expected is None or identity!=expected:raise ValueError('adapter requires verified configured-source evidence')
    description=schema(tree,root,wrapper);model,body=render(description)
    out.mkdir(parents=True,exist_ok=False)
    header=out/'entry_model.h';header.write_text(model)
    adapter=out/'numeric_adapter.c';adapter.write_text('#include '+json.dumps(str(source))+'\n#include "entry_model.h"\n'+body)
    compiler,args,cwd=compiler_arguments(database,source)
    replacement=[str(adapter) if not a.startswith('-') and (Path(a) if Path(a).is_absolute() else cwd/a).resolve()==source else a for a in args]
    db=out/'compile_commands.json';entries=json.loads(database.read_text())
    write(db,[*entries,dict(directory=str(cwd),file=str(adapter),arguments=[compiler,*replacement])])
    # Check the generated record and actual C call after the original source's
    # macros/types have been applied. No prototype spelling is trusted alone.
    adapter_tree,adapter_identity=load_ast(db,adapter)
    originals=children(tree)
    if semantic_tree(children(adapter_tree)[:len(originals)])!=semantic_tree(originals):
        raise ValueError('including original source changed configured declarations or bodies')
    record=next((n for n in children(adapter_tree) if n.get('kind')=='RecordDecl' and n.get('name')==description['carrier_type'].removeprefix('struct ') and n.get('completeDefinition')),None)
    expected_fields={f['field']:f['storage_type']+('[1]' if f['pointer'] else '') for f in description['fields']}
    if description['result_field']:expected_fields[description['result_field']]=description['return_storage_type']+'[1]'
    if record is None or {n['name']:type_of(n) for n in children(record) if n.get('kind')=='FieldDecl'}!=expected_fields:
        raise ValueError('generated carrier fields differ after preprocessing')
    target=next((n for n in children(adapter_tree) if n.get('kind')=='FunctionDecl' and n.get('name')==description['adapter_root'] and any(c.get('kind')=='CompoundStmt' for c in children(n))),None)
    if target is None or type_of(target)!='unsigned int ('+description['carrier_type']+' *)':
        raise ValueError('generated adapter name or status ABI changed during preprocessing')
    if any(macro_location(n) for n in walk(target)):
        raise ValueError('macros changed the generated adapter')
    calls=[n for n in walk(target) if n.get('kind')=='CallExpr']
    refs=[n['referencedDecl'] for c in calls for n in walk(children(c)[0]) if n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('kind')=='FunctionDecl']
    if len(calls)!=1 or len(refs)!=1 or refs[0]['name']!=root or type_of(refs[0])!=description['original_signature']:
        raise ValueError('adapter call no longer identifies the original configured signature')
    policies={description['adapter_root']:{'state':dict(CONTRACT)}}
    write(out/'argument-policy.json',dict(format='osrec-entry-state-boundaries-v1',boundaries={},argument_objects=policies))
    result=discover(db,adapter,description['adapter_root'],index,max_units=max_units,max_contexts=max_contexts,
        analysis_options=dict(argument_objects=policies,max_alias_paths=max_alias_paths))
    captured=False;error=None
    try:
        hooks=capture_header([result['plan'],dict(effect_plan(result['plan']),root='effects_'+description['adapter_root'])])
        (out/'capture.h').write_text(hooks);captured=True
    except ValueError as failure:error=str(failure)
    result.update(format='osrec-numeric-entry-adapter-v1',adapter=description,original_source_identity=identity,
        generated_source_identity=adapter_identity,analysis_sources_sha256=analysis_sources(),adapter_tool_sha256=digest(Path(__file__).read_bytes()),
        snapshot_generation='generated' if captured else 'unsupported',snapshot_error=error,runtime_validated=False,
        original_compilation_database_sha256=digest(database.read_bytes()))
    write(out/'result.json',result)
    write(out/'plan.json',dict(format='osrec-entry-state-plan-v1',plans=[result['plan']]))
    write(out/'adapter-schema.json',description)
    if captured:
        check=out/'capture-check.c';check.write_text('#include "numeric_adapter.c"\n#include "capture.h"\n')
        command=[compiler,*[str(check) if a==str(adapter) else a for a in replacement],'-I'+str(Path(__file__).resolve().parents[1]/'include'),'-fsyntax-only']
        syntax=subprocess.run(command,cwd=cwd,capture_output=True,text=True,timeout=30)
        result['target_syntax_check']=dict(command=command,compile_directory=str(cwd),returncode=syntax.returncode,stderr=syntax.stderr)
        write(out/'result.json',result)
        if syntax.returncode:
            result.update(status='failed',capture_schema_accepted=False,snapshot_generation='failed',snapshot_error=syntax.stderr)
            (out/'capture.h').unlink();write(out/'result.json',result)
            raise ValueError('generated capture header failed configured syntax check: '+syntax.stderr)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--survey',type=Path,required=True);parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--root',required=True);parser.add_argument('--wrapper');parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--max-translation-units',type=int,default=8);parser.add_argument('--max-contexts',type=int,default=100)
    parser.add_argument('--max-alias-paths',type=int,default=256);args=parser.parse_args()
    if min(args.max_translation_units,args.max_contexts,args.max_alias_paths)<1:parser.error('limits must be positive')
    survey=args.survey.resolve();db=survey/'compile_commands.json';index=DefinitionIndex.from_survey(survey,db)
    r=prepare(db,args.source,args.root,args.out,index,args.wrapper,args.max_translation_units,args.max_contexts,args.max_alias_paths)
    print(json.dumps(dict(status=r['status'],original_root=args.root,adapter_root=r['adapter']['adapter_root'],snapshot_generation=r['snapshot_generation'],out=str(args.out.resolve())),indent=2))
if __name__=='__main__':main()
