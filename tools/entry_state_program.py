"""Link configured C ASTs into a conservative direct-call analysis program.

Only compilation-database sources are available. Missing definitions remain
blockers; no linker, scheduler, or whole-program alias proof is implied.
"""
import copy
from collections import defaultdict
import json
import re
from pathlib import Path
from entry_state import children,walk,type_of,load_ast


def function_reference_closure(declarations,roots,qualified_name=None,reference_key=None,reference_cache=None,reference_cache_key=None):
    """Retain every syntactically referenced function, including address uses."""
    # Before cloning, names and declaration IDs still belong to their original
    # translation units. These projections apply the same namespace as clone,
    # without copying bodies that the resulting closure will discard.
    name_of=qualified_name or (lambda owner,ref:ref['name'])
    key_of=reference_key or (lambda owner,ref:ref['id'])
    functions=defaultdict(list);globals_by_name=defaultdict(list);global_ids=set()
    for node in declarations:
        if node.get('kind')=='FunctionDecl':functions[name_of(node,node)].append(node)
        elif node.get('kind')=='VarDecl':
            globals_by_name[name_of(node,node)].append(node);global_ids.add(key_of(node,node))
    pending=[('function',name) for name in roots];seen=set();names=set()
    while pending:
        kind,name=pending.pop()
        if (kind,name) in seen:continue
        seen.add((kind,name))
        if kind=='function':names.add(name)
        for node in (functions if kind=='function' else globals_by_name).get(name,[]):
            key=reference_cache_key(node) if reference_cache_key else key_of(node,node)
            refs=reference_cache.get(key) if reference_cache is not None else None
            if refs is None:
                refs=[]
                for term in walk(node):
                    ref=term.get('referencedDecl',{})
                    if ref.get('kind')=='FunctionDecl':refs.append(('function',name_of(node,ref)))
                    elif ref.get('kind')=='VarDecl' and key_of(node,ref) in global_ids:
                        refs.append(('global',name_of(node,ref)))
                if reference_cache is not None:reference_cache[key]=tuple(refs)
            pending.extend(refs)
    return names


def canonical_type(text,unit,typedefs):
    """A type spelled with its unit's typedef names expanded. Clang prints C's `_Bool` as `bool` or `_Bool`
    depending on per-unit printing state, so `bool` that no typedef names is `_Bool`."""
    names={'bool':'_Bool',**typedefs.get(unit,{})}
    for _ in range(8):
        expanded=re.sub(r'(?<!struct )(?<!union )(?<!enum )\b[A-Za-z_]\w*\b',lambda m:names.get(m.group(),m.group()),text)
        if expanded==text:break
        text=expanded
    return re.sub(r'\s+',' ',text).strip()

def merge_translation_units(units,roots=None,syntax_cache=None):
    # A discovery owns immutable parsed units for its lifetime. Reuse only
    # namespaced syntax, never layouts/check results, aliases or root plans.
    declarations=[];signatures={};definitions={};records={};typedefs=defaultdict(dict)
    scopes={};configured=[];origins={}
    for index,(original,identity) in enumerate(units):
        source=identity['source'];prefix=f'tu{index}:'
        local_functions={n['name'] for n in children(original) if n.get('kind')=='FunctionDecl' and (n.get('storageClass')=='static' or n.get('inline'))}
        local_globals={n['name'] for n in children(original) if n.get('kind')=='VarDecl' and n.get('storageClass')=='static'}
        scope=(prefix,local_functions,local_globals)
        configured.append((original,identity,scope))
    def name_in_scope(scope,ref):
        prefix,local_functions,local_globals=scope
        kind=ref.get('kind');name=ref['name']
        return prefix+name if (kind=='FunctionDecl' and name in local_functions or kind=='VarDecl' and name in local_globals) else name
    def qualified_name(owner,ref):return name_in_scope(scopes[id(owner)],ref)
    def reference_key(owner,ref):return scopes[id(owner)][0],ref['id']
    names=None;slicing=None
    if roots is not None:
        # Shallow declaration views distinguish unit occurrences even if a
        # caller reuses the same parsed tree. Nested bodies remain immutable
        # shared input here; only retained declarations are deeply cloned.
        original_declarations=[]
        for original,_,scope in configured:
            for node in children(original):
                view=dict(node);scopes[id(view)]=scope;origins[id(view)]=node;original_declarations.append(view)
        references=syntax_cache.setdefault('references',{}) if syntax_cache is not None else None
        names=function_reference_closure(original_declarations,roots,qualified_name,reference_key,references,
            lambda owner:(id(origins[id(owner)]),reference_key(owner,owner)))
        before=sum(n.get('kind')=='FunctionDecl' for n in original_declarations)
    for original,identity,scope in configured:
        prefix,local_functions,local_globals=scope
        source=identity['source']
        if syntax_cache is None:memo={}
        else:
            key=(id(original),source,prefix)
            entry=syntax_cache.setdefault('units',{}).setdefault(key,{'tree':original,'memo':{}})
            memo=entry['memo']
        def clone(value):
            if isinstance(value,dict):
                key_id=id(value)
                if key_id in memo:return memo[key_id]
                result={};memo[key_id]=result
                kind=value.get('kind');name=value.get('name')
                for key,item in value.items():
                    if key=='name' and ((kind=='FunctionDecl' and name in local_functions) or (kind=='VarDecl' and name in local_globals)):
                        result[key]=prefix+item
                    elif key in ('id','previousDecl','referencedMemberDecl','typeAliasDeclId','declId','targetLabelDeclId') and isinstance(item,str) and item.startswith('0x'):
                        result[key]=prefix+item
                    else:result[key]=clone(item)
                if kind:result['_translation_unit']=source
                return result
            if isinstance(value,list):
                key_id=id(value)
                if key_id in memo:return memo[key_id]
                result=[];memo[key_id]=result
                result.extend(clone(item) for item in value)
                return result
            # Configured Clang JSON contains only dict/list/scalar values.
            # Other Python objects are outside this experimental contract.
            if value is None or isinstance(value,(str,int,float,bool)):return value
            raise TypeError('merge prototype requires JSON AST values')
        for node in children(original):
            if names is not None and node.get('kind')=='FunctionDecl' and name_in_scope(scope,node) not in names:continue
            declarations.append(clone(node))
    if roots is not None:
        slicing={'kind':'syntactic_function_and_global_reference_closure','roots':list(roots),
                 'retained_function_names':sorted(names),
                 'removed_function_declarations':before-sum(n.get('kind')=='FunctionDecl' for n in declarations),
                 'record_checks':'all configured records retained'}
    for node in declarations:
        kind=node.get('kind');name=node.get('name')
        if kind=='RecordDecl' and name and node.get('completeDefinition'):
            layout=(node.get('tagUsed'),tuple((c.get('name'),type_of(c),c.get('isBitfield',False),
                tuple(n.get('value') for n in walk(c) if n.get('kind')=='ConstantExpr'))
                for c in children(node) if c.get('kind')=='FieldDecl'))
            if name in records and records[name]!=layout:
                raise ValueError('incompatible configured record definitions: '+name)
            records[name]=layout
        if kind=='TypedefDecl' and name:typedefs[node.get('_translation_unit')][name]=type_of(node)
        if kind=='FunctionDecl':
            signature=type_of(node),node.get('_translation_unit')
            if name in signatures and signatures[name][0]!=signature[0] and canonical_type(*signatures[name],typedefs)!=canonical_type(*signature,typedefs):
                raise ValueError('incompatible configured function declarations: '+name)
            signatures.setdefault(name,signature)
            if any(c.get('kind')=='CompoundStmt' for c in children(node)):
                if name in definitions:
                    # A second external body is ambiguous. Static header
                    # functions have distinct TU names and do not collide.
                    raise ValueError('multiple configured function definitions: '+name)
                definitions[name]=node['_translation_unit']
    return {'kind':'TranslationUnitDecl','inner':declarations}, {
        'translation_units':len(units),'defined_functions':len(definitions),
        'resolution':'direct C calls by external linkage name; static and inline functions isolated per translation unit',
        'source_identities':[identity for _,identity in units],**({'function_slice':slicing} if slicing is not None else {})}


def load_program(database,source,clang=None,closure_sources=(),all_sources=False,max_units=100):
    source=source.resolve();sources=[source]
    if all_sources:
        for entry in json.loads(database.read_text()):
            path=Path(entry['file'])
            if not path.is_absolute():path=Path(entry['directory'])/path
            sources.append(path.resolve())
    else:sources.extend(path.resolve() for path in closure_sources)
    sources=list(dict.fromkeys(sources))
    if len(sources)>max_units:raise ValueError('translation-unit limit exceeded; select closure sources or increase --max-translation-units')
    units=[load_ast(database,path,clang) for path in sources]
    # Check the requested architecture before combining object paths.
    def target(identity):
        args=identity['compile_arguments']
        return next((a for a in args if a.startswith('--target=')),
            next((args[i+1] for i,a in enumerate(args[:-1]) if a in ('-target','--target')), 'compiler-default'))
    if len({target(identity) for _,identity in units})!=1:
        raise ValueError('translation units use different compiler targets')
    return merge_translation_units(units)
