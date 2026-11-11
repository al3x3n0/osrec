"""Clang-AST state ownership and direct-call context threading for bounded C closures.

The transformation keeps kernel/provider bodies, relocates mutable file-scope
objects and supported function-local statics into caller-owned state, and adds
explicit context parameters. Function pointers, TLS, volatile state and unsupported declarations
are rejected rather than silently sharing state.
"""
import hashlib,json,re,subprocess
from pathlib import Path,PurePosixPath

def owned_paths(directory,names):
    """Keep prepared source identities relative, unambiguous and inside their root."""
    directory=Path(directory).resolve();paths=[]
    for name in names:
        if not isinstance(name,str) or not name or any(c in name for c in ('\\','"','\n','\r')):raise ValueError('invalid prepared source path')
        relative=PurePosixPath(name);path=directory/name
        if relative.is_absolute() or '..' in relative.parts or str(relative)!=name or name=='.':raise ValueError('prepared source path must be normalized and relative: '+name)
        if path.resolve()!=path or not path.is_file():raise ValueError('prepared source must be an owned regular file: '+name)
        if path in paths:raise ValueError('duplicate prepared source path: '+name)
        paths.append(path)
    return paths

def walk(node):
    if node.get('kind'):yield node
    # Clang places sparse/designated array elements in array_filler rather
    # than inner. They can contain state references and calls too.
    for key in ('inner','array_filler'):
        for child in node.get(key,[]):yield from walk(child)

def point(loc,default):
    loc=loc.get('spellingLoc',loc)
    return Path(loc.get('file',default)).resolve(),loc.get('offset'),loc.get('tokLen',0)

def source_point(loc,default):
    return point(loc.get('expansionLoc',loc),default)

def source_end(text,start,separators):
    """Find a byte offset, keeping complete constant macro invocations."""
    stack=[];pairs={b')':b'(',b']':b'[',b'}':b'{'};separators=separators.encode('ascii')
    tokens=re.finditer(rb'"(?:\\[\s\S]|[^"\\])*"|\'(?:\\[\s\S]|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\r\n]*|[()\[\]{},;]',text[start:])
    for token in tokens:
        value=token.group()
        if len(value)!=1:continue
        if value in b'([{':stack.append(value)
        elif value in pairs:
            if not stack or stack.pop()!=pairs[value]:raise ValueError('unbalanced state declaration spelling')
        elif not stack and value in separators:return start+token.start()
    raise ValueError('state declaration delimiter missing')

def field(typ,name):
    if '[' in typ:
        base,extent=typ.split('[',1);return base.strip()+' '+name+'['+extent
    if '(' in typ:raise ValueError('function/vector declarator requires a reviewed context adapter')
    return typ+' '+name

def transform(directory,sources,headers,clang,context='osrec_kernel_context',include_dirs=(),prefix='osrec_kernel_'):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*',prefix):raise ValueError('invalid kernel symbol prefix')
    if not sources or not headers or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*',context):raise ValueError('context sources, model header and identifier are required')
    directory=Path(directory).resolve();paths=owned_paths(directory,(*sources,*headers))
    # Clang offsets/tokLen count original bytes, including UTF-8 and CRLF.
    # Decode only complete expressions or regex input; every edit stays in
    # byte coordinates, and provenance hashes the exact supplied bytes.
    texts={p:p.read_bytes() for p in paths};decoded_texts={p:t.decode('utf-8') for p,t in texts.items()};asts={};functions={};globals_by_name={};global_ids={};edits={p:{} for p in paths};file_definitions=[];function_definitions=[];readonly_definitions=[];macro_names=set()
    source_indices={directory/n:i for i,n in enumerate(sources)}
    def edit(p,start,end,value):
        if p not in texts or start is None or not 0<=start<=end<=len(texts[p]):raise ValueError('AST edit outside owned source: %s at %r inserting %r'%(getattr(p,'name',p),start,value[:80]))
        key=(start,end);value=value.encode('utf-8')
        if key in edits[p] and edits[p][key]!=value:raise ValueError('conflicting AST edits')
        edits[p][key]=value
    for name in sources:
        path=directory/name
        base=[str(clang),'--target=aarch64-none-elf','-std=c11','-ffreestanding','-fno-builtin','-I'+str(directory),*['-I'+str(p) for p in include_dirs]]
        command=[*base,'-Xclang','-ast-dump=json','-fsyntax-only',str(path)]
        result=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',timeout=60)
        if result.returncode:raise ValueError('context analysis compilation failed: '+result.stderr)
        preprocessed=subprocess.run([*base,'-dD','-E',str(path)],capture_output=True,text=True,encoding='utf-8',timeout=60)
        if preprocessed.returncode:raise ValueError('context macro analysis failed: '+preprocessed.stderr)
        macro_names.update(re.findall(r'(?m)^#define[ \t]+([^\W\d]\w*)',preprocessed.stdout))
        ast=json.loads(result.stdout);asts[path]=ast;global_ids[path]={}
        for node in ast.get('inner',[]):
            if node.get('loc',{}).get('includedFrom'):continue
            p,offset,_=point(node.get('loc',{}),path)
            if p!=path or offset is None:continue
            if node['kind']=='FunctionDecl' and any(n['kind']=='CompoundStmt' for n in node.get('inner',[])):
                function_definitions.append((path,node))
            if node['kind']=='VarDecl':
                # A declaration without storage in this closure is not an
                # owned definition. It can resolve to another supplied TU
                # during the join below; otherwise mutable use must reject.
                if node.get('storageClass')=='extern' and not node.get('init'):continue
                typ=node['type']['qualType']
                if 'const ' in typ and '*' not in typ:
                    readonly_definitions.append((path,node,None));continue
                if 'volatile' in typ or node.get('tls'):raise ValueError('volatile/TLS state needs an explicit adapter')
                file_definitions.append((path,node))
    # Static storage is private to its translation unit. Qualify colliding
    # private spellings, while keeping public fields and unique names stable.
    definitions_by_name={};file_bindings={};public_bindings={};private_state=[]
    for path,node in file_definitions:definitions_by_name.setdefault(node['name'],[]).append((path,node))
    reserved=set(definitions_by_name)
    for path,node in file_definitions:
        name=node['name'];definitions=definitions_by_name[name]
        if (path,name) in file_bindings or sum(n.get('storageClass')!='static' for _,n in definitions)>1:raise ValueError('ambiguous file-scope object: '+name)
        key=name
        if node.get('storageClass')=='static' and len(definitions)>1:
            key='osrec_private_'+str(source_indices[path])+'_'+name
            if key in reserved or key in globals_by_name:raise ValueError('generated private-state field conflicts with owned state')
            private_state.append(dict(name=key,source=path.relative_to(directory).as_posix(),declaration=name,type=node['type']['qualType']))
        globals_by_name[key]=(path,node);file_bindings[path,name]=key;global_ids[path][node['id']]=key
        if node.get('storageClass')!='static':public_bindings[name]=key
    # Functions need the same TU-local identity as objects. Dependency keys
    # distinguish private helpers before propagating context requirements.
    function_declarations={path:[n for n in walk(ast) if n['kind']=='FunctionDecl'] for path,ast in asts.items()}
    function_names={n['name'] for nodes in function_declarations.values() for n in nodes}
    function_definitions_by_name={};function_bindings={};public_functions={};private_functions=[];function_ids={path:{} for path in asts}
    for path,node in function_definitions:function_definitions_by_name.setdefault(node['name'],[]).append((path,node))
    for path,node in function_definitions:
        name=node['name'];definitions=function_definitions_by_name[name]
        if (path,name) in function_bindings or sum(n.get('storageClass')!='static' for _,n in definitions)>1:raise ValueError('duplicate public/owned function definition: '+name)
        key=name
        if node.get('storageClass')=='static' and len(definitions)>1:
            key='osrec_private_'+str(source_indices[path])+'_'+name
            if key in function_names or key in functions:raise ValueError('generated private-function key conflicts with supplied function')
            private_functions.append(dict(name=key,source=path.relative_to(directory).as_posix(),declaration=name,symbol=prefix+key))
        functions[key]=(path,node);function_bindings[path,name]=key
        if node.get('storageClass')!='static':public_functions[name]=key
    for path,nodes in function_declarations.items():
        for node in nodes:
            name=node['name'];key=function_bindings.get((path,name))
            if key is None and node.get('storageClass')!='static':key=public_functions.get(name)
            if key is not None:function_ids[path][node['id']]=key
            elif name in function_definitions_by_name:raise ValueError('external function declaration cannot bind to private function: '+name)
    def function_key(path,ref):return function_ids[path].get(ref.get('id')) if ref.get('kind')=='FunctionDecl' else None
    # Local statics have storage duration identical to file-scope state, but
    # their declaration identity (rather than spelling) determines ownership.
    # Keep generated fields distinct even for shadowed names in one function.
    local_state=[];local_owners={};block_ids={};block_types={};local_enum_scopes={}
    for name,(path,fn) in functions.items():
        parts=list(walk(fn));block_ids[name]={n['id'] for n in parts if n.get('id') and n['kind'].endswith('Decl')}
        local_types={n['id'] for n in parts if n['kind']=='TypedefDecl'}
        local_type_names={n['name'] for n in parts if n['kind']=='TypedefDecl'}
        local_tags={n.get('name') for n in parts if n['kind'] in ('RecordDecl','EnumDecl') and n.get('name')}
        block_types[name]=(local_types,local_type_names,local_tags)
        def enum_scopes(node,scopes):
            scoped=node.get('kind') in ('CompoundStmt','ForStmt')
            if scoped:scopes.append([])
            if node.get('kind')=='EnumDecl' and scopes and any(n.get('kind')=='EnumConstantDecl' for n in node.get('inner',[])):scopes[-1].append(node)
            if node.get('kind')=='VarDecl' and node.get('storageClass')=='static':local_enum_scopes[path,node['id']]=tuple(tuple(scope) for scope in scopes)
            for child in node.get('inner',[]):enum_scopes(child,scopes)
            if scoped:scopes.pop()
        enum_scopes(fn,[])
        for node in parts:
            if node['kind']!='VarDecl':continue
            if node.get('tls'):raise ValueError('function-local TLS state needs an explicit adapter')
            if node.get('storageClass')!='static':continue
            typ=node['type']['qualType']
            if 'volatile' in typ:raise ValueError('volatile state needs an explicit adapter')
            if 'const' in typ and '*' not in typ:
                readonly_definitions.append((path,node,name));continue
            if any(part['kind'].endswith('Attr') for part in node.get('inner',[])):raise ValueError('function-local state attributes need an explicit adapter')
            if node['type'].get('typeAliasDeclId') in local_types or any(re.search(r'\b'+re.escape(alias)+r'\b',typ) for alias in local_type_names) or any(re.search(r'\b(?:struct|union|enum)\s+'+re.escape(tag)+r'\b',typ) for tag in local_tags):raise ValueError('function-local state type must be available outside its function')
            key='osrec_local_'+name+'_'+node['name']+'_'+str(len([s for s in local_state if s['function']==name]))
            if key in globals_by_name:raise ValueError('generated local-state field conflicts with owned state')
            globals_by_name[key]=(path,node);global_ids[path][node['id']]=key;local_owners[key]=name
            local_state.append(dict(name=key,source=path.relative_to(directory).as_posix(),function=name,declaration=node['name'],type=typ))
    # A local readonly object used by a restoration seed must have the same
    # lifetime and identity in the function and the source-local helper. Lift
    # that declaration (and its readonly local dependencies), using AST IDs so
    # shadowed names remain distinct. Unreferenced constants stay in place.
    local_readonly={(path,node['id']):(node,function) for path,node,function in readonly_definitions if function is not None}
    def local_seed_scope(path,init,function):
        local_types,aliases,tags=block_types[function]
        _,fn=functions[function];_,start,_=point(fn['range']['begin'],path)
        for part in walk(init):
            for info in (part.get('type',{}),part.get('argType',{})):
                typ=info.get('qualType','')
                if info.get('typeAliasDeclId') in local_types or any(re.search(r'\b'+re.escape(alias)+r'\b',typ) for alias in aliases) or any(re.search(r'\b(?:struct|union|enum)\s+'+re.escape(tag)+r'\b',typ) for tag in tags):raise ValueError('local-state initializer type must be available outside its function')
            for loc in part.get('range',{}).values():
                if 'spellingLoc' not in loc or loc.get('expansionLoc',{}).get('isMacroArgExpansion'):continue
                p,offset,_=point(loc,path)
                if p==path and offset is not None and offset>=start:raise ValueError('local-state initializer macro must be defined before its function')
    lifted={};pending=[]
    for name,(path,node) in globals_by_name.items():
        if name in local_owners and node.get('init'):
            local_seed_scope(path,node['inner'][-1],local_owners[name])
            pending.extend((path,part.get('referencedDecl',{}).get('id')) for part in walk(node['inner'][-1]) if part['kind']=='DeclRefExpr')
    while pending:
        key=pending.pop()
        if key not in local_readonly or key in lifted:continue
        path,identity=key;node,function=local_readonly[key];typ=node['type']['qualType']
        if node.get('tls') or 'volatile' in typ or any(part['kind'].endswith('Attr') for part in node.get('inner',[])):raise ValueError('lifted local readonly attributes/TLS/volatile need an explicit adapter')
        local_types,local_type_names,local_tags=block_types[function]
        if node['type'].get('typeAliasDeclId') in local_types or any(re.search(r'\b'+re.escape(alias)+r'\b',typ) for alias in local_type_names) or any(re.search(r'\b(?:struct|union|enum)\s+'+re.escape(tag)+r'\b',typ) for tag in local_tags):raise ValueError('lifted local readonly type must be available outside its function')
        field(typ,node['name'])
        lifted[key]=(node,function)
        if not node.get('init'):continue
        local_seed_scope(path,node['inner'][-1],function)
        for part in walk(node['inner'][-1]):
            ref=part.get('referencedDecl',{});ref_key=(path,ref.get('id'))
            if part['kind']=='CompoundLiteralExpr' or ref.get('kind')=='FunctionDecl':raise ValueError('lifted local readonly initializer needs an explicit object/callback adapter')
            if part['kind']!='DeclRefExpr':continue
            if ref.get('id') in global_ids[path]:raise ValueError('local readonly initializer refers to context-owned state')
            if ref_key in local_readonly:pending.append(ref_key)
            elif ref.get('id') in block_ids[function]:raise ValueError('local readonly initializer depends on function-local declarations')
            elif ref.get('kind')=='VarDecl' and ('*' in ref['type']['qualType'] or 'const' not in ref['type']['qualType']):raise ValueError('local readonly initializer refers to state outside the supplied closure')
    lifted_symbols={};lifted_constants=[]
    ordered_lifted=sorted(lifted.items(),key=lambda item:(source_indices[item[0][0]],source_point(item[1][0]['loc'],item[0][0])[1]))
    reserved_declarations={n.get('name') for ast in asts.values() for n in walk(ast) if n['kind'].endswith('Decl')}
    for key,(node,function) in ordered_lifted:
        path,identity=key;symbol=prefix+'local_constant_'+function+'_'+node['name']+'_'+str(len(lifted_constants))
        if symbol in reserved_declarations or symbol in {prefix+n for n in functions} or any(re.search(r'\b'+re.escape(symbol)+r'\b',text) for text in decoded_texts.values()):raise ValueError('lifted local readonly symbol conflicts with supplied source')
        lifted_symbols[key]=symbol
        lifted_constants.append(dict(declaration=node['name'],source=path.relative_to(directory).as_posix(),function=function,type=node['type']['qualType'],symbol=symbol,offset=source_point(node['loc'],path)[1]))
    readonly_bindings={}
    if lifted_symbols:
        for source,ast in asts.items():
            for node in walk(ast):
                if node['kind']=='DeclRefExpr':
                    p,start,size=point(node['range']['begin'],source)
                    readonly_bindings.setdefault((p,start,size),set()).add((source,node.get('referencedDecl',{}).get('id')))
    for function,(path,fn) in functions.items():
        for node in walk(fn):
            identity=(path,node.get('referencedDecl',{}).get('id'));symbol=lifted_symbols.get(identity)
            if node['kind']=='DeclRefExpr' and symbol:
                p,start,size=point(node['range']['begin'],path)
                if readonly_bindings[p,start,size]!={identity}:raise ValueError('readonly reference spelling binds to multiple declarations')
                edit(p,start,start+size,symbol)
    dependencies={name:set() for name in functions};needs=set(local_owners.values());owned_refs=[];calls=[]
    for name,(path,fn) in functions.items():
        for node in walk(fn):
            if node['kind']=='DeclRefExpr':
                ref=node.get('referencedDecl',{})
                if ref.get('id') in global_ids[path]:needs.add(name);owned_refs.append((path,node,global_ids[path][ref['id']],name))
            if node['kind']=='CallExpr':
                refs=[n.get('referencedDecl',{}) for n in walk(node['inner'][0]) if n['kind']=='DeclRefExpr']
                if len(refs)!=1 or refs[0].get('kind')!='FunctionDecl':raise ValueError('indirect/ambiguous calls need an explicit adapter')
                callee=function_key(path,refs[0]) or refs[0]['name'];dependencies[name].add(callee);calls.append((path,node,callee,name))
    # Join declarations to their own private definition or a public definition.
    # Block-scope extern declarations retain that same C linkage contract.
    top_variables={path:{n['id']:n for n in ast.get('inner',[]) if n.get('kind')=='VarDecl'} for path,ast in asts.items()}
    for path,fn in functions.values():
        for node in walk(fn):
            if node['kind']=='VarDecl' and node.get('storageClass')=='extern':top_variables[path][node['id']]=node
    for path,ast in asts.items():
        for node in top_variables[path].values():
            typ=node['type']['qualType']
            if 'const' in typ and '*' not in typ and (node.get('storageClass')!='extern' or node.get('init')):continue
            name=node.get('name');key=file_bindings.get((path,name),public_bindings.get(name))
            if key is not None:
                typ=node['type'];definition=globals_by_name[key][1]['type']
                actual=typ.get('desugaredQualType',typ['qualType']);expected=definition.get('desugaredQualType',definition['qualType'])
                if '[]' in actual:expected=re.sub(r'\[[0-9]+\]','[]',expected,count=1)
                if actual!=expected:raise ValueError('incompatible owned-state declaration: '+name)
                global_ids[path][node['id']]=key
            elif name in definitions_by_name:raise ValueError('external declaration cannot bind to private state: '+name)
    for name,(path,fn) in functions.items():
        for node in walk(fn):
            ref=node.get('referencedDecl',{});decl=top_variables[path].get(ref.get('id'))
            if node['kind']=='DeclRefExpr' and decl and ref['id'] not in global_ids[path]:
                typ=decl['type']['qualType']
                if '*' in typ or 'const' not in typ:raise ValueError('mutable external/header state is outside the supplied closure: '+ref['name'])
    # Recollect references after joining the translation units.
    owned_refs=[]
    for name,(path,fn) in functions.items():
        for node in walk(fn):
            ref=node.get('referencedDecl',{})
            if node['kind']=='DeclRefExpr' and ref.get('id') in global_ids[path]:
                needs.add(name);owned_refs.append((path,node,global_ids[path][ref['id']],name))
    while True:
        extra={name for name,callees in dependencies.items() if callees&needs}
        if extra<=needs:break
        needs|=extra
    # Generated parameters must not capture existing locals, constants or
    # macro names. Declaration/reference identities still select state edits.
    context_names={}
    for name,(path,fn) in functions.items():
        if name not in needs:continue
        reserved=macro_names|{n.get('name') for n in walk(fn) if n['kind'].endswith('Decl')}|{n.get('referencedDecl',{}).get('name') for n in walk(fn) if n['kind']=='DeclRefExpr'}
        reserved|={p.get('name') for source,nodes in function_declarations.items() for declaration in nodes if function_ids[source].get(declaration.get('id'))==name for p in declaration.get('inner',[]) if p['kind']=='ParmVarDecl'}
        parameter='ctx'
        while parameter in reserved:parameter+='_'
        context_names[name]=parameter
    symbols={n:prefix+n for n in functions}
    for name,(path,fn) in functions.items():
        for node in walk(fn):
            ref=node.get('referencedDecl',{})
            key=function_key(path,ref)
            if node['kind']=='DeclRefExpr' and key in symbols:
                p,start,size=point(node['range']['begin'],path);edit(p,start,start+size,symbols[key])
    # A file-scope readonly initializer may name a function that takes no context (a callback the slice
    # stores but never calls through); it is renamed like a call. One that needs the context cannot escape.
    for path,ast in asts.items():
        for declaration in ast.get('inner',[]):
            if declaration['kind']!='VarDecl' or not declaration.get('init') or not re.match(r'const\b',declaration['type']['qualType']):continue
            for node in walk(declaration['inner'][-1]):
                key=function_key(path,node.get('referencedDecl',{}))
                if node['kind']!='DeclRefExpr' or key is None:continue
                if key in needs:raise ValueError('context function address escapes through a readonly initializer')
                p,start,size=point(node['range']['begin'],path)
                if p==path:edit(p,start,start+size,symbols[key])
    direct_refs=set()
    for path,node,callee,caller in calls:
        if callee in needs:
            for ref in walk(node['inner'][0]):
                if ref['kind']=='DeclRefExpr':direct_refs.add((path,ref.get('id')))
    for name,(path,fn) in functions.items():
        for node in walk(fn):
            ref=node.get('referencedDecl',{})
            if node['kind']=='DeclRefExpr' and function_key(path,ref) in needs and (path,node.get('id')) not in direct_refs:raise ValueError('context function address escapes through a function pointer')
    for path,node,name,owner in owned_refs:
        p,start,size=point(node['range']['begin'],path);edit(p,start,start+size,context_names[owner]+'->'+name)
    for path,node,callee,caller in calls:
        if callee not in needs:continue
        # Use the callee token's spelling location, including calls in macro definitions.
        refs=[n for n in walk(node['inner'][0]) if n['kind']=='DeclRefExpr']
        p,start,size=point(refs[0]['range']['end'],path);position=texts[p].find(b'(',start+size)
        if position<0:raise ValueError('call opening parenthesis missing')
        following=texts[p][position+1:].lstrip();arg=context_names[caller]+('' if following.startswith(b')') else ', ')
        edit(p,position+1,position+1,arg)
    # AST declarations in headers inherit their file location from the preceding top-level declaration.
    seen={}
    def function_declaration(source,node,current):
        key=function_ids[source].get(node.get('id'))
        if key is None:return
        p,start,size=point(node.get('loc',{}),current)
        if any(n['kind']=='CompoundStmt' for n in node.get('inner',[])):p=source
        if p not in texts:raise ValueError('context function declaration outside owned headers')
        location=(p,start)
        if location in seen:
            if seen[location]!=key:raise ValueError('shared declaration spelling binds to different private functions')
            return
        seen[location]=key;edit(p,start,start+size,symbols[key])
        if key not in needs:return
        position=texts[p].find(b'(',start+size);end=texts[p].find(b')',position)
        if position<0 or end<0:raise ValueError('function declaration parameter range missing')
        empty=texts[p][position+1:end].strip() in (b'',b'void')
        edit(p,position+1,end if empty else position+1,'struct '+context+' *'+context_names[key]+('' if empty else ', '))
    for source,ast in asts.items():
        current=source
        for node in ast.get('inner',[]):
            loc=node.get('loc',{});raw=loc.get('spellingLoc',loc)
            lexical=loc.get('expansionLoc',raw)
            if lexical.get('file'):current=Path(lexical['file']).resolve()
            if node['kind']=='FunctionDecl':function_declaration(source,node,current)
        for path,fn in functions.values():
            if path!=source:continue
            for node in walk(fn):
                if node['kind']=='FunctionDecl' and node is not fn:function_declaration(source,node,source)
    restore_parameter='ctx'
    while restore_parameter in macro_names:restore_parameter+='_'
    restore_index='osrec_i'
    while restore_index in macro_names or restore_index==restore_parameter:restore_index+='_'
    declarations=[];initializers=[];groups={};group_nodes={};declaration_helpers={};array_initializers=[];value_initializers=[];local_helpers={};state_initializers=[];initializer_enums=[]
    integer_types={'_Bool','char','signed char','unsigned char','short','unsigned short','int','unsigned int','long','unsigned long','long long','unsigned long long'}
    def enum_snapshot(path,node):
        if node.get('fixedUnderlyingType') or any(n['kind'].endswith('Attr') for n in walk(node)):raise ValueError('local enum attributes/fixed underlying types require preparation')
        p,offset,_=source_point(node['range']['begin'],path)
        if p!=path or offset is None:raise ValueError('local enum declaration must be inside its owned source')
        values=[];declarations=[]
        for entry in node.get('inner',[]):
            if entry['kind']!='EnumConstantDecl':continue
            item=dict(declaration=entry['name'],type=entry['type']['qualType'],implicit=not bool(entry.get('inner')))
            declaration=entry['name']
            if entry.get('inner'):
                evaluated=next((n for n in walk(entry['inner'][0]) if n['kind']=='ConstantExpr' and 'value' in n),None)
                if evaluated is None:raise ValueError('local enum initializer lacks a target-evaluated integer')
                typ=evaluated['type'].get('desugaredQualType',evaluated['type']['qualType']);value=int(evaluated['value'])
                if typ not in integer_types or not -(1<<63)<=value<(1<<64):raise ValueError('local enum initializer exceeds the supported integer domain')
                literal=str(value)+'ULL' if value>=0 else '(-9223372036854775807LL-1LL)' if value==-(1<<63) else '('+str(value)+'LL)'
                declaration+=' = (('+typ+')'+literal+')';item.update(initializer_type=typ,initializer_value=str(value))
            declarations.append(declaration);values.append(item)
        body='enum '+(node['name']+' ' if node.get('name') else '')+'{'+', '.join(declarations)+'};'
        return body,dict(source=path.relative_to(directory).as_posix(),offset=offset,tag=node.get('name'),values=values)
    for name,(path,node) in globals_by_name.items():
        typ=node['type']['qualType'];declarations.append('    '+field(typ,name)+';')
        p,start,_=source_point(node['range']['begin'],path)
        if p!=path or start is None:raise ValueError('state declaration spelling must be inside owned source')
        groups[p,start]=source_end(texts[p],start,';')
        group_nodes.setdefault((p,start),[]).append(node)
        if node.get('init'):
            init=node['inner'][-1];begin,a,_=source_point(init['range']['begin'],path)
            if any(part['kind']=='CompoundLiteralExpr' for part in walk(init)):raise ValueError('anonymous objects in state initializers need an explicit adapter')
            if begin!=path or a is None or not 0<=a<len(texts[path]):raise ValueError('initializer spelling must be inside its owned source: '+name)
            end=source_end(texts[path],a,',;');expression=texts[path][a:end];original_expression=expression;local={};enum_scopes=[];enum_ids=set();enum_names=set()
            if name in local_owners:
                available=local_enum_scopes.get((path,node['id']),())
                candidates={entry['id'] for scope in available for group in scope for entry in group.get('inner',[]) if entry['kind']=='EnumConstantDecl'}
                # Semantic ASTs omit array designator expressions. Recreate
                # visible enums for such seeds, including designator macros.
                refs={n.get('referencedDecl',{}).get('id') for n in walk(init) if n['kind']=='DeclRefExpr'}
                arrays=any(n['kind']=='InitListExpr' and '[' in n.get('type',{}).get('qualType','') for n in walk(init))
                macros=any('expansionLoc' in loc for n in walk(init) for loc in n.get('range',{}).values())
                unquoted=re.sub(rb'"(?:\\[\s\S]|[^"\\])*"|\'(?:\\[\s\S]|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\r\n]*',b'',expression)
                if refs&candidates or arrays and (b'[' in unquoted or macros):
                    for scope in available:
                        snapshots=[]
                        for group in scope:
                            body,item=enum_snapshot(path,group);snapshots.append((body,item))
                            enum_ids.update(entry['id'] for entry in group['inner'] if entry['kind']=='EnumConstantDecl')
                            enum_names.update(entry['name'] for entry in group['inner'] if entry['kind']=='EnumConstantDecl')
                        if snapshots:enum_scopes.append(snapshots)
            for ref in walk(init):
                declaration=ref.get('referencedDecl',{})
                if ref['kind']!='DeclRefExpr':continue
                if declaration.get('kind')=='FunctionDecl':raise ValueError('function addresses in state initializers need an explicit adapter')
                if declaration.get('id') in global_ids[path]:
                    origin,off,sz=point(ref['range']['begin'],path)
                    if origin!=path or off is None or not a<=off<off+sz<=end:raise ValueError('initializer state reference spelling is outside its owned expression: '+name)
                    local[off-a,off-a+sz]='ctx->'+global_ids[path][declaration['id']]
                elif (path,declaration.get('id')) in lifted_symbols:
                    origin,off,sz=point(ref['range']['begin'],path)
                    if origin!=path or off is None or not a<=off<off+sz<=end:raise ValueError('initializer readonly reference spelling is outside its owned expression: '+name)
                    local[off-a,off-a+sz]=lifted_symbols[path,declaration['id']]
                elif declaration.get('kind')=='VarDecl':
                    external_type=declaration['type']['qualType']
                    if '*' in external_type or 'const' not in external_type:raise ValueError('initializer refers to state outside the supplied closure: '+declaration['name'])
                if name in local_owners and declaration.get('id') in block_ids[local_owners[name]] and declaration.get('id') not in global_ids[path] and (path,declaration.get('id')) not in lifted_symbols and declaration.get('id') not in enum_ids:raise ValueError('local-state initializer depends on function-local declarations: '+name)
            for (a,b),value in sorted(local.items(),reverse=True):expression=expression[:a]+value.encode('utf-8')+expression[b:]
            expression=expression.decode('utf-8')
            helper=prefix+('restore_state_'+str(len(state_initializers)) if name in local_owners else 'restore_array_'+str(len(array_initializers)) if '[' in typ else 'restore_value_'+str(len(value_initializers)))
            if helper in symbols.values() or helper in function_names:raise ValueError('state restoration helper name conflicts with kernel function')
            # Every initializer stays beside its declaration, preserving its
            # private constants without exposing them in the context header.
            def fresh(candidate):
                while candidate in enum_names or candidate in macro_names:candidate+='_'
                enum_names.add(candidate);return candidate
            parameter=fresh('ctx');temporary=fresh('osrec_initial');index=fresh('osrec_i')
            # Replace only our inserted tokens; an enum or macro named ctx
            # retains its original spelling in the initializer expression.
            if parameter!='ctx':
                for key,value in local.items():
                    if value.startswith('ctx->'):local[key]=parameter+value[3:]
                expression_bytes=original_expression
                for (x,y),value in sorted(local.items(),reverse=True):expression_bytes=expression_bytes[:x]+value.encode('utf-8')+expression_bytes[y:]
                expression=expression_bytes.decode('utf-8')
            opening=''.join('{\n'+'\n'.join(body for body,_ in scope)+'\n' for scope in enum_scopes)
            body='void '+helper+'(struct '+context+' *'+parameter+')\n{\n'+opening+'    __typeof__('+parameter+'->'+name+') '+temporary+' = '+expression+';\n    for('+('__SIZE_TYPE__' if enum_scopes else 'size_t')+' '+index+'=0;'+index+'<sizeof('+parameter+'->'+name+');++'+index+')((unsigned char *)&'+parameter+'->'+name+')['+index+']=((const unsigned char *)&'+temporary+')['+index+'];\n'+'}\n'*len(enum_scopes)+'}\n'
            if enum_scopes:initializer_enums.append(dict(name=name,function=helper,scopes=[[item for _,item in scope] for scope in enum_scopes]))
            if name in local_owners:
                _,fn=functions[local_owners[name]];origin,position,_=point(fn['range']['begin'],path)
                if origin!=path:raise ValueError('local-state function spelling must be inside owned source')
                local_helpers.setdefault((origin,position),[]).append(body)
                state_initializers.append(dict(name=name,type=typ,function=helper))
            else:
                declaration_helpers.setdefault((p,start),[]).append(body)
                if '[' not in typ:value_initializers.append(dict(name=name,type=typ,function=helper,source=path.relative_to(directory).as_posix()))
            initializers.append('    '+helper+'('+restore_parameter+');')
            if '[' in typ:array_initializers.append(dict(name=name,type=typ,function=helper))
    lifted_text={}
    for key,(node,function) in ordered_lifted:
        path,identity=key;p,start,_=source_point(node['range']['begin'],path)
        if p!=path or start is None:raise ValueError('lifted readonly declaration spelling must be inside owned source')
        groups[p,start]=source_end(texts[p],start,';');group_nodes.setdefault((p,start),[]).append(node)
        declaration='static '+field(node['type']['qualType'],lifted_symbols[key])
        if node.get('init'):
            init=node['inner'][-1];p,a,_=source_point(init['range']['begin'],path)
            if p!=path or a is None:raise ValueError('lifted readonly initializer spelling must be inside owned source')
            end=source_end(texts[path],a,',;');expression=texts[path][a:end];local={}
            for ref in walk(init):
                symbol=lifted_symbols.get((path,ref.get('referencedDecl',{}).get('id')))
                if ref['kind']=='DeclRefExpr' and symbol:
                    p,off,sz=point(ref['range']['begin'],path)
                    if p!=path or off is None or not a<=off<off+sz<=end:raise ValueError('lifted readonly reference spelling is outside its owned expression')
                    local[off-a,off-a+sz]=symbol
            for (a,b),value in sorted(local.items(),reverse=True):expression=expression[:a]+value.encode('utf-8')+expression[b:]
            declaration+=' = '+expression.decode('utf-8')
        _,fn=functions[function];p,position,_=point(fn['range']['begin'],path)
        if p!=path:raise ValueError('lifted readonly function spelling must be inside owned source')
        lifted_text.setdefault((p,position),[]).append(declaration+';\n')
    # A common declaration can contain readonly objects and mutable pointers.
    # Retain the readonly definitions when removing only the owned storage.
    readonly_groups={};retained_declarations=[];retained_text={}
    for path,node,function in readonly_definitions:
        p,start,_=source_point(node['range']['begin'],path);key=(p,start)
        if key in groups and (path,node['id']) not in lifted:readonly_groups.setdefault(key,[]).append((node,function))
    for path,start in dict.fromkeys([*readonly_groups,*[(p,source_point(n['range']['begin'],p)[1]) for (p,_),(n,_) in lifted.items()]]):
        siblings=readonly_groups.get((path,start),[])
        nodes=group_nodes[path,start]+[node for node,_ in siblings]
        locations=[source_point(node.get('loc',{}),path) for node in nodes]
        if any(p!=path or offset is None for p,offset,_ in locations):raise ValueError('mixed declaration spelling must be inside owned source')
        prefix_text=texts[path][start:min(offset for _,offset,_ in locations)]
        if not prefix_text.strip() or any(c in prefix_text for c in (b'{',b'[',b'(')):raise ValueError('mixed declaration type needs explicit source preparation')
        for node,function in siblings:
            if node.get('tls') or any(part['kind'].endswith('Attr') for part in node.get('inner',[])):raise ValueError('mixed readonly declaration attributes/TLS need an explicit adapter')
            declaration=(node.get('storageClass','')+' '+field(node['type']['qualType'],node['name'])).lstrip()
            if node.get('init'):
                init=node['inner'][-1];p,offset,_=source_point(init['range']['begin'],path)
                if p!=path or offset is None:raise ValueError('readonly initializer spelling must be inside owned source')
                end=source_end(texts[path],offset,',;');expression=texts[path][offset:end];local={}
                for part in walk(init):
                    ref=part.get('referencedDecl',{})
                    if part['kind']=='CompoundLiteralExpr' or ref.get('kind')=='FunctionDecl':raise ValueError('mixed readonly initializer needs an explicit object/callback adapter')
                    if ref.get('id') in global_ids[path]:raise ValueError('readonly declaration refers to context-owned state')
                    symbol=lifted_symbols.get((path,ref.get('id')))
                    if part['kind']=='DeclRefExpr' and symbol:
                        p,off,sz=point(part['range']['begin'],path)
                        if p!=path or off is None or not offset<=off<off+sz<=end:raise ValueError('retained readonly reference spelling is outside its owned expression')
                        local[off-offset,off-offset+sz]=symbol
                for (a,b),value in sorted(local.items(),reverse=True):expression=expression[:a]+value.encode('utf-8')+expression[b:]
                declaration+=' = '+expression.decode('utf-8')
            retained_text.setdefault((path,start),[]).append(declaration+';')
            item=dict(declaration=node['name'],source=path.relative_to(directory).as_posix(),type=node['type']['qualType'],offset=source_point(node['loc'],path)[1])
            if function is not None:item['function']=function
            retained_declarations.append(item)
    for (path,start),finish in groups.items():
        # References within initializers belong to the generated restoration code.
        for key in list(edits[path]):
            if start<=key[0]<=finish:del edits[path][key]
        edit(path,start,finish+1,'\n'.join((*retained_text.get((path,start),[]),*declaration_helpers.get((path,start),[]))))
    for path,position in set(local_helpers)|set(lifted_text):edit(path,position,position,'\n'.join((*lifted_text.get((path,position),[]),*local_helpers.get((path,position),[])))+'\n')
    for path,text in texts.items():
        ordered=sorted(edits[path].items(),reverse=True);previous=len(text)+1
        for (a,b),value in ordered:
            if b>previous:raise ValueError('overlapping context edits')
            text=text[:a]+value+text[b:];previous=a
        preamble=('#include "slice_context.h"\n' if path in source_indices else 'struct '+context+';\n').encode('utf-8')
        # Keep an optional UTF-8 BOM first, ahead of generated declarations.
        bom=b'\xef\xbb\xbf' if text.startswith(b'\xef\xbb\xbf') else b''
        path.write_bytes(bom+preamble+text[len(bom):])
    helpers={f['function']:f for f in (*array_initializers,*state_initializers,*value_initializers)}
    prototypes=''.join('void '+f['function']+'(struct '+context+' *'+restore_parameter+');\n' for f in helpers.values())
    context_header='#ifndef OSREC_SLICE_CONTEXT_H\n#define OSREC_SLICE_CONTEXT_H\n#include "'+headers[0]+'"\n#include "osrec/syscall_slice.h"\nstruct '+context+' {\n'+'\n'.join(declarations)+'\n};\n'+prototypes+'static inline void osrec_context_restore(struct '+context+' *'+restore_parameter+')\n{\n    for(size_t '+restore_index+'=0;'+restore_index+'<sizeof(*'+restore_parameter+');++'+restore_index+')((unsigned char *)'+restore_parameter+')['+restore_index+']=0;\n'+'\n'.join(initializers)+'\n}\n#endif\n'
    (directory/'slice_context.h').write_text(context_header,encoding='utf-8')
    report={'format':'osrec-context-threading-v1','context':context,'symbols':symbols,'owned_state':[{'name':n,'type':v[1]['type']['qualType']} for n,v in globals_by_name.items()],
        'context_functions':sorted(needs),'pure_functions':sorted(set(functions)-needs),'signatures':{n:{'parameters':[p['type']['qualType'] for p in v[1].get('inner',[]) if p.get('kind')=='ParmVarDecl'],'variadic':bool(v[1].get('variadic')),'type':v[1]['type']['qualType']} for n,v in functions.items()},'function_dependencies':{n:sorted(v) for n,v in dependencies.items()},'indirect_calls_supported':False,'source_encoding':'utf-8','source_offsets':'bytes','input_sha256':{p.relative_to(directory).as_posix():hashlib.sha256(t).hexdigest() for p,t in texts.items()}}
    if array_initializers:report['array_initializers']=array_initializers
    if value_initializers:report['value_initializers']=value_initializers
    if private_state:report['private_state']=private_state
    if private_functions:report['private_functions']=private_functions
    if local_state:report['local_state']=local_state
    if state_initializers:report['state_initializers']=state_initializers
    if retained_declarations:report['retained_declarations']=retained_declarations
    if lifted_constants:report['lifted_constants']=lifted_constants
    if initializer_enums:report['initializer_enums']=initializer_enums
    renamed_parameters={n:p for n,p in context_names.items() if p!='ctx'}
    if renamed_parameters:report['context_parameters']=renamed_parameters
    (directory/'context-plan.json').write_text(json.dumps(report,indent=2)+'\n');return report
