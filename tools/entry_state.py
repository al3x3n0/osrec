#!/usr/bin/env python3
"""Conservative typed entry-state discovery from configured Clang C sources."""
import argparse
import copy
import hashlib
import json
import re
from pathlib import Path
import shlex
import subprocess
import tempfile


def digest(data):return hashlib.sha256(data).hexdigest()
def children(node):
    # Clang's JSON dumper puts partially filled array initializer entries in
    # array_filler, alongside the implicit default initializer. They contain
    # evaluated expressions and must participate in effects/reference closure.
    return node.get('inner',[])+(node.get('array_filler',[]) if node.get('kind')=='InitListExpr' else [])
def walk(node):
    yield node
    for child in children(node):yield from walk(child)
SELECTIONS=('GenericSelectionExpr','ChooseExpr')
def selected_expression(node):
    """Read a configured Clang selection; never infer C type compatibility."""
    parts=children(node)
    if node.get('kind')=='GenericSelectionExpr':
        selected=[part for part in parts if part.get('selected') is True]
        if len(selected)!=1:return None
        association=selected[0];terms=children(association)
        count={'case':2,'default':1}.get(association.get('associationKind'))
        return terms[-1] if count is not None and len(terms)==count and terms[-1].get('valueCategory') else None
    if node.get('kind')=='ChooseExpr' and len(parts)==3:
        condition=parts[0];value=condition.get('value','')
        if condition.get('kind')=='ConstantExpr':
            if type_of(condition)=='_Bool' and value in ('true','false'):
                return parts[1] if value=='true' else parts[2]
            if isinstance(value,str) and re.fullmatch(r'-?[0-9]+',value):
                return parts[1] if int(value)!=0 else parts[2]
    return None

def binary_conditional_parts(node):
    """Validate Clang's shared-value proxies for GNU common ?: fallback."""
    parts=children(node)
    if node.get('kind')!='BinaryConditionalOperator' or len(parts)!=4:return None
    common,condition,chosen,fallback=parts
    if not common.get('id') or common.get('valueCategory')!='prvalue':return None
    def proxy(value):
        while value.get('kind') in ('ParenExpr','ImplicitCastExpr'):
            terms=children(value)
            if len(terms)!=1:return None
            if value.get('kind')=='ImplicitCastExpr' and value.get('castKind') not in (
                'NoOp','BitCast','IntegralCast','IntegralToFloating','FloatingCast','FloatingToIntegral',
                'IntegralToBoolean','FloatingToBoolean','PointerToBoolean','NullToPointer'):
                return None
            value=terms[0]
        terms=children(value)
        if value.get('kind')!='OpaqueValueExpr' or not value.get('id') or len(terms)!=1 or terms[0]!=common:return None
        return value['id']
    condition_proxy=proxy(condition);chosen_proxy=proxy(chosen)
    return (common,fallback) if condition_proxy is not None and condition_proxy==chosen_proxy else None

def effect_walk(node):
    """Walk effects, excluding only compiler-selected unevaluated operands."""
    yield node
    # Ordinary sizeof/alignof operands are unevaluated. Variably modified
    # types are rejected separately: the JSON AST does not retain every bound
    # evaluation, so walking the operand cannot supply a sound effect model.
    if node.get('kind')=='UnaryExprOrTypeTraitExpr':return
    if node.get('kind')=='BinaryConditionalOperator':
        parts=binary_conditional_parts(node)
        if parts is not None:
            for child in parts:yield from effect_walk(child)
            return
    selected=selected_expression(node) if node.get('kind') in SELECTIONS else None
    for child in [selected] if selected is not None else children(node):yield from effect_walk(child)
def type_of(node):
    typ=node.get('type',{})
    return typ.get('desugaredQualType',typ.get('qualType','unknown'))
def fixed_array(typ):
    match=re.fullmatch(r'([^\[\]]+)\[([0-9]+)\](?:\[[0-9]+\])*',typ)
    # A pointer-to-array also ends in [N], but denotes no inline storage.
    return match if match and not re.search(r'\(\s*\*',match[1]) else None
def without_typeof(typ):
    """Drop `typeof (expr)` spellings: subscripts inside the expression are not array bounds.

    Clang spells typeof types with the operand text, e.g. `typeof (*(fdt->fd[fd & mask])) *`.
    Variable-length arrays are not used by the configured kernels (-Wvla).
    """
    while True:
        match=re.search(r'(?:__typeof__|__typeof|typeof)\s*\(',typ)
        if not match:return typ
        depth=0;end=match.end()-1
        for end in range(match.end()-1,len(typ)):
            depth+=typ[end]=='(';depth-=typ[end]==')'
            if depth==0:break
        typ=typ[:match.start()]+'typeof-expr'+typ[end+1:]

def variably_modified_type(typ):
    # [] denotes an incomplete array, not an evaluated variable bound. Keep
    # expressions and [*] conservative: Clang JSON can omit their effects.
    typ=without_typeof(typ)
    if '[' not in typ:return False
    return any(bound.strip() and not re.fullmatch(r'[0-9]+',bound.strip())
               for bound in re.findall(r'\[([^\]]*)\]',typ))
def declared_array_shape(typ):
    """Only an inline array with a possibly unknown outer dimension."""
    match=re.fullmatch(r'([^\[\]]+)\[([0-9]*)\]((?:\[[0-9]+\])*)',typ)
    if not match or re.search(r'\(\s*\*',match[1]):return None
    return match[1].strip(),(int(match[2]) if match[2] else None,)+tuple(int(n) for n in re.findall(r'\[([0-9]+)\]',match[3]))

def array_pointer_lvalue(node):
    """Canonicalize immediate array-offset lvalues, preserving each operand once.

    Only a direct compiler array decay carries storage bounds. This does not
    assign provenance to a pointer variable, explicit cast, or escaped offset.
    The ordinary subscript resolver must still prove every extent and index.
    """
    def parens(value):
        while value.get('kind')=='ParenExpr' and len(children(value))==1:value=children(value)[0]
        return value
    def offset(value):
        value=parens(value);terms=children(value)
        if value.get('kind')!='BinaryOperator' or value.get('opcode')!='+' or len(terms)!=2:return None
        for array,index in (terms,terms[::-1]):
            array=parens(array)
            if array.get('kind')=='ImplicitCastExpr' and array.get('castKind')=='ArrayToPointerDecay' and len(children(array))==1:
                if declared_array_shape(type_of(parens(children(array)[0]))) is not None:return array,index
        return None
    kind=node.get('kind');terms=children(node)
    if kind=='UnaryOperator' and node.get('opcode')=='*' and len(terms)==1:
        parts=offset(terms[0])
        if parts is not None:
            array,index=parts
            return {**node,'kind':'ArraySubscriptExpr','inner':[array_pointer_lvalue(array),index],
                    '_array_pointer_access':True,'opcode':None}
    if kind=='MemberExpr' and node.get('isArrow') and len(terms)==1:
        parts=offset(terms[0])
        if parts is not None:
            array,index=parts;base,dimensions=declared_array_shape(type_of(parens(children(array)[0])))
            element=base+''.join('['+str(n)+']' for n in dimensions[1:])
            subscript={**parens(terms[0]),'kind':'ArraySubscriptExpr','type':{'qualType':element},
                       'valueCategory':'lvalue','inner':[array_pointer_lvalue(array),index],
                       '_array_pointer_access':True,'opcode':None}
            return {**node,'isArrow':False,'inner':[subscript]}
    # Recurse only along storage chains, never through an arbitrary value or
    # index expression. In particular &*(array+i) remains an escaped offset.
    if terms and (kind in ('MemberExpr','ArraySubscriptExpr','ParenExpr') or
                  kind=='ImplicitCastExpr' and node.get('castKind') in ('ArrayToPointerDecay','LValueToRValue','NoOp')):
        base=array_pointer_lvalue(terms[0])
        if base is not terms[0]:return {**node,'inner':[base,*terms[1:]]}
    return node

def pointer_arithmetic_detail(node):
    terms=children(node)
    if node.get('kind')=='BinaryOperator' and node.get('opcode') in ('+','-') and any('*' in type_of(c) for c in terms):
        if node['opcode']=='-' and all('*' in type_of(c) for c in terms):
            return 'pointer difference requires common-array provenance'
        return 'pointer range/offset requires a memory contract'
    return None
def object_pointer_element(typ):
    """Array elements that are plain object pointers: loads yield pointer values, never bytes."""
    return isinstance(typ,str) and bool(re.fullmatch(r'(?:const )?(?:(?:struct|union) )?[A-Za-z_]\w* \*(?: ?const)?',typ.strip()))

def validate_state_ranges(ranges):
    """Declared integer field ranges; each names the check that enforces it on live state."""
    result={}
    if not isinstance(ranges,list):raise ValueError('state_ranges must be a list')
    for item in ranges:
        # `elements`: the range holds for every element of an array field (a table indexed at run time).
        # `element_ranges`: tighter ranges of the elements at an index interval ({indices: [lo, hi], min, max}).
        if 'element_ranges' in item and (not item.get('elements') or not isinstance(item['element_ranges'],list) or any(not isinstance(r,dict) or set(r)!={'indices','min','max'} or
                len(r['indices'])!=2 or any(type(v) is not int for v in [*r['indices'],r['min'],r['max']]) or not 0<=r['indices'][0]<=r['indices'][1] or not item['min']<=r['min']<=r['max']<=item['max'] for r in item['element_ranges'])):
            raise ValueError('invalid element ranges')
        if (not isinstance(item,dict) or set(item)-{'record','field','min','max','reason','validated_by','elements','element_ranges'} or item.get('elements',True) is not True or
            not re.fullmatch(r'struct [A-Za-z_]\w*',str(item.get('record',''))) or not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?',str(item.get('field',''))) or
            type(item.get('min')) is not int or type(item.get('max')) is not int or item['min']>item['max'] or not item.get('reason') or not item.get('validated_by')):
            raise ValueError('state range requires record, field, integer min<=max, reason and validated_by')
        key=(item['record'],item['field'])
        if key in result:raise ValueError('duplicate state range: %s.%s'%key)
        result[key]=dict(item)
    return result

POINTER_WIDTH_INTEGERS=('unsigned long','unsigned long long','long','long long')
TAGGED=re.compile(r'tagged:(\d+):(\d+):(.*)',re.S)

def tag_value(path,tag=0,cleared=0):
    """Integer provenance: a pointer path with OR-ed low tag bits and the bits cleared from it."""
    return 'tagged:%d:%d:%s'%(tag,cleared,path)

def qualifier_only_conversion(cast,operand):
    """READ_ONCE/WRITE_ONCE: a cast that adds volatile to the same pointee type.

    Other explicit casts, including same-type ones, still drop array element
    provenance (a pointer view never borrows an array bound).
    """
    def pointee(node):
        typ=type_of(node).strip()
        if not typ.endswith('*') or '(' in typ:return None,None
        body=typ[:-1]
        return re.sub(r'\s+',' ',re.sub(r'\b(?:const|volatile|restrict)\b','',body)).strip(),bool(re.search(r'\bvolatile\b',body))
    (target,target_volatile),(source,source_volatile)=pointee(cast),pointee(operand)
    if target is not None and target==source and target_volatile and not source_volatile:return True
    # Adding const (keeping volatile) to the same pointee type keeps the object.
    constant=lambda node:bool(re.search(r'\bconst\b',type_of(node).strip()[:-1]))
    if target is not None and target==source and target_volatile==source_volatile and constant(cast) and not constant(operand):return True
    # Clang marks qualification-only conversions as NoOp, even when the target is
    # spelled through typeof/_Generic (__unqual_scalar_typeof in READ_ONCE).
    spelled=type_of(cast).strip()
    return (cast.get('castKind')=='NoOp' and spelled.endswith('*') and bool(re.search(r'\bvolatile\b',spelled[:-1])) and
            source is not None and not source_volatile)

def void_view(cast):
    """A conversion to (const/volatile) void *: an opaque view that cannot be dereferenced."""
    return bool(re.fullmatch(r'(?:(?:const|volatile)\s+)*void\s*\*(?:\s*(?:const|volatile|restrict))*',type_of(cast).strip()))

def object_pointee(typ):
    """Canonical object identity ignores const views, not the C pointer type."""
    match=re.fullmatch(r'(?:const )?((?:struct )?[A-Za-z_]\w*) \*(?:const)?',typ)
    return match[1] if match and match[1]!='void' else None

def const_storage(typ):
    return bool(re.search(r'\*\s*const(?:\s|\[|$)',typ)) if '*' in typ else typ.startswith('const ')

def path_provider(path):
    # Most kernel paths contain no provider call. Avoid an unanchored greedy
    # identifier search at every character of a long, provider-free path.
    if '()' not in path:return None
    match=re.search(r'([A-Za-z_]\w*)\(\)',path)
    return match[1] if match else None

PRESERVATION_REASON='full typed overwrite is not proven at every exit'
PRESERVATION_FORMAT='osrec-write-state-preservation-v1'
DEFAULT_MAX_ALIAS_PATHS=256
INDEX_INTEGER_LIMITS={'int':(-0x80000000,0x7fffffff),'unsigned int':(0,0xffffffff),
    'long':(-0x80000000,0x7fffffff),'unsigned long':(0,0xffffffff),
    'long long':(-0x8000000000000000,0x7fffffffffffffff),'unsigned long long':(0,0xffffffffffffffff)}
ALIAS_LIMIT_ORIGIN='unresolved:alias-limit'
# A pointer whose only value is null, read where a guard proves it non-null: the code is unreachable.
INFEASIBLE='infeasible:null-guarded'
LINKS='#links';LINK_SUFFIX='#nonnull-if';INVALID_LINK='#invalid'
AUTO_PATH=re.compile(r'(?:\*\()?auto:(\d+)\)?((?:->|\.)[A-Za-z_][\w.>-]*)?')
# value_model semantics: index_mask(index, size) is all-ones when index < size, else zero.
VALUE_MODELS=('index_mask',)
COMPILE_TIME_BUILTINS={'__builtin_constant_p':'implicit Clang builtin; compile-time 0/1 query whose operand is not evaluated at run time',
    '__builtin_unreachable':'implicit Clang builtin; marks unreachable code and has no run-time effect'}

# Explicit integer-only compiler operations; ordinary library functions and
# memory, floating-point, target-state and variadic builtins remain unmodeled.
INTEGER_BIT_BUILTINS={
    '__builtin_'+operation+suffix:('int',argument)
    for operation in ('clz','ctz','ffs','clrsb','popcount','parity')
    for suffix,base in (('','int'),('l','long'),('ll','long long'))
    for argument in [base if operation in ('ffs','clrsb') else 'unsigned '+base]
}
INTEGER_BIT_BUILTINS.update({
    '__builtin_bswap16':('unsigned short','unsigned short'),
    '__builtin_bswap32':('unsigned int','unsigned int'),
    '__builtin_bswap64':('unsigned long long','unsigned long long'),
})

def arithmetic_scalar(typ):
    return isinstance(typ,str) and bool(re.fullmatch(r'(?:const )?(?:(?:unsigned |signed )?(?:char|short(?: int)?|int|long(?: int)?|long long(?: int)?)|_Bool|float|double|long double)',typ))

def constant_initializer(node):
    """Retain only a configured, pure numeric constant-expression syntax tree."""
    if not isinstance(node,dict) or not isinstance(node.get('type',{}),dict) or not isinstance(node.get('inner',[]),list):return None
    kind=node.get('kind');typ=type_of(node);parts=children(node)
    if not arithmetic_scalar(typ):return None
    result={'kind':kind,'type':{'qualType':typ}}
    if kind=='IntegerLiteral':
        if parts or not re.fullmatch(r'[0-9]+',str(node.get('value',''))):return None
        result['value']=str(node['value']);return result
    if kind=='FloatingLiteral':
        if parts or not re.fullmatch(r'[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?',str(node.get('value',''))):return None
        result['value']=str(node['value']);return result
    if kind in ('ParenExpr','ConstantExpr'):
        if len(parts)!=1:return None
    elif kind in ('ImplicitCastExpr','CStyleCastExpr'):
        if len(parts)!=1 or node.get('castKind') not in ('NoOp','IntegralCast','IntegralToFloating','FloatingCast','FloatingToIntegral','IntegralToBoolean','FloatingToBoolean'):return None
        result['castKind']=node['castKind']
    elif kind=='UnaryOperator':
        if len(parts)!=1 or node.get('opcode') not in ('+','-','~','!'):return None
        result['opcode']=node['opcode']
    elif kind=='BinaryOperator':
        if len(parts)!=2 or node.get('opcode') not in ('+','-','*','/','%','<<','>>','&','|','^','&&','||','==','!=','<','<=','>','>='):return None
        result['opcode']=node['opcode']
    else:return None
    terms=[constant_initializer(part) for part in parts]
    if any(term is None for term in terms):return None
    result['inner']=terms;return result

def numeric_array(typ):
    if not isinstance(typ,str):return None
    array=fixed_array(typ)
    if array is None or not arithmetic_scalar(array[1].strip()):return None
    dimensions=tuple(int(n) for n in re.findall(r'\[([0-9]+)\]',typ))
    return (array[1].strip(),dimensions) if dimensions and all(n>0 for n in dimensions) else None

def constant_array_initializer(node):
    """Check numeric array initialization without expanding zero-fill extents."""
    if (not isinstance(node,dict) or not isinstance(node.get('type',{}),dict) or
        not isinstance(node.get('inner',[]),list) or not isinstance(node.get('array_filler',[]),list)):return None
    typ=type_of(node);array=numeric_array(typ);kind=node.get('kind')
    if kind=='ImplicitValueInitExpr' and not children(node) and (array or arithmetic_scalar(typ)):
        return {'kind':kind,'type':{'qualType':typ}}
    if array is None:return constant_initializer(node)
    if kind!='InitListExpr':return None
    base,dimensions=array;element=base+''.join('['+str(n)+']' for n in dimensions[1:])
    result={'kind':kind,'type':{'qualType':typ}}
    for field in ('inner','array_filler'):
        if field not in node:continue
        terms=node[field]
        if not isinstance(terms,list) or len(terms)>dimensions[0]+(field=='array_filler'):return None
        normalized=[]
        for term in terms:
            value=constant_array_initializer(term)
            if value is None or type_of(value).removeprefix('const ')!=element.removeprefix('const '):return None
            normalized.append(value)
        result[field]=normalized
    return result

def record_type_key(typ):
    typ=typ.removeprefix('const ').strip()
    anonymous=re.fullmatch(r'struct .*\((?:unnamed|anonymous)(?: struct)? at (.+):([0-9]+):([0-9]+)\)',typ)
    if anonymous:return 'struct @'+':'.join(anonymous.groups())
    return typ if re.fullmatch(r'struct [A-Za-z_]\w*',typ) else None

def constant_shape_type(shape):
    dimensions=[]
    while shape['kind']=='array':dimensions.append(shape['elements']);shape=shape['element']
    return shape['type']+''.join('['+str(n)+']' for n in dimensions)

def valid_constant_shape(shape,depth=0,budget=None):
    if budget is None:budget=[1024]
    budget[0]-=1
    if budget[0]<0 or not isinstance(shape,dict) or depth>16:return False
    kind=shape.get('kind')
    if kind=='scalar':return set(shape)=={'kind','type'} and arithmetic_scalar(shape['type']) and not shape['type'].startswith('const ')
    if kind=='array':return (set(shape)=={'kind','elements','element'} and type(shape['elements']) is int and shape['elements']>0 and valid_constant_shape(shape['element'],depth+1,budget))
    if kind!='struct' or set(shape)!={'kind','type','fields'} or not isinstance(shape['type'],str) or not shape['type'].startswith('struct '):return False
    fields=shape['fields']
    return (isinstance(fields,list) and 0<len(fields)<=128 and
            all(isinstance(f,dict) and set(f)=={'name','shape'} and isinstance(f['name'],str) and re.fullmatch(r'[A-Za-z_]\w*',f['name']) and valid_constant_shape(f['shape'],depth+1,budget) for f in fields) and
            len({f['name'] for f in fields})==len(fields))

def constant_record_initializer(node,shape,budget=None):
    """Validate a canonical numeric struct/array initializer without zero expansion."""
    if budget is None:budget=[8192]
    budget[0]-=1
    if budget[0]<0 or not isinstance(node,dict) or type_of(node)!=constant_shape_type(shape):return None
    if shape['kind']=='scalar':return constant_array_initializer(node)
    if node.get('kind')=='ImplicitValueInitExpr' and not children(node):
        return {'kind':'ImplicitValueInitExpr','type':{'qualType':constant_shape_type(shape)}}
    if node.get('kind')!='InitListExpr' or 'field' in node:return None
    result={'kind':'InitListExpr','type':{'qualType':constant_shape_type(shape)}}
    if shape['kind']=='struct':
        terms=node.get('inner',[])
        if not isinstance(terms,list) or 'array_filler' in node or len(terms)!=len(shape['fields']):return None
        values=[constant_record_initializer(term,field['shape'],budget) for term,field in zip(terms,shape['fields'])]
        if any(v is None for v in values):return None
        result['inner']=values
    else:
        for key in ('inner','array_filler'):
            if key not in node:continue
            terms=node[key]
            if not isinstance(terms,list) or len(terms)>shape['elements']+(key=='array_filler'):return None
            values=[constant_record_initializer(term,shape['element'],budget) for term in terms]
            if any(v is None for v in values):return None
            result[key]=values
    return result

def constant_record_leaf(path,name,shape):
    prefix='global:'+name
    if not isinstance(path,str) or not path.startswith(prefix):return None
    suffix=path[len(prefix):]
    while suffix:
        if shape['kind']=='struct':
            match=re.match(r'\.([A-Za-z_]\w*)',suffix)
            if not match:return None
            field=next((f for f in shape['fields'] if f['name']==match[1]),None)
            if field is None:return None
            shape=field['shape']
        elif shape['kind']=='array':
            match=re.match(r'\[([0-9]+)\]',suffix)
            if not match or int(match[1])>=shape['elements']:return None
            shape=shape['element']
        else:return None
        suffix=suffix[match.end():]
    return 'const '+shape['type'] if shape['kind']=='scalar' else None

def fixed_global_read(item,plan):
    """Validate evidence before excluding a fixed program constant from input."""
    if 'immutable_global' not in item:return False
    proof=item['immutable_global']
    if isinstance(proof,dict) and proof.get('kind')=='defined_const_initializer_leaf':return constant_leaf_read(item,proof,plan)
    if isinstance(proof,dict) and proof.get('kind')=='defined_const_record':return constant_record_read(item,proof,plan)
    required={'kind','object','type','initializer','initializer_sha256','declaration_location'}
    if isinstance(proof,dict) and proof.get('kind')=='defined_const_numeric_record':required|={'schema','schema_sha256'}
    if not isinstance(proof,dict) or set(proof)!=required:raise ValueError('invalid immutable global evidence')
    typ=proof['type'];name=proof['object'];initializer=proof['initializer']
    if (not isinstance(typ,str) or not typ.startswith('const ') or
        not isinstance(name,str) or not re.fullmatch(r'(?:tu[0-9]+:)?[A-Za-z_]\w*',name) or item.get('pointer_edge') or item.get('volatile') or item.get('bitfield') or
        item.get('entry_candidate') is not True or not isinstance(proof['declaration_location'],dict) or not isinstance(initializer,dict) or
        proof['initializer_sha256']!=digest(json.dumps(initializer,sort_keys=True).encode())):
        raise ValueError('invalid immutable global evidence')
    if proof['kind']=='defined_const_numeric_scalar':
        valid=(arithmetic_scalar(typ) and item.get('path')=='global:'+name and item.get('type')==typ and
               constant_initializer(initializer)==initializer and type_of(initializer)==typ.removeprefix('const '))
    elif proof['kind']=='defined_const_numeric_array':
        array=numeric_array(typ);path=item.get('path','')
        match=re.fullmatch(re.escape('global:'+name)+r'((?:\[[0-9]+\])+)',path) if isinstance(path,str) else None
        indexes=tuple(int(n) for n in re.findall(r'\[([0-9]+)\]',match[1])) if match else ()
        valid=(array is not None and len(indexes)==len(array[1]) and all(i<n for i,n in zip(indexes,array[1])) and
               item.get('type')==array[0] and constant_array_initializer(initializer)==initializer and type_of(initializer)==typ)
    elif proof['kind']=='defined_const_numeric_record':
        shape=proof['schema']
        leaf=constant_record_leaf(item.get('path'),name,shape) if valid_constant_shape(shape) else None
        valid=(valid_constant_shape(shape) and typ=='const '+constant_shape_type(shape) and
               proof['schema_sha256']==digest(json.dumps(shape,sort_keys=True).encode()) and
               constant_record_initializer(initializer,shape)==initializer and
               leaf is not None and item.get('type')==leaf)
    else:valid=False
    if not valid:raise ValueError('invalid immutable global evidence')
    origin=re.compile(re.escape('global:'+name)+r'(?=$|[.\[\)]|->)')
    if any(origin.search(row['path']) for row in plan.get('state_writes',[])):
        raise ValueError('immutable global is also written: '+name)
    return True

def constant_record_read(item,proof,plan):
    """Validate evidence for a whole-record read of a defined const global (`struct futex_q q = futex_q_init;`).

    A file-scope initializer is a constant expression (C11 6.7.9p4), so a const object defined once
    holds fixed program data; the copy reads no entry state. Values it copies out (addresses) are
    resolved separately where they are used.
    """
    required={'kind','object','type','initializer_sha256','declaration_location'}
    name=proof.get('object');typ=proof.get('type')
    if (set(proof)!=required or not isinstance(name,str) or not re.fullmatch(r'(?:tu[0-9]+:)?[A-Za-z_]\w*',name) or
        not isinstance(typ,str) or not typ.startswith('const ') or record_type_key(typ) is None or item.get('path')!='global:'+name or item.get('type')!=typ or
        item.get('volatile') or item.get('bitfield') or item.get('pointer_edge') or item.get('entry_candidate') is not True or
        not isinstance(proof['declaration_location'],dict) or not isinstance(proof['initializer_sha256'],str)):
        raise ValueError('invalid constant record evidence')
    origin=re.compile(re.escape('global:'+name)+r'(?=$|[.\[\)]|->)')
    if any(origin.search(row['path']) for row in plan.get('state_writes',[])):
        raise ValueError('immutable global is also written: '+name)
    return True

def constant_leaf_read(item,proof,plan):
    """Validate evidence for a read of one constant member (numeric or address) of a const global."""
    required={'kind','object','path','type','initializer','initializer_sha256','declaration_location'}
    name=proof.get('object');initializer=proof.get('initializer')
    if (set(proof)!=required or not isinstance(name,str) or not re.fullmatch(r'(?:tu[0-9]+:)?[A-Za-z_]\w*',name) or
        item.get('path')!=proof['path'] or not isinstance(proof['path'],str) or not re.fullmatch(re.escape('global:'+name)+r'(?:\.[A-Za-z_]\w*|\[[0-9]+\])*',proof['path']) or
        item.get('volatile') or item.get('bitfield') or item.get('entry_candidate') is not True or
        not isinstance(initializer,dict) or proof['initializer_sha256']!=digest(json.dumps(initializer,sort_keys=True).encode()) or
        not isinstance(proof['declaration_location'],dict)):
        raise ValueError('invalid constant leaf evidence')
    if initializer.get('kind')=='address_constant':
        value=initializer.get('value')
        valid=(set(initializer)=={'kind','value'} and item.get('pointer_edge') is True and isinstance(value,str) and
               re.fullmatch(r'null|function:(?:tu[0-9]+:)?[A-Za-z_]\w*|global:(?:tu[0-9]+:)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|\[[0-9]+\])*',value) is not None)
    else:
        valid=(not item.get('pointer_edge') and arithmetic_scalar(type_of(initializer)) and
               (constant_initializer(initializer)==initializer or initializer.get('kind')=='ImplicitValueInitExpr' and set(initializer)=={'kind','type'}))
    if not valid:raise ValueError('invalid constant leaf evidence')
    origin=re.compile(re.escape('global:'+name)+r'(?=$|[.\[\)]|->)')
    if any(origin.search(row['path']) for row in plan.get('state_writes',[])):
        raise ValueError('immutable global is also written: '+name)
    return True

def unwrap(node):
    while True:
        kind=node.get('kind')
        if kind in ('ImplicitCastExpr','ParenExpr','CStyleCastExpr','ConstantExpr'):
            parts=children(node)
            if parts:node=parts[0];continue
        elif kind in SELECTIONS:
            selected=selected_expression(node)
            if selected is not None:node=selected;continue
        break
    return node

def callee(node):
    parts=children(node)
    if not parts:return None
    target=unwrap(parts[0])
    if target.get('kind')=='DeclRefExpr' and target.get('referencedDecl',{}).get('kind')=='FunctionDecl':
        return target['referencedDecl']['name']
    return None

def compiler_arguments(database,source,clang=None):
    source=source.resolve();entries=json.loads(database.read_text());selected=[]
    for entry in entries:
        directory=Path(entry['directory']).resolve();file=Path(entry['file'])
        if not file.is_absolute():file=directory/file
        if file.resolve()==source:selected.append((entry,directory))
    if len(selected)!=1:raise ValueError('source needs exactly one compilation database entry')
    entry,directory=selected[0]
    command=entry.get('arguments') or shlex.split(entry['command'])
    compiler=clang or command[0];args=[];skip=False
    for value in command[1:]:
        if skip:skip=False;continue
        if value in ('-o','-MF','-MT','-MQ','-MJ','--serialize-diagnostics'):skip=True;continue
        if value in ('-c','-MD','-MMD','-MP','-MG'):continue
        if value.startswith(('-MF','-MT','-MQ','-MJ')) and len(value)>3:continue
        # Kbuild passes dependency output through the preprocessor; parsing must
        # not overwrite the build's own .d files.
        if value.startswith('-Wp,-M'):continue
        args.append(value)
    return str(compiler),args,directory


def load_ast(database,source,clang=None):
    compiler,args,directory=compiler_arguments(database,source,clang)
    with tempfile.TemporaryDirectory(prefix='osrec-entry-state-') as name:
        output=Path(name)/'ast.json';dep=Path(name)/'dependencies.d'
        # The added -MD is unused under -fsyntax-only; builds such as Kbuild make that an error.
        command=[compiler,*args,'-fsyntax-only','-Xclang','-ast-dump=json','-MD','-MF',str(dep),'-Wno-error=unused-command-line-argument']
        with output.open('w') as stream:
            result=subprocess.run(command,cwd=directory,stdout=stream,stderr=subprocess.PIPE,text=True,timeout=120)
        if result.returncode:raise ValueError('configured Clang parse failed: '+result.stderr.strip())
        tree=json.loads(output.read_text())
        from entry_state_offsetof import annotate
        designators=annotate(tree,compiler,source,args,directory)
        dependencies={source.resolve()}
        if dep.exists():
            text=dep.read_text().replace('\\\n',' ')
            for filename in shlex.split(text.split(':',1)[1]):
                path=Path(filename)
                if not path.is_absolute():path=directory/path
                if path.is_file():dependencies.add(path.resolve())
        identity={'source':str(source.resolve()),'source_sha256':digest(source.read_bytes()),
            'compiler':subprocess.check_output([compiler,'--version'],text=True).splitlines()[0],
            'compile_arguments':args,'compile_directory':str(directory),
            'compilation_database_sha256':digest(database.read_bytes()),'offsetof_designators':designators,
            'dependencies':{str(path):digest(path.read_bytes()) for path in sorted(dependencies)}}
    return tree,identity



class RootRanges(dict):
    """Root parameter intervals from argument_ranges contracts; reading one records its use."""
    def __init__(self,analyzer):
        super().__init__();self.analyzer=analyzer;self.contracts={}
    def __contains__(self,key):return key in self.contracts
    def __getitem__(self,key):
        contract=self.contracts[key];self.analyzer.argument_range_uses.add((contract['function'].split(':',1)[-1],contract['parameter']))
        return (contract['min'],contract['max'])
    def get(self,key,default=None):return self[key] if key in self.contracts else default

class Analyzer:
    def __init__(self,tree,boundaries=None,max_contexts=500,max_range_elements=64,prune_written=False,argument_objects=None,preserve_write_state=False,max_alias_paths=DEFAULT_MAX_ALIAS_PATHS,cache_alias_syntax=True,state_ranges=None,linked_symbols=None,volatile_fields=None,operand_free_asm=None,volatile_accesses=None,pointer_extents=None,callback_targets=None,pointer_values=None,pointer_identity=None,user_addresses=None,fault_assertions=None,argument_ranges=None,allocations=None,pointer_objects=None,deallocators=None,empty_lists=None):
        if preserve_write_state and not prune_written:raise ValueError('write-state preservation requires prune_written')
        if type(max_alias_paths) is not int or max_alias_paths<1:raise ValueError('max_alias_paths must be a positive integer')
        self.max_alias_paths=max_alias_paths;self.alias_path_limit_observed=False;self._quiet_limits=[];self._tree=tree
        self.cache_alias_syntax=cache_alias_syntax
        self._effect_nodes_cache={};self._alias_program_cache={};self._return_program_cache={}
        self._expression_nodes_cache={};self._direct_calls_cache={};self._parameters_cache={}
        self._static_index_cache={};self._array_lvalue_cache={}
        self._bounded_pointer_keys={};self._bounded_pointers={};self._pointer_access_constants={};self._pointer_access_types={};self._pointer_scope_cache={};self._definite_pointer_cache={};self._pointer_initialization_environments={};self.pointer_initializations=[];self.pointer_returns=[];self.pointer_stores=[];self.index_values=[];self._local_index_definitions={};self._local_index_cache={};self._local_index_inputs={};self._local_index_declarations={}
        self._diagnostic_keys=set();self._diagnostic_nodes={}
        from entry_state_values import Values
        self._scalar_objects={};self._scalar_fields={};self.trap_proofs=[];self.tagged_pointer_proofs=[];self.ordering_asm_proofs=[];self.extent_assumptions=[];self._union_tags={};self.range_uses=set();self.assertion_uses=[];self.array_summaries=[];self.infeasible_accesses=[];self.automatic_views=[]
        def classification(item,name):
            if item is None:return None
            if not isinstance(item,dict) or set(item)!={'classification','reason','validated_by'} or not all(isinstance(v,str) and v for v in item.values()):
                raise ValueError(name+' requires classification, reason and validated_by')
            return dict(item)
        self.operand_free_asm=classification(operand_free_asm,'operand_free_asm')
        self.volatile_accesses=classification(volatile_accesses,'volatile_accesses')
        self.callback_targets={};self.callback_uses=[]
        for item in callback_targets or []:
            if (set(item)!={'record','field','targets','reason','validated_by'} or not isinstance(item['targets'],list) or
                    not all(isinstance(t,str) and re.fullmatch(r'[A-Za-z_]\w*',t) for t in item['targets']) or
                    not all(isinstance(item[k],str) and item[k] for k in ('record','field','reason','validated_by'))):
                raise ValueError('callback targets require record, field, targets (function names), reason and validated_by')
            self.callback_targets[(item['record'],item['field'])]=dict(item)
        self.pointer_extents={}
        for item in pointer_extents or []:
            if set(item)!={'record','field','extent_field','reason','validated_by'} or not all(isinstance(v,str) and v for v in item.values()):
                raise ValueError('pointer extent requires record, field, extent_field, reason and validated_by')
            self.pointer_extents[(item['record'],item['field'])]=dict(item)
        self._function_facts={};self._context_calls={}
        self.pointer_values={};self._pointer_value_items=list(pointer_values or [])
        # The replay restores object identity: pointers to one captured object stay equal, to distinct ones distinct.
        if pointer_identity is not None and (not isinstance(pointer_identity,dict) or set(pointer_identity)!={'reason','implementation'} or
                not all(isinstance(v,str) and v for v in pointer_identity.values())):
            raise ValueError('pointer identity requires a reason and an implementation')
        self.pointer_identity=pointer_identity
        # Root parameters that hold user-space addresses: exact register values, never kernel objects.
        self.user_addresses=set()
        for item in user_addresses or []:
            if (not isinstance(item,dict) or set(item)!={'function','parameter','reason','validated_by'} or
                    not all(isinstance(item[k],str) and item[k] for k in item)):
                raise ValueError('user addresses require function, parameter, reason and validated_by')
            self.user_addresses.add((item['function'].split(':',1)[-1],item['parameter']))
        # Functions whose condition argument rejects the run when it holds (a model's sticky fault flag
        # that the replay checks): after such a call statement the condition is false.
        self.fault_assertions={};self.fault_assertion_items=list(fault_assertions or [])
        for item in self.fault_assertion_items:
            if (not isinstance(item,dict) or set(item)!={'function','condition_argument','reason','validated_by'} or type(item['condition_argument']) is not int or
                    item['condition_argument']<0 or not all(isinstance(item[k],str) and item[k] for k in ('function','reason','validated_by'))):
                raise ValueError('fault assertions require function, condition_argument, reason and validated_by')
            self.fault_assertions[item['function'].split(':',1)[-1]]=item['condition_argument']
        self._auto_objects={};self._auto_info={};self._auto_store={};self._auto_reads={};self._auto_late=False;self._auto_storage=None;self._auto_sites={};self._call_nodes=[]
        self.volatile_fields={}
        for item in volatile_fields or []:
            if set(item)!={'record','field','reason','validated_by'} or not all(isinstance(item[k],str) and item[k] for k in item):raise ValueError('volatile field classification requires record, field, reason and validated_by')
            self.volatile_fields[(item['record'],item['field'])]=dict(item)
        self.null_guard_proofs=[];self.masked_pointer_proofs=[];self.external_accesses=[]
        self.state_ranges=validate_state_ranges(state_ranges or []);self.values=Values(self)
        # Root parameter ranges the boundary enforces (writev's vlen: the binding admits at most 12 segments).
        self.argument_ranges={}
        for item in argument_ranges or []:
            if (not isinstance(item,dict) or set(item)!={'function','parameter','min','max','reason','validated_by'} or type(item['min']) is not int or
                    type(item['max']) is not int or not 0<=item['min']<=item['max'] or not item['reason'] or not item['validated_by']):
                raise ValueError('argument range requires function, parameter, min<=max, reason and validated_by')
            self.argument_ranges[(item['function'].split(':',1)[-1],item['parameter'])]=dict(item)
        # Allocators whose result is fresh memory the call writes before it reads: a summarized object of
        # `elements` `element_type` records backed by the listed context object.
        self.allocations={}
        for item in allocations or []:
            if (not isinstance(item,dict) or set(item)!={'function','element_type','elements','object','reason','validated_by'} or type(item['elements']) is not int or
                    item['elements']<=0 or not re.fullmatch(r'argument:ctx->[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*',str(item['object'])) or not item['reason'] or not item['validated_by']):
                raise ValueError('allocation requires function, element_type, elements, object, reason and validated_by')
            self.allocations[item['function'].split(':',1)[-1]]=dict(item)
        # Pointer fields whose non-null value is the address of an object of a declared type (kmem_cache_cpu.freelist).
        self.pointer_objects={}
        for item in pointer_objects or []:
            if (not isinstance(item,dict) or set(item)!={'record','field','object_type','reason','validated_by'} or not re.fullmatch(r'struct [A-Za-z_]\w*',str(item['record'])) or
                    not re.fullmatch(r'struct [A-Za-z_]\w*',str(item['object_type'])) or not item['reason'] or not item['validated_by']):
                raise ValueError('pointer object requires record, field, object_type, reason and validated_by')
            self.pointer_objects[(item['record'],item['field'])]=dict(item)
        self.allocation_uses=[];self.argument_range_uses=set()
        from entry_state_lists import validate as empty_list_contracts
        self.empty_list_heads=empty_list_contracts(empty_lists);self.empty_list_items=[dict(i) for i in empty_lists or []];self.list_proofs=[]
        self.deallocators={}
        for item in deallocators or []:
            if not isinstance(item,dict) or set(item)!={'function','parameter','reason','validated_by'} or not isinstance(item['parameter'],str) or not item['reason'] or not item['validated_by']:
                raise ValueError('deallocator requires function, parameter, reason and validated_by')
            self.deallocators[item['function'].split(':',1)[-1]]=dict(item)
        # Struct layouts by tag, for pointer fields of automatic records passed by value.
        self.record_layouts={};self._field_records={};self.record_decls={}
        for n in walk(tree):
            if n.get('kind')=='RecordDecl' and n.get('completeDefinition') and n.get('name'):
                self.record_decls.setdefault(n.get('tagUsed','struct')+' '+n['name'],n)
                for c in children(n):
                    if c.get('kind')=='FieldDecl':self._field_records[c['id']]=n.get('tagUsed','struct')+' '+n['name']
            if n.get('kind')=='RecordDecl' and n.get('completeDefinition') and n.get('name') and n.get('tagUsed')=='struct':
                layout=tuple((c.get('name'),type_of(c)) for c in children(n) if c.get('kind')=='FieldDecl')
                key='struct '+n['name'];self.record_layouts[key]=layout if self.record_layouts.get(key,layout)==layout else None
        self.fields={n["id"]:n for n in walk(tree) if n.get("kind")=="FieldDecl"};self.functions={};self.globals={};self.boundaries=boundaries or {};self.max_contexts=max_contexts
        self.reads=[];self.writes=[];self.calls=[];self.blockers=[];self.arguments=[];self.contexts=0;self.providers={};self.ranges=[];self.max_range_elements=max_range_elements;self.prune_written=prune_written
        self._local_volatile_storage={};self.local_volatile_proofs=[];self.user_address_proofs=[]
        self.scalar_addresses=[]
        self._self_recursion_syntax={};self.recursion_proofs=[]
        self.argument_objects=argument_objects or {}
        self.loop_index_sites={}
        self.loop_enum_declarations=[n for n in walk(tree) if n.get('kind')=='EnumDecl'];self.loop_enum_values=None
        self.preserve_write_state=preserve_write_state
        self.typedefs={(n.get('_translation_unit'),n['name']):type_of(n) for n in children(tree) if n.get('kind')=='TypedefDecl'}
        self.record_typedefs={(n.get('_translation_unit'),n['name']) for n in children(tree)
            if n.get('kind')=='TypedefDecl' and any(t.get('kind')=='RecordType' for t in walk(n))}
        for node in children(tree):
            if node.get('kind')=='FunctionDecl':
                if any(c.get('kind')=='CompoundStmt' for c in children(node)):self.functions[node['name']]=node
            elif node.get('kind')=='VarDecl':self.globals[node['id']]=node
        self._builtin_declarations={n['id']:n for n in children(tree) if n.get('kind')=='FunctionDecl' and n.get('name') in ('__builtin_expect',*COMPILE_TIME_BUILTINS)}
        self.linked_symbols=frozenset(linked_symbols) if linked_symbols is not None else None
        self._error_functions=set();self._external_declarations=set()
        for n in walk(tree):
            if n.get('kind')!='FunctionDecl':continue
            if any(c.get('kind')=='ErrorAttr' for c in children(n)):self._error_functions.add(n['id'])
            if not n.get('isImplicit') and not any(c.get('kind')=='CompoundStmt' for c in children(n)):self._external_declarations.add(n['id'])
        self.integer_bit_declarations={}
        for node in children(tree):
            signature=INTEGER_BIT_BUILTINS.get(node.get('name'))
            if node.get('kind')!='FunctionDecl' or signature is None or not node.get('isImplicit'):continue
            result,argument=signature
            attrs={c.get('kind') for c in children(node) if c.get('implicit') is True}
            if not {'BuiltinAttr','ConstAttr'}<=attrs or type_of(node)!=result+' ('+argument+')':continue
            if any(c.get('kind')=='CompoundStmt' for c in children(node)):continue
            parameters=[c for c in children(node) if c.get('kind')=='ParmVarDecl']
            if len(parameters)==1 and type_of(parameters[0])==argument:
                self.integer_bit_declarations[node['id']]=(node['name'],result,argument)
        # Merged internal objects already have TU-qualified names. External
        # objects may have compatible incomplete and complete declarations.
        global_declarations={}
        for node in self.globals.values():global_declarations.setdefault(node['name'],[]).append(node)
        self.completed_global_arrays={}
        for name,nodes in global_declarations.items():
            shapes=[declared_array_shape(type_of(node)) for node in nodes]
            if any(shape is None for shape in shapes):continue
            elements=[self.numeric_element_type(shape[0],node.get('_translation_unit')) for node,shape in zip(nodes,shapes)]
            if any(element is None for element in elements):continue
            complete={(element,shape[1]) for element,shape in zip(elements,shapes) if shape[1][0] is not None}
            if len(complete)!=1:continue
            element,dimensions=next(iter(complete))
            if not all(n>0 for n in dimensions):continue
            if any(base!=element or shape[1][1:]!=dimensions[1:] or shape[1][0] not in (None,dimensions[0]) for base,shape in zip(elements,shapes)):continue
            typ=element+''.join('['+str(n)+']' for n in dimensions)
            proof={'kind':'configured_composite_array_type','object':name,'type':typ,
                   'declarations':[{'type':type_of(node),'element_type':base,'location':self.location(node)} for node,base in zip(nodes,elements)]}
            for node,shape in zip(nodes,shapes):
                if shape[1][0] is None:self.completed_global_arrays[node['id']]=proof
        self.immutable_globals={}
        for name,nodes in global_declarations.items():
            definitions=[n for n in nodes if n.get('init')]
            if len(definitions)!=1 or not all(type_of(n).startswith('const ') and not n.get('tls') and
                all(c.get('kind') in ('VisibilityAttr','AlignedAttr') for c in children(n) if c.get('kind','').endswith('Attr')) for n in nodes):continue
            node=definitions[0];typ=type_of(node)
            parts=[c for c in children(node) if not c.get('kind','').endswith('Attr')]
            if len(parts)!=1 or node.get('storageClass')=='extern':continue
            if arithmetic_scalar(typ):
                if any(type_of(n)!=typ for n in nodes):continue
                kind='defined_const_numeric_scalar';initializer=constant_initializer(parts[0]);expected=typ.removeprefix('const ')
            elif numeric_array(typ):
                element,dimensions=numeric_array(typ)
                shapes=[declared_array_shape(type_of(n)) for n in nodes]
                if any(s is None or s[0]!=element or s[1][1:]!=dimensions[1:] or s[1][0] not in (None,dimensions[0]) for s in shapes):continue
                kind='defined_const_numeric_array';initializer=constant_array_initializer(parts[0]);expected=typ
            else:continue
            if initializer is None or type_of(initializer)!=expected:continue
            proof={'kind':kind,'object':name,'type':typ,
                'initializer':initializer,'initializer_sha256':digest(json.dumps(initializer,sort_keys=True).encode()),'declaration_location':self.location(node)}
            for declaration in nodes:self.immutable_globals[declaration['id']]=proof
        self._referenced_globals=set()
        self.pointer_differences=[]
        self.pointer_comparisons=[]
        self.pointer_updates=[];self._pointer_update_syntax={}
        self._constant_record_declarations=tuple(n for n in children(tree) if n.get('kind')!='FunctionDecl')
        self._global_declarations=global_declarations
        for item in self._pointer_value_items:
            # Values of one pointer field: null or an object address aligned to `alignment`.
            if (set(item)!={'record','field','alignment','reason','validated_by'} or not all(isinstance(item[k],str) and item[k] for k in ('record','field','reason','validated_by')) or
                    type(item['alignment']) is not int or item['alignment']<2 or item['alignment']&(item['alignment']-1)):
                raise ValueError('pointer values require record, field, a power-of-two alignment, reason and validated_by')
            owners=[k for k,r in self.record_decls.items() if any(c.get('kind')=='FieldDecl' and c.get('name')==item['field'] for c in children(r))]
            record=self.record_decls.get(item['record'])
            field=next((c for c in children(record or {}) if c.get('kind')=='FieldDecl' and c.get('name')==item['field']),None)
            # Paths name fields, not records: the field name must belong to this record alone.
            if field is None or '*' not in type_of(field) or owners!=[item['record']]:raise ValueError('pointer values field must be a pointer member unique to its record: '+item['field'])
            self.pointer_values[item['field']]=item['alignment']
        from entry_state_const_graph import ConstGraph
        self.const_graph=ConstGraph(self);self.container_proofs=[];self._stable_bases={}
        self._derived_keys={};self._derived_pointers={};self.derived_proofs=[];self.span_proofs=[];self._mutation_nodes={}
        self._auto_scalars={};self._auto_scalar_reads={};self.branch_proofs=[];self._taken_arms={};self.quiet=0;self._visited_gotos={}
        self._flow={};self._flow_live=True;self._flow_off=0;self._flow_masks=[];self._flow_carried=[];self._flow_stable=[];self._flow_returns=[];self._flow_return_classes=[];self._return_values=[];self._last_return_values=None;self._recent_return={};self._prior_returns={};self._last_partition=None;self._recent_partition=None;self._flow_weak=0;self._pure={};self._written_fields={};self._decisions={};self._unreachable=set();self._prior_unreachable=frozenset();self._auto_written={};self._auto_scalar_written={};self._inline_cache={};self._goto_states={};self._prior_goto_states=None;self._optimistic=True
        self._constant_record_groups={name:nodes for name,nodes in global_declarations.items() if any(
            type_of(n).startswith('const ') and not arithmetic_scalar(type_of(n)) and not numeric_array(type_of(n)) and n.get('init') for n in nodes)}
        self._constant_records={};self._constant_record_index=None;self._constant_record_shapes={}
        # Parameters are automatic objects of their call too (C11 6.9.1p9): `&param` in a callee is that
        # frame's copy (is_valid_gup_args' &gup_flags), not the caller's value.
        self.automatic_scalars={n['id']:n for n in walk(tree) if n.get('kind') in ('VarDecl','ParmVarDecl') and
            n['id'] not in self.globals and n.get('storageClass') is None and not n.get('tls') and
            arithmetic_scalar(type_of(n)) and not re.search(r'\bconst\b',type_of(n)) and
            not any(c.get('kind')=='CleanupAttr' for c in children(n))}
        self.automatic_arrays={n['id']:n for n in walk(tree) if n.get('kind')=='VarDecl' and
            n['id'] not in self.globals and n.get('storageClass') is None and not n.get('tls') and
            fixed_array(type_of(n)) and
            not re.search(r'\bvolatile\b|_Atomic',type_of(n)) and
            not any(c.get('kind')=='CleanupAttr' for c in children(n))}
        # By-value record parameters whose address is taken (gup_fast_pte_range's &pmd): tracked like an
        # automatic record of their call, never as the root's argument.
        self.parameter_records={n['id']:n for n in walk(tree) if n.get('kind')=='ParmVarDecl' and
            '*' not in type_of(n) and '[' not in type_of(n) and
            (re.sub(r'^const\s+','',type_of(n)).startswith(('struct ','union ')) or
             (n.get('_translation_unit'),re.sub(r'^const\s+','',type_of(n))) in getattr(self,'record_typedefs',{})) and
            not re.search(r'\bvolatile\b|_Atomic',type_of(n))}
        self.automatic_records={n['id']:n for n in walk(tree) if n.get('kind')=='VarDecl' and
            n['id'] not in self.globals and n.get('storageClass') is None and not n.get('tls') and
            '*' not in type_of(n) and '[' not in type_of(n) and
            (re.sub(r'^const\s+','',type_of(n)).startswith(('struct ','union ')) or
             (n.get('_translation_unit'),re.sub(r'^const\s+','',type_of(n))) in self.record_typedefs) and
            not re.search(r'\bvolatile\b|_Atomic',type_of(n)) and
            not any(c.get('kind')=='CleanupAttr' for c in children(n))}
        # Clang 16 does not serialize compound-literal storage duration. C
        # literals lexically inside a function body have automatic duration;
        # file-scope literals must not be classified as automatic objects.
        self.automatic_compound_literals={}
        for name,function in self.functions.items():
            body=next(c for c in children(function) if c.get('kind')=='CompoundStmt')
            literals=(n for n in walk(body) if n.get('kind')=='CompoundLiteralExpr')
            for number,literal in enumerate(literals):
                if literal.get('storageClass') is None and not literal.get('tls') and literal.get('storageDuration') in (None,'automatic'):
                    self.automatic_compound_literals[literal['id']]='local:compound-literal:'+name+':'+str(number)
        for name,policy in self.boundaries.items():
            if policy.get('kind') not in ('object_provider','scalar_transcript','ordering_model','memory_model','value_model') or not policy.get('reason') or not policy.get('implementation'):
                raise ValueError('boundary '+name+' requires kind, reason and implementation')
            if (policy['kind']=='value_model')!=('semantics' in policy) or policy.get('semantics',VALUE_MODELS[0]) not in VALUE_MODELS:
                raise ValueError('boundary '+name+' value_model requires semantics in '+', '.join(VALUE_MODELS))
            if 'result' in policy and (policy['kind']!='memory_model' or policy['result']!='external_memory'):
                raise ValueError('boundary '+name+' result must be external_memory on a memory_model')
            for effect in ('reads','writes'):
                if effect in policy and (policy['kind']!='memory_model' or not isinstance(policy[effect],list) or
                        not all(type(i) is int and 0<=i<16 for i in policy[effect])):
                    raise ValueError('boundary '+name+' '+effect+' must list pointer argument indexes on a memory_model')
            if 'user_values' in policy and (not isinstance(policy['user_values'],list) or not set(policy['user_values'])<=set(policy.get('writes',[])) or
                    not all(type(i) is int for i in policy['user_values'])):
                raise ValueError('boundary '+name+' user_values must list written argument indexes')
            if 'spans' in policy and (policy['kind']!='memory_model' or not isinstance(policy['spans'],list) or not policy['spans'] or not all(
                    isinstance(span,dict) and set(span)-{'fill'}=={'pointer','length','access','objects'} and span.get('fill','data') in ('data','zero') and type(span['pointer']) is int and 0<=span['pointer']<16 and
                    type(span['length']) is int and 0<=span['length']<16 and span['access'] in ('read','write') and isinstance(span['objects'],list) and span['objects'] and
                    all(isinstance(o,str) and re.fullmatch(r'(?:automatic|global:[A-Za-z_]\w*|argument:[A-Za-z_]\w*(?:->|\.)[A-Za-z_][\w.>\[\]-]*)',o) for o in span['objects'])
                    for span in policy['spans'])):
                raise ValueError('boundary '+name+' spans must list pointer, length, access (read/write) and the checked objects')

    def boundary(self,name):
        return self.boundaries.get(name) or self.boundaries.get(name.split(':',1)[-1] if name else None)

    def numeric_element_type(self,typ,unit):
        """Resolve numeric typedefs in their own TU; never equate aliases by name."""
        qualifiers=set();seen=set()
        while True:
            match=re.match(r'^(const|volatile)\s+(.+)$',typ)
            if match:
                qualifiers.add(match[1]);typ=match[2];continue
            key=(unit,typ)
            if key not in self.typedefs:break
            if key in seen:return None
            seen.add(key);typ=self.typedefs[key]
        if not arithmetic_scalar(typ) or typ.startswith('const '):return None
        return ' '.join([*sorted(qualifiers),typ])

    def constant_record_index(self):
        if self._constant_record_index is not None:return self._constant_record_index
        records={};keys={}
        def bind(unit,key,node):
            if key:keys.setdefault((unit,key),{})[node['id']]=node
        def scan(sequence,unit):
            latest=None
            for node in sequence:
                own_unit=node.get('_translation_unit',unit)
                if node.get('kind')=='RecordDecl' and node.get('completeDefinition'):
                    records[node['id']]=node
                    if node.get('name'):bind(own_unit,'struct '+node['name'],node)
                    else:latest=node
                    scan(children(node),own_unit)
                elif node.get('kind') in ('FieldDecl','VarDecl') and latest is not None:
                    typ=type_of(node).removeprefix('const ');shape=declared_array_shape(typ)
                    key=record_type_key(shape[0] if shape else typ)
                    if key and key.startswith('struct @'):
                        loc=latest.get('loc',{});loc=loc.get('spellingLoc',loc)
                        match=re.search(r':([0-9]+):([0-9]+)$',key)
                        if (match and loc.get('col')==int(match[2]) and
                            (loc.get('line') is None or loc['line']==int(match[1]))):bind(own_unit,key,latest)
        scan(self._constant_record_declarations,None)
        self._constant_record_index=(keys,records)
        return self._constant_record_index

    def constant_record_shape(self,typ,unit,active=()):
        typ=typ.removeprefix('const ').strip()
        if len(active)>16:return None
        array=declared_array_shape(typ)
        if array:
            base,dimensions=array
            if any(n is None or n<=0 for n in dimensions):return None
            shape=self.constant_record_shape(base,unit,active)
            if shape is None:return None
            for count in reversed(dimensions):shape=dict(kind='array',elements=count,element=shape)
            return shape
        numeric=self.numeric_element_type(typ,unit)
        if numeric is not None:
            if 'volatile' in numeric:return None
            return dict(kind='scalar',type=numeric.removeprefix('const '))
        seen=set()
        while (unit,typ) in self.typedefs and (unit,typ) not in seen:
            seen.add((unit,typ));other=self.typedefs[unit,typ]
            if other==typ:break
            typ=other.removeprefix('const ')
        key=record_type_key(typ)
        keys,_=self.constant_record_index();matches=keys.get((unit,key),{})
        if len(matches)!=1:return None
        record=next(iter(matches.values()));identity=record['id']
        if identity in active or record.get('tagUsed')!='struct':return None
        if identity in self._constant_record_shapes:return self._constant_record_shapes[identity]
        fields=[]
        for field in children(record):
            if field.get('kind','').endswith('Attr'):return None
            if field.get('kind')!='FieldDecl':continue
            if not field.get('name') or field.get('isBitfield') or children(field):return None
            shape=self.constant_record_shape(type_of(field),unit,active+(identity,))
            if shape is None:return None
            fields.append(dict(name=field['name'],shape=shape))
        result=dict(kind='struct',type=key,fields=fields)
        if not valid_constant_shape(result):return None
        self._constant_record_shapes[identity]=result
        return result

    def canonical_record_initializer(self,node,shape,unit,budget=None):
        if budget is None:budget=[8192]
        budget[0]-=1
        if budget[0]<0 or self.constant_record_shape(type_of(node),unit)!=shape:return None
        if shape['kind']=='scalar':
            def numeric(value):
                budget[0]-=1
                typ=self.numeric_element_type(type_of(value),unit)
                if budget[0]<0 or typ is None or 'volatile' in typ:return None
                result={**value,'type':{'qualType':typ.removeprefix('const ')}}
                terms=[numeric(child) for child in children(value)]
                if any(term is None for term in terms):return None
                if terms:result['inner']=terms
                return result
            value=numeric(node)
            return constant_array_initializer(value) if value is not None else None
        result={'kind':node.get('kind'),'type':{'qualType':constant_shape_type(shape)}}
        if result['kind']=='ImplicitValueInitExpr' and not children(node):return result
        if result['kind']!='InitListExpr' or 'field' in node:return None
        if shape['kind']=='struct':
            terms=node.get('inner',[])
            if 'array_filler' in node or len(terms)!=len(shape['fields']):return None
            values=[self.canonical_record_initializer(term,field['shape'],unit,budget) for term,field in zip(terms,shape['fields'])]
            if any(v is None for v in values):return None
            result['inner']=values
        else:
            for key in ('inner','array_filler'):
                if key not in node:continue
                values=[self.canonical_record_initializer(term,shape['element'],unit,budget) for term in node[key]]
                if any(v is None for v in values):return None
                result[key]=values
        return constant_record_initializer(result,shape)

    def missing_constant_records(self,plan):
        """External numeric record leaves needing a positive C initializer."""
        required=set()
        for read in plan['entry_reads']:
            match=re.match(r'^global:([A-Za-z_]\w*)(?=$|[.\[])',read['path'])
            if not match or read.get('immutable_global'):continue
            name=match[1];nodes=self._global_declarations.get(name,[])
            if not nodes or any(n.get('init') for n in nodes):continue
            if arithmetic_scalar(type_of(nodes[0])) or numeric_array(type_of(nodes[0])):continue
            if not all(n.get('storageClass')=='extern' and type_of(n).startswith('const ') and not n.get('tls') and
                all(c.get('kind') in ('VisibilityAttr','AlignedAttr') for c in children(n) if c.get('kind','').endswith('Attr')) for n in nodes):continue
            shapes=[self.constant_record_shape(type_of(n),n.get('_translation_unit')) for n in nodes]
            if shapes[0] is not None and all(s==shapes[0] for s in shapes) and constant_record_leaf(read['path'],name,shapes[0])==read['type']:
                required.add(name)
        return sorted(required)

    def missing_constant_data(self,plan):
        """Also request scalar/array definitions whose storage was resolved.

        Incomplete arrays can fail before producing an entry-read path. Their
        declaration still must have been encountered by the address resolver.
        A fresh definition can supply an extent, never an index-range proof.
        """
        required=set(self.missing_constant_records(plan))
        for name in self._referenced_globals:
            if not re.fullmatch(r'[A-Za-z_]\w*',name):continue
            nodes=self._global_declarations[name]
            if any(n.get('init') for n in nodes):continue
            if not all(n.get('storageClass')=='extern' and type_of(n).startswith('const ') and not n.get('tls') and
                all(c.get('kind') in ('VisibilityAttr','AlignedAttr') for c in children(n) if c.get('kind','').endswith('Attr')) for n in nodes):continue
            types=[type_of(n) for n in nodes]
            if all(arithmetic_scalar(t) and t==types[0] for t in types):required.add(name);continue
            shapes=[declared_array_shape(t) for t in types]
            if any(s is None or not arithmetic_scalar(s[0]) for s in shapes):continue
            if all(s[0]==shapes[0][0] and s[1][1:]==shapes[0][1][1:] for s in shapes):required.add(name)
        return sorted(required)

    def constant_record_for(self,path,typ):
        match=re.match(r'^global:((?:tu[0-9]+:)?[A-Za-z_]\w*)(?=$|[.\[])',path)
        if not match or match[1] not in self._constant_record_groups:return None
        name=match[1]
        if name not in self._constant_records:
            nodes=self._constant_record_groups[name];proof=None
            definitions=[n for n in nodes if n.get('init')]
            if len(definitions)==1 and all(type_of(n).startswith('const ') and not n.get('tls') and
                all(c.get('kind') in ('VisibilityAttr','AlignedAttr') for c in children(n) if c.get('kind','').endswith('Attr')) for n in nodes):
                node=definitions[0];unit=node.get('_translation_unit')
                shapes=[self.constant_record_shape(type_of(n),n.get('_translation_unit')) for n in nodes]
                shape=shapes[0]
                parts=[n for n in children(node) if not n.get('kind','').endswith('Attr')]
                if shape is not None and all(s==shape for s in shapes) and len(parts)==1 and node.get('storageClass')!='extern':
                    initializer=self.canonical_record_initializer(parts[0],shape,unit)
                    if initializer is not None:
                        proof=dict(kind='defined_const_numeric_record',object=name,type='const '+constant_shape_type(shape),
                            schema=shape,schema_sha256=digest(json.dumps(shape,sort_keys=True).encode()),initializer=initializer,
                            initializer_sha256=digest(json.dumps(initializer,sort_keys=True).encode()),declaration_location=self.location(node))
            self._constant_records[name]=proof
        proof=self._constant_records[name]
        return proof if proof is not None and constant_record_leaf(path,name,proof['schema'])==typ else None

    def fresh(self):
        """Reuse immutable AST indexes while isolating each root's analysis state."""
        result=copy.copy(self)
        result._referenced_globals=set()
        result.pointer_differences=[]
        result.pointer_comparisons=[]
        result.pointer_updates=[];result.container_proofs=[];result._stable_bases={};result.list_proofs=[]
        result._derived_keys={};result._derived_pointers={};result.derived_proofs=[];result.span_proofs=[]
        result._auto_scalars={};result._auto_scalar_reads={};result.branch_proofs=[];result._taken_arms={};result.quiet=0;result._visited_gotos={}
        result._flow={};result._flow_live=True;result._flow_off=0;result._flow_masks=[];result._flow_carried=[];result._flow_stable=[];result._flow_returns=[];result._flow_return_classes=[];result._return_values=[];result._last_return_values=None;result._recent_return={};result._prior_returns={};result._last_partition=None;result._recent_partition=None;result._flow_weak=0;result._pure={};result._written_fields={};result._decisions={};result._unreachable=set();result._auto_written={};result._auto_scalar_written={};result._inline_cache={};result._goto_states={}
        for name in ('reads','writes','calls','blockers','arguments','ranges'):setattr(result,name,[])
        result.contexts=0;result.providers={};result.loop_index_sites={};result.alias_path_limit_observed=False;result._quiet_limits=[]
        result._effect_nodes_cache={};result._alias_program_cache={};result._return_program_cache={}
        result._expression_nodes_cache={};result._direct_calls_cache={};result._parameters_cache={}
        result._static_index_cache={};result._array_lvalue_cache={}
        result._bounded_pointer_keys={};result._bounded_pointers={};result._pointer_access_constants={};result._pointer_access_types={};result._pointer_scope_cache={};result._definite_pointer_cache={};result._pointer_initialization_environments={};result.pointer_initializations=[];result.pointer_returns=[];result.pointer_stores=[];result.index_values=[];result._local_index_definitions={};result._local_index_cache={};result._local_index_inputs={};result._local_index_declarations={}
        result._diagnostic_keys=set();result._diagnostic_nodes={}
        from entry_state_values import Values
        result.callback_uses=[];result._auto_objects={};result._auto_info={};result._auto_store={};result._auto_reads={};result._auto_late=False;result._auto_storage=None;result._auto_sites={};result._call_nodes=[]
        result._scalar_objects={};result._scalar_fields={};result.trap_proofs=[];result.tagged_pointer_proofs=[];result.ordering_asm_proofs=[];result.extent_assumptions=[];result._union_tags={};result.range_uses=set();result.assertion_uses=[];result.array_summaries=[];result.infeasible_accesses=[];result.automatic_views=[];result._context_calls={};result.allocation_uses=[];result.argument_range_uses=set();result.null_guard_proofs=[];result.masked_pointer_proofs=[];result.external_accesses=[];result.values=Values(result)
        result._local_volatile_storage={};result.local_volatile_proofs=[];result.user_address_proofs=[]
        result.scalar_addresses=[]
        result._self_recursion_syntax={};result.recursion_proofs=[]
        if hasattr(result,'root_aliases'):del result.root_aliases
        return result

    def argument_pointer_type(self,typ,unit=None):
        """Expose pointee qualifiers inherited from typedefs in binding types."""
        pointee=object_pointee(typ)
        for _ in range(16):
            if (unit,pointee) not in self.typedefs:return typ
            underlying=self.typedefs[unit,pointee]
            if any(c in underlying for c in '*[('):raise ValueError('argument pointee typedef is not a plain object: '+pointee)
            if re.search(r'\bvolatile\b',underlying):return None
            if re.search(r'\bconst\b',underlying) and not typ.startswith('const '):typ='const '+typ
            resolved=re.sub(r'^const\s+','',underlying)
            # Clang spells an anonymous record's terminal typedef using its
            # own name; it is a complete type, not a recursive alias chain.
            if resolved==pointee:return typ
            pointee=resolved
        raise ValueError('argument pointee typedef chain exceeds the supported limit')

    def state_range(self,member):
        """Declared range of an integer field read; its consumer validates live state against it."""
        if not self.state_ranges or member.get('kind')!='MemberExpr' or not children(member):return None
        typ=type_of(children(member)[0]).strip()
        if member.get('isArrow'):
            if not typ.endswith('*'):return None
            typ=typ[:-1].strip()
        typ=re.sub(r'^(?:const|volatile)\s+','',typ)
        contract=self.state_ranges.get((typ,member.get('name')))
        if contract is None:contract=self.nested_state_range(member)
        if contract is None or self.fields.get(member.get('referencedMemberDecl'),{}).get('isBitfield'):return None
        return contract

    def nested_state_range(self,member):
        """A range declared on a member of a member (`struct futex_hash_bucket` `waiters.counter`).

        It applies when the inner record is reached as that member of the outer record: `(&o->m)->f`,
        `o->m.f` or `o.m.f`. The inner record alone (`atomic_t`) may hold unrelated counters.
        """
        base=unwrap(children(member)[0])
        if member.get('isArrow'):
            if base.get('kind')!='UnaryOperator' or base.get('opcode')!='&' or not children(base):return None
            base=unwrap(children(base)[0])
        if base.get('kind')!='MemberExpr' or not children(base):return None
        typ=type_of(children(base)[0]).strip()
        if base.get('isArrow'):
            if not typ.endswith('*'):return None
            typ=typ[:-1].strip()
        typ=re.sub(r'^(?:const|volatile)\s+','',typ)
        return self.state_ranges.get((typ,base.get('name')+'.'+member.get('name')))

    def context_ranges(self,stack):
        return self._context_calls.get(tuple(stack),{})

    def enter_call(self,name,call,stack):
        from entry_state_values import ArgumentRanges
        self._context_calls[tuple(stack+[name])]=ArgumentRanges(self.values,call,stack[-1],self.context_ranges(stack),self.functions[name])

    def function_facts(self,node,stack):
        name=stack[-1] if stack else None
        if name not in self.functions:return None
        facts=self.values.facts_for(name)
        return facts if facts.contains(node) else None

    def masked_pointer(self,node,stack):
        from entry_state_values import masked_pointer
        facts=self.function_facts(node,stack)
        return masked_pointer(node,stack[-1],self.values,facts) if facts is not None else None

    # Stack objects whose address is passed to callees: a field store per object.
    def auto_origin(self,key,stack):
        """Token for an automatic record declared in the innermost frame of `stack` that holds it."""
        owner=None
        for index in range(len(stack),0,-1):
            name=stack[index-1]
            if name in self.functions and (key in self.values.facts_for(name).declarations or key in self.parameter_records and any(c.get('id')==key for c in children(self.functions[name]))):
                owner=tuple(stack[:index]);break
        if owner is None:return None
        token=self._auto_objects.get((owner,key))
        if token is None:
            token='auto:%d'%len(self._auto_objects);self._auto_objects[(owner,key)]=token
            declaration=self.values.facts_for(owner[-1]).declarations.get(key)
            # A parameter holds its argument from the call on: initialized.
            self._auto_info[token]=dict(owner=owner,declaration=key,initialized=declaration is None or bool(children(declaration)))
        return token
    def summary_array(self,key):
        """(element type, element count, element record or None) for an automatic one-dimensional array
        of pointers or of records with pointer fields, which is tracked as one summarized object."""
        cache=self.__dict__.setdefault('_summary_arrays',{})
        if key not in cache:
            result=None;declaration=self.automatic_arrays.get(key)
            shape=declared_array_shape(type_of(declaration)) if declaration is not None else None
            if shape is not None and len(shape[1])==1 and shape[1][0]:
                element=shape[0];record=self.record_declaration(element) if '*' not in element else None
                pointers=object_pointer_element(element) or (record is not None and any('*' in f[1] and '(' not in f[1] for f in self.flat_fields(record)))
                if pointers:result=(element,shape[1][0],record)
            cache[key]=result
        return cache[key]
    def summary_token(self,path):
        """The summarized array a pointer value `auto:N` points into (any element or one past), or None."""
        return path if path in self._auto_info and self._auto_info[path].get('summary') else None
    def summary_origin(self,key,node,stack):
        """`auto:N` for a pointer into the summarized automatic array `key` (its decay)."""
        shape=self.summary_array(key)
        if shape is None:return None
        token=self.auto_origin(key,stack)
        if token is None:return None
        info=self._auto_info[token]
        if not info.get('summary'):
            info['summary']=dict(element_type=shape[0],elements=shape[1])
            self.array_summaries.append(dict(kind='automatic_array_summary',function=info['owner'][-1],call_path=list(info['owner']),
                array=self.values.facts_for(info['owner'][-1]).declarations[key].get('name'),element_type=shape[0],elements=shape[1],location=self.location(node),
                assumptions=['element accesses stay inside the array (kernel memory safety)','an element is read only after it is stored'],
                validated_by='the reduced replay image initializes automatic storage with a pattern (-ftrivial-auto-var-init=pattern): an element read before its store yields the pattern, which no admitted object holds'))
        return token
    def summary_paths(self,paths):
        """The summarized arrays `paths` all point into, or None."""
        return frozenset(paths) if paths and all(self.summary_token(p) for p in paths) else None
    def summary_arithmetic(self,node,env,stack):
        """`p + k`, `p - k` and `&p[k]` on a pointer into a summarized array stay that array."""
        node=unwrap(node);terms=children(node)
        if node.get('kind')=='BinaryOperator' and node.get('opcode') in ('+','-') and len(terms)==2:
            pointers=[t for t in terms if '*' in type_of(t)]
            if len(pointers)==1:
                values=self.resolve(pointers[0],env,stack)
                # Arithmetic on a null pointer is undefined (C11 6.5.6): a null alternative has no result.
                found=self.summary_paths(values-{'null',INFEASIBLE})
                if found is not None:
                    if 'null' in values:self.derived_proofs.append(dict(kind='null_pointer_arithmetic_excluded',function=stack[-1],call_path=stack,location=self.location(node),
                        reason='pointer arithmetic on a null pointer is undefined behavior (C11 6.5.6p8); only the summarized arrays remain'))
                    return set(found)
            if len(pointers)==2 and node.get('opcode')=='-':
                left,right=(self.summary_paths(self.resolve(t,env,stack)) for t in terms)
                if left is not None and left==right:return set()
        return None
    def auto_record(self,token):
        """The record declaration whose fields an automatic object holds (a summarized array's element)."""
        info=self._auto_info[token]
        if info.get('summary'):return self.record_declaration(info['summary']['element_type'])
        declaration=next((n for n in self.values.facts_for(info['owner'][-1]).order if n.get('id')==info['declaration']),None)
        return self.record_declaration(type_of(declaration)) if declaration is not None else None
    def escaped_record(self,node,stack):
        """An automatic record whose address is taken in its function: tracked through an auto origin."""
        if node.get('kind')!='DeclRefExpr':return None
        key=node.get('referencedDecl',{}).get('id')
        parameter=key in self.parameter_records and key not in self.automatic_records
        if (key not in self.automatic_records and not parameter) or not stack or stack[-1] not in self.functions:return None
        if parameter and (len(stack)<2 or not any(c.get('id')==key for c in children(self.functions[stack[-1]]))):return None
        if key not in self.values.facts_for(stack[-1]).escaped:return None
        return self.auto_origin(key,stack)
    def escaped_pointer_local(self,node,stack):
        """A local pointer whose address is taken: a one-field automatic object (field '*')."""
        if node.get('kind')!='DeclRefExpr' or not stack or stack[-1] not in self.functions:return None
        declaration=node.get('referencedDecl',{});key=declaration.get('id')
        typ=type_of(node)
        if declaration.get('kind')!='VarDecl' or key in self.globals or '*' not in typ or '(' in typ or '[' in typ:return None
        facts=self.values.facts_for(stack[-1])
        if key not in facts.escaped:return None
        local=facts.declarations.get(key)
        if local is None or local.get('storageClass') is not None or local.get('tls'):return None
        return self.auto_origin(key,stack)
    @staticmethod
    def auto_key(path):
        # *(&field) is the field: a pointer to a member is spelled by that member's path.
        while path.startswith('*(') and path.endswith(')') and AUTO_PATH.fullmatch(path[2:-1]) and AUTO_PATH.fullmatch(path[2:-1])[2]:
            path=path[2:-1]
        match=AUTO_PATH.fullmatch(path)
        if match and not match[2] and path.startswith('*(auto:') and path.endswith(')'):return 'auto:'+match[1],'*'
        if not match or not match[2]:return None
        return 'auto:'+match[1],re.sub(r'->|\.','.',match[2]).strip('.')
    def flat_fields(self,declaration,depth=0):
        """(name, type, owner record, union?) for fields, with anonymous members flattened."""
        if declaration is None or depth>8:return []
        out=[];anonymous=None;union=declaration.get('tagUsed')=='union'
        for child in children(declaration):
            if child.get('kind')=='RecordDecl':
                if not child.get('name'):anonymous=child
                continue
            if child.get('kind')!='FieldDecl':continue
            if not child.get('name'):
                out.extend(self.flat_fields(anonymous,depth+1) if anonymous is not None else []);continue
            out.append((child['name'],type_of(child),child.get('id'),union))
        return out
    def record_declaration(self,typ):
        return self.record_decls.get(re.sub(r'^(?:const |volatile )+','',(typ or '').strip()))
    def flat_initializer(self,declaration,node,env,stack,depth=0):
        """Pointer-field values of an initializer, flattened like flat_fields; unions alias their pointer members."""
        if declaration is None or depth>8:return None
        while node.get('kind') in ('ParenExpr','ConstantExpr') or node.get('kind')=='ImplicitCastExpr' and node.get('castKind') in ('NoOp','LValueToRValue'):
            if not children(node):return None
            node=children(node)[0]
        if node.get('kind')=='CompoundLiteralExpr' and children(node):node=children(node)[0]
        pointers=[f for f in self.flat_fields(declaration) if '*' in f[1] and '(' not in f[1]]
        if node.get('kind')=='ImplicitValueInitExpr':return {f[0]:{'null'} for f in pointers}
        if node.get('kind')!='InitListExpr':return None
        members=[];anonymous=None
        for child in children(declaration):
            if child.get('kind')=='RecordDecl':
                if not child.get('name'):anonymous=child
                continue
            if child.get('kind')=='FieldDecl':members.append((child,anonymous if not child.get('name') else None))
        values={}
        def assign(member,record,term):
            if record is not None:
                nested=self.flat_initializer(record,term,env,stack,depth+1)
                if nested is None:return False
                values.update(nested);return True
            if '*' in type_of(member) and '(' not in type_of(member):
                found=self.resolve(term,env,stack)
                values[member['name']]=found or ({'null'} if term.get('kind')=='ImplicitValueInitExpr' or (lambda n:n.get('kind')=='IntegerLiteral' and n.get('value')=='0')(unwrap(term)) else {'unresolved:auto-field'})
            return True
        if declaration.get('tagUsed')=='union':
            chosen=node.get('field',{}).get('id');terms=children(node)
            for member,record in members:
                if member.get('id')==chosen and terms:
                    if not assign(member,record,terms[0]):return None
                    # Direct pointer members share the chosen member's bits at offset 0.
                    initialized=[v for k,v in values.items()]
                    if member.get('name') and '*' in type_of(member):
                        for name,typ,_,union in pointers:
                            if union and name not in values:values[name]=set(values[member['name']])
                    return values
            return None
        terms=children(node)
        if len(terms)!=len(members):return None
        for (member,record),term in zip(members,terms):
            if not assign(member,record,term):return None
        return values
    def tag_fields(self,declaration):
        """Integer fields of a record (outside unions) that the program writes only by whole-record
        stores (`*i = (struct T){.type = X, ...}`): they stay as set with the union bits stored beside them."""
        cache=self.__dict__.setdefault('_tag_field_cache',{})
        if declaration is None:return ()
        key=declaration.get('id')
        if key not in cache:
            written=self.__dict__.get('_field_level_writes')
            if written is None:
                written=set()
                for function in self.functions.values():
                    for n in walk(function):
                        kind=n.get('kind');terms=children(n)
                        target=None
                        if kind in ('BinaryOperator','CompoundAssignOperator') and n.get('opcode','').endswith('=') and n.get('opcode') not in ('==','!=','<=','>=') and terms:target=terms[0]
                        elif kind=='UnaryOperator' and n.get('opcode') in ('++','--','&') and terms:target=terms[0]
                        target=unwrap(target) if target is not None else None
                        if target is not None and target.get('kind')=='MemberExpr':written.add(target.get('referencedMemberDecl'))
                self._field_level_writes=written
            from entry_state_values import integer_type
            cache[key]=tuple(f[0] for f in self.flat_fields(declaration) if integer_type(f[1]) and not f[3] and f[2] not in written)
        return cache[key]
    def stores_record(self,node,record_type,active=frozenset()):
        """Can `node` (or a function it calls) store a whole `record_type` object (`*p = (struct T){...}`)?"""
        cache=self.__dict__.setdefault('_record_store_cache',{})
        for n in walk(node):
            kind=n.get('kind')
            if kind=='BinaryOperator' and n.get('opcode')=='=' and children(n) and re.sub(r'^(?:const |volatile )+','',type_of(children(n)[0]).strip())==record_type:return True
            if kind=='CallExpr':
                name=callee(n)
                if name is None or name not in self.functions:
                    if name is None or not self.boundary(name):return True
                    continue
                if name in active:continue
                key=(name,record_type)
                if key not in cache:cache[key]=self.stores_record(self.functions[name],record_type,active|{name})
                if cache[key]:return True
        return False
    def union_fields(self,declaration):
        return {f[0] for f in self.flat_fields(declaration) if f[3] and '*' in f[1] and '(' not in f[1]}
    def current_tag(self,token,declaration):
        """The tag fields' current singleton values in this object (fields with unknown values are left out)."""
        tag=[]
        for field in self.tag_fields(declaration):
            value=self.flow_value((token,field));interval=value[1] if value is not None and value[0]=='i' else self._auto_scalars.get((token,field))
            if isinstance(interval,tuple) and interval[0]==interval[1]:tag.append((field,interval[0]))
        return frozenset(tag)
    def tag_union_values(self,token,field,values,tag):
        """Record the tag-field values these union-member values were stored beside."""
        tags=self.__dict__.setdefault('_union_tags',{}).setdefault((token,field),{})
        for v in values:tags.setdefault(v,set()).add(tag)
    def union_filter(self,token,field,values):
        """Values of a union member whose recorded tags agree with the tag fields' current values."""
        tags=self.__dict__.get('_union_tags',{}).get((token,field))
        if not tags:return values
        declaration=self.auto_record(token)
        current={}
        for f in self.tag_fields(declaration):
            value=self.flow_value((token,f));interval=value[1] if value is not None and value[0]=='i' else None
            if isinstance(interval,tuple):current[f]=interval
        if not current:return values
        def agrees(tag):return all(f not in current or current[f][0]<=x<=current[f][1] for f,x in tag)
        kept={v for v in values if v not in tags or any(agrees(t) for t in tags[v])}
        return kept or values
    def owner_site(self,token,node,stack):
        """The node in the owning function through which this access happens (itself or a call site)."""
        owner=self._auto_info[token]['owner']
        if len(stack)<=len(owner) or len(self._call_nodes)<len(owner):return node
        return self._call_nodes[len(owner)-1]
    RECURSIVE_CHAIN=re.compile(r'(->[A-Za-z_]\w*)\1{2,}')
    def auto_write(self,token,field,paths,node=None,stack=None,strong=False):
        key=(token,field)
        # A summarized array's field stands for every element: a store updates one of them.
        if self._auto_info.get(token,{}).get('summary'):strong=False
        # A walk along a recursive link (node->parent->parent...) would grow a stored value by one
        # step per pass and never reach a fixpoint: three equal steps widen to an unknown origin.
        if any(self.RECURSIVE_CHAIN.search(p) for p in paths):
            paths={'unresolved:recursive-chain' if self.RECURSIVE_CHAIN.search(p) else p for p in paths}
        self.flow_write(key,'p',paths,strong)
        self._auto_written[key]=self._auto_written.get(key,set())|set(paths)
        if node is not None:
            site=self.owner_site(token,node,stack)
            if all(site is not other for other in self._auto_sites.setdefault(key,[])):self._auto_sites[key].append(site)
        previous=self._auto_store.get(key,set());combined=previous|paths
        if combined!=previous:
            if key in self._auto_reads and len(combined)>self._auto_reads[key]:self._auto_late=True
            self._auto_store[key]=combined
    def auto_read(self,token,field,node=None,stack=None):
        key=(token,field);values=self._auto_store.get(key)
        self._auto_reads[key]=max(self._auto_reads.get(key,-1),len(values) if values else 0)
        flow=self.flow_value(key)
        # An empty flow set holds no value at all (nothing stored on the path yet), never "no pointer": fall back.
        if flow is not None and flow[0]=='p' and flow[1]:return self.union_filter(token,field,set(flow[1]))
        if not values:return {'unresolved:auto-field'}
        values=self.union_filter(token,field,set(values))
        info=self._auto_info[token]
        # A summarized array's elements are read only after a store: its stated (replay-checked) assumption.
        if not info.get('initialized') and node is not None and not info.get('summary'):
            # Without an initializer the field is indeterminate unless a write dominates this read.
            site=self.owner_site(token,node,stack);facts=self.values.facts_for(info['owner'][-1])
            direct=field=='*' and site is node and facts.contains(node) and facts.dominated(node,info['declaration'])
            if not direct and not any(facts.dominates(write,site) for write in self._auto_sites.get(key,())):return set(values)|{'unresolved:indeterminate'}
        return set(values)
    # Flow-sensitive values of automatic-record fields, in visit order (see docs: flow state).
    # self._flow maps (token, field) to ('p', pointer values) or ('i', interval or None); an
    # absent key falls back to the union over every write. Loops and labels drop the keys
    # they can carry; calls join their return states.
    @staticmethod
    def flow_join_values(kind,a,b):
        if kind=='p':return frozenset(a)|frozenset(b)
        return None if a is None or b is None else (min(a[0],b[0]),max(a[1],b[1]))
    def flow_carried(self,token,key=None):
        return any(token in carried for carried in self._flow_carried) and not (key is not None and any(key in stable for stable in self._flow_stable))
    def flow_write(self,key,kind,value,strong):
        if self.flow_carried(key[0],key):self._flow.pop(key,None);return
        if strong and not self._flow_weak:self._flow[key]=(kind,frozenset(value) if kind=='p' else value);return
        old=self._flow.get(key)
        if old is not None and old[0]=='u':self._flow[key]=('u',None)
        elif old is not None:self._flow[key]=(kind,self.flow_join_values(kind,old[1],frozenset(value) if kind=='p' else value))
    def flow_value(self,key):
        if self._flow_off or not self._flow_live or self.flow_carried(key[0],key):return None
        # Inside a callee's out-of-order alias closure, keys it may store are unknown.
        if key[0]!='PL' and any(set(key[1].split('.'))&mask for mask in self._flow_masks):return None
        value=self._flow.get(key)
        return value if value is not None and value[0]!='u' else None
    def overwritten_after(self,call,token,prefix,env,stack):
        """Fields of a stack object that a later statement of the call's block assigns before anything can read them.

        The call (memset) is a statement of a compound block. Each later top-level statement up to an assignment
        `p->field = value` (p resolving to the object) must not mention the field, and no call there may receive a
        pointer to the object: then the zero the call stored in that field is never read."""
        facts=self.function_facts(call,stack)
        if facts is None or facts.has_labels:return set()
        statement=call;parent=facts.parent.get(id(statement))
        while parent is not None and parent.get('kind') in ('ImplicitCastExpr','ParenExpr','CStyleCastExpr'):statement=parent;parent=facts.parent.get(id(statement))
        if parent is None or parent.get('kind')!='CompoundStmt':return set()
        terms=children(parent);index=next(i for i,t in enumerate(terms) if t is statement)
        found=set();blocked=set()
        object_paths=lambda n:{v for v in self.resolve(n,env,stack) if re.match(r'^(?:\*\()*'+re.escape(token)+r'(?![\d])',v)}
        self.quiet+=1
        try:
            for later in terms[index+1:]:
                if later.get('kind') not in ('BinaryOperator','CompoundAssignOperator','UnaryOperator','CallExpr','DeclStmt','IfStmt','ImplicitCastExpr','CStyleCastExpr') or any(n.get('kind') in ('GotoStmt','ReturnStmt','LabelStmt') for n in walk(later)):break
                names={n.get('name') for n in walk(later) if n.get('kind')=='MemberExpr'}
                if any(n.get('kind')=='CallExpr' and any('*' in type_of(a) and object_paths(a) for a in children(n)[1:]) for n in walk(later)):break
                plain=unwrap(later)
                if plain.get('kind')=='BinaryOperator' and plain.get('opcode')=='=' and unwrap(children(plain)[0]).get('kind')=='MemberExpr':
                    left=unwrap(children(plain)[0]);storage=self.storage_paths(left,env,stack)
                    keys={self.auto_key(p) for p in storage}
                    if len(storage)==1 and all(k is not None and k[0]==token for k in keys) and left.get('name') not in {n.get('name') for n in walk(children(plain)[1]) if n.get('kind')=='MemberExpr'}:
                        field=next(iter(keys))[1]
                        if field not in blocked:found.add(field)
                blocked|={f for (t,f) in self._auto_store if t==token and f.rsplit('.',1)[-1] in names}-found
        finally:self.quiet-=1
        if found:self.span_proofs.append(dict(kind='dead_zero_fill',function=stack[-1],call_path=stack,location=self.location(call),object=token,fields=sorted(found),
            evidence='a later statement of the block assigns each field before any read of it or any call receiving the object'))
        return found
    def always_rejects(self,name):
        """Does the body of `name` call a fault assertion with a nonzero constant condition, unconditionally,
        before any return (models.c's `linux_assert(1)` fault models)?"""
        cache=self.__dict__.setdefault('_always_rejects',{})
        if name not in cache:
            cache[name]=False;function=self.functions.get(name)
            body=next((c for c in children(function) if c.get('kind')=='CompoundStmt'),None) if function else None
            for statement in children(body) if body else []:
                if statement.get('kind')=='ReturnStmt' or any(n.get('kind') in ('ReturnStmt','GotoStmt','LabelStmt') for n in walk(statement)):break
                call=unwrap(statement)
                if call.get('kind')=='CallExpr' and callee(call).split(':',1)[-1] in self.fault_assertions:
                    index=self.fault_assertions[callee(call).split(':',1)[-1]];arguments=children(call)[1:]
                    bounds=self.constant_interval(arguments[index]) if index<len(arguments) else None
                    if bounds is not None and bounds[0]>0:cache[name]=True;break
        return cache[name]
    def loop_writes_no_stack_objects(self,loop,env,stack):
        facts=self.function_facts(loop,stack)
        if facts is None or facts.has_labels:return False
        for n in walk(loop):
            kind=n.get('kind');terms=children(n)
            if kind in ('BinaryOperator','CompoundAssignOperator') and n.get('opcode','').endswith('=') and n.get('opcode') not in ('==','!=','<=','>=') or kind=='UnaryOperator' and n.get('opcode') in ('++','--'):
                target=unwrap(terms[0]) if terms else {}
                key=target.get('referencedDecl',{}).get('id') if target.get('kind')=='DeclRefExpr' else None
                if key is None or key in self.globals or key in facts.escaped or key not in facts.declarations and target.get('referencedDecl',{}).get('kind')!='ParmVarDecl':return False
            elif kind in ('GCCAsmStmt','MSAsmStmt','StmtExpr'):return False
            elif kind=='CallExpr':
                self.quiet+=1
                try:
                    for argument in terms[1:]:
                        if '*' in type_of(argument) and any(re.match(r'^(?:\*\()*auto:\d+',v) or v.startswith('unresolved:') for v in self.resolve(argument,env,stack)):return False
                finally:self.quiet-=1
        return True
    def flow_snapshot(self):return (dict(self._flow),self._flow_live)
    def flow_restore(self,state):self._flow=dict(state[0]);self._flow_live=state[1]
    def flow_join(self,states):
        live=[f for f,l in states if l]
        if not live:self._flow={};self._flow_live=False;return
        result={}
        for key in set.intersection(*(set(f) for f in live)):
            values=[f[key] for f in live]
            # A value no state changed keeps its identity (return partitions test it).
            if all(v is values[0] for v in values):result[key]=values[0];continue
            if any(v[0]!=values[0][0] for v in values) or values[0][0]=='r':continue
            joined=values[0][1]
            for v in values[1:]:joined=self.flow_join_values(values[0][0],joined,v[1])
            result[key]=(values[0][0],joined)
        self._flow=result;self._flow_live=True
    def flow_reset(self,stack,label=None):
        """A label or case: control may also arrive from a jump.

        A label joins the fall-through state with the states the previous pass recorded at
        the gotos that jump to it (an unvisited goto was unreachable); without a previous
        pass, or for a case label, every value falls back to its union over all writes."""
        # Integer locals of enclosing frames cannot change inside this function (they do not escape).
        kept={k:v for k,v in self._flow.items() if k[0] in ('L','PL') and k[1]!=tuple(stack)}
        if label is not None and (self._prior_goto_states is not None or self._optimistic):
            states=[self.flow_snapshot()] if self._flow_live else []
            states+=[state for (target,context),state in (self._prior_goto_states or {}).items() if target==label and context==tuple(stack)]
            if states:
                self.flow_join(states);self._flow.update(kept);return
        self._flow=dict(kept);self._flow_live=True
    def flow_record_goto(self,label,stack):
        if not self._flow_live:return
        key=(label,tuple(stack));state=self.flow_snapshot()
        if key in self._goto_states:
            previous=self._goto_states[key];self.flow_join([previous,state]);state=self.flow_snapshot()
        self._goto_states[key]=state
    def local_flow_key(self,stack,key):return ('L',tuple(stack),key)
    def local_flow(self,stack,key):
        """The flow interval of an integer local of frame `stack`, if known on this path."""
        if self._flow_off or any(self._flow_masks) or not self._flow_live:return 'unset'
        value=self._flow.get(self.local_flow_key(stack,key))
        return value[1] if value is not None and value[0]!='u' else 'unset'
    def flow_interval(self,expression,env,stack):
        """The interval of an integer expression here (flow values included), or None."""
        bounds=self.constant_interval(expression)
        if bounds is not None:return bounds
        if not stack or stack[-1] not in self.functions or not self.values.facts_for(stack[-1]).contains(expression):return None
        self.values.pointer_env.append(env);self.values.call_stack.append(list(stack));self.quiet+=1
        try:bounds,_=self.values.interval(expression,stack[-1],self.context_ranges(stack))
        finally:self.values.pointer_env.pop();self.values.call_stack.pop();self.quiet-=1
        return tuple(bounds) if bounds is not None else None
    def integer_local(self,node,stack):
        """The declaration id of a non-escaped integer local or parameter of the current frame."""
        from entry_state_values import integer_type
        if node.get('kind')!='DeclRefExpr' or not stack or stack[-1] not in self.functions:return None
        declaration=node.get('referencedDecl',{});key=declaration.get('id')
        if declaration.get('kind') not in ('VarDecl','ParmVarDecl') or key in self.globals or not integer_type(type_of(node)):return None
        facts=self.values.facts_for(stack[-1])
        if key in facts.escaped or 'volatile' in type_of(node):return None
        local=facts.declarations.get(key)
        if local is not None and (local.get('storageClass') is not None or local.get('tls')):return None
        return key
    def local_flow_write(self,stack,key,interval):
        if self._flow_weak:self._flow.pop(self.local_flow_key(stack,key),None);return
        self._flow[self.local_flow_key(stack,key)]=('i',interval)
    @staticmethod
    def assigned_local(node):
        terms=children(node)
        if not terms or not (node.get('kind') in ('BinaryOperator','CompoundAssignOperator') and node.get('opcode','').endswith('=') and node.get('opcode') not in ('==','!=','<=','>=') or
                node.get('kind')=='UnaryOperator' and node.get('opcode') in ('++','--')):return None
        target=unwrap(terms[0])
        return target.get('referencedDecl',{}).get('id') if target.get('kind')=='DeclRefExpr' else None
    def pointer_local_key(self,node,stack):
        """('PL', frame, id): the flow key of a pointer local or parameter whose address is never taken."""
        node=unwrap(node)
        if node.get('kind')!='DeclRefExpr' or not stack or stack[-1] not in self.functions:return None
        declaration=node.get('referencedDecl',{});key=declaration.get('id')
        typ=type_of(node)
        if declaration.get('kind') not in ('VarDecl','ParmVarDecl') or key in self.globals or '*' not in typ or '(' in typ or '[' in typ:return None
        facts=self.values.facts_for(stack[-1])
        if key in facts.escaped or (declaration.get('kind')=='VarDecl' and key not in facts.declarations):return None
        return ('PL',tuple(stack),key)
    def pointer_local_write(self,key,values):
        """A store to a pointer local: its flow value is now exactly these values. Values that only the
        alias closure resolves well (pointer arithmetic: derived and bounded pointers) leave none."""
        if key is None:return
        # Bounded cursors have a separate versioned update certificate. A flow value seeded at
        # declaration must never hide later versions or an out-of-bounds alternative.
        plain=values and not any(re.search(r'(?:^|\*\()(?:unresolved:|derived-pointer:|bounded-pointer:|argument:|local:)',v) for v in values)
        if self._flow_live and plain:self._flow[key]=('p',frozenset(values))
        else:self._flow.pop(key,None)
    def local_null_tests(self,condition,truth,stack):
        """(pointer-local key, nonnull) pairs that `condition` having `truth` implies."""
        from entry_state_values import condition as strip,is_null
        node=strip(condition);kind=node.get('kind');op=node.get('opcode');terms=children(node)
        if kind=='UnaryOperator' and op=='!' and len(terms)==1:return self.local_null_tests(terms[0],not truth,stack)
        if kind=='BinaryOperator' and op in ('&&','||') and len(terms)==2:
            return [t for term in terms for t in self.local_null_tests(term,truth,stack)] if (op=='&&')==truth else []
        if kind=='BinaryOperator' and op in ('==','!=') and len(terms)==2:
            for pointer,other in (terms,terms[::-1]):
                if is_null(other):
                    key=self.pointer_local_key(pointer,stack)
                    return [(key,(op=='!=')==truth)] if key is not None else []
            return []
        key=self.pointer_local_key(node,stack) if '*' in type_of(node) else None
        return [(key,truth)] if key is not None else []
    def null_tests(self,condition,truth,stack):
        """(token, nonnull) pairs that `condition` having `truth` implies for escaped pointer locals."""
        from entry_state_values import condition as strip,is_null
        node=strip(condition);kind=node.get('kind');op=node.get('opcode');terms=children(node)
        if kind=='UnaryOperator' and op=='!' and len(terms)==1:return self.null_tests(terms[0],not truth,stack)
        if kind=='BinaryOperator' and op in ('&&','||') and len(terms)==2:
            return [t for term in terms for t in self.null_tests(term,truth,stack)] if (op=='&&')==truth else []
        if kind=='BinaryOperator' and op in ('==','!=') and len(terms)==2:
            for pointer,other in (terms,terms[::-1]):
                if is_null(other):
                    token=self.escaped_pointer_local(unwrap(pointer),stack)
                    return [(token,(op=='!=')==truth)] if token is not None else []
            return []
        token=self.escaped_pointer_local(unwrap(node),stack) if '*' in type_of(node) else None
        return [(token,truth)] if token is not None else []
    # Return partitions: a call's return states split by the sign of the returned value
    # (negative, zero/null, positive/non-null). ('RP', frame, local) holds the partition of the
    # call last stored to that local, as ('r', (possible, ((key, joined, per-sign values), ...)))
    # with `possible` and the values in SIGNS order. An entry applies only while the flow still
    # holds the very `joined` value object: every write makes a new object, so a key written
    # since the call no longer matches. A key some return states lack joins to a fresh
    # ('u', None): present, but read as the fallback.
    SIGNS=('neg','zero','pos')
    ALL_SIGNS=frozenset(SIGNS)
    def return_class(self,expression,env,stack):
        """The signs this returned value may have in the current state."""
        if '*' in type_of(expression):
            values=self.resolve(expression,env,stack)
            if values=={'null'}:return frozenset({'zero'})
            if values and 'null' not in values and not any(v.startswith(('unresolved:','user:')) for v in values):return frozenset({'pos'})
            return frozenset({'zero','pos'})
        from entry_state_values import integer_type
        if not integer_type(type_of(expression)) and type_of(expression) not in ('_Bool','bool'):return self.ALL_SIGNS
        bounds=self.flow_interval(expression,env,stack)
        if bounds is None:return self.ALL_SIGNS
        return frozenset(c for c,(low,high) in zip(self.SIGNS,((None,-1),(0,0),(1,None)))
                         if (low is None or bounds[1]>=low) and (high is None or bounds[0]<=high))
    def partition_join(self,values):
        """Join flow values of one key (None: unknown in some state)."""
        if any(v is None or v[0]!=values[0][0] or v[0]=='r' for v in values):return None
        if all(v is values[0] for v in values):return values[0]
        joined=values[0][1]
        for v in values[1:]:joined=self.flow_join_values(values[0][0],joined,v[1])
        return (values[0][0],joined)
    def partition_of(self,states,classes,frame):
        """The partition of joined return states by sign (None if it splits nothing)."""
        groups=[[f for (f,l),c in zip(states,classes) if l and sign in c] for sign in self.SIGNS]
        possible=tuple(bool(g) for g in groups)
        if sum(possible)<2:return None
        entries=[];keys={}
        for group in groups:
            for f in group:
                for key in f:keys.setdefault(key,None)
        for key in keys:
            # The callee's own frame is gone; partitions of partitions do not nest.
            if key[0] in ('L','RP','PL') and len(key[1])>len(frame):continue
            if key[0]=='RP':continue
            joined=self._flow.get(key)
            if joined is not None and joined[0]=='r':continue
            values=tuple(self.partition_join([f.get(key) for f in group]) if group else None for group in groups)
            if all(v==joined for v,p in zip(values,possible) if p):continue
            if joined is None:joined=self._flow[key]=('u',None)
            entries.append((key,joined,values))
        return ('r',(possible,tuple(entries))) if entries else None
    def partition_state(self,partition,allowed):
        """The flow state where the value has one of the `allowed` signs (None: no such return)."""
        possible,entries=partition[1]
        chosen=[i for i,sign in enumerate(self.SIGNS) if sign in allowed and possible[i]]
        if not chosen:return None
        state=dict(self._flow)
        for key,joined,values in entries:
            if state.get(key) is not joined:continue
            value=self.partition_join([values[i] for i in chosen])
            if value is None:state.pop(key,None)
            else:state[key]=value
        return state
    def partition_states(self,partition):
        """(signs, state) for each possible sign: a returned partitioned value returns each part."""
        return [(frozenset({sign}),self.partition_state(partition,{sign})) for i,sign in enumerate(self.SIGNS) if partition[1][0][i]]
    def recent_partition(self,expression,stack):
        """The partition of `expression` if it is the call just visited, or a local holding its result."""
        node=unwrap(expression)
        if node.get('kind')=='CallExpr':
            recent=self._recent_partition
            return recent[2] if recent is not None and recent[0]==id(node) and recent[1]==tuple(stack) else None
        if node.get('kind')=='DeclRefExpr':
            entry=self._flow.get(('RP',tuple(stack),node.get('referencedDecl',{}).get('id')))
            return entry
        return None
    def partition_store(self,key,expression,stack):
        """A local stored from `expression`: it now holds that call's partition, or none."""
        self._flow.pop(('RP',tuple(stack),key),None)
        if expression is None or not self._flow_live or self._flow_weak:return
        facts=self.values.facts_for(stack[-1]) if stack and stack[-1] in self.functions else None
        if facts is None or key in facts.escaped or key in self.globals:return
        partition=self.recent_partition(expression,stack) if unwrap(expression).get('kind')=='CallExpr' else None
        if partition is not None:self._flow[('RP',tuple(stack),key)]=partition
    SIGN_TESTS={'==':{'zero'},'!=':{'neg','pos'},'<':{'neg'},'<=':{'neg','zero'},'>':{'pos'},'>=':{'zero','pos'}}
    MIRROR={'<':'>','>':'<','<=':'>=','>=':'<=','==':'==','!=':'!='}
    def sign_tests(self,condition,truth,stack):
        """(expression, signs) pairs that `condition` having `truth` implies for calls and locals."""
        from entry_state_values import condition as strip,is_null
        node=strip(condition);kind=node.get('kind');op=node.get('opcode');terms=children(node)
        if kind=='UnaryOperator' and op=='!' and len(terms)==1:return self.sign_tests(terms[0],not truth,stack)
        if kind=='BinaryOperator' and op in ('&&','||') and len(terms)==2:
            return [t for term in terms for t in self.sign_tests(term,truth,stack)] if (op=='&&')==truth else []
        if kind=='BinaryOperator' and op in self.SIGN_TESTS and len(terms)==2:
            for value,other,operator in ((terms[0],terms[1],op),(terms[1],terms[0],self.MIRROR[op])):
                if is_null(other) or self.constant_interval(other)==(0,0):
                    signs=self.SIGN_TESTS[operator]
                    return [(value,frozenset(signs) if truth else self.ALL_SIGNS-signs)]
            return []
        if unwrap(node).get('kind') in ('CallExpr','DeclRefExpr'):
            return [(node,frozenset({'neg','pos'}) if truth else frozenset({'zero'}))]
        return []
    def partition_refine(self,condition,truth,stack):
        if not self._flow_live:return
        for expression,signs in self.sign_tests(condition,truth,stack):
            partition=self.recent_partition(expression,stack)
            if partition is None:continue
            state=self.partition_state(partition,signs)
            if state is None:continue
            self._flow=state
            # The local's later uses (`return ret`) see only the signs this arm allows.
            node=unwrap(expression)
            if node.get('kind')=='DeclRefExpr':
                key=('RP',tuple(stack),node.get('referencedDecl',{}).get('id'))
                possible=tuple(p and sign in signs for p,sign in zip(partition[1][0],self.SIGNS))
                if key in self._flow:self._flow[key]=('r',(possible,partition[1][1]))
    def flow_refine(self,condition,truth,env,stack):
        """Restrict escaped pointer locals in the arm's state to the values the condition allows."""
        if not self._flow_live:return
        self.partition_refine(condition,truth,stack)
        for local,nonnull in self.local_null_tests(condition,truth,stack):
            value=self.flow_value(local)
            if value is None or value[0]!='p':continue
            refined=set(value[1])-{'null'} if nonnull else {'null'}&set(value[1])
            # No value this local holds satisfies the test: the arm never runs.
            if not refined:self._flow_live=False;return
            self._flow[local]=('p',frozenset(refined))
        for token,nonnull in self.null_tests(condition,truth,stack):
            key=(token,'*');value=self.flow_value(key)
            values=set(value[1]) if value is not None else set(self._auto_store.get(key,set()))
            if not values:continue
            # In the null arm the pointer is null; in the other arm it is any non-null value.
            refined=values-{'null'} if nonnull else {'null'}
            if refined:self._flow[key]=('p',frozenset(refined))
        self.value_split_refine(condition,truth,env,stack)
        self.tag_split_refine(condition,truth,env,stack)
    def tag_split_refine(self,condition,truth,env,stack):
        """Narrow a small-interval tag field of an object the condition reads (directly or through
        a called helper) to the values under which the condition can have this truth."""
        if not self._flow_live or not stack or stack[-1] not in self.functions:return
        tokens=set()
        for n in walk(condition):
            if '*' in type_of(n) and n.get('kind') in ('DeclRefExpr','MemberExpr','UnaryOperator'):
                self.quiet+=1
                try:tokens|={re.match(r'^(?:\*\()*(auto:\d+)',v)[1] for v in self.resolve(n,env,stack) if re.match(r'^(?:\*\()*(auto:\d+)',v)}
                finally:self.quiet-=1
        for token in sorted(tokens):
            record=self.auto_record(token)
            for field in self.tag_fields(record):
                key=(token,field);value=self.flow_value(key)
                if value is None or value[0]!='i' or not isinstance(value[1],tuple):continue
                low,high=value[1]
                if low==high or high-low>7:continue
                kept=[]
                for x in range(low,high+1):
                    self._flow[key]=('i',(x,x))
                    self.values.pointer_env.append(env);self.values.call_stack.append(list(stack));self.quiet+=1
                    try:bounds,_=self.values.interval(condition,stack[-1],self.context_ranges(stack))
                    finally:self.values.pointer_env.pop();self.values.call_stack.pop();self.quiet-=1
                    outcome=None if bounds is None else 0 if bounds==(0,0) else 1 if bounds[0]>0 or bounds[1]<0 else None
                    if outcome is None or outcome==int(truth):kept.append(x)
                self._flow[key]=('i',(min(kept),max(kept))) if kept else value
                if not kept:self._flow_live=False;return
    @staticmethod
    def value_classes(values):
        """Pointer values grouped by integer view: null, the error range, each constant address, objects."""
        groups={}
        for v in values:
            label=v if v in ('null','error-pointer') or re.fullmatch(r'const-address:[0-9]+',v) else 'user' if v.startswith('user:') else 'object'
            groups.setdefault(label,set()).add(v)
        return list(groups.values())
    def value_split_refine(self,condition,truth,env,stack):
        """Drop the value classes of an escaped pointer local under which the condition is decided the other way."""
        if not self._flow_live or not stack or stack[-1] not in self.functions:return
        tokens={}
        for n in walk(condition):
            if n.get('kind')=='DeclRefExpr' and '*' in type_of(n):
                token=self.escaped_pointer_local(n,stack)
                if token is not None:tokens[token]=None
        for token in tokens:
            key=(token,'*');current=self._flow.get(key);value=self.flow_value(key)
            values=set(value[1]) if value is not None else set(self._auto_store.get(key,set()))
            groups=self.value_classes(values)
            if len(groups)<2:continue
            kept=set()
            for group in groups:
                self._flow[key]=('p',frozenset(group))
                self.values.pointer_env.append(env);self.values.call_stack.append(list(stack));self.quiet+=1
                try:bounds,_=self.values.interval(condition,stack[-1],self.context_ranges(stack))
                finally:self.values.pointer_env.pop();self.values.call_stack.pop();self.quiet-=1
                outcome=None if bounds is None else 0 if bounds==(0,0) else 1 if bounds[0]>0 or bounds[1]<0 else None
                if outcome is None or outcome==int(truth):kept|=group
            if current is None:self._flow.pop(key,None)
            else:self._flow[key]=current
            if kept and kept!=values:self._flow[key]=('p',frozenset(kept))
    def boundary_user_value(self,name,argument,node,env,stack):
        """A boundary that loads a user-space pointer from user memory (__get_user of an iovec's
        iov_base) stores a user address: the pointer local it writes holds `user:NAME`."""
        for value in self.resolve(argument,env,stack):
            match=re.fullmatch(r'(auto:\d+)',value)
            if match is None:continue
            info=self._auto_info[match[1]]
            declaration=next((n for n in self.values.facts_for(info['owner'][-1]).order if n.get('id')==info['declaration']),None)
            if declaration is not None and '*' in type_of(declaration) and '(' not in type_of(declaration) and self.record_declaration(type_of(declaration)) is None:
                self.auto_write(match[1],'*',{'user:'+name.split(':',1)[-1]},node,stack,strong=True)
    def referenced_tokens(self,env):
        """Objects named by this frame's values, closed over the pointers stored in objects."""
        pattern=re.compile(r'auto:(\d+)')
        found={'auto:'+m for values in env.values() if isinstance(values,(set,frozenset)) for v in values for m in pattern.findall(v)}
        pending=list(found)
        while pending:
            token=pending.pop()
            for (owner,field),values in list(self._auto_store.items())+[(k,v[1]) for k,v in self._flow.items() if v[0]=='p' and k[0]!='PL']:
                if owner!=token:continue
                for v in values:
                    for m in pattern.findall(v):
                        if 'auto:'+m not in found:found.add('auto:'+m);pending.append('auto:'+m)
        return found
    def flow_tokens(self,stack):
        """Records whose owner frame encloses the current one: they outlive a loop iteration."""
        return {t for t,i in self._auto_info.items() if tuple(stack[:len(i['owner'])])==tuple(i['owner'])}
    def writes_memory(self,name,depth=0,active=()):
        """May this function (or a callee) store into non-automatic memory or escape to unknown code?"""
        if name in self._pure:return self._pure[name]
        if depth>6 or name in active:return True
        function=self.functions.get(name)
        if function is None:return True
        result=False
        for n in walk(function):
            kind=n.get('kind');terms=children(n)
            if kind in ('BinaryOperator','CompoundAssignOperator') and (n.get('opcode','').endswith('=') and n.get('opcode') not in ('==','!=','<=','>=')) or kind=='UnaryOperator' and n.get('opcode') in ('++','--'):
                target=unwrap(terms[0]) if terms else {}
                if not (target.get('kind')=='DeclRefExpr' and target.get('referencedDecl',{}).get('id') not in self.globals):result=True;break
            if kind=='CallExpr':
                target=self.direct_call(n)
                if target is None or (target not in self.functions and not self.boundary(target) and target not in INTEGER_BIT_BUILTINS and target not in COMPILE_TIME_BUILTINS and target!='__builtin_expect'):result=True;break
                if target in self.functions and self.writes_memory(target,depth+1,active+(name,)):result=True;break
                policy=self.boundary(target)
                if policy and (policy.get('writes') or policy.get('spans') or policy.get('kind') not in ('memory_model','value_model','ordering_model')):result=True;break
        self._pure[name]=result
        return result

    def written_fields(self,name,depth=0,active=()):
        """Member names this function (or a callee) may store; None if it may store other memory."""
        if name in self._written_fields:return self._written_fields[name]
        if depth>6 or name in active:return None
        function=self.functions.get(name)
        if function is None:return None
        result=set()
        for n in walk(function):
            kind=n.get('kind');terms=children(n)
            if kind in ('BinaryOperator','CompoundAssignOperator') and (n.get('opcode','').endswith('=') and n.get('opcode') not in ('==','!=','<=','>=')) or kind=='UnaryOperator' and n.get('opcode') in ('++','--'):
                target=unwrap(terms[0]) if terms else {}
                while target.get('kind')=='ArraySubscriptExpr' and children(target):target=unwrap(children(target)[0])
                if target.get('kind')=='DeclRefExpr':
                    if target.get('referencedDecl',{}).get('id') in self.globals or '[' not in type_of(target):continue
                    result=None;break
                if target.get('kind')!='MemberExpr' or not target.get('name'):result=None;break
                result.add(target['name'])
            if kind=='CallExpr':
                target=self.direct_call(n)
                if target in INTEGER_BIT_BUILTINS or target in COMPILE_TIME_BUILTINS or target=='__builtin_expect':continue
                if target in self.functions and not self.boundary(target):
                    callee_fields=self.written_fields(target,depth+1,active+(name,))
                    if callee_fields is None:result=None;break
                    result|=callee_fields;continue
                policy=self.boundary(target) if target is not None else None
                if not policy or policy.get('writes') or policy.get('spans') or policy.get('kind') not in ('memory_model','value_model','ordering_model'):result=None;break
        result=frozenset(result) if result is not None else None
        # A cut-off recursion is only a sound answer for the outermost function.
        if depth==0 or result is not None:self._written_fields[name]=result
        return result
    def flow_mask(self,name):
        """Enter a region that may store what `name` stores, out of order: hide those flow keys."""
        fields=self.written_fields(name)
        if fields is None:self._flow_off+=1
        else:self._flow_masks.append(fields)
        return fields
    def flow_unmask(self,fields):
        if fields is None:self._flow_off-=1
        else:self._flow_masks.pop()

    def auto_scalar_write(self,token,field,interval,node=None,stack=None,strong=False):
        """Union an integer field's possible values (None: unknown) over every write to it."""
        key=(token,field)
        if self._auto_info.get(token,{}).get('summary'):strong=False
        if node is not None:
            site=self.owner_site(token,node,stack)
            if all(site is not other for other in self._auto_sites.setdefault(key,[])):self._auto_sites[key].append(site)
        self.flow_write(key,'i',interval,strong)
        written=self._auto_scalar_written.get(key,'unset')
        self._auto_scalar_written[key]=interval if written=='unset' else None if written is None or interval is None else (min(written[0],interval[0]),max(written[1],interval[1]))
        previous=self._auto_scalars.get(key,'unset')
        if previous=='unset':combined=interval
        elif previous is None or interval is None:combined=None
        else:combined=(min(previous[0],interval[0]),max(previous[1],interval[1]))
        if combined!=previous:
            if key in self._auto_scalar_reads:self._auto_late=True
            self._auto_scalars[key]=combined
    def auto_scalar_read(self,token,field,node,stack):
        """The union of an integer field's writes, if a write dominates this read (or the record is initialized)."""
        key=(token,field);self._auto_scalar_reads[key]=True
        flow=self.flow_value(key)
        if flow is not None and flow[0]=='i':return flow[1]
        value=self._auto_scalars.get(key,'unset')
        if value in ('unset',None):return None
        info=self._auto_info[token]
        if not info.get('initialized'):
            site=self.owner_site(token,node,stack);facts=self.values.facts_for(info['owner'][-1])
            if not any(facts.dominates(write,site) for write in self._auto_sites.get(key,())):return None
        return value
    def scalar_initializer(self,declaration,node,stack,depth=0):
        """Integer-field intervals of a whole-record initializer, flattened like flat_fields (None: unknown)."""
        if declaration is None or depth>8:return None
        while node.get('kind') in ('ParenExpr','ConstantExpr') or node.get('kind')=='ImplicitCastExpr' and node.get('castKind') in ('NoOp','LValueToRValue'):
            if not children(node):return None
            node=children(node)[0]
        if node.get('kind')=='CompoundLiteralExpr' and children(node):node=children(node)[0]
        from entry_state_values import integer_type
        scalars=[f for f in self.flat_fields(declaration) if integer_type(f[1]) and not f[3]]
        if node.get('kind')=='ImplicitValueInitExpr':return {f[0]:(0,0) for f in scalars}
        if node.get('kind')!='InitListExpr' or declaration.get('tagUsed')=='union':return None
        members=[];anonymous=None
        for child in children(declaration):
            if child.get('kind')=='RecordDecl':
                if not child.get('name'):anonymous=child
                continue
            if child.get('kind')=='FieldDecl':members.append((child,anonymous if not child.get('name') else None))
        terms=children(node)
        if len(terms)!=len(members):return None
        values={}
        for (member,record),term in zip(members,terms):
            if record is not None:
                nested=self.scalar_initializer(record,term,stack,depth+1)
                if nested is not None:values.update(nested)
                continue
            if not integer_type(type_of(member)) or member.get('isBitfield'):continue
            bounds=self.constant_interval(term)
            if bounds is None and term.get('kind')=='ImplicitValueInitExpr':bounds=(0,0)
            if bounds is None:bounds,_=self.values.interval(term,stack[-1],self.context_ranges(stack))
            values[member['name']]=tuple(bounds) if bounds is not None else None
        return values
    def const_table(self,base):
        """Element values of a const global integer array with a constant initializer (its definition may be in
        another translation unit), or None. An element left to the array filler takes the filler's value."""
        while base.get('kind') in ('ImplicitCastExpr','ParenExpr') and children(base):base=children(base)[0]
        declaration=base.get('referencedDecl',{}) if base.get('kind')=='DeclRefExpr' else {}
        if declaration.get('kind')!='VarDecl' or declaration.get('id') not in self.globals:return None
        cache=self.__dict__.setdefault('_const_tables',{})
        name=declaration.get('name')
        if name not in cache:
            cache[name]=None
            for node in self.globals.values():
                init=children(node)[-1] if children(node) else None
                if node.get('name')!=name or init is None or init.get('kind')!='InitListExpr' or not type_of(node).startswith('const ') or not fixed_array(type_of(node)):continue
                count=int(fixed_array(type_of(node))[2]);values=[]
                filler=node.get('array_filler') or init.get('array_filler') or []
                fill=self.constant_interval(filler[0]) if filler else None
                for term in children(init)[:count]:
                    bounds=self.constant_interval(term) if term.get('kind')!='ImplicitValueInitExpr' else fill
                    values.append(bounds[0] if bounds and bounds[0]==bounds[1] else None)
                values+=[fill[0] if fill and fill[0]==fill[1] else None]*(count-len(values))
                cache[name]=values
        return cache[name]
    def constant_interval(self,term):
        """A constant integer expression (enum constants included), converted to the term's own type."""
        inner=term
        while inner.get('kind') in ('ImplicitCastExpr','CStyleCastExpr','ParenExpr','ConstantExpr') and inner.get('castKind') in (None,'IntegralCast','NoOp') and len(children(inner))==1:
            inner=children(inner)[0]
        bounds,_=self.static_index_bounds(inner)
        if bounds is None:return None
        fitted=self.values.fit(bounds[0],bounds[1],term)
        # A conversion that cannot keep the value is not folded here.
        return tuple(fitted) if fitted is not None and tuple(fitted)==tuple(bounds) else None
    def unreachable_region(self,node,stack):
        self._unreachable.add((id(node),tuple(stack)))
    def prior_reachable(self,node,name,stack):
        """Was `node` (in function `name`, call context `stack`) reachable in the previous pass?"""
        if not self._prior_unreachable or name not in self.functions:return True
        facts=self.values.facts_for(name);context=tuple(stack)
        while node is not None:
            if (id(node),context) in self._prior_unreachable:return False
            node=facts.parent.get(id(node))
        return True
    def decided_outcome(self,condition,env,stack):
        key=(id(condition),tuple(stack))
        if key not in self._decisions:self._decisions[key]=self.decided(condition,env,stack)
        return self._decisions[key]
    def loop_never_runs(self,node,env,stack):
        """Is the loop condition false on entry? It is evaluated on values from before the loop."""
        parts=children(node)
        condition=parts[0] if node.get('kind')=='WhileStmt' and len(parts)==2 else parts[2] if node.get('kind')=='ForStmt' and len(parts)==5 and not parts[1].get('kind') else None
        if condition is None or not condition.get('kind'):return False
        key=(id(condition),tuple(stack))
        if key not in self._decisions and self.empty_list_heads and self.empty_list_walk(node,env,stack):self._decisions[key]=0
        if key not in self._decisions:
            name=stack[-1] if stack else None
            entry_env=env
            if name in self.functions:
                function=self.functions[name];body=next(c for c in children(function) if c.get('kind')=='CompoundStmt')
                region={id(n) for n in walk(parts[-1])}|({id(n) for n in walk(parts[3])} if node.get('kind')=='ForStmt' else set())
                parameters={p['id'] for p in self.parameters(function)}
                entry_env={k:set(v) for k,v in env.items() if k in parameters or any(k.startswith(p+'.') for p in parameters)}
                self.quiet+=1
                try:self.pointer_aliases(body,entry_env,stack,exclude=region)
                finally:self.quiet-=1
            self._decisions[key]=self.decided(condition,entry_env,stack)
        return self._decisions[key]==0
    def empty_list_walk(self,node,env,stack):
        """A list walk over a contract's empty head: its cursor starts at the head, so the loop never runs."""
        from entry_state_lists import walk_parts,head as list_head,SENTINEL
        parts=walk_parts(node)
        if parts is None:return False
        cursor,fields,bound,value,first=parts
        self.quiet+=1
        try:heads=self.resolve(bound,env,stack);cursors=self.resolve(value,env,stack)
        finally:self.quiet-=1
        if not heads or not all(list_head(self.empty_list_heads,h) for h in heads):return False
        if not cursors or cursors!={SENTINEL+h+'#'+fields for h in heads}:return False
        self.list_proofs.append(dict(kind='empty_list_walk',function=stack[-1],call_path=stack,location=self.location(node),member=fields,
            heads=sorted({re.sub(r'\[\d+\]','[]',h) for h in heads}),
            reason='the initializer sets the cursor from HEAD->next and the condition compares &cursor->member with the same side-effect-free HEAD: an empty head links to itself, so the condition is false on entry'))
        return True
    def decided(self,condition,env,stack):
        """0 or 1 when the condition's interval in this call context excludes the other outcome."""
        if not stack or stack[-1] not in self.functions:return None
        self.values.pointer_env.append(env);self.values.call_stack.append(list(stack));self.quiet+=1
        try:bounds,proof=self.values.interval(condition,stack[-1],self.context_ranges(stack))
        finally:self.values.pointer_env.pop();self.values.call_stack.pop();self.quiet-=1
        if bounds is None:return None
        if bounds==(0,0):outcome=0
        elif bounds[0]>0 or bounds[1]<0:outcome=1
        else:return None
        self.branch_proofs.append(dict(kind='decided_condition',function=stack[-1],call_path=stack,location=self.location(condition),
            outcome=outcome,interval=list(bounds),evidence=proof))
        return outcome

    def storage_paths(self,node,env,stack):
        """Lvalue paths of `node` itself; inner pointer loads still read the stack-object store."""
        previous=self._auto_storage;self._auto_storage=id(unwrap(node))
        try:return self.resolve(node,env,stack)
        finally:self._auto_storage=previous
    def auto_storage(self,paths):
        return bool(paths) and all(re.match(r'^(?:\*\()*auto:\d+',p) for p in paths)

    def flag_guarded(self,node,key,flag,stack):
        """A dominating truth of `record.flag & C` (C != 0) or `record.flag`."""
        from entry_state_values import condition,member_of
        facts=self.function_facts(node,stack)
        if facts is None:return False
        for cond,truth,guard in facts.facts(node):
            cond=condition(cond)
            if not truth:continue
            operand=cond
            if cond.get('kind')=='BinaryOperator' and cond.get('opcode')=='&':
                operand=None
                for a,b in (children(cond),children(cond)[::-1]):
                    constant=self.low_constant(b)
                    if constant and constant[0]=='value' and constant[1]>0:operand=a;break
                if operand is None:continue
            if member_of(operand)==(key,flag):
                self.null_guard_proofs.append(dict(kind='tag_linked_flag_guard',function=stack[-1],call_path=stack,value=key+'.'+flag,
                    guard=self.location(guard),location=self.location(node)))
                return True
        return False

    def guard_classes(self,node,key,values,env,stack):
        """Drop the value classes of a pointer local (an ERR_PTR constant, null) that a dominating
        guard excludes: `if (IS_ERR(p)) return ...;` before the use is evaluated with p holding each
        class alone, and a class it decides the other way never reaches the use."""
        if not any(re.fullmatch(r'const-address:\d+',v) or v=='error-pointer' for v in values):return values
        groups=self.value_classes(values);facts=self.function_facts(node,stack)
        active=self.__dict__.setdefault('_guard_split_active',set())
        if len(groups)<2 or facts is None or id(node) in active:return values
        kept=set(values);active.add(id(node))
        # A local copied from another (`void *x = (void *)object;`, neither changed since) holds the same
        # value: a guard on the source narrows the copy (kfree tests object, then frees x).
        keys={key};source=self.copied_local(node,key,facts)
        if source is not None:keys.add(source)
        try:
            for cond,truth,guard in facts.facts(node):
                if not any(n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('id') in keys for n in walk(cond)):continue
                local=('PL',tuple(stack),key);held=self._flow.get(local)
                for group in groups:
                    if not group<=kept or len(kept)==len(group):continue
                    self.values.pointer_env.append({**env,**{k:set(group) for k in keys}});self.values.call_stack.append(list(stack));self.quiet+=1
                    if held is not None:self._flow[local]=('p',frozenset(group))
                    try:bounds,_=self.values.interval(cond,stack[-1],self.context_ranges(stack))
                    finally:
                        self.values.pointer_env.pop();self.values.call_stack.pop();self.quiet-=1
                        if held is not None:self._flow[local]=held
                    outcome=None if bounds is None else 0 if bounds==(0,0) else 1 if bounds[0]>0 or bounds[1]<0 else None
                    if outcome is not None and outcome!=int(truth):
                        kept-=group
                        self.null_guard_proofs.append(dict(kind='value_class_guard',function=stack[-1],call_path=stack,value=sorted(group),
                            guard=self.location(guard),location=self.location(node)))
        finally:active.discard(id(node))
        return kept
    def return_correlated_nonnull(self,node,key,env,stack):
        """`r = f(..., x, ...)`; later a guard proves r non-null: x is non-null when f returns null only where its
        parameter for x is null (`if (!time) return NULL;`) and otherwise returns a parameter given a non-null
        address (`return timeout;` for `&timeout`). Neither r nor x may change or escape (futex_setup_timer)."""
        from entry_state_values import implies_nonnull,match_variable,is_null
        facts=self.function_facts(node,stack)
        if facts is None or key in facts.escaped or facts.has_labels:return False
        if facts.declarations.get(key) is not None and len(facts.mutations.get(key,()))>1 or key not in facts.declarations and facts.mutations.get(key):return False
        for cond,truth,guard in facts.facts(node):
            for local,declaration in facts.declarations.items():
                if local==key or local in facts.escaped or '*' not in type_of(declaration) or not implies_nonnull(cond,truth,match_variable(local)):continue
                # r's one definition: an initializer or a single assignment of a direct call.
                stores=[n for n in facts.order if n.get('kind')=='BinaryOperator' and n.get('opcode')=='=' and children(n) and unwrap(children(n)[0]).get('referencedDecl',{}).get('id')==local]
                if len(stores)+(1 if children(declaration) else 0)!=1:continue
                call=unwrap(children(stores[0])[1] if stores else children(declaration)[-1])
                if call.get('kind')!='CallExpr':continue
                name=self.direct_call(call)
                if not name or name not in self.functions:continue
                arguments=children(call)[1:];parameters=self.parameters(self.functions[name])
                index=next((i for i,a in enumerate(arguments) if unwrap(a).get('kind')=='DeclRefExpr' and unwrap(a).get('referencedDecl',{}).get('id')==key),None)
                if index is None or index>=len(parameters):continue
                if self.null_only_when_null(name,parameters,index,arguments,env,stack):
                    self.null_guard_proofs.append(dict(kind='return_correlated_guard',function=stack[-1],call_path=stack,value=facts.declarations.get(key,{}).get('name') or 'parameter',
                        result=declaration.get('name'),callee=name,guard=self.location(guard),location=self.location(node)))
                    return True
        return False
    def null_only_when_null(self,name,parameters,index,arguments,env,stack):
        from entry_state_values import implies_nonnull,match_variable,is_null
        function=self.functions[name];callee=self.values.facts_for(name);parameter=parameters[index]['id']
        if parameter in callee.escaped or callee.mutations.get(parameter) or callee.has_labels:return False
        returns=[n for n in callee.order if n.get('kind')=='ReturnStmt']
        if not returns:return False
        for r in returns:
            value=unwrap(children(r)[0]) if children(r) else None
            if value is None:return False
            if is_null(children(r)[0]) or is_null(value):
                # A null return must lie where the parameter is null: a guard whose opposite truth proves it non-null.
                if not any(implies_nonnull(c,not t,match_variable(parameter)) for c,t,_ in callee.facts(r)):return False
                continue
            # Any other return passes back a parameter whose argument here is a non-null address.
            target=value.get('referencedDecl',{}) if value.get('kind')=='DeclRefExpr' else {}
            position=next((i for i,p in enumerate(parameters) if p['id']==target.get('id')),None)
            if position is None or target.get('id') in callee.mutations or position>=len(arguments):return False
            self.quiet+=1
            try:passed=self.resolve(arguments[position],env,stack)
            finally:self.quiet-=1
            if not passed or any(v=='null' or v.startswith(('unresolved:','const-address:','error-pointer')) for v in passed):return False
        return True
    def copied_local(self,node,key,facts):
        """The variable a pointer local was initialized from by a plain (cast) copy, when neither is ever assigned."""
        declaration=facts.declarations.get(key)
        if declaration is None or not children(declaration) or facts.mutations.get(key,[])!=[facts.span[id(declaration)][1]] or key in facts.escaped:return None
        value=children(declaration)[-1]
        while value.get('kind') in ('ParenExpr','ImplicitCastExpr','CStyleCastExpr') and children(value) and (value.get('kind')=='ParenExpr' or value.get('castKind') in ('NoOp','BitCast','LValueToRValue')):value=children(value)[0]
        if value.get('kind')!='DeclRefExpr':return None
        source=value.get('referencedDecl',{}).get('id')
        if source is None or source in self.globals or source in facts.escaped or facts.mutations.get(source) and source in facts.declarations and facts.mutations[source]!=[facts.span[id(facts.declarations[source])][1]]:return None
        if source not in facts.declarations and facts.mutations.get(source):return None
        return source
    def nonnull(self,node,match,label,stack):
        """A dominating guard proves this read of a pointer non-null."""
        from entry_state_values import implies_nonnull
        facts=self.function_facts(node,stack)
        if facts is None:return False
        for cond,truth,guard in facts.facts(node):
            if implies_nonnull(cond,truth,match):
                self.null_guard_proofs.append(dict(kind='dominating_null_guard',function=stack[-1],call_path=stack,value=label,
                    guard=self.location(guard),location=self.location(node)))
                return True
        return False

    PURE_CONDITION_KINDS=('DeclRefExpr','IntegerLiteral','CharacterLiteral','ImplicitCastExpr','CStyleCastExpr','ParenExpr','ConstantExpr','BinaryOperator','UnaryOperator')
    @staticmethod
    def condition_signature(cond,truth):
        """A structural spelling of `cond` with this truth value, with negations folded into the truth."""
        from entry_state_values import condition
        cond=condition(cond)
        while cond.get('kind')=='UnaryOperator' and cond.get('opcode')=='!' and len(children(cond))==1:
            cond=condition(children(cond)[0]);truth=not truth
        def spell(n):
            while n.get('kind')=='ParenExpr' and len(children(n))==1:n=children(n)[0]
            return (n.get('kind'),n.get('opcode'),n.get('referencedDecl',{}).get('id'),n.get('value'),n.get('castKind'),type_of(n),tuple(spell(c) for c in children(n)))
        return spell(cond),truth
    def correlated_nonnull(self,node,key,env,stack):
        """A guard `C` on this read repeats an earlier `if (C)` whose arm stored a non-null value.

        `p` starts null and is stored only by that arm. The earlier `if` precedes the
        statement holding this read in one block, with no label or case between them, and
        `C` reads only unescaped locals that nothing stores in between. So whenever `C`
        holds here it held there, the arm ran, and the store happened.
        """
        from entry_state_values import condition,is_null
        facts=self.function_facts(node,stack)
        if facts is None or key in facts.escaped:return False
        declaration=facts.declarations.get(key)
        if declaration is None or not children(declaration) or not is_null(children(declaration)[0]):return False
        stores=[n for n in facts.order if n.get('kind')=='BinaryOperator' and n.get('opcode')=='=' and children(n) and unwrap(children(n)[0]).get('referencedDecl',{}).get('id')==key]
        if len(stores)!=1 or sorted(facts.mutations.get(key,()))!=sorted([facts.span[id(declaration)][1],facts.span[id(stores[0])][1]]):return False
        store=stores[0]
        # The arm statement holding the store, and the if whose arm it is.
        statement=store;parent=facts.parent.get(id(statement))
        while parent is not None and parent.get('kind') in ('ImplicitCastExpr','ParenExpr','ExprWithCleanups'):statement=parent;parent=facts.parent.get(id(statement))
        arm=statement
        if parent is not None and parent.get('kind')=='CompoundStmt':
            before=children(parent)[:next(i for i,t in enumerate(children(parent)) if t is statement)]
            if any(n.get('kind') in ('GotoStmt','BreakStmt','ContinueStmt','LabelStmt','CaseStmt','DefaultStmt') for b in before for n in walk(b)):return False
            arm=parent;parent=facts.parent.get(id(arm))
        if parent is None or parent.get('kind')!='IfStmt' or len(children(parent))<2 or arm is children(parent)[0]:return False
        first=parent;parts=children(first)
        cond=parts[0];truth=arm is parts[1]
        if facts.entered(first) or any(n.get('kind') not in self.PURE_CONDITION_KINDS or n.get('opcode') in ('=','++','--','&','*') and n.get('kind')=='UnaryOperator'
                                       or n.get('kind')=='BinaryOperator' and n.get('opcode','').endswith('=') and n.get('opcode') not in ('==','!=','<=','>=')
                                       for n in walk(condition(cond))):return False
        variables=facts.variables(cond)
        if not variables or variables&facts.escaped or any(v in self.globals for v in variables):return False
        # The statement holding this read follows `first` in the same block.
        block=facts.parent.get(id(first))
        if block is None or block.get('kind')!='CompoundStmt':return False
        holder=node
        while holder is not None and facts.parent.get(id(holder)) is not block:holder=facts.parent.get(id(holder))
        if holder is None:return False
        terms=children(block);index=next(i for i,t in enumerate(terms) if t is first)
        later=next((i for i,t in enumerate(terms) if t is holder),None)
        if later is None or later<=index:return False
        if any(t.get('kind') in ('LabelStmt','CaseStmt','DefaultStmt') or facts.entered(t) for t in terms[index+1:later+1]):return False
        low=facts.span[id(cond)][0];high=facts.span[id(node)][0]-1
        if not facts.stable(cond,low,high) or low<=facts.span[id(declaration)][1]<=high:return False
        wanted=self.condition_signature(cond,truth)
        guard=next((g for c,t,g in facts.facts(node) if self.condition_signature(c,t)==wanted),None)
        if guard is None:return False
        if 'null' in self.resolve(children(store)[1],env,stack):return False
        self.null_guard_proofs.append(dict(kind='correlated_store_guard',function=stack[-1],call_path=stack,value=declaration.get('name'),
            guard=self.location(guard),store=self.location(store),location=self.location(node)))
        return True

    def null_replaced(self,node,key,env,stack):
        """`if (!p) p = E;` with E non-null precedes this read in its block, and p is not stored since.

        When the test is false p is already non-null; when it is true the arm stores E.
        """
        from entry_state_values import implies_nonnull,match_variable
        facts=self.function_facts(node,stack)
        if facts is None or key in facts.escaped:return False
        holder=node;block=facts.parent.get(id(holder))
        while block is not None:
            if block.get('kind')=='CompoundStmt':
                terms=children(block);index=next(i for i,t in enumerate(terms) if t is holder)
                for back in range(index-1,-1,-1):
                    statement=terms[back]
                    if statement.get('kind') in ('LabelStmt','CaseStmt','DefaultStmt') or facts.entered(statement):return False
                    if statement.get('kind')=='IfStmt' and len(children(statement))==2:
                        cond,arm=children(statement)
                        if implies_nonnull(cond,False,match_variable(key)):
                            store=arm
                            if store.get('kind')=='CompoundStmt' and children(store):
                                before=children(store)[:-1];store=children(store)[-1]
                                if any(n.get('kind') in ('GotoStmt','BreakStmt','ContinueStmt','LabelStmt','CaseStmt','DefaultStmt') for b in before for n in walk(b)):return False
                            store=unwrap(store)
                            if not (store.get('kind')=='BinaryOperator' and store.get('opcode')=='=' and unwrap(children(store)[0]).get('referencedDecl',{}).get('id')==key):return False
                            if 'null' in self.resolve(children(store)[1],env,stack):return False
                            low=facts.span[id(statement)][1]+1;high=facts.span[id(node)][0]-1
                            if facts.assigned(key,low,high) or facts.has_labels and any(facts.entered(t) for t in terms[back+1:index+1]):return False
                            self.null_guard_proofs.append(dict(kind='null_replaced_before_use',function=stack[-1],call_path=stack,
                                value=facts.declarations.get(key,{}).get('name'),guard=self.location(statement),location=self.location(node)))
                            return True
                    if any(n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('id')==key for n in walk(statement)) and facts.assigned(key,*facts.span[id(statement)]):return False
                return False
            if block.get('kind') in ('FunctionDecl','WhileStmt','ForStmt','DoStmt','SwitchStmt'):return False
            holder=block;block=facts.parent.get(id(holder))
        return False

    def record_pointer_fields(self,typ):
        layout=self.record_layouts.get(re.sub(r'^const\s+','',typ or '').strip())
        if not layout:return None
        return [(name,t) for name,t in layout if name and '*' in t and '(' not in t]

    def tracked_record(self,key,stack):
        """Pointer fields of an automatic record or by-value parameter whose address never escapes."""
        if key is None or key in self.globals or not stack or stack[-1] not in self.functions:return False
        return key not in self.values.facts_for(stack[-1]).escaped

    def tracked_member(self,node,env,stack):
        """Environment key for `record.field` when that pointer field's values are tracked."""
        if node.get('kind')!='MemberExpr' or node.get('isArrow') or '*' not in type_of(node) or not children(node):return None
        base=unwrap(children(node)[0])
        if base.get('kind')!='DeclRefExpr' or base.get('referencedDecl',{}).get('kind') not in ('VarDecl','ParmVarDecl'):return None
        key=base['referencedDecl']['id'];composite=key+'.'+node['name']
        return composite if composite in env and self.tracked_record(key,stack) else None

    def record_value(self,expression,env,stack,depth=0):
        """Pointer-field values of a struct-valued expression, or None when unknown."""
        from entry_state_values import is_null
        node=expression
        while node.get('kind') in ('ParenExpr','ConstantExpr') or node.get('kind')=='ImplicitCastExpr' and node.get('castKind') in ('NoOp','LValueToRValue'):
            terms=children(node)
            if len(terms)!=1:return None
            node=terms[0]
        fields=self.record_pointer_fields(type_of(node))
        if fields is None or depth>8:return None
        kind=node.get('kind');terms=children(node)
        if kind=='CompoundLiteralExpr' and len(terms)==1:return self.record_value(terms[0],env,stack,depth+1)
        if kind=='InitListExpr':
            layout=self.record_layouts[re.sub(r'^const\s+','',type_of(node)).strip()]
            if 'field' in node or 'array_filler' in node or len(terms)!=len(layout):return None
            wanted=dict(fields);values={}
            for (name,_),term in zip(layout,terms):
                if name not in wanted:continue
                found=self.resolve(term,env,stack)
                values[name]=found or ({'null'} if term.get('kind')=='ImplicitValueInitExpr' or is_null(term) else {'unresolved:record'})
            links=self.tag_links(layout,terms,env,stack)
            if links:values[LINKS]=links
            return values
        if kind=='DeclRefExpr':
            key=node.get('referencedDecl',{}).get('id')
            if not self.tracked_record(key,stack):return None
            values={name:env.get(key+'.'+name,{'unresolved:record'}) for name,_ in fields}
            links={field:next(iter(env[key+'.'+field+LINK_SUFFIX])) for field,_ in fields if env.get(key+'.'+field+LINK_SUFFIX,{INVALID_LINK})!={INVALID_LINK}}
            if links:values[LINKS]=links
            return values
        if kind=='ConditionalOperator' and len(terms)==3:
            arms=[self.record_value(t,env,stack,depth+1) for t in terms[1:]]
            if any(a is None for a in arms):return None
            return {name:arms[0][name]|arms[1][name] for name,_ in fields}
        if kind=='CallExpr':
            name=self.direct_call(node)
            if not name or self.boundary(name) or name not in self.functions or name in stack:return None
            local=self.inline_environment(name,node,terms[1:],env,stack)
            values={field:set() for field,_ in fields};links=None
            for returned,_ in self.return_alias_program(self.functions[name])[1]:
                value=self.record_value(returned,local,stack+[name],depth+1)
                if value is None:return None
                for field in values:values[field]|=value[field]
                # A link holds for the call only when every return provides it.
                found=value.get(LINKS,{});links=dict(found) if links is None else {k:v for k,v in links.items() if found.get(k)==v}
            if links:values[LINKS]=links
            return values
        return None

    def tag_links(self,layout,terms,env,stack):
        """{pointer field: flags field} for `{(T *)(v & ~L), v & M}` where M <= L and null in v has tag 0.

        A non-zero flags field then implies a non-null pointer field (the fd idiom:
        __to_fd splits __fdget's tagged word).
        """
        def masked(term,want):
            node=term
            while node.get('kind') in ('ParenExpr','ImplicitCastExpr','CStyleCastExpr') and children(node) and (node.get('castKind') in (None,'IntegralCast','NoOp','LValueToRValue') or want=='pointer' and node.get('castKind')=='IntegralToPointer'):
                if want=='pointer' and node.get('castKind')=='IntegralToPointer':want='cleared'
                node=children(node)[0]
            if node.get('kind')!='BinaryOperator' or node.get('opcode')!='&':return None
            for operand,constant in (children(node),children(node)[::-1]):
                value=self.low_constant(constant);variable=unwrap(operand)
                if value is None or variable.get('kind')!='DeclRefExpr':continue
                if want=='cleared' and value[0]=='clear':return variable['referencedDecl']['id'],value[1],variable
                if want=='flags' and value[0]=='value' and value[1]>0:return variable['referencedDecl']['id'],value[1],variable
            return None
        pointers={};flags={}
        for (name,typ),term in zip(layout,terms):
            if '*' in typ:
                found=masked(term,'pointer')
                if found:pointers[name]=found
            elif arithmetic_scalar(re.sub(r'\b(?:const|volatile)\s+','',typ)):
                found=masked(term,'flags')
                if found:flags[name]=found
        links={}
        for pointer,(key,cleared,variable) in pointers.items():
            for flag,(other,mask,_) in flags.items():
                if other!=key or mask & ~cleared:continue
                values=self.resolve(variable,env,stack)
                nulls=[v for v in values if v=='null' or v.endswith(':null')]
                if all(v=='null' or (TAGGED.fullmatch(v) and int(TAGGED.fullmatch(v)[1])==0) for v in nulls):links[pointer]=flag
        return links

    def assign_record(self,key,expression,env,stack):
        if not self.tracked_record(key,stack):return False
        fields=self.record_pointer_fields(type_of(expression)) or []
        value=self.record_value(expression,env,stack);changed=False
        links=(value or {}).get(LINKS,{})
        for name,_ in fields:
            link={links[name]} if name in links else {INVALID_LINK}
            previous=env.get(key+'.'+name+LINK_SUFFIX)
            combined=link if previous is None or previous==link else {INVALID_LINK}
            if combined!=previous:env[key+'.'+name+LINK_SUFFIX]=combined;changed=True
        for name,_ in fields:
            paths=value[name] if value is not None and name in value else {'unresolved:record'}
            previous=env.get(key+'.'+name,set());combined=self.bounded_aliases(previous|paths,expression,stack)
            if combined!=previous:env[key+'.'+name]=combined;changed=True
        return changed

    def inline_environment(self,name,call,arguments,env,stack):
        """Bind a callee's parameters for return-value resolution; its body is visited separately."""
        function=self.functions[name];local={}
        self.enter_call(name,call,stack)
        for parameter,argument in zip(self.parameters(function),arguments):
            local[parameter['id']]=self.resolve(argument,env,stack)
            if self.record_pointer_fields(type_of(parameter)):
                value=self.record_value(argument,env,stack)
                for field,paths in (value or {}).items():
                    if field==LINKS:
                        for pointer,flag in paths.items():local[parameter['id']+'.'+pointer+LINK_SUFFIX]={flag}
                    else:local[parameter['id']+'.'+field]=paths
        self.pointer_aliases(function,local,stack+[name])
        updates,_=self.return_alias_program(function)
        for key,expression,statement in updates:
            if not self.prior_reachable(statement,name,stack+[name]):continue
            local[key]=self.bounded_aliases(local.get(key,set())|self.resolve(expression,local,stack+[name]),statement,stack+[name])
        return local

    def issue(self,kind,node,stack,detail):
        # AST nodes and call paths are immutable during a root analysis. Avoid
        # allocating the same diagnostic in every alias-fixpoint iteration;
        # analyze() still deduplicates equal locations from distinct AST nodes.
        if self.quiet:return
        key=(kind,id(node),tuple(stack),detail)
        if key in self._diagnostic_keys:return
        self._diagnostic_keys.add(key);self._diagnostic_nodes[id(node)]=node
        self.blockers.append({'kind':kind,'function':stack[-1],'call_path':stack,'detail':detail,'location':self.location(node)})

    @staticmethod
    def location(node):
        value=node.get('range',{}).get('begin',node.get('loc',{}))
        result=dict(value.get('expansionLoc',value))
        if node.get('_translation_unit'):result['translation_unit']=node['_translation_unit']
        return result

    def array_lvalue(self,node):
        key=id(node)
        if key not in self._array_lvalue_cache:
            self._array_lvalue_cache[key]=(node,array_pointer_lvalue(node))
        return self._array_lvalue_cache[key][1]

    def pointer_scopes(self,name):
        if name not in self._pointer_scope_cache:
            scopes={}
            def scan(node,scope):
                if node.get('kind') in ('CompoundStmt','ForStmt','StmtExpr'):scope=scope+(node.get('id'),)
                if node.get('id'):scopes[node['id']]=scope
                for child in children(node):scan(child,scope)
            scan(self.functions[name],())
            self._pointer_scope_cache[name]=scopes
        return self._pointer_scope_cache[name]

    def pointer_lifetime(self,paths,node,stack):
        for path in paths:
            origin=self._bounded_pointers.get(path)
            if origin is None or not origin['owner']:continue
            owner=origin['owner']
            live=tuple(stack[:len(owner)])==owner
            if live and tuple(stack)==owner:
                scope=self.pointer_scopes(stack[-1]).get(node.get('id'))
                live=scope is not None and scope[:len(origin['scope'])]==origin['scope']
            if not live:self.issue('pointer_arithmetic',node,stack,'bounded pointer is outside its automatic storage scope/lifetime')

    SCALAR_BYTES={'_Bool':1,'char':1,'signed char':1,'unsigned char':1,'short':2,'unsigned short':2,'int':4,'unsigned int':4,
                  'long':8,'unsigned long':8,'long long':8,'unsigned long long':8}
    def type_bytes(self,typ):
        """Byte size on the AArch64 slice target, or None."""
        layout=self.type_layout(typ);return layout[0] if layout else None

    def named_type(self,typ):
        """(resolved type spelling, record declaration or None) through typedefs, including typedefs of
        anonymous records (freeptr_t), which the typedef table spells by their own name."""
        typ=re.sub(r'^(?:const |volatile )+','',(typ or '').strip())
        if '_typedef_records' not in self.__dict__:
            records={n['id']:n for n in walk(self._tree) if n.get('kind')=='RecordDecl' and n.get('completeDefinition')}
            self._typedef_records={}
            for n in walk(self._tree):
                if n.get('kind')!='TypedefDecl':continue
                ref=next((x['decl']['id'] for x in walk(n) if x.get('kind')=='RecordType' and x.get('decl',{}).get('id') in records),None)
                if ref is not None:self._typedef_records.setdefault(n['name'],records[ref])
        for _ in range(8):
            record=self.record_declaration(typ)
            if record is not None:return typ,record
            if typ in self._typedef_records:return typ,self._typedef_records[typ]
            target=next((t for (unit,name),t in self.typedefs.items() if name==typ),None)
            if target is None or target==typ:return typ,None
            typ=re.sub(r'^(?:const |volatile )+','',target.strip())
        return typ,None

    def type_layout(self,typ,depth=0):
        """(size, alignment) of a type under the AArch64 LP64 ABI: scalars, pointers, fixed arrays and
        records of them (C11 layout: members in order at aligned offsets, unions overlaid), or None."""
        typ=re.sub(r'^(?:const |volatile )+','',(typ or '').strip())
        if depth>8 or not typ:return None
        if not re.search(r'[\[*]',typ):typ,_=self.named_type(typ)
        if typ in self.SCALAR_BYTES:return self.SCALAR_BYTES[typ],self.SCALAR_BYTES[typ]
        if typ in ('__int128','unsigned __int128'):return 16,16
        if typ.endswith('*') and '(' not in typ:return 8,8
        array=re.fullmatch(r'(.+?)\s*\[(\d+)\]((?:\[\d+\])*)',typ)
        if array and '(' not in typ:
            inner=self.type_layout((array[1]+(' '+array[3] if array[3] else '')).strip(),depth+1)
            return (inner[0]*int(array[2]),inner[1]) if inner else None
        _,record=self.named_type(typ)
        if record is None:return None
        if any(c.get('kind')=='FieldDecl' and c.get('isBitfield') for c in walk(record)):return None
        size=0;align=1;union=record.get('tagUsed')=='union'
        members=[]
        for k,child in enumerate(children(record)):
            if child.get('kind')!='FieldDecl':continue
            if child.get('name'):
                layout=self.type_layout(type_of(child),depth+1)
                # A named member of an anonymous record type (union futex_key's `struct {...} shared;`): the
                # record is declared just before the field.
                previous=children(record)[k-1] if k else None
                if layout is None and previous is not None and previous.get('kind')=='RecordDecl' and not previous.get('name') and re.search(r'\((?:unnamed|anonymous) ',type_of(child)):
                    layout=self.anonymous_layout(previous,depth+1)
                members.append(layout)
            else:
                anonymous=children(record)[k-1] if k and children(record)[k-1].get('kind')=='RecordDecl' else None
                members.append(self.type_layout((anonymous.get('tagUsed','struct')+' '+anonymous['name']) if anonymous and anonymous.get('name') else None,depth+1) if anonymous is None or anonymous.get('name') else self.anonymous_layout(anonymous,depth+1))
        for member in members:
            if member is None:return None
            msize,malign=member;align=max(align,malign)
            if union:size=max(size,msize)
            else:size=(size+malign-1)//malign*malign+msize
        return (size+align-1)//align*align,align

    def anonymous_layout(self,record,depth):
        size=0;align=1;union=record.get('tagUsed')=='union'
        for k,child in enumerate(children(record)):
            if child.get('kind')!='FieldDecl':continue
            member=self.type_layout(type_of(child),depth+1) if child.get('name') else self.anonymous_layout(children(record)[k-1],depth+1) if k and children(record)[k-1].get('kind')=='RecordDecl' else None
            if member is None:return None
            msize,malign=member;align=max(align,malign)
            if union:size=max(size,msize)
            else:size=(size+malign-1)//malign*malign+msize
        return (size+align-1)//align*align,align

    def entry_path_type(self,path):
        """Declared type of an entry lvalue path (`argument:ctx->a[0][2]->b.c`), or None."""
        match=re.match(r'argument:ctx',path)
        if match is None:return None
        typ='struct osrec_kernel_context *';rest=path[match.end():]
        for step in re.findall(r'->[A-Za-z_]\w*|\.[A-Za-z_]\w*|\[\d+\]',rest):
            if step.startswith('['):
                array=re.fullmatch(r'(.+?)\s*\[(\d+)\]((?:\[\d+\])*)',typ)
                if array:typ=(array[1]+(' '+array[3] if array[3] else '')).strip();continue
                if typ.endswith('*'):typ=typ[:-1].strip();continue
                return None
            if step.startswith('->'):
                if not typ.endswith('*'):return None
                typ=typ[:-1].strip()
            record=self.record_declaration(typ)
            if record is None:return None
            name=step.lstrip('-.>');typ=next((f[1] for f in self.flat_fields(record) if f[0]==name),None)
            if typ is None:return None
        if ''.join(re.findall(r'->[A-Za-z_]\w*|\.[A-Za-z_]\w*|\[\d+\]',rest))!=rest:return None
        return typ

    def word_store(self,path):
        """An object that is one array of integers (`struct kmalloc_object {u64 words[24];}`), addressable by
        byte offset: (array path, element type, element bytes, element count, object type), or None.

        `path` is the object itself (`argument:ctx->kmalloc_object`) or a pointer field's value whose
        declared object type a pointer_objects contract gives (`...->cpu_slab->freelist`)."""
        typ=None;array_path=None
        direct=self.entry_path_type(path) if re.fullmatch(r'argument:ctx->[A-Za-z_]\w*',path) else None
        if direct is not None and self.record_declaration(direct) is not None:typ=direct;separator='.'
        else:
            member=re.fullmatch(r'(.+)(->|\.)([A-Za-z_]\w*)',path)
            if member is None:return None
            owner=self.entry_path_type(member[1])
            if owner is None:return None
            if member[2]=='->':
                if not owner.endswith('*'):return None
                owner=owner[:-1].strip()
            contract=self.pointer_objects.get((re.sub(r'^(?:const |volatile )+','',owner),member[3]))
            if contract is None:return None
            typ=contract['object_type'];separator='->'
        record=self.record_declaration(typ)
        if record is None or record.get('tagUsed')=='union':return None
        fields=self.flat_fields(record)
        if len(fields)!=1 or fields[0][1].count('[')!=1:return None
        array=fixed_array(fields[0][1])
        if array is None:return None
        element=array[1].strip();size=self.SCALAR_BYTES.get(self.named_type(element)[0])
        if size is None:return None
        return path+separator+fields[0][0],element,size,int(array[2]),typ

    def allocation_token(self,name,node,stack):
        """The summarized object an allocator call returns: one per call site, owned by the root frame
        (the allocation outlives the allocating call; kfree ends its use)."""
        contract=self.allocations[name];owner=(stack[0],) if stack else ()
        key='allocation:'+str(node.get('id'))
        token=self._auto_objects.get((owner,key))
        if token is None:
            token='auto:%d'%len(self._auto_objects);self._auto_objects[(owner,key)]=token
            self._auto_info[token]=dict(owner=owner,declaration=key,initialized=False,allocation=contract,
                summary=dict(element_type=contract['element_type'],elements=contract['elements']))
        return token

    def integer_address(self,node,env,stack,depth=0):
        """[(object path, low, high)] for an integer that is an object's address plus a proven byte offset:
        `(unsigned long)p + off`, through casts and single reaching definitions of integer locals."""
        if depth>8:return None
        while node.get('kind')=='ParenExpr' or node.get('kind') in ('ImplicitCastExpr','CStyleCastExpr') and node.get('castKind') in ('NoOp','LValueToRValue','IntegralCast') and type_of(node) in POINTER_WIDTH_INTEGERS:
            if not children(node):return None
            node=children(node)[0]
        kind=node.get('kind');terms=children(node)
        if kind in ('ImplicitCastExpr','CStyleCastExpr') and node.get('castKind')=='PointerToIntegral' and terms and type_of(node) in POINTER_WIDTH_INTEGERS:
            inner=terms[0]
            while inner.get('kind')=='ParenExpr' or inner.get('kind') in ('ImplicitCastExpr','CStyleCastExpr') and inner.get('castKind') in ('NoOp','BitCast') and children(inner):inner=children(inner)[0]
            if inner.get('kind') in ('ImplicitCastExpr','CStyleCastExpr') and inner.get('castKind')=='IntegralToPointer' and children(inner):
                return self.integer_address(children(inner)[0],env,stack,depth+1)
            self.quiet+=1
            try:values=self.resolve(terms[0],env,stack)-{INFEASIBLE}
            finally:self.quiet-=1
            if not values or any(self.word_store(v) is None and not self._auto_info.get(v,{}).get('allocation') for v in values):return None
            return [(v,0,0) for v in sorted(values)]
        if kind=='BinaryOperator' and node.get('opcode')=='+' and len(terms)==2:
            for base,offset in (terms,terms[::-1]):
                found=self.integer_address(base,env,stack,depth+1)
                if found is None:continue
                self.quiet+=1
                try:bounds,_=self.fallback_index_bounds(offset,stack)
                finally:self.quiet-=1
                if bounds is None or bounds[0]<0:return None
                return [(p,low+bounds[0],high+bounds[1]) for p,low,high in found]
            return None
        if kind=='DeclRefExpr' and stack and stack[-1] in self.functions:
            declaration=node.get('referencedDecl',{});facts=self.values.facts_for(stack[-1])
            if declaration.get('kind')!='VarDecl' or declaration.get('id') in self.globals or declaration.get('id') in facts.escaped or not facts.contains(node):return None
            definition=facts.reaching(node,declaration['id'])
            return self.integer_address(definition,env,stack,depth+1) if definition is not None else None
        return None

    def allocation_bytes(self,allocation):
        _,_,size,count,_=self.word_store(allocation['object'].rsplit('.',1)[0]) or (None,None,0,0,None)
        return size*count

    def word_store_pointer(self,cast,env,stack):
        """Bounded pointers for `(T *)integer` whose integer is a word-store object's address plus a proven offset."""
        if not children(cast):return None
        found=self.integer_address(children(cast)[0],env,stack)
        access=self.type_bytes(type_of(cast).strip()[:-1]) if type_of(cast).strip().endswith('*') else None
        if not found or access is None:return None
        result=set()
        for path,low,high in found:
            allocation=self._auto_info.get(path,{}).get('allocation')
            if allocation is not None:
                # SLUB's free pointer, stored into the object kfree releases: freed memory the call no longer
                # reads (kernel memory safety: no use after free), so the store has no tracked effect.
                if high+access>self.allocation_bytes(allocation):
                    self.issue('array_bounds',cast,stack,'byte offset reaches outside its allocation');return set()
                self.allocation_uses.append(dict(kind='allocation_byte_offset',function=stack[-1],call_path=stack,location=self.location(cast),
                    allocation=allocation['function'],byte_offsets=[low,high],access_bytes=access,assumption='the allocation is not read after kfree stores its free pointer'))
                result.add(path);continue
            array,element,size,count,_=self.word_store(path)
            if high+access>size*count:
                self.issue('array_bounds',cast,stack,'byte offset reaches outside its object');return set()
            origin=dict(identity='word-store:'+array,path=array,extent=count,element_type=element,owner=(),scope=(),immutable_global=None,array_type_evidence=None)
            # Every element an access of `access` bytes at an offset in [low, high] can touch.
            for k in range(low//size,(high+access-1)//size+1):result.add(self.bounded_pointer(origin,k,cast,stack))
            self.derived_proofs.append(dict(kind='word_store_byte_offset',function=stack[-1],call_path=stack,location=self.location(cast),
                object=path,array=array,byte_offsets=[low,high],access_bytes=access,elements=[low//size,(high+access-1)//size]))
        return result

    def bounded_pointer(self,origin,offset,node,stack):
        """Intern pointer values separately from lvalue object-path strings."""
        key=(origin['identity'],origin['path'],origin['extent'],origin['element_type'],origin['owner'],origin['scope'],offset)
        if key not in self._bounded_pointer_keys:
            token='bounded-pointer:'+str(len(self._bounded_pointer_keys))
            self._bounded_pointer_keys[key]=token
            self._bounded_pointers[token]={**origin,'offset':offset}
        return self._bounded_pointer_keys[key]

    def array_pointer(self,node,env,stack):
        """Retain only configured one-dimensional numeric array decays."""
        if node.get('kind')!='ImplicitCastExpr' or node.get('castKind')!='ArrayToPointerDecay':return None
        terms=children(node)
        if len(terms)!=1:return None
        base=self.array_lvalue(unwrap(terms[0]));shape=declared_array_shape(type_of(base))
        if shape is None or len(shape[1])!=1:return None
        element,dimensions=shape;count=dimensions[0];key=base.get('referencedDecl',{}).get('id')
        completion=self.completed_global_arrays.get(key)
        if count is None and completion is not None:
            completed=declared_array_shape(completion['type'])
            if completed is not None:element,(count,)=completed
        # Elements may be records spelled by a typedef (pud_t, a page table's descriptor).
        typedef_record=(base.get('_translation_unit'),element.removeprefix('const ').strip()) in self.record_typedefs
        if count is None or count<=0 or (self.numeric_element_type(element,base.get('_translation_unit')) is None and not object_pointer_element(element) and record_type_key(element) is None and not typedef_record):return None
        if base.get('kind')=='DeclRefExpr' and self.summary_array(key) is not None:
            token=self.summary_origin(key,node,stack)
            if token is not None:return {token}
        global_array=key in self.globals
        automatic=key in self.automatic_arrays
        compound=base.get('kind')=='CompoundLiteralExpr' and base.get('id') in self.automatic_compound_literals
        if not (global_array or automatic or compound or base.get('kind')=='MemberExpr'):return None
        paths=self.resolve(base,env,stack)
        # A dereferenced object path (`*(get_current()->files->fdt)->...`, from READ_ONCE) is
        # storage like any other; dereferences of locals or unknown origins are not.
        if not paths or any(re.match(r'^(?:\*\()*(?:unresolved:|null|bounded-pointer:|infeasible:)',p) or (p.startswith('*(') and 'local:' in p) for p in paths):return None
        identity=key if base.get('kind')=='DeclRefExpr' else base.get('referencedMemberDecl',base.get('id'))
        proof=self.immutable_globals.get(key) if global_array else None
        scope=()
        if any(path.startswith('local:') for path in paths):
            owners=[n.get('referencedDecl',{}).get('id') for n in walk(base) if n.get('kind')=='DeclRefExpr' and
                    n.get('referencedDecl',{}).get('id') in (self.automatic_arrays.keys()|self.automatic_records.keys())]
            if compound:owners.append(base.get('id'))
            if len(set(owners))!=1:return None
            scope=self.pointer_scopes(stack[-1]).get(owners[0])
            if scope is None:return None
        result=set()
        for path in paths:
            origin=dict(identity=identity,path=path,extent=count,element_type=element,
                        owner=tuple(stack) if path.startswith('local:') else (),scope=scope,
                        immutable_global=proof,array_type_evidence=completion)
            result.add(self.bounded_pointer(origin,0,node,stack))
        return self.bounded_aliases(result,node,stack)

    def automatic_view(self,pointer,paths,node,stack):
        """Read-only scalar elements of stack objects through a const pointer view (jhash2's `const u32 *k`).

        Every value must be a stack object (`auto:N`, or a member of one) or an address derived from
        one by arithmetic. The const pointee forbids writes through the view, so stored pointer values
        the analysis tracks are unchanged; reads, at any offset, touch only stack memory and are no
        entry state. The paths stay rooted at their objects, so access() checks the owning call.
        """
        pointee=type_of(pointer).strip()
        if not paths or not pointee.endswith('*') or not re.match(r'const\b',pointee) or not arithmetic_scalar(re.sub(r'^const\s+','',type_of(node).strip())):return None
        stack_object=r'auto:\d+(?:(?:->|\.)[A-Za-z_]\w*)*'
        origins=[]
        for path in paths:
            origin=self._derived_pointers.get(path,{}).get('path') if path in self._derived_pointers and self._derived_pointers[path].get('kind')=='object' else path
            if origin is None or not re.fullmatch(stack_object,origin):return None
            origins.append(origin)
        self.automatic_views.append(dict(function=stack[-1],call_path=stack,location=self.location(node),element_type=type_of(node),
            objects=sorted(set(origins)),access='read through a const pointer view'))
        return {'*('+o+')' for o in origins}

    def automatic_scalar_paths(self,pointer,paths):
        """Paths that are whole automatic objects (auto:N) declared with the pointer's pointee type, not arrays."""
        pointee=re.sub(r'\b(?:const|volatile)\b','',type_of(pointer)).replace('*','',1).strip() if '*' in type_of(pointer) else None
        if pointee is None or not paths:return False
        clean=lambda t:re.sub(r'\s+',' ',re.sub(r'\b(?:const|volatile)\b','',t)).strip()
        for path in paths:
            info=self._auto_info.get(path) if re.fullmatch(r'auto:\d+',path) else None
            if info is None or info.get('summary'):return False
            owner=info['owner'];declaration=next((n for n in self.values.facts_for(owner[-1]).order if n.get('id')==info['declaration']),None) if owner and owner[-1] in self.functions else None
            if declaration is None or fixed_array(type_of(declaration)) or clean(type_of(declaration))!=clean(pointee):return False
        return True

    def scalar_object_paths(self,pointer,paths):
        """Paths that are scalar fields taken by address, viewed through a pointer to the same type."""
        pointee=re.sub(r'\b(?:const|volatile)\b','',type_of(pointer)).replace('*','',1).strip() if '*' in type_of(pointer) else None
        if pointee is None or not paths:return False
        clean=lambda t:re.sub(r'\s+',' ',re.sub(r'\b(?:const|volatile)\b','',t)).strip()
        return all(p in self._scalar_objects and clean(self._scalar_objects[p])==clean(pointee) for p in paths)

    def volatile_field(self,path):
        """A declared volatile-field classification for a read of a scalar field taken by address."""
        inner=path[2:-1] if path.startswith('*(') and path.endswith(')') else path
        field=self._scalar_fields.get(inner)
        if field is None:return None
        return self.volatile_fields.get((self._field_records.get(field),self.fields.get(field,{}).get('name')))

    def scalar_address(self,node,target,stack):
        """Keep scalar storage separate from the value held in its alias env."""
        if target.get('kind')!='DeclRefExpr':return None
        key=target.get('referencedDecl',{}).get('id');declaration=self.automatic_scalars.get(key)
        if declaration is None:return None
        # A root's parameters are its arguments (entry state), not a frame of this analysis.
        if declaration.get('kind')=='ParmVarDecl' and len(stack)<2:return None
        scope=self.pointer_scopes(stack[-1]).get(key)
        if scope is None:return None
        path='local:'+declaration['name']
        origin=dict(identity=key,path=path,extent=1,element_type=type_of(declaration),owner=tuple(stack),scope=scope,
            immutable_global=None,array_type_evidence=None,storage_kind='automatic_scalar')
        self.scalar_addresses.append(dict(kind='automatic_numeric_scalar_address',variable=declaration['name'],
            type=type_of(declaration),declaration=self.location(declaration),location=self.location(node),
            function=stack[-1],call_path=stack,storage=path,elements=1,element_offset=0,
            owner_call_path=list(stack),lexical_scope_retained=True,value_aliases_not_used_as_storage=True,
            initializer_value_assumed=False))
        return {self.bounded_pointer(origin,0,node,stack)}

    def offset_pointers(self,node,env,stack):
        """Prove all alternatives in a pointer +/- integer operation."""
        terms=children(node);op=node.get('opcode')
        if len(terms)!=2 or op not in ('+','-'):return None
        pointer,index=terms
        if '*' not in type_of(pointer):
            if op!='+' or '*' not in type_of(index):return None
            pointer,index=index,pointer
        elif '*' in type_of(index):return None # differences need a separate value model
        paths=self.resolve(pointer,env,stack)
        # GNU byte offsets on a void * view would be counted in elements.
        if any(p in self._bounded_pointers for p in paths) and re.fullmatch(r'(?:(?:const|volatile)\s+)*void\s*\*.*',type_of(pointer).strip()):return None
        extent=self.extent_contract(pointer) if paths and any(p not in self._bounded_pointers for p in paths) else None
        if extent is not None and not any(re.search(r'(?:^|\*\()(?:null|unresolved:)|bounded-pointer:',p) for p in paths):
            # A contracted heap array behaves like an inline array of `elements` slots.
            element=re.sub(r'\s*\*\s*$','',type_of(unwrap(pointer)))
            paths={self.bounded_pointer(dict(identity=('extent',extent['record'],extent['field']),path=path,extent=extent['elements'],element_type=element,
                owner=(),scope=(),immutable_global=None,array_type_evidence=None),0,node,stack) for path in paths}
            self.extent_assumptions.append(extent['state_range'])
        if paths and self.scalar_object_paths(pointer,paths):
            # A scalar object is a one-element array: only offset 0 (or one past) is formed.
            bounds,_=self.index_bounds_for(index,stack)
            if bounds is None:bounds,_=self.fallback_index_bounds(index,stack)
            if bounds is not None and tuple(bounds)==(0,0):return set(paths)
            return None
        if not paths or any(p not in self._bounded_pointers for p in paths):return None
        bounds,proof=self.index_bounds_for(index,stack)
        if bounds is None:bounds,proof=self.fallback_index_bounds(index,stack)
        if bounds is None:return None
        low,high=bounds
        if op=='-':low,high=-high,-low
        if high-low+1>self.max_range_elements:
            self.issue('range_limit',node,stack,'pointer offset interval exceeds the configured element limit');return None
        origins=[self._bounded_pointers[p] for p in paths]
        if any(o['offset']+low<0 or o['offset']+high>o['extent'] for o in origins):
            self.issue('array_bounds',node,stack,'pointer formation exceeds its array or one-past extent');return None
        result=set()
        for origin in origins:
            for offset in range(origin['offset']+low,origin['offset']+high+1):
                result.add(self.bounded_pointer(origin,offset,node,stack))
                if len(result)>self.max_alias_paths:return self.bounded_aliases(result,node,stack)
        return result

    def same_array_operands(self,node,env,stack):
        """Validate all pointer alternatives against one live direct array."""
        terms=children(node)
        if len(terms)!=2 or not all('*' in type_of(c) for c in terms):return None
        sides=[self.resolve(c,env,stack) for c in terms]
        if any(not paths or any(p not in self._bounded_pointers for p in paths) for paths in sides):return None
        origins=[[self._bounded_pointers[p] for p in paths] for paths in sides]
        all_origins=origins[0]+origins[1];origin=all_origins[0]
        identity=lambda o:(o['identity'],o['path'],o['extent'],o['element_type'],o['owner'],o['scope'])
        storage=r'(?:global|local):(?:tu[0-9]+:)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|\[[0-9]+\])*'
        # An array a pointer member of entry state holds (a pointer_extents contract) is one array as long as the
        # call never stores that member: both operands then index the same loaded base (checked against the
        # final write set, see analyze()).
        reached=origin['identity'][0]=='extent' and re.fullmatch(r'argument:ctx->[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|\[[0-9]+\])*',origin['path'])
        if not (re.fullmatch(storage,origin['path']) or reached) or any(identity(o)!=identity(origin) or not 0<=o['offset']<=o['extent'] for o in all_origins):return None
        owner=origin['owner']
        if owner:
            if tuple(stack[:len(owner)])!=owner:return None
            if tuple(stack)==owner:
                scope=self.pointer_scopes(stack[-1]).get(node.get('id'))
                if scope is None or scope[:len(origin['scope'])]!=origin['scope']:return None
        offsets=[sorted({o['offset'] for o in side}) for side in origins]
        return origin,offsets

    def derived_pointer(self,origin,node,stack):
        """Intern a pointer formed by arithmetic whose offset is not proven: it is only an address."""
        key=json.dumps(origin,sort_keys=True,default=str)
        if key not in self._derived_keys:
            token='derived-pointer:'+str(len(self._derived_keys))
            self._derived_keys[key]=token;self._derived_pointers[token]=origin
        return self._derived_keys[key]

    def derived_pointers(self,node,env,stack):
        """`p + n` / `p - n` where n has no proven bound: an address derived from p's object, never dereferenced as such.

        Every use that reaches memory (a dereference, a store into non-automatic memory, a
        boundary argument other than a checked span, a root return) still blocks; the
        value remembers the array or object it was derived from."""
        terms=children(node);op=node.get('opcode')
        if node.get('kind')!='BinaryOperator' or len(terms)!=2 or op not in ('+','-'):return None
        pointer,index=terms
        if '*' not in type_of(pointer):
            if op!='+' or '*' not in type_of(index):return None
            pointer,index=index,pointer
        elif '*' in type_of(index):return None
        values=self.resolve(pointer,env,stack)
        if not values:return None
        if any(p in self._bounded_pointers for p in values) and not re.fullmatch(r'(?:(?:const|volatile)\s+)*void\s*\*.*',type_of(pointer).strip()):
            # A proven offset is judged by offset_pointers (in bounds, or an array_bounds formation);
            # it refuses byte offsets on void * views, which stay derived here.
            bounds,_=self.index_bounds_for(index,stack)
            if bounds is None:bounds,_=self.fallback_index_bounds(index,stack)
            if bounds is not None:return None
        result=set();origins=[]
        for value in values:
            if value==INFEASIBLE:continue
            if value.startswith('user:'):result.add(value);origins.append(dict(kind='user',path=value));continue
            if value in self._bounded_pointers:
                o=self._bounded_pointers[value]
                if o['owner'] and tuple(stack[:len(o['owner'])])!=o['owner']:return None
                origin=dict(kind='array',path=o['path'],extent=o['extent'],element_type=o['element_type'],owner=list(o['owner']),
                    immutable_global=o['immutable_global'])
            elif value in self._derived_pointers:origin=self._derived_pointers[value]
            elif (re.search(r'(?:^|\*\()(?:unresolved:|local:|const-address:|error-pointer)',value) or 'derived-pointer:' in value) and not re.search(r'bounded-pointer:|tagged:',value):
                # A value loaded through a derived pointer is as unknown as an unresolved one.
                # An unknown address stays unknown: every dereference of it already blocks.
                result.add('unresolved:pointer-arithmetic');origins.append(dict(kind='unresolved'));continue
            elif re.search(r'bounded-pointer:|tagged:',value) or value.startswith('function:'):return None
            elif value=='null':origin=dict(kind='null')
            else:origin=dict(kind='object',path=value)
            result.add(self.derived_pointer(origin,node,stack));origins.append(origin)
        if not result:return None
        self.derived_proofs.append(dict(kind='derived_pointer_address',function=stack[-1],call_path=stack,location=self.location(node),
            origins=sorted({json.dumps({k:v for k,v in o.items() if k!='immutable_global'},sort_keys=True) for o in origins}),
            dereference='blocked unless passed to a declared checked-span boundary'))
        return self.bounded_aliases(result,node,stack)

    def local_pointer_mutation(self,node,env,stack):
        """A local pointer stepped by an unproven offset holds a derived address (see alias_program)."""
        target=unwrap(children(node)[0]) if children(node) else {}
        if target.get('kind')!='DeclRefExpr' or target.get('referencedDecl',{}).get('id') in self.globals:return False
        value=self.mutation_expression(node)
        return value is not None and (self.summary_arithmetic(value,env,stack) is not None or self.offset_pointers(value,env,stack) is not None or self.derived_pointers(value,env,stack) is not None)

    def escaped_pointer_step(self,node,env,stack):
        """The value an escaped pointer local holds after `p++`, `p += n` and the like.

        Its value lives in the automatic-object store, which does not follow the counted-loop
        cursor proofs: a step that can repeat (in a loop, or with labels) is an unresolved value.
        """
        value=self.mutation_expression(node)
        stepped=self.summary_arithmetic(value,env,stack) if value is not None else None
        if stepped is not None:return stepped
        facts=self.function_facts(node,stack)
        if facts is None or facts.has_labels:return {'unresolved:pointer-mutation'}
        parent=facts.parent.get(id(node))
        while parent is not None:
            if parent.get('kind') in ('ForStmt','WhileStmt','DoStmt'):return {'unresolved:pointer-mutation'}
            parent=facts.parent.get(id(parent))
        value=self.mutation_expression(node)
        return self.resolve(value,env,stack) if value is not None else {'unresolved:pointer-mutation'}
    def mutation_expression(self,node):
        """`p++`, `p--`, `p += n`, `p -= n` as the value `p + 1`, `p - 1`, `p + n`, `p - n` (cached synthetic node)."""
        key=id(node)
        if key not in self._mutation_nodes:
            terms=children(node);result=None
            if terms and '*' in type_of(node):
                if node.get('kind')=='UnaryOperator' and node.get('opcode') in ('++','--'):
                    one={'kind':'IntegerLiteral','type':{'qualType':'int'},'value':'1','range':node.get('range',{})}
                    result={'kind':'BinaryOperator','opcode':'+' if node['opcode']=='++' else '-','type':node.get('type'),'range':node.get('range',{}),'inner':[terms[0],one],'id':str(node.get('id'))+'#value'}
                elif node.get('kind')=='CompoundAssignOperator' and node.get('opcode') in ('+=','-=') and len(terms)==2:
                    result={'kind':'BinaryOperator','opcode':node['opcode'][0],'type':node.get('type'),'range':node.get('range',{}),'inner':list(terms),'id':str(node.get('id'))+'#value'}
            self._mutation_nodes[key]=(node,result)
        return self._mutation_nodes[key][1]

    def derived_values(self,values):
        return [p for p in values if p in self._derived_pointers]

    def span_accesses(self,policy,node,inner,env,stack):
        """A checked-span boundary reads or writes the span its pointer argument names.

        The model fails at run time unless [pointer, pointer + length) lies inside one of
        the listed objects. A value derived from (or pointing into) a listed array selects
        that whole array; a value with another known origin never completes the call; a
        value of unknown origin may address any listed object.
        """
        for span in policy.get('spans',[]):
            index=span['pointer']
            if index>=len(inner)-1 or '*' not in type_of(inner[1+index]):
                self.issue('boundary_memory_effect',node,stack,'checked span does not name a pointer argument');continue
            values=self.resolve(inner[1+index],env,stack)-{INFEASIBLE}
            # An argument naming an automatic pointer object's storage (`p[i]` over `&object`) passes its value.
            for value in [v for v in values if re.fullmatch(r'\*\(auto:\d+\)',v)]:
                token=value[2:-1]
                if self.auto_record(token) is None:values=(values-{value})|self.auto_read(token,'*',node,stack)
            listed={};rejected=set();unknown=False
            for value in values:
                # Stack storage of this call chain (`automatic`): no entry state. Its tracked pointer fields take
                # the written bytes: null for a zero fill (memset), unresolved for data.
                stack_object=re.match(r'^(auto:\d+)((?:(?:->|\.)[A-Za-z_]\w*)*)$',self._derived_pointers.get(value,{}).get('path',value) if value in self._derived_pointers and self._derived_pointers[value].get('kind')=='object' else value)
                if stack_object and 'automatic' in span['objects'] and not self._auto_info.get(stack_object[1],{}).get('allocation'):
                    if span['access']=='write':
                        token=stack_object[1];prefix=re.sub(r'->|\.','.',stack_object[2]).strip('.')
                        written={'null'} if span.get('fill')=='zero' else {'unresolved:span-write'}
                        overwritten=self.overwritten_after(node,token,prefix,env,stack) if span.get('fill')=='zero' else set()
                        for (t,field) in list(self._auto_store):
                            if t==token and (not prefix or field==prefix or field.startswith(prefix+'.')) and field not in overwritten:self.auto_write(token,field,written,node,stack,strong=False)
                    self.span_proofs.append(dict(kind='automatic_storage_span',function=stack[-1],call_path=stack,location=self.location(node),object=stack_object[0],access=span['access'],fill=span.get('fill','data')))
                    continue
                # Null or a constant address lies in no listed object: the checked span fails there.
                if value=='null' or value.startswith(('const-address:','error-pointer')):rejected.add(value.split(':',1)[0]);continue
                origin=self._derived_pointers.get(value)
                # An allocation backed by a listed object: fresh memory of this call, no entry state.
                allocation=self._auto_info.get(origin['path'] if origin is not None and origin.get('kind')=='object' else value,{}).get('allocation')
                if allocation is not None and allocation['object'] in span['objects']:
                    self.allocation_uses.append(dict(kind='allocation_checked_span',function=stack[-1],call_path=stack,location=self.location(node),
                        allocation=allocation['function'],object=allocation['object'],access=span['access']));continue
                # A word-store object (or an address derived from one) whose array is a listed object, by type and member.
                stored=self.word_store(origin['path'] if origin is not None and origin.get('kind')=='object' else value) if origin is None or origin.get('kind')=='object' else None
                if stored is not None:
                    array,element,size,count,typ=stored;member=array.rsplit('.',1)[-1].rsplit('>',1)[-1]
                    match=next((o for o in span['objects'] if '.' in o and o.rsplit('.',1)[1]==member and (self.word_store(o.rsplit('.',1)[0]) or (None,)*5)[4]==typ),None)
                    if match is not None:
                        listed.setdefault(match,dict(kind='array',path=array,extent=count,element_type=element,owner=[],immutable_global=None,word_store=True))
                        if listed[match]['path']!=array:listed[match+'#'+array]=dict(kind='array',path=array,extent=count,element_type=element,owner=[],immutable_global=None,word_store=True)
                        continue
                if origin is None and value in self._bounded_pointers:
                    o=self._bounded_pointers[value];origin=dict(kind='array',path=o['path'],extent=o['extent'],element_type=o['element_type'],owner=list(o['owner']),immutable_global=o['immutable_global'])
                if origin is None or origin.get('kind') in ('unresolved','object'):unknown=True;continue
                if origin.get('kind')!='array':rejected.add(origin.get('kind'));continue
                normalized=re.sub(r'^global:tu[0-9]+:','global:',origin['path'])
                if normalized not in span['objects']:rejected.add(normalized);continue
                if origin['owner'] and tuple(stack[:len(origin['owner'])])!=tuple(origin['owner']):
                    self.issue('boundary_memory_effect',node,stack,'checked span pointer outlives its automatic array');continue
                listed[normalized]=origin
            if unknown and {k.split('#',1)[0] for k in listed}!=set(span['objects'])-{'automatic'}:
                # An unknown address may name any listed object; each must be materialized from a known pointer.
                self.issue('boundary_memory_effect',node,stack,'checked span pointer of unknown origin: every listed object must be reachable');continue
            for normalized,origin in sorted(listed.items()):
                paths={origin['path']+'['+str(k)+']' for k in range(origin['extent'])}
                element={'kind':'UnaryOperator','opcode':'*','type':{'qualType':origin['element_type']},'valueCategory':'lvalue','range':node.get('range',{}),'inner':[],'id':str(node.get('id'))+'#span'+str(span['pointer'])}
                # Keep the synthetic node alive: access types are keyed by its identity.
                self._mutation_nodes.setdefault(id(element),(element,None))
                for path in paths:
                    self._pointer_access_types[id(element),path]=origin['element_type']
                    if origin['immutable_global'] is not None and span['access']=='read':self._pointer_access_constants[id(element),path]=origin['immutable_global']
                self.access(paths,element,stack,span['access']=='write')
            self.span_proofs.append(dict(kind='checked_span_boundary',function=stack[-1],call_path=stack,location=self.location(node),
                boundary=policy.get('implementation'),objects=sorted(listed),access=span['access'],pointer_argument=index,length_argument=span['length'],
                rejected_at_run_time=sorted(rejected),selection='every element of each reachable checked object'))

    def container_of(self,node,env,stack):
        """`(char *)member_pointer - offsetof(T, m...)` whose every value is the address of member m of a T object.

        The designator comes from the compiler (see entry_state_offsetof); the object
        path and its declared record type come from the global's definition, so the
        result is exactly that object's address. Null alternatives must already be
        excluded by a dominating guard (they arrive as infeasible values).
        """
        terms=children(node)
        if node.get('kind')!='BinaryOperator' or node.get('opcode')!='-' or len(terms)!=2:return None
        offset=unwrap(terms[1]);designator=offset.get('_offsetof') if offset.get('kind')=='OffsetOfExpr' else None
        if not designator or not designator.get('field_only'):return None
        if not re.fullmatch(r'(?:(?:const|volatile)\s+)*(?:(?:signed|unsigned)\s+)?(?:char|void)\s*\*',type_of(terms[0]).strip()):return None
        suffix=''.join('.'+f for f in designator['fields']);result=set();origins=[]
        values=self.resolve(terms[0],env,stack)
        from entry_state_lists import head as list_head,sentinel as list_sentinel
        if values and self.empty_list_heads and all(list_head(self.empty_list_heads,v) for v in values):
            # The first entry of an empty list is no object: the walk cursor names only the head (entry_state_lists).
            self.list_proofs.append(dict(kind='empty_list_cursor',function=stack[-1],call_path=stack,location=self.location(node),
                record=designator['record'],member='.'.join(designator['fields']),heads=sorted({re.sub(r'\[\d+\]','[]',v) for v in values})))
            return {list_sentinel(v,'.'.join(designator['fields'])) for v in values}
        if values=={INFEASIBLE}:
            # The only value is null and a dominating guard excludes it: this arm never runs.
            self.container_proofs.append(dict(kind='container_of_unreachable',function=stack[-1],call_path=stack,location=self.location(node),
                reason='the member pointer is only null and a dominating guard proves it non-null'))
            return set()
        for value in values:
            walked=self.const_graph.walk(value,require_const=False) if value.startswith('global:') else None
            if walked is None or not walked[0].endswith(suffix):return None
            prefix=walked[0][:-len(suffix)];owner=self.const_graph.walk(prefix,require_const=False)
            from entry_state_const_graph import plain
            if owner is None or self.const_graph.resolve_type(owner[1],owner[3])!=plain(designator['record']):return None
            result.add(prefix);origins.append(dict(member=walked[0],object=prefix,record=designator['record']))
        if not result:return None
        self.container_proofs.append(dict(kind='container_of_member_address',function=stack[-1],call_path=stack,location=self.location(node),
            designator=dict(record=designator['record'],fields=designator['fields'],source=designator['source']),origins=sorted(origins,key=lambda o:o['object'])))
        return result

    def pointer_difference_value(self,node,env,stack):
        """`p - q` involving a derived pointer: an integer of unknown value; no memory is accessed."""
        terms=children(node)
        if node.get('kind')!='BinaryOperator' or node.get('opcode')!='-' or len(terms)!=2 or not all('*' in type_of(c) for c in terms):return False
        sides=[self.resolve(c,env,stack) for c in terms]
        if not all(sides):return False
        # Both sides one and the same object: an object is an array of one element, and p - p is 0.
        if len(sides[0])==1 and sides[0]==sides[1] and not re.search(r'(?:^|\*\()(?:unresolved:|local:|bounded-pointer:|null$|const-address:|error-pointer|user:)',next(iter(sides[0]))):
            self.derived_proofs.append(dict(kind='same_object_pointer_difference',function=stack[-1],call_path=stack,location=self.location(node),object=next(iter(sides[0])),value=0))
            return True
        if not any(self.derived_values(side) for side in sides):return False
        if any(re.search(r'(?:^|\*\()(?:unresolved:|local:)',p) for side in sides for p in side):return False
        self.derived_proofs.append(dict(kind='derived_pointer_difference',function=stack[-1],call_path=stack,location=self.location(node),value='unknown integer'))
        return True

    def user_arithmetic(self,node,env,stack):
        """`u + n`, `u - n` and `u - v` on user addresses: values, not kernel memory.

        A user address is the exact value the caller passed. The kernel never
        dereferences it directly (access() blocks that); boundaries check it at run time.
        """
        terms=children(node);pointers=[c for c in terms if '*' in type_of(c)]
        sides=[self.resolve(c,env,stack) for c in pointers]
        if not sides or not all(side and all(v.startswith('user:') for v in side) for side in sides):return None
        difference=len(pointers)==2
        self.user_address_proofs.append(dict(kind='user_address_difference' if difference else 'user_address_offset',function=stack[-1],
            call_path=stack,location=self.location(node),values=sorted(set().union(*sides)),kernel_memory=False))
        return set() if difference else set(sides[0])
    def pointer_difference(self,node,env,stack):
        """A same-array subtraction also needs a representable signed result."""
        if node.get('kind')!='BinaryOperator' or node.get('opcode')!='-' or type_of(node) not in ('int','long','long long'):return False
        checked=self.same_array_operands(node,env,stack)
        if checked is None:return False
        origin,offsets=checked;owner=origin['owner']
        low=offsets[0][0]-offsets[1][-1];high=offsets[0][-1]-offsets[1][0]
        if low < -32767 or high > 32767:return False
        self.pointer_differences.append(dict(kind='same_array_pointer_difference',function=stack[-1],call_path=stack,
            location=self.location(node),storage=origin['path'],elements=origin['extent'],element_type=origin['element_type'],
            left_offsets=offsets[0],right_offsets=offsets[1],bounds=[low,high],
            all_may_alias_pairs_checked=True,portable_result_range=[-32767,32767],
            automatic_storage=bool(owner),owner_call_path=list(owner),one_past_allowed=True))
        return True

    def fixed_object(self,value):
        """Storage the replay does not reconstruct: automatic objects and named globals."""
        origin=self._bounded_pointers.get(value)
        if origin is not None:
            if origin['owner']:return True
            value=origin['path']
        return bool(re.fullmatch(r'(?:auto:\d+|\*\(auto:\d+\)|global:[A-Za-z_]\w*)(?:\[\d+\]|\.\w+)*',value))
    def pointer_equality(self,node,env,stack):
        """`==`/`!=` between resolved pointers (an element pointer among them): no memory is read.

        Constants (null, constant addresses, the error range, functions), one path on both
        sides, and storage the replay does not rebuild compare alike at capture and replay.
        Other pairs (two reconstructed objects) need the pointer identity contract.
        """
        terms=children(node)
        if node.get('opcode') not in ('==','!=') or len(terms)!=2 or not all('*' in type_of(c) for c in terms):return False
        sides=[self.resolve(c,env,stack) for c in terms]
        if not all(sides) or any(re.search(r'(?:^|\*\()(?:unresolved:|local:)',p) for side in sides for p in side):return False
        constant=lambda v:v in ('null','error-pointer') or v.startswith('function:') or re.fullmatch(r'const-address:[0-9]+',v) is not None
        independent=all(constant(l) or constant(r) or l==r or self.fixed_object(l) and self.fixed_object(r) for l in sides[0] for r in sides[1])
        if not independent and self.pointer_identity is None:return False
        self.pointer_comparisons.append(dict(kind='pointer_equality',operator=node['opcode'],function=stack[-1],call_path=stack,location=self.location(node),
            result_range=[0,1],branch_pruning=False,memory_read=False,identity='address_independent' if independent else 'pointer_identity_contract'))
        return True
    def pointer_comparison(self,node,env,stack):
        """Admit the original runtime comparison without folding its value.

        Equality across distinct arrays and comparisons involving provider or
        unknown origins still need an identity model. Comparisons within one
        array need no ptrdiff_t subtraction or target-specific width claim.
        """
        if node.get('kind')!='BinaryOperator' or node.get('opcode') not in ('==','!=','<','>','<=','>=') or type_of(node)!='int':return False
        checked=self.same_array_operands(node,env,stack)
        if checked is None:return False
        origin,offsets=checked
        self.pointer_comparisons.append(dict(kind='same_array_pointer_comparison',operator=node['opcode'],
            function=stack[-1],call_path=stack,location=self.location(node),storage=origin['path'],
            elements=origin['extent'],element_type=origin['element_type'],left_offsets=offsets[0],right_offsets=offsets[1],
            all_may_alias_pairs_checked=True,result_range=[0,1],branch_pruning=False,index_bounds_inferred=False,
            automatic_storage=bool(origin['owner']),owner_call_path=list(origin['owner']),one_past_allowed=True,
            **({'base_pointer':origin['path'],'base_pointer_unwritten':True} if origin['path'].startswith('argument:') else {})))
        if origin['path'].startswith('argument:'):self._stable_bases.setdefault(origin['path'],(node,list(stack)))
        return True

    def bounded_pointer_return(self,paths,node,stack):
        """Internal returns transport stable array values, not new lifetimes.

        A selected root still needs a result-binding model. Automatic arrays,
        including borrowed caller storage, retain the existing escape blocker.
        Never accept just the known subset of a mixed may-alias return value.
        """
        # Named global objects may join the array elements (try_get_folio's folio: the bound user folio or a
        # page-cache pool element): they have static storage too, and every alternative is still kept.
        named=r'global:(?:tu[0-9]+:)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|\[[0-9]+\])*'
        if len(stack)<2 or not paths or any(p not in self._bounded_pointers and not re.fullmatch(named,p) for p in paths):return False
        origins=[self._bounded_pointers[p] for p in paths if p in self._bounded_pointers]
        if any(o['owner'] or not 0<=o['offset']<=o['extent'] for o in origins):return False
        self.pointer_returns.append(dict(kind='bounded_internal_array_return',
            function=stack[-1],call_path=stack,location=self.location(node),
            may_alias_origins_retained=len(paths),automatic_storage_allowed=False,
            origins=sorted([dict(storage=o['path'],elements=o['extent'],element_type=o['element_type'],
                                 element_offset=o['offset']) for o in origins],
                           key=lambda o:(o['storage'],o['elements'],o['element_type'],o['element_offset']))))
        return True

    def pointer_access(self,paths,node,stack,bounds=(0,0),proof=None):
        """Materialize checked element lvalues; never export internal tokens."""
        if not paths or not any(p in self._bounded_pointers for p in paths):return None
        ordinary={p for p in paths if p not in self._bounded_pointers}
        # A plain dereference may mix array elements with ordinary object paths;
        # an offset access through an ordinary path still has no proven extent.
        if ordinary and (bounds is None or tuple(bounds)!=(0,0) or any(re.search(r'(?:^|\*\()(?:null(?=$|->|[.\[\)])|unresolved:|const-address:|error-pointer)',p) for p in ordinary)):
            self.issue('unresolved_pointer_origin',node,stack,'bounded pointer also has an unproven origin');return set()
        paths=[p for p in paths if p in self._bounded_pointers]
        if bounds is None:
            self.issue('dynamic_extent',node,stack,'pointer subscript index bounds are not proven');return set()
        low,high=bounds;origins=[self._bounded_pointers[p] for p in paths]
        if any(o['offset']+low<0 or o['offset']+high>=o['extent'] for o in origins):
            self.issue('array_bounds',node,stack,'pointer dereference reaches outside its array elements');return set()
        if high-low+1>self.max_range_elements:
            self.issue('range_limit',node,stack,'pointer access interval exceeds the configured element limit');return set()
        result=set();per_array={};where=self.location(node)
        for origin in origins:
            if origin['owner'] and tuple(stack[:len(origin['owner'])])!=origin['owner']:
                self.issue('pointer_arithmetic',node,stack,'automatic array pointer is outside its owning call lifetime');return set()
            for offset in range(origin['offset']+low,origin['offset']+high+1):
                path=origin['path'] if origin.get('storage_kind')=='automatic_scalar' else origin['path']+'['+str(offset)+']'
                if path not in result:per_array[origin['path']]=per_array.get(origin['path'],0)+1
                result.add(path)
                self._pointer_access_types[id(node),path]=origin['element_type']
                if origin['immutable_global'] is not None:self._pointer_access_constants[id(node),path]=origin['immutable_global']
            self.ranges.append(dict(paths=[origin['path']],elements=origin['extent'],index_bounds=[origin['offset']+low,origin['offset']+high],
                selection='proven bounded pointer interval',element_type=origin['element_type'],access_form='bounded_pointer',
                bound_source='configured numeric array with propagated element offset',function=stack[-1],call_path=stack,location=where,
                pointer_provenance=dict(kind='object_relative_array_pointer',storage=origin['path'],extent=origin['extent'],element_offset=origin['offset'],automatic_lifetime_owner=list(origin['owner']))))
            if origin.get('storage_kind')=='automatic_scalar':
                self.ranges[-1]['bound_source']='configured automatic numeric scalar treated as one element'
                self.ranges[-1]['pointer_provenance']['storage_kind']='automatic_scalar'
            if proof is not None:self.ranges[-1]['index_proof']=proof
            if origin['array_type_evidence'] is not None:self.ranges[-1]['array_type_evidence']=origin['array_type_evidence']
            # The element limit applies to each array; the alias limit bounds how many arrays.
            if per_array.get(origin['path'],0)>self.max_range_elements:
                self.issue('range_limit',node,stack,'pointer access selection exceeds the configured element limit');return set()
        return result|{'*('+p+')' for p in ordinary}

    def access(self,paths,node,stack,write=False):
        if not paths:
            self.issue('unresolved_memory',node,stack,'memory address could not be resolved to an object path');return
        if any('list-head:' in p for p in paths):
            self.issue('unresolved_pointer_origin',node,stack,'an empty list walk cursor is not an object');return
        if '_Atomic' in type_of(node):
            self.issue('architecture_or_ordering',node,stack,'atomic memory access needs a target/state model')
        autos=[p for p in paths if re.match(r'^(?:\*\()*auto:\d+',p)]
        for path in autos:
            owner=self._auto_info[re.match(r'^(?:\*\()*(auto:\d+)',path)[1]]['owner']
            if tuple(stack[:len(owner)])!=owner:self.issue('unresolved_local_pointer',node,stack,'stack object used outside its owning call')
        paths=[p for p in paths if p not in autos]
        if autos and not paths:return
        if all(re.match(r'^(?:\*\()*'+INFEASIBLE,p) for p in paths):
            self.infeasible_accesses.append(dict(function=stack[-1],call_path=stack,location=self.location(node),
                reason='only value is null and a dominating guard proves non-null'))
            return
        for path in paths:
            if 'bounded-pointer:' in path:
                self.issue('unresolved_memory',node,stack,'bounded pointer value was not materialized as an element lvalue');continue
            if 'derived-pointer:' in path:
                self.issue('dynamic_extent',node,stack,'dereference of a derived pointer (unproven offset) needs a checked span');continue
            # Dereferences wrap origins in *(...), so checking only the first
            # characters can accidentally admit an unresolved alias. Match
            # origin positions, not legitimate fields/globals named "null".
            if re.search(r'(?:^|\*\()user:',path):
                self.issue('unresolved_pointer_origin',node,stack,'user address dereferenced outside a user-memory boundary');continue
            if re.search(r'(?:^|\*\()(?:null(?=$|->|[.\[\)])|unresolved:|const-address:|error-pointer)',path):
                self.issue('unresolved_pointer_origin',node,stack,'pointer may be null or have an unresolved origin');continue
            if re.match(r'^(?:\*\()*external:',path):
                # Memory returned by a declared external-memory boundary (for
                # example admitted user memory) is not kernel entry state.
                self.external_accesses.append(dict(path=path,write=write,type=type_of(node),function=stack[-1],call_path=stack,location=self.location(node)));continue
            if path.startswith('local:') or ('local:' in path and path.startswith('*(')):
                if 'volatile' in type_of(node) and not self.local_volatile_storage(node,stack):
                    self.issue('volatile_memory',node,stack,'classify volatile automatic storage before ignoring local memory')
                if '->' in path or path.startswith('*('):self.issue('unresolved_local_pointer',node,stack,'local pointer provenance is unresolved')
                continue
            member=node
            while member.get('kind')=='ArraySubscriptExpr':member=unwrap(children(member)[0])
            field=self.fields.get(member.get('referencedMemberDecl'),{})
            item={'path':path,'type':type_of(node),'function':stack[-1],'call_path':stack,'location':self.location(node),
                'pointer_edge':'*' in type_of(node),'volatile':'volatile' in type_of(node),
                'entry_candidate':not write,'bitfield':field.get('isBitfield',False)}
            if const_storage(type_of(field)):item['storage_const']=True
            if not write and node.get('kind')=='DeclRefExpr':
                proof=self.immutable_globals.get(node.get('referencedDecl',{}).get('id'))
                if proof is not None and path=='global:'+proof['object']:item['immutable_global']=proof
            elif not write and node.get('kind')=='ArraySubscriptExpr' and member.get('kind')=='DeclRefExpr':
                proof=self.immutable_globals.get(member.get('referencedDecl',{}).get('id'))
                if proof is not None and proof['kind']=='defined_const_numeric_array' and arithmetic_scalar(type_of(node)):
                    item['immutable_global']=proof
            provider=self.providers.get(path_provider(path),{})
            if write and provider.get('return_type','').startswith('const '):
                self.issue('const_argument_write',node,stack,'const object bindings currently require a readonly footprint')
            origin_type=self._pointer_access_types.get((id(node),path),'')
            if 'volatile' in origin_type:item['volatile']=True
            if const_storage(origin_type):
                item['storage_const']=True
                if write:self.issue('const_argument_write',node,stack,'bounded pointer write targets const array storage')
            classified=self.volatile_field(path) if item['volatile'] and not write else None
            if classified is not None:item['volatile_snapshot']=dict(record=classified['record'],field=classified['field'])
            elif item['volatile'] and self.volatile_accesses is not None and not re.search(r'(?:^|\*\()(?:null|unresolved:)|external:',path):
                item['volatile_snapshot']=dict(classification=self.volatile_accesses['classification'])
            elif item['volatile']:self.issue('volatile_memory',node,stack,'classify shared state or device memory')
            if not write and (id(node),path) in self._pointer_access_constants:
                item['immutable_global']=self._pointer_access_constants[id(node),path]
            if not write and 'immutable_global' not in item and arithmetic_scalar(type_of(node)):
                record=self.constant_record_for(path,type_of(node))
                if record is not None:item['immutable_global']=record
            if not write and 'immutable_global' not in item and re.fullmatch(r'global:(?:tu[0-9]+:)?[A-Za-z_]\w*',path) and type_of(node).startswith('const ') and record_type_key(type_of(node)) is not None:
                found=self.const_graph.definition(path[len('global:'):],syntax=False)
                if found is not None and type_of(found[0])==type_of(node):
                    item['immutable_global']=dict(kind='defined_const_record',object=path[len('global:'):],type=type_of(node),
                        initializer_sha256=digest(json.dumps(found[1],sort_keys=True,default=str).encode()),declaration_location=self.location(found[0]))
            if not write and 'immutable_global' not in item and path.startswith('global:'):
                leaf=self.const_graph.leaf(path,type_of(node))
                if leaf is not None:
                    definition,_=self.const_graph.definition(leaf['object'])
                    item['immutable_global']=dict(leaf,initializer_sha256=digest(json.dumps(leaf['initializer'],sort_keys=True).encode()),
                        declaration_location=self.location(definition))
            (self.writes if write else self.reads).append(item)

    @staticmethod
    def index_bounds(node):
        while node.get('kind')=='ParenExpr':node=children(node)[0]
        if node.get('kind') in SELECTIONS:
            selected=selected_expression(node)
            return Analyzer.index_bounds(selected) if selected is not None else None
        # Integer casts can truncate or change sign; do not strip them when
        # proving a constant index or interval.
        if node.get('kind')=='IntegerLiteral':
            value=int(node['value']);return value,value
        if node.get('kind')=='UnaryOperator' and node.get('opcode') in ('+','-'):
            child=Analyzer.index_bounds(children(node)[0])
            if child and child[0]==child[1]:
                # Unsigned negation wraps, so it is not a negative offset.
                # The portable constant evaluator below also rejects wrap.
                if node['opcode']=='-' and 'unsigned' in type_of(node) and child[0]!=0:return None
                value=child[0] * (-1 if node['opcode']=='-' else 1);return value,value
        if node.get('kind')=='BinaryOperator':
            left,right=children(node);constant=Analyzer.index_bounds(right)
            if constant and constant[0]==constant[1]:
                value=constant[0];unsigned='unsigned' in type_of(left)
                if node.get('opcode')=='%' and unsigned and value>0:return 0,value-1
                if node.get('opcode')=='&' and unsigned and value>=0:return 0,value
        return None

    def bounded_aliases(self,paths,node,stack):
        if len(paths)>self.max_alias_paths:
            self.alias_path_limit_observed=True
            if self.quiet:self._quiet_limits.append((node,list(stack)))
            self.issue('alias_limit',node,stack,'pointer alias path count exceeds configured limit of '+str(self.max_alias_paths))
            return {ALIAS_LIMIT_ORIGIN}
        # Unknown is absorbing, including after field/dereference projection.
        # Keeping a subset would restart growth and could suggest false origins.
        if self.alias_path_limit_observed and any(ALIAS_LIMIT_ORIGIN in p for p in paths):return {ALIAS_LIMIT_ORIGIN}
        return paths

    def static_index_bounds(self,node):
        """Cache syntax-only bounds; contextual loop-site proofs stay separate."""
        key=id(node)
        if self.cache_alias_syntax and key in self._static_index_cache:
            _,bounds,proof=self._static_index_cache[key];return bounds,proof
        bounds=self.index_bounds(node);proof=None
        if bounds is None:
            from entry_state_constants import constant_index,enum_values
            if self.loop_enum_values is None:self.loop_enum_values=enum_values(self.loop_enum_declarations)
            constant=constant_index(node,self.loop_enum_values)
            if constant is not None:bounds=constant['bounds'];proof=constant['proof']
        if self.cache_alias_syntax:self._static_index_cache[key]=(node,bounds,proof)
        return bounds,proof

    def local_index_definitions(self,name):
        """Index single definitions whose value cannot be changed or escaped."""
        if name in self._local_index_definitions:return self._local_index_definitions[name]
        nodes=self.effect_nodes(self.functions[name]);locals_={};definitions={};changed=set()
        for node in nodes:
            if node.get('kind')!='VarDecl' or node.get('id') in self.globals:continue
            locals_[node['id']]=node
            typ=type_of(node).removeprefix('const ');terms=children(node)
            if (typ not in INDEX_INTEGER_LIMITS or node.get('storageClass') is not None or node.get('tls') or
                terms and (not node.get('init') or len(terms)!=1)):continue
            definitions[node['id']]=[(terms[0],node)] if terms else []
        for node in nodes:
            terms=children(node);kind=node.get('kind');op=node.get('opcode')
            if not terms:continue
            target=unwrap(terms[0]);key=target.get('referencedDecl',{}).get('id')
            if target.get('kind')!='DeclRefExpr' or key not in definitions:continue
            if kind=='BinaryOperator' and op=='=' and len(terms)==2:definitions[key].append((terms[1],node))
            elif kind=='CompoundAssignOperator' or kind=='UnaryOperator' and op in ('&','++','--'):changed.add(key)
        values={key:dict(declaration=locals_[key],value=terms[0][0],definition=terms[0][1])
                for key,terms in definitions.items() if len(terms)==1 and key not in changed}
        if len(values)>64:values={}
        if values:
            from entry_state_dominance import definite_local_initialization
            certified=definite_local_initialization(self.functions[name],values,initialized_declarations=True)
            values={key:value for key,value in values.items() if key in certified}
        self._local_index_inputs[name]=dict(values)
        self._local_index_declarations[name]=locals_
        # Uncertified automatic dependencies cannot be hidden by a final mask.
        # Parameters and global/provider reads remain ordinary runtime inputs.
        while values:
            rejected={key for key,value in values.items() if any(n.get('kind')=='DeclRefExpr' and
                n.get('referencedDecl',{}).get('id') in locals_ and n['referencedDecl']['id'] not in values
                for n in self.effect_nodes(value['value']))}
            if not rejected:break
            values={key:value for key,value in values.items() if key not in rejected}
        self._local_index_definitions[name]=values
        return values

    def index_bounds_for(self,node,stack):
        """Expand certified local values only for proof, never for execution."""
        bounds,proof=self.static_index_bounds(node)
        if bounds is not None:return bounds,proof
        name=stack[-1];cache_key=(name,id(node))
        if cache_key not in self._local_index_cache:
            definitions=self.local_index_definitions(name);used=set();budget=[64]
            inputs=self._local_index_inputs[name];local_declarations=self._local_index_declarations[name]
            runtime_inputs=set();wide_used=[False]
            def expand(value,active):
                budget[0]-=1
                if budget[0]<0:raise ValueError('local index expansion limit')
                terms=children(value)
                if value.get('kind')=='ImplicitCastExpr' and value.get('castKind')=='LValueToRValue' and len(terms)==1:
                    target=unwrap(terms[0]);key=target.get('referencedDecl',{}).get('id')
                    if target.get('kind')=='DeclRefExpr' and key in definitions:
                        source=definitions[key]['value']
                        if key in active or type_of(source).removeprefix('const ')!=type_of(value):raise ValueError('unproved local index conversion')
                        used.add(key);return expand(source,active|{key})
                if not terms:return value
                replacement=[expand(child,active) for child in terms]
                return {**value,'inner':replacement} if any(a is not b for a,b in zip(terms,replacement)) else value
            def interval(value):
                result,evidence=self.static_index_bounds(value)
                if result is not None:return result,evidence
                terms=children(value);kind=value.get('kind');typ=type_of(value)
                from entry_state_constants import wide_unsigned_index
                wide=wide_unsigned_index(value,self.loop_enum_values)
                if wide is not None:
                    reduction=value
                    while reduction.get('kind')=='ParenExpr':reduction=children(reduction)[0]
                    references={n.get('referencedDecl',{}).get('id') for n in self.effect_nodes(children(reduction)[0]) if n.get('kind')=='DeclRefExpr'}
                    automatic=references&local_declarations.keys()
                    if not automatic<=inputs.keys():return None,None
                    runtime_inputs.update(automatic);wide_used[0]=True
                    return wide['bounds'],wide['proof']
                if kind=='ParenExpr' and len(terms)==1:return interval(terms[0])
                if kind=='ImplicitCastExpr' and value.get('castKind')=='IntegralCast' and typ in INDEX_INTEGER_LIMITS and len(terms)==1:
                    result,evidence=interval(terms[0])
                    low,high=INDEX_INTEGER_LIMITS[typ]
                    if result is not None and low<=result[0]<=result[1]<=high:
                        return result,dict(kind='value_preserving_32bit_integral_conversion' if typ in ('int','unsigned int') else 'value_preserving_minimum_width_integral_conversion',source_type=type_of(terms[0]),type=typ,operand=evidence)
                return None,None
            expanded=node
            try:
                expanded=expand(node,set());bounds,evidence=interval(expanded)
                if not used and not wide_used[0]:bounds=None;evidence=None
            except ValueError:bounds=None;evidence=None
            proof=None
            if bounds is not None:
                witnesses={**inputs,**definitions}
                proof=dict(kind='single_definition_local_index' if used or runtime_inputs else 'wide_unsigned_index',bounds=list(bounds),ast_node_limit=64,
                    locals=[dict(variable=witnesses[key]['declaration']['name'],type=type_of(witnesses[key]['declaration']),
                        declaration=self.location(witnesses[key]['declaration']),definition=self.location(witnesses[key]['definition']),
                        **({'role':'initialized_runtime_operand'} if key not in used else {}))
                        for key in sorted(used|runtime_inputs)],range_evidence=evidence,
                    evaluation='initialized before use; one definition; no address escape; original effects retained')
            self._local_index_cache[cache_key]=(node,expanded,bounds,proof)
        _,_,bounds,proof=self._local_index_cache[cache_key]
        if proof is not None:self.index_values.append(dict(function=name,call_path=stack,location=self.location(node),proof=proof))
        return bounds,proof

    def fallback_index_bounds(self,node,stack):
        """Path facts, state ranges and call returns, after every narrower proof failed."""
        bounds,proof=self.values.interval(node,stack[-1],self.context_ranges(stack)) if stack else (None,None)
        # A wide interval proves nothing useful here; keep reporting the index as unproven.
        if bounds is not None and bounds[1]-bounds[0]+1>self.max_range_elements:bounds,proof=None,None
        if proof is not None:self.index_values.append(dict(function=stack[-1],call_path=stack,location=self.location(node),proof=proof))
        return bounds,proof

    def effect_nodes(self,node):
        """Reuse immutable AST traversal order, never environment-dependent data."""
        if not self.cache_alias_syntax:return tuple(effect_walk(node))
        key=id(node)
        if key not in self._effect_nodes_cache:self._effect_nodes_cache[key]=tuple(effect_walk(node))
        # The tuple retains node itself, preventing identity reuse within a root.
        return self._effect_nodes_cache[key]

    def pointer_update_program(self,body):
        """Expand sequenced cursor versions, including one bounded loop.

        Each version depends on the preceding expression, never on the local
        pointer's eventual may-alias union. All versions still enter that union.
        Complete statements and explicit numeric-read/store contexts establish
        sequencing. A certified loop supplies an exact count or bounded prefixes;
        no general expression order or branch model is inferred.
        """
        if body.get('kind')=='FunctionDecl':body=next(c for c in children(body) if c.get('kind')=='CompoundStmt')
        cache_key=id(body)
        if cache_key in self._pointer_update_syntax:return self._pointer_update_syntax[cache_key][1]
        result={};self._pointer_update_syntax[cache_key]=(body,result)
        nodes=self.effect_nodes(body);statements=children(body);direct={id(n) for n in statements}
        if not any('*' in type_of(n) and (n.get('kind')=='UnaryOperator' and n.get('opcode') in ('++','--') or
            n.get('kind')=='CompoundAssignOperator' or n.get('kind')=='BinaryOperator' and n.get('opcode')=='=') for n in nodes):return result
        top_statements=statements;loop_domains={};loop_bindings={};allowed_compounds={id(body)};allowed_loops=set()
        loops=[n for n in top_statements if n.get('kind')=='ForStmt']
        if len(loops)>1:return result
        if loops:
            from entry_state_loops import fixed_cursor_loop
            from entry_state_constants import enum_values
            if self.loop_enum_values is None:self.loop_enum_values=enum_values(self.loop_enum_declarations)
            certified=fixed_cursor_loop(loops[0],self.location,constants=self.loop_enum_values)
            if certified is None:return result
            for domain in certified['updates']:
                loop_domains[id(domain['update'])]=domain['proof']
                loop_bindings[id(domain['update'])]=domain['bindings']
            allowed_loops.add(id(loops[0]))
            loop_body=certified['body'];allowed_compounds.add(id(loop_body))
            statements=[]
            for statement in top_statements:
                statements.extend((children(loop_body) if loop_body.get('kind')=='CompoundStmt' else [loop_body]) if statement is loops[0] else [statement])
            direct={id(n) for n in statements}
        if body.get('kind')!='CompoundStmt' or any(
            n.get('kind')=='CompoundStmt' and id(n) not in allowed_compounds or
            n.get('kind')=='ForStmt' and id(n) not in allowed_loops or n.get('kind') in (
            'IfStmt','WhileStmt','DoStmt','SwitchStmt','GotoStmt','LabelStmt','IndirectGotoStmt') for n in nodes):return result
        if any(n.get('kind')=='ReturnStmt' and (not top_statements or n is not top_statements[-1]) for n in nodes):return result
        consumed={}
        def transparent(node):
            while node.get('kind')=='ParenExpr' or (node.get('kind')=='ImplicitCastExpr' and node.get('castKind') in ('LValueToRValue','NoOp')):
                terms=children(node)
                if len(terms)!=1:return None
                node=terms[0]
            return node
        for statement in statements:
            terms=children(statement);value=None;assignment_target=None
            if statement.get('kind')=='ReturnStmt' and len(terms)==1:value=terms[0]
            elif statement.get('kind')=='DeclStmt' and len(terms)==1:
                declaration=terms[0];initial=children(declaration)
                if declaration.get('kind')=='VarDecl' and arithmetic_scalar(type_of(declaration)) and len(initial)==1:value=initial[0]
            elif len(terms)==2 and (statement.get('kind')=='BinaryOperator' and statement.get('opcode')=='=' or statement.get('kind')=='CompoundAssignOperator' and statement.get('opcode') in ('+=','-=','*=','/=','%=','<<=','>>=','&=','|=','^=')):
                target=transparent(terms[0])
                if target and arithmetic_scalar(type_of(target)):value=terms[1];assignment_target=terms[0]
            if value is None:continue
            value=transparent(value)
            while value and value.get('kind')=='ImplicitCastExpr' and len(children(value))==1 and arithmetic_scalar(type_of(value)) and arithmetic_scalar(type_of(children(value)[0])):
                value=transparent(children(value)[0])
            if not value or value.get('kind')!='UnaryOperator' or value.get('opcode')!='*' or not arithmetic_scalar(type_of(value)):continue
            terms=children(value)
            update=transparent(terms[0]) if len(terms)==1 else None
            if update and update.get('kind')=='UnaryOperator' and update.get('opcode') in ('++','--') and '*' in type_of(update):
                source=transparent(children(update)[0]);key=source.get('referencedDecl',{}).get('id') if source else None
                if assignment_target is not None and (key is None or any(n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('id')==key for n in self.effect_nodes(assignment_target))):continue
                consumed[id(update)]=dict(context='sequenced_numeric_dereference')
        for statement in statements:
            terms=children(statement);kind=statement.get('kind');op=statement.get('opcode')
            if len(terms)!=2 or not (kind=='BinaryOperator' and op=='=' or kind=='CompoundAssignOperator' and op in ('+=','-=','*=','/=','%=','<<=','>>=','&=','|=','^=')):continue
            target=transparent(terms[0])
            if not target or target.get('kind')!='UnaryOperator' or target.get('opcode')!='*' or not arithmetic_scalar(type_of(target)):continue
            address=children(target);update=transparent(address[0]) if len(address)==1 else None
            if not update or update.get('kind')!='UnaryOperator' or update.get('opcode') not in ('++','--') or '*' not in type_of(update):continue
            operands=children(update);variable=transparent(operands[0]) if len(operands)==1 else None
            if not variable or variable.get('kind')!='DeclRefExpr':continue
            key=variable.get('referencedDecl',{}).get('id')
            # C does not order assignment operands. The address update may not
            # race a read/change of the cursor on the other side. Address
            # escapes are separately rejected for the entire cursor program.
            if key is None or any(n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('id')==key for n in self.effect_nodes(terms[1])):continue
            consumed[id(update)]=dict(context='independent_numeric_store',store_operator=op)
        declarations={}
        for statement in top_statements:
            if statement.get('kind')!='DeclStmt':continue
            for node in children(statement):
                terms=children(node)
                if (node.get('kind')=='VarDecl' and '*' in type_of(node) and node.get('storageClass') is None and
                    not node.get('tls') and node.get('init') and len(terms)==1 and
                    not any(n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('id')==node['id'] for n in self.effect_nodes(terms[0]))):
                    declarations[node['id']]=node
        if len(declarations)>64:return result
        for key,declaration in declarations.items():
            versions=[children(declaration)[0]];updates=[];invalid=False
            for node in nodes:
                terms=children(node);kind=node.get('kind');op=node.get('opcode')
                if not terms:continue
                target=unwrap(terms[0]);target_key=target.get('referencedDecl',{}).get('id')
                if target.get('kind')!='DeclRefExpr' or target_key!=key:continue
                if kind=='UnaryOperator' and op=='&':invalid=True;break
                mutation=(kind=='UnaryOperator' and op in ('++','--') or kind=='CompoundAssignOperator' or kind=='BinaryOperator' and op=='=')
                if not mutation:continue
                if id(node) not in direct and id(node) not in consumed:invalid=True;break
                if kind=='UnaryOperator':
                    index={'kind':'IntegerLiteral','value':'1','type':{'qualType':'int'}};operation='+' if op=='++' else '-'
                elif kind=='CompoundAssignOperator' and op in ('+=','-='):
                    index=terms[1];operation=op[0]
                elif kind=='BinaryOperator' and op=='=':
                    if any(n.get('kind')=='CStyleCastExpr' or n.get('castKind') in ('IntegralToPointer','PointerToIntegral','BitCast') for n in self.effect_nodes(terms[1])):
                        invalid=True;break
                    value=unwrap(terms[1]);parts=children(value);operation=value.get('opcode')
                    if value.get('kind')!='BinaryOperator' or operation not in ('+','-') or len(parts)!=2:invalid=True;break
                    pointer,index=parts
                    if '*' not in type_of(pointer) and operation=='+':pointer,index=index,pointer
                    if (unwrap(pointer).get('referencedDecl',{}).get('id')!=key or
                        any(n.get('kind')=='CStyleCastExpr' for n in self.effect_nodes(pointer))):invalid=True;break
                else:invalid=True;break
                if any(n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('id')==key for n in self.effect_nodes(index)):
                    invalid=True;break
                loop=loop_domains.get(id(node));before_versions=[];after_versions=[];initial_versions=versions
                for _ in range(loop.get('maximum_iterations',loop.get('iterations')) if loop else 1):
                    before_versions.extend(versions)
                    versions=[{**node,'kind':'BinaryOperator','opcode':operation,'inner':[version,index]} for version in versions]
                    after_versions.extend(versions)
                entry=dict(declaration=declaration,before=before_versions[0],after=after_versions[-1],index=index,
                    operation=op,variable=key,result_used=id(node) in consumed,
                    result_context=consumed.get(id(node)),
                    result_version='before' if node.get('isPostfix') else 'after')
                if loop or len(before_versions)>1:entry.update(before_alternatives=before_versions,after_alternatives=after_versions)
                if loop:entry.update(loop=loop,body_bindings=loop_bindings[id(node)])
                if loop and loop.get('all_exit_prefixes_retained'):versions=[*initial_versions,*after_versions]
                updates.append((node,entry))
            if not invalid and 0<sum(len(e.get('after_alternatives',(e['after'],))) for n,e in updates)<=16:
                result.update((id(node),entry) for node,entry in updates)
        return result

    def pointer_update_values(self,entry,version,env,stack,node):
        values=set()
        for expression in entry.get(version+'_alternatives',(entry[version],)):
            values=self.bounded_aliases(values|self.resolve(expression,env,stack),node,stack)
        return values

    def loop_cursor_value(self,node,env,stack):
        """Bind an ordinary cursor read at its full-statement loop phase."""
        key=node.get('referencedDecl',{}).get('id')
        for entry in self.pointer_update_program(self.functions[stack[-1]]).values():
            if entry['variable']!=key:continue
            binding=entry.get('body_bindings',{}).get(id(node))
            if binding is not None:return self.pointer_update_values(entry,binding[1],env,stack,node)
        return None

    def pointer_update(self,node,env,stack):
        entry=self.pointer_update_program(self.functions[stack[-1]]).get(id(node))
        if entry is None:return None
        paths=env.get(entry['variable'],set())
        if not paths or any(p not in self._bounded_pointers for p in paths):return None
        before=self.pointer_update_values(entry,'before',env,stack,node);after=self.pointer_update_values(entry,'after',env,stack,node)
        if not before or not after or any(p not in self._bounded_pointers for p in before|after):return None
        def origins(values):
            return sorted([dict(storage=o['path'],elements=o['extent'],element_type=o['element_type'],element_offset=o['offset'])
                for o in (self._bounded_pointers[p] for p in values)],key=lambda o:json.dumps(o,sort_keys=True))
        proof=dict(kind='straight_line_bounded_pointer_update',variable=entry['declaration']['name'],
            declaration=self.location(entry['declaration']),location=self.location(node),function=stack[-1],call_path=stack,
            operation=entry['operation'],before=origins(before),after=origins(after),all_versions_retained=True,
            may_alias_origins_retained=len(paths),statement_result_used=entry['result_used'],max_updates=16)
        if entry.get('loop'):proof.update(kind='bounded_counted_loop_pointer_update',loop=entry['loop'])
        if entry.get('loop',{}).get('all_exit_prefixes_retained'):
            proof['exit_prefix_origins']=origins(before|after)
        if entry.get('body_bindings'):
            proof['iteration_value_bindings']=[dict(location=self.location(reference),version=version)
                for reference,version in entry['body_bindings'].values()]
        if entry['result_used']:
            context=entry['result_context']
            proof.update(result_version=entry['result_version'],result_origins=proof[entry['result_version']],result_context=context['context'])
            if context['context']=='independent_numeric_store':
                proof.update(store_operator=context['store_operator'],rhs_independent_of_cursor=True)
        self.pointer_updates.append(proof)
        return entry

    def alias_program(self,body):
        """Index seed operations and assignments without evaluating aliases."""
        key=id(body)
        if self.cache_alias_syntax and key in self._alias_program_cache:return self._alias_program_cache[key]
        seeds=[];assignments=[];updates=self.pointer_update_program(body)
        for statement in self.effect_nodes(body):
            update=updates.get(id(statement))
            if update is not None:
                assignments.extend((update['variable'],version) for version in update.get('after_alternatives',(update['after'],)));continue
            kind=statement.get('kind')
            if (kind=='UnaryOperator' and statement.get('opcode') in ('++','--') or
                    kind=='CompoundAssignOperator' and statement.get('opcode') in ('+=','-=')) and '*' in type_of(statement):
                target=unwrap(children(statement)[0]);declaration=target.get('referencedDecl',{}).get('id')
                if target.get('kind')=='DeclRefExpr' and declaration not in self.globals:
                    value=self.mutation_expression(statement)
                    if value is not None:assignments.append((declaration,value))
                    else:seeds.append(('mutation',declaration,'unresolved:pointer-mutation',statement))
            if kind=='VarDecl' and '*' in type_of(statement):
                parts=children(statement)
                if parts:assignments.append((statement['id'],parts[-1]))
                else:seeds.append(('local',statement['id'],'local:'+statement.get('name','unknown'),statement))
            elif kind=='VarDecl' and children(statement) and statement['id'] not in self.globals and type_of(statement) in POINTER_WIDTH_INTEGERS:
                assignments.append((statement['id'],children(statement)[-1]))
            elif kind=='CompoundAssignOperator' and statement.get('opcode') in ('|=','&=') and type_of(statement) in POINTER_WIDTH_INTEGERS:
                parts=children(statement);left=unwrap(parts[0]);declaration=left.get('referencedDecl',{}).get('id')
                if left.get('kind')=='DeclRefExpr' and declaration not in self.globals:
                    assignments.append((declaration,{**statement,'kind':'BinaryOperator','opcode':statement['opcode'][0],'inner':parts,'_statement':statement,'_target':declaration}))
            elif kind=='VarDecl' and children(statement) and statement['id'] not in self.globals and self.record_pointer_fields(type_of(statement)):
                assignments.append((('record',statement['id']),children(statement)[-1]))
            elif kind=='BinaryOperator' and statement.get('opcode')=='=':
                parts=children(statement);left=unwrap(parts[0]);declaration=left.get('referencedDecl',{}).get('id')
                if left.get('kind')=='DeclRefExpr' and ('*' in type_of(left) or type_of(left) in POINTER_WIDTH_INTEGERS) and declaration not in self.globals:
                    assignments.append((declaration,parts[1]))
                elif left.get('kind')=='DeclRefExpr' and declaration not in self.globals and self.record_pointer_fields(type_of(left)):
                    assignments.append((('record',declaration),parts[1]))
                elif left.get('kind')=='MemberExpr' and not left.get('isArrow') and '*' in type_of(left):
                    base=unwrap(children(left)[0]);owner=base.get('referencedDecl',{})
                    if base.get('kind')=='DeclRefExpr' and owner.get('kind') in ('VarDecl','ParmVarDecl') and owner.get('id') not in self.globals:
                        assignments.append((owner['id']+'.'+left['name'],parts[1]))
        result=(tuple(seeds),tuple(assignments))
        if self.cache_alias_syntax:self._alias_program_cache[key]=result
        return result

    def return_alias_program(self,function):
        """Index the existing return-alias scan, preserving its statement order."""
        key=id(function)
        if self.cache_alias_syntax and key in self._return_program_cache:return self._return_program_cache[key]
        updates=[];returns=[]
        for statement in self.effect_nodes(function):
            kind=statement.get('kind');parts=children(statement)
            if kind=='VarDecl' and parts:updates.append((statement['id'],parts[-1],statement))
            if kind=='BinaryOperator' and statement.get('opcode')=='=':
                left=unwrap(parts[0])
                if left.get('kind')=='DeclRefExpr':updates.append((left.get('referencedDecl',{}).get('id'),parts[1],statement))
            if kind=='ReturnStmt' and parts:returns.append((parts[0],statement))
        result=(tuple(updates),tuple(returns))
        if self.cache_alias_syntax:self._return_program_cache[key]=result
        return result

    def resolve(self,node,env,stack):
        paths=self._resolve(node,env,stack)
        if self._bounded_pointers:self.pointer_lifetime(paths,node,stack)
        if len(paths)<=self.max_alias_paths and not self.alias_path_limit_observed:return paths
        return self.bounded_aliases(paths,node,stack)

    def expression_syntax(self,node):
        """Index immutable expression syntax, retaining the original node."""
        key=id(node)
        if self.cache_alias_syntax and key in self._expression_nodes_cache:return self._expression_nodes_cache[key]
        expression=unwrap(node)
        result=(node,expression,expression.get('kind'),tuple(children(expression)))
        if self.cache_alias_syntax:self._expression_nodes_cache[key]=result
        return result

    def direct_call(self,node):
        """Cache direct call spelling only; callback targets still use env."""
        if not self.cache_alias_syntax:return callee(node)
        key=id(node)
        if key not in self._direct_calls_cache:self._direct_calls_cache[key]=(node,callee(node))
        return self._direct_calls_cache[key][1]

    def parameters(self,node):
        key=id(node)
        if self.cache_alias_syntax and key in self._parameters_cache:return self._parameters_cache[key][1]
        result=tuple(c for c in children(node) if c.get('kind')=='ParmVarDecl')
        if self.cache_alias_syntax:self._parameters_cache[key]=(node,result)
        return result

    def integer_bit_intrinsic(self,node):
        parts=children(node)
        if len(parts)!=2:return None
        target=parts[0]
        while target.get('kind')=='ParenExpr' or (target.get('kind')=='ImplicitCastExpr' and target.get('castKind') in ('BuiltinFnToFnPtr','FunctionToPointerDecay')):
            terms=children(target)
            if len(terms)!=1:return None
            target=terms[0]
        if target.get('kind')!='DeclRefExpr':return None
        ref=target.get('referencedDecl',{})
        declaration=self.integer_bit_declarations.get(ref.get('id'))
        if declaration is None or ref.get('kind')!='FunctionDecl':return None
        name,result,argument=declaration
        if ref.get('name')!=name or type_of(ref)!=result+' ('+argument+')':return None
        if type_of(node)!=result or type_of(parts[1])!=argument:return None
        return {'kind':'integer_bit_operation','name':name,'return_type':result,'argument_type':argument,
                'recognition':'implicit Clang BuiltinAttr and ConstAttr with exact integer signature'}

    def trap_asm(self,node,stack):
        """An operand-less asm followed by __builtin_unreachable() is a trap (arm64 BUG()): the path ends there."""
        if node.get('kind')!='GCCAsmStmt' or children(node) or not stack or stack[-1] not in self.functions:return False
        facts=self.values.facts_for(stack[-1]);block=facts.parent.get(id(node))
        if block is None or block.get('kind')!='CompoundStmt':return False
        terms=children(block);index=next(i for i,t in enumerate(terms) if t is node)
        # unreachable() is `do { annotate_unreachable(); __builtin_unreachable(); } while (0)`;
        # empty annotations leave null statements between the asm and the builtin.
        def first(statements):
            for statement in statements:
                if statement.get('kind')=='NullStmt':continue
                if statement.get('kind')=='DoStmt' and children(statement):return first(children(children(statement)[0]) if children(statement)[0].get('kind')=='CompoundStmt' else children(statement)[:1])
                if statement.get('kind')=='CompoundStmt':return first(children(statement))
                return statement
            return {}
        following=first(terms[index+1:])
        builtin=self.compile_time_builtin(following) if following.get('kind')=='CallExpr' else None
        if builtin is None or builtin['name']!='__builtin_unreachable':return False
        self.trap_proofs.append(dict(kind='operand_free_asm_trap',function=stack[-1],call_path=stack,location=self.location(node),
            evidence='no asm operands; immediately followed by __builtin_unreachable(); control does not continue'))
        return True

    def low_constant(self,node):
        """('value', c) for a constant 0..7, ('clear', L) for ~L with L in 0..7."""
        while node.get('kind') in ('ParenExpr','ConstantExpr') or node.get('kind') in ('ImplicitCastExpr','CStyleCastExpr') and node.get('castKind') in ('IntegralCast','NoOp'):
            terms=children(node)
            if len(terms)!=1:return None
            node=terms[0]
        if node.get('kind')=='UnaryOperator' and node.get('opcode')=='~' and children(node):
            inner=self.low_constant(children(node)[0])
            return ('clear',inner[1]) if inner and inner[0]=='value' else None
        bounds,_=self.static_index_bounds(node)
        if bounds and bounds[0]==bounds[1] and 0<=bounds[0]<=7:return ('value',bounds[0])
        return None

    @staticmethod
    def user_tag(value):
        match=TAGGED.fullmatch(value)
        return match[3] if match is not None and match[3].startswith('user:') else None
    def user_integer(self,node,env,stack):
        """Integer arithmetic on a user address's integer value is another user address value.

        Every operand is that user value, a pointer-free integer or a constant: an
        operand carrying a kernel pointer's integer keeps the existing rules.
        """
        values=set()
        for term in children(node):values|=self.integer_values(term,env,stack) if type_of(term) in POINTER_WIDTH_INTEGERS else set()
        users={self.user_tag(v) for v in values}-{None}
        if not users:return None
        if any(self.user_tag(v) is None and not v.startswith('unresolved:integer') and not (TAGGED.fullmatch(v) and TAGGED.fullmatch(v)[3]=='null') for v in values):return None
        return {tag_value(u) for u in users}

    def tagged_operation(self,node,env,stack):
        """Tag bits OR-ed into, or cleared from, an integer that carries pointer provenance."""
        terms=children(node);op=node['opcode']
        for value_side,constant_side in (terms,terms[::-1]):
            constant=self.low_constant(constant_side)
            if constant is None:continue
            values=self.integer_values(value_side,env,stack);result=set()
            if op=='&' and constant[0]=='value':return set() # only tag bits remain: no pointer
            if op=='|' and node.get('_statement') is not None and self.recovered_nonnull(node['_statement'],node['_target'],stack):
                # The OR runs only where the pointer recovered from this word is non-null.
                values={v for v in values if not (v=='null' or v.endswith(':null'))}
            for value in values:
                if value=='null':value=tag_value('null')
                match=TAGGED.fullmatch(value)
                if match is None:
                    result.add(value if value.startswith('unresolved:') else 'unresolved:integer-arithmetic');continue
                tag,cleared,path=int(match[1]),int(match[2]),match[3]
                if op=='|' and constant[0]=='value':tag|=constant[1]
                elif op=='&' and constant[0]=='clear':tag&=~constant[1];cleared|=constant[1]
                else:result.add('unresolved:integer-arithmetic');continue
                result.add(tag_value(path,tag,cleared))
            return self.bounded_aliases(result,node,stack)
        return None

    def integer_values(self,expression,env,stack):
        """Provenance of a pointer-width integer: pointer-free constants are tagged nulls, others unresolved."""
        values=self.resolve(expression,env,stack)
        if values:return values
        constant=self.low_constant(expression)
        if constant is not None and constant[0]=='value':return {tag_value('null',constant[1])}
        return {'unresolved:integer'}

    def recovered_nonnull(self,statement,word,stack):
        """Is `statement` dominated by a non-null guard on p = (T *)(word & ~L), word unchanged since?"""
        from entry_state_values import implies_nonnull,match_variable,declref,parens
        facts=self.function_facts(statement,stack)
        if facts is None:return False
        start=facts.span[id(statement)][0]
        for cond,truth,guard in facts.facts(statement):
            for use in walk(cond):
                ref=declref(use) if use.get('kind')=='DeclRefExpr' else None
                if ref is None or '*' not in type_of(ref):continue
                key=ref['referencedDecl']['id']
                if not implies_nonnull(cond,truth,match_variable(key)):continue
                definition=facts.reaching(ref,key)
                if definition is None:continue
                cast=parens(definition)
                while cast.get('kind') in ('ImplicitCastExpr','CStyleCastExpr') and cast.get('castKind') in ('BitCast','NoOp') and children(cast):cast=parens(children(cast)[0])
                if cast.get('castKind')!='IntegralToPointer' or not children(cast):continue
                masked=parens(children(cast)[0])
                if masked.get('kind')!='BinaryOperator' or masked.get('opcode')!='&':continue
                operands=children(masked)
                if not any(unwrap(a).get('referencedDecl',{}).get('id')==word and (self.low_constant(b) or ('',))[0]=='clear' for a,b in (operands,operands[::-1])):continue
                end=facts.span[id(definition)][1]
                if not facts.assigned(word,end+1,start-1):return True
        return False

    def pointee_alignment(self,typ):
        """A lower bound on a struct pointee's alignment: 8 when it holds a pointer or 64-bit integer."""
        pointee=re.sub(r'^(?:const |volatile )+','',typ.rstrip().removesuffix('*').strip())
        layout=self.record_layouts.get(pointee)
        if not layout:return None
        return 8 if any('*' in t or re.sub(r'\b(?:const|volatile)\s+','',t) in POINTER_WIDTH_INTEGERS for _,t in layout) else None

    def tagged_recovery(self,cast,env,stack):
        """(T *)(v & ~L) where every value of v is a tagged pointer whose tags are cleared."""
        values=self.resolve(children(cast)[0],env,stack) if children(cast) else set()
        if not values or not any(v.startswith('tagged:') for v in values):return None
        result=set();cleared=0
        for value in values:
            if value=='null':result.add('null');continue
            match=TAGGED.fullmatch(value)
            if match is None or int(match[1])!=0:return None
            cleared|=int(match[2]);result.add(match[3])
        alignment=self.pointee_alignment(type_of(cast)) if cleared else None
        if cleared and (alignment is None or alignment<=cleared):return None
        self.tagged_pointer_proofs.append(dict(kind='tagged_pointer_recovery',function=stack[-1],call_path=stack,location=self.location(cast),
            cleared_bits=cleared,pointee=type_of(cast),pointee_alignment_at_least=alignment,origins=len(result),
            evidence='every value is a pointer OR-ed with constants below 8; the mask clears those bits; the pointee alignment exceeds them'))
        return self.bounded_aliases(result,cast,stack)

    def ordering_asm(self,node,stack):
        """An operand-free asm under a kernel contract that such asm has no memory effects."""
        if node.get('kind')!='GCCAsmStmt' or children(node) or self.operand_free_asm is None:return False
        self.ordering_asm_proofs.append(dict(kind='operand_free_asm',function=stack[-1],call_path=stack,location=self.location(node),
            classification=self.operand_free_asm['classification']))
        return True

    def extent_contract(self,base):
        """Exact element count for a pointer field declared to point at `extent_field` elements."""
        member=unwrap(base)
        if member.get('kind')!='MemberExpr' or not children(member) or '*' not in type_of(member):return None
        typ=type_of(children(member)[0]).strip()
        if member.get('isArrow'):typ=typ.removesuffix('*').strip()
        typ=re.sub(r'^(?:const|volatile)\s+','',typ)
        contract=self.pointer_extents.get((typ,member.get('name')))
        if contract is None:return None
        size=self.state_ranges.get((typ,contract['extent_field']))
        if size is None or size['min']!=size['max'] or size['min']<=0:return None
        return dict(contract,elements=size['min'],state_range=size)

    def compile_time_builtin(self,node):
        """__builtin_constant_p (a 0/1 compile-time query) and __builtin_unreachable (no run-time effect)."""
        parts=children(node)
        if not parts:return None
        target=unwrap(parts[0]);ref=target.get('referencedDecl',{})
        if target.get('kind')!='DeclRefExpr' or ref.get('kind')!='FunctionDecl' or ref.get('name') not in COMPILE_TIME_BUILTINS:return None
        declaration=self._builtin_declarations.get(ref.get('id'))
        if declaration is None or not declaration.get('isImplicit'):return None
        return {'kind':'compile_time_builtin','name':ref['name'],'return_type':type_of(node),'recognition':COMPILE_TIME_BUILTINS[ref['name']]}

    def build_eliminated_call(self,node,name):
        """A body-less callee that the successful build proves was never emitted.

        A function with the `error` attribute fails compilation if a call survives.
        With the final image's symbol list, an external with no definition anywhere
        in the image would fail the link; the analyzed build linked without it.
        """
        target=unwrap(children(node)[0]) if children(node) else {}
        key=target.get('referencedDecl',{}).get('id')
        if key in self._error_functions:
            return {'kind':'error_attribute','function':name,'evidence':'call would be a compile-time error; the configured build compiled'}
        plain=name.split(':',1)[-1]
        if self.linked_symbols is not None and plain not in self.linked_symbols and key in self._external_declarations:
            return {'kind':'absent_from_linked_image','function':plain,'evidence':'no definition in the linked image symbol list; the image has no undefined symbols'}
        return None

    def expect_intrinsic(self,node):
        """__builtin_expect(value, expected): a branch hint returning its first operand."""
        parts=children(node)
        if len(parts)!=3:return None
        target=unwrap(parts[0]);ref=target.get('referencedDecl',{})
        if target.get('kind')!='DeclRefExpr' or ref.get('kind')!='FunctionDecl' or ref.get('name')!='__builtin_expect':return None
        declaration=self._builtin_declarations.get(ref.get('id'))
        if declaration is None or not declaration.get('isImplicit'):return None
        return {'kind':'branch_hint','name':'__builtin_expect','return_type':type_of(node),'argument_type':type_of(parts[1]),
                'recognition':'implicit Clang builtin declaration; returns its first operand and accesses no memory'}

    def _resolve(self,node,env,stack):
        original=node
        while original.get('kind')=='ParenExpr' or (original.get('kind')=='ImplicitCastExpr' and original.get('castKind') in ('LValueToRValue','NoOp')):
            original=children(original)[0]
        if original.get('castKind')=='PointerToIntegral' and type_of(original) in POINTER_WIDTH_INTEGERS and children(original):
            values=self.resolve(children(original)[0],env,stack)
            return {v if v.startswith(('unresolved:','tagged:')) else tag_value(v) for v in values}
        if original.get('castKind')=='IntegralToPointer':
            if children(original):
                values=self.resolve(children(original)[0],env,stack)
                if values and all(self.user_tag(v) for v in values):return {self.user_tag(v) for v in values}
            recovered=self.tagged_recovery(original,env,stack)
            if recovered is not None:return recovered
            stored=self.word_store_pointer(original,env,stack)
            if stored is not None:return stored
            masked=self.masked_pointer(original,stack)
            if masked is not None:
                self.masked_pointer_proofs.append(dict(kind='index_mask_pointer',function=stack[-1],call_path=stack,location=self.location(original),
                    mask_function=masked['mask_function'],mask_type=masked['mask_type'],values='the masked pointer operand or null'))
                return self.bounded_aliases(self.resolve(masked['pointer'],env,stack)|{'null'},original,stack)
            # A constant address (an xarray sentinel) or an errno (ERR_PTR) is a value, not an object.
            operand=children(original)[0] if children(original) else {}
            bounds=self.constant_interval(operand)
            if bounds is None and stack and stack[-1] in self.functions and self.values.facts_for(stack[-1]).contains(operand):
                self.quiet+=1
                try:bounds,_=self.values.interval(operand,stack[-1],self.context_ranges(stack))
                finally:self.quiet-=1
            if bounds is not None:
                low,high=bounds
                if low==high==0:return {'null'}
                if low==high:return {'const-address:%d'%(low%(1<<64))}
                if -4095<=low and high<=-1:return {'error-pointer'}
            return {'unresolved:integer-address'}
        converted=(original.get('kind')=='CStyleCastExpr' or original.get('kind')=='ImplicitCastExpr' and
                   original.get('castKind') not in ('ArrayToPointerDecay','LValueToRValue','NoOp'))
        if converted and '*' in type_of(original) and children(original):
            values=self.resolve(children(original)[0],env,stack)
            if any(p in self._bounded_pointers for p in values) and qualifier_only_conversion(original,children(original)[0]):
                return values
            # A void * view keeps the object; offsets on it and casts back from it stay rejected.
            # The same holds when some alternatives are named objects (a global, or a member of one) instead of
            # array elements: page_folio's folio is a page-cache pool element or the bound user folio.
            if values and all(p in self._bounded_pointers or re.fullmatch(r'(?:global:(?:tu[0-9]+:)?|argument:ctx->)[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|\[[0-9]+\])*',p) for p in values) and void_view(original):
                return values
            if any(p in self._bounded_pointers for p in values):
                self.issue('pointer_arithmetic',original,stack,'pointer conversions do not retain array element provenance')
                return {'unresolved:pointer-cast'}
            inner=children(original)[0]
            while inner.get('kind')=='ParenExpr' and children(inner):inner=children(inner)[0]
            # Unwrapping would drop the origin of a recognized masked pointer.
            if inner.get('castKind')=='IntegralToPointer' and values:return values
        decay=self.array_pointer(original,env,stack)
        if decay is not None:return decay
        _,node,kind,inner=self.expression_syntax(node)
        normalized=self.array_lvalue(node)
        if normalized is not node:return self.resolve(normalized,env,stack)
        if kind=='OpaqueValueExpr':
            self.issue('unsupported_construct',node,stack,'opaque value outside a validated shared conditional')
            return {'unresolved:opaque-value'} if '*' in type_of(node) else set()
        if kind=='IntegerLiteral' and node.get('value')=='0':return {'null'}
        if kind=='DeclRefExpr':
            declaration=node.get('referencedDecl',{});key=declaration.get('id')
            if declaration.get('kind')=='FunctionDecl':return {'function:'+declaration['name']}
            if '*' in type_of(node):
                values=self.loop_cursor_value(node,env,stack)
                if values is not None:return values
            # Array and record initializers supply values, not aliases for the
            # automatic object's storage. Initializer effects are visited in
            # full; dereferencing a local pointer field remains unresolved.
            if key in self.automatic_records:
                token=self.escaped_record(node,stack)
                if token is not None:return {'*('+token+')'}
            if key in self.automatic_arrays or key in self.automatic_records:return {'local:'+declaration['name']}
            token=self.escaped_pointer_local(node,stack)
            if token is not None:
                # Its value lives in the automatic-object store (direct and indirect stores alike).
                if self._auto_storage==id(node):return {'*('+token+')'}
                values=self.auto_read(token,'*',node,stack)
                if 'null' in values:
                    from entry_state_values import match_variable
                    if self.nonnull(node,match_variable(key),declaration.get('name'),stack):return values-{'null'} or {INFEASIBLE}
                return values
            if key in env:
                # A pointer local's flow value (its stores in visit order) is exact where it is known.
                # The closure keeps every value it ever held (and the derived-pointer proofs); the flow
                # value removes the constant classes (null, ERR_PTR codes, sentinels) absent at this point.
                local=self.pointer_local_key(node,stack)
                flowed=self.flow_value(local) if local is not None and not self._flow_masks else None
                values=env[key]
                if flowed is not None and flowed[0]=='p' and flowed[1] and set(flowed[1])<=set(values):values=set(flowed[1])
                values=self.guard_classes(node,key,values,env,stack)
                if 'null' in env[key] and 'null' not in values:
                    # Flow narrowing still owes the same auditable guard evidence as alias narrowing.
                    from entry_state_values import match_variable
                    self.nonnull(node,match_variable(key),declaration.get('name'),stack)
                if 'null' in values:
                    from entry_state_values import match_variable
                    if self.nonnull(node,match_variable(key),declaration.get('name'),stack):return values-{'null'} or {INFEASIBLE}
                    if self.correlated_nonnull(node,key,env,stack):return values-{'null'} or {INFEASIBLE}
                    if self.null_replaced(node,key,env,stack):return values-{'null'} or {INFEASIBLE}
                    if self.return_correlated_nonnull(node,key,env,stack):return values-{'null'} or {INFEASIBLE}
                return values
            if key in self.globals:
                self._referenced_globals.add(declaration['name'])
                return {'global:'+declaration['name']}
            return {'local:'+declaration.get('name','unknown')}
        if kind=='CompoundLiteralExpr':
            origin=self.automatic_compound_literals.get(node.get('id'))
            return {origin} if origin is not None else set()
        if kind=='MemberExpr':
            tracked=self.tracked_member(node,env,stack)
            if tracked is not None:
                values=env[tracked]
                if 'null' in values:
                    from entry_state_values import match_member
                    if self.nonnull(node,match_member(tracked),tracked,stack):return values-{'null'} or {INFEASIBLE}
                    link=env.get(tracked+LINK_SUFFIX,{INVALID_LINK})
                    if link!={INVALID_LINK} and self.flag_guarded(node,tracked.rsplit('.',1)[0],next(iter(link)),stack):return values-{'null'} or {INFEASIBLE}
                return values
            # Members of anonymous structs/unions are spelled through their enclosing member.
            if not node.get('name'):return {base+('->' if node.get('isArrow') else '') for base in self.resolve(inner[0],env,stack)}
            bases=self.resolve(inner[0],env,stack)
            if node.get('isArrow') and any(p in self._bounded_pointers for p in bases):
                # p->m through a bounded pointer to a record element is member m of that element.
                selected=self.pointer_access(bases,node,stack)
                if not selected:return set()
                paths={p[2:-1]+'->'+node['name'] if p.startswith('*(') else p+'.'+node['name'] for p in selected}
            else:paths={re.sub(r'->\.','->',base+('->' if node.get('isArrow') else '.')+node['name']) for base in bases}
            # Members of const globals are spelled by their canonical object path.
            paths={self.const_graph.canonical(p) if p.startswith('global:') else p for p in paths}
            if self.empty_list_heads:
                # `&sentinel->m` of an empty list's walk cursor is the head itself (entry_state_lists).
                from entry_state_lists import member as list_member,link as list_link
                paths={list_member(p) for p in paths}
                if self._auto_storage!=id(node) and '*' in type_of(node):
                    linked={p:list_link(self.empty_list_heads,p) for p in paths}
                    if any(linked.values()):
                        # The link of an empty head is the head: next and prev both point at it.
                        self.list_proofs.append(dict(kind='empty_list_link',function=stack[-1],call_path=stack,location=self.location(node),
                            heads=sorted({re.sub(r'\[\d+\]','[]',h) for h in linked.values() if h}),links=sum(1 for h in linked.values() if h)))
                        return {h if h else p for p,h in linked.items()}
            if self._auto_storage==id(node) or '*' not in type_of(node):return paths
            # A pointer member of a const global with a constant initializer holds that value.
            loaded=[self.const_graph.load(p) for p in paths]
            if paths and all(v is not None for v in loaded):return set().union(*loaded)
            values=set();stored=False
            for path in paths:
                key=self.auto_key(path)
                if key is not None:stored=True
                values|=self.auto_read(*key,node,stack) if key is not None else {path}
            if stored and 'null' in values:
                from entry_state_values import match_member_access
                if self.nonnull(node,match_member_access(node),node.get('name'),stack):return values-{'null'} or {INFEASIBLE}
            return values
        if kind=='StmtExpr':
            if len(inner)!=1 or inner[0].get('kind')!='CompoundStmt':
                self.issue('unsupported_construct',node,stack,'statement expression requires a configured compound body')
                return {'unresolved:statement-expression'} if '*' in type_of(node) else set()
            if type_of(node)=='void':return set()
            statements=children(inner[0]);local={key:set(paths) for key,paths in env.items()}
            # Locals and assignments use the same bounded may-alias closure
            # as function bodies. Effects are visited separately, in full.
            self.pointer_aliases(inner[0],local,stack)
            result=self.resolve(statements[-1],local,stack) if statements else set()
            return result or ({'unresolved:statement-expression'} if '*' in type_of(node) else set())
        if kind in ('BinaryOperator','UnaryOperator') and node.get('opcode') in ('+','-','*','/','%','&','|','^','<<','>>','~') and type_of(node) in POINTER_WIDTH_INTEGERS:
            user=self.user_integer(node,env,stack)
            if user is not None:return user
        if kind=='BinaryOperator' and node.get('opcode') in ('|','&') and type_of(node) in POINTER_WIDTH_INTEGERS:
            tagged=self.tagged_operation(node,env,stack)
            if tagged is not None:return tagged
        if kind=='BinaryOperator' and node.get('opcode') in (',','='):
            # Both operands' effects are visited; the expression value is the
            # right operand's value, never a union with the left operand.
            return self.resolve(inner[-1],env,stack)
        if kind=='ArraySubscriptExpr':
            base=unwrap(inner[0]);index=inner[1]
            # Only an actual array decay retains the configured storage bound.
            # A pointer cast or pointer variable cannot borrow that bound.
            array=fixed_array(type_of(base))
            direct=inner[0].get('kind')=='ImplicitCastExpr' and inner[0].get('castKind')=='ArrayToPointerDecay'
            global_array=(base.get('kind')=='DeclRefExpr' and
                          base.get('referencedDecl',{}).get('id') in self.globals)
            completion=None
            if array is None and global_array:
                key=base['referencedDecl']['id'];proof=self.completed_global_arrays.get(key)
                if proof is not None and type_of(base)==type_of(self.globals[key]):
                    array=fixed_array(proof['type']);completion=proof
            automatic_array=(base.get('kind')=='DeclRefExpr' and
                             base.get('referencedDecl',{}).get('id') in self.automatic_arrays)
            compound_array=(base.get('kind')=='CompoundLiteralExpr' and base.get('id') in self.automatic_compound_literals)
            nested_array=base.get('kind')=='ArraySubscriptExpr'
            if automatic_array and direct and self.summary_array(base['referencedDecl']['id']) is not None:
                token=self.summary_origin(base['referencedDecl']['id'],node,stack)
                # The element's storage when that is asked for (or it is a record); otherwise a pointer element's
                # value: what the summarized stores put there (`local[0]->index` reads through it).
                if token is not None:
                    if self._auto_storage==id(node) or '*' not in type_of(node) or self.auto_record(token) is not None:return {'*('+token+')'}
                    return self.auto_read(token,'*',node,stack)
            if not array or not direct or not (base.get('kind')=='MemberExpr' or nested_array or global_array or automatic_array or compound_array):
                summary=None if direct else self.summary_paths(self.resolve(inner[0],env,stack))
                if summary is not None:return {'*('+p+')' for p in summary}
                bounds,proof=self.index_bounds_for(index,stack)
                if bounds is None and node.get('id') in self.loop_index_sites:
                    certified=self.loop_index_sites[node['id']];bounds=certified['bounds'];proof=certified['proof']
                if bounds is None:bounds,proof=self.fallback_index_bounds(index,stack)
                base_paths=self.resolve(inner[0],env,stack)
                if base_paths and all(re.match(r'^(?:\*\()*external:',p) for p in base_paths):
                    # Memory returned by a declared external-memory boundary is not kernel entry
                    # state, element by element as for a dereference; the boundary checks extents.
                    return {p+'[*]' for p in base_paths}
                selected=self.pointer_access(base_paths,node,stack,bounds,proof)
                if selected is not None:return selected
                view=self.automatic_view(inner[0],base_paths,node,stack)
                if view is not None:return view
                extent=self.extent_contract(inner[0])
                if extent is not None and bounds is not None and base_paths and not any(re.search(r'(?:^|\*\()(?:null|unresolved:)|bounded-pointer:',p) for p in base_paths):
                    low,high=bounds
                    if low<0 or high>=extent['elements']:
                        self.issue('array_bounds',node,stack,'subscript range exceeds the contracted pointer extent');return set()
                    if high-low+1>self.max_range_elements:
                        self.issue('range_limit',node,stack,'selected range exceeds the configured element limit');return set()
                    self.ranges.append(dict(paths=sorted(base_paths),elements=extent['elements'],index_bounds=[low,high],selection='proven bounded index interval',
                        element_type=type_of(node),bound_source='pointer extent contract %s.%s -> %s'%(extent['record'],extent['field'],extent['extent_field']),
                        extent_contract=dict(record=extent['record'],field=extent['field'],extent_field=extent['extent_field']),
                        function=stack[-1],call_path=stack,location=self.location(node),**({'index_proof':proof} if proof else {})))
                    self.extent_assumptions.append(extent['state_range'])
                    return {p+'['+str(i)+']' for p in base_paths for i in range(low,high+1)}
                if bounds is not None and tuple(bounds)==(0,0) and self.automatic_scalar_paths(inner[0],base_paths):
                    # p[0] where p holds the address of an automatic non-array object of p's pointee type
                    # (slab_post_alloc_hook's p[i] over &object, i < size == 1): that object itself.
                    self.ranges.append(dict(paths=sorted(base_paths),elements=1,index_bounds=[0,0],selection='automatic object as one-element array',
                        element_type=type_of(node),bound_source='address of an automatic object of the pointee type',function=stack[-1],call_path=stack,location=self.location(node),**({'index_proof':proof} if proof else {})))
                    return {'*('+p+')' for p in base_paths}
                if bounds is not None and tuple(bounds)==(0,0) and self.scalar_object_paths(inner[0],base_paths):
                    self.ranges.append(dict(paths=sorted(base_paths),elements=1,index_bounds=[0,0],selection='scalar object as one-element array',
                        element_type=type_of(node),bound_source='address of a numeric scalar field',function=stack[-1],call_path=stack,location=self.location(node)))
                    return {'*('+p+')' for p in base_paths}
                self.issue('dynamic_extent',node,stack,'subscript needs a configured inline-array bound or memory contract')
                return set()
            count=int(array[2]);bounds,loop_proof=self.index_bounds_for(index,stack)
            if bounds is None and node.get('id') in self.loop_index_sites:
                certified=self.loop_index_sites[node['id']];bounds=certified['bounds'];loop_proof=certified['proof']
            if bounds is None:bounds,loop_proof=self.fallback_index_bounds(index,stack)
            if bounds is None:
                self.issue('dynamic_extent',node,stack,'index bounds are not proven; use a bounded index expression or memory contract')
                return set()
            low,high=bounds
            if low<0 or high>=count:
                self.issue('array_bounds',node,stack,'subscript range exceeds the configured array extent')
                return set()
            if high-low+1>self.max_range_elements:
                self.issue('range_limit',node,stack,'selected array range exceeds the configured element limit')
                return set()
            value=low if low==high else None
            indexes=range(low,high+1)
            paths=self.resolve(base,env,stack)
            # Bound the Cartesian selection before expanding another dimension.
            # Resolving the base independently checks every enclosing extent;
            # an inner row cannot lend its bound to the outer dimension.
            if nested_array and len(paths)*(high-low+1)>self.max_range_elements:
                self.issue('range_limit',node,stack,'nested array selection exceeds the configured element limit')
                return set()
            self.ranges.append({'paths':sorted(paths),'elements':count,'selection':'constant element' if value is not None else 'proven bounded index interval',
                'index_bounds':[low,high],
                'index':value,'bound_source':('configured Clang global-array type' if global_array else
                    'configured Clang automatic-array type' if automatic_array else
                    'configured Clang automatic compound-literal array type' if compound_array else
                    'configured Clang nested-array type' if nested_array else 'configured Clang inline-array type'),'element_type':type_of(node),
                'function':stack[-1],'call_path':stack,'location':self.location(node)})
            if node.get('_array_pointer_access'):self.ranges[-1]['access_form']='array_pointer_offset'
            if loop_proof is not None:self.ranges[-1]['index_proof']=loop_proof
            if completion is not None:
                self.ranges[-1]['bound_source']='compatible configured global-array declarations'
                self.ranges[-1]['array_type_evidence']=completion
            return {path+'['+str(i)+']' for path in paths for i in indexes}
        if kind=='UnaryOperator' and node.get('opcode') in ('&','*'):
            target=unwrap(inner[0])
            if node['opcode']=='&':
                token=self.escaped_record(target,stack) or self.escaped_pointer_local(target,stack)
                if token is not None:return {token}
                scalar=self.scalar_address(node,target,stack)
                if scalar is not None:return scalar
                field=self.fields.get(target.get('referencedMemberDecl'),{})
                if target.get('kind')=='MemberExpr' and field and not field.get('isBitfield') and arithmetic_scalar(re.sub(r'\b(?:const|volatile)\s+','',type_of(target))):
                    for path in self.resolve(target,env,stack):
                        self._scalar_objects.setdefault(path,type_of(target));self._scalar_fields.setdefault(path,field.get('id'))
            if node['opcode']=='&' and target.get('kind')=='UnaryOperator' and target.get('opcode')=='*':
                values=self.resolve(children(target)[0],env,stack)
                if any(p in self._bounded_pointers for p in values):return values
            if node['opcode']=='&' and target.get('kind')=='ArraySubscriptExpr':
                array,index=children(target)
                offset={**node,'kind':'BinaryOperator','opcode':'+','inner':[array,index]}
                values=self.offset_pointers(offset,env,stack)
                if values is not None:return values
            # &member designates the member's storage, not the pointer value it holds.
            base=self.storage_paths(inner[0],env,stack) if node['opcode']=='&' else self.resolve(inner[0],env,stack)
            if node['opcode']=='&' and any(p in self._bounded_pointers for p in base):
                self.issue('pointer_arithmetic',node,stack,'address of a pointer variable needs an indirect-assignment model')
                return {'unresolved:pointer-address'}
            if node['opcode']=='*':
                selected=self.pointer_access(base,node,stack)
                if selected is not None:return selected
                # A load through the address of an escaped pointer local (`*vp` with vp == &v), or of
                # an element of a summarized pointer array, reads the stored pointer values.
                if '*' in type_of(node) and '(' not in type_of(node) and self._auto_storage!=id(node) and base and all(
                        b in self._auto_info and self.auto_record(b) is None for b in base):
                    values=set()
                    for b in base:values|=self.auto_read(b,'*',node,stack)
                    return values
            return base if node['opcode']=='&' else {'*('+value+')' for value in base}
        if kind=='UnaryOperator' and node.get('opcode') in ('++','--') and '*' in type_of(node):
            update=self.pointer_update(node,env,stack)
            if update is not None and update['result_used']:
                return self.pointer_update_values(update,update['result_version'],env,stack,node)
            # ++p is the stepped value and p++ the previous one; a step without a proven
            # offset is a derived pointer (see derived_pointers).
            stepped=self.mutation_expression(node)
            if stepped is not None and self.local_pointer_mutation(node,env,stack):
                return self.resolve(stepped,env,stack) if node.get('isPostfix') is False else self.resolve(inner[0],env,stack)
            return {'unresolved:pointer-mutation'}
        if kind=='CallExpr':
            # This pass's visit-time result at this call, or (optimistically) the previous pass's.
            recent=self._recent_return.get((id(node),tuple(stack)))
            if recent is None and self._optimistic:recent=self._prior_returns.get((id(node),tuple(stack)))
            # Only constants and values rooted at stack objects, whose stores the visit tracks: a value
            # naming a global's or an entry path's contents may miss a store the closure would see.
            if recent and all(re.fullmatch(r'auto:\d+(?:(?:->|\.)[\w\[\]>.-]*)?|const-address:-?\d+|null|error-pointer',v) and 'unresolved:' not in v for v in recent):return set(recent)
            result=set()
            for name in self.targets(node,env,stack) or ():
                policy=self.boundary(name) or {}
                if policy.get('kind')=='object_provider':
                    if len(inner)>1:self.issue('provider_arguments',node,stack,'provider arguments need explicit entry bindings')
                    provider=name.split(':',1)[-1]
                    self.providers[provider]={'function':provider,'return_type':type_of(node),'contract':policy}
                    result.add(provider+'()')
                elif policy.get('kind')=='memory_model' and policy.get('result')=='external_memory':
                    result.add('external:'+name.split(':',1)[-1]+'()')
                elif name in self.functions and not policy and name not in stack:
                    # Resolve simple return aliases; execution visits the full body separately.
                    # The result depends only on the call, its context and its pointer arguments.
                    # The callee's returns read records after its own writes: no flow state here,
                    # unless it writes no memory, so every record it reads holds its value at the call.
                    flow=None if self._flow_off or not self._flow_live else frozenset(self._flow.items())
                    cache_key=(id(node),name,tuple(stack),tuple(frozenset(self.resolve(a,env,stack)) if '*' in type_of(a) else None for a in inner[1:]),flow)
                    cached=self._inline_cache.get(cache_key)
                    if cached is not None:
                        result=self.bounded_aliases(result|cached,node,stack+[name]);continue
                    own=set()
                    if tuple(stack+[name]) not in self._context_calls:self.enter_call(name,node,stack)
                    mask=self.flow_mask(name)
                    try:
                        local=self.inline_environment(name,node,inner[1:],env,stack)
                        _,returns=self.return_alias_program(self.functions[name])
                        kept=[(e,st) for e,st in returns if self.prior_reachable(st,name,stack+[name])]
                        returns=kept
                        for expression,statement in returns:
                            # Values only: the callee's own accesses are checked where its body is visited.
                            self.quiet+=1
                            try:values=self.integer_values(expression,local,stack+[name]) if type_of(node) in POINTER_WIDTH_INTEGERS else self.resolve(expression,local,stack+[name])
                            finally:self.quiet-=1
                            own=self.bounded_aliases(own|values,statement,stack+[name])
                    finally:self.flow_unmask(mask)
                    self._inline_cache[cache_key]=frozenset(own)
                    result=self.bounded_aliases(result|own,node,stack+[name])
            allocators=[n for n in (self.targets(node,env,stack) or ()) if n.split(':',1)[-1] in self.allocations]
            if allocators and '*' in type_of(node):
                # Constants (null, ZERO_SIZE_PTR, ERR_PTR) stay; every object the allocator can return is the
                # allocation, fresh memory written before it is read (the allocator body is analyzed separately).
                kept={v for v in result if v=='null' or v.startswith(('const-address:','error-pointer',INFEASIBLE))}
                result=kept|{self.allocation_token(allocators[0].split(':',1)[-1],node,stack)}
            if not result and '*' in type_of(node):return {'unresolved:call'}
            return result
        if kind=='BinaryConditionalOperator':
            parts=binary_conditional_parts(node)
            if parts is None:
                self.issue('unsupported_construct',node,stack,'GNU conditional lacks a validated shared value')
                return {'unresolved:binary-conditional'} if '*' in type_of(node) else set()
            return set().union(*(self.resolve(c,env,stack) for c in parts))
        if kind=='ConditionalOperator':
            outcome=self._decisions.get((id(inner[0]),tuple(stack))) if len(inner)==3 else None
            if outcome is not None:return self.resolve(inner[1] if outcome else inner[2],env,stack)
            return set().union(*(self.resolve(c,env,stack) for c in inner[1:]))
        if pointer_arithmetic_detail(node):
            user=self.user_arithmetic(node,env,stack)
            if user is not None:return user
            summary=self.summary_arithmetic(node,env,stack)
            if summary is not None:return summary
            if self.pointer_difference(node,env,stack):return set()
            container=self.container_of(node,env,stack)
            if container is not None:return container
            pointers=self.offset_pointers(node,env,stack)
            if pointers is not None:return pointers
            derived=self.derived_pointers(node,env,stack)
            if derived is not None:return derived
            if self.pointer_difference_value(node,env,stack):return set()
            self.issue('pointer_arithmetic',node,stack,pointer_arithmetic_detail(node))
            return set()
        return set()

    def pointer_aliases(self,body,env,stack,exclude=None):
        """Compute a bounded may-alias closure, retaining every possible origin."""
        seeds,assignments=self.alias_program(body)
        if exclude:
            # Values before a region: its assignments (and pointer steps) have not run yet.
            seeds=tuple(x for x in seeds if id(x[3]) not in exclude)
            assignments=tuple((key,expression) for key,expression in assignments if id(expression) not in exclude)
        local_seeds={key:(origin,statement) for operation,key,origin,statement in seeds if operation=='local'}
        proofs={}
        if local_seeds and len(local_seeds)<=64:
            proof_body=next((c for c in children(body) if c.get('kind')=='CompoundStmt'),body) if body.get('kind')=='FunctionDecl' else body
            cache_key=id(proof_body)
            if cache_key not in self._definite_pointer_cache:
                from entry_state_dominance import definite_pointer_initialization
                self._definite_pointer_cache[cache_key]=(proof_body,definite_pointer_initialization(proof_body,local_seeds))
            proofs=self._definite_pointer_cache[cache_key][1]
        # Every read has a unique reaching assignment, so the declaration's
        # indeterminate value is never read; all assigned values stay in env.
        reached={}
        if stack and stack[-1] in self.functions:
            facts=self.values.facts_for(stack[-1])
            for key,(origin,statement) in local_seeds.items():
                if facts.contains(statement) and facts.defined_before_use(key):reached[key]=statement
        for operation,key,origin,statement in seeds:
            if operation=='mutation':
                env.setdefault(key,set()).add(origin)
                env[key]=self.bounded_aliases(env[key],statement,stack)
            elif key in proofs or key in reached:env.setdefault(key,set())
            else:env.setdefault(key,{origin})
        empty=set()
        if stack and stack[-1] in self.functions and self._prior_unreachable:
            before=len(assignments)
            assignments=tuple((key,expression) for key,expression in assignments if self.prior_reachable(expression,stack[-1],stack))
        def sweep():
            changed=False
            for key,expression in assignments:
                if isinstance(key,tuple):
                    changed=self.assign_record(key[1],expression,env,stack) or changed;continue
                paths=self.resolve(expression,env,stack) or {'unresolved:alias'}
                previous=env.get(key,empty)
                combined=self.bounded_aliases(previous|paths,expression,stack)
                if combined!=previous:env[key]=combined;changed=True
            return changed
        def settle():
            # A limit met in a quiet sweep is absorbed there, so the reporting sweep would not meet it.
            mark=len(self._quiet_limits)
            for _ in range(32):
                # Before the fixpoint the closure is partial (an assignment may be read before the
                # one that binds its variable): only the sweep over the fixpoint reports issues.
                self.quiet+=1
                try:changed=sweep()
                finally:self.quiet-=1
                if not changed:
                    sweep()
                    for node,at in self._quiet_limits[mark:]:self.issue('alias_limit',node,at,'pointer alias path count exceeds configured limit of '+str(self.max_alias_paths))
                    del self._quiet_limits[mark:];return
            del self._quiet_limits[mark:]
            self.issue('alias_limit',body,stack,'pointer alias fixpoint did not converge within 32 iterations')
        settle()
        eligible=set(proofs)-set(reached)
        # A syntactic initialization proof removes no unknown value origin.
        # Restore the old seed for every non-array/unknown alternative, then
        # propagate it through dependents before accepting any certificate.
        while eligible:
            # Null and bounded array pointers are fully known values; an unknown origin would
            # survive the certificate anyway, so it gains nothing from removing the seed.
            rejected={key for key in eligible if not env.get(key) or any(p not in self._bounded_pointers and p!='null' for p in env[key])}
            if not rejected:break
            for key in rejected:
                origin,statement=local_seeds[key]
                env[key]=self.bounded_aliases(env.get(key,set())|{origin},statement,stack)
            eligible-=rejected;settle()
        self._pointer_initialization_environments.pop(id(env),None)
        if eligible or reached:self._pointer_initialization_environments[id(env)]=(env,frozenset(eligible|set(reached)))
        for key,declaration in sorted(reached.items()):
            self.pointer_initializations.append(dict(kind='reaching_assignment_pointer_initialization',
                variable=declaration.get('name'),declaration=self.location(declaration),function=stack[-1],call_path=stack,
                may_alias_origins_retained=len(env.get(key,())),value_domain='all assigned values retained'))
        if eligible:
            for key in sorted(eligible):
                proof=proofs[key];declaration=proof['declaration']
                self.pointer_initializations.append(dict(kind='structured_definite_pointer_initialization',
                    variable=declaration['name'],declaration=self.location(declaration),
                    assignments=[self.location(n) for n in proof['assignments']],
                    function=stack[-1],call_path=stack,may_alias_origins_retained=len(env[key]),
                    value_domain='configured numeric arrays with bounded element offsets'))

    def targets(self,node,env,stack):
        name=self.direct_call(node)
        if name:return {name}
        target=unwrap(children(node)[0])
        # (*callback)(...) and callback(...) denote the same function target.
        if target.get('kind')=='UnaryOperator' and target.get('opcode')=='*':target=unwrap(children(target)[0])
        contract=self.callback_contract(target)
        if contract is not None:
            self.callback_uses.append(dict(record=contract['record'],field=contract['field'],targets=list(contract['targets']),
                function=stack[-1] if stack else None,location=self.location(node)))
            return frozenset(contract['targets'])
        paths=self.resolve(target,env,stack)
        if paths and all(path.startswith('function:') for path in paths):
            return {path[len('function:'):] for path in paths}
        return None

    def callback_contract(self,target):
        """Declared targets of a function-pointer field load (`ops->field`), from live object values."""
        if target.get('kind')!='MemberExpr' or not children(target):return None
        typ=type_of(children(target)[0]).strip()
        if target.get('isArrow'):typ=typ.removesuffix('*').strip()
        typ=re.sub(r'^(?:const |volatile )+','',typ)
        return self.callback_targets.get((typ,target.get('name')))

    def local_volatile_storage(self,node,stack):
        """Classify initialized scalar storage without dropping its operations.

        Evaluated addresses never occur in the function. Declaration-then-store
        locals use the shared structured definite-assignment pass. Jumps, asm
        and cleanup attributes disable this ownership proof.
        """
        name=stack[-1]
        if name not in self._local_volatile_storage:
            body=next(c for c in children(self.functions[name]) if c.get('kind')=='CompoundStmt')
            nodes=self.effect_nodes(body);eligible={};pending={}
            if not any(n.get('kind') in ('GotoStmt','IndirectGotoStmt','LabelStmt','CaseStmt','DefaultStmt',
                'GCCAsmStmt','MSAsmStmt','CleanupAttr') for n in nodes):
                escaped={r.get('referencedDecl',{}).get('id') for n in nodes
                    if n.get('kind')=='UnaryOperator' and n.get('opcode')=='&'
                    for r in walk(n) if r.get('kind')=='DeclRefExpr'}
                for declaration in nodes:
                    typ=type_of(declaration);parts=children(declaration)
                    if (declaration.get('kind')!='VarDecl' or declaration.get('id') in self.globals or
                        declaration.get('storageClass') is not None or declaration.get('tls') or
                        declaration['id'] in escaped or
                        not re.search(r'\bvolatile\b',typ) or
                        not arithmetic_scalar(' '.join(re.sub(r'\bvolatile\b','',typ).split())) or
                        parts and (not declaration.get('init') or len(parts)!=1 or
                            any(n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('id')==declaration['id']
                                for n in walk(parts[0])))):continue
                    if parts:eligible[declaration['id']]=(declaration,None)
                    else:pending[declaration['id']]=declaration
                if pending and len(pending)<=64:
                    from entry_state_dominance import definite_local_initialization
                    certified=definite_local_initialization(body,pending,scalar_updates=True)
                    for key,proof in certified.items():eligible[key]=(pending[key],proof)
            self._local_volatile_storage[name]=eligible
        key=node.get('id') if node.get('kind')=='VarDecl' else node.get('referencedDecl',{}).get('id') if node.get('kind')=='DeclRefExpr' else None
        storage=self._local_volatile_storage[name].get(key)
        if storage is None:return self.discarded_volatile(name,key,stack)
        declaration,initialization=storage
        proof=dict(kind='initialized_nonescaping_volatile_scalar',variable=declaration['name'],
            type=type_of(declaration),declaration=self.location(declaration),
            function=name,call_path=stack,automatic_storage=True,address_taken=False,initialized_before_use=True,
            entry_capture_required=False,original_operations_retained=True,value_folding=False,
            scope='local scalar storage only; floating-point environment and shared/device memory are not modeled')
        if initialization is None:proof['initializer']=self.location(children(declaration)[0])
        else:
            proof['kind']='definitely_assigned_nonescaping_volatile_scalar'
            proof['initialization_proof']=dict(kind='structured_definite_assignment',
                assignments=[self.location(n) for n in initialization['assignments']],branch_joins='intersection',
                loop_body_stores_initialize_continuation=False,scalar_updates_require_prior_assignment=True,
                unsequenced_operands_share_incoming_facts=True,max_declarations=64)
        self.local_volatile_proofs.append(proof)
        return True

    def discarded_volatile(self,name,key,stack):
        """A volatile automatic scalar whose value nothing uses.

        Every reference stores to it, reads it into a discarded value (`(void)c`), or
        passes its address to a memory-model boundary that declares writing that
        argument. Its (possibly indeterminate) value never reaches a computation.
        """
        facts=self.values.facts_for(name);declaration=facts.declarations.get(key)
        if (declaration is None or declaration.get('storageClass') is not None or declaration.get('tls') or
                not re.search(r'\bvolatile\b',type_of(declaration)) or not arithmetic_scalar(' '.join(re.sub(r'\bvolatile\b','',type_of(declaration)).split()))):return False
        transparent=('ParenExpr','ImplicitCastExpr','CStyleCastExpr')
        def up(n):
            parent=facts.parent.get(id(n))
            while parent is not None and parent.get('kind')=='ParenExpr':n=parent;parent=facts.parent.get(id(n))
            return n,parent
        boundaries=[]
        for ref in facts.order:
            if ref.get('kind')!='DeclRefExpr' or ref.get('referencedDecl',{}).get('id')!=key:continue
            ref,parent=up(ref)
            if parent is None:return False
            # sizeof/_Alignof operands are not evaluated.
            if parent.get('kind')=='UnaryExprOrTypeTraitExpr':continue
            if parent.get('kind')=='BinaryOperator' and parent.get('opcode')=='=' and children(parent)[0] is ref:continue
            if parent.get('kind')=='ImplicitCastExpr' and parent.get('castKind')=='LValueToRValue':
                read,outer=up(parent)
                if outer is not None and (outer.get('kind')=='CompoundStmt' or outer.get('kind')=='CStyleCastExpr' and outer.get('castKind')=='ToVoid'):continue
                return False
            if parent.get('kind')=='UnaryOperator' and parent.get('opcode')=='&':
                argument=parent;call=facts.parent.get(id(argument))
                while call is not None and call.get('kind') in transparent:argument=call;call=facts.parent.get(id(argument))
                if call is None or call.get('kind')!='CallExpr':return False
                index=next((i for i,c in enumerate(children(call)[1:]) if c is argument),None)
                policy=self.boundary(self.direct_call(call) or '') or {}
                if index is None or policy.get('kind')!='memory_model' or index not in policy.get('writes',[]) or index in policy.get('reads',[]):return False
                boundaries.append(self.location(call));continue
            return False
        self.local_volatile_proofs.append(dict(kind='discarded_volatile_scalar',variable=declaration['name'],type=type_of(declaration),
            declaration=self.location(declaration),function=name,call_path=stack,automatic_storage=True,value_used=False,
            boundary_writes=boundaries,original_operations_retained=True))
        return True

    def local_qualified_access(self,node,stack):
        # Pointer pointee qualifiers do not qualify the pointer variable.
        storage_type=type_of(node).rsplit('*',1)[-1]
        if re.search(r'\bvolatile\b',storage_type) and not self.local_volatile_storage(node,stack):
            self.issue('volatile_memory',node,stack,'classify volatile automatic storage before ignoring local memory')
        if '_Atomic' in storage_type or (re.match(r'^(?:const\s+|volatile\s+)*_Atomic\(',type_of(node)) and type_of(node).rstrip().endswith(')')):
            self.issue('architecture_or_ordering',node,stack,'atomic automatic storage needs a target/state model')

    def self_recursive_footprint(self,node,name,stack):
        """Close an unchanged-address self edge, never fold recursive execution.

        Numeric values are not propagated through call bindings into memory
        bounds. Every branch and loop body is already visited by this pass.
        With immutable pointer parameters passed in their original positions,
        another activation introduces no new externally reachable origin.
        """
        if name!=stack[-1] or len(children(node))!=len(self.parameters(self.functions[name]))+1:return False
        def plain(expression,casts):
            while expression.get('kind')=='ParenExpr' or (expression.get('kind')=='ImplicitCastExpr' and expression.get('castKind') in casts):
                if len(children(expression))!=1:return {}
                expression=children(expression)[0]
            return expression
        target=plain(children(node)[0],('FunctionToPointerDecay',))
        if target.get('kind')!='DeclRefExpr' or target.get('referencedDecl',{}).get('name')!=name:return False
        if name not in self._self_recursion_syntax:
            function=self.functions[name];parameters=self.parameters(function);result_type=type_of(function).split(' (',1)[0]
            pointers=[];valid=(result_type=='void' or arithmetic_scalar(result_type)) and '...' not in type_of(function)
            for i,parameter in enumerate(parameters):
                # Clang JSON decays array parameters to pointer types without
                # retaining bound-expression effects. Require the declaration
                # to end at its name, as ordinary scalar/pointer parameters do.
                loc=parameter.get('loc',{});end=parameter.get('range',{}).get('end',{})
                if (not parameter.get('name') or 'offset' not in loc or loc.get('offset')!=end.get('offset') or
                    loc.get('tokLen')!=end.get('tokLen') or loc.get('tokLen')!=len(parameter['name'])):valid=False
                typ=type_of(parameter)
                if arithmetic_scalar(typ):continue
                if typ.endswith(' *') and arithmetic_scalar(typ[:-2]):pointers.append((i,parameter))
                else:valid=False
            keys={p['id'] for i,p in pointers}
            for term in self.effect_nodes(function):
                kind=term.get('kind');op=term.get('opcode');parts=children(term)
                if (kind in ('GotoStmt','IndirectGotoStmt','LabelStmt','CaseStmt','DefaultStmt','GCCAsmStmt','MSAsmStmt',
                    'AtomicExpr','VAArgExpr','StmtExpr','CleanupAttr') or kind.startswith('CXX') or
                    kind=='VarDecl' and '*' in type_of(term) or kind=='UnaryOperator' and op=='&'):
                    valid=False
                if parts and (kind=='BinaryOperator' and op=='=' or kind=='CompoundAssignOperator' or kind=='UnaryOperator' and op in ('++','--')):
                    dest=unwrap(parts[0])
                    if dest.get('kind')=='DeclRefExpr' and dest.get('referencedDecl',{}).get('id') in keys:valid=False
            self._self_recursion_syntax[name]=(valid,pointers,result_type)
        valid,pointers,result_type=self._self_recursion_syntax[name]
        if not valid:return False
        for i,parameter in pointers:
            argument=plain(children(node)[i+1],('LValueToRValue','NoOp'))
            if argument.get('kind')!='DeclRefExpr' or argument.get('referencedDecl',{}).get('id')!=parameter['id']:return False
        self.recursion_proofs.append(dict(kind='unchanged_pointer_self_recursive_footprint',function=name,call_path=stack,
            location=self.location(node),pointer_parameters=[dict(index=i,name=p['name'],type=type_of(p)) for i,p in pointers],
            return_type=result_type,pointer_parameters_immutable=True,recursive_pointer_arguments_unchanged=True,
            all_branch_effects_retained=True,numeric_arguments_not_folded=True,runtime_execution_unchanged=True,
            termination_proven=False,recursion_depth_bound_proven=False,
            rule='direct self edge; unchanged numeric pointer parameters; no frame address-taking or pointer locals'))
        return True

    def visit(self,node,env,stack):
        kind=node.get('kind','');inner=children(node)
        if kind=='BinaryConditionalOperator':
            parts=binary_conditional_parts(node)
            if parts is None:self.issue('unsupported_construct',node,stack,'GNU conditional lacks a validated shared value')
            for child in parts if parts is not None else inner:self.visit(child,env,stack)
            return
        if kind=='OpaqueValueExpr':
            self.issue('unsupported_construct',node,stack,'opaque value outside a validated shared conditional')
        if kind in SELECTIONS:
            selected=selected_expression(node)
            if selected is None:self.issue('unsupported_construct',node,stack,'compile-time selection lacks a unique configured Clang result')
            else:self.visit(selected,env,stack)
            return
        if kind=='CleanupAttr':
            self.issue('unsupported_construct',node,stack,'implicit local cleanup effects need a call/lifetime model')
        if kind=='VarDecl' and (node.get('storageClass') in ('static','extern') or node.get('tls')):
            self.issue('unsupported_construct',node,stack,'nonautomatic local storage needs an explicit storage model')
        # This applies to every evaluated declaration/type operand, independently
        # of statement expressions, jumps or compile-time selections.
        types=[type_of(node)]
        if kind=='UnaryExprOrTypeTraitExpr':
            types=[type_of({'type':node['argType']})] if 'argType' in node else [type_of(c) for c in inner]
        if any(variably_modified_type(typ) for typ in types):
            self.issue('unsupported_construct',node,stack,'variably modified types need bound/effect analysis')
        if kind=='StmtExpr':
            typ=without_typeof(type_of(node))
            if ('*' not in typ and (typ.startswith(('struct ','union ')) or
                    (node.get('_translation_unit'),typ) in self.record_typedefs)) or '[' in typ:
                self.issue('unsupported_construct',node,stack,'aggregate or array statement-expression results need a value/storage model')
        if kind=='ForStmt':
            from entry_state_loops import counted_loop
            from entry_state_constants import enum_values
            if self.loop_enum_values is None:self.loop_enum_values=enum_values(self.loop_enum_declarations)
            self.loop_index_sites.update(counted_loop(node,self.location,self.loop_enum_values) or {})
        # A pointer converted to an integer accesses no memory. A pointer formed
        # from an integer needs an origin, except the all-ones/zero index mask.
        # The pointer itself accesses no memory; a dereference of its unresolved origin blocks.
        if kind.startswith('CXX') or kind in ('VAArgExpr','IndirectGotoStmt','AddrLabelExpr'):
            self.issue('unsupported_construct',node,stack,'construct is outside the supported C analysis subset')
        if kind in ('GCCAsmStmt','MSAsmStmt','AtomicExpr') and not self.trap_asm(node,stack) and not self.ordering_asm(node,stack):
            self.issue('architecture_or_ordering',node,stack,'assembly or atomic operation needs a target/state model')
        detail=pointer_arithmetic_detail(node)
        if (detail and self.user_arithmetic(node,env,stack) is None and self.summary_arithmetic(node,env,stack) is None and not self.pointer_difference(node,env,stack) and self.container_of(node,env,stack) is None and self.offset_pointers(node,env,stack) is None and
                self.derived_pointers(node,env,stack) is None and not self.pointer_difference_value(node,env,stack)):self.issue('pointer_arithmetic',node,stack,detail)
        if kind=='InitListExpr' and any(p in self._bounded_pointers or p in self._derived_pointers for c in inner if '*' in type_of(c) for p in self.resolve(c,env,stack)):
            self.issue('pointer_arithmetic',node,stack,'bounded pointer aggregate storage needs an escape and reconstruction model')
        if kind=='ReturnStmt' and inner and '*' in type_of(inner[0]):
            paths=self.resolve(inner[0],env,stack)
            if any(p in self._bounded_pointers for p in paths) and not self.bounded_pointer_return(paths,node,stack):
                self.issue('pointer_arithmetic',node,stack,'bounded pointer return needs a lifetime and result-binding model')
            if len(stack)<2 and self.derived_values(paths):
                self.issue('pointer_arithmetic',node,stack,'derived pointer return needs a result-binding model')
        if kind=='BinaryOperator' and node.get('opcode') in ('==','!=','<','>','<=','>='):
            if any(p in self._bounded_pointers for c in inner if '*' in type_of(c) for p in self.resolve(c,env,stack)) and not self.pointer_comparison(node,env,stack) and not self.pointer_equality(node,env,stack):
                self.issue('pointer_arithmetic',node,stack,'bounded pointer comparisons need an identity/value model')
        if kind=='ImplicitCastExpr' and node.get('castKind')=='LValueToRValue':
            original=unwrap(inner[0]);target=self.array_lvalue(original)
            if target.get('kind')=='DeclRefExpr' and target.get('referencedDecl',{}).get('id') not in self.globals:
                self.local_qualified_access(target,stack)
            # A call in the address (`f(x)->field`) runs before the load: visit it first, so the
            # access sees what it returned here.
            called=any(n.get('kind')=='CallExpr' for n in walk(target))
            if called:self.visit(target,env,stack)
            if self.tracked_member(target,env,stack) is not None:pass # automatic record storage
            elif target.get('kind') in ('MemberExpr','UnaryOperator') and self.auto_storage(self.storage_paths(target,env,stack)):pass # stack object storage
            elif target.get('kind') in ('MemberExpr','ArraySubscriptExpr','CompoundLiteralExpr') or target.get('kind')=='UnaryOperator' and target.get('opcode')=='*' or target.get('kind')=='DeclRefExpr' and target.get('referencedDecl',{}).get('id') in self.globals:
                pointer_member=target.get('kind')=='MemberExpr' and '*' in type_of(target)
                self.access(self.storage_paths(target,env,stack) if pointer_member else self.resolve(target,env,stack),target,stack)
            if called:return
            if target is not original:
                self.visit(target,env,stack);return
        if kind=='UnaryExprOrTypeTraitExpr':return # sizeof/alignof do not evaluate ordinary operands
        if kind in ('IfStmt','ConditionalOperator') and len(inner)>=2 and inner[0].get('kind'):
            # A condition decided in this call context leaves the other arm unreachable here.
            outcome=self.decided_outcome(inner[0],env,stack)
            if outcome is not None:
                self.visit(inner[0],env,stack)
                arm=inner[1] if outcome else (inner[2] if len(inner)>2 else None)
                other=inner[2] if outcome and len(inner)>2 else inner[1] if not outcome else None
                if other is not None:self.unreachable_region(other,stack)
                if arm is not None:self.visit(arm,env,stack)
                self._taken_arms[id(node),tuple(stack)]=arm
                return
        if kind=='ReturnStmt':
            for child in inner:self.visit(child,env,stack)
            if self._return_values and self._flow_live and inner and '*' in type_of(inner[0]):
                self._return_values[-1].append(self.resolve(inner[0],env,stack))
            if self._flow_returns:
                partition=self.recent_partition(inner[0],stack) if inner and self._flow_live else None
                if partition is not None:
                    for signs,state in self.partition_states(partition):
                        self._flow_returns[-1].append((state,True));self._flow_return_classes[-1].append(signs)
                else:
                    self._flow_returns[-1].append(self.flow_snapshot())
                    self._flow_return_classes[-1].append(self.return_class(inner[0],env,stack) if inner and self._flow_live else self.ALL_SIGNS)
            self._flow_live=False;return
        if kind in ('GotoStmt','BreakStmt','ContinueStmt'):
            if kind=='GotoStmt':
                self._visited_gotos.setdefault(tuple(stack),set()).add(node.get('targetLabelDeclId'))
                self.flow_record_goto(node.get('targetLabelDeclId'),stack)
            self._flow_live=False;return
        if kind=='LabelStmt':self.flow_reset(stack,node.get('declId'))
        if kind in ('CaseStmt','DefaultStmt'):self.flow_reset(stack)
        if kind=='IfStmt' and len(inner)>=2 and inner[0].get('kind') and self.decided_outcome(inner[0],env,stack) is None:
            # Both arms may run: each starts from the state after the condition (refined by it); they rejoin.
            self.visit(inner[0],env,stack);base=self.flow_snapshot()
            self.flow_refine(inner[0],True,env,stack)
            self.visit(inner[1],env,stack);taken=self.flow_snapshot();self.flow_restore(base)
            self.flow_refine(inner[0],False,env,stack)
            if len(inner)>2:self.visit(inner[2],env,stack)
            self.flow_join([taken,self.flow_snapshot()]);return
        if kind=='ConditionalOperator' and len(inner)==3 and self.decided_outcome(inner[0],env,stack) is None:
            self.visit(inner[0],env,stack);base=self.flow_snapshot()
            self.visit(inner[1],env,stack);taken=self.flow_snapshot();self.flow_restore(base)
            self.visit(inner[2],env,stack);self.flow_join([taken,self.flow_snapshot()]);return
        if kind=='BinaryOperator' and node.get('opcode') in ('&&','||') and len(inner)==2:
            self.visit(inner[0],env,stack);base=self.flow_snapshot()
            self.visit(inner[1],env,stack);self.flow_join([base,self.flow_snapshot()]);return
        if kind in ('WhileStmt','ForStmt','DoStmt','SwitchStmt') and not (kind in ('WhileStmt','ForStmt') and self.loop_never_runs(node,env,stack)):
            # Records that outlive an iteration (or a case entry) lose their flow values here.
            # Objects declared in the body begin a new lifetime (indeterminate until stored) every
            # iteration; a for-init declaration runs once and is carried.
            body=inner[0] if kind=='DoStmt' else inner[-1] if inner else {}
            fresh={n['id'] for n in walk(body) if n.get('kind')=='VarDecl'}
            # An enclosing frame's object can change in the loop only through a pointer this frame holds.
            reachable=self.referenced_tokens(env)
            carried={t for t in self.flow_tokens(stack) if (self._auto_info[t]['owner']==tuple(stack) and self._auto_info[t]['declaration'] not in fresh) or
                (self._auto_info[t]['owner']!=tuple(stack) and t in reachable)}
            # A loop that cannot write stack objects keeps their values: its stores are to plain unescaped locals,
            # and no call in it receives a pointer to a stack object (hrtimer_active's seqcount retry loop).
            if carried and self.loop_writes_no_stack_objects(node,env,stack):carried=set()
            assigned={variable_key for n in walk(node) for variable_key in [self.assigned_local(n)] if variable_key is not None}
            # A tag field changes only by a whole-record store: one nothing in the loop makes keeps its value.
            stable=set()
            for t in carried:
                record=self.auto_record(t)
                if record is not None and self.tag_fields(record) and not self.stores_record(node,record.get('tagUsed','struct')+' '+(record.get('name') or '')):
                    stable|={(t,f) for f in self.tag_fields(record)}
            # A pointer local the loop only steps (p++, p += k) and that points into summarized arrays
            # stays in them: its entry value holds for the whole loop.
            steps=set()
            for k,v in self._flow.items():
                if k[0]=='PL' and k[1]==tuple(stack) and k[2] in assigned and v[0]=='p' and v[1] and all(self.summary_token(x) for x in v[1]):
                    writes=[n for n in walk(node) if self.assigned_local(n)==k[2]]
                    if all(n.get('kind')=='UnaryOperator' or n.get('kind')=='CompoundAssignOperator' and n.get('opcode') in ('+=','-=') for n in writes):steps.add(k)
            dropped=lambda k:(k[0] in carried and k not in stable) or k[0] in ('L','RP','PL') and k[1]==tuple(stack) and k[2] in assigned and k not in steps
            self._flow={k:v for k,v in self._flow.items() if not dropped(k)}
            self._flow_carried.append(carried);self._flow_stable.append(stable)
            try:
                for child in inner:self.visit(child,env,stack)
            finally:self._flow_carried.pop();self._flow_stable.pop()
            self._flow={k:v for k,v in self._flow.items() if not dropped(k)};self._flow_live=True
            return
        if kind in ('WhileStmt','ForStmt'):
            parts=inner
            condition=parts[0] if kind=='WhileStmt' and len(parts)==2 else parts[2] if kind=='ForStmt' and len(parts)==5 and not parts[1].get('kind') else None
            if condition is not None and condition.get('kind') and self.decided_outcome(condition,env,stack)==0:
                # The condition is false on entry: the body (and a for increment) never runs.
                self.unreachable_region(parts[-1],stack)
                if kind=='ForStmt':self.unreachable_region(parts[3],stack)
                if kind=='ForStmt' and parts[0].get('kind'):self.visit(parts[0],env,stack)
                self.visit(condition,env,stack)
                return
        if kind=='CompoundStmt' and stack and stack[-1] in self.functions:
            facts=self.values.facts_for(stack[-1])
            labels=lambda statement:{n.get('declId') for n in walk(statement) if n.get('kind')=='LabelStmt'}
            visited=set();skipped=[];index=0
            while index<len(inner):
                child=inner[index];visited.add(index)
                self.visit(child,env,stack)
                key=(id(child),tuple(stack))
                arm=self._taken_arms.get(key) if child.get('kind')=='IfStmt' else None
                dead=not self._flow_live and index+1<len(inner)
                if (dead or arm is not None and facts.exits(arm)) and not any(s.get('kind') in ('CaseStmt','DefaultStmt') or
                        any(n.get('kind') in ('CaseStmt','DefaultStmt') for n in walk(s)) for s in inner[index+1:]):
                    # The taken arm always leaves the block: later statements run only from a label
                    # that a goto visited in this context targets.
                    jumped=self._visited_gotos.get(tuple(stack),set())
                    resume=next((k for k in range(index+1,len(inner)) if labels(inner[k])&jumped),None)
                    later=range(index+1,resume if resume is not None else len(inner))
                    if later:self.branch_proofs.append(dict(kind='unreachable_after_decided_exit',function=stack[-1],call_path=stack,
                        location=self.location(child),skipped_statements=len(later)))
                    skipped.extend(later)
                    for k in later:self.unreachable_region(inner[k],stack)
                    if resume is None:break
                    index=resume;continue
                index+=1
            # A goto visited later may target a label in a skipped statement: visit from there too.
            while True:
                jumped=self._visited_gotos.get(tuple(stack),set())
                entry=next((k for k in skipped if k not in visited and labels(inner[k])&jumped),None)
                if entry is None:break
                for k in range(entry,len(inner)):
                    if k in visited:break
                    visited.add(k);self._unreachable.discard((id(inner[k]),tuple(stack)));self.visit(inner[k],env,stack)
            return
        if kind=='VarDecl' and inner and node.get('id') in self.automatic_records and stack and stack[-1] in self.functions and node['id'] in self.values.facts_for(stack[-1]).escaped:
            token=self.auto_origin(node['id'],stack);declaration=self.record_declaration(type_of(node))
            if token is not None and declaration is not None:
                initial=self.flat_initializer(declaration,inner[-1],env,stack)
                for field in [f[0] for f in self.flat_fields(declaration) if '*' in f[1] and '(' not in f[1]]:
                    self.auto_write(token,field,initial.get(field,{'unresolved:auto-field'}) if initial is not None else {'unresolved:auto-field'},node,stack,strong=True)
                from entry_state_values import integer_type
                scalars=self.scalar_initializer(declaration,inner[-1],stack) or {}
                for field in [f[0] for f in self.flat_fields(declaration) if integer_type(f[1])]:
                    self.auto_scalar_write(token,field,scalars.get(field),node,stack,strong=True)
        if kind=='VarDecl':
            if inner and node.get('storageClass') is None and not node.get('tls'):self.local_qualified_access(node,stack)
            for child in inner:self.visit(child,env,stack)
            # Numeric scalars carry no alias values; `size_t n=0` is not a null pointer.
            from entry_state_values import integer_type
            if inner and integer_type(type_of(node)) and node.get('storageClass') is None and stack and stack[-1] in self.functions and node['id'] not in self.values.facts_for(stack[-1]).escaped:
                self.local_flow_write(stack,node['id'],self.flow_interval(inner[-1],env,stack))
            if node.get('storageClass') is None and stack and stack[-1] in self.functions:self.partition_store(node['id'],inner[-1] if inner else None,stack)
            if inner and not arithmetic_scalar(type_of(node)):
                initial=self.resolve(inner[-1],env,stack)
                env[node['id']]=self.bounded_aliases(env.get(node['id'],set())|initial,node,stack)
                if '*' in type_of(node) and stack and stack[-1] in self.functions and node['id'] not in self.values.facts_for(stack[-1]).escaped:
                    self.pointer_local_write(('PL',tuple(stack),node['id']),initial)
                if '*' in type_of(node) and stack and stack[-1] in self.functions and node['id'] in self.values.facts_for(stack[-1]).escaped:
                    token=self.auto_origin(node['id'],stack)
                    if token is not None:self.auto_write(token,'*',initial or {'unresolved:alias'},node,stack,strong=True)
            elif inner:pass
            else:
                certified=self._pointer_initialization_environments.get(id(env),(None,frozenset()))[1]
                if node['id'] not in certified:env[node['id']]={'local:'+node.get('name','unknown')}
            return
        if kind in ('BinaryOperator','CompoundAssignOperator','UnaryOperator') and node.get('opcode') in ('=','+=','-=','++','--'):
            update=self.pointer_update(node,env,stack)
            if update is not None:
                self.local_qualified_access(unwrap(inner[0]),stack)
                if kind!='UnaryOperator':self.visit(update['index'],env,stack)
                return
        if kind in ('BinaryOperator','CompoundAssignOperator') and node.get('opcode','').endswith('=') and node.get('opcode') not in ('==','!=','<=','>='):
            left=self.array_lvalue(unwrap(inner[0]));right=inner[1]
            if kind=='CompoundAssignOperator' and '*' in type_of(left) and not self.local_pointer_mutation(node,env,stack):
                self.issue('pointer_arithmetic',node,stack,'pointer mutation needs an offset/provenance model')
            self.visit(right,env,stack)
            storage=self.storage_paths(left,env,stack) if left.get('kind') in ('MemberExpr','UnaryOperator','DeclRefExpr') else set()
            # A pointer local whose address is never taken is its own storage: `p = q` rebinds p. Its
            # resolved values name what p points to, which a store to p never writes.
            if left.get('kind')=='DeclRefExpr' and self.pointer_local_key(left,stack) is not None:storage=set()
            if self.auto_storage(storage):
                declaration=self.record_declaration(type_of(left))
                if declaration is not None and kind=='BinaryOperator':
                    # Whole-object store: *p = (struct T){...} or s = (struct T){...}.
                    fields=[f[0] for f in self.flat_fields(declaration) if '*' in f[1] and '(' not in f[1]]
                    initial=self.flat_initializer(declaration,right,env,stack)
                    from entry_state_values import integer_type
                    scalar_fields=[f[0] for f in self.flat_fields(declaration) if integer_type(f[1])]
                    scalars=self.scalar_initializer(declaration,right,stack) or {}
                    union=self.union_fields(declaration)
                    tag=frozenset((f,scalars[f][0]) for f in self.tag_fields(declaration) if isinstance(scalars.get(f),tuple) and scalars[f][0]==scalars[f][1])
                    for path in storage:
                        token=re.match(r'^(?:\*\()*(auto:\d+)',path)[1]
                        for field in fields:
                            written=(initial or {}).get(field,{'unresolved:auto-field'}) if initial is not None else {'unresolved:auto-field'}
                            if field in union:self.tag_union_values(token,field,written,tag)
                            self.auto_write(token,field,written,node,stack,strong=len(storage)==1)
                        for field in scalar_fields:self.auto_scalar_write(token,field,scalars.get(field),node,stack,strong=len(storage)==1)
                elif '*' in type_of(left):
                    values=self.resolve(right,env,stack) or {'unresolved:auto-field'}
                    for path in storage:
                        key=self.auto_key(path)
                        if key is None:continue
                        record=self.auto_record(key[0])
                        if record is not None and key[1] in self.union_fields(record):
                            self.tag_union_values(key[0],key[1],values,self.current_tag(key[0],record))
                        self.auto_write(key[0],key[1],values,node,stack,strong=len(storage)==1)
                else:
                    # An integer field: its value here, or unknown for compound updates and wider records.
                    from entry_state_values import integer_type
                    bounds=None
                    if kind=='BinaryOperator' and integer_type(type_of(left)):
                        bounds=self.constant_interval(right)
                        if bounds is None:bounds,_=self.values.interval(right,stack[-1],self.context_ranges(stack))
                    for path in storage:
                        key=self.auto_key(path)
                        if key is not None:self.auto_scalar_write(key[0],key[1],tuple(bounds) if bounds is not None else None,node,stack,strong=len(storage)==1)
                self.visit(left if left is not unwrap(inner[0]) else inner[0],env,stack);return
            tracked=self.tracked_member(left,env,stack)
            automatic_pointer=(left.get('kind')=='DeclRefExpr' and
                left.get('referencedDecl',{}).get('id') not in self.globals)
            stored=[p for p in self.resolve(right,env,stack) if p in self._bounded_pointers] if '*' in type_of(right) and not automatic_pointer else []
            # The address of one element of a non-automatic array is an ordinary object address:
            # a later load of it carries no array provenance, so arithmetic on it stays unproven.
            elements=[self._bounded_pointers[p] for p in stored]
            if stored and all(not o['owner'] and isinstance(o['offset'],int) and 0<=o['offset']<o['extent'] for o in elements):
                self.pointer_stores.append(dict(kind='array_element_address_store',function=stack[-1],call_path=stack,location=self.location(node),
                    elements=sorted({'%s[%d]'%(o['path'],o['offset']) for o in elements}),array_provenance_retained=False))
            elif stored:
                self.issue('pointer_arithmetic',node,stack,'bounded pointer store needs an escape and reconstruction model')
            if '*' in type_of(right) and not automatic_pointer and tracked is None and self.derived_values(self.resolve(right,env,stack)):
                self.issue('pointer_arithmetic',node,stack,'derived pointer store needs an escape and reconstruction model')
            if left.get('kind')=='DeclRefExpr' and left.get('referencedDecl',{}).get('id') not in self.globals:
                self.local_qualified_access(left,stack)
                key=left.get('referencedDecl',{}).get('id')
                # p += n holds p + n, not n.
                value=self.mutation_expression(node) if kind=='CompoundAssignOperator' and '*' in type_of(left) else right
                assigned=self.resolve(value,env,stack) if value is not None else {'unresolved:pointer-mutation'}
                env[key]=self.bounded_aliases(env.get(key,set())|assigned,node,stack)
                if '*' in type_of(left):self.pointer_local_write(self.pointer_local_key(left,stack),assigned)
                if self.integer_local(left,stack) is not None:
                    self.local_flow_write(stack,key,self.flow_interval(right,env,stack) if kind=='BinaryOperator' else None)
                self.partition_store(key,right if kind=='BinaryOperator' else None,stack)
                token=self.escaped_pointer_local(left,stack)
                if token is not None and kind=='CompoundAssignOperator' and '*' in type_of(left):assigned=self.escaped_pointer_step(node,env,stack)
                if token is not None:self.auto_write(token,'*',assigned or {'unresolved:alias'},node,stack,strong=True)
            elif tracked is not None:
                env[tracked]=self.bounded_aliases(env[tracked]|self.resolve(right,env,stack),node,stack)
            else:
                paths=self.storage_paths(left,env,stack) if left.get('kind')=='MemberExpr' and '*' in type_of(left) else self.resolve(left,env,stack)
                self.access(paths,left,stack,True)
                if kind=='CompoundAssignOperator':self.access(paths,left,stack)
            self.visit(left if left is not unwrap(inner[0]) else inner[0],env,stack);return
        if kind=='UnaryOperator' and node.get('opcode') in ('++','--'):
            original=unwrap(inner[0]);target=self.array_lvalue(original)
            if '*' in type_of(target) and not self.local_pointer_mutation(node,env,stack):
                self.issue('pointer_arithmetic',node,stack,'pointer mutation needs an offset/provenance model')
            local_integer=(target.get('kind')=='DeclRefExpr' and (arithmetic_scalar(type_of(target)) or '*' in type_of(target) and self.local_pointer_mutation(node,env,stack)) and
                           target.get('referencedDecl',{}).get('id') not in self.globals)
            if 'volatile' in type_of(target) and self.local_volatile_storage(target,stack):local_integer=True
            if local_integer and self.integer_local(target,stack) is not None:
                self.local_flow_write(stack,target['referencedDecl']['id'],None)
            if target.get('kind')=='DeclRefExpr':self._flow.pop(('RP',tuple(stack),target.get('referencedDecl',{}).get('id')),None)
            if '*' in type_of(target):
                local=self.pointer_local_key(target,stack);stepped=self.mutation_expression(node)
                if local is not None:self.pointer_local_write(local,self.resolve(stepped,env,stack) if stepped is not None else set())
            token=self.escaped_pointer_local(target,stack) if '*' in type_of(target) else None
            if token is not None:self.auto_write(token,'*',self.escaped_pointer_step(node,env,stack),node,stack,strong=True)
            if not local_integer:
                paths=self.resolve(target,env,stack)
                for path in paths:
                    key=self.auto_key(path) if re.match(r'^(?:\*\()*auto:\d+',path) else None
                    if key is not None:self.auto_scalar_write(key[0],key[1],None,node,stack,strong=len(paths)==1)
                self.access(paths,target,stack);self.access(paths,target,stack,True)
            if target is not original:
                self.visit(target,env,stack);return
        if kind=='CallExpr':
            names=self.targets(node,env,stack)
            constant_query=self.compile_time_builtin(node)
            if constant_query is not None and constant_query['name']=='__builtin_constant_p':
                # The operand is examined by the compiler and never evaluated at run time.
                self.calls.append({'caller':stack[-1],'callee':constant_query['name'],'call_path':stack,'location':self.location(node),
                    'boundary':None,'resolution':'compiler_builtin','intrinsic':constant_query})
                return
            for child in inner[1:]:self.visit(child,env,stack)
            if not self.direct_call(node):self.visit(inner[0],env,stack)
            intrinsic=self.integer_bit_intrinsic(node) or self.expect_intrinsic(node) or constant_query
            if intrinsic is not None and not self.boundary(intrinsic['name']) and intrinsic['name'] not in self.functions:
                self.calls.append({'caller':stack[-1],'callee':intrinsic['name'],'call_path':stack,'location':self.location(node),
                    'boundary':None,'resolution':'compiler_builtin','intrinsic':intrinsic})
                return
            if names is not None and not names:
                # The contract says the field is NULL for every admitted object: the call is unreachable.
                self.calls.append({'caller':stack[-1],'callee':None,'call_path':stack,'location':self.location(node),'boundary':None,'resolution':'contract_null_callback'})
                return
            if not names:
                self.calls.append({'caller':stack[-1],'callee':None,'call_path':stack,'location':self.location(node),'boundary':None})
                self.issue('indirect_call',node,stack,'callback target set is unresolved');return
            base=None;outcomes=[];returned=[]
            for name in sorted(names):
                policy=self.boundary(name)
                if (name not in self.functions or policy) and (not policy or policy.get('kind') not in ('ordering_model','value_model')):
                    # Code without a body may store through any stack object it receives,
                    # except declared memory models, whose writes are listed.
                    for index,argument in enumerate(inner[1:]):
                        if policy and policy.get('kind')=='memory_model' and index not in policy.get('writes',[]):continue
                        # A declared user-value write stores exactly a user address (boundary_user_value), not unknown data.
                        if policy and policy.get('kind')=='memory_model' and index in policy.get('user_values',[]):continue
                        for value in self.resolve(argument,env,stack) if '*' in type_of(argument) else ():
                            match=re.match(r'^(auto:\d+)$',value)
                            if match is None:continue
                            info=self._auto_info[match[1]];owner=info['owner']
                            declaration=next((n for n in self.values.facts_for(owner[-1]).order if n.get('id')==info['declaration']),None)
                            record=self.auto_record(match[1])
                            if info.get('summary') and record is None:
                                self.auto_write(match[1],'*',{'unresolved:auto-escape'});continue
                            for field in [f[0] for f in self.flat_fields(record) if '*' in f[1] and '(' not in f[1]]:
                                self.auto_write(match[1],field,{'unresolved:auto-escape'})
                            for field in [f[0] for f in self.flat_fields(record) if '*' not in f[1]]:
                                self.auto_scalar_write(match[1],field,None)
                            if declaration is not None and '*' in type_of(declaration) and record is None:
                                self.auto_write(match[1],'*',{'unresolved:auto-escape'})
                self.calls.append({'caller':stack[-1],'callee':name,'call_path':stack,'location':self.location(node),'boundary':policy,
                    'resolution':'direct' if self.direct_call(node) else 'callback contract' if isinstance(names,frozenset) else 'finite local function-pointer targets'})
                if policy:
                    # An ordering model only names its lock object; it needs no extent or lifetime contract.
                    # Declared read/write arguments are checked below as accesses of their pointee.
                    declared=set(policy.get('reads',[]))|set(policy.get('writes',[]))
                    spans={span['pointer'] for span in policy.get('spans',[])}
                    if policy['kind']!='ordering_model' and any(p in self._bounded_pointers for i,c in enumerate(inner[1:]) if '*' in type_of(c) and i not in declared|spans for p in self.resolve(c,env,stack)):
                        self.issue('boundary_memory_effect',node,stack,'bounded pointer boundary arguments need an extent/lifetime contract')
                    if any(p in self._derived_pointers for i,c in enumerate(inner[1:]) if '*' in type_of(c) and i not in spans for p in self.resolve(c,env,stack)):
                        self.issue('boundary_memory_effect',node,stack,'derived pointer boundary arguments need a checked span')
                    if spans:self.span_accesses(policy,node,inner,env,stack)
                    if policy['kind']=='scalar_transcript' and any('*' in type_of(c) for c in inner[1:]):
                        self.issue('boundary_memory_effect',node,stack,'pointer arguments require an explicit memory-effect model')
                    # Declared argument effects: the boundary reads or writes the pointee of these arguments.
                    for write,indexes in ((False,policy.get('reads',[])),(True,policy.get('writes',[]))):
                        for index in indexes:
                            if index>=len(inner)-1 or '*' not in type_of(inner[1+index]):
                                self.issue('boundary_memory_effect',node,stack,'declared argument effect does not name a pointer argument');continue
                            argument=inner[1+index];pointee=re.sub(r'\s*\*\s*(?:const\s*)?$','',type_of(argument))
                            # The address of this frame's own scalar local that has no scalar-address
                            # model (a volatile one): the boundary writes live automatic storage, which
                            # is no kernel state (volatile storage stays classified).
                            local=unwrap(argument)
                            if local.get('kind')=='UnaryOperator' and local.get('opcode')=='&' and children(local):
                                target=unwrap(children(local)[0]);declaration=target.get('referencedDecl',{})
                                if declaration.get('id') in self.automatic_scalars:target={}
                                facts=self.values.facts_for(stack[-1]) if stack[-1] in self.functions else None
                                if (target.get('kind')=='DeclRefExpr' and declaration.get('kind')=='VarDecl' and declaration.get('id') not in self.globals and
                                        facts is not None and declaration.get('id') in facts.declarations and arithmetic_scalar(' '.join(re.sub(r'\b(?:volatile|const)\b','',type_of(target)).split())) and
                                        facts.declarations[declaration['id']].get('storageClass') is None and
                                        ('volatile' not in type_of(target) or self.local_volatile_storage(target,stack))):continue
                            dereference={'kind':'UnaryOperator','opcode':'*','type':{'qualType':pointee},'valueCategory':'lvalue',
                                'range':node.get('range',{}),'inner':[argument],'id':(node.get('id') or '')+'#arg'+str(index)}
                            self.access(self.resolve(dereference,env,stack),dereference,stack,write)
                            if write and index in policy.get('user_values',[]):self.boundary_user_value(name,argument,node,env,stack)
                    continue
                if name not in self.functions:
                    eliminated=self.build_eliminated_call(node,name)
                    if eliminated is not None:self.calls[-1].update(resolution='build_eliminated',build_evidence=eliminated);continue
                    self.issue('unmodeled_external',node,stack,'external dependency requires a boundary model: '+name);continue
                if name in stack:
                    if not self.self_recursive_footprint(node,name,stack):self.issue('recursion',node,stack,'recursive memory closure needs a bound/fixpoint')
                    continue
                bindings=[self.resolve(c,env,stack) for c in inner[1:]]
                records=[self.record_value(c,env,stack) if self.record_pointer_fields(type_of(c)) else None for c in inner[1:]]
                self.enter_call(name,node,stack)
                self._call_nodes.append(node)
                if base is None:base=self.flow_snapshot()
                else:self.flow_restore(base)
                try:self.function(name,stack,bindings,records)
                finally:self._call_nodes.pop()
                # A reviewed model that always fails its fault assertion rejects the run: nothing after the call is
                # on an accepted (equivalent) path, so the state there is dead.
                if self.always_rejects(name):
                    self._flow_live=False
                    self.allocation_uses.append(dict(kind='rejecting_model_call',function=stack[-1],callee=name,call_path=stack,location=self.location(node)))
                outcomes.append((self.flow_snapshot(),self._last_partition))
                returned.append(self._last_return_values)
            if len(outcomes)>1 or outcomes and len(names)>1:
                # Any one of several targets runs: their states join (a skipped one leaves the call's state).
                self.flow_join([state for state,_ in outcomes]+([base] if len(outcomes)<len(names) else []))
            self._recent_partition=(id(node),tuple(stack),outcomes[0][1]) if len(outcomes)==1 and len(names)==1 and outcomes[0][1] is not None else None
            # A pointer call whose every target body ran here returns what those bodies returned.
            key=(id(node),tuple(stack))
            if '*' in type_of(node) and returned and len(returned)==len(names):self._recent_return[key]=frozenset().union(*returned)
            else:self._recent_return.pop(key,None)
            return
        for child in inner:self.visit(child,env,stack)

    def function(self,name,stack,bindings=None,records=None):
        self.contexts+=1
        if self.contexts>self.max_contexts:
            self.issue('analysis_limit',self.functions[name],stack+[name],'call-context limit reached');return
        node=self.functions[name];env={}
        contracts=self.argument_objects.get(name,self.argument_objects.get(name.split(':',1)[-1],{})) if not stack else {}
        parameters=self.parameters(node)
        if set(contracts)-{p.get('name') for p in parameters}:raise ValueError('unknown root argument object contract: '+name)
        for index,parameter in enumerate(parameters):
            if variably_modified_type(type_of(parameter)):
                self.issue('unsupported_construct',parameter,stack+[name],'variably modified parameter types need bound/effect analysis')
            env[parameter['id']]=bindings[index] if bindings is not None and index<len(bindings) else {'argument:'+parameter['name']}
            if not stack and (name.split(':',1)[-1],parameter.get('name')) in self.user_addresses and '*' in type_of(parameter):
                env[parameter['id']]={'user:'+parameter['name']}
            env[parameter['id']]=self.bounded_aliases(env[parameter['id']],parameter,stack+[name])
            release=self.deallocators.get(name.split(':',1)[-1])
            if release is not None and release['parameter']==parameter.get('name'):
                # Releasing automatic storage is undefined (kfree takes kmalloc'd memory or NULL): a stack object
                # among the argument's values never reaches the deallocator.
                stack_objects={v for v in env[parameter['id']] if re.fullmatch(r'auto:\d+',v) and not self._auto_info.get(v,{}).get('allocation')}
                if stack_objects:
                    env[parameter['id']]=(env[parameter['id']]-stack_objects) or {INFEASIBLE}
                    self.allocation_uses.append(dict(kind='deallocator_excludes_automatic_storage',function=name,call_path=stack+[name],argument=parameter['name'],
                        excluded=len(stack_objects),reason=release['reason']))
            if records is not None and index<len(records) and records[index] is not None:
                for field,paths in records[index].items():
                    if field==LINKS:
                        for pointer,flag in paths.items():env[parameter['id']+'.'+pointer+LINK_SUFFIX]={flag}
                    else:env[parameter['id']+'.'+field]=self.bounded_aliases(paths,parameter,stack+[name])
            typ=type_of(parameter)
            if parameter['name'] in contracts:typ=self.argument_pointer_type(typ,parameter.get('_translation_unit'))
            if typ is None:raise ValueError('volatile argument object typedef requires an adapter')
            if not stack:self.arguments.append({'name':parameter['name'],'type':typ,'pointer':'*' in typ})
            if parameter['name'] in contracts:
                contract=contracts[parameter['name']]
                if (contract.get('kind')!='object_argument' or contract.get('snapshot_safe') is not True or
                    not contract.get('reason') or not contract.get('implementation') or
                    object_pointee(typ) is None):
                    raise ValueError('root argument requires a plain object pointer and explicit snapshot_safe contract: '+parameter['name'])
                provider='osrec_argument_'+parameter['name']
                if provider in self.functions or self.boundary(provider):raise ValueError('reserved argument binding name conflicts: '+provider)
                self.providers[provider]={'function':provider,'return_type':typ,'contract':contract,
                    'binding_kind':'root_argument','argument':parameter['name'],'argument_index':index}
                env[parameter['id']]={provider+'()'}
        body=next(c for c in children(node) if c.get('kind')=='CompoundStmt')
        # May-access unions need no reachability proof for direct jumps, but
        # every target must belong to the configured function body.
        if any(term.get('kind')=='GotoStmt' for term in self.effect_nodes(body)):
            labels={term.get('declId') for term in self.effect_nodes(body) if term.get('kind')=='LabelStmt'}
            for term in self.effect_nodes(body):
                kind=term.get('kind')
                if kind=='GotoStmt' and (not term.get('targetLabelDeclId') or term['targetLabelDeclId'] not in labels):
                    self.issue('unsupported_construct',term,stack+[name],'direct jump target is outside the available function body')
        # Aliases are computed before the body runs: flow values hold only if it writes no memory.
        frame=tuple(stack+[name])
        self._flow={k:v for k,v in self._flow.items() if not (k[0]=='PL' and k[1]==frame)}
        bound={p['id']:set(env.get(p['id'],())) for p in parameters if '*' in type_of(p) and '(' not in type_of(p)}
        mask=self.flow_mask(name)
        try:self.pointer_aliases(body,env,stack+[name])
        finally:self.flow_unmask(mask)
        escaped=self.values.facts_for(name).escaped
        for pid,values in bound.items():
            if pid not in escaped:self.pointer_local_write(('PL',frame,pid),values)
        if not stack:self.root_aliases=dict(env)
        facts=self.values.facts_for(name);ranges=self.context_ranges(stack+[name])
        from entry_state_values import integer_type
        for parameter in parameters:
            if integer_type(type_of(parameter)) and parameter['id'] in facts.mutations and parameter['id'] not in facts.escaped:
                self.local_flow_write(stack+[name],parameter['id'],ranges.get(parameter['id']) if hasattr(ranges,'get') else None)
        self._flow_returns.append([]);self._flow_return_classes.append([]);self._return_values.append([])
        try:self.visit(body,env,stack+[name])
        finally:returns=self._flow_returns.pop();classes=self._flow_return_classes.pop();values=self._return_values.pop()
        # The values its live returns produced in this context (a function never returning yields none).
        self._last_return_values=set().union(*values) if values else set()
        if self._flow_live:returns.append(self.flow_snapshot());classes.append(self.ALL_SIGNS)
        if returns:self.flow_join(returns)
        else:self._flow={};self._flow_live=True
        self._last_partition=self.partition_of(returns,classes,tuple(stack)) if returns else None
        self._flow={k:v for k,v in self._flow.items() if not (k[0]=='PL' and k[1]==frame)}

    def analyze(self,root):
        """Analyze a root by iterating whole-root passes to a fixpoint.

        A pass uses the previous pass's unreachable regions, its goto states (joined at
        labels; the first pass takes a label's fall-through state) and the stack-object
        values it wrote. A converged result solves the analysis equations, so it is sound.
        Without convergence the root is analyzed again conservatively: no regions or goto
        states carried, every label resets, and only late stack-object writes repeat a pass.
        """
        if root not in self.functions:raise ValueError('root has no available configured body: '+root)
        for optimistic,passes in ((True,10),(False,5)):
            store={};sites={};scalars={};unreachable=frozenset();goto_states=None;returns=None;converged=False;objects={};infos={}
            for attempt in range(passes):
                run=self if optimistic and not attempt else self.fresh()
                run._optimistic=optimistic
                if attempt:
                    # The carried store is keyed by stack-object tokens: each (owner stack, declaration) keeps its
                    # token across passes, whatever order this pass meets the objects in.
                    run._auto_objects=dict(objects);run._auto_info={k:dict(v) for k,v in infos.items()}
                    run._auto_store={k:set(v) for k,v in store.items()};run._auto_sites={k:list(v) for k,v in sites.items()};run._auto_scalars=dict(scalars)
                    run._prior_unreachable=unreachable if optimistic else frozenset();run._prior_goto_states=goto_states if optimistic else None
                    run._prior_returns=returns if optimistic and returns is not None else {}
                report=run.analyze_once(root)
                regions=frozenset(run._unreachable)
                # The stack-object store this pass wrote must be the one it started from: a value only an
                # earlier pass wrote (code that pass still visited) would otherwise survive the fixpoint.
                same_store=attempt>0 and {k:set(v) for k,v in run._auto_written.items() if v}=={k:set(v) for k,v in store.items() if v}
                if optimistic:converged=not run._auto_late and attempt>0 and regions==unreachable and run._goto_states==goto_states and run._recent_return==returns and same_store
                else:converged=not run._auto_late
                if converged:break
                # Carry only this pass's writes: earlier passes may have visited code now unreachable.
                # Values written while more code was reachable can sustain themselves through the carried store
                # (a field read and written back); when reachability changes, the store restarts empty.
                restart=regions!=unreachable
                store={} if restart else run._auto_written;sites={} if restart else run._auto_sites;scalars={} if restart else run._auto_scalar_written
                unreachable=regions;goto_states=dict(run._goto_states);returns=dict(run._recent_return);objects=dict(run._auto_objects);infos={k:{f:x for f,x in v.items() if f!='summary' or v.get('allocation')} for k,v in run._auto_info.items()}
            if converged:break
        if not converged:
            report['blockers'].append({'kind':'analysis_limit','function':root,'call_path':[root],'detail':'stack-object field values did not converge in 5 passes','location':{}})
            report['classification']='requires_review'
        if run is not self:self.__dict__.update(run.__dict__)
        return report

    def analyze_once(self,root):
        self._flow={};self._flow_live=True;self._flow_off=0;self._flow_masks=[];self._flow_carried=[];self._flow_stable=[];self._flow_returns=[];self._flow_return_classes=[];self._return_values=[];self._last_return_values=None;self._recent_return={};self._last_partition=None;self._recent_partition=None;self._flow_weak=0
        # Root parameters with a boundary-enforced range start in it; each range a proof reads is reported.
        ranges=RootRanges(self)
        for parameter in self.parameters(self.functions[root]):
            contract=self.argument_ranges.get((root.split(':',1)[-1],parameter.get('name')))
            if contract is not None:ranges.contracts[parameter['id']]=contract
        if ranges.contracts:self._context_calls[(root,)]=ranges
        self.function(root,[])
        def unique(items):
            result=[];seen=set()
            for item in items:
                key=json.dumps(item,sort_keys=True)
                if key not in seen:seen.add(key);result.append(item)
            return result
        # The empty-list contract holds only if the call stores to no such head (or the object holding one).
        if self.empty_list_heads and self.list_proofs:
            from entry_state_lists import normalized as list_path
            for w in self.writes:
                n=list_path(w.get('path',''))
                if any(n==h or n.startswith(h+'.') or h.startswith(n+'.') for h in self.empty_list_heads):
                    self.blockers.append(dict(kind='pointer_arithmetic',function=w['function'],call_path=w['call_path'],detail='an empty list head is stored during the call',location=w['location']))
        # A comparison within an array reached through a pointer member needs that member unwritten by the call.
        for base,(node,stack) in sorted(self._stable_bases.items()):
            if any(w.get('path')==base or base.startswith(w.get('path','')+'.') for w in self.writes):
                self.issue('pointer_arithmetic',node,stack,'array comparison base pointer is stored during the call')
        reads=unique(self.reads);writes=unique(self.writes);blockers=unique(self.blockers)
        report={'root':root,'classification':'requires_review' if blockers else 'candidate_with_models' if self.boundaries or self.argument_objects else 'candidate',
            'analysis_limits':{'max_alias_paths':self.max_alias_paths,'alias_path_limit_observed':self.alias_path_limit_observed},
            'analysis_kind':'conservative configured-AST may-access closure','minimality_proven':False,'completeness_proven':False,
            'arguments':self.arguments,'entry_reads':reads,'state_writes':writes,'call_sites':unique(self.calls),
            'object_providers':list(self.providers.values()),'memory_ranges':unique(self.ranges),'blockers':blockers,
            'policy':'retain may-reads including reads after writes; both branch arms and loop bodies; unknown effects block automatic export'}
        if self.pointer_initializations:report['pointer_initialization_proofs']=unique(self.pointer_initializations)
        if self.pointer_returns:report['pointer_return_proofs']=unique(self.pointer_returns)
        if self.pointer_stores:report['pointer_store_proofs']=unique(self.pointer_stores)
        if self.user_address_proofs:report['user_address_proofs']=unique(self.user_address_proofs)
        if self.array_summaries:report['automatic_array_summaries']=unique(self.array_summaries)
        if self.automatic_views:report['automatic_views']=unique(self.automatic_views)
        if self.assertion_uses:
            report['fault_assertion_guards']=unique(self.assertion_uses)
            report['fault_assertion_contracts']=[dict(a) for a in self.fault_assertion_items if any(u['assertion']==a['function'].split(':',1)[-1] for u in self.assertion_uses)]
        if self.pointer_differences:report['pointer_difference_proofs']=unique(self.pointer_differences)
        if self.pointer_comparisons:report['pointer_comparison_proofs']=unique(self.pointer_comparisons)
        if self.pointer_updates:report['pointer_update_proofs']=unique(self.pointer_updates)
        if self.container_proofs:report['container_proofs']=unique(self.container_proofs)
        if self.list_proofs:
            report['empty_list_proofs']=unique(self.list_proofs)
            report['empty_list_contracts']=self.empty_list_items
        if self.derived_proofs:report['derived_pointer_proofs']=unique(self.derived_proofs)
        if self.span_proofs:report['checked_span_proofs']=unique(self.span_proofs)
        if self.branch_proofs:report['decided_branch_proofs']=unique(self.branch_proofs)
        if self.index_values:report['local_index_proofs']=unique(self.index_values)
        if self.local_volatile_proofs:report['local_volatile_storage_proofs']=unique(self.local_volatile_proofs)
        if self.scalar_addresses:report['scalar_address_proofs']=unique(self.scalar_addresses)
        if self.recursion_proofs:report['recursion_footprint_proofs']=unique(self.recursion_proofs)
        if self.null_guard_proofs:report['null_guard_proofs']=unique(self.null_guard_proofs)
        if self.trap_proofs:report['trap_proofs']=unique(self.trap_proofs)
        if self.tagged_pointer_proofs:report['tagged_pointer_proofs']=unique(self.tagged_pointer_proofs)
        if self.ordering_asm_proofs:report['operand_free_asm_proofs']=unique(self.ordering_asm_proofs)
        if self.infeasible_accesses:report['infeasible_accesses']=unique(self.infeasible_accesses)
        if self.callback_uses:report['callback_contract_uses']=unique(self.callback_uses)
        if self.masked_pointer_proofs:report['masked_pointer_proofs']=unique(self.masked_pointer_proofs)
        if self.external_accesses:report['external_memory_accesses']=unique(self.external_accesses)
        used=unique([(s['record'],s['field']) for v in self.index_values for s in v['proof'].get('state_ranges',[])]+sorted(self.range_uses))
        assumptions=[dict(self.state_ranges[s]) for s in used]+self.extent_assumptions
        if assumptions:report['state_range_assumptions']=unique(assumptions)
        if self.argument_range_uses:report['argument_range_assumptions']=[dict(self.argument_ranges[k]) for k in sorted(self.argument_range_uses)]
        if self.allocation_uses or any(i.get('allocation') for i in self._auto_info.values()):
            report['allocation_summaries']=unique([dict(function=i['allocation']['function'],element_type=i['allocation']['element_type'],elements=i['allocation']['elements'],
                object=i['allocation']['object'],validated_by=i['allocation']['validated_by'],assumptions=['the allocation is written before it is read','it is not read after kfree'])
                for i in self._auto_info.values() if i.get('allocation')])+unique(self.allocation_uses)
        if self.prune_written:
            from entry_state_dominance import MustStore
            body=next(c for c in children(self.functions[root]) if c.get('kind')=='CompoundStmt')
            report=MustStore(self,root,self.root_aliases).run(report,body)
        return report


def snapshot_providers(plan):
    """Check synthetic argument bindings before capture or reconstruction."""
    providers=plan['object_providers'];names=set();arguments=set()
    for provider in providers:
        name=provider['function']
        if name in names:raise ValueError('duplicate snapshot provider: '+name)
        names.add(name)
        kind=provider.get('binding_kind')
        if kind is None:
            if name.startswith('osrec_argument_'):raise ValueError('reserved argument binding requires metadata')
            continue
        if kind!='root_argument':raise ValueError('unsupported snapshot binding kind')
        index=provider.get('argument_index');argument=provider.get('argument');contract=provider.get('contract',{})
        if (type(index) is not int or not 0<=index<len(plan['arguments']) or
            plan['arguments'][index]!={'name':argument,'type':provider['return_type'],'pointer':True} or
            not isinstance(argument,str) or name!='osrec_argument_'+argument or argument in arguments or
            object_pointee(provider['return_type']) is None or
            contract.get('kind')!='object_argument' or contract.get('snapshot_safe') is not True or
            not contract.get('reason') or not contract.get('implementation')):
            raise ValueError('invalid root argument object binding')
        arguments.add(argument)
    const_roots={p['function'] for p in providers if p['return_type'].startswith('const ')}
    if any(path_provider(w['path']) in const_roots for w in plan.get('state_writes',[])):
        raise ValueError('const object bindings require a readonly footprint')
    return providers


def preservation_eligible(plan,write):
    """Preserve a scalar only through captured, syntactically unwritten edges.

    Runtime aliases of writable edges are checked by reconstruction against
    entry object IDs, as for all other nested scalar effects.
    """
    path=write['path'];typ=write['type']
    if (not re.fullmatch(r'[A-Za-z_]\w*\(\)(?:->[A-Za-z_]\w*(?:\[[0-9]+\])*)+',path) or
        write['pointer_edge'] or write['volatile'] or write['bitfield'] or write.get('storage_const') or
        '*' in typ or typ.startswith(('struct ','union '))):return False
    provider=next((p for p in plan['object_providers'] if p['function']==path_provider(path)),{})
    if any(provider.get('contract',{}).get(flag) is not True
           for flag in ('snapshot_safe','stable_identity','exclusive_state','preserves_entry_state')):return False
    parts=path.split('->')
    for end in range(2,len(parts)):
        prefix='->'.join(parts[:end])
        if any(w['path']==prefix for w in plan.get('state_writes',[])):return False
        if not any(r['path']==prefix and r['pointer_edge'] and not r['volatile'] and not r['bitfield']
                   and not r.get('storage_const') and object_pointee(r['type']) is not None
                   for r in plan['entry_reads']):return False
    return True


def entry_accesses(plan):
    """Snapshot reads plus checked incoming scalar state needed for preservation."""
    preserved=plan.get('preserved_entry_fields',[])
    if preserved:
        if plan.get('write_state_preservation',{}).get('format')!=PRESERVATION_FORMAT:
            raise ValueError('preserved entry fields require preservation analysis metadata')
        snapshot_providers(plan);seen=set()
        for row in preserved:
            path=row['path']
            if (path in seen or not preservation_eligible(plan,row) or
                not any(row=={**write,'entry_candidate':True,'preservation_reason':PRESERVATION_REASON}
                        for write in plan.get('state_writes',[]))):
                raise ValueError('invalid preserved entry field projection')
            seen.add(path)
    return [item for item in plan['entry_reads']+preserved if not fixed_global_read(item,plan)]


def capture_header(plans):
    """Generate only checked object-provider field paths, never pointer-byte copies."""
    from entry_state_constants import extent_assertions
    lines=['/* Generated construction-time snapshot hooks. Include after kernel declarations. */',
           '#include "osrec/entry_snapshot.h"']
    lines.extend(extent_assertions(plans))
    for plan in plans:
        root=plan['root'];fields={item['path']:item for item in entry_accesses(plan)}
        if plan['blockers']:raise ValueError(root+' has unresolved analysis blockers; cannot generate snapshot hook')
        providers={item['function']:item for item in snapshot_providers(plan)}
        selected=[]
        for path,item in fields.items():
            import re
            match=re.fullmatch(r'([A-Za-z_]\w*)\(\)((?:->[A-Za-z_]\w*(?:\[[0-9]+\])*)+)',path)
            if not match or match[1] not in providers or '[' in item['type'] or item['volatile'] or item['bitfield'] or item.get('storage_const') or '(' in item['type'] or item['type'].count('*')>1 or (not item['pointer_edge'] and re.match(r'(?:const )?(?:struct|union) ',item['type'])):
                raise ValueError('snapshot generation requires plain nonvolatile provider field paths: '+path)
            selected.append((match[1],match[2].split('->')[1:],item))
        parameters=''.join(', '+p['return_type']+' '+p['function'] for p in providers.values() if p.get('binding_kind')=='root_argument')
        lines.append('static inline int osrec_snapshot_'+root+'(struct osrec_entry_snapshot *snapshot'+parameters+') {')
        for index,name in enumerate(sorted(providers)):
            provider=providers[name]
            if provider['contract'].get('snapshot_safe') is not True:raise ValueError('object provider requires an explicit snapshot_safe contract: '+name)
            if '*' not in provider['return_type']:raise ValueError('object provider must return a pointer: '+name)
            variable='object_'+str(index);typename=object_pointee(provider['return_type'])
            if typename is None:raise ValueError('unsupported provider object pointer type: '+name)
            expression=name if provider.get('binding_kind')=='root_argument' else name+'()'
            lines += ['  __auto_type '+variable+' = '+expression+';',
                      '  if (!osrec_snapshot_bind(snapshot,'+json.dumps(name+'()')+','+variable+','+json.dumps(typename)+')) return 0;']
            emitted=set()
            for selected_name,parts,item in sorted(selected,key=lambda row:(len(row[1]),row[1])):
                if selected_name!=name:continue
                owner=variable+''.join('->'+part for part in parts[:-1])
                expression=owner+'->'+parts[-1]
                guard=' && '.join(variable+''.join('->'+part for part in parts[:i]) for i in range(len(parts)))
                if item['pointer_edge']:
                    target_type=object_pointee(item['type'])
                    if target_type is None:raise ValueError('unsupported pointer edge type: '+item['type'])
                    statement='osrec_snapshot_edge(snapshot,'+owner+','+json.dumps(parts[-1])+','+expression+','+json.dumps(target_type)+')'
                else:
                    statement='osrec_snapshot_scalar(snapshot,'+owner+','+json.dumps(parts[-1])+',&('+expression+'),sizeof('+expression+'))'
                if statement not in emitted:
                    lines.append('  if ('+guard+' && !'+statement+') return 0;');emitted.add(statement)
        lines+=['  return !snapshot->failed;','}']
    return '\n'.join(lines)+'\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compile-commands',required=True,type=Path)
    parser.add_argument('--source',required=True,type=Path)
    parser.add_argument('--root',required=True,action='append')
    parser.add_argument('--closure-source',type=Path,action='append',default=[],help='additional configured source containing callees')
    parser.add_argument('--all-sources',action='store_true',help='load all compilation database sources for direct-call closure')
    parser.add_argument('--max-translation-units',type=int,default=100)
    parser.add_argument('--max-range-elements',type=int,default=64)
    parser.add_argument('--max-alias-paths',type=int,default=DEFAULT_MAX_ALIAS_PATHS)
    parser.add_argument('--max-contexts',type=int,default=500,help='call contexts analyzed per root before an analysis_limit blocker')
    parser.add_argument('--prune-written-fields',dest='prune_written',action='store_true',help='omit proven dominated loads under stable/exclusive provider or argument-object contracts')
    parser.add_argument('--preserve-write-state',action='store_true',help='also retain eligible may-written scalar inputs unless overwritten on every analyzed exit; requires --prune-written-fields')
    parser.add_argument('--boundaries',type=Path)
    parser.add_argument('--linked-symbols',type=Path,help='symbol names defined in the final linked image (llvm-nm output); proves eliminated external calls')
    parser.add_argument('--clang',type=Path)
    parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--capture-header',type=Path)
    args=parser.parse_args()
    if args.max_alias_paths<1 or args.max_contexts<1:parser.error('--max-alias-paths and --max-contexts must be positive')
    if args.preserve_write_state and not args.prune_written:parser.error('--preserve-write-state requires --prune-written-fields')
    boundaries={};boundary_hash=None;argument_objects={};state_ranges=[];volatile_fields=[];contracts={}
    if args.boundaries:
        document=json.loads(args.boundaries.read_text())
        if document.get('format')!='osrec-entry-state-boundaries-v1':raise ValueError('unsupported boundary policy format')
        boundaries=document['boundaries'];boundary_hash=digest(args.boundaries.read_bytes())
        argument_objects=document.get('argument_objects',{});state_ranges=document.get('state_ranges',[]);volatile_fields=document.get('volatile_fields',[])
        contracts=dict(operand_free_asm=document.get('operand_free_asm'),volatile_accesses=document.get('volatile_accesses'),pointer_extents=document.get('pointer_extents',[]),callback_targets=document.get('callback_targets',[]),
            pointer_values=document.get('pointer_values',[]),pointer_identity=document.get('pointer_identity'),user_addresses=document.get('user_addresses',[]),
            fault_assertions=document.get('fault_assertions',[]),argument_ranges=document.get('argument_ranges',[]),allocations=document.get('allocations',[]),pointer_objects=document.get('pointer_objects',[]),deallocators=document.get('deallocators',[]),empty_lists=document.get('empty_lists',[]))
    program=None
    if args.closure_source or args.all_sources:
        from entry_state_program import load_program
        tree,program=load_program(args.compile_commands,args.source,args.clang,args.closure_source,args.all_sources,args.max_translation_units)
        identity=program['source_identities'][0]
    else:tree,identity=load_ast(args.compile_commands,args.source,args.clang)
    linked=None
    if args.linked_symbols:
        linked={line.split()[-1] for line in args.linked_symbols.read_text().splitlines() if line.split() and line.split()[-2:-1]!=['U']}
        if any(line.split()[-2:-1]==['U'] for line in args.linked_symbols.read_text().splitlines()):raise ValueError('linked image has undefined symbols; elimination is not proven')
    plans=[]
    for root in args.root:
        analyzer=Analyzer(tree,boundaries,max_contexts=args.max_contexts,max_range_elements=args.max_range_elements,prune_written=args.prune_written,argument_objects=argument_objects,preserve_write_state=args.preserve_write_state,max_alias_paths=args.max_alias_paths,state_ranges=state_ranges,linked_symbols=linked,volatile_fields=volatile_fields,**contracts)
        internal='tu0:'+root if program and 'tu0:'+root in analyzer.functions else root
        plan=analyzer.analyze(internal);plan['root']=root;plans.append(plan)
    report={'format':'osrec-entry-state-plan-v1','source_identity':identity,'boundary_policy_sha256':boundary_hash,
            'plans':plans,'snapshot_generation':'not_requested'}
    if program:
        report['program']={k:v for k,v in program.items() if k!='source_identities'};report['source_identities']=program['source_identities']
    header=None
    if args.capture_header:
        header=capture_header(plans);report['snapshot_generation']='generated'
        report['capture_header_sha256']=digest(header.encode())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    if header is not None:
        args.capture_header.parent.mkdir(parents=True,exist_ok=True);args.capture_header.write_text(header)
    print(json.dumps({'report':str(args.out),'roots':len(plans),'read_paths':sum(len(plan['entry_reads']) for plan in plans),
        'blockers':sum(len(plan['blockers']) for plan in plans),'snapshot_generation':report['snapshot_generation']},indent=2))

if __name__=='__main__':main()
