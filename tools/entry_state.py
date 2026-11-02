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
        if (not isinstance(item,dict) or set(item)-{'record','field','min','max','reason','validated_by'} or
            not re.fullmatch(r'struct [A-Za-z_]\w*',str(item.get('record',''))) or not re.fullmatch(r'[A-Za-z_]\w*',str(item.get('field',''))) or
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


class Analyzer:
    def __init__(self,tree,boundaries=None,max_contexts=500,max_range_elements=64,prune_written=False,argument_objects=None,preserve_write_state=False,max_alias_paths=DEFAULT_MAX_ALIAS_PATHS,cache_alias_syntax=True,state_ranges=None,linked_symbols=None,volatile_fields=None,operand_free_asm=None,volatile_accesses=None,pointer_extents=None,callback_targets=None):
        if preserve_write_state and not prune_written:raise ValueError('write-state preservation requires prune_written')
        if type(max_alias_paths) is not int or max_alias_paths<1:raise ValueError('max_alias_paths must be a positive integer')
        self.max_alias_paths=max_alias_paths;self.alias_path_limit_observed=False
        self.cache_alias_syntax=cache_alias_syntax
        self._effect_nodes_cache={};self._alias_program_cache={};self._return_program_cache={}
        self._expression_nodes_cache={};self._direct_calls_cache={};self._parameters_cache={}
        self._static_index_cache={};self._array_lvalue_cache={}
        self._bounded_pointer_keys={};self._bounded_pointers={};self._pointer_access_constants={};self._pointer_access_types={};self._pointer_scope_cache={};self._definite_pointer_cache={};self._pointer_initialization_environments={};self.pointer_initializations=[];self.pointer_returns=[];self.index_values=[];self._local_index_definitions={};self._local_index_cache={};self._local_index_inputs={};self._local_index_declarations={}
        self._diagnostic_keys=set();self._diagnostic_nodes={}
        from entry_state_values import Values
        self._scalar_objects={};self._scalar_fields={};self.trap_proofs=[];self.tagged_pointer_proofs=[];self.ordering_asm_proofs=[];self.extent_assumptions=[];self.infeasible_accesses=[]
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
        self._auto_objects={};self._auto_info={};self._auto_store={};self._auto_reads={};self._auto_late=False;self._auto_storage=None;self._auto_sites={};self._call_nodes=[]
        self.volatile_fields={}
        for item in volatile_fields or []:
            if set(item)!={'record','field','reason','validated_by'} or not all(isinstance(item[k],str) and item[k] for k in item):raise ValueError('volatile field classification requires record, field, reason and validated_by')
            self.volatile_fields[(item['record'],item['field'])]=dict(item)
        self.null_guard_proofs=[];self.masked_pointer_proofs=[];self.external_accesses=[]
        self.state_ranges=validate_state_ranges(state_ranges or []);self.values=Values(self)
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
        self._local_volatile_storage={};self.local_volatile_proofs=[]
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
        from entry_state_const_graph import ConstGraph
        self.const_graph=ConstGraph(self);self.container_proofs=[]
        self._constant_record_groups={name:nodes for name,nodes in global_declarations.items() if any(
            type_of(n).startswith('const ') and not arithmetic_scalar(type_of(n)) and not numeric_array(type_of(n)) and n.get('init') for n in nodes)}
        self._constant_records={};self._constant_record_index=None;self._constant_record_shapes={}
        self.automatic_scalars={n['id']:n for n in walk(tree) if n.get('kind')=='VarDecl' and
            n['id'] not in self.globals and n.get('storageClass') is None and not n.get('tls') and
            arithmetic_scalar(type_of(n)) and not re.search(r'\bconst\b',type_of(n)) and
            not any(c.get('kind')=='CleanupAttr' for c in children(n))}
        self.automatic_arrays={n['id']:n for n in walk(tree) if n.get('kind')=='VarDecl' and
            n['id'] not in self.globals and n.get('storageClass') is None and not n.get('tls') and
            fixed_array(type_of(n)) and
            not re.search(r'\bvolatile\b|_Atomic',type_of(n)) and
            not any(c.get('kind')=='CleanupAttr' for c in children(n))}
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
        result.pointer_updates=[];result.container_proofs=[]
        for name in ('reads','writes','calls','blockers','arguments','ranges'):setattr(result,name,[])
        result.contexts=0;result.providers={};result.loop_index_sites={};result.alias_path_limit_observed=False
        result._effect_nodes_cache={};result._alias_program_cache={};result._return_program_cache={}
        result._expression_nodes_cache={};result._direct_calls_cache={};result._parameters_cache={}
        result._static_index_cache={};result._array_lvalue_cache={}
        result._bounded_pointer_keys={};result._bounded_pointers={};result._pointer_access_constants={};result._pointer_access_types={};result._pointer_scope_cache={};result._definite_pointer_cache={};result._pointer_initialization_environments={};result.pointer_initializations=[];result.pointer_returns=[];result.index_values=[];result._local_index_definitions={};result._local_index_cache={};result._local_index_inputs={};result._local_index_declarations={}
        result._diagnostic_keys=set();result._diagnostic_nodes={}
        from entry_state_values import Values
        result.callback_uses=[];result._auto_objects={};result._auto_info={};result._auto_store={};result._auto_reads={};result._auto_late=False;result._auto_storage=None;result._auto_sites={};result._call_nodes=[]
        result._scalar_objects={};result._scalar_fields={};result.trap_proofs=[];result.tagged_pointer_proofs=[];result.ordering_asm_proofs=[];result.extent_assumptions=[];result.infeasible_accesses=[];result._context_calls={};result.null_guard_proofs=[];result.masked_pointer_proofs=[];result.external_accesses=[];result.values=Values(result)
        result._local_volatile_storage={};result.local_volatile_proofs=[]
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
        if contract is None or self.fields.get(member.get('referencedMemberDecl'),{}).get('isBitfield'):return None
        return contract

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
            if name in self.functions and any(n.get('id')==key for n in self.values.facts_for(name).order if n.get('kind')=='VarDecl'):
                owner=tuple(stack[:index]);break
        if owner is None:return None
        token=self._auto_objects.get((owner,key))
        if token is None:
            token='auto:%d'%len(self._auto_objects);self._auto_objects[(owner,key)]=token
            declaration=next(n for n in self.values.facts_for(owner[-1]).order if n.get('kind')=='VarDecl' and n.get('id')==key)
            self._auto_info[token]=dict(owner=owner,declaration=key,initialized=bool(children(declaration)))
        return token
    def escaped_record(self,node,stack):
        """An automatic record whose address is taken in its function: tracked through an auto origin."""
        if node.get('kind')!='DeclRefExpr':return None
        key=node.get('referencedDecl',{}).get('id')
        if key not in self.automatic_records or not stack or stack[-1] not in self.functions:return None
        if key not in self.values.facts_for(stack[-1]).escaped:return None
        return self.auto_origin(key,stack)
    @staticmethod
    def auto_key(path):
        # *(&field) is the field: a pointer to a member is spelled by that member's path.
        while path.startswith('*(') and path.endswith(')') and AUTO_PATH.fullmatch(path[2:-1]) and AUTO_PATH.fullmatch(path[2:-1])[2]:
            path=path[2:-1]
        match=AUTO_PATH.fullmatch(path)
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
    def owner_site(self,token,node,stack):
        """The node in the owning function through which this access happens (itself or a call site)."""
        owner=self._auto_info[token]['owner']
        if len(stack)<=len(owner) or len(self._call_nodes)<len(owner):return node
        return self._call_nodes[len(owner)-1]
    def auto_write(self,token,field,paths,node=None,stack=None):
        key=(token,field)
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
        if not values:return {'unresolved:auto-field'}
        info=self._auto_info[token]
        if not info.get('initialized') and node is not None:
            # Without an initializer the field is indeterminate unless a write dominates this read.
            site=self.owner_site(token,node,stack);facts=self.values.facts_for(info['owner'][-1])
            if not any(facts.dominates(write,site) for write in self._auto_sites.get(key,())):return set(values)|{'unresolved:indeterminate'}
        return set(values)
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
            local[key]=self.bounded_aliases(local.get(key,set())|self.resolve(expression,local,stack+[name]),statement,stack+[name])
        return local

    def issue(self,kind,node,stack,detail):
        # AST nodes and call paths are immutable during a root analysis. Avoid
        # allocating the same diagnostic in every alias-fixpoint iteration;
        # analyze() still deduplicates equal locations from distinct AST nodes.
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
        if count is None or count<=0 or (self.numeric_element_type(element,base.get('_translation_unit')) is None and not object_pointer_element(element) and record_type_key(element) is None):return None
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
        if not re.fullmatch(storage,origin['path']) or any(identity(o)!=identity(origin) or not 0<=o['offset']<=o['extent'] for o in all_origins):return None
        owner=origin['owner']
        if owner:
            if tuple(stack[:len(owner)])!=owner:return None
            if tuple(stack)==owner:
                scope=self.pointer_scopes(stack[-1]).get(node.get('id'))
                if scope is None or scope[:len(origin['scope'])]!=origin['scope']:return None
        offsets=[sorted({o['offset'] for o in side}) for side in origins]
        return origin,offsets

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
            automatic_storage=bool(origin['owner']),owner_call_path=list(origin['owner']),one_past_allowed=True))
        return True

    def bounded_pointer_return(self,paths,node,stack):
        """Internal returns transport stable array values, not new lifetimes.

        A selected root still needs a result-binding model. Automatic arrays,
        including borrowed caller storage, retain the existing escape blocker.
        Never accept just the known subset of a mixed may-alias return value.
        """
        if len(stack)<2 or not paths or any(p not in self._bounded_pointers for p in paths):return False
        origins=[self._bounded_pointers[p] for p in paths]
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
        if ordinary and (bounds is None or tuple(bounds)!=(0,0) or any(re.search(r'(?:^|\*\()(?:null(?=$|->|[.\[\)])|unresolved:)',p) for p in ordinary)):
            self.issue('unresolved_pointer_origin',node,stack,'bounded pointer also has an unproven origin');return set()
        paths=[p for p in paths if p in self._bounded_pointers]
        if bounds is None:
            self.issue('dynamic_extent',node,stack,'pointer subscript index bounds are not proven');return set()
        low,high=bounds;origins=[self._bounded_pointers[p] for p in paths]
        if any(o['offset']+low<0 or o['offset']+high>=o['extent'] for o in origins):
            self.issue('array_bounds',node,stack,'pointer dereference reaches outside its array elements');return set()
        if high-low+1>self.max_range_elements:
            self.issue('range_limit',node,stack,'pointer access interval exceeds the configured element limit');return set()
        result=set()
        for origin in origins:
            if origin['owner'] and tuple(stack[:len(origin['owner'])])!=origin['owner']:
                self.issue('pointer_arithmetic',node,stack,'automatic array pointer is outside its owning call lifetime');return set()
            for offset in range(origin['offset']+low,origin['offset']+high+1):
                path=origin['path'] if origin.get('storage_kind')=='automatic_scalar' else origin['path']+'['+str(offset)+']'
                result.add(path)
                self._pointer_access_types[id(node),path]=origin['element_type']
                if origin['immutable_global'] is not None:self._pointer_access_constants[id(node),path]=origin['immutable_global']
            self.ranges.append(dict(paths=[origin['path']],elements=origin['extent'],index_bounds=[origin['offset']+low,origin['offset']+high],
                selection='proven bounded pointer interval',element_type=origin['element_type'],access_form='bounded_pointer',
                bound_source='configured numeric array with propagated element offset',function=stack[-1],call_path=stack,location=self.location(node),
                pointer_provenance=dict(kind='object_relative_array_pointer',storage=origin['path'],extent=origin['extent'],element_offset=origin['offset'],automatic_lifetime_owner=list(origin['owner']))))
            if origin.get('storage_kind')=='automatic_scalar':
                self.ranges[-1]['bound_source']='configured automatic numeric scalar treated as one element'
                self.ranges[-1]['pointer_provenance']['storage_kind']='automatic_scalar'
            if proof is not None:self.ranges[-1]['index_proof']=proof
            if origin['array_type_evidence'] is not None:self.ranges[-1]['array_type_evidence']=origin['array_type_evidence']
            # The element limit applies to each array; the alias limit bounds how many arrays.
            if len({p for p in result if p==origin['path'] or p.startswith(origin['path']+'[')})>self.max_range_elements:
                self.issue('range_limit',node,stack,'pointer access selection exceeds the configured element limit');return set()
        return result|{'*('+p+')' for p in ordinary}

    def access(self,paths,node,stack,write=False):
        if not paths:
            self.issue('unresolved_memory',node,stack,'memory address could not be resolved to an object path');return
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
            # Dereferences wrap origins in *(...), so checking only the first
            # characters can accidentally admit an unresolved alias. Match
            # origin positions, not legitimate fields/globals named "null".
            if re.search(r'(?:^|\*\()(?:null(?=$|->|[.\[\)])|unresolved:)',path):
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
                    seeds.append(('mutation',declaration,'unresolved:pointer-mutation',statement))
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
            recovered=self.tagged_recovery(original,env,stack)
            if recovered is not None:return recovered
            masked=self.masked_pointer(original,stack)
            if masked is not None:
                self.masked_pointer_proofs.append(dict(kind='index_mask_pointer',function=stack[-1],call_path=stack,location=self.location(original),
                    mask_function=masked['mask_function'],mask_type=masked['mask_type'],values='the masked pointer operand or null'))
                return self.bounded_aliases(self.resolve(masked['pointer'],env,stack)|{'null'},original,stack)
            return {'unresolved:integer-address'}
        converted=(original.get('kind')=='CStyleCastExpr' or original.get('kind')=='ImplicitCastExpr' and
                   original.get('castKind') not in ('ArrayToPointerDecay','LValueToRValue','NoOp'))
        if converted and '*' in type_of(original) and children(original):
            values=self.resolve(children(original)[0],env,stack)
            if any(p in self._bounded_pointers for p in values) and qualifier_only_conversion(original,children(original)[0]):
                return values
            # A void * view keeps the object; offsets on it and casts back from it stay rejected.
            if values and all(p in self._bounded_pointers for p in values) and void_view(original):
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
            if key in env:
                values=env[key]
                if 'null' in values:
                    from entry_state_values import match_variable
                    if self.nonnull(node,match_variable(key),declaration.get('name'),stack):return values-{'null'} or {INFEASIBLE}
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
            if not array or not direct or not (base.get('kind')=='MemberExpr' or nested_array or global_array or automatic_array or compound_array):
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
                token=self.escaped_record(target,stack)
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
            return base if node['opcode']=='&' else {'*('+value+')' for value in base}
        if kind=='UnaryOperator' and node.get('opcode') in ('++','--') and '*' in type_of(node):
            update=self.pointer_update(node,env,stack)
            if update is not None and update['result_used']:
                return self.pointer_update_values(update,update['result_version'],env,stack,node)
            return {'unresolved:pointer-mutation'}
        if kind=='CallExpr':
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
                    local=self.inline_environment(name,node,inner[1:],env,stack)
                    _,returns=self.return_alias_program(self.functions[name])
                    for expression,statement in returns:
                        values=self.integer_values(expression,local,stack+[name]) if type_of(node) in POINTER_WIDTH_INTEGERS else self.resolve(expression,local,stack+[name])
                        result=self.bounded_aliases(result|values,statement,stack+[name])
            if not result and '*' in type_of(node):return {'unresolved:call'}
            return result
        if kind=='BinaryConditionalOperator':
            parts=binary_conditional_parts(node)
            if parts is None:
                self.issue('unsupported_construct',node,stack,'GNU conditional lacks a validated shared value')
                return {'unresolved:binary-conditional'} if '*' in type_of(node) else set()
            return set().union(*(self.resolve(c,env,stack) for c in parts))
        if kind=='ConditionalOperator':
            return set().union(*(self.resolve(c,env,stack) for c in inner[1:]))
        if pointer_arithmetic_detail(node):
            if self.pointer_difference(node,env,stack):return set()
            container=self.container_of(node,env,stack)
            if container is not None:return container
            pointers=self.offset_pointers(node,env,stack)
            if pointers is not None:return pointers
            self.issue('pointer_arithmetic',node,stack,pointer_arithmetic_detail(node))
            return set()
        return set()

    def pointer_aliases(self,body,env,stack):
        """Compute a bounded may-alias closure, retaining every possible origin."""
        seeds,assignments=self.alias_program(body)
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
        def settle():
            for _ in range(32):
                changed=False
                for key,expression in assignments:
                    if isinstance(key,tuple):
                        changed=self.assign_record(key[1],expression,env,stack) or changed;continue
                    paths=self.resolve(expression,env,stack) or {'unresolved:alias'}
                    previous=env.get(key,empty)
                    combined=self.bounded_aliases(previous|paths,expression,stack)
                    if combined!=previous:env[key]=combined;changed=True
                if not changed:return
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
        if storage is None:return False
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
        if detail and not self.pointer_difference(node,env,stack) and self.container_of(node,env,stack) is None and self.offset_pointers(node,env,stack) is None:self.issue('pointer_arithmetic',node,stack,detail)
        if kind=='InitListExpr' and any(p in self._bounded_pointers for c in inner if '*' in type_of(c) for p in self.resolve(c,env,stack)):
            self.issue('pointer_arithmetic',node,stack,'bounded pointer aggregate storage needs an escape and reconstruction model')
        if kind=='ReturnStmt' and inner and '*' in type_of(inner[0]):
            paths=self.resolve(inner[0],env,stack)
            if any(p in self._bounded_pointers for p in paths) and not self.bounded_pointer_return(paths,node,stack):
                self.issue('pointer_arithmetic',node,stack,'bounded pointer return needs a lifetime and result-binding model')
        if kind=='BinaryOperator' and node.get('opcode') in ('==','!=','<','>','<=','>='):
            if any(p in self._bounded_pointers for c in inner if '*' in type_of(c) for p in self.resolve(c,env,stack)) and not self.pointer_comparison(node,env,stack):
                self.issue('pointer_arithmetic',node,stack,'bounded pointer comparisons need an identity/value model')
        if kind=='ImplicitCastExpr' and node.get('castKind')=='LValueToRValue':
            original=unwrap(inner[0]);target=self.array_lvalue(original)
            if target.get('kind')=='DeclRefExpr' and target.get('referencedDecl',{}).get('id') not in self.globals:
                self.local_qualified_access(target,stack)
            if self.tracked_member(target,env,stack) is not None:pass # automatic record storage
            elif target.get('kind') in ('MemberExpr','UnaryOperator') and self.auto_storage(self.storage_paths(target,env,stack)):pass # stack object storage
            elif target.get('kind') in ('MemberExpr','ArraySubscriptExpr','CompoundLiteralExpr') or target.get('kind')=='UnaryOperator' and target.get('opcode')=='*' or target.get('kind')=='DeclRefExpr' and target.get('referencedDecl',{}).get('id') in self.globals:
                pointer_member=target.get('kind')=='MemberExpr' and '*' in type_of(target)
                self.access(self.storage_paths(target,env,stack) if pointer_member else self.resolve(target,env,stack),target,stack)
            if target is not original:
                self.visit(target,env,stack);return
        if kind=='UnaryExprOrTypeTraitExpr':return # sizeof/alignof do not evaluate ordinary operands
        if kind=='VarDecl' and inner and node.get('id') in self.automatic_records and stack and stack[-1] in self.functions and node['id'] in self.values.facts_for(stack[-1]).escaped:
            token=self.auto_origin(node['id'],stack);declaration=self.record_declaration(type_of(node))
            if token is not None and declaration is not None:
                initial=self.flat_initializer(declaration,inner[-1],env,stack)
                for field in [f[0] for f in self.flat_fields(declaration) if '*' in f[1] and '(' not in f[1]]:
                    self.auto_write(token,field,initial.get(field,{'unresolved:auto-field'}) if initial is not None else {'unresolved:auto-field'},node,stack)
        if kind=='VarDecl':
            if inner and node.get('storageClass') is None and not node.get('tls'):self.local_qualified_access(node,stack)
            for child in inner:self.visit(child,env,stack)
            # Numeric scalars carry no alias values; `size_t n=0` is not a null pointer.
            if inner and not arithmetic_scalar(type_of(node)):env[node['id']]=self.bounded_aliases(env.get(node['id'],set())|self.resolve(inner[-1],env,stack),node,stack)
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
            if kind=='CompoundAssignOperator' and '*' in type_of(left):
                self.issue('pointer_arithmetic',node,stack,'pointer mutation needs an offset/provenance model')
            self.visit(right,env,stack)
            storage=self.storage_paths(left,env,stack) if left.get('kind') in ('MemberExpr','UnaryOperator','DeclRefExpr') else set()
            if self.auto_storage(storage):
                declaration=self.record_declaration(type_of(left))
                if declaration is not None and kind=='BinaryOperator':
                    # Whole-object store: *p = (struct T){...} or s = (struct T){...}.
                    fields=[f[0] for f in self.flat_fields(declaration) if '*' in f[1] and '(' not in f[1]]
                    initial=self.flat_initializer(declaration,right,env,stack)
                    for path in storage:
                        token=re.match(r'^(?:\*\()*(auto:\d+)',path)[1]
                        for field in fields:self.auto_write(token,field,(initial or {}).get(field,{'unresolved:auto-field'}) if initial is not None else {'unresolved:auto-field'},node,stack)
                elif '*' in type_of(left):
                    values=self.resolve(right,env,stack) or {'unresolved:auto-field'}
                    for path in storage:
                        key=self.auto_key(path)
                        if key is not None:self.auto_write(key[0],key[1],values,node,stack)
                self.visit(left if left is not unwrap(inner[0]) else inner[0],env,stack);return
            tracked=self.tracked_member(left,env,stack)
            automatic_pointer=(left.get('kind')=='DeclRefExpr' and
                left.get('referencedDecl',{}).get('id') not in self.globals)
            if '*' in type_of(right) and not automatic_pointer and any(p in self._bounded_pointers for p in self.resolve(right,env,stack)):
                self.issue('pointer_arithmetic',node,stack,'bounded pointer store needs an escape and reconstruction model')
            if left.get('kind')=='DeclRefExpr' and left.get('referencedDecl',{}).get('id') not in self.globals:
                self.local_qualified_access(left,stack)
                key=left.get('referencedDecl',{}).get('id');env[key]=self.bounded_aliases(env.get(key,set())|self.resolve(right,env,stack),node,stack)
            elif tracked is not None:
                env[tracked]=self.bounded_aliases(env[tracked]|self.resolve(right,env,stack),node,stack)
            else:
                paths=self.storage_paths(left,env,stack) if left.get('kind')=='MemberExpr' and '*' in type_of(left) else self.resolve(left,env,stack)
                self.access(paths,left,stack,True)
                if kind=='CompoundAssignOperator':self.access(paths,left,stack)
            self.visit(left if left is not unwrap(inner[0]) else inner[0],env,stack);return
        if kind=='UnaryOperator' and node.get('opcode') in ('++','--'):
            original=unwrap(inner[0]);target=self.array_lvalue(original)
            if '*' in type_of(target):
                self.issue('pointer_arithmetic',node,stack,'pointer mutation needs an offset/provenance model')
            local_integer=(target.get('kind')=='DeclRefExpr' and arithmetic_scalar(type_of(target)) and
                           target.get('referencedDecl',{}).get('id') not in self.globals)
            if 'volatile' in type_of(target) and self.local_volatile_storage(target,stack):local_integer=True
            if not local_integer:
                paths=self.resolve(target,env,stack)
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
            for name in sorted(names):
                policy=self.boundary(name)
                if (name not in self.functions or policy) and (not policy or policy.get('kind') not in ('ordering_model','value_model')):
                    # Code without a body may store through any stack object it receives,
                    # except declared memory models, whose writes are listed.
                    for index,argument in enumerate(inner[1:]):
                        if policy and policy.get('kind')=='memory_model' and index not in policy.get('writes',[]):continue
                        for value in self.resolve(argument,env,stack) if '*' in type_of(argument) else ():
                            match=re.match(r'^(auto:\d+)$',value)
                            if match is None:continue
                            info=self._auto_info[match[1]];owner=info['owner']
                            declaration=next((n for n in self.values.facts_for(owner[-1]).order if n.get('id')==info['declaration']),None)
                            record=self.record_declaration(type_of(declaration)) if declaration is not None else None
                            for field in [f[0] for f in self.flat_fields(record) if '*' in f[1] and '(' not in f[1]]:
                                self.auto_write(match[1],field,{'unresolved:auto-escape'})
                self.calls.append({'caller':stack[-1],'callee':name,'call_path':stack,'location':self.location(node),'boundary':policy,
                    'resolution':'direct' if self.direct_call(node) else 'callback contract' if isinstance(names,frozenset) else 'finite local function-pointer targets'})
                if policy:
                    # An ordering model only names its lock object; it needs no extent or lifetime contract.
                    # Declared read/write arguments are checked below as accesses of their pointee.
                    declared=set(policy.get('reads',[]))|set(policy.get('writes',[]))
                    if policy['kind']!='ordering_model' and any(p in self._bounded_pointers for i,c in enumerate(inner[1:]) if '*' in type_of(c) and i not in declared for p in self.resolve(c,env,stack)):
                        self.issue('boundary_memory_effect',node,stack,'bounded pointer boundary arguments need an extent/lifetime contract')
                    if policy['kind']=='scalar_transcript' and any('*' in type_of(c) for c in inner[1:]):
                        self.issue('boundary_memory_effect',node,stack,'pointer arguments require an explicit memory-effect model')
                    # Declared argument effects: the boundary reads or writes the pointee of these arguments.
                    for write,indexes in ((False,policy.get('reads',[])),(True,policy.get('writes',[]))):
                        for index in indexes:
                            if index>=len(inner)-1 or '*' not in type_of(inner[1+index]):
                                self.issue('boundary_memory_effect',node,stack,'declared argument effect does not name a pointer argument');continue
                            argument=inner[1+index];pointee=re.sub(r'\s*\*\s*(?:const\s*)?$','',type_of(argument))
                            dereference={'kind':'UnaryOperator','opcode':'*','type':{'qualType':pointee},'valueCategory':'lvalue',
                                'range':node.get('range',{}),'inner':[argument],'id':(node.get('id') or '')+'#arg'+str(index)}
                            self.access(self.resolve(dereference,env,stack),dereference,stack,write)
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
                try:self.function(name,stack,bindings,records)
                finally:self._call_nodes.pop()
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
            env[parameter['id']]=self.bounded_aliases(env[parameter['id']],parameter,stack+[name])
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
        self.pointer_aliases(body,env,stack+[name])
        if not stack:self.root_aliases=dict(env)
        self.visit(body,env,stack+[name])

    def analyze(self,root):
        """Analyze a root; repeat while a stack-object field grew after it was read."""
        if root not in self.functions:raise ValueError('root has no available configured body: '+root)
        run=self;store={};sites={}
        for attempt in range(4):
            if attempt:
                run=self.fresh();run._auto_store={k:set(v) for k,v in store.items()};run._auto_sites={k:list(v) for k,v in sites.items()}
            report=run.analyze_once(root)
            if not run._auto_late:break
            store=run._auto_store;sites=run._auto_sites
        else:
            report['blockers'].append({'kind':'analysis_limit','function':root,'call_path':[root],'detail':'stack-object field values did not converge in 4 passes','location':{}})
            report['classification']='requires_review'
        if run is not self:self.__dict__.update(run.__dict__)
        return report

    def analyze_once(self,root):
        self.function(root,[])
        def unique(items):
            result=[];seen=set()
            for item in items:
                key=json.dumps(item,sort_keys=True)
                if key not in seen:seen.add(key);result.append(item)
            return result
        reads=unique(self.reads);writes=unique(self.writes);blockers=unique(self.blockers)
        report={'root':root,'classification':'requires_review' if blockers else 'candidate_with_models' if self.boundaries or self.argument_objects else 'candidate',
            'analysis_limits':{'max_alias_paths':self.max_alias_paths,'alias_path_limit_observed':self.alias_path_limit_observed},
            'analysis_kind':'conservative configured-AST may-access closure','minimality_proven':False,'completeness_proven':False,
            'arguments':self.arguments,'entry_reads':reads,'state_writes':writes,'call_sites':unique(self.calls),
            'object_providers':list(self.providers.values()),'memory_ranges':unique(self.ranges),'blockers':blockers,
            'policy':'retain may-reads including reads after writes; both branch arms and loop bodies; unknown effects block automatic export'}
        if self.pointer_initializations:report['pointer_initialization_proofs']=unique(self.pointer_initializations)
        if self.pointer_returns:report['pointer_return_proofs']=unique(self.pointer_returns)
        if self.pointer_differences:report['pointer_difference_proofs']=unique(self.pointer_differences)
        if self.pointer_comparisons:report['pointer_comparison_proofs']=unique(self.pointer_comparisons)
        if self.pointer_updates:report['pointer_update_proofs']=unique(self.pointer_updates)
        if self.container_proofs:report['container_proofs']=unique(self.container_proofs)
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
        used=unique([s for v in self.index_values for s in v['proof'].get('state_ranges',[])])
        assumptions=[dict(self.state_ranges[(s['record'],s['field'])]) for s in used]+self.extent_assumptions
        if assumptions:report['state_range_assumptions']=unique(assumptions)
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
    parser.add_argument('--prune-written-fields',dest='prune_written',action='store_true',help='omit proven dominated loads under stable/exclusive provider or argument-object contracts')
    parser.add_argument('--preserve-write-state',action='store_true',help='also retain eligible may-written scalar inputs unless overwritten on every analyzed exit; requires --prune-written-fields')
    parser.add_argument('--boundaries',type=Path)
    parser.add_argument('--linked-symbols',type=Path,help='symbol names defined in the final linked image (llvm-nm output); proves eliminated external calls')
    parser.add_argument('--clang',type=Path)
    parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--capture-header',type=Path)
    args=parser.parse_args()
    if args.max_alias_paths<1:parser.error('--max-alias-paths must be positive')
    if args.preserve_write_state and not args.prune_written:parser.error('--preserve-write-state requires --prune-written-fields')
    boundaries={};boundary_hash=None;argument_objects={};state_ranges=[];volatile_fields=[];contracts={}
    if args.boundaries:
        document=json.loads(args.boundaries.read_text())
        if document.get('format')!='osrec-entry-state-boundaries-v1':raise ValueError('unsupported boundary policy format')
        boundaries=document['boundaries'];boundary_hash=digest(args.boundaries.read_bytes())
        argument_objects=document.get('argument_objects',{});state_ranges=document.get('state_ranges',[]);volatile_fields=document.get('volatile_fields',[])
        contracts=dict(operand_free_asm=document.get('operand_free_asm'),volatile_accesses=document.get('volatile_accesses'),pointer_extents=document.get('pointer_extents',[]),callback_targets=document.get('callback_targets',[]))
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
        analyzer=Analyzer(tree,boundaries,max_range_elements=args.max_range_elements,prune_written=args.prune_written,argument_objects=argument_objects,preserve_write_state=args.preserve_write_state,max_alias_paths=args.max_alias_paths,state_ranges=state_ranges,linked_symbols=linked,volatile_fields=volatile_fields,**contracts)
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
