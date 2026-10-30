"""Portable integer expressions, enum constants and array counts for loop proofs."""
import re
from entry_state import children,type_of,object_pointee,SELECTIONS,selected_expression

TYPES=('int','unsigned int')
SIZE_TYPES=('unsigned int','unsigned long','unsigned long long')


def integer_constant(node,values,max_nodes=64):
    """Evaluate a pure portable 32-bit integer expression, or fail closed."""
    def fold(node,budget):
        budget[0]-=1
        typ=type_of(node);kind=node.get('kind');parts=children(node)
        if budget[0]<0 or typ not in TYPES:return None
        if kind in SELECTIONS:
            selected=selected_expression(node)
            value=fold(selected,budget) if selected is not None else None
        elif kind=='IntegerLiteral':value=int(node['value'])
        elif kind=='DeclRefExpr':value=values.get(node.get('referencedDecl',{}).get('id'),{}).get('value')
        elif kind in ('ParenExpr','ConstantExpr','ImplicitCastExpr') and len(parts)==1:
            if kind=='ImplicitCastExpr' and node.get('castKind')!='IntegralCast':return None
            value=fold(parts[0],budget)
            if kind=='ConstantExpr' and value is not None and str(value)!=node.get('value'):return None
        elif kind=='UnaryOperator' and node.get('opcode') in ('+','-','~') and len(parts)==1:
            value=fold(parts[0],budget)
            if value is not None and node['opcode']=='-':value=-value
            if node['opcode']=='~':
                if typ!='unsigned int' or value is None:return None
                value=value^0xffffffff
        elif kind=='BinaryOperator' and node.get('opcode') in ('+','-','*','/','%','<<','>>','&','|','^') and len(parts)==2:
            left=fold(parts[0],budget);right=fold(parts[1],budget)
            if left is None or right is None:return None
            op=node['opcode']
            if op=='+':value=left+right
            elif op=='-':value=left-right
            elif op=='*':value=left*right
            elif op in ('/','%'):
                # C99 division truncates toward zero; Python // rounds down.
                # Both / and % are undefined for the signed MIN/-1 pair.
                if right==0 or (left==-0x80000000 and right==-1):return None
                quotient=abs(left)//abs(right)
                if (left<0)!=(right<0):quotient=-quotient
                value=quotient if op=='/' else left-quotient*right
            elif op in ('<<','>>'):
                # Negative signed right shifts are implementation-defined;
                # negative left shifts and out-of-width counts are invalid.
                if left<0 or not 0<=right<32:return None
                value=left<<right if op=='<<' else left>>right
            else:
                # Exclude representation-dependent signed negative bitwise
                # operands. Unsigned complement above has fixed 32-bit width.
                if left<0 or right<0:return None
                value=left&right if op=='&' else left|right if op=='|' else left^right
        else:return None
        lower,upper=(-0x80000000,0x7fffffff) if typ=='int' else (0,0xffffffff)
        return value if value is not None and lower<=value<=upper else None
    return fold(node,[max_nodes])


def enum_values(declarations):
    values={}
    for declaration in declarations:
        previous=-1
        for item in children(declaration):
            if item.get('kind')!='EnumConstantDecl':continue
            parts=children(item)
            value=integer_constant(parts[0],values) if len(parts)==1 else previous+1 if not parts and previous is not None else None
            typ=type_of(item);lower,upper=(-0x80000000,0x7fffffff) if typ=='int' else (0,0xffffffff)
            if typ not in TYPES or value is None or not lower<=value<=upper:previous=None;continue
            previous=value
            values[item['id']]={'kind':'enum_constant','name':item['name'],'value':value,
                                'evaluation':'portable_nonwrapping_32bit_constant_expression'}
    return values


def constant_index(node,values):
    """Prove a fixed index or an unsigned mask/remainder with a pure bound.

    This adds no variable-value propagation. In the interval case the runtime
    operand keeps its effects, and only the constant operand is evaluated here.
    """
    value=integer_constant(node,values)
    if value is not None:
        bounds=[value,value];kind='integer_constant_expression';operand=node
    else:
        expression=parens(node);parts=children(expression);op=expression.get('opcode')
        if (expression.get('kind')!='BinaryOperator' or op not in ('%','&') or len(parts)!=2 or
            type_of(expression)!='unsigned int' or type_of(parts[0])!='unsigned int'):return None
        operand=parts[1];value=integer_constant(operand,values)
        if value is None or value<0 or (op=='%' and value==0):return None
        bounds=[0,value-1 if op=='%' else value];kind='unsigned_constant_remainder' if op=='%' else 'unsigned_constant_mask'
    return {'bounds':bounds,'proof':{'kind':kind,'constant_value':value,'constant_type':type_of(operand),
            'evaluation':'portable_nonwrapping_32bit_constant_expression','ast_node_limit':64}}


def wide_unsigned_index(node,values,max_nodes=64):
    """Bound a wide unsigned reduction without evaluating its runtime input.

    Only nonnegative constants fitting the minimum width of every conversion
    are admitted. This never folds a wrapping or narrowing wide constant, or
    assumes whether unsigned long has 32 or 64 bits on the configured target.
    """
    limits={'int':0x7fffffff,'unsigned int':0xffffffff,'long':0x7fffffff,
            'unsigned long':0xffffffff,'long long':0x7fffffffffffffff,
            'unsigned long long':0xffffffffffffffff}
    def small_constant(value,budget):
        budget-=1
        if budget<0:return None
        typ=type_of(value);kind=value.get('kind');parts=children(value)
        if typ in TYPES:
            result=integer_constant(value,values,max_nodes=budget+1)
            if result is not None and 0<=result<=0xffffffff:return result
        if kind=='ParenExpr' and len(parts)==1:return small_constant(parts[0],budget)
        if kind=='IntegerLiteral' and typ in limits:
            result=int(value['value'])
            return result if 0<=result<=min(limits[typ],0xffffffff) else None
        if kind=='ImplicitCastExpr' and value.get('castKind')=='IntegralCast' and typ in limits and len(parts)==1:
            result=small_constant(parts[0],budget)
            return result if result is not None and result<=limits[typ] else None
        return None
    expression=parens(node);parts=children(expression);op=expression.get('opcode');typ=type_of(expression)
    if (expression.get('kind')!='BinaryOperator' or op not in ('%','&') or len(parts)!=2 or
        typ not in ('unsigned long','unsigned long long') or any(type_of(p)!=typ for p in parts)):return None
    bound=small_constant(parts[1],max_nodes)
    if bound is None or op=='%' and bound==0:return None
    return dict(bounds=[0,bound-1 if op=='%' else bound],proof=dict(
        kind='wide_unsigned_constant_remainder' if op=='%' else 'wide_unsigned_constant_mask',
        unsigned_type=typ,constant_value=bound,constant_ast_node_limit=max_nodes,
        evaluation='nonnegative value-preserving constant conversions; runtime operand not evaluated'))


def parens(node):
    while node.get('kind')=='ParenExpr' and len(children(node))==1:node=children(node)[0]
    return node


def array_count(node):
    node=parens(node);parts=children(node)
    if node.get('kind')!='BinaryOperator' or node.get('opcode')!='/' or len(parts)!=2 or type_of(node) not in SIZE_TYPES:return None
    operands=[]
    for part in parts:
        part=parens(part)
        if part.get('kind')!='UnaryExprOrTypeTraitExpr' or part.get('name')!='sizeof' or len(children(part))!=1:return None
        operands.append(parens(children(part)[0]))
    array,element=operands;terms=children(element)
    if array.get('kind')!='MemberExpr' or element.get('kind')!='ArraySubscriptExpr' or len(terms)!=2:return None
    decay=parens(terms[0]);index=parens(terms[1])
    if decay.get('kind')!='ImplicitCastExpr' or decay.get('castKind')!='ArrayToPointerDecay' or len(children(decay))!=1:return None
    other=parens(children(decay)[0])
    if (other.get('kind')!='MemberExpr' or other.get('referencedMemberDecl')!=array.get('referencedMemberDecl') or
        type_of(other)!=type_of(array) or index.get('kind')!='IntegerLiteral' or index.get('value')!='0'):return None
    match=re.fullmatch(r'(int|unsigned int)\[([0-9]+)\]',type_of(array))
    if not match or type_of(element)!=match[1] or not 0<int(match[2])<=0x7fffffff:return None
    owner=type_of(children(array)[0]);pointer=owner if array.get('isArrow') else owner+' *'
    if object_pointee(pointer) is None:return None
    return {'kind':'inline_array_count','owner_pointer_type':pointer,'member':array['name'],
            'elements':int(match[2]),'value':int(match[2]),'evaluation':'sizeof_matching_array_over_first_element'}


def resolved_bound(node,constants):
    original=node
    node=parens(node)
    while node.get('kind')=='ImplicitCastExpr' and node.get('castKind')=='IntegralCast' and type_of(node) in TYPES and len(children(node))==1:
        node=parens(children(node)[0])
    evidence=constants.get(node.get('referencedDecl',{}).get('id')) if node.get('kind')=='DeclRefExpr' else array_count(node)
    if evidence is None:
        value=integer_constant(original,constants)
        if value is not None:
            evidence={'kind':'integer_constant_expression','value':value,
                      'evaluation':'portable_nonwrapping_32bit_constant_expression','ast_node_limit':64}
    return evidence if evidence is not None and 0<=evidence['value']<=0x7fffffff else None


def extent_assertions(plans):
    lines=set()
    for plan in plans:
        for region in plan.get('memory_ranges',[]):
            proof=region.get('index_proof',{}).get('constant_bounds',{})
            for evidence in [proof.get('initial',{}),*proof.get('guards',[])]:
                if evidence.get('kind')!='inline_array_count':continue
                pointer=evidence.get('owner_pointer_type','');member=evidence.get('member','');count=evidence.get('elements')
                if object_pointee(pointer) is None or not re.fullmatch(r'[A-Za-z_]\w*',member) or type(count) is not int or not 0<count<=0x7fffffff:
                    raise ValueError('invalid inline-array count proof')
                expression='(('+pointer+')0)->'+member
                lines.add('_Static_assert(__builtin_types_compatible_p(__typeof__('+expression+'),__typeof__(('+expression+')[0])['+str(count)+']),"loop array extent differs");')
    return sorted(lines)
