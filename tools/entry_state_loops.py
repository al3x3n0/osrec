"""Narrow counted-loop index proofs, independent of object/provider resolution."""
from entry_state import children,walk,type_of,array_pointer_lvalue

TYPES=('int','unsigned int')


def plain_integer(node):
    # Only value-preserving implicit 32-bit integer conversions are admitted
    # below; explicit/narrowing casts never become loop bounds.
    while node.get('kind')=='ParenExpr' or (node.get('kind')=='ImplicitCastExpr' and
        node.get('castKind') in ('LValueToRValue','IntegralCast') and type_of(node) in TYPES):
        if not children(node):return {}
        node=children(node)[0]
    return node


def literal(node):
    node=plain_integer(node)
    if node.get('kind')!='IntegerLiteral' or type_of(node) not in TYPES:return None
    value=int(node['value'])
    return value if 0<=value<=0x7fffffff else None


def conjuncts(node):
    node=plain_integer(node)
    if node.get('kind')=='BinaryOperator' and node.get('opcode')=='&&':
        left,right=children(node)
        return conjuncts(left)+conjuncts(right)
    return [node]


def capacity_guard(condition,key,constants):
    """Resolve an ascending counter's upper bound without changing old proofs."""
    from entry_state_constants import resolved_bound,SIZE_TYPES
    terms=children(condition);op=condition.get('opcode')
    if condition.get('kind')!='BinaryOperator' or len(terms)!=2 or op not in ('<','<=','>','>='):return None
    right=op in ('>','>=');counter_node,bound_node=(terms[1],terms[0]) if right else terms
    value=literal(bound_node);evidence=None
    if value is None:
        evidence=resolved_bound(bound_node,constants)
        if evidence is None:return None
        value=evidence['value']
    counter=plain_integer(counter_node)
    if (evidence is not None and evidence['kind']=='inline_array_count' and
        counter.get('kind')=='ImplicitCastExpr' and counter.get('castKind')=='IntegralCast' and
        type_of(counter) in SIZE_TYPES and len(children(counter))==1):
        counter=plain_integer(children(counter)[0])
    if counter.get('kind')!='DeclRefExpr' or counter.get('referencedDecl',{}).get('id')!=key:return None
    inclusive=op in ('<=','>=');limit=value+int(inclusive)
    # The counter's final ++ must remain representable, including for <=.
    if not 0<=limit<=0x7fffffff:return None
    normalization=None if op=='<' else {'operator':op,'counter_operand':'right' if right else 'left',
        'bound_value':value,'inclusive':inclusive,'exclusive_limit':limit}
    return limit,evidence,normalization


def affine_index(node,key,low,high):
    """Prove a single-counter affine expression without C integer wrapping.

    Correlation is retained as a*i+b, but every intermediate operation and
    implicit conversion must fit its actual int/u32 type. Explicit casts,
    unrelated variables and nonlinear products require a separate model.
    """
    remaining=64
    def bounds(a,b):return tuple(sorted((a*low+b,a*high+b)))
    def fits(interval,typ):
        lower,upper=(-0x80000000,0x7fffffff) if typ=='int' else (0,0xffffffff)
        return lower<=interval[0]<=interval[1]<=upper
    def visit(n):
        nonlocal remaining
        remaining-=1
        typ=type_of(n);kind=n.get('kind');parts=children(n)
        if remaining<0 or typ not in TYPES:return None
        if kind=='DeclRefExpr' and n.get('referencedDecl',{}).get('id')==key:
            result=(1,0,True,[],True)
        elif kind=='IntegerLiteral':result=(0,int(n['value']),False,[],False)
        elif kind=='ParenExpr' and len(parts)==1:return visit(parts[0])
        elif kind=='ImplicitCastExpr' and len(parts)==1 and n.get('castKind') in ('LValueToRValue','IntegralCast'):
            child=visit(parts[0])
            if child is None:return None
            a,b,used,steps,direct=child
            interval=bounds(a,b)
            if not fits(interval,typ):return None
            if n['castKind']=='IntegralCast':
                steps=steps+[{'operation':'implicit_conversion','type':typ,'bounds':list(interval)}];direct=False
            result=(a,b,used,steps,direct)
        elif kind=='UnaryOperator' and n.get('opcode') in ('+','-') and len(parts)==1:
            child=visit(parts[0])
            if child is None:return None
            a,b,used,steps,_=child
            if n['opcode']=='-':a,b=-a,-b
            result=(a,b,used,steps+[{'operation':'unary'+n['opcode'],'type':typ,'bounds':list(bounds(a,b))}],False)
        elif kind=='BinaryOperator' and n.get('opcode') in ('+','-','*') and len(parts)==2:
            left=visit(parts[0]);right=visit(parts[1])
            if left is None or right is None:return None
            a,b,used,steps,_=left;c,d,other,extra,_=right;op=n['opcode']
            if op=='+':a,b=a+c,b+d
            elif op=='-':a,b=a-c,b-d
            elif a==0:a,b=b*c,b*d
            elif c==0:a,b=a*d,b*d
            else:return None
            result=(a,b,used or other,steps+extra+[{'operation':op,'type':typ,'bounds':list(bounds(a,b))}],False)
        else:return None
        return result if fits(bounds(result[0],result[1]),typ) else None
    result=visit(node)
    if result is None or not result[2]:return None
    a,b,_,steps,direct=result
    return {'bounds':bounds(a,b),'direct':direct,'arithmetic':{'kind':'affine_32bit','coefficient':a,'offset':b,
            'bounds':list(bounds(a,b)),'steps':steps,'implicit_conversions':'value_preserving_only','ast_node_limit':64}}


def counted_loop(node,location,constants=None):
    from entry_state_constants import resolved_bound
    constants=constants or {}
    parts=children(node)
    if node.get('kind')!='ForStmt' or len(parts)!=5 or parts[1].get('kind'):return None
    init,_,condition,increment,body=parts
    declarations=children(init)
    if init.get('kind')!='DeclStmt' or len(declarations)!=1:return None
    declaration=declarations[0];values=children(declaration)
    if (declaration.get('kind')!='VarDecl' or type_of(declaration) not in TYPES or len(values)!=1 or
        declaration.get('storageClass') is not None):return None
    key=declaration['id'];low=literal(values[0]);initial=None
    if low is None:
        initial=resolved_bound(values[0],constants)
        if initial is not None:low=initial['value']
    guards=conjuncts(condition)
    limits=[];evidence=[];literals=0;comparisons=[]
    for guard in guards:
        resolved=capacity_guard(guard,key,constants)
        if resolved is None:continue
        limit,bound,comparison=resolved;limits.append(limit)
        if bound is None:literals+=1
        else:evidence.append(bound)
        if comparison is not None:comparisons.append(comparison)
    if not limits:return None
    limit=min(limits);any_start=False
    runtime_start=any(n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('kind') in ('VarDecl','ParmVarDecl') for n in walk(values[0]))
    if low is None and type_of(declaration)=='unsigned int' and runtime_start:
        # A start read from a variable: any start of an unsigned counter is >= 0, a start at or above
        # the limit runs no iteration, and below a limit of at most 2^31 the increment cannot wrap.
        # Constant starts keep the constant rules (wrapped or narrowed constants stay rejected).
        low=0;any_start=True
    if low is None or not low<limit:return None
    increment=plain_integer(increment);targets=children(increment)
    if increment.get('kind')!='UnaryOperator' or increment.get('opcode')!='++' or len(targets)!=1:return None
    target=plain_integer(targets[0])
    if target.get('kind')!='DeclRefExpr' or target.get('referencedDecl',{}).get('id')!=key:return None
    # Every conjunction must be true at body entry. A later conjunct must not
    # mutate the counter after the capacity guard succeeds (nor leak its address
    # for a later condition/body call). Scan the entire condition and body.
    for statement in [*walk(condition),*walk(body)]:
        kind=statement.get('kind');op=statement.get('opcode');operands=children(statement)
        # Labels/cases could admit entry bypassing the initializer or guard.
        if kind in ('LabelStmt','CaseStmt','DefaultStmt','GotoStmt','IndirectGotoStmt','GCCAsmStmt','MSAsmStmt'):
            return None
        if not operands:continue
        if ((kind=='BinaryOperator' and op=='=') or kind=='CompoundAssignOperator' or
            (kind=='UnaryOperator' and op in ('++','--'))):
            dest=plain_integer(operands[0])
            if dest.get('kind')=='DeclRefExpr' and dest.get('referencedDecl',{}).get('id')==key:return None
        if kind=='UnaryOperator' and op=='&':
            if any(n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('id')==key for n in walk(operands[0])):
                return None
    proof={'kind':'canonical_for_induction','variable':declaration['name'],'initial':low,'exclusive_limit':limit,
           'step':1,'body_index_immutable':True,'loop':location(node)}
    if any_start:proof['initial']={'kind':'unsigned_counter_any_start','minimum':0}
    if initial is not None or evidence:
        proof['constant_bounds']={'initial':initial or {},'guards':evidence}
    if comparisons:proof['comparison_guards']=comparisons
    if len(guards)>1:
        proof['condition']={'kind':'conjunction','terms':len(guards),'literal_guards':literals,
                            'counter_immutable':True,'zero_trip_possible':True}
        if evidence:proof['condition']['constant_guards']=len(evidence)
    sites={}
    for statement in walk(body):
        statement=array_pointer_lvalue(statement)
        if statement.get('kind')!='ArraySubscriptExpr' or len(children(statement))!=2:continue
        certified=affine_index(children(statement)[1],key,low,limit-1)
        if certified is not None:
            site_proof=proof if certified['direct'] else {**proof,'arithmetic':certified['arithmetic']}
            sites[statement['id']]={'bounds':certified['bounds'],'proof':site_proof}
    return sites


def fixed_cursor_loop(node,location,max_iterations=16,max_cursors=4,constants=None):
    """Certify literal or capacity-guarded loops with fixed cursor steps.

    A literal guard establishes an exact sequence. Additional direct scalar
    guards instead retain every possible prefix, including zero iterations.
    Bodies have no branches, early exits, nested scopes or counter escapes.
    """
    from entry_state import effect_walk,unwrap,arithmetic_scalar
    from entry_state_constants import resolved_bound
    constants=constants or {}
    def constant(node):
        value=literal(node)
        if value is not None:return value,None
        evidence=resolved_bound(node,constants)
        # sizeof-based extents need capture-side layout assertions separately.
        if evidence is None or evidence['kind']=='inline_array_count':return None,None
        return evidence['value'],evidence
    parts=children(node)
    if node.get('kind')!='ForStmt' or len(parts)!=5 or parts[1].get('kind'):return None
    init,_,condition,increment,body=parts;declarations=children(init)
    if init.get('kind')!='DeclStmt' or len(declarations)!=1:return None
    declaration=declarations[0];values=children(declaration)
    if declaration.get('kind')!='VarDecl' or type_of(declaration) not in TYPES or declaration.get('storageClass') is not None or len(values)!=1:return None
    key=declaration['id'];low,initial=constant(values[0]);guards=conjuncts(condition);limits=[];dynamic=[];bounds=[];literals=0
    if not 0<len(guards)<=4:return None
    for guard in guards:
        terms=children(guard)
        if guard.get('kind')!='BinaryOperator' or guard.get('opcode')!='<' or len(terms)!=2:return None
        counter=plain_integer(terms[0])
        if counter.get('kind')!='DeclRefExpr' or counter.get('referencedDecl',{}).get('id')!=key:return None
        limit,evidence=constant(terms[1])
        if limit is not None:
            limits.append(limit)
            if evidence is None:literals+=1
            else:bounds.append(evidence)
            continue
        bound=terms[1]
        while (bound.get('kind')=='ParenExpr' or bound.get('kind')=='ImplicitCastExpr' and bound.get('castKind') in ('LValueToRValue','IntegralCast')) and len(children(bound))==1 and arithmetic_scalar(type_of(bound)) and arithmetic_scalar(type_of(children(bound)[0])):
            bound=children(bound)[0]
        reference=bound.get('referencedDecl',{})
        if bound.get('kind')!='DeclRefExpr' or not arithmetic_scalar(type_of(bound)) or reference.get('id')==key:return None
        dynamic.append(dict(variable=reference['name'],type=type_of(bound),location=location(bound)))
    if not limits:return None
    limit=min(limits)
    if low is None or limit is None or not 0<limit-low<=max_iterations:return None
    targets=children(increment)
    if increment.get('kind')!='UnaryOperator' or increment.get('opcode')!='++' or len(targets)!=1:return None
    if plain_integer(targets[0]).get('referencedDecl',{}).get('id')!=key:return None
    updates=[]
    for statement in effect_walk(body):
        kind=statement.get('kind');op=statement.get('opcode');operands=children(statement)
        if (statement is not body and kind=='CompoundStmt' or kind in ('IfStmt','ForStmt','WhileStmt','DoStmt','SwitchStmt',
            'BreakStmt','ContinueStmt','ReturnStmt','LabelStmt','CaseStmt','DefaultStmt','GotoStmt','IndirectGotoStmt','GCCAsmStmt','MSAsmStmt','StmtExpr')):return None
        if not operands:continue
        target=unwrap(operands[0]);target_key=target.get('referencedDecl',{}).get('id')
        mutation=(kind=='BinaryOperator' and op=='=' or kind=='CompoundAssignOperator' or kind=='UnaryOperator' and op in ('++','--'))
        if mutation and target.get('kind')=='DeclRefExpr':
            if target_key==key:return None
            if '*' in type_of(target):
                if kind=='UnaryOperator' and op in ('++','--'):stride=1 if op=='++' else -1
                elif kind=='CompoundAssignOperator' and op in ('+=','-=') and len(operands)==2:
                    value,step_bound=constant(operands[1])
                    if value is None or value==0:return None
                    stride=value if op=='+=' else -value
                else:return None
                updates.append((statement,stride,target_key,step_bound if kind=='CompoundAssignOperator' else None))
        if kind=='UnaryOperator' and op=='&' and any(n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('id')==key for n in effect_walk(operands[0])):return None
    if not 0<len(updates)<=max_cursors or len({cursor for update,stride,cursor,step in updates})!=len(updates):return None
    statements=children(body) if body.get('kind')=='CompoundStmt' else [body]
    sites=[tuple(effect_walk(statement)) for statement in statements]
    domains=[]
    for update,stride,cursor,step in updates:
        update_nodes={id(n) for n in effect_walk(update)}
        position=next(i for i,terms in enumerate(sites) if any(n is update for n in terms))
        bindings={}
        for i,terms in enumerate(sites):
            references=[n for n in terms if id(n) not in update_nodes and n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('id')==cursor]
            # No order is inferred between other reads of this cursor and its
            # update in the same expression. Other cursor variables are distinct;
            # their pointed arrays need not be disjoint.
            if i==position and references:return None
            for reference in references:bindings[id(reference)]=(reference,'before' if i<position else 'after')
        proof=dict(kind='fixed_count_cursor_for',loop=location(node),variable=declaration['name'],initial=low,
            exclusive_limit=limit,counter_step=1,iterations=limit-low,pointer_step=stride,max_iterations=max_iterations,
            counter_immutable_in_body=True,early_exits=False,all_iteration_versions_retained=True)
        if initial is not None or bounds or step is not None:
            proof['constant_bounds']=dict(initial=initial or {},guards=bounds,pointer_step=step or {})
        if dynamic:
            proof.pop('iterations')
            proof.update(kind='bounded_count_cursor_for',maximum_iterations=limit-low,minimum_iterations=0,
                zero_trip_possible=True,all_exit_prefixes_retained=True,dynamic_guards=dynamic,
                condition=dict(kind='conjunction',terms=len(guards),literal_capacity_guards=literals,side_effect_free=True))
            if bounds:proof['condition']['constant_capacity_guards']=len(bounds)
        if len(updates)>1:proof.update(cursor_count=len(updates),max_cursors=max_cursors,distinct_cursor_variables=True)
        domains.append(dict(update=update,bindings=bindings,proof=proof))
    return dict(body=body,updates=domains)
