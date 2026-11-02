"""Path facts and integer intervals inside one configured C function context.

Facts are conditions known to hold at an AST node because a structured guard
dominates it: the taken arm of an `if`, `&&`, `||` or `?:`, or an earlier
sibling `if` whose arm always leaves the enclosing block. Loop conditions are
not facts here; induction variables keep the analyzer's loop certificates, and
pure constant expressions keep its portable constant folder. A fact is retained
only when no variable it mentions is assigned between the guard and the use
(loops between them widen that region to the whole block), the variables'
addresses are never taken, and no label or case can enter the region.
Memory reads inside a guard are never matched as the guarded quantity; they
only contribute their declared state range or type range, which hold at
every time point.

Intervals are evaluated with the widest LP64 range for unknown values and the
narrowest supported range when deciding that arithmetic or a conversion
cannot wrap. Calls with available bodies are evaluated from their return
expressions with argument intervals. Every interval is a may-value bound for
proofs; execution keeps the original expressions and effects.
"""
import re
from entry_state import children,walk,unwrap,type_of,callee

WIDE={'_Bool':(0,1),'char':(-0x80,0xff),'signed char':(-0x80,0x7f),'unsigned char':(0,0xff),
    'short':(-0x8000,0x7fff),'unsigned short':(0,0xffff),'int':(-0x80000000,0x7fffffff),'unsigned int':(0,0xffffffff),
    'long':(-0x8000000000000000,0x7fffffffffffffff),'unsigned long':(0,0xffffffffffffffff),
    'long long':(-0x8000000000000000,0x7fffffffffffffff),'unsigned long long':(0,0xffffffffffffffff)}
# Ranges every configured target provides (long may be 32 bits).
NARROW={**WIDE,'char':(0,0x7f),'long':(-0x80000000,0x7fffffff),'unsigned long':(0,0xffffffff)}
SPELLINGS={'short int':'short','signed short':'short','signed short int':'short','unsigned short int':'unsigned short',
    'signed':'int','signed int':'int','unsigned':'unsigned int','long int':'long','signed long':'long','signed long int':'long',
    'unsigned long int':'unsigned long','long long int':'long long','signed long long':'long long','signed long long int':'long long',
    'unsigned long long int':'unsigned long long','bool':'_Bool'}
LOOPS=('ForStmt','WhileStmt','DoStmt')
EXITS=('ReturnStmt','BreakStmt','ContinueStmt','GotoStmt')
ENTRIES=('LabelStmt','CaseStmt','DefaultStmt')
MUTATIONS={'=','+=','-=','*=','/=','%=','<<=','>>=','&=','|=','^='}
TRANSPARENT_CASTS=('LValueToRValue','NoOp','PointerToBoolean','IntegralToBoolean','BitCast','NullToPointer')
MAX_DEPTH=12;MAX_NODES=8192;SPAN_LIMIT=1<<20

class Unproven(Exception):
    """A value depends on volatile or possibly uninitialized automatic storage."""

def integer_type(typ):
    if not isinstance(typ,str):return None
    words=[w for w in typ.split() if w not in ('const','volatile')]
    name=' '.join(words);name=SPELLINGS.get(name,name)
    # An enumerated type's integer type is implementation-defined (int or unsigned int here):
    # evaluate it in a range that holds both.
    if len(words)==2 and words[0]=='enum':return 'long long'
    return name if name in WIDE else None

def parens(node):
    while node.get('kind')=='ParenExpr' and len(children(node))==1:node=children(node)[0]
    return node

def condition(node):
    """Strip value-preserving wrappers around a truth value, including __builtin_expect and !!x."""
    while True:
        node=parens(node);terms=children(node)
        if node.get('kind') in ('ImplicitCastExpr','CStyleCastExpr') and node.get('castKind') in TRANSPARENT_CASTS+('IntegralCast',) and len(terms)==1:
            node=terms[0];continue
        if node.get('kind')=='CallExpr' and callee(node)=='__builtin_expect' and len(terms)==3:node=terms[1];continue
        if node.get('kind')=='UnaryOperator' and node.get('opcode')=='!' and len(terms)==1:
            inner=parens(terms[0])
            if inner.get('kind')=='UnaryOperator' and inner.get('opcode')=='!' and len(children(inner))==1:node=children(inner)[0];continue
        return node

def is_null(node):
    node=parens(node)
    while node.get('kind') in ('ImplicitCastExpr','CStyleCastExpr') and node.get('castKind') in ('NullToPointer','BitCast','NoOp','IntegralCast') and len(children(node))==1:
        node=parens(children(node)[0])
    return node.get('kind')=='IntegerLiteral' and str(node.get('value'))=='0'

def declref(node):
    """The DeclRefExpr of a plain variable read, through value-preserving wrappers."""
    node=parens(node)
    while node.get('kind')=='ImplicitCastExpr' and node.get('castKind') in ('LValueToRValue','NoOp') and len(children(node))==1:
        node=parens(children(node)[0])
    if node.get('kind')!='DeclRefExpr':return None
    return node if node.get('referencedDecl',{}).get('kind') in ('VarDecl','ParmVarDecl') else None

def variable(node):
    found=declref(node);return found['referencedDecl'].get('id') if found is not None else None

def storage_owner(node):
    """The variable whose own storage an lvalue designates (x, x.f, x[i]), if any."""
    node=parens(node)
    while True:
        if node.get('kind') in ('ParenExpr','ImplicitCastExpr') and children(node) and node.get('castKind') in (None,'NoOp','LValueToRValue','ArrayToPointerDecay'):
            node=children(node)[0];continue
        if node.get('kind')=='MemberExpr' and not node.get('isArrow') and children(node):node=children(node)[0];continue
        if node.get('kind')=='ArraySubscriptExpr' and children(node):
            base=children(node)[0]
            if base.get('kind')=='ImplicitCastExpr' and base.get('castKind')=='ArrayToPointerDecay':node=children(base)[0];continue
            return None
        break
    return node.get('referencedDecl',{}).get('id') if node.get('kind')=='DeclRefExpr' else None

def member_of(node):
    """(variable id, field) for `x.field` read through value-preserving wrappers."""
    node=parens(node)
    while node.get('kind')=='ImplicitCastExpr' and node.get('castKind') in ('LValueToRValue','NoOp') and len(children(node))==1:node=parens(children(node)[0])
    if node.get('kind')!='MemberExpr' or node.get('isArrow') or not children(node):return None
    base=unwrap(children(node)[0])
    return (base.get('referencedDecl',{}).get('id'),node.get('name')) if base.get('kind')=='DeclRefExpr' else None

def member_shape(node):
    """(base variable, arrow?, field) for `v.f` or `v->f` reads, else None."""
    node=parens(node)
    while node.get('kind')=='ImplicitCastExpr' and node.get('castKind') in ('LValueToRValue','NoOp') and len(children(node))==1:node=parens(children(node)[0])
    if node.get('kind')!='MemberExpr' or not children(node):return None
    base=variable(children(node)[0]) if node.get('isArrow') else unwrap(children(node)[0]).get('referencedDecl',{}).get('id') if unwrap(children(node)[0]).get('kind')=='DeclRefExpr' else None
    return (base,bool(node.get('isArrow')),node.get('name')) if base is not None else None

def match_member_access(node):
    shape=member_shape(node)
    return (lambda other:shape is not None and member_shape(other)==shape)

def match_variable(key):
    return lambda node:variable(node)==key

def match_member(composite):
    key,field=composite.rsplit('.',1)
    return lambda node:member_of(node)==(key,field)

def widening(node):
    """Strip conversions that preserve every value on every configured target."""
    node=parens(node)
    while node.get('kind') in ('ImplicitCastExpr','CStyleCastExpr') and len(children(node))==1:
        cast=node.get('castKind');inner=parens(children(node)[0])
        if cast in ('LValueToRValue','NoOp'):node=inner;continue
        if cast=='IntegralCast':
            source=integer_type(type_of(inner));target=integer_type(type_of(node))
            if source and target and NARROW[target][0]<=WIDE[source][0] and WIDE[source][1]<=NARROW[target][1]:node=inner;continue
        break
    return node

PURE_OPERATORS=('+','-','*','/','%','&','|','^','<<','>>')

def canonical(node):
    """Hashable shape of a pure expression over variables and literals, else None."""
    node=widening(node);kind=node.get('kind');terms=children(node)
    if kind=='DeclRefExpr':
        declaration=node.get('referencedDecl',{})
        if 'volatile' in type_of(node):return None
        return ('var',declaration.get('id')) if declaration.get('kind') in ('VarDecl','ParmVarDecl') else None
    if kind=='IntegerLiteral':return ('int',str(node.get('value')),integer_type(type_of(node)))
    if kind=='BinaryOperator' and node.get('opcode') in PURE_OPERATORS and len(terms)==2:
        parts=[canonical(t) for t in terms]
        return None if None in parts else ('op',node['opcode'],integer_type(type_of(node)),*parts)
    if kind=='UnaryOperator' and node.get('opcode') in ('-','~') and len(terms)==1:
        part=canonical(terms[0]);return None if part is None else ('unary',node['opcode'],integer_type(type_of(node)),part)
    return None

class FunctionFacts:
    """Immutable per-body indexes: parents, preorder spans, mutations and escapes."""
    def __init__(self,function):
        self.function=function;self.gotos={};self._facts={};self.parent={};self.effects=[];self.span={};self.order=[];self.mutations={};self.escaped=set();self.has_labels=False
        def index(node,parent):
            start=len(self.order);self.order.append(node)
            if parent is not None:self.parent[id(node)]=parent
            for child in children(node):index(child,node)
            self.span[id(node)]=(start,len(self.order)-1)
        index(function,None)
        for node in self.order:
            kind=node.get('kind');terms=children(node);op=node.get('opcode')
            if kind in ENTRIES:self.has_labels=True
            if kind=='CallExpr' or terms and (kind=='BinaryOperator' and op=='=' or kind=='CompoundAssignOperator' or kind=='UnaryOperator' and op in ('++','--')):
                self.effects.append(self.span[id(node)][1])
            target=None
            if terms and (kind=='BinaryOperator' and op=='=' or kind=='CompoundAssignOperator' or kind=='UnaryOperator' and op in ('++','--')):
                # Field and element stores count as assignments to the owning variable.
                target=variable(terms[0]) or storage_owner(terms[0])
                if target is not None:self.mutations.setdefault(target,[]).append(self.span[id(node)][1])
            if kind=='UnaryOperator' and op=='&' and terms:
                base=parens(terms[0])
                while base.get('kind') in ('MemberExpr','ArraySubscriptExpr','ParenExpr','ImplicitCastExpr') and children(base) and not (base.get('kind')=='MemberExpr' and base.get('isArrow')):
                    base=children(base)[0]
                if base.get('kind')=='DeclRefExpr':self.escaped.add(base.get('referencedDecl',{}).get('id'))
            if kind=='VarDecl' and terms:self.mutations.setdefault(node['id'],[]).append(self.span[id(node)][1])
            if kind=='GotoStmt':self.gotos.setdefault(node.get('targetLabelDeclId'),[]).append(node)
    def contains(self,node):return id(node) in self.span
    def variables(self,node):
        return {n.get('referencedDecl',{}).get('id') for n in walk(node) if n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('kind') in ('VarDecl','ParmVarDecl')}
    def assigned(self,key,low,high):
        return any(low<=position<=high for position in self.mutations.get(key,()))
    def stable(self,node,low,high):
        """No variable of a guard is stored from the guard's start until the use (stores inside the guard included).

        A variable whose address escaped may change through that pointer, so its guard
        holds only when nothing between the guard and the use calls or stores at all.
        """
        if any(n.get('kind')=='DeclRefExpr' and 'volatile' in type_of(n) for n in walk(node)):return False
        keys=self.variables(node)
        if keys&self.escaped and any(low<=position<=high for position in self.effects):return False
        return not any(self.assigned(k,low,high) for k in keys)
    def stable_regions(self,node,regions):
        """`stable` over several position intervals."""
        if any(n.get('kind')=='DeclRefExpr' and 'volatile' in type_of(n) for n in walk(node)):return False
        keys=self.variables(node)
        for low,high in regions:
            if keys&self.escaped and any(low<=position<=high for position in self.effects):return False
            if any(self.assigned(k,low,high) for k in keys):return False
        return True
    def entered(self,node):
        """Can control enter this subtree other than through its start?"""
        for n in walk(node):
            if n.get('kind')=='LabelStmt':return True
        def scan(n):
            for c in children(n):
                if c.get('kind')=='SwitchStmt':continue
                if c.get('kind') in ('CaseStmt','DefaultStmt') or scan(c):return True
            return False
        return node.get('kind') in ('CaseStmt','DefaultStmt') or scan(node)
    @staticmethod
    def exits(statement):
        kind=statement.get('kind')
        if kind in EXITS:return True
        if kind=='CompoundStmt':
            terms=children(statement)
            return bool(terms) and FunctionFacts.exits(terms[-1]) and not any(n.get('kind') in ENTRIES for n in walk(statement))
        if kind=='IfStmt':
            terms=children(statement)
            return len(terms)==3 and FunctionFacts.exits(terms[1]) and FunctionFacts.exits(terms[2])
        return False
    def region_end(self,use,container,child):
        """Loops between the guard's block and the use widen the checked region to the block child."""
        node=use
        while node is not child:
            node=self.parent.get(id(node))
            if node is None:return self.span[id(child)][1]
            if node.get('kind') in LOOPS:return self.span[id(child)][1]
        # Stores are indexed at the end of their expression: one that contains
        # the use completes after it, so only earlier positions count.
        return self.span[id(use)][0]-1
    def facts(self,use):
        """(condition, truth, guard) triples that hold whenever `use` is evaluated."""
        if id(use) not in self._facts:self._facts[id(use)]=(use,self._collect(use))
        return self._facts[id(use)][1]
    def _collect(self,use):
        result=[];child=use;node=self.parent.get(id(use))
        while node is not None:
            kind=node.get('kind');terms=children(node)
            if kind=='IfStmt' and len(terms)>=2 and child is not terms[0] and not self.entered(child):
                cond=terms[0];low=self.span[id(cond)][0];high=self.region_end(use,node,child)
                if self.stable(cond,low,high):result.append((cond,child is terms[1],node))
            elif kind=='BinaryOperator' and node.get('opcode') in ('&&','||') and len(terms)==2 and child is terms[1]:
                low=self.span[id(terms[0])][0];high=self.region_end(use,node,child)
                if self.stable(terms[0],low,high):result.append((terms[0],node['opcode']=='&&',node))
            elif kind=='ConditionalOperator' and len(terms)==3 and child is not terms[0]:
                low=self.span[id(terms[0])][0];high=self.region_end(use,node,child)
                if self.stable(terms[0],low,high):result.append((terms[0],child is terms[1],node))
            elif kind=='CompoundStmt' and not self.entered(child):
                siblings=terms[:next(i for i,t in enumerate(terms) if t is child)]
                high=self.region_end(use,node,child)
                for statement in reversed(siblings):
                    # A label or case between a guard and the use lets control bypass the guard.
                    if statement.get('kind') in ENTRIES or self.entered(statement):break
                    if statement.get('kind')!='IfStmt':continue
                    parts=children(statement)
                    if len(parts)<2:continue
                    cond=parts[0];low=self.span[id(cond)][0]
                    then_exits=self.exits(parts[1]);else_exits=len(parts)==3 and self.exits(parts[2])
                    if then_exits==else_exits:continue
                    if self.stable(cond,low,high):result.append((cond,not then_exits,statement))
            elif kind=='ForStmt' and len(terms)==5 and terms[2].get('kind') and not terms[1].get('kind') and child in (terms[3],terms[4]) and not self.entered(node):
                # The condition held when this iteration began. Up to a use in the body, the
                # condition and the body before the use must not store its variables; up to a use
                # in the increment, the whole body (continue reaches the increment) must not either.
                cond,increment,body=terms[2],terms[3],terms[4]
                regions=[self.span[id(cond)]]
                if child is body:regions.append((self.span[id(body)][0],self.region_end(use,node,child)))
                else:regions+=[self.span[id(body)],(self.span[id(increment)][0],self.region_end(use,node,child))]
                if self.stable_regions(cond,regions):result.append((cond,True,node))
            elif kind in ('FunctionDecl',):break
            child=node;node=self.parent.get(id(node))
        return result
    def initialized(self,use,key):
        """A declaration initializer runs before every use in scope unless a jump skips it."""
        declaration=next((n for n in self.order if n.get('kind')=='VarDecl' and n.get('id')==key),None)
        if declaration is None or not children(declaration) or self.has_labels:return False
        low,high=self.span[id(declaration)]
        return not low<=self.span[id(use)][0]<=high
    def dominates(self,first,second):
        """Does `first` run, unconditionally, before every evaluation of `second`?

        Both must lie in this function. `first` must sit in a statement that precedes
        the statement holding `second` in a common block, reached from that statement
        without a branch, loop or short-circuit, and no label or case may enter between.
        """
        if not self.contains(first) or not self.contains(second) or self.has_labels:return False
        chain=[];node=second
        while node is not None:chain.append(node);node=self.parent.get(id(node))
        seen={id(n) for n in chain};node=first;top=None
        while node is not None and id(node) not in seen:
            parent=self.parent.get(id(node))
            if parent is None:return False
            if parent.get('kind')=='CompoundStmt':top=node
            elif parent.get('kind') in ('IfStmt','ForStmt','WhileStmt','DoStmt','SwitchStmt','ConditionalOperator','BinaryConditionalOperator') or parent.get('kind')=='BinaryOperator' and parent.get('opcode') in ('&&','||'):
                if top is None:return False
            node=parent
        if node is None or node.get('kind')!='CompoundStmt' or top is None:return False
        terms=children(node);index={id(t):i for i,t in enumerate(terms)}
        later=next((c for c in chain if id(c) in index),None)
        return later is not None and index[id(top)]<index[id(later)]
    def defined_before_use(self,key):
        """Does every read of `key` have a unique reaching assignment?"""
        if key in self.escaped:return False
        for node in self.order:
            if node.get('kind')!='DeclRefExpr' or node.get('referencedDecl',{}).get('id')!=key:continue
            child=node;parent=self.parent.get(id(node))
            while parent is not None and parent.get('kind')=='ParenExpr':child=parent;parent=self.parent.get(id(parent))
            if parent is not None and parent.get('kind')=='BinaryOperator' and parent.get('opcode')=='=' and children(parent)[0] is child:continue
            if self.reaching(node,key) is None and not self.loop_initialized(node,key):return False
        return True
    @staticmethod
    def defines(statement,key):
        """Does this statement always assign `key` (`key = v;`, `T key = v;`, possibly labelled)?"""
        while statement.get('kind')=='LabelStmt' and len(children(statement))==1:statement=children(statement)[0]
        plain=parens(statement)
        if plain.get('kind')=='BinaryOperator' and plain.get('opcode')=='=' and variable(children(plain)[0])==key:return True
        return statement.get('kind')=='DeclStmt' and any(d.get('id')==key and children(d) for d in children(statement))
    def dominated(self,use,key,visiting=frozenset()):
        """Is `key` assigned before `use` on every path, jumps included?

        Walks back through enclosing blocks. A label on the way is reached by falling
        through or by a goto, so each goto to it must itself follow an assignment (a goto
        reached again through the same label adds no new entry path). Case labels, and
        labels nested in a skipped statement, end the proof. A case label is reached from
        its switch, which must itself follow an assignment."""
        if key in self.escaped:return False
        child=use;node=self.parent.get(id(use))
        while node is not None and node.get('kind')!='FunctionDecl':
            kind=node.get('kind');terms=children(node)
            if kind in ('CaseStmt','DefaultStmt') and not self.switch_dominated(node,key,visiting):return False
            if kind=='LabelStmt' and not self.jumps_dominated(node,key,visiting):return False
            if kind=='ForStmt' and len(terms)==5 and child is not terms[0] and terms[0].get('kind') and self.defines(terms[0],key):return True
            if kind=='CompoundStmt':
                index=next(i for i,t in enumerate(terms) if t is child)
                for statement in reversed(terms[:index]):
                    if self.defines(statement,key):return True
                    inner=statement
                    while inner.get('kind')=='LabelStmt':
                        if not self.jumps_dominated(inner,key,visiting) or len(children(inner))!=1:return False
                        inner=children(inner)[0]
                    if inner.get('kind') in ('CaseStmt','DefaultStmt'):
                        if not self.switch_dominated(inner,key,visiting):return False
                        while inner.get('kind') in ('CaseStmt','DefaultStmt') and children(inner):inner=children(inner)[-1]
                    if self.entered(inner):return False
            child=node;node=self.parent.get(id(node))
        return False
    def switch_dominated(self,label,key,visiting):
        node=self.parent.get(id(label))
        while node is not None and node.get('kind')!='SwitchStmt':node=self.parent.get(id(node))
        return node is not None and self.dominated(node,key,visiting)
    def jumps_dominated(self,label,key,visiting):
        if id(label) in visiting:return True
        return all(self.dominated(jump,key,visiting|{id(label)}) for jump in self.gotos.get(label.get('declId'),()))
    def loop_initialized(self,use,key):
        """Is `use` inside a for loop (condition, increment or body) whose initializer assigns `key`?

        Control reaches the condition, increment and body only through the initializer,
        so every value of `key` there comes from an assignment, never the declaration."""
        if self.has_labels or key in self.escaped:return False
        child=use;node=self.parent.get(id(use))
        while node is not None and node.get('kind')!='FunctionDecl':
            terms=children(node)
            if node.get('kind')=='ForStmt' and len(terms)==5 and child is not terms[0] and terms[0].get('kind'):
                init=parens(terms[0])
                if init.get('kind')=='BinaryOperator' and init.get('opcode')=='=' and variable(children(init)[0])==key:return True
                if init.get('kind')=='DeclStmt' and any(d.get('id')==key and children(d) for d in children(init)):return True
            child=node;node=self.parent.get(id(node))
        return False
    def reaching(self,use,key):
        """The unique assignment or initializer of `key` that every path to `use` passes last."""
        if key in self.escaped:return None
        child=use;node=self.parent.get(id(use))
        while node is not None and node.get('kind')!='FunctionDecl':
            if node.get('kind')=='CompoundStmt' and not self.entered(child):
                terms=children(node);index=next(i for i,t in enumerate(terms) if t is child)
                high=self.region_end(use,node,child)
                for statement in reversed(terms[:index]):
                    labelled=statement
                    # `label: key = value;` defines key on every entry, including jumps to the label.
                    while labelled.get('kind')=='LabelStmt' and len(children(labelled))==1:labelled=children(labelled)[0]
                    if labelled is not statement and labelled.get('kind') not in ENTRIES and not self.entered(labelled):
                        plain=parens(labelled)
                        if plain.get('kind')=='BinaryOperator' and plain.get('opcode')=='=' and variable(children(plain)[0])==key and self.mutations.get(key,[]).count(self.span[id(plain)][1])==1 and not any(
                                p!=self.span[id(plain)][1] and self.span[id(plain)][0]<=p<=self.span[id(plain)][1] for p in self.mutations.get(key,())):
                            end=self.span[id(statement)][1]
                            return children(plain)[1] if not self.assigned(key,end+1,high) else None
                    if statement.get('kind') in ENTRIES or self.entered(statement):return None
                    value=None
                    plain=parens(statement)
                    if plain.get('kind')=='BinaryOperator' and plain.get('opcode')=='=' and variable(children(plain)[0])==key:value=children(plain)[1]
                    elif statement.get('kind')=='DeclStmt':
                        for declaration in children(statement):
                            if declaration.get('id')==key and declaration.get('kind')=='VarDecl' and children(declaration):value=children(declaration)[-1]
                    if value is not None:
                        end=self.span[id(statement)][1]
                        return value if not self.assigned(key,end+1,high) else None
                    if self.assigned(key,*self.span[id(statement)]):return None
                # Reached the block start without a definition: keep searching outward,
                # but the whole block up to the use must not assign the variable.
                if self.assigned(key,self.span[id(node)][0],high):return None
            elif node.get('kind') in LOOPS:
                # A definition before a loop does not reach a use inside it if the body assigns.
                if self.assigned(key,*self.span[id(node)]):return None
            child=node;node=self.parent.get(id(node))
        return None


def implies_nonnull(cond,truth,match):
    """Does `cond` having this truth value prove that the matched pointer is non-null?"""
    cond=condition(cond);kind=cond.get('kind');op=cond.get('opcode');terms=children(cond)
    if kind=='UnaryOperator' and op=='!' and len(terms)==1:return implies_nonnull(terms[0],not truth,match)
    if kind=='BinaryOperator' and op in ('&&','||') and len(terms)==2:
        if (op=='&&')==truth:return any(implies_nonnull(t,truth,match) for t in terms)
        return False
    if kind=='BinaryOperator' and op in ('==','!=') and len(terms)==2:
        for left,right in (terms,terms[::-1]):
            if match(left) and '*' in type_of(left) and is_null(right):return (op=='!=')==truth
        return False
    return truth and match(cond) and '*' in type_of(cond)

class ArgumentRanges:
    """Parameter intervals from one call site, evaluated on first use in the caller's context."""
    def __init__(self,values,call,caller,caller_ranges,function):
        self.values=values;self.caller=caller;self.caller_ranges=caller_ranges;self.cache={}
        parameters=[c for c in children(function) if c.get('kind')=='ParmVarDecl']
        self.parameters={p['id']:(p,a) for p,a in zip(parameters,children(call)[1:])}
    def __contains__(self,key):return self.get(key) is not None
    def __getitem__(self,key):return self.get(key)
    def get(self,key):
        if key not in self.parameters or self.caller not in self.values.analyzer.functions:return None
        if key not in self.cache:
            parameter,argument=self.parameters[key];self.cache[key]=None
            facts=self.values.facts_for(self.caller)
            if integer_type(type_of(parameter)) and facts.contains(argument) and self.values.proof is not None:
                value=self.values.value(argument,self.caller,facts,self.caller_ranges,1)
                if value is not None:self.cache[key]=self.values.fit(*value,parameter)
        return self.cache[key]


class Values:
    """Integer intervals for proofs in the analyzer's current call context."""
    def __init__(self,analyzer):
        self.analyzer=analyzer;self.proof=None;self.assumed={};self.active=set();self.pointer_env=[];self.call_stack=[]
    def facts_for(self,name):
        cache=self.analyzer._function_facts
        if name not in cache:cache[name]=FunctionFacts(self.analyzer.functions[name])
        return cache[name]
    def interval(self,node,name,parameters=None):
        """Return ((low, high), proof) or (None, None); spans beyond SPAN_LIMIT are not reported."""
        if name not in self.analyzer.functions:return None,None
        facts=self.facts_for(name)
        if not facts.contains(node):return None,None
        if not any(n.get('kind') in ('DeclRefExpr','MemberExpr','CallExpr') and n.get('referencedDecl',{}).get('kind')!='EnumConstantDecl' for n in walk(node)):
            return None,None
        self.proof=dict(kind='path_fact_interval',state_ranges=[],guards=[],definitions=[],calls=[],parameters=[]);self.budget=MAX_NODES
        try:result=self.value(node,name,facts,parameters or {},0)
        except (RecursionError,Unproven):return None,None
        if result is None or result[1]-result[0]+1>SPAN_LIMIT:return None,None
        proof=self.proof;proof['bounds']=list(result)
        for k in ('state_ranges','guards','definitions','calls','parameters'):
            unique=[];[unique.append(v) for v in proof[k] if v not in unique];proof[k]=unique
        return result,proof
    def note(self,kind,value):self.proof[kind].append(value)
    def value(self,node,name,facts,parameters,depth):
        self.budget-=1
        if self.budget<0 or depth>MAX_DEPTH:return self.wide(node)
        base=self.base(node,name,facts,parameters,depth)
        if base is None:return None
        return self.refine(node,base,name,facts,parameters,depth)
    def wide(self,node):
        t=integer_type(type_of(node));return WIDE[t] if t else None
    def fit(self,low,high,node):
        t=integer_type(type_of(node))
        if t is None:return None
        return (low,high) if NARROW[t][0]<=low and high<=NARROW[t][1] else WIDE[t]
    def base(self,node,name,facts,parameters,depth):
        kind=node.get('kind');terms=children(node);typ=integer_type(type_of(node))
        bounds,_=self.analyzer.static_index_bounds(node)
        if bounds is not None and typ:
            # A constant mask or remainder must not hide an indeterminate operand.
            for read in walk(node):
                declaration=read.get('referencedDecl',{}) if read.get('kind')=='DeclRefExpr' else {}
                if declaration.get('kind')=='VarDecl' and declaration.get('id') not in self.analyzer.globals:
                    key=declaration['id']
                    if 'volatile' in type_of(read) or key in facts.escaped or (facts.reaching(read,key) is None and not facts.initialized(read,key)):
                        raise Unproven('constant bound over an indeterminate automatic variable')
            return tuple(bounds)
        if kind in ('IntegerLiteral','CharacterLiteral'):
            try:value=int(node.get('value'))
            except (TypeError,ValueError):return self.wide(node)
            return (value,value)
        if kind=='ConstantExpr' and terms:return self.value(terms[0],name,facts,parameters,depth)
        if kind=='ParenExpr' and len(terms)==1:return self.value(terms[0],name,facts,parameters,depth)
        if kind in ('ImplicitCastExpr','CStyleCastExpr') and len(terms)==1:
            cast=node.get('castKind')
            if cast in ('LValueToRValue','NoOp'):return self.load(terms[0],name,facts,parameters,depth) if cast=='LValueToRValue' else self.value(terms[0],name,facts,parameters,depth)
            if cast in ('IntegralCast','IntegralToBoolean') and typ:
                inner=self.value(terms[0],name,facts,parameters,depth)
                if inner is None:return WIDE[typ]
                if cast=='IntegralToBoolean':return (0 if inner[0]<=0<=inner[1] else 1,0 if inner==(0,0) else 1)
                return self.fit(inner[0],inner[1],node)
            return self.wide(node)
        if typ is None:return None
        if kind=='UnaryOperator' and len(terms)==1:
            op=node.get('opcode')
            if op=='!':
                inner=self.value(terms[0],name,facts,parameters,depth) if integer_type(type_of(terms[0])) else None
                if inner is None:return (0,1)
                return (1,1) if inner==(0,0) else (0,0) if inner[0]>0 or inner[1]<0 else (0,1)
            inner=self.value(terms[0],name,facts,parameters,depth)
            if inner is None:return WIDE[typ]
            if op=='+':return self.fit(*inner,node)
            if op=='-':return self.fit(-inner[1],-inner[0],node)
            return WIDE[typ]
        if kind=='BinaryOperator' and len(terms)==2:return self.binary(node,name,facts,parameters,depth)
        if kind=='ConditionalOperator' and len(terms)==3:
            # A condition whose interval excludes zero (or is zero) selects one arm.
            test=self.value(terms[0],name,facts,parameters,depth) if integer_type(type_of(terms[0])) else None
            if test is not None and (test[0]>0 or test[1]<0):return self.value(terms[1],name,facts,parameters,depth)
            if test==(0,0):return self.value(terms[2],name,facts,parameters,depth)
            arms=[self.value(t,name,facts,parameters,depth) for t in terms[1:]]
            if any(a is None for a in arms):return WIDE[typ]
            return (min(a[0] for a in arms),max(a[1] for a in arms))
        if kind=='CallExpr':return self.call(node,name,facts,parameters,depth)
        return WIDE[typ]
    def load(self,target,name,facts,parameters,depth):
        target=parens(target);typ=integer_type(type_of(target))
        if typ is None:return None
        if target.get('kind')=='DeclRefExpr':
            declaration=target.get('referencedDecl',{});key=declaration.get('id')
            if declaration.get('kind') not in ('VarDecl','ParmVarDecl') or key in self.analyzer.globals:return WIDE[typ]
            if 'volatile' in type_of(target):raise Unproven('volatile')
            local=declaration.get('kind')=='VarDecl'
            if key in facts.escaped:
                if local:raise Unproven('escaped automatic variable')
                return WIDE[typ]
            if key in self.assumed:return self.assumed[key]
            definition=facts.reaching(target,key)
            if definition is not None:
                self.note('definitions',self.analyzer.location(definition))
                result=self.value(definition,name,facts,parameters,depth+1)
                if result is None:return WIDE[typ]
                return self.fit(*result,target)
            if declaration.get('kind')=='ParmVarDecl' and key not in facts.mutations and key in parameters:
                self.note('parameters',dict(function=name,parameter=declaration.get('name'),bounds=list(parameters[key])))
                return parameters[key]
            if local and not facts.initialized(target,key) and not facts.loop_initialized(target,key) and not facts.dominated(target,key):
                raise Unproven('automatic variable may be read before initialization')
            union=self.definitions(target,key,name,facts,parameters,depth)
            return self.fit(*union,target) if union is not None else WIDE[typ]
        if target.get('kind')=='MemberExpr' and children(target) and self.pointer_env:
            # A field of an automatic record, read through the pointer values of this context.
            stack=self.call_stack[-1] if self.call_stack else None
            if stack:
                paths=self.analyzer.storage_paths(target,self.pointer_env[-1],stack)
                found=[]
                for path in paths:
                    key=self.analyzer.auto_key(path) if re.match(r'^(?:\*\()*auto:\d+',path) else None
                    value=self.analyzer.auto_scalar_read(key[0],key[1],target,stack) if key else None
                    if value is None:found=None;break
                    found.append(value)
                if found:
                    self.note('definitions',dict(kind='automatic_record_field',field=target.get('name'),bounds=[min(v[0] for v in found),max(v[1] for v in found)]))
                    return self.fit(min(v[0] for v in found),max(v[1] for v in found),target) or WIDE[typ]
        if target.get('kind')=='MemberExpr' and children(target):
            contract=self.analyzer.state_range(target)
            if contract is not None:
                self.note('state_ranges',dict(record=contract['record'],field=contract['field'],bounds=[contract['min'],contract['max']]))
                return (contract['min'],contract['max'])
        return WIDE[typ]
    def definitions(self,target,key,name,facts,parameters,depth):
        """Every value an initialized local (or mutated parameter) can hold: the union over its assignments.

        Each assigned value is evaluated where it is assigned. Assignments that read the
        variable itself (`i++`, `i = i + 1`) must map the union of the others back into
        it, assuming it holds before them (an inductive interval); an update whose
        guards contradict that interval never runs."""
        declaration=target.get('referencedDecl',{})
        node=next((n for n in facts.order if n.get('id')==key and n.get('kind') in ('VarDecl','ParmVarDecl')),None)
        if node is None or key in self.active or node.get('storageClass') is not None or node.get('tls'):return None
        typ=integer_type(type_of(node))
        if typ is None:return None
        plain_values=[];updates=[]
        if declaration.get('kind')=='ParmVarDecl':
            if key not in parameters:return None
            plain_values.append(parameters[key])
        reads=lambda n:any(r.get('kind')=='DeclRefExpr' and r.get('referencedDecl',{}).get('id')==key for r in walk(n))
        for n in facts.order:
            kind=n.get('kind');terms=children(n);op=n.get('opcode')
            if kind=='VarDecl' and n.get('id')==key and terms:
                if reads(terms[-1]):return None
                plain_values.append(terms[-1])
            elif kind=='BinaryOperator' and op=='=' and len(terms)==2 and variable(terms[0])==key:
                (updates if reads(terms[1]) else plain_values).append(terms[1])
            elif kind=='UnaryOperator' and op in ('++','--') and len(terms)==1 and variable(terms[0])==key:updates.append(n)
            elif kind=='CompoundAssignOperator' and len(terms)==2 and variable(terms[0])==key:return None
        if not plain_values:return None
        self.active.add(key)
        try:
            values=[v if isinstance(v,tuple) else self.value(v,name,facts,parameters,depth+1) for v in plain_values]
            if any(v is None for v in values):return None
            union=(min(v[0] for v in values),max(v[1] for v in values))
            for update in updates:
                self.assumed[key]=union
                try:
                    if update.get('kind')=='UnaryOperator':
                        empty=[False];operand=children(update)[0]
                        before=self.refine(operand,union,name,facts,parameters,depth+1,empty)
                        if empty[0]:continue
                        step=1 if update['opcode']=='++' else -1
                        after=(before[0]+step,before[1]+step)
                    else:after=self.value(update,name,facts,parameters,depth+1)
                finally:self.assumed.pop(key,None)
                if after is None or after[0]<union[0] or after[1]>union[1]:return None
            self.note('definitions',dict(variable=node.get('name'),kind='inductive_union' if updates else 'union',bounds=list(union),assignments=len(plain_values)+len(updates)))
            return union
        finally:self.active.discard(key)
    def affine(self,node,shape,base,name,facts,parameters,depth):
        """(a, b) with node == a*shape + b, a > 0, when no intermediate value leaves its type for shape in base."""
        node=widening(node);kind=node.get('kind');terms=children(node);typ=integer_type(type_of(node))
        if canonical(node)==shape:return 1,0
        if typ is None or kind!='BinaryOperator' or node.get('opcode') not in ('+','-','*') or len(terms)!=2:return None
        op=node['opcode']
        for inner,other,swap in ((terms[0],terms[1],False),(terms[1],terms[0],True)):
            if swap and op=='-':break
            if any(n.get('kind') in ('DeclRefExpr','MemberExpr','CallExpr') for n in walk(other)):continue
            constant=self.value(other,name,facts,parameters,depth+1)
            if constant is None or constant[0]!=constant[1]:continue
            c=constant[0];part=self.affine(inner,shape,base,name,facts,parameters,depth)
            if part is None:continue
            a,b=part
            if op=='+':a,b=a,b+c
            elif op=='-':a,b=a,b-c
            elif c>0:a,b=a*c,b*c
            else:return None
            low,high=a*base[0]+b,a*base[1]+b
            return (a,b) if NARROW[typ][0]<=low and high<=NARROW[typ][1] else None
        return None
    def binary(self,node,name,facts,parameters,depth):
        op=node.get('opcode');left,right=children(node);typ=integer_type(type_of(node))
        if op in ('==','!=','<','>','<=','>='):
            # Decided only when both operands are integers and every pair of values agrees.
            a=self.value(left,name,facts,parameters,depth) if integer_type(type_of(widening(left))) else None
            b=self.value(right,name,facts,parameters,depth) if integer_type(type_of(widening(right))) else None
            if a is None or b is None:return (0,1)
            decide={'<':(a[1]<b[0],a[0]>=b[1]),'<=':(a[1]<=b[0],a[0]>b[1]),'>':(a[0]>b[1],a[1]<=b[0]),'>=':(a[0]>=b[1],a[1]<b[0]),
                    '==':(a[0]==a[1]==b[0]==b[1],a[1]<b[0] or b[1]<a[0]),'!=':(a[1]<b[0] or b[1]<a[0],a[0]==a[1]==b[0]==b[1])}[op]
            return (1,1) if decide[0] else (0,0) if decide[1] else (0,1)
        if op in ('&&','||'):return (0,1)
        if op==',':return self.value(right,name,facts,parameters,depth)
        if op in MUTATIONS:return WIDE[typ]
        a=self.value(left,name,facts,parameters,depth);b=self.value(right,name,facts,parameters,depth)
        if a is None or b is None:return WIDE[typ]
        if op=='+':return self.fit(a[0]+b[0],a[1]+b[1],node)
        if op=='-':return self.fit(a[0]-b[1],a[1]-b[0],node)
        if op=='*':
            products=[x*y for x in a for y in b];return self.fit(min(products),max(products),node)
        if op in ('/','%') and b[0]==b[1] and b[0]>0 and a[0]>=0:
            return self.fit(a[0]//b[0],a[1]//b[0],node) if op=='/' else (0,min(a[1],b[0]-1))
        if op=='>>' and b[0]==b[1] and 0<=b[0]<64 and a[0]>=0:return (a[0]>>b[0],a[1]>>b[0])
        if op=='<<' and b[0]==b[1] and 0<=b[0]<64 and a[0]>=0:return self.fit(a[0]<<b[0],a[1]<<b[0],node)
        if op=='&' and a[0]>=0 and b[0]>=0:
            masked=self.masked_index(node,name,facts,parameters,depth)
            if masked is not None:return masked
            return (0,min(a[1],b[1]))
        if op=='&' and (a[0]>=0 or b[0]>=0):return (0,a[1] if a[0]>=0 else b[1])
        if op in ('|','^') and a[0]>=0 and b[0]>=0:return self.fit(0,(1<<max(a[1],b[1]).bit_length())-1,node)
        return WIDE[typ]
    def call(self,node,name,facts,parameters,depth):
        target=callee(node);typ=integer_type(type_of(node))
        if target=='__builtin_expect' and len(children(node))==3:return self.value(children(node)[1],name,facts,parameters,depth+1)
        function=self.analyzer.functions.get(target)
        if function is None or self.analyzer.boundary(target) or depth>=MAX_DEPTH:return WIDE[typ]
        callee_facts=self.facts_for(target)
        arguments=children(node)[1:];bound={}
        for parameter,argument in zip([c for c in children(function) if c.get('kind')=='ParmVarDecl'],arguments):
            if integer_type(type_of(parameter)):
                value=self.value(argument,name,facts,parameters,depth+1)
                if value is not None:
                    converted=self.fit(*value,parameter)
                    if converted is not None:bound[parameter['id']]=converted
        returns=[n for n in walk(function) if n.get('kind')=='ReturnStmt']
        if not returns or any(not children(r) for r in returns):return WIDE[typ]
        # Pointer arguments carry their alias values into the callee (fields of automatic records).
        entered=False
        if self.pointer_env and self.call_stack and target not in self.call_stack[-1]:
            env=self.pointer_env[-1];stack=self.call_stack[-1];callee_env={}
            for parameter,argument in zip([c for c in children(function) if c.get('kind')=='ParmVarDecl'],arguments):
                if '*' in type_of(parameter):callee_env[parameter['id']]=self.analyzer.resolve(argument,env,stack)
            self.pointer_env.append(callee_env);self.call_stack.append(stack+[target]);entered=True
        try:values=[self.value(children(r)[0],target,callee_facts,bound,depth+1) for r in returns]
        finally:
            if entered:self.pointer_env.pop();self.call_stack.pop()
        if any(v is None for v in values):return WIDE[typ]
        self.note('calls',dict(caller=name,callee=target,location=self.analyzer.location(node)))
        return self.fit(min(v[0] for v in values),max(v[1] for v in values),node)
    def refine(self,node,base,name,facts,parameters,depth,empty=None):
        """Intersect with comparisons against `node`, or an affine `a*node + b`, that dominate it."""
        shape=canonical(node)
        if shape is None or shape[0] in ('int',):return base
        low,high=base
        swapped={'<':'>','>':'<','<=':'>=','>=':'<=','==':'==','!=':'!='}
        for cond,truth,guard in facts.facts(node):
            for comparison,holds in self.comparisons(cond,truth):
                left,right=children(comparison);op=comparison['opcode']
                form=self.affine(left,shape,base,name,facts,parameters,depth+1)
                if form is not None:other=right
                else:
                    form=self.affine(right,shape,base,name,facts,parameters,depth+1)
                    if form is None:continue
                    other=left;op=swapped[op]
                if not holds:op={'<':'>=','>=':'<','>':'<=','<=':'>','==':'!=','!=':'=='}[op]
                bound=self.value(other,name,facts,parameters,depth+1)
                if bound is None:continue
                # a*x + b OP bound, a > 0, without wrapping: solve for x.
                a,b=form
                if op=='<':high=min(high,(bound[1]-1-b)//a)
                elif op=='<=':high=min(high,(bound[1]-b)//a)
                elif op=='>':low=max(low,-((b-bound[0]-1)//a))
                elif op=='>=':low=max(low,-((b-bound[0])//a))
                elif op=='==':low=max(low,-((b-bound[0])//a));high=min(high,(bound[1]-b)//a)
                else:continue
                self.note('guards',self.analyzer.location(guard))
        if low>high and empty is not None:empty[0]=True
        return (low,high) if low<=high else base
    def comparisons(self,cond,truth):
        """Comparisons implied by a condition with the given truth value: (node, holds)."""
        cond=condition(cond);kind=cond.get('kind');op=cond.get('opcode');terms=children(cond)
        if kind=='UnaryOperator' and op=='!' and len(terms)==1:return self.comparisons(terms[0],not truth)
        if kind=='BinaryOperator' and op in ('&&','||') and len(terms)==2:
            return [c for t in terms for c in self.comparisons(t,truth)] if (op=='&&')==truth else []
        if kind=='BinaryOperator' and op in ('<','>','<=','>=','==','!=') and len(terms)==2:
            # Comparison operands are converted to a common type; keep only
            # value-preserving conversions so the relation holds for the originals.
            if all(integer_type(type_of(widening(t))) for t in terms):return [(cond,truth)]
        return []
    def mask_definition(self,node,name,facts):
        """A variable whose reaching definition calls f(i, n) returning all-ones when i < n (or i <= n), else zero.

        f is either a body `return c ? ~0 : 0;` or a declared index_mask value model
        (an architecture that implements the mask in assembly). The result names the
        call's index and limit arguments and the comparison.
        """
        shape=widening(node);use=declref(shape)
        if use is None:return None
        definition=facts.reaching(use,use['referencedDecl']['id'])
        if definition is None:return None
        call=widening(definition)
        if call.get('kind')!='CallExpr':return None
        target=callee(call);arguments=children(call)[1:]
        mask_type=integer_type(type_of(call))
        if mask_type is None or not mask_type.startswith('unsigned') or integer_type(type_of(shape))!=mask_type:return None
        policy=self.analyzer.boundary(target) if target else None
        if policy and policy.get('kind')=='value_model' and policy.get('semantics')=='index_mask':
            if len(arguments)!=2:return None
            return dict(call=call,function=target,type=mask_type,index=arguments[0],limit=arguments[1],op='<',model=policy)
        function=self.analyzer.functions.get(target)
        if function is None or policy:return None
        returns=[n for n in walk(function) if n.get('kind')=='ReturnStmt']
        if len(returns)!=1 or len(children(returns[0]))!=1:return None
        selection=widening(children(returns[0])[0])
        if selection.get('kind')!='ConditionalOperator':return None
        test,ones,zero=children(selection)
        if not (all_ones(ones) and is_zero(zero)):return None
        test=widening(test)
        if test.get('kind')!='BinaryOperator' or test.get('opcode') not in ('<','<=','>','>='):return None
        parameters=[c for c in children(function) if c.get('kind')=='ParmVarDecl']
        if any(p['id'] in self.facts_for(target).mutations for p in parameters):return None
        ids={p['id']:i for i,p in enumerate(parameters)}
        left,right=children(test);op=test['opcode']
        lhs=variable(widening(left));rhs=variable(widening(right))
        if op in ('>','>='):lhs,rhs=rhs,lhs;op={'>':'<','>=':'<='}[op]
        if lhs not in ids or rhs not in ids or ids[lhs]>=len(arguments) or ids[rhs]>=len(arguments):return None
        return dict(call=call,function=target,type=mask_type,index=arguments[ids[lhs]],limit=arguments[ids[rhs]],op=op)
    def masked_index(self,node,name,facts,parameters,depth):
        """x & mask where mask = f(x, n) and f is all-ones only for x < n: x is below n or zero."""
        if integer_type(type_of(node)) is None:return None
        for index,mask in (children(node),children(node)[::-1]):
            definition=self.mask_definition(mask,name,facts)
            if definition is None or integer_type(type_of(node))!=definition['type']:continue
            key=variable(widening(index))
            # The masked operand is the same unassigned variable that was compared.
            if key is None or key!=variable(widening(definition['index'])) or key in facts.mutations or key in facts.escaped:continue
            bound=self.value(definition['limit'],name,facts,parameters,depth+1)
            if bound is None:continue
            self.note('calls',dict(caller=name,callee=definition['function'],location=self.analyzer.location(definition['call']),idiom='index_mask',
                **({'value_model':'index_mask'} if definition.get('model') else {})))
            return (0,max(0,bound[1]-(1 if definition['op']=='<' else 0)))
        return None

def is_zero(node):
    # Every integer conversion maps zero to zero.
    node=parens(node)
    while node.get('kind') in ('ImplicitCastExpr','CStyleCastExpr') and node.get('castKind') in ('IntegralCast','NoOp') and len(children(node))==1:node=parens(children(node)[0])
    return node.get('kind')=='IntegerLiteral' and str(node.get('value'))=='0'

def all_ones(node):
    node=widening(node)
    if node.get('kind') in ('ImplicitCastExpr','CStyleCastExpr') and node.get('castKind')=='IntegralCast' and len(children(node))==1:
        inner=parens(children(node)[0])
        # Converting -1 to an unsigned type yields that type's all-ones value.
        if inner.get('kind')=='UnaryOperator' and inner.get('opcode')=='-' and is_one(children(inner)[0]) and integer_type(type_of(node)).startswith('unsigned'):return True
        node=inner
    return (node.get('kind')=='UnaryOperator' and node.get('opcode')=='~' and is_zero(children(node)[0]) and
            (integer_type(type_of(node)) or '').startswith('unsigned'))

def is_one(node):
    node=widening(node);return node.get('kind')=='IntegerLiteral' and str(node.get('value'))=='1'

def masked_pointer(node,name,values,facts):
    """(T *)(mask & (uintptr)p) where mask is all-ones or zero: the value is p or null."""
    node=parens(node)
    if node.get('kind') not in ('ImplicitCastExpr','CStyleCastExpr') or node.get('castKind')!='IntegralToPointer':return None
    operation=widening(children(node)[0])
    if operation.get('kind')!='BinaryOperator' or operation.get('opcode')!='&':return None
    for mask,pointer in (children(operation),children(operation)[::-1]):
        definition=values.mask_definition(mask,name,facts)
        if definition is None or integer_type(type_of(operation))!=definition['type'] or definition['type'] not in ('unsigned long','unsigned long long'):continue
        cast=parens(pointer)
        if cast.get('kind') in ('ImplicitCastExpr','CStyleCastExpr') and cast.get('castKind')=='PointerToIntegral' and integer_type(type_of(cast))==definition['type']:
            return dict(pointer=children(cast)[0],mask_function=definition['function'],mask_type=definition['type'])
    return None
