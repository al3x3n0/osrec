"""Conservative must-store pruning for isolated bound fields in one C body.

This pass proves only selected omissions relative to explicit binding contracts.
It does not establish whole-program minimality, alias freedom or concurrency.
"""
import json
import re
from entry_state import children,effect_walk as walk,unwrap,type_of,callee,path_provider,PRESERVATION_REASON,PRESERVATION_FORMAT,preservation_eligible,selected_expression,SELECTIONS
PLAIN=re.compile(r'^([A-Za-z_]\w*)\(\)->[A-Za-z_]\w*(?:\[[0-9]+\])*$')

class MustStore:
    def __init__(self,analyzer,root,env):
        self.analyzer=analyzer;self.root=root;self.env=dict(env);self.facts={};self.observations={}
        self.exits=[];self.unsupported_control=False
        self.null_exits=[];self.null_returns={};self.null_guard_proofs=[]
        self.guard_parameters={}
        if not analyzer.preserve_write_state:return
        body=self.analyzer.functions[root]
        for parameter in children(body):
            if parameter.get('kind')!='ParmVarDecl':continue
            key=parameter['id'];provider='osrec_argument_'+parameter['name']
            if self.env.get(key)!={provider+'()'} or provider not in analyzer.providers:continue
            # The guard must test the entry binding itself. Reject parameters
            # assigned anywhere or whose address could escape, even on paths
            # that this structured proof does not analyze precisely.
            changed=False
            for node in walk(body):
                parts=children(node);kind=node.get('kind');op=node.get('opcode')
                if parts and ((kind=='BinaryOperator' and op=='=') or kind=='CompoundAssignOperator' or
                              (kind=='UnaryOperator' and op in ('&','++','--'))):
                    targets=walk(parts[0]) if kind=='UnaryOperator' and op=='&' else (unwrap(parts[0]),)
                    if any(n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('id')==key for n in targets):
                        changed=True;break
            if not changed:self.guard_parameters[key]=provider

    def null_guard_return(self,condition,then,otherwise=None):
        if not self.analyzer.preserve_write_state:return
        # Recognize only direct parameter truth tests and a single immediate
        # pure return in the null arm. Do not strip explicit casts or infer
        # comparisons, compound predicates, aliases or continuation truth.
        def plain(node):
            while node.get('kind') in ('ParenExpr','ImplicitCastExpr') and children(node):node=children(node)[0]
            return node
        test=plain(condition);negated=test.get('kind')=='UnaryOperator' and test.get('opcode')=='!'
        if negated:test=plain(children(test)[0])
        if test.get('kind')!='DeclRefExpr':return
        provider=self.guard_parameters.get(test.get('referencedDecl',{}).get('id'))
        arm=then if negated else otherwise
        if not provider or arm is None:return
        if arm.get('kind')=='CompoundStmt' and len(children(arm))==1:arm=children(arm)[0]
        if arm.get('kind')!='ReturnStmt' or not self.pure(arm):return
        self.null_returns[arm['id']]={provider}
        self.null_guard_proofs.append({'root':provider,'condition':self.analyzer.location(condition),
                                      'return':self.analyzer.location(arm)})

    def eligible(self,path,node):
        match=PLAIN.fullmatch(path)
        if not match or '*' in type_of(node) or 'volatile' in type_of(node) or type_of(node).startswith(('struct ','union ')):return False
        field=self.analyzer.fields.get(node.get('referencedMemberDecl'),{})
        if field.get('isBitfield'):return False
        # Argument objects use synthetic binding names, not callable provider
        # boundaries. Their stronger isolation/identity promises must come from
        # the explicit argument contract, never from snapshot_safe alone.
        binding=self.analyzer.providers.get(match[1],{})
        policy=binding.get('contract') or self.analyzer.boundary(match[1]) or {}
        return policy.get('stable_identity') is True and policy.get('exclusive_state') is True and policy.get('preserves_entry_state') is True

    def key(self,path,node):
        return (path,type_of(node),json.dumps(self.analyzer.location(node),sort_keys=True))

    def reads(self,node):
        for expression in walk(node):
            if expression.get('kind')!='ImplicitCastExpr' or expression.get('castKind')!='LValueToRValue':continue
            target=unwrap(children(expression)[0]);kind=target.get('kind')
            if kind not in ('MemberExpr','ArraySubscriptExpr','UnaryOperator','DeclRefExpr'):continue
            for path in self.analyzer.resolve(target,self.env,[self.root]):
                key=self.key(path,target)
                proof=self.facts.get(path) if self.eligible(path,target) else None
                if proof and proof['type']!=type_of(target):proof=None
                self.observations.setdefault(key,[]).append(proof)

    def pure(self,node):
        for expression in walk(node):
            kind=expression.get('kind','')
            if kind in ('CallExpr',):
                policy=self.analyzer.boundary(callee(expression)) or {}
                if policy.get('kind')!='object_provider' or policy.get('stable_identity') is not True or policy.get('exclusive_state') is not True or policy.get('preserves_entry_state') is not True:
                    return False
            if kind in ('CompoundAssignOperator','GCCAsmStmt','MSAsmStmt','AtomicExpr','StmtExpr','VAArgExpr') or kind.startswith('CXX'):return False
            if kind=='BinaryOperator' and expression.get('opcode')=='=':return False
            if kind=='UnaryOperator' and expression.get('opcode') in ('++','--'):return False
        return True

    @staticmethod
    def merge(left,right):
        # Path joins can reuse the same incoming store on both sides. Keep
        # distinct source witnesses, not one copy per possible execution path.
        return {path:{'type':value['type'],'locations':list({json.dumps(location,sort_keys=True):location
                    for location in value['locations']+right[path]['locations']}.values())}
                for path,value in left.items() if path in right and value['type']==right[path]['type']}

    def sequenced(self,node):
        target=unwrap(node)
        if target.get('kind')=='BinaryOperator' and target.get('opcode')=='=':
            self.statement(target)
        else:self.expression(node)

    def expression(self,node):
        # Statement expressions can leave the enclosing function/loop. This
        # structured pass does not prove their exits or use their stores to
        # justify entry-state preservation omissions.
        if any(term.get('kind')=='StmtExpr' for term in walk(node)):
            self.unsupported_control=True
        expression=unwrap(node)
        parts=children(expression)
        if expression.get('kind')=='ConditionalOperator' and len(parts)==3:
            # The condition precedes exactly one selected arm. Analyze both
            # possible arms, retaining only facts guaranteed by either result.
            self.sequenced(parts[0]);incoming=dict(self.facts)
            self.sequenced(parts[1]);then_facts=dict(self.facts)
            self.facts=dict(incoming);self.sequenced(parts[2])
            self.facts=self.merge(then_facts,self.facts)
            return
        if expression.get('kind')=='BinaryOperator' and expression.get('opcode') in ('&&','||'):
            # The right operand may be skipped. It can use left-side facts,
            # but later expressions must also admit the skipped-right path.
            self.sequenced(parts[0]);skipped=dict(self.facts)
            self.sequenced(parts[1]);self.facts=self.merge(skipped,self.facts)
            return
        if expression.get('kind')=='BinaryOperator' and expression.get('opcode')==',':
            # The comma operator sequences its operands. Only honor that
            # guarantee when this is the expression being evaluated; an
            # enclosing unsequenced expression still takes the conservative
            # path below and observes all nested reads without new facts.
            for operand in parts:self.sequenced(operand)
            return
        # C operand order is often unspecified. Any effect in the expression
        # invalidates incoming facts before considering any of its reads.
        if not self.pure(node):self.facts={}
        self.reads(node)
        if not self.pure(node):self.facts={}

    def statement(self,node):
        kind=node.get('kind');parts=children(node)
        if kind=='CompoundStmt':
            for statement in parts:
                if not self.statement(statement):return False
            return True
        if kind=='IfStmt':
            # C IfStmt has condition, then, and optional else. Reject init/
            # condition-variable forms rather than guessing child positions.
            if node.get('hasInit') or node.get('hasVar') or len(parts) not in (2,3):
                self.expression(node);self.facts={};return True
            self.null_guard_return(parts[0],parts[1],parts[2] if len(parts)==3 else None)
            self.expression(parts[0]);incoming=dict(self.facts)
            then_live=self.statement(parts[1]);then_facts=dict(self.facts)
            self.facts=dict(incoming)
            else_live=self.statement(parts[2]) if len(parts)==3 else True
            else_facts=dict(self.facts)
            if then_live and else_live:
                self.facts=self.merge(then_facts,else_facts)
            elif then_live:self.facts=then_facts
            elif else_live:self.facts=else_facts
            else:self.facts={}
            return then_live or else_live
        if kind=='ReturnStmt':
            for expression in parts:self.expression(expression)
            self.exits.append(dict(self.facts))
            self.null_exits.append(self.null_returns.get(node.get('id'),set()))
            return False
        if kind=='BinaryOperator' and node.get('opcode')=='=':
            left,right=parts;target=unwrap(left)
            left_pure=self.pure(left);right_pure=self.pure(right)
            if not left_pure:
                # Assignment operands are unsequenced. The target evaluation
                # may change state before or during right-hand evaluation.
                self.facts={};self.reads(right);self.reads(left);self.facts={}
                return True
            # First observe every load without crediting the new store. Other
            # writes invalidate existing facts, including possible overlap.
            incoming=dict(self.facts)
            self.expression(right)
            # Left-hand reads cannot borrow a store from the right operand:
            # they may have been evaluated before that store.
            self.facts=incoming if right_pure else {}
            self.expression(left);self.facts={}
            paths=self.analyzer.resolve(target,self.env,[self.root])
            if len(paths)==1 and target.get('kind') in ('MemberExpr','ArraySubscriptExpr') and left_pure and right_pure:
                path=next(iter(paths))
                if self.eligible(path,target):self.facts[path]={'type':type_of(target),'locations':[self.analyzer.location(target)]}
            return True
        if kind in ('ForStmt','WhileStmt','DoStmt','SwitchStmt','GotoStmt','IndirectGotoStmt','LabelStmt','BreakStmt','ContinueStmt'):
            # Loop backedges, jumps and switch fallthrough need a full CFG.
            # Keep all reads in the region; do not export its stores as facts.
            self.unsupported_control=True
            self.facts={};self.reads(node);self.facts={};return True
        if kind=='DeclStmt':
            for declaration in parts:
                for expression in children(declaration):self.expression(expression)
            return True
        self.expression(node)
        return True

    def run(self,plan,body):
        if plan['blockers']:return plan
        # A label can be entered after a syntactically later jump, or after a
        # return that would stop this structured traversal. Disable the entire
        # omission proof for such bodies, including labels inside expressions.
        jumps=any(node.get('kind') in ('GotoStmt','IndirectGotoStmt','LabelStmt','AddrLabelExpr') for node in walk(body))
        if jumps:self.unsupported_control=True
        elif self.statement(body):
            self.exits.append(dict(self.facts));self.null_exits.append(set())
        retained=[];omitted=[]
        for read in plan['entry_reads']:
            key=(read['path'],read['type'],json.dumps(read['location'],sort_keys=True))
            evidence=self.observations.get(key,[])
            # Do not use caller stores to prune helper contexts. Every matching
            # occurrence must have a must-store proof, including macro aliases.
            if read['function']==self.root and evidence and all(evidence):
                omitted.append({**read,'entry_candidate':False,'omission_reason':'full typed store on every incoming path',
                    'covering_stores':[location for item in evidence for location in item['locations']]})
            else:retained.append(read)
        plan['entry_reads']=retained;plan['dominated_reads']=omitted
        plan['policy']='may-read closure with selected full-store omissions under explicit model contracts; unknown effects block export'
        plan['write_omission_analysis']='conservative structured must-store pass with explicit stable/exclusive provider contracts'
        if self.analyzer.preserve_write_state:
            guaranteed={}
            if not self.unsupported_control:
                for path in {path for facts in self.exits for path in facts}:
                    applicable=[facts for facts,null_roots in zip(self.exits,self.null_exits) if path_provider(path) not in null_roots]
                    merged=dict(applicable[0]) if applicable else {}
                    for facts in applicable[1:]:merged=self.merge(merged,facts)
                    if path in merged:
                        guaranteed[path]=merged[path]
                        excluded=len(self.exits)-len(applicable)
                        if excluded:guaranteed[path]['excluded_null_exits']=excluded
            captured={(r['path'],r['type']) for r in retained};preserved=[]
            for write in plan.get('state_writes',[]):
                path=write['path'];typ=write['type']
                if not preservation_eligible(plan,write):continue
                if (path,typ) in captured or guaranteed.get(path,{}).get('type')==typ:continue
                preserved.append({**write,'entry_candidate':True,'preservation_reason':PRESERVATION_REASON});captured.add((path,typ))
            plan['preserved_entry_fields']=preserved
            plan['write_state_preservation']={'format':PRESERVATION_FORMAT,'unsupported_control_flow':self.unsupported_control,
                'guaranteed_exit_stores':[{'path':path,**fact} for path,fact in sorted(guaranteed.items())],
                'null_guard_exit_proofs':self.null_guard_proofs}
        return plan


def definite_pointer_initialization(body,keys):
    return definite_local_initialization(body,keys)


def definite_local_initialization(body,keys,initialized_declarations=False,scalar_updates=False):
    """Certify use-after-assignment without narrowing the may-alias union.

    Branch joins intersect facts; early returns remove a continuation. Facts
    from unsequenced operands cannot initialize each other's reads. Loop-body
    stores never justify a later use, and jumps/indirect writes disable proof.
    This is a syntax-only certificate. Callers separately validate pointer
    origins or scalar value bounds before using its initialization facts.
    scalar_updates admits read-modify-write syntax only for caller-validated
    numeric keys; those reads still require incoming initialization facts.
    """
    if body.get('kind')=='FunctionDecl':
        body=next((n for n in children(body) if n.get('kind')=='CompoundStmt'),{})
    keys=set(keys);nodes=tuple(walk(body));bad=set();declarations={};stores={k:[] for k in keys}
    forbidden={'GotoStmt','IndirectGotoStmt','LabelStmt','SwitchStmt','CaseStmt','DefaultStmt',
               'BreakStmt','ContinueStmt','GCCAsmStmt','MSAsmStmt','AtomicExpr','StmtExpr',
               'BinaryConditionalOperator','OpaqueValueExpr','VAArgExpr'}
    if any(n.get('kind') in forbidden or n.get('kind','').startswith('CXX') for n in nodes):return {}
    for node in nodes:
        terms=children(node);kind=node.get('kind');op=node.get('opcode')
        if kind=='VarDecl' and node.get('id') in keys:declarations[node['id']]=node
        if terms and (kind=='UnaryOperator' and op in ('&','++','--') or kind=='CompoundAssignOperator'):
            target=unwrap(terms[0]);key=target.get('referencedDecl',{}).get('id')
            if target.get('kind')=='DeclRefExpr' and key in keys and (not scalar_updates or op=='&'):bad.add(key)
    unsupported=False
    def expression(node,state):
        nonlocal unsupported
        state=set(state);kind=node.get('kind');terms=children(node);op=node.get('opcode')
        if kind=='UnaryExprOrTypeTraitExpr':return state
        if kind in SELECTIONS:
            selected=selected_expression(node)
            if selected is None:unsupported=True;return state
            return expression(selected,state)
        if kind=='DeclRefExpr':
            key=node.get('referencedDecl',{}).get('id')
            if key in keys and key not in state:bad.add(key)
            return state
        if kind=='BinaryOperator' and op=='=' and len(terms)==2:
            left=unwrap(terms[0]);key=left.get('referencedDecl',{}).get('id')
            if left.get('kind')=='DeclRefExpr':
                result=expression(terms[1],state)
                if key in keys:stores[key].append(node);result.add(key)
                return result
        if kind=='BinaryOperator' and op==',' and len(terms)==2:
            return expression(terms[1],expression(terms[0],state))
        if kind=='BinaryOperator' and op in ('&&','||') and len(terms)==2:
            left=expression(terms[0],state);right=expression(terms[1],left)
            return left&right
        if kind=='ConditionalOperator' and len(terms)==3:
            condition=expression(terms[0],state)
            return expression(terms[1],condition)&expression(terms[2],condition)
        # All ordinary operands execute, but their evaluation order cannot
        # establish initialization for another operand or call argument.
        result=set(state)
        for child in terms:result.update(expression(child,state))
        return result
    def statement(node,state):
        nonlocal unsupported
        state=set(state);kind=node.get('kind');terms=children(node)
        if not kind:return state,True
        if kind in ('CompoundStmt','DeclStmt'):
            live=True
            for child in terms:
                if not live:break
                state,live=statement(child,state)
            return state,live
        if kind=='VarDecl':
            if node.get('id') in keys:state.discard(node['id'])
            for child in terms:state=expression(child,state)
            if initialized_declarations and node.get('id') in keys and node.get('init') and terms:
                state.add(node['id']);stores[node['id']].append(node)
            return state,True
        if kind=='IfStmt' and len(terms) in (2,3):
            condition=expression(terms[0],state)
            left,live_left=statement(terms[1],condition)
            right,live_right=statement(terms[2],condition) if len(terms)==3 else (condition,True)
            if live_left and live_right:return left&right,True
            if live_left:return left,True
            return right,live_right
        if kind=='ReturnStmt':
            for child in terms:state=expression(child,state)
            return state,False
        if kind=='WhileStmt' and len(terms)==2:
            condition=expression(terms[0],state);statement(terms[1],condition)
            return condition,True
        if kind=='ForStmt' and len(terms)==5 and not terms[1].get('kind'):
            initial,live=statement(terms[0],state)
            condition=expression(terms[2],initial)
            statement(terms[4],condition);expression(terms[3],condition)
            return condition,live
        if kind=='DoStmt' and len(terms)==2:
            # The body runs before the first test; later iterations start with at least its stores. (A break or
            # continue in the body is an unsupported statement, so the body's end state reaches the test.)
            after,live=statement(terms[0],state)
            condition=expression(terms[1],after if live else state)
            return condition,live
        if kind=='NullStmt':return state,True
        if kind.endswith('Stmt'):
            unsupported=True;return state,True
        return expression(node,state),True
    statement(body,set())
    if unsupported:return {}
    return {key:{'declaration':declarations[key],'assignments':tuple(stores[key])}
            for key in keys-bad if key in declarations and stores[key]}
