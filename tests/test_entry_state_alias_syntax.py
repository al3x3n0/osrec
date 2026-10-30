"""Syntax indexes must preserve per-call aliases, effects and diagnostics."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

import test_entry_state as basic
from entry_state import Analyzer,capture_header,walk,path_provider

POLICY={name:{**basic.POLICY['current']} for name in ('current','alternate')}
SOURCE='''struct Obj{unsigned first,second,values[4];struct Obj *next,*parent;};
struct Obj *current(void),*alternate(void);unsigned external(unsigned);
struct Obj *pick(struct Obj *p){struct Obj *q=p;return q;}
struct Obj *wrapped(struct Obj *p){return ({struct Obj *q=pick(p);q;});}
unsigned left(void){return pick(current())->first;}
unsigned right(void){return pick(alternate())->second;}
unsigned contexts(void){return left()+right()+wrapped(current())->second;}
struct Obj *parent_of(struct Obj *p){struct Obj *q=p->parent;return q;}
unsigned parents(void){return parent_of(current())->first+parent_of(alternate())->second;}
unsigned first(struct Obj *p){return p->first;}unsigned second(struct Obj *p){return p->second;}
unsigned invoke(unsigned(*fn)(struct Obj *),struct Obj *p){return fn(p);}
unsigned callbacks(void){return invoke(first,current())+invoke(second,alternate());}
struct Obj *touch(struct Obj *p){for(unsigned i=0;i<4;i++)p->values[i]++;return p;}
unsigned loops(void){return touch(current())->first+touch(alternate())->second;}
struct Obj *selected(struct Obj *p){return __builtin_choose_expr(1,p,({struct Obj *q=alternate();external(1);q;}));}
unsigned selection(void){return selected(current())->first;}
struct Obj *branch(struct Obj *p,unsigned n){while(n--)p=n&1?p->next:p->parent;return p;}
unsigned limited(unsigned n){return branch(current(),n)->first;}
unsigned issue_helper(struct Obj *p){external(p->first);return p->second;}
unsigned issue_left(void){return issue_helper(current());}unsigned issue_right(void){return issue_helper(alternate());}
unsigned issues(void){return issue_left()+issue_right();}
struct Obj *global;
struct Obj *update(struct Obj *p){global=p;return global;}
unsigned global_assignment(void){return update(current())->first;}
'''


class AliasSyntaxTests(unittest.TestCase):
    def parse(self,stage):return basic.EntryStateTests().parse(stage,SOURCE)[0]

    def plans(self,tree,root,limit=256):
        plans=[Analyzer(tree,POLICY,max_alias_paths=limit,cache_alias_syntax=enabled).analyze(root) for enabled in (False,True)]
        self.assertEqual(plans[0],plans[1]);return plans[1]

    def test_parameter_bindings_and_statement_expression_environments_remain_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=self.plans(self.parse(Path(tmp)),'contexts');self.assertFalse(p['blockers'])
            self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->first','current()->second','alternate()->second'})
            capture_header([p])

    def test_helper_return_aliases_use_each_actual_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=self.plans(self.parse(Path(tmp)),'parents');self.assertFalse(p['blockers'])
            self.assertEqual({r['path'] for r in p['entry_reads']},
                {'current()->parent','current()->parent->first','alternate()->parent','alternate()->parent->second'})

    def test_callback_targets_are_recomputed_for_each_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=self.plans(self.parse(Path(tmp)),'callbacks');self.assertFalse(p['blockers'])
            self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->first','alternate()->second'})
            self.assertTrue({'first','second'}<={r['callee'] for r in p['call_sites']})

    def test_loop_ranges_and_effects_keep_both_object_origins(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=self.plans(self.parse(Path(tmp)),'loops');self.assertFalse(p['blockers'])
            self.assertEqual({r['path'] for r in p['state_writes']},
                {provider+'()->values['+str(i)+']' for provider in ('current','alternate') for i in range(4)})
            self.assertTrue(p['memory_ranges']);capture_header([p])

    def test_discarded_compile_time_branch_does_not_add_aliases_or_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=self.plans(self.parse(Path(tmp)),'selection');self.assertFalse(p['blockers'])
            self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->first'})
            self.assertNotIn('external',{c['callee'] for c in p['call_sites']})

    def test_global_assignment_is_retained_in_the_return_alias_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=self.plans(self.parse(Path(tmp)),'global_assignment');self.assertFalse(p['blockers'])
            self.assertIn('current()->first',{r['path'] for r in p['entry_reads']})
            self.assertIn('global:global',{r['path'] for r in p['state_writes']})

    def test_same_diagnostic_node_keeps_distinct_call_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=self.plans(self.parse(Path(tmp)),'issues')
            paths={tuple(b['call_path']) for b in p['blockers'] if b['kind']=='unmodeled_external'}
            self.assertEqual(paths,{('issues','issue_left','issue_helper'),('issues','issue_right','issue_helper')})
            with self.assertRaises(ValueError):capture_header([p])

    def test_resource_limits_fresh_roots_and_immutable_input_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp));before=copy.deepcopy(tree);p=self.plans(tree,'limited',8)
            self.assertTrue(p['analysis_limits']['alias_path_limit_observed'])
            a=Analyzer(tree,POLICY,max_alias_paths=8);first=a.analyze('limited')
            self.assertEqual(first,a.fresh().analyze('limited'))
            fresh=a.fresh().analyze('contexts');self.assertFalse(fresh['blockers'])
            self.assertFalse(fresh['analysis_limits']['alias_path_limit_observed'])
            self.assertEqual(tree,before)

    def test_long_paths_preserve_provider_identity_and_unknown_origin_rejection(self):
        tail='->parent'*256+'->first'
        self.assertIsNone(path_provider('global:root'+tail))
        self.assertEqual(path_provider('*(current()'+tail+')'),'current')
        self.assertEqual(path_provider('123current()'+tail),'current')
        with tempfile.TemporaryDirectory() as tmp:
            a=Analyzer(self.parse(Path(tmp)),POLICY)
            node={'kind':'MemberExpr','type':{'qualType':'unsigned int'}}
            a.access({'global:root'+tail},node,['long_path'])
            self.assertEqual(a.reads[0]['path'],'global:root'+tail)
            a.access({'*(unresolved:call)'+tail},node,['long_path'])
            self.assertEqual(len(a.reads),1)
            self.assertIn('unresolved_pointer_origin',{b['kind'] for b in a.blockers})

    def test_expression_syntax_cache_does_not_reuse_alias_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp));a=Analyzer(tree,POLICY)
            function=a.functions['pick'];parameter=next(n for n in walk(function) if n.get('kind')=='ParmVarDecl')
            expression=next(n for n in walk(function) if n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('id')==parameter['id'])
            for origin in ('current()','alternate()','unresolved:call'):
                self.assertEqual(a.resolve(expression,{parameter['id']:{origin}},['pick']),{origin})
            self.assertTrue(a._expression_nodes_cache)
            self.assertFalse(a.fresh()._expression_nodes_cache)


if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
