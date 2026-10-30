"""Excessive alias growth must stay bounded, unknown and unexportable."""
from pathlib import Path
import sys
import tempfile
import unittest

import test_entry_state as basic
from entry_state import Analyzer,ALIAS_LIMIT_ORIGIN,capture_header,walk

MODEL='''struct Node{unsigned value;struct Node *left,*right;};struct Node *current(void);
unsigned branching(unsigned n){struct Node *p=current();while(n--)p=n&1?p->left:p->right;return p->value;}
unsigned finite(unsigned n){struct Node *p=n==0?current()->left:n==1?current()->right:current();return p->value;}
struct Node *step(struct Node *p,unsigned n){while(n--)p=n&1?p->left:p->right;return p;}
unsigned helper(unsigned n){return step(current(),n)->value;}
unsigned statement(unsigned n){struct Node *p=({struct Node *q=current();while(n--)q=n&1?q->left:q->right;q;});return p->value;}
unsigned unused(unsigned n){struct Node *p=current();while(n--)p=n&1?p->left:p->right;return 0;}
unsigned linear(unsigned n){struct Node *p=current();while(n--)p=p->left;return p->value;}
unsigned a(void){return current()->value;}unsigned b(void){return current()->value;}unsigned c(void){return current()->value;}
unsigned callback(unsigned n){unsigned(*fn)(void)=n==0?a:n==1?b:c;return fn();}
'''


class AliasLimitTests(unittest.TestCase):
    def parse(self,stage):return basic.EntryStateTests().parse(stage,MODEL)[0]

    def limited(self,tree,root,limit=256):
        analyzer=Analyzer(tree,basic.POLICY,max_alias_paths=limit);plan=analyzer.analyze(root)
        self.assertTrue(plan['analysis_limits']['alias_path_limit_observed'])
        self.assertTrue(any(b['kind']=='alias_limit' and 'path count' in b['detail'] for b in plan['blockers']))
        with self.assertRaises(ValueError):capture_header([plan])
        return analyzer,plan

    def test_exponential_backedges_stop_at_an_explicit_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp));analyzer,plan=self.limited(tree,'branching')
            self.assertIn({ALIAS_LIMIT_ORIGIN},list(analyzer.root_aliases.values()))
            self.assertTrue(all(len(v)<=256 for v in analyzer.root_aliases.values()))
            self.assertIn('unresolved_pointer_origin',{b['kind'] for b in plan['blockers']})

    def test_helper_returns_and_statement_expression_aliases_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp))
            for root in ('helper','statement'):
                with self.subTest(root=root):self.limited(tree,root,16)

    def test_even_an_unused_oversized_alias_set_blocks_export(self):
        with tempfile.TemporaryDirectory() as tmp:self.limited(self.parse(Path(tmp)),'unused',8)

    def test_exact_threshold_preserves_all_finite_origins(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp));plans=[]
            for limit in (3,256):
                plan=Analyzer(tree,basic.POLICY,max_alias_paths=limit).analyze('finite')
                self.assertFalse(plan['blockers'],plan['blockers']);capture_header([plan])
                self.assertFalse(plan.pop('analysis_limits')['alias_path_limit_observed']);plans.append(plan)
            self.assertEqual(plans[0],plans[1])
            analyzer,plan=self.limited(tree,'finite',2)
            self.assertIn({ALIAS_LIMIT_ORIGIN},list(analyzer.root_aliases.values()))

    def test_finite_callback_targets_are_not_silently_truncated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp));plan=Analyzer(tree,basic.POLICY,max_alias_paths=3).analyze('callback')
            self.assertFalse(plan['blockers']);self.assertTrue({'a','b','c'}<={c['callee'] for c in plan['call_sites']})
            self.limited(tree,'callback',2)

    def test_unknown_absorbs_unions_and_field_dereference_projections(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp));a,_=self.limited(tree,'finite',2);node=next(walk(tree))
            for paths in ({ALIAS_LIMIT_ORIGIN,'current()'},{ALIAS_LIMIT_ORIGIN+'->left'}, {'*('+ALIAS_LIMIT_ORIGIN+')->right'}):
                self.assertEqual(a.bounded_aliases(paths,node,['finite']),{ALIAS_LIMIT_ORIGIN})

    def test_fresh_analysis_does_not_inherit_a_previous_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp));a,_=self.limited(tree,'branching')
            b=a.fresh();plan=b.analyze('finite');self.assertFalse(plan['blockers'])
            self.assertFalse(b.alias_path_limit_observed);self.assertTrue(a.alias_path_limit_observed)

    def test_iteration_limit_and_positive_configuration_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp));p=Analyzer(tree,basic.POLICY).analyze('linear')
            self.assertTrue(any(b['kind']=='alias_limit' and '32 iterations' in b['detail'] for b in p['blockers']))
            self.assertFalse(p['analysis_limits']['alias_path_limit_observed'])
            for value in (0,-1,True,1.5,'4'):
                with self.subTest(value=value),self.assertRaises(ValueError):Analyzer(tree,max_alias_paths=value)

    def test_survey_and_cross_file_api_report_the_actual_limit(self):
        from discover_kernel_state import survey_unit
        from discover_call_closure import DefinitionIndex,discover
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);self.parse(stage);db=stage/'compile_commands.json';source=stage/'input.c'
            unit=survey_unit(db,source,100,max_alias_paths=2)
            finite=next(r for r in unit['roots'] if r['name']=='finite')
            self.assertEqual(finite['analysis_limits'],dict(max_alias_paths=2,alias_path_limit_observed=True))
            result=discover(db,source,'finite',DefinitionIndex({}),analysis_options={'max_alias_paths':2})
            self.assertEqual(result['limits']['max_alias_paths'],2)
            self.assertTrue(result['limits']['alias_path_limit_observed']);self.assertEqual(result['status'],'blocked')


if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
