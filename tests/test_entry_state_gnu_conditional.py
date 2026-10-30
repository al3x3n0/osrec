"""GNU omitted-middle conditionals preserve both origins and one common evaluation."""
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import test_entry_state as basic
import test_entry_state_local_effects as local_effects
from entry_state import Analyzer,capture_header,walk,children,effect_walk
POLICY={name:dict(basic.POLICY['current']) for name in ('left','right','third')}
HEADER='struct Obj{unsigned value,other;};struct Obj *left(void),*right(void),*third(void);'


class GnuConditionalTests(unittest.TestCase):
    def parse(self,stage,body):return basic.EntryStateTests().parse(stage,HEADER+body)[0]

    def test_both_pointer_origins_are_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),'unsigned root(void){return (left()?:right())->value;}'),POLICY).analyze('root')
            self.assertFalse(p['blockers']);self.assertEqual({r['path'] for r in p['entry_reads']},{'left()->value','right()->value'});capture_header([p])

    def test_callback_targets_keep_both_possible_functions(self):
        body='''unsigned first(struct Obj*p){return p->value;}unsigned second(struct Obj*p){return p->other;}
unsigned root(void){unsigned(*fn)(struct Obj*)=first;return (fn?:second)(left());}'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body),POLICY).analyze('root');self.assertFalse(p['blockers'])
            self.assertEqual({r['path'] for r in p['entry_reads']},{'left()->value','left()->other'})
            self.assertTrue({'first','second'}<={r['callee'] for r in p['call_sites']});capture_header([p])

    def test_common_effect_is_visited_once_within_the_context_budget(self):
        body='''struct Obj*first(void){return left();}struct Obj*second(void){return right();}
unsigned root(void){return (first()?:second())->value;}'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body);a=Analyzer(tree,POLICY,max_contexts=3);p=a.analyze('root')
            self.assertFalse(p['blockers']);self.assertEqual(a.contexts,3)
            evaluated=[n for n in effect_walk(a.functions['root']) if n.get('kind')=='CallExpr']
            self.assertEqual(len(evaluated),2)
            self.assertEqual({r['path'] for r in p['entry_reads']},{'left()->value','right()->value'})

    def test_common_and_fallback_global_effects_remain_visible(self):
        body='''unsigned common_count,fallback_count;
struct Obj*first(void){common_count++;return left();}struct Obj*second(void){fallback_count++;return right();}
unsigned root(void){return (first()?:second())->value;}'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body),POLICY).analyze('root')
            self.assertEqual({r['path'] for r in p['state_writes']},{'global:common_count','global:fallback_count'})
            self.assertTrue({'global:common_count','global:fallback_count','left()->value','right()->value'}<={r['path'] for r in p['entry_reads']})

    def test_first_operand_pointer_mutation_remains_blocked(self):
        body='unsigned root(void){struct Obj*p=left();return (p++?:right())->value;}'
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body),POLICY).analyze('root');self.assertIn('pointer_arithmetic',{r['kind'] for r in p['blockers']})
            with self.assertRaises(ValueError):capture_header([p])

    def test_nested_operators_keep_all_origins_and_fresh_root_isolation(self):
        body='unsigned root(void){return ((left()?:right())?:third())->value;}'
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body);before=copy.deepcopy(tree);a=Analyzer(tree,POLICY);p=a.fresh().analyze('root')
            self.assertFalse(p['blockers']);self.assertEqual({r['path'] for r in p['entry_reads']},{x+'()->value' for x in ('left','right','third')})
            self.assertEqual(p,a.fresh().analyze('root'));self.assertEqual(tree,before)

    def test_inconsistent_or_missing_shared_proxies_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),'unsigned root(void){return (left()?:right())->value;}')
            for change in ('id','source','arity'):
                q=copy.deepcopy(tree);node=next(n for n in walk(q) if n.get('kind')=='BinaryConditionalOperator')
                if change=='id':node['inner'][2]['id']='different'
                elif change=='source':node['inner'][2]['inner'][0]['inner'][0]['inner'][0]['referencedDecl']['name']='third'
                else:node['inner'].pop(1)
                p=Analyzer(q,POLICY).analyze('root');self.assertIn('unsupported_construct',{r['kind'] for r in p['blockers']})
                with self.assertRaises(ValueError):capture_header([p])

    def test_unbound_opaque_values_do_not_supply_pointer_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),'unsigned root(void){return (left()?:right())->value;}')
            node=next(n for n in walk(tree) if n.get('kind')=='BinaryConditionalOperator');node['kind']='OpaqueValueExpr';node['inner']=[node['inner'][0]]
            p=Analyzer(tree,POLICY).analyze('root');self.assertIn('unsupported_construct',{r['kind'] for r in p['blockers']})
            with self.assertRaises(ValueError):capture_header([p])

    def test_optional_fallback_store_does_not_justify_pruning(self):
        body='unsigned root(unsigned n){struct Obj*p=left();(void)(n?:(p->value=2));return p->value;}'
        policy={k:{**v,'stable_identity':True,'exclusive_state':True,'preserves_entry_state':True} for k,v in POLICY.items()}
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body),policy,prune_written=True,preserve_write_state=True).analyze('root')
            self.assertFalse(p['blockers']);self.assertIn('left()->value',{r['path'] for r in p['entry_reads']})
            self.assertNotIn('left()->value',{r['path'] for r in p.get('dominated_reads',[])})

    def test_unevaluated_and_discarded_operators_do_not_add_effects(self):
        body='''struct Obj*unknown(void);
unsigned root(void){return sizeof((left()?:unknown())->value)+__builtin_choose_expr(1,1,(left()?:unknown())->value);}'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body),POLICY).analyze('root');self.assertFalse(p['blockers']);self.assertFalse(p['call_sites']);capture_header([p])

    def test_cross_translation_unit_shared_values_remain_valid(self):
        sources={'a.c':'''struct Obj*helper(void);unsigned root(void){return (helper()?:current())->value;}''',
                 'b.c':'''struct Obj*helper(void){return current();}'''}
        with tempfile.TemporaryDirectory() as tmp:
            tree=local_effects.LocalEffectTests().parse(Path(tmp),sources);p=Analyzer(tree,local_effects.POLICY).analyze('root')
            self.assertFalse(p['blockers']);self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->value'});capture_header([p])

    def test_native_capture_keeps_both_possible_objects(self):
        body='unsigned root(void){return (left()?:right())->value;}'
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);p=Analyzer(self.parse(stage,body),POLICY).analyze('root');(stage/'capture.h').write_text(capture_header([p]))
            source=stage/'run.c';source.write_text(HEADER+body+'''\n#include <assert.h>
static struct Obj a={17,0},b={29,0};struct Obj*left(void){return &a;}struct Obj*right(void){return &b;}
#include "capture.h"
int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s));assert(s.object_count==2&&s.field_count==2);assert(root()==17);return 0;}
''');binary=stage/'run'
            subprocess.run([basic.CLANG,'-std=gnu11','-I',str(basic.ROOT/'include'),'-I',str(stage),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True,text=True)
            subprocess.run([str(binary)],check=True,capture_output=True)


if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=local_effects.CLANG=sys.argv.pop()
    unittest.main()
