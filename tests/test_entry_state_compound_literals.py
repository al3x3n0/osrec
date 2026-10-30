"""Lexical lifetime, initializer effects and bounds of automatic compound literals."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest

import test_entry_state as basic
import test_entry_state_local_effects as local_effects
from entry_state import Analyzer,capture_header,walk
POLICY=local_effects.POLICY
HEADER='struct Obj{unsigned value;struct Obj *next;};struct Obj *current(void);'


class CompoundLiteralTests(unittest.TestCase):
    def parse(self,stage,body):return basic.EntryStateTests().parse(stage,HEADER+body)[0]

    def reject(self,plan,kind):
        self.assertIn(kind,{b['kind'] for b in plan['blockers']},plan)
        with self.assertRaises(ValueError):capture_header([plan])

    def test_scalar_union_and_record_literals_are_automatic_storage(self):
        body='''typedef union{double f;unsigned long long bits;} Bits;
unsigned root(double x){return ((Bits){x}).bits>>32;}
unsigned record(unsigned x){return ((struct Obj){x,0}).value;}
unsigned scalar(unsigned x){return (unsigned){x};}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body)
            for root in ('root','record','scalar'):
                p=Analyzer(tree).analyze(root);self.assertFalse(p['blockers']);self.assertFalse(p['entry_reads']);capture_header([p])

    def test_initializers_keep_reads_writes_and_external_calls(self):
        body='''unsigned external(void);
unsigned root(void){return ((struct Obj){current()->value,0}).value;}
unsigned writes(void){return ((struct Obj){current()->value=3,0}).value;}
unsigned unknown(void){return ((struct Obj){external(),0}).value;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body);p=Analyzer(tree,POLICY).analyze('root');self.assertFalse(p['blockers'])
            self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->value'});capture_header([p])
            p=Analyzer(tree,POLICY).analyze('writes');self.assertFalse(p['blockers']);self.assertEqual({r['path'] for r in p['state_writes']},{'current()->value'})
            self.reject(Analyzer(tree,POLICY).analyze('unknown'),'unmodeled_external')

    def test_literal_arrays_use_only_their_configured_bounds(self):
        body='''unsigned root(void){return (unsigned[]){1,2}[1]+(unsigned[2][2]){{1,2},{3,4}}[1][0];}
unsigned dynamic(unsigned n){return (unsigned[]){1,2}[n];}
unsigned outside(void){return (unsigned[]){1,2}[2];}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body);p=Analyzer(tree).analyze('root');self.assertFalse(p['blockers']);capture_header([p])
            self.assertTrue(any(r['bound_source']=='configured Clang automatic compound-literal array type' for r in p['memory_ranges']))
            self.reject(Analyzer(tree).analyze('dynamic'),'dynamic_extent');self.reject(Analyzer(tree).analyze('outside'),'array_bounds')

    def test_pointer_casts_cannot_borrow_literal_array_bounds(self):
        body='unsigned root(void){return ((unsigned*)(unsigned[]){1,2})[1];}'
        with tempfile.TemporaryDirectory() as tmp:self.reject(Analyzer(self.parse(Path(tmp),body)).analyze('root'),'dynamic_extent')

    def test_pointer_members_and_callback_members_remain_unknown(self):
        body='''struct Box{struct Obj*p;unsigned(*fn)(void);};unsigned target(void){return 1;}
unsigned pointer(void){return ((struct Box){current(),target}).p->value;}
unsigned callback(void){return ((struct Box){current(),target}).fn();}
unsigned scalar_pointer(void){return *((unsigned*){&current()->value});}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body)
            for root in ('pointer','scalar_pointer'):self.reject(Analyzer(tree,POLICY).analyze(root),'unresolved_local_pointer')
            self.reject(Analyzer(tree,POLICY).analyze('callback'),'indirect_call')

    def test_volatile_scalar_and_member_accesses_cannot_be_ignored(self):
        body='''struct V{volatile unsigned x;};
unsigned scalar(unsigned x){return (volatile unsigned){x};}
unsigned record(unsigned x){return ((struct V){x}).x;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body)
            for root in ('scalar','record'):self.reject(Analyzer(tree).analyze(root),'volatile_memory')

    def test_volatile_automatic_scalars_need_initialization_and_ownership(self):
        body='''unsigned initialized(unsigned x){volatile unsigned y=x;return x;}
unsigned write(unsigned x){volatile unsigned y;y=x;return x;}
unsigned read(void){volatile unsigned y;return y;}
unsigned pointer(unsigned x){unsigned *volatile p=&x;return x;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body)
            initialized=Analyzer(tree).analyze('initialized');self.assertFalse(initialized['blockers'])
            self.assertEqual(len(initialized['local_volatile_storage_proofs']),1)
            assigned=Analyzer(tree).analyze('write');self.assertFalse(assigned['blockers'])
            self.assertEqual(assigned['local_volatile_storage_proofs'][0]['kind'],'definitely_assigned_nonescaping_volatile_scalar')
            for root in ('read','pointer'):self.reject(Analyzer(tree).analyze(root),'volatile_memory')

    def test_atomic_locals_block_but_pointee_qualifiers_do_not_qualify_pointer_storage(self):
        body='''unsigned atomic(unsigned x){_Atomic(unsigned) y=x;return x;}
unsigned atomic_pointer(unsigned x){_Atomic(unsigned *) p=&x;return x;}
unsigned pointer(void){volatile unsigned *p=0;return 1;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body);self.reject(Analyzer(tree).analyze('atomic'),'architecture_or_ordering')
            self.reject(Analyzer(tree).analyze('atomic_pointer'),'architecture_or_ordering')
            self.assertFalse(Analyzer(tree).analyze('pointer')['blockers'])

    def test_file_scope_literals_are_not_automatic(self):
        body='struct Obj *global=&(struct Obj){3,0};unsigned root(void){return global->value;}'
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body);a=Analyzer(tree);literal=next(n for n in walk(tree) if n.get('kind')=='CompoundLiteralExpr')
            self.assertNotIn(literal['id'],a.automatic_compound_literals);self.assertEqual(a.resolve(literal,{},['root']),set())
            p=a.analyze('root');self.assertEqual({r['path'] for r in p['entry_reads']},{'global:global','global:global->value'})
            with self.assertRaises(ValueError):capture_header([p])

    def test_literal_identities_are_distinct_repeatable_and_input_is_immutable(self):
        body='unsigned root(void){return (unsigned[]){1,2}[0]+(unsigned[]){3,4}[1];}'
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);tree=self.parse(stage,body);before=copy.deepcopy(tree);a=Analyzer(tree);p=a.fresh().analyze('root')
            paths={r['paths'][0] for r in p['memory_ranges']};self.assertEqual(len(paths),2)
            self.assertEqual(p,a.fresh().analyze('root'));self.assertEqual(tree,before)
            self.assertEqual(paths,{r['paths'][0] for r in Analyzer(self.parse(stage,body)).analyze('root')['memory_ranges']})

    def test_merged_function_scopes_and_escaped_addresses_remain_distinct(self):
        sources={'a.c':'''unsigned helper(void);unsigned root(void){return (unsigned[]){1,2}[0]+helper();}
unsigned read(struct Obj*p){return p->value;}unsigned escape(void){return read(&(struct Obj){1,0});}
''','b.c':'''unsigned helper(void){return (unsigned[]){3,4}[1];}'''}
        with tempfile.TemporaryDirectory() as tmp:
            tree=local_effects.LocalEffectTests().parse(Path(tmp),sources);p=Analyzer(tree,POLICY).analyze('root');self.assertFalse(p['blockers'])
            self.assertEqual(len({r['paths'][0] for r in p['memory_ranges']}),2);capture_header([p])
            self.reject(Analyzer(tree,POLICY).analyze('escape'),'unresolved_local_pointer')

    def test_discarded_literal_initializers_do_not_add_effects(self):
        body='''unsigned external(void);
unsigned root(void){return __builtin_choose_expr(1,(unsigned[]){current()->value}[0],(unsigned[]){external()}[0]);}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body),POLICY).analyze('root');self.assertFalse(p['blockers'])
            self.assertNotIn('external',{c['callee'] for c in p['call_sites']});capture_header([p])


if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=local_effects.CLANG=sys.argv.pop()
    unittest.main()
