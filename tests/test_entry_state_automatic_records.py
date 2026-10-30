"""Automatic record storage is distinct from initializer alias values."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest

import test_entry_state as basic
from entry_state import Analyzer,capture_header
import test_entry_state_local_effects as local_effects
POLICY=local_effects.POLICY


class AutomaticRecordTests(unittest.TestCase):
    def parse(self,stage,body):return basic.EntryStateTests().parse(stage,body)[0]

    def reject(self,plan,kind):
        self.assertIn(kind,{b['kind'] for b in plan['blockers']})
        with self.assertRaises(ValueError):capture_header([plan])

    def test_initialized_scalar_unions_and_structs_keep_automatic_storage(self):
        body='''typedef union {double f;unsigned long long bits;} Bits;
struct Pair{unsigned a,b;};
unsigned named(unsigned x){struct Pair p={x,2};p.a+=p.b;return p.a;}
unsigned anonymous(unsigned x){union{unsigned x;unsigned char bytes[4];}u={x};return u.x;}
unsigned alias(double x){const Bits u={x};return u.bits>>32;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body);before=copy.deepcopy(tree);index=Analyzer(tree)
            for root in ('named','anonymous','alias'):
                p=index.fresh().analyze(root)
                self.assertFalse(p['blockers']);self.assertFalse(p['entry_reads']);self.assertFalse(p['state_writes']);capture_header([p])
            self.assertEqual(tree,before)

    def test_initializer_and_later_assignment_effects_are_retained(self):
        body='''unsigned input,output;struct Pair{unsigned a,b;};
unsigned root(void){struct Pair p={input,1};p=(struct Pair){input,output=3};output=p.a;return p.b;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body)).analyze('root')
            self.assertFalse(p['blockers']);self.assertEqual({r['path'] for r in p['entry_reads']},{'global:input'})
            self.assertEqual({r['path'] for r in p['state_writes']},{'global:output'})
            with self.assertRaises(ValueError):capture_header([p])

    def test_local_pointer_members_track_values_until_the_record_escapes(self):
        body='''struct Obj{unsigned value;};struct Obj *current(void);void keep(struct Box *);
struct Box{struct Obj *p;};
unsigned arrow(void){struct Box b={current()};return b.p->value;}
unsigned dereference(void){struct Box b={current()};return *(&b.p->value);}
unsigned escaped(void){struct Box b={current()};keep(&b);return b.p->value;}
unsigned field_address(void){struct Box b={current()};struct Obj **q=&b.p;return b.p->value;}
unsigned field_store(void){struct Box b={current()};struct Obj **q=&b.p;*q=0;return b.p->value;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body)
            for root,path in (('arrow','current()->value'),('dereference','*(current()->value)')):
                plan=Analyzer(tree,POLICY).analyze(root)
                self.assertFalse(plan['blockers'],plan['blockers'])
                self.assertEqual({r['path'] for r in plan['entry_reads']},{path})
            # An address passed to code without a body leaves the pointer fields unknown.
            self.reject(Analyzer(tree,POLICY).analyze('escaped'),'unresolved_pointer_origin')
            # A pointer to one field stores into the same tracked field.
            p=Analyzer(tree,POLICY).analyze('field_address');self.assertFalse(p['blockers'],p['blockers'])
            self.reject(Analyzer(tree,POLICY).analyze('field_store'),'unresolved_pointer_origin')

    def test_function_pointer_members_remain_unresolved_callbacks(self):
        body='''unsigned target(void){return 1;}struct Box{unsigned(*fn)(void);};
unsigned root(void){struct Box b={target};return b.fn();}
'''
        with tempfile.TemporaryDirectory() as tmp:self.reject(Analyzer(self.parse(Path(tmp),body)).analyze('root'),'indirect_call')

    def test_storage_duration_volatile_and_cleanup_effects_still_block(self):
        body='''struct Pair{unsigned a;};struct Vol{volatile unsigned a;};void clean(struct Pair*);
unsigned persistent(void){static struct Pair p={1};return ++p.a;}
unsigned thread(void){static _Thread_local struct Pair p={1};return p.a;}
unsigned cleanup(void){struct Pair p __attribute__((cleanup(clean)))={1};return p.a;}
unsigned qualified(void){volatile struct Pair p={1};return p.a;}
unsigned member(void){struct Vol p={1};return p.a;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body)
            for root in ('persistent','thread','cleanup'):self.reject(Analyzer(tree).analyze(root),'unsupported_construct')
            self.reject(Analyzer(tree).analyze('qualified'),'unresolved_memory')
            self.reject(Analyzer(tree).analyze('member'),'volatile_memory')

    def test_copying_global_records_keeps_aggregate_reads(self):
        body='''struct Pair{unsigned a,b;};struct Pair input,other;
unsigned root(void){struct Pair p=input;p=other;return p.a;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body)).analyze('root')
            self.assertEqual({r['path'] for r in p['entry_reads']},{'global:input','global:other'})
            self.assertTrue(all(r['type']=='struct Pair' for r in p['entry_reads']))
            with self.assertRaises(ValueError):capture_header([p])

    def test_nested_records_and_fixed_local_arrays_keep_storage_bounds(self):
        body='''struct Pair{unsigned a;};struct Outer{struct Pair p;unsigned values[2];};
unsigned root(unsigned x){struct Outer p={{x},{1,2}};struct Pair a[2]={{x},{3}};return p.p.a+p.values[1]+a[0].a;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body)).analyze('root');self.assertFalse(p['blockers']);self.assertTrue(p['memory_ranges']);capture_header([p])

    def test_merged_typedefs_and_escaped_local_addresses_remain_distinct(self):
        sources={'a.c':'''typedef struct{unsigned a;} Value;unsigned helper(void);
unsigned root(void){Value x={2};return x.a+helper();}
unsigned read(struct Obj*p){return p->value;}
unsigned escape(void){struct Obj x={1,0};return read(&x);}
''','b.c':'''typedef union{double f;unsigned long long bits;} Value;
unsigned helper(void){Value x={1.0};return x.bits>>32;}
'''}
        with tempfile.TemporaryDirectory() as tmp:
            tree=local_effects.LocalEffectTests().parse(Path(tmp),sources)
            p=Analyzer(tree,POLICY).analyze('root');self.assertFalse(p['blockers']);capture_header([p])
            # A callee reading the caller's stack object through its address reads local storage.
            p=Analyzer(tree,POLICY).analyze('escape');self.assertFalse(p['blockers'],p['blockers']);self.assertFalse(p['entry_reads'])


if __name__=='__main__':
    if len(sys.argv)==2:
        basic.CLANG=sys.argv.pop()
        import test_entry_state_local_effects as local_effects
        local_effects.CLANG=basic.CLANG
    unittest.main()
