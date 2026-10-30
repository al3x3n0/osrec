"""Incomplete array declarations may borrow only compatible configured bounds."""
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import test_entry_state_global_arrays as arrays
import test_entry_state as basic
from entry_state import Analyzer,capture_header,variably_modified_type

class IncompleteArrayTests(unittest.TestCase):
    def parse(self,stage,files):return arrays.GlobalArrayTests().parse(stage,files)

    def test_unknown_extent_is_not_a_vla_but_access_remains_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=Analyzer(self.parse(Path(tmp),{'root.c':'extern unsigned data[];unsigned root(void){return data[0];}'}))
            p=a.analyze('root');self.assertNotIn('unsupported_construct',{b['kind'] for b in p['blockers']})
            self.assertIn('dynamic_extent',{b['kind'] for b in p['blockers']});self.assertFalse(p['memory_ranges'])
            with self.assertRaises(ValueError):capture_header([p])

    def test_later_definition_completes_earlier_reference(self):
        text='extern unsigned data[];unsigned root(void){return data[2];}unsigned data[4];'
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),{'root.c':text});p=Analyzer(tree).analyze('root');self.assertFalse(p['blockers'])
            self.assertEqual({r['path'] for r in p['entry_reads']},{'global:data[2]'})
            proof=p['memory_ranges'][0]['array_type_evidence'];self.assertEqual(proof['type'],'unsigned int[4]')
            self.assertEqual({r['type'] for r in proof['declarations']},{'unsigned int[]','unsigned int[4]'})
            # A storage bound supplies no global capture adapter.
            with self.assertRaises(ValueError):capture_header([p])

    def test_complete_declaration_can_supply_bound_without_inventing_definition(self):
        text='extern unsigned data[];unsigned root(void){return data[1];}extern unsigned data[3];'
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),{'root.c':text})).analyze('root');self.assertFalse(p['blockers'])
            self.assertEqual(p['memory_ranges'][0]['elements'],3)

    def test_loaded_translation_unit_completion_and_volatile_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),{'root.c':'extern unsigned data[];extern volatile unsigned device[];unsigned root(void){return data[1];}unsigned mmio(void){return device[0];}',
                                      'storage.c':'unsigned data[2];volatile unsigned device[1];'})
            a=Analyzer(tree);p=a.fresh().analyze('root');self.assertFalse(p['blockers'])
            self.assertEqual(p['memory_ranges'][0]['elements'],2)
            p=a.fresh().analyze('mmio');self.assertIn('volatile_memory',{b['kind'] for b in p['blockers']})
            self.assertNotIn('unsupported_construct',{b['kind'] for b in p['blockers']})

    def test_conflicting_loaded_declarations_do_not_supply_a_bound(self):
        for storage in ('unsigned data[2];unsigned helper(void){return 0;}',
                        'long data[3];unsigned helper(void){return 0;}',
                        'unsigned data[3][2];unsigned helper(void){return 0;}'):
            with self.subTest(storage=storage),tempfile.TemporaryDirectory() as tmp:
                # Use a reference before any completion to exercise the incomplete type.
                tree=self.parse(Path(tmp),{'root.c':'extern unsigned data[];unsigned root(void){return data[0];}extern unsigned data[3];', 'storage.c':storage})
                p=Analyzer(tree).analyze('root')
                self.assertIn('dynamic_extent',{b['kind'] for b in p['blockers']});self.assertFalse(p['memory_ranges'])

    def test_static_object_in_another_unit_cannot_complete_external(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),{'root.c':'extern unsigned data[];unsigned root(void){return data[0];}',
                                      'storage.c':'static unsigned data[4];unsigned helper(void){return data[0];}'})
            a=Analyzer(tree);p=a.fresh().analyze('root');self.assertIn('dynamic_extent',{b['kind'] for b in p['blockers']})
            self.assertFalse(a.fresh().analyze('helper')['blockers'])

    def test_typedefs_are_compared_in_their_configured_translation_unit(self):
        for other,compatible in (('unsigned',True),('unsigned long',False)):
            with self.subTest(other=other),tempfile.TemporaryDirectory() as tmp:
                tree=self.parse(Path(tmp),{'root.c':'typedef unsigned Count;extern Count data[];unsigned root(void){return data[0];}',
                                          'storage.c':f'typedef {other} Count;Count data[3];'})
                p=Analyzer(tree).analyze('root')
                if compatible:
                    self.assertFalse(p['blockers']);self.assertEqual(p['memory_ranges'][0]['array_type_evidence']['type'],'unsigned int[3]')
                else:self.assertIn('dynamic_extent',{b['kind'] for b in p['blockers']})

    def test_multidimensional_bounds_and_out_of_bounds_are_preserved(self):
        text='extern unsigned data[][3];unsigned root(unsigned i){return data[i%2][2];}unsigned bad(void){return data[2][0];}unsigned data[2][3];'
        with tempfile.TemporaryDirectory() as tmp:
            a=Analyzer(self.parse(Path(tmp),{'root.c':text}));p=a.fresh().analyze('root');self.assertFalse(p['blockers'])
            self.assertEqual({r['path'] for r in p['entry_reads']},{'global:data[0][2]','global:data[1][2]'})
            self.assertIn('array_bounds',{b['kind'] for b in a.fresh().analyze('bad')['blockers']})

    def test_pointer_casts_and_pointer_variables_do_not_borrow_bounds(self):
        text='extern unsigned data[];unsigned cast(void){return ((unsigned*)data)[0];}unsigned alias(void){unsigned*p=data;return p[0];}unsigned data[4];'
        with tempfile.TemporaryDirectory() as tmp:
            a=Analyzer(self.parse(Path(tmp),{'root.c':text}))
            p=a.fresh().analyze('cast');self.assertIn('dynamic_extent',{b['kind'] for b in p['blockers']});self.assertFalse(p['memory_ranges'])
            p=a.fresh().analyze('alias');self.assertFalse(p['blockers'],p['blockers'])
            self.assertEqual({r['path'] for r in p['entry_reads']},{'global:data[0]'})
            self.assertEqual(p['memory_ranges'][0]['array_type_evidence']['type'],'unsigned int[4]')

    def test_real_variable_bounds_and_unevaluated_pointer_sizes_remain_conservative(self):
        text='unsigned external(void);unsigned root(unsigned n){unsigned a[n];a[0]=1;return a[0];}unsigned effect(void){return sizeof(unsigned[external()]);}unsigned pointer(unsigned n){return sizeof(unsigned(*)[n]);}'
        with tempfile.TemporaryDirectory() as tmp:
            a=Analyzer(self.parse(Path(tmp),{'root.c':text}))
            for root in ('root','effect','pointer'):
                p=a.fresh().analyze(root);self.assertIn('unsupported_construct',{b['kind'] for b in p['blockers']})
                with self.assertRaises(ValueError):capture_header([p])
            self.assertFalse(variably_modified_type('unsigned int[]'));self.assertFalse(variably_modified_type('unsigned int (*)[]'))
            self.assertTrue(variably_modified_type('unsigned int (*)[*]'))

    def test_flexible_member_and_incomplete_array_pointer_keep_unknown_extent(self):
        text='struct Obj{unsigned n;unsigned data[];};unsigned flex(struct Obj*p){return p->data[0];}unsigned ptr(unsigned(*p)[]){return (*p)[0];}'
        with tempfile.TemporaryDirectory() as tmp:
            a=Analyzer(self.parse(Path(tmp),{'root.c':text}))
            for root in ('flex','ptr'):
                p=a.fresh().analyze(root);self.assertIn('dynamic_extent',{b['kind'] for b in p['blockers']})
                self.assertNotIn('unsupported_construct',{b['kind'] for b in p['blockers']})

    def test_fresh_analysis_keeps_ast_and_declaration_evidence_unchanged(self):
        text='extern unsigned data[];unsigned root(void){return data[0];}unsigned other(void){return data[1];}unsigned data[2];'
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),{'root.c':text});before=copy.deepcopy(tree);a=Analyzer(tree);p=a.fresh().analyze('root');a.fresh().analyze('other')
            self.assertEqual(a.fresh().analyze('root'),p);self.assertEqual(tree,before)

    def test_completed_cross_file_access_matches_native_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);tree=self.parse(stage,{'root.c':'extern unsigned data[];unsigned root(void){return data[2];}',
                                                'storage.c':'unsigned data[3]={1,2,9};'})
            p=Analyzer(tree).analyze('root');self.assertFalse(p['blockers'])
            self.assertEqual({r['path'] for r in p['entry_reads']},{'global:data[2]'})
            (stage/'main.c').write_text('#include <assert.h>\nunsigned root(void);int main(void){assert(root()==9);return 0;}\n')
            binary=stage/'native'
            subprocess.run([arrays.CLANG,str(stage/'root.c'),str(stage/'storage.c'),str(stage/'main.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)

    def test_static_index_cache_keeps_plans_and_fresh_roots_equivalent(self):
        from unittest.mock import patch
        import entry_state_constants as constants
        text='extern unsigned data[];unsigned helper(unsigned x){return data[1+2]+data[x];}unsigned root(void){return helper(0)+helper(1);}unsigned data[4];'
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),{'root.c':text});a=Analyzer(tree)
            with patch.object(constants,'constant_index',wraps=constants.constant_index) as fold:
                plan=a.fresh().analyze('root');cached_calls=fold.call_count
            with patch.object(constants,'constant_index',wraps=constants.constant_index) as fold:
                other=Analyzer(tree,cache_alias_syntax=False).analyze('root');uncached_calls=fold.call_count
            self.assertEqual(plan,other);self.assertLess(cached_calls,uncached_calls)
            self.assertEqual(a.fresh().analyze('root'),plan)

if __name__=='__main__':
    if len(sys.argv)==2:arrays.CLANG=basic.CLANG=sys.argv.pop()
    unittest.main()
