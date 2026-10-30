"""Fixed numeric arrays require pure definitions and proved scalar selections."""
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import test_entry_state as basic
import test_entry_state_local_effects as local_effects
from entry_state import Analyzer,capture_header,entry_accesses,digest
from automated_entry_state import validate_snapshot
import json


class ConstantArrayTests(unittest.TestCase):
    def parse(self,stage,body):return basic.EntryStateTests().parse(stage,body)[0]

    def reject(self,plan,kind=None):
        if kind:self.assertIn(kind,{b['kind'] for b in plan['blockers']})
        with self.assertRaises(ValueError):capture_header([plan])

    def test_numeric_arrays_and_nested_extents_retain_reads_and_bounds(self):
        body='''static const double values[2]={1.0,-2.0};const unsigned matrix[2][2]={{1,2},{3,4}};
double root(void){return values[1]+matrix[1][0];}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body)).analyze('root');self.assertFalse(p['blockers']);self.assertTrue(p['memory_ranges'])
            self.assertEqual({r['path'] for r in p['entry_reads']},{'global:values[1]','global:matrix[1][0]'})
            self.assertFalse(entry_accesses(p));capture_header([p]);validate_snapshot({'format':'osrec-entry-snapshot-v1','objects':[],'roots':[],'fields':[]},p)

    def test_designated_partial_and_empty_initializers_are_fixed_without_expansion(self):
        body='''const unsigned values[4]={[2]=7};const int matrix[2][2]={{1},{2,3}};const int empty[1024]={};
unsigned root(void){return values[0]+values[2]+matrix[0][1]+empty[3];}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body)).analyze('root');self.assertFalse(p['blockers']);self.assertFalse(entry_accesses(p));capture_header([p])
            self.assertTrue(any('array_filler' in r['immutable_global']['initializer'] for r in p['entry_reads']))

    def test_dynamic_and_out_of_bounds_selections_still_block(self):
        body='''const unsigned values[2]={1,2};
unsigned dynamic(unsigned n){return values[n];}unsigned outside(void){return values[2];}unsigned negative(void){return values[-1];}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body)
            self.reject(Analyzer(tree).analyze('dynamic'),'dynamic_extent')
            for root in ('outside','negative'):self.reject(Analyzer(tree).analyze(root),'array_bounds')

    def test_pointer_views_do_not_borrow_array_bounds(self):
        body='''const unsigned values[2]={1,2};
unsigned cast(void){return ((const unsigned*)values)[0];}unsigned pointer(void){const unsigned*p=values;return p[0];}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body)
            self.reject(Analyzer(tree).analyze('cast'),'dynamic_extent')
            p=Analyzer(tree).analyze('pointer');self.assertFalse(p['blockers'],p['blockers'])
            self.assertTrue(p['entry_reads'][0]['immutable_global']);capture_header([p])

    def test_mutable_extern_and_volatile_arrays_do_not_gain_evidence(self):
        body='''unsigned mutable[2]={1,2};extern const unsigned missing[2];const volatile unsigned vol[2]={1,2};
unsigned a(void){return mutable[0];}unsigned b(void){return missing[0];}unsigned c(void){return vol[0];}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body)
            for root in ('a','b','c'):
                p=Analyzer(tree).analyze(root);self.assertFalse(any('immutable_global' in r for r in p['entry_reads']));self.reject(p)

    def test_pointer_arrays_strings_and_record_members_remain_ineligible(self):
        body='''unsigned x;unsigned*const pointers[2]={&x,&x};const char text[]="ab";
struct S{unsigned values[2];};const struct S record={{1,2}};
unsigned a(void){return *pointers[0];}unsigned b(void){return text[0];}unsigned c(void){return record.values[0];}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body)
            for root in ('a','b'):
                p=Analyzer(tree).analyze(root);self.assertFalse(any('immutable_global' in r for r in p['entry_reads']));self.reject(p)
            p=Analyzer(tree).analyze('c');self.assertFalse(entry_accesses(p));capture_header([p])
            self.assertEqual(p['entry_reads'][0]['immutable_global']['kind'],'defined_const_numeric_record')

    def test_writes_to_any_element_of_the_const_object_prevent_omission(self):
        body='''const unsigned values[2]={1,2};unsigned root(void){*(unsigned*)values=3;return values[1];}'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body)).analyze('root')
            self.assertIn('pointer_arithmetic',{b['kind'] for b in p['blockers']})
            with self.assertRaises(ValueError):capture_header([p])

    def test_tampered_indexes_types_and_initializer_shape_fail_closed(self):
        body='const unsigned values[2]={1,2};unsigned root(void){return values[0];}'
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body)).analyze('root')
            for path in ('global:values[2]','global:values[-1]','global:values','global:values[0][0]','global:values[0]->x'):
                q=copy.deepcopy(p);q['entry_reads'][0]['path']=path;self.reject(q)
            q=copy.deepcopy(p);q['entry_reads'][0]['type']='unsigned int';self.reject(q)
            q=copy.deepcopy(p);proof=q['entry_reads'][0]['immutable_global'];proof['initializer']['inner'].append(proof['initializer']['inner'][0]);proof['initializer_sha256']=digest(json.dumps(proof['initializer'],sort_keys=True).encode());self.reject(q)

    def test_nonconstant_initializer_terms_do_not_gain_evidence(self):
        body='const unsigned values[2]={1,2};unsigned root(void){return values[0];}'
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body);decl=next(n for n in tree['inner'] if n.get('kind')=='VarDecl')
            decl['inner'][0]['inner'][1]={'kind':'CallExpr','type':{'qualType':'unsigned int'},'inner':[]}
            p=Analyzer(tree).analyze('root');self.assertNotIn('immutable_global',p['entry_reads'][0]);self.reject(p)

    def test_merged_static_arrays_and_fresh_roots_remain_distinct(self):
        sources={'a.c':'''static const unsigned values[2]={1,2};unsigned helper(void);unsigned root(void){return values[0]+helper();}''',
                 'b.c':'''static const unsigned values[2]={3,4};unsigned helper(void){return values[1];}'''}
        with tempfile.TemporaryDirectory() as tmp:
            tree=local_effects.LocalEffectTests().parse(Path(tmp),sources);before=copy.deepcopy(tree);a=Analyzer(tree);p=a.fresh().analyze('root')
            self.assertFalse(p['blockers']);self.assertEqual(len({r['immutable_global']['object'] for r in p['entry_reads']}),2);capture_header([p])
            self.assertEqual(p,a.fresh().analyze('root'));self.assertEqual(tree,before)

    def test_native_hook_preserves_fixed_table_behavior_without_input_fields(self):
        body='const unsigned values[4]={[2]=7};unsigned root(void){return values[0]+values[2];}'
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);p=Analyzer(self.parse(stage,body)).analyze('root');(stage/'capture.h').write_text(capture_header([p]))
            source=stage/'run.c';source.write_text(body+'''\n#include <assert.h>
#include "capture.h"
int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s));assert(s.field_count==0&&s.object_count==0);assert(root()==7);return 0;}
''');binary=stage/'run'
            subprocess.run([basic.CLANG,'-std=gnu11','-I',str(basic.ROOT/'include'),'-I',str(stage),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True,text=True)
            subprocess.run([str(binary)],check=True,capture_output=True)


if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=local_effects.CLANG=sys.argv.pop()
    unittest.main()
