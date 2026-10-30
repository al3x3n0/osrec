"""Immediate array offsets reuse subscript proofs; raw pointer arithmetic blocks."""
from pathlib import Path
import copy
import subprocess
import sys
import tempfile
import unittest
import test_entry_state as basic
from entry_state import Analyzer,capture_header

class PointerArithmeticTests(unittest.TestCase):
    def parse(self,stage,text):return basic.EntryStateTests().parse(stage,text)[0]
    def test_storage_forms_and_counted_loop(self):
        text='''struct Row { unsigned value; }; struct Obj { unsigned data[4]; struct Row rows[3]; unsigned matrix[2][3]; };struct Obj *current(void);
unsigned root(unsigned n){ unsigned sum=*(current()->data+(n%4));
 sum+=*(1+current()->data);sum+=(current()->rows+1)->value;
 sum+=(*(current()->rows+2)).value;
 sum+=*(*(current()->matrix+1)+2);
 for(unsigned i=0;i<4;i++)sum+=*(current()->data+i);
 *(current()->data+2)=7;(*(current()->data+3))++;
 return sum;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),text);before=copy.deepcopy(tree)
            p=Analyzer(tree,basic.POLICY).analyze('root')
            self.assertFalse(p['blockers'],p['blockers']);self.assertEqual(tree,before)
            reads={r['path'] for r in p['entry_reads']}
            self.assertTrue({'current()->data['+str(i)+']' for i in range(4)}<=reads)
            self.assertTrue({'current()->rows[1].value','current()->rows[2].value','current()->matrix[1][2]'}<=reads)
            self.assertEqual({r['path'] for r in p['state_writes']},{'current()->data[2]','current()->data[3]'})
            self.assertTrue(any(r.get('index_proof',{}).get('kind')=='canonical_for_induction' for r in p['memory_ranges']))
            self.assertTrue(any(r.get('access_form')=='array_pointer_offset' for r in p['memory_ranges']))
            # Record-array field export retains the existing schema restriction.
            with self.assertRaises(ValueError):capture_header([p])
            self.assertEqual(p,Analyzer(tree,basic.POLICY).fresh().analyze('root'))

    def test_automatic_and_const_global(self):
        text='''const unsigned data[3]={4,5,6};unsigned root(void){unsigned a[3]={1,2,3};return *(a+1)+*(data+2);}'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),text)).analyze('root');self.assertFalse(p['blockers'],p['blockers'])
            self.assertEqual({r['path'] for r in p['entry_reads']},{'global:data[2]'})
            self.assertIn('immutable_global',p['entry_reads'][0]);capture_header([p])

    def test_unsupported_offsets_fail_closed(self):
        cases={
            'unsigned a[4];return *(a+4);':'array_bounds',
            'unsigned a[4];return *(a+n);':'dynamic_extent',
            'unsigned a[4];return *(a+(n&7));':'array_bounds',
            'unsigned a[4];return *((unsigned*)a+1);':'pointer_arithmetic',
            'unsigned a[4];return *(a-1);':'pointer_arithmetic',
            'unsigned a[4];return &*(a+9)==a;':'pointer_arithmetic',
            'volatile unsigned a[4];return *(a+1);':'dynamic_extent',
        }
        for body,blocker in cases.items():
            with self.subTest(body=body),tempfile.TemporaryDirectory() as tmp:
                p=Analyzer(self.parse(Path(tmp),'unsigned root(unsigned n){'+body+'}')).analyze('root')
                self.assertIn(blocker,{b['kind'] for b in p['blockers']},p)
                with self.assertRaises(ValueError):capture_header([p])

    def test_pointer_difference_and_formation_are_checked_without_memory_access(self):
        text='''long difference(unsigned*p,unsigned*q){return p-q;}
unsigned formation(unsigned*p){return (p+1)!=p;}
unsigned *returned(unsigned*p){return p+1;}
unsigned *cast_return(unsigned*p){return (unsigned*)(p+1);}
unsigned unevaluated(unsigned*p,unsigned*q){return sizeof(p-q)+sizeof(*(p+9));}'''
        with tempfile.TemporaryDirectory() as tmp:
            a=Analyzer(self.parse(Path(tmp),text))
            p=a.fresh().analyze('difference');self.assertIn('pointer difference requires common-array provenance',{b['detail'] for b in p['blockers']})
            self.assertIn('pointer_arithmetic',{b['kind'] for b in a.fresh().analyze('formation')['blockers']})
            for name in ('returned','cast_return'):
                self.assertIn('pointer_arithmetic',{b['kind'] for b in a.fresh().analyze(name)['blockers']})
            self.assertFalse(a.fresh().analyze('unevaluated')['blockers'])

    def test_nested_bounds_effects_and_qualifiers(self):
        text="""struct Obj {unsigned matrix[2][3];volatile unsigned device[2];unsigned data[4];};struct Obj*current(void);
unsigned nested(void){return *(*(current()->matrix+2)+0);}
unsigned device(void){return *(current()->device+1);}
unsigned effect(unsigned n){return *(current()->data+((n++)%4));}
unsigned escaped(void){return &*(current()->data+1)==current()->data;}
unsigned loop(void){unsigned sum=0;for(unsigned i=0;i<4;i++)sum+=*(current()->data+(i+1));return sum;}
"""
        with tempfile.TemporaryDirectory() as tmp:
            a=Analyzer(self.parse(Path(tmp),text),basic.POLICY)
            for name,kind in (("nested","array_bounds"),("device","volatile_memory"),("escaped","pointer_arithmetic"),("loop","array_bounds")):
                p=a.fresh().analyze(name);self.assertIn(kind,{b['kind'] for b in p['blockers']},p)
            p=a.fresh().analyze('effect');self.assertFalse(p['blockers'],p['blockers'])
            # Runtime effects are visited once despite canonicalizing the lvalue.
            self.assertEqual(len(p['call_sites']),1)

    def test_index_effects_are_not_lost(self):
        text="""struct Obj {unsigned data[4];};struct Obj*current(void);unsigned external(void);
unsigned root(void){return *(current()->data+(external()%4));}"""
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),text),basic.POLICY).analyze('root')
            self.assertIn('unmodeled_external',{b['kind'] for b in p['blockers']})
            self.assertEqual([c['callee'] for c in p['call_sites']],['current','external'])

    def test_range_limits_and_completed_array_extent(self):
        text="""extern unsigned data[];unsigned root(void){return *(data+1);}unsigned data[3];
unsigned wide(unsigned n){unsigned a[65];return *(a+(n%65));}
unsigned product(unsigned i,unsigned j){unsigned a[9][9];return *(*(a+(i%9))+(j%9));}
"""
        with tempfile.TemporaryDirectory() as tmp:
            a=Analyzer(self.parse(Path(tmp),text))
            p=a.fresh().analyze('root');self.assertFalse(p['blockers'],p['blockers'])
            self.assertEqual(p['memory_ranges'][0]['array_type_evidence']['type'],'unsigned int[3]')
            for name in ('wide','product'):
                p=a.fresh().analyze(name);self.assertIn('range_limit',{b['kind'] for b in p['blockers']})
                with self.assertRaises(ValueError):capture_header([p])

    def test_loaded_helper_uses_namespaced_array_bound(self):
        import test_entry_state_global_arrays as arrays
        with tempfile.TemporaryDirectory() as tmp:
            tree=arrays.GlobalArrayTests().parse(Path(tmp),{
                'root.c':'unsigned helper(unsigned);unsigned root(unsigned n){return helper(n);}',
                'helper.c':'const unsigned data[4]={11,22,33,44};unsigned helper(unsigned n){return *(data+(n%4));}'})
            p=Analyzer(tree).analyze('root');self.assertFalse(p['blockers'],p['blockers'])
            self.assertEqual({r['path'] for r in p['entry_reads']},{'global:data['+str(i)+']' for i in range(4)})
            self.assertTrue(all(r['location'].get('translation_unit') for r in p['memory_ranges']))
            capture_header([p])

    def test_native_capture_of_provider_array(self):
        text='''struct Obj {unsigned data[4];};struct Obj*current(void);
unsigned root(unsigned n){return *(current()->data+(n%4));}'''
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);p=Analyzer(self.parse(stage,text),basic.POLICY).analyze('root')
            self.assertFalse(p['blockers'],p['blockers']);(stage/'capture.h').write_text(capture_header([p]))
            source=stage/'native.c';source.write_text(text+'''
#include "capture.h"
#include <string.h>
static struct Obj object={{11,22,33,44}};
struct Obj*current(void){return &object;}
int main(void){struct osrec_entry_snapshot state;osrec_snapshot_init(&state);
 if(!osrec_snapshot_root(&state))return 1;
 if(state.field_count!=4)return 2;
 for(unsigned i=0;i<4;i++)if(state.fields[i].size!=sizeof(unsigned)||memcmp(state.fields[i].bytes,&object.data[i],sizeof(unsigned)))return 4;
 for(unsigned i=0;i<4;i++)if(root(i)!=(i+1)*11)return 3;
 return 0;}
''')
            executable=stage/'native'
            subprocess.run([basic.CLANG,'-std=c11','-I',str(basic.ROOT/'include'),'-I',str(stage),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(executable)],check=True,capture_output=True)
            subprocess.run([str(executable)],check=True,timeout=10)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
