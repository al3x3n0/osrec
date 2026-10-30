"""Single-definition integer locals carry bounded values, not repeated effects."""
import copy,json,subprocess,sys,tempfile
from pathlib import Path
import unittest
import test_entry_state as basic
from entry_state import Analyzer,capture_header
MODEL='struct Obj{unsigned a[4];unsigned calls;};struct Obj*current(void);\n'
class LocalIndexTests(unittest.TestCase):
    def plan(self,text,**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree)
            a=Analyzer(tree,basic.POLICY,**options);p=a.analyze('root')
            self.assertEqual(tree,before);self.assertEqual(p,a.fresh().analyze('root'))
            self.assertNotIn('bounded-pointer:',json.dumps(p));return p
    def positive(self,text):
        p=self.plan(text);self.assertFalse(p['blockers'],p['blockers']);capture_header([p])
        self.assertTrue(p['local_index_proofs']);return p
    def test_initializer_copies_modulus_and_pointer_offsets(self):
        p=self.positive(MODEL+'''unsigned root(unsigned n){const unsigned limit=4;unsigned i=n%limit;const unsigned j=i;
unsigned*p=current()->a;return p[j]+*(current()->a+j);}''')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->a['+str(i)+']' for i in range(4)})
        names={v['variable'] for x in p['local_index_proofs'] for v in x['proof']['locals']}
        self.assertTrue({'limit','i','j'}<=names)
    def test_single_assignment_and_preserving_signed_conversion(self):
        p=self.positive(MODEL+'unsigned root(unsigned n){int i;i=n%4u;return current()->a[i];}')
        self.assertEqual(len(p['entry_reads']),4)
        self.assertTrue(any(x['proof']['range_evidence']['kind']=='value_preserving_32bit_integral_conversion' for x in p['local_index_proofs']))
    def test_constants_and_enums(self):
        p=self.positive(MODEL+'enum{COUNT=4};unsigned root(unsigned n){const unsigned i=n%COUNT;return current()->a[i];}')
        self.assertEqual(len(p['entry_reads']),4)
        p=self.positive(MODEL+'unsigned root(void){const unsigned i=2;return current()->a[i];}')
        self.assertEqual(p['entry_reads'][0]['path'],'current()->a[2]')
    def test_mutation_escape_volatile_and_unknown_values_stay_blocked(self):
        bodies=(
            'unsigned i=n&3u;i=9;return current()->a[i];',
            'unsigned i=n&3u;++i;return current()->a[i];',
            'unsigned i=n&3u;mutate(&i);return current()->a[i];',
            'volatile unsigned i=n&3u;return current()->a[i];',
            'unsigned i=n;return current()->a[i];',
            'unsigned i=i&3u;return current()->a[i];',
            'unsigned i,j;i=j&3u;j=i&3u;return current()->a[i];',
            'unsigned i=(unsigned char)n;return current()->a[i];',
        )
        for body in bodies:
            with self.subTest(body=body):
                p=self.plan(MODEL+'void mutate(unsigned*p){*p=9;}unsigned root(unsigned n){'+body+'}')
                self.assertTrue(p['blockers'],p)
                with self.assertRaises(ValueError):capture_header([p])
    def test_skipped_initialization_and_unbounded_signed_values(self):
        texts=(
            MODEL+'unsigned root(unsigned n){goto use;unsigned i=n&3u;use:return current()->a[i];}',
            MODEL+'unsigned root(unsigned n){unsigned i;if(n)i=n&3u;return current()->a[i];}',
            MODEL+'unsigned root(int n){int i=n%4;return current()->a[i];}',
            MODEL+'unsigned root(unsigned n){int i=n&0xffffffffu;return current()->a[i];}',
        )
        for text in texts:
            with self.subTest(text=text):self.assertTrue(self.plan(text)['blockers'])
    def test_no_clamping_and_existing_caps(self):
        for body in ('unsigned i=4;','int i=-1;','unsigned i=n&7u;'):
            with self.subTest(body=body):
                p=self.plan(MODEL+'unsigned root(unsigned n){'+body+'return current()->a[i];}')
                self.assertIn('array_bounds',{b['kind'] for b in p['blockers']})
        text=MODEL+'unsigned root(unsigned n){unsigned i=n&3u;unsigned*p=current()->a+i;return *p;}'
        p=self.plan(text,max_alias_paths=2);self.assertTrue(p['analysis_limits']['alias_path_limit_observed'])
        p=self.plan(text,max_range_elements=2);self.assertIn('range_limit',{b['kind'] for b in p['blockers']})
    def test_initializer_effects_remain_in_the_plan(self):
        text=MODEL+'unsigned external(void);unsigned root(void){unsigned i=external()&3u;return current()->a[i];}'
        p=self.plan(text);self.assertIn('unmodeled_external',{b['kind'] for b in p['blockers']})
        self.assertEqual([c['callee'] for c in p['call_sites']].count('external'),1)
        self.assertTrue(p['local_index_proofs'])
    def test_loaded_helper_and_constant_array_evidence(self):
        import test_entry_state_global_arrays as arrays
        with tempfile.TemporaryDirectory() as tmp:
            tree=arrays.GlobalArrayTests().parse(Path(tmp),{
                'root.c':'unsigned helper(unsigned);unsigned root(unsigned n){return helper(n);}',
                'helper.c':'static const unsigned a[4]={11,22,33,44};unsigned helper(unsigned n){unsigned i=n&3u;return a[i];}'})
            p=Analyzer(tree).analyze('root');self.assertFalse(p['blockers'],p['blockers']);capture_header([p])
            self.assertEqual(len(p['entry_reads']),4);self.assertTrue(all(r['immutable_global'] for r in p['entry_reads']))
            self.assertTrue(p['local_index_proofs'])
    def test_syntax_cache_controls_and_range_after_a_helper_return(self):
        text=MODEL+'unsigned*get(void){return current()->a;}unsigned root(unsigned n){unsigned i=n&3u;return get()[i];}'
        p=self.positive(text);other=self.plan(text,cache_alias_syntax=False)
        self.assertEqual(p,other);self.assertTrue(p['pointer_return_proofs'])
    def test_native_initializer_executes_once_per_call(self):
        text=MODEL+'''unsigned next(void){return current()->calls++;}
unsigned root(void){unsigned i=next()&3u;return current()->a[i];}'''
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);tree=basic.EntryStateTests().parse(stage,text)[0]
            p=Analyzer(tree,basic.POLICY).analyze('root');self.assertFalse(p['blockers'],p['blockers'])
            (stage/'capture.h').write_text(capture_header([p]));source=stage/'native.c'
            source.write_text(text+'''
#include "capture.h"
static struct Obj object={{11,22,33,44},0};struct Obj*current(void){return &object;}
int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);if(!osrec_snapshot_root(&s)||s.field_count!=5||object.calls)return 1;
if(root()!=11||root()!=22||object.calls!=2)return 2;return 0;}
''')
            exe=stage/'native';subprocess.run([basic.CLANG,'-std=c11','-I',str(basic.ROOT/'include'),'-I',str(stage),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(exe)],check=True,capture_output=True)
            subprocess.run([str(exe)],check=True,timeout=10)
if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
