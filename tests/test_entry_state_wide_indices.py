"""Wide unsigned reductions prove small index ranges without truncating inputs."""
import copy,json,subprocess,sys,tempfile
from pathlib import Path
import unittest
import test_entry_state as basic
from entry_state import Analyzer,capture_header
MODEL='struct Obj{unsigned a[4];unsigned calls;};struct Obj*current(void);\n'
class WideIndexTests(unittest.TestCase):
    def plan(self,text,flags=(),**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text,flags)[0];before=copy.deepcopy(tree)
            a=Analyzer(tree,basic.POLICY,**options);p=a.analyze('root')
            self.assertEqual(tree,before);self.assertEqual(p,a.fresh().analyze('root'))
            self.assertNotIn('bounded-pointer:',json.dumps(p));return p
    def positive(self,text,**options):
        p=self.plan(text,**options);self.assertFalse(p['blockers'],p['blockers']);capture_header([p])
        self.assertTrue(p['local_index_proofs']);return p
    def test_direct_masks_remainders_and_promoted_enum_constants(self):
        for typ,expression in (('unsigned long','n%4'),('unsigned long long','n&3'),('unsigned long long','n%N')):
            with self.subTest(typ=typ,expression=expression):
                p=self.positive(MODEL+'enum{N=4};unsigned root('+typ+' n){return current()->a['+expression+'];}')
                self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->a['+str(i)+']' for i in range(4)})
    def test_wide_locals_and_value_preserving_narrowing(self):
        for typ in ('unsigned long long','unsigned long','long long','long','int','unsigned int'):
            with self.subTest(typ=typ):
                p=self.positive(MODEL+'unsigned root(unsigned long long n){'+typ+' i=n%4ULL;return current()->a[i];}')
                self.assertEqual(len(p['entry_reads']),4)
    def test_initialized_unknown_bits_are_not_expanded_as_a_float_value(self):
        text=MODEL+'''unsigned long long bits(double x){union{double d;unsigned long long u;}v={.d=x};return v.u;}
unsigned root(double x){double y=x;unsigned long long k=bits(y);y=0;return current()->a[k%4];}'''
        p=self.positive(text)
        self.assertTrue(any(v.get('role')=='initialized_runtime_operand' for x in p['local_index_proofs'] for v in x['proof']['locals']))
    def test_uninitialized_mutated_and_escaped_local_inputs_stay_blocked(self):
        bodies=(
            'unsigned long long k;return current()->a[k%4];',
            'unsigned long long k;if(n)k=n;return current()->a[k%4];',
            'unsigned long long k=n%4;k++;return current()->a[k];',
            'unsigned long long k=n;touch(&k);return current()->a[k%4];',
        )
        for body in bodies:
            with self.subTest(body=body):
                p=self.plan(MODEL+'void touch(unsigned long long*p){*p=9;}unsigned root(unsigned long long n){'+body+'}')
                self.assertTrue(p['blockers'],p)
                with self.assertRaises(ValueError):capture_header([p])
    def test_constants_never_wrap_or_narrow_into_small_bounds(self):
        for typ,minus in (('unsigned int','-1U'),('unsigned long','-1UL'),('unsigned long long','-1ULL')):
            with self.subTest(unsigned_negation=typ):
                p=self.plan(MODEL+'unsigned root(void){unsigned*p=current()->a+1;const '+typ+' i='+minus+';return *(p+i);}')
                self.assertTrue(p['blockers'],p)
                with self.assertRaises(ValueError):capture_header([p])
        expressions=('n%0ULL','n%-1','n%0x100000000ULL','n%(1ULL<<32)',
                     'n%(unsigned long long)(unsigned char)257','n%d','n&~0ULL')
        for expression in expressions:
            with self.subTest(expression=expression):
                p=self.plan(MODEL+'unsigned root(unsigned long long n,unsigned long long d){return current()->a['+expression+'];}')
                self.assertTrue(p['blockers'],p)
        p=self.plan(MODEL+'unsigned root(long long n){return current()->a[n%4LL];}')
        self.assertTrue(p['blockers'])
    def test_existing_extent_alias_and_range_caps(self):
        p=self.plan(MODEL+'unsigned root(unsigned long long n){return current()->a[n%5ULL];}')
        self.assertIn('array_bounds',{b['kind'] for b in p['blockers']})
        text=MODEL+'unsigned root(unsigned long long n){return *(current()->a+(n%4ULL));}'
        p=self.plan(text,max_alias_paths=2);self.assertTrue(p['analysis_limits']['alias_path_limit_observed'])
        text='struct Obj{unsigned a[128];};struct Obj*current(void);unsigned root(unsigned long long n){return current()->a[n%128];}'
        p=self.plan(text);self.assertIn('range_limit',{b['kind'] for b in p['blockers']})
        self.positive(text,max_range_elements=128)
    def test_unknown_external_effects_are_not_dropped(self):
        p=self.plan(MODEL+'unsigned long long external(void);unsigned root(void){return current()->a[external()%4ULL];}')
        self.assertIn('unmodeled_external',{b['kind'] for b in p['blockers']})
        self.assertEqual([c['callee'] for c in p['call_sites']].count('external'),1)
    def test_unsigned_long_bounds_are_valid_for_host_and_arm(self):
        text=MODEL+'unsigned root(unsigned long n){unsigned long i=n%4UL;return current()->a[i];}'
        host=self.positive(text);arm=self.positive(text,flags=('--target=armv7-none-eabi','-ffreestanding'))
        self.assertEqual({r['path'] for r in host['entry_reads']},{r['path'] for r in arm['entry_reads']})
    def test_loaded_helper_and_cache_controls(self):
        import test_entry_state_global_arrays as arrays
        with tempfile.TemporaryDirectory() as tmp:
            tree=arrays.GlobalArrayTests().parse(Path(tmp),{
                'root.c':'unsigned helper(unsigned long long);unsigned root(unsigned long long n){return helper(n);}',
                'helper.c':'static const unsigned a[4]={11,22,33,44};unsigned helper(unsigned long long n){unsigned i=n%4ULL;return a[i];}'})
            p=Analyzer(tree).analyze('root');q=Analyzer(tree,cache_alias_syntax=False).analyze('root')
            self.assertEqual(p,q);self.assertFalse(p['blockers'],p['blockers']);capture_header([p])
            self.assertTrue(all(r['immutable_global'] for r in p['entry_reads']))
    def test_native_large_value_and_initializer_effects(self):
        text=MODEL+'''unsigned long long next(void){current()->calls++;return 0x100000004ULL;}
unsigned root(void){unsigned long long k=next();unsigned i=k%3ULL;return current()->a[i];}'''
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);tree=basic.EntryStateTests().parse(stage,text)[0]
            p=Analyzer(tree,basic.POLICY).analyze('root');self.assertFalse(p['blockers'],p['blockers'])
            self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->calls'}|{'current()->a['+str(i)+']' for i in range(3)})
            (stage/'capture.h').write_text(capture_header([p]));source=stage/'native.c'
            source.write_text(text+'''
#include "capture.h"
static struct Obj object={{11,22,33,44},0};struct Obj*current(void){return &object;}
int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);if(!osrec_snapshot_root(&s)||s.field_count!=4||object.calls)return 1;
if(root()!=33||root()!=33||object.calls!=2)return 2;return 0;}
''')
            exe=stage/'native';subprocess.run([basic.CLANG,'-std=c11','-I',str(basic.ROOT/'include'),'-I',str(stage),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(exe)],check=True,capture_output=True)
            subprocess.run([str(exe)],check=True,timeout=10)
if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
