"""Definite assignment discharges only the uninitialized seed, not value origins."""
import copy,json,subprocess,sys,tempfile
from pathlib import Path
import unittest
import test_entry_state as basic
from entry_state import Analyzer,capture_header
MODEL='struct Obj{unsigned a[4];unsigned b[4];};struct Obj*current(void);\n'
class PointerInitializationTests(unittest.TestCase):
    def plan(self,text,**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree)
            a=Analyzer(tree,basic.POLICY,**options);p=a.analyze('root')
            self.assertEqual(tree,before);self.assertEqual(p,a.fresh().analyze('root'))
            self.assertNotIn('bounded-pointer:',json.dumps(p));return p
    def positive(self,text,paths=None):
        p=self.plan(text);self.assertFalse(p['blockers'],p['blockers'])
        self.assertTrue(p['pointer_initialization_proofs'])
        if paths is not None:self.assertEqual({r['path'] for r in p['entry_reads']},paths)
        capture_header([p]);return p
    def test_all_branch_origins_are_retained_through_helper(self):
        p=self.positive(MODEL+'''unsigned read(unsigned*p){return *p;}
unsigned root(unsigned n){unsigned*p;if(n)p=current()->a+1;else p=current()->b+2;return read(p);}''',{'current()->a[1]','current()->b[2]'})
        self.assertEqual(p['pointer_initialization_proofs'][0]['may_alias_origins_retained'],2)
    def test_early_returns_else_if_and_sequenced_expressions(self):
        bodies=(
            'if(n)return 0;p=current()->a;return *p;',
            'if(n==1)p=current()->a;else if(n==2)p=current()->b;else return 0;return *p;',
            'return (p=current()->a,*p);',
            'n?(p=current()->a):(p=current()->b);return *p;',
            'while((p=current()->a),n--){}return *p;',
        )
        for body in bodies:
            with self.subTest(body=body):self.positive(MODEL+'unsigned root(unsigned n){unsigned*p;'+body+'}')
    def test_read_after_join_inside_counted_loop(self):
        self.positive(MODEL+'''unsigned root(unsigned n){unsigned*p;if(n)p=current()->a;else p=current()->b;
unsigned sum=0;for(unsigned i=0;i<4;i++)sum+=p[i];return sum;}''',{'current()->'+a+'['+str(i)+']' for a in ('a','b') for i in range(4)})
    def test_missing_assignments_and_unsequenced_reads_stay_blocked(self):
        bodies=(
            'if(n)p=current()->a;return *p;',
            'unsigned x=*p;p=current()->a;return x;',
            'n&&(p=current()->a);return *p;',
            'n?(p=current()->a):0;return *p;',
            'while(n--){p=current()->a;}return *p;',
            'for(unsigned i=0;i<n;i++){p=current()->a;}return *p;',
            'return consume((p=current()->a),*p);',
            'p=n?current()->a:p;return *p;',
            'goto label;p=current()->a;label:return *p;',
        )
        prefix=MODEL+'unsigned consume(unsigned*p,unsigned x){return x;}\n'
        for body in bodies:
            with self.subTest(body=body):
                p=self.plan(prefix+'unsigned root(unsigned n){unsigned*p;'+body+'}')
                self.assertTrue(p['blockers'],p)
                with self.assertRaises(ValueError):capture_header([p])
    def test_initialization_does_not_discard_unknown_null_or_invalid_values(self):
        texts=(
            MODEL+'unsigned root(unsigned n){unsigned*p;if(n)p=current()->a;else p=0;return *p;}',
            MODEL+'unsigned root(unsigned n){unsigned*p;if(n)p=current()->a;else p=current()->b+4;return *p;}',
            MODEL+'void mutate(unsigned**p){*p=0;}unsigned root(void){unsigned*p;p=current()->a;mutate(&p);return *p;}',
        )
        for text in texts:
            with self.subTest(text=text):
                p=self.plan(text);self.assertTrue(p['blockers'],p)
                with self.assertRaises(ValueError):capture_header([p])
        # A definitely assigned root argument remains visible in the footprint. Its pointee
        # still has no snapshot binding, so automatic capture must reject the mixed origins.
        p=self.plan(MODEL+'unsigned root(unsigned*unknown,unsigned n){unsigned*p;if(n)p=current()->a;else p=unknown;return *p;}')
        self.assertEqual({r['path'] for r in p['entry_reads']},
                         {'current()->a[0]','*(argument:unknown)'})
        with self.assertRaisesRegex(ValueError,'provider field paths'):capture_header([p])
    def test_automatic_scope_and_external_effects_remain_blocked(self):
        texts=(
            'unsigned root(unsigned n){unsigned*p;{unsigned a[4];p=a;}return *p;}',
            MODEL+'unsigned external(void);unsigned root(void){unsigned*p;if(external())p=current()->a;else p=current()->b;return *p;}',
        )
        for text in texts:
            with self.subTest(text=text):self.assertTrue(self.plan(text)['blockers'])
    def test_caps_and_fresh_roots_preserve_unknown(self):
        text=MODEL+'unsigned root(unsigned n){unsigned*p;p=current()->a+(n%4);return *p;}'
        p=self.plan(text,max_alias_paths=2)
        self.assertTrue(p['analysis_limits']['alias_path_limit_observed'])
        self.assertTrue(p['blockers'])
        with self.assertRaises(ValueError):capture_header([p])
    def test_constant_table_selection_and_loaded_helper(self):
        text='const unsigned a[2]={11,22},b[2]={33,44};unsigned root(unsigned n){const unsigned*p;if(n)p=a;else p=b;return p[1];}'
        p=self.positive(text,{'global:a[1]','global:b[1]'})
        self.assertTrue(all(r['immutable_global'] for r in p['entry_reads']))
        import test_entry_state_global_arrays as arrays
        with tempfile.TemporaryDirectory() as tmp:
            tree=arrays.GlobalArrayTests().parse(Path(tmp),{
                'root.c':'unsigned helper(unsigned);unsigned root(unsigned n){return helper(n);}',
                'helper.c':text.replace('root(','helper(')})
            p=Analyzer(tree).analyze('root');self.assertFalse(p['blockers'],p['blockers']);capture_header([p])
            self.assertTrue(p['pointer_initialization_proofs'])
    def test_native_capture_and_both_branch_results(self):
        text=MODEL+'unsigned root(unsigned n){unsigned*p;if(n)p=current()->a+1;else p=current()->b+2;return *p;}'
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);tree=basic.EntryStateTests().parse(stage,text)[0]
            p=Analyzer(tree,basic.POLICY).analyze('root');self.assertFalse(p['blockers'],p['blockers'])
            (stage/'capture.h').write_text(capture_header([p]));source=stage/'native.c'
            source.write_text(text+'''
#include "capture.h"
#include <string.h>
static struct Obj object={{11,22,33,44},{55,66,77,88}};struct Obj*current(void){return &object;}
int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);if(!osrec_snapshot_root(&s)||s.field_count!=2)return 1;
unsigned expected[2]={22,77};for(unsigned i=0;i<2;i++)if(s.fields[i].size!=sizeof(unsigned)||memcmp(s.fields[i].bytes,&expected[i],sizeof(unsigned)))return 2;
return root(0)!=77||root(1)!=22;}
''')
            exe=stage/'native';subprocess.run([basic.CLANG,'-std=c11','-I',str(basic.ROOT/'include'),'-I',str(stage),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(exe)],check=True,capture_output=True)
            subprocess.run([str(exe)],check=True,timeout=10)
if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
