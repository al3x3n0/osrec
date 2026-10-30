"""Internal helpers may return stable bounded arrays without losing provenance."""
import copy,json,subprocess,sys,tempfile
from pathlib import Path
import unittest
import test_entry_state as basic
from entry_state import Analyzer,capture_header
MODEL='struct Obj{unsigned a[4];unsigned b[4];unsigned calls;};struct Obj*current(void);\n'
class PointerReturnTests(unittest.TestCase):
    def plan(self,text,root='root',**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree)
            a=Analyzer(tree,basic.POLICY,**options);p=a.analyze(root)
            self.assertEqual(tree,before);self.assertEqual(p,a.fresh().analyze(root))
            self.assertNotIn('bounded-pointer:',json.dumps(p));return p
    def test_constant_global_array_return_retains_immutable_evidence(self):
        text='const unsigned a[4]={11,22,33,44};const unsigned*get(void){return a+1;}unsigned root(void){return get()[1];}'
        p=self.plan(text);self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:a[2]'})
        self.assertTrue(p['entry_reads'][0]['immutable_global']);capture_header([p])
        proof=p['pointer_return_proofs'][0];self.assertFalse(proof['automatic_storage_allowed'])
        self.assertEqual(proof['origins'][0]['element_offset'],1)
        self.assertTrue(self.plan(text,'get')['blockers'])
    def test_provider_array_through_chained_helpers(self):
        p=self.plan(MODEL+'''unsigned*identity(unsigned*p){return p;}
unsigned*get(void){return identity(current()->a+1)+1;}
unsigned root(void){return *get();}''')
        self.assertFalse(p['blockers'],p['blockers']);capture_header([p])
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->a[2]'})
        self.assertEqual({r['function'] for r in p['pointer_return_proofs']},{'identity','get'})
    def test_return_union_and_initialization_proof_preserve_both_arrays(self):
        text=MODEL+'''unsigned*get(unsigned n){unsigned*p;if(n)p=current()->a+1;else p=current()->b+2;return p;}
unsigned root(unsigned n){return *get(n);}'''
        p=self.plan(text);self.assertFalse(p['blockers'],p['blockers']);capture_header([p])
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->a[1]','current()->b[2]'})
        self.assertTrue(p['pointer_initialization_proofs'])
        self.assertEqual(p['pointer_return_proofs'][0]['may_alias_origins_retained'],2)
    def test_one_past_can_return_but_cannot_be_dereferenced(self):
        text=MODEL+'unsigned*end(void){return current()->a+4;}unsigned root(void){return end()[-1];}'
        p=self.plan(text);self.assertFalse(p['blockers'],p['blockers']);capture_header([p])
        self.assertEqual(p['entry_reads'][0]['path'],'current()->a[3]')
        p=self.plan(text.replace('end()[-1]','*end()'))
        self.assertIn('array_bounds',{b['kind'] for b in p['blockers']})
    def test_automatic_and_borrowed_automatic_storage_stays_blocked(self):
        texts=(
            'unsigned*get(void){unsigned a[4];return a+1;}unsigned root(void){return *get();}',
            'unsigned*id(unsigned*p){return p;}unsigned root(void){unsigned a[4]={1,2,3,4};return *id(a);}',
            'unsigned*get(void){return (unsigned[2]){1,2};}unsigned root(void){return *get();}',
            'unsigned*get(void){static unsigned a[4];return a;}unsigned root(void){return *get();}',
        )
        for text in texts:
            with self.subTest(text=text):
                p=self.plan(text);self.assertTrue(p['blockers'],p)
                with self.assertRaises(ValueError):capture_header([p])
    def test_mixed_unknown_null_and_unbounded_returns_stay_blocked(self):
        texts=(
            MODEL+'unsigned*get(unsigned n,unsigned*p){return n?current()->a:p;}unsigned root(unsigned n,unsigned*p){return *get(n,p);}',
            MODEL+'unsigned*get(unsigned n){return n?current()->a:0;}unsigned root(unsigned n){return *get(n);}',
            'extern unsigned a[];unsigned*get(void){return a+1;}unsigned root(void){return *get();}',
            MODEL+'unsigned*get(unsigned n){if(n)return current()->a+4;return current()->b;}unsigned root(unsigned n){return *get(n);}',
        )
        for text in texts:
            with self.subTest(text=text):
                p=self.plan(text);self.assertTrue(p['blockers'],p)
                with self.assertRaises(ValueError):capture_header([p])
    def test_effects_casts_and_pointer_stores_remain_checked(self):
        texts=(
            MODEL+'void external(void);unsigned*get(void){external();return current()->a;}unsigned root(void){return *get();}',
            MODEL+'unsigned char*get(void){return (unsigned char*)current()->a;}unsigned root(void){return *get();}',
            MODEL+'unsigned*g;unsigned*get(void){g=current()->a;return current()->a;}unsigned root(void){return *get();}',
            'const unsigned a[4]={1,2,3,4};unsigned*get(void){return a;}unsigned root(void){*get()=9;return 0;}',
            'volatile unsigned a[4];unsigned*get(void){return a;}unsigned root(void){return *get();}',
            'unsigned a[4];unsigned*get(unsigned n){if(n)return get(n-1);return a;}unsigned root(void){return *get(1);}',
        )
        for text in texts:
            with self.subTest(text=text):self.assertTrue(self.plan(text)['blockers'])
    def test_alias_cap_and_call_contexts(self):
        text=MODEL+'unsigned*get(unsigned n){return current()->a+(n%4);}unsigned root(unsigned n){return *get(n);}'
        p=self.plan(text,max_alias_paths=2);self.assertTrue(p['analysis_limits']['alias_path_limit_observed'])
        with self.assertRaises(ValueError):capture_header([p])
        text=MODEL+'unsigned*id(unsigned*p){return p;}unsigned root(void){return *id(current()->a+1)+*id(current()->b+2);}'
        p=self.plan(text);self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->a[1]','current()->b[2]'})
    def test_loaded_helper_return(self):
        import test_entry_state_global_arrays as arrays
        with tempfile.TemporaryDirectory() as tmp:
            tree=arrays.GlobalArrayTests().parse(Path(tmp),{
                'root.c':'const unsigned*get(void);unsigned root(void){return get()[1];}',
                'helper.c':'static const unsigned a[3]={11,22,33};const unsigned*get(void){return a+1;}'})
            p=Analyzer(tree).analyze('root');self.assertFalse(p['blockers'],p['blockers']);capture_header([p])
            self.assertTrue(p['pointer_return_proofs']);self.assertTrue(p['entry_reads'][0]['immutable_global'])
    def test_native_capture_never_executes_the_returning_helper(self):
        text=MODEL+'''unsigned*get(unsigned n){current()->calls++;return n?current()->a+1:current()->b+2;}
unsigned root(unsigned n){return *get(n);}'''
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);tree=basic.EntryStateTests().parse(stage,text)[0]
            p=Analyzer(tree,basic.POLICY).analyze('root');self.assertFalse(p['blockers'],p['blockers'])
            (stage/'capture.h').write_text(capture_header([p]));source=stage/'native.c'
            source.write_text(text+'''
#include "capture.h"
#include <string.h>
static struct Obj object={{11,22,33,44},{55,66,77,88},0};struct Obj*current(void){return &object;}
int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);if(!osrec_snapshot_root(&s)||s.field_count!=3||object.calls)return 1;
for(unsigned i=0;i<s.field_count;i++){unsigned v;if(s.fields[i].size!=sizeof(v))return 2;memcpy(&v,s.fields[i].bytes,sizeof(v));
if(!strcmp(s.fields[i].name,"a[1]")){if(v!=22)return 3;}else if(!strcmp(s.fields[i].name,"b[2]")){if(v!=77)return 4;}
else if(!strcmp(s.fields[i].name,"calls")){if(v)return 5;}else return 6;}
if(root(0)!=77||root(1)!=22||object.calls!=2)return 7;return 0;}
''')
            exe=stage/'native';subprocess.run([basic.CLANG,'-std=c11','-I',str(basic.ROOT/'include'),'-I',str(stage),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(exe)],check=True,capture_output=True)
            subprocess.run([str(exe)],check=True,timeout=10)
if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
