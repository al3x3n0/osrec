"""Object-relative pointer values retain bounds through local aliases and calls."""
import copy,json,subprocess,sys,tempfile
from pathlib import Path
import unittest
import test_entry_state as basic
from entry_state import Analyzer,capture_header

class BoundedPointerTests(unittest.TestCase):
    def parse(self,stage,text):return basic.EntryStateTests().parse(stage,text)[0]
    def plan(self,text,root='root',**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),text);before=copy.deepcopy(tree)
            a=Analyzer(tree,basic.POLICY,**options);p=a.analyze(root)
            self.assertEqual(tree,before)
            self.assertEqual(p,a.fresh().analyze(root))
            self.assertNotIn('bounded-pointer:',json.dumps(p))
            return p
    def test_stored_offsets_and_helper_parameters(self):
        p=self.plan('''struct Obj{unsigned data[8];};struct Obj*current(void);
unsigned read(unsigned*p){return p[0]+*(p+1);}
unsigned root(unsigned n){unsigned*p=current()->data+(n%4);unsigned*q=p+2;*q=9;return read(q);}''')
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->data['+str(i)+']' for i in range(2,7)})
        self.assertEqual({r['path'] for r in p['state_writes']},{'current()->data['+str(i)+']' for i in range(2,6)})
        capture_header([p])
    def test_address_one_past_and_retreat(self):
        p=self.plan('''struct Obj{unsigned data[4];};struct Obj*current(void);
unsigned root(void){unsigned*p=&current()->data[4];unsigned*q=&*p;return q[-1]+*(q-2);}''')
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->data[2]','current()->data[3]'})
        capture_header([p])
    def test_const_global_and_automatic_storage(self):
        p=self.plan('''const unsigned values[4]={1,2,3,4};unsigned read(const unsigned*p){return p[1];}
unsigned root(void){unsigned local[2]={3,4};unsigned*p=local;return p[1]+read(values+1);}''')
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:values[2]'})
        self.assertTrue(p['entry_reads'][0]['immutable_global']);capture_header([p])
    def test_counted_subscript_and_alias_union(self):
        p=self.plan('''struct Obj{unsigned data[4];unsigned other[4];};struct Obj*current(void);
unsigned root(unsigned n){unsigned*p=n?current()->data:current()->other;unsigned sum=0;for(unsigned i=0;i<4;i++)sum+=p[i];return sum;}''')
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual(len(p['entry_reads']),8);capture_header([p])
    def test_invalid_and_unknown_offsets(self):
        bodies=(
            'unsigned a[4];unsigned*p=a+4;return *p;',
            'unsigned a[4];unsigned*p=a+3;return p[1];',
            'unsigned a[4];unsigned*p=a+1;return p[-2];',
            'unsigned a[4];unsigned*p=a;return *(p+n);',
            'unsigned a[4];unsigned*p=n?a:0;return *p;',
            'unsigned a[4];unsigned*p=a;unsigned char*q=(unsigned char*)p;return *q;',
            'unsigned a[4];unsigned*p=a;void*v=p;unsigned char*q=v;return *q;',
        )
        for body in bodies:
            with self.subTest(body=body):
                p=self.plan('unsigned root(unsigned n){'+body+'}')
                self.assertTrue(p['blockers'],p)
                with self.assertRaises(ValueError):capture_header([p])
    def test_returns_stores_and_pointer_variable_addresses_do_not_escape(self):
        texts=(
            'unsigned values[4];unsigned*root(void){return values+1;}',
            'unsigned*g;unsigned root(void){unsigned a[4];g=a+1;return 0;}',
            'struct Box{unsigned*p;};unsigned root(void){unsigned a[4];struct Box b;b.p=a+1;return 0;}',
            'struct Box{unsigned*p;};unsigned root(void){unsigned a[4];struct Box b={a+1};return 0;}',
            'void mutate(unsigned**p){*p=0;}unsigned root(void){unsigned a[4];unsigned*p=a;mutate(&p);return *p;}',
            'unsigned*bad(void){unsigned a[4];return a;}unsigned root(void){return *bad();}',
        )
        for text in texts:
            with self.subTest(text=text):
                p=self.plan(text);self.assertTrue(p['blockers'],p)
                with self.assertRaises(ValueError):capture_header([p])
    def test_qualifiers_survive_implicit_conversion(self):
        for qualifier,kind in (('const','const_argument_write'),('volatile','volatile_memory')):
            with self.subTest(qualifier=qualifier):
                p=self.plan(qualifier+' unsigned a[4];unsigned root(void){unsigned*p=a;*p=3;return 0;}')
                self.assertIn(kind,{b['kind'] for b in p['blockers']},p)
    def test_alias_and_range_caps(self):
        text='unsigned a[8];unsigned root(unsigned n){unsigned*p=a+(n%8);return *p;}'
        p=self.plan(text,max_alias_paths=3)
        self.assertTrue(p['analysis_limits']['alias_path_limit_observed'])
        self.assertIn('alias_limit',{b['kind'] for b in p['blockers']})
        p=self.plan(text,max_range_elements=3)
        self.assertIn('range_limit',{b['kind'] for b in p['blockers']})
    def test_automatic_arrays_do_not_outlive_their_lexical_block(self):
        bodies=(
            'unsigned outer[1]={0};unsigned*p=outer;{unsigned inner[1]={1};p=inner;}return *p;',
            'unsigned*p=({unsigned a[1]={1};a;});return *p;',
            'unsigned outer[1]={0};unsigned*p=outer;for(unsigned i=0;i<1;i++){unsigned a[1]={1};p=a;}return *p;',
        )
        for body in bodies:
            with self.subTest(body=body):
                p=self.plan('unsigned root(void){'+body+'}')
                self.assertTrue(any('scope/lifetime' in b['detail'] for b in p['blockers']),p)
                with self.assertRaises(ValueError):capture_header([p])
        p=self.plan('unsigned read(unsigned*p){return *p;}unsigned root(void){unsigned result;{unsigned a[1]={7};result=read(a);}return result;}')
        self.assertFalse(p['blockers'],p['blockers'])

    def test_call_contexts_and_loaded_helper(self):
        p=self.plan('''struct Obj{unsigned data[4];unsigned other[4];};struct Obj*current(void);
unsigned read(unsigned*p){return *p;}
unsigned root(void){return read(current()->data+1)+read(current()->other+2);}''')
        self.assertFalse(p['blockers'],p['blockers'])
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->data[1]','current()->other[2]'})
        import test_entry_state_global_arrays as arrays
        with tempfile.TemporaryDirectory() as tmp:
            tree=arrays.GlobalArrayTests().parse(Path(tmp),{
                'root.c':'unsigned read(unsigned*);unsigned root(void){unsigned a[4]={1,2,3,4};unsigned*p=a+1;return read(p);}',
                'helper.c':'unsigned read(unsigned*p){return p[1];}'})
            p=Analyzer(tree).analyze('root');self.assertFalse(p['blockers'],p['blockers'])
            self.assertEqual(p['entry_reads'],[]);capture_header([p])

    def test_native_capture_has_the_propagated_elements(self):
        text='''struct Obj{unsigned data[4];};struct Obj*current(void);
unsigned read(unsigned*p){return *p+p[1];}
unsigned root(void){unsigned*p=current()->data+1;return read(p);}'''
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);p=Analyzer(self.parse(stage,text),basic.POLICY).analyze('root')
            self.assertFalse(p['blockers'],p['blockers']);(stage/'capture.h').write_text(capture_header([p]))
            source=stage/'native.c';source.write_text(text+'''
#include "capture.h"
#include <string.h>
static struct Obj object={{11,22,33,44}};struct Obj*current(void){return &object;}
int main(void){struct osrec_entry_snapshot state;osrec_snapshot_init(&state);
 if(!osrec_snapshot_root(&state)||state.field_count!=2)return 1;
 for(unsigned i=0;i<2;i++)if(state.fields[i].size!=sizeof(unsigned)||memcmp(state.fields[i].bytes,&object.data[i+1],sizeof(unsigned)))return 2;
 return root()!=55;}
''')
            exe=stage/'native';subprocess.run([basic.CLANG,'-std=c11','-I',str(basic.ROOT/'include'),'-I',str(stage),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(exe)],check=True,capture_output=True)
            subprocess.run([str(exe)],check=True,timeout=10)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
