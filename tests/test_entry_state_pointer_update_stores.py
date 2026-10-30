"""Standalone stores select the address version and keep scalar RHS effects."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer,capture_header

MODEL='struct Obj{unsigned a[4];};struct Obj*current(void);'

class PointerUpdateStoreTests(unittest.TestCase):
    def plan(self,text,**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree)
            analyzer=Analyzer(tree,basic.POLICY,**options);p=analyzer.analyze('root')
            self.assertEqual(p,analyzer.fresh().analyze('root'));self.assertEqual(tree,before)
            self.assertNotIn('bounded-pointer:',json.dumps(p));return p
    def positive(self,text,**options):
        p=self.plan(text,**options);self.assertFalse(p['blockers'],p['blockers'])
        self.assertTrue(p['pointer_update_proofs']);capture_header([p]);return p
    def test_all_four_store_addresses_and_pointer_versions(self):
        for expression,initial,index,version in (('*p++','current()->a',0,'before'),('*++p','current()->a',1,'after'),('*p--','current()->a+2',2,'before'),('*--p','current()->a+2',1,'after')):
            with self.subTest(expression=expression):
                p=self.positive(MODEL+'void root(unsigned n){unsigned*p='+initial+';'+expression+'=n;}')
                self.assertEqual({w['path'] for w in p['state_writes']},{'current()->a['+str(index)+']'})
                self.assertFalse(p['entry_reads']);proof=p['pointer_update_proofs'][0]
                self.assertEqual(proof['result_version'],version);self.assertEqual(proof['result_origins'],proof[version])
                self.assertEqual(proof['result_context'],'independent_numeric_store');self.assertTrue(proof['rhs_independent_of_cursor'])
                self.assertEqual(proof['store_operator'],'=')
    def test_compound_stores_retain_old_value_reads(self):
        for op in ('+=','-=','*=','/=','%=','<<=','>>=','&=','|=','^='):
            with self.subTest(op=op):
                p=self.positive(MODEL+'void root(unsigned n){unsigned*p=current()->a;*++p'+op+'n;}')
                self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->a[1]'})
                self.assertEqual({w['path'] for w in p['state_writes']},{'current()->a[1]'})
                self.assertEqual(p['pointer_update_proofs'][0]['store_operator'],op)
    def test_sequenced_read_store_and_unused_updates_cooperate(self):
        p=self.positive(MODEL+'unsigned root(unsigned n){unsigned*p=current()->a;*p++=n;unsigned x=*p++;p--;*++p+=n;return x;}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->a[1]','current()->a[2]'})
        self.assertEqual({w['path'] for w in p['state_writes']},{'current()->a[0]','current()->a[2]'})
        self.assertEqual(len(p['pointer_update_proofs']),4)
    def test_rhs_cursor_observation_and_escapes_are_rejected(self):
        for rhs in ('*p','(unsigned)(p-current()->a)','use(p)','*p++'):
            with self.subTest(rhs=rhs):
                p=self.plan(MODEL+'unsigned use(unsigned*);void root(void){unsigned*p=current()->a;*p++='+rhs+';}')
                self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
        p=self.plan(MODEL+'unsigned use(unsigned**);void root(void){unsigned*p=current()->a;*p++=use(&p);}')
        self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
    def test_rhs_calls_and_mutations_are_visited_once(self):
        p=self.plan(MODEL+'unsigned ext(void);void root(void){unsigned*p=current()->a;*p++=ext();}')
        self.assertIn('unmodeled_external',{b['kind'] for b in p['blockers']})
        self.assertEqual([c['callee'] for c in p['call_sites']],['current','ext'])
        p=self.plan(MODEL+'unsigned counter;void root(void){unsigned*p=current()->a;*p++=counter++;}')
        self.assertFalse(p['blockers']);self.assertTrue(p['pointer_update_proofs'])
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:counter'})
        self.assertEqual({w['path'] for w in p['state_writes']},{'global:counter','current()->a[0]'})
        p=self.positive(MODEL+'void root(void){unsigned*p=current()->a;*p++=sizeof(*p++);}')
        self.assertEqual(len(p['pointer_update_proofs']),1)
    def test_nested_results_control_flow_and_compound_pointer_updates_stay_blocked(self):
        bodies=('return (*p++=7);','unsigned x=(*p++=7);return x;',
            'if(n)*p++=7;return 0;',
            '*(p+=1)=7;return 0;','(*p++)++;return 0;')
        for body in bodies:
            with self.subTest(body=body):
                p=self.plan(MODEL+'unsigned root(unsigned n){unsigned*p=current()->a;'+body+'}')
                self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
    def test_one_past_store_and_formation_are_checked(self):
        for expression,initial,index in (('*p++','current()->a+3',3),('*--p','current()->a+4',3)):
            p=self.positive(MODEL+'void root(void){unsigned*p='+initial+';'+expression+'=7;}')
            self.assertEqual({w['path'] for w in p['state_writes']},{'current()->a['+str(index)+']'})
        for expression,initial in (('*++p','current()->a+3'),('*p++','current()->a+4'),('*p--','current()->a')):
            with self.subTest(expression=expression,initial=initial):
                p=self.plan(MODEL+'void root(void){unsigned*p='+initial+';'+expression+'=7;}')
                self.assertIn('array_bounds',{b['kind'] for b in p['blockers']})
    def test_unknown_const_volatile_and_alias_limits_remain_review(self):
        p=self.plan('void root(unsigned*arg){unsigned*p=arg;*p++=7;}');self.assertTrue(p['blockers'])
        p=self.plan('const unsigned a[4]={};void root(void){unsigned*p=a;*p++=7;}')
        self.assertIn('const_argument_write',{b['kind'] for b in p['blockers']})
        p=self.plan('volatile unsigned a[4];void root(void){volatile unsigned*p=a;*p++=7;}')
        self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
        p=self.plan(MODEL+'void root(unsigned n){unsigned*p=current()->a+(n%4);*p++=7;}',max_alias_paths=3)
        self.assertTrue(p['analysis_limits']['alias_path_limit_observed']);self.assertTrue(p['blockers'])
    def test_native_capture_keeps_rmw_input_and_original_store_results(self):
        body=MODEL+'void root(unsigned n){unsigned*p=current()->a;*p++=2*n;*++p+=n;}'
        p=self.positive(body)
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);(stage/'capture.h').write_text(capture_header([p]));source=stage/'run.c'
            source.write_text(body+'\n#include "capture.h"\n#include <assert.h>\n#include <string.h>\nstatic struct Obj object={{10,20,30,40}};struct Obj*current(void){return &object;}\nint main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s));assert(s.object_count==1&&s.field_count==1);assert(s.fields[0].size==sizeof(unsigned)&&memcmp(s.fields[0].bytes,&object.a[2],sizeof(unsigned))==0);root(7);assert(object.a[0]==14&&object.a[1]==20&&object.a[2]==37&&object.a[3]==40);return 0;}')
            binary=stage/'run';subprocess.run([basic.CLANG,'-std=c11','-I'+str(basic.ROOT/'include'),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
