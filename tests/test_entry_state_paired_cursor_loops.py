"""Distinct bounded cursor variables may share data but not unordered updates."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer,capture_header,entry_accesses
MODEL='struct Obj{unsigned a[8],b[8],c[8],d[8];};struct Obj*current(void);'

class PairedCursorLoopTests(unittest.TestCase):
    def plan(self,text,**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree)
            analyzer=Analyzer(tree,basic.POLICY,**options);p=analyzer.analyze('root')
            self.assertEqual(p,analyzer.fresh().analyze('root'));self.assertEqual(tree,before)
            self.assertNotIn('bounded-pointer:',json.dumps(p));return p
    def positive(self,text,**options):
        p=self.plan(text,**options);self.assertFalse(p['blockers'],p['blockers'])
        self.assertTrue(p['pointer_update_proofs']);capture_header([p]);return p
    def test_postfix_copy_retains_source_reads_and_destination_writes(self):
        p=self.positive(MODEL+'void root(void){unsigned*d=current()->a;const unsigned*s=current()->b;for(unsigned i=0;i<4;i++)*d++=*s++;}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->b['+str(i)+']' for i in range(4)})
        self.assertEqual({w['path'] for w in p['state_writes']},{'current()->a['+str(i)+']' for i in range(4)})
        self.assertEqual({v['variable'] for v in p['pointer_update_proofs']},{'d','s'})
        self.assertTrue(all(v['loop']['cursor_count']==2 and v['loop']['distinct_cursor_variables'] and v['loop']['max_cursors']==4 for v in p['pointer_update_proofs']))
    def test_independent_steps_and_ordinary_body_bindings(self):
        p=self.positive(MODEL+'void root(void){unsigned*d=current()->a;const unsigned*s=current()->b;for(unsigned i=0;i<4;i++){*d=*s;d+=2;s++;}}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->b['+str(i)+']' for i in range(4)})
        self.assertEqual({w['path'] for w in p['state_writes']},{'current()->a['+str(i)+']' for i in (0,2,4,6)})
        self.assertEqual({v['variable']:v['loop']['pointer_step'] for v in p['pointer_update_proofs']},{'d':2,'s':1})
    def test_reverse_source_and_forward_destination_use_distinct_versions(self):
        p=self.positive(MODEL+'void root(void){unsigned*d=current()->a;const unsigned*s=current()->b+4;for(unsigned i=0;i<4;i++)*d++=*--s;}')
        by_name={v['variable']:v for v in p['pointer_update_proofs']}
        self.assertEqual(by_name['s']['result_version'],'after');self.assertEqual(by_name['s']['loop']['pointer_step'],-1)
        self.assertEqual(by_name['d']['result_version'],'before');self.assertEqual(by_name['d']['loop']['pointer_step'],1)
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->b['+str(i)+']' for i in range(4)})
    def test_compound_copy_keeps_both_rmw_and_source_inputs(self):
        text=MODEL+'void root(void){unsigned*d=current()->a;const unsigned*s=current()->b;for(unsigned i=0;i<4;i++)*d+++=*s++;}'
        p=self.positive(text,prune_written=True,preserve_write_state=True)
        self.assertEqual({r['path'] for r in entry_accesses(p)},{'current()->'+name+'['+str(i)+']' for name in ('a','b') for i in range(4)})
    def test_four_distinct_cursors_are_supported_but_a_fifth_is_not(self):
        p=self.positive(MODEL+'void root(void){unsigned*p=current()->a;unsigned*q=current()->b;unsigned*r=current()->c;unsigned*s=current()->d;for(unsigned i=0;i<4;i++){*p++=*q++;*r++=*s++;}}')
        self.assertEqual(len(p['pointer_update_proofs']),4);self.assertTrue(all(v['loop']['cursor_count']==4 for v in p['pointer_update_proofs']))
        p=self.plan(MODEL+'void root(void){unsigned*p=current()->a;unsigned*q=current()->b;unsigned*r=current()->c;unsigned*s=current()->d;unsigned*t=current()->a;for(unsigned i=0;i<1;i++){p++;q++;r++;s++;t++;}}')
        self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
    def test_duplicate_updates_and_same_expression_dependencies_stay_blocked(self):
        bodies=('*d++=*d++;','*d++=*s++ + *d;','*d++=*s++ + *s;',
            '*d++=*s++;d++;','*d++=observe(d,*s++);')
        for body in bodies:
            with self.subTest(body=body):
                p=self.plan(MODEL+'unsigned observe(unsigned*,unsigned);void root(void){unsigned*d=current()->a;unsigned*s=current()->b;for(unsigned i=0;i<3;i++){'+body+'}}')
                self.assertTrue(p['blockers'])
    def test_every_cursor_needs_known_origins_and_valid_final_formations(self):
        p=self.plan(MODEL+'void root(const unsigned*arg){unsigned*d=current()->a;const unsigned*s=arg;for(unsigned i=0;i<4;i++)*d++=*s++;}')
        self.assertTrue(p['blockers']);self.assertNotIn('s',{v['variable'] for v in p.get('pointer_update_proofs',[])})
        p=self.plan('struct Obj{unsigned a[4],b[3];};struct Obj*current(void);void root(void){unsigned*d=current()->a;unsigned*s=current()->b;for(unsigned i=0;i<4;i++)*d++=*s++;}')
        self.assertIn('array_bounds',{b['kind'] for b in p['blockers']})
        p=self.plan(MODEL+'void root(void){unsigned*d=current()->a;unsigned*s=current()->b;unsigned**escaped=&s;for(unsigned i=0;i<4;i++)*d++=*s++;}')
        self.assertTrue(p['blockers'])
    def test_alias_and_iteration_caps_apply_to_each_cursor(self):
        p=self.plan(MODEL+'void root(void){unsigned*d=current()->a;unsigned*s=current()->b;for(unsigned i=0;i<4;i++)*d++=*s++;}',max_alias_paths=3)
        self.assertTrue(p['analysis_limits']['alias_path_limit_observed']);self.assertTrue(p['blockers'])
        p=self.plan('void root(void){unsigned a[32],b[32];unsigned*d=a,*s=b;for(unsigned i=0;i<17;i++)*d++=*s++;}')
        self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
    def test_overlapping_data_is_not_assumed_disjoint(self):
        body=MODEL+'void root(void){unsigned*d=current()->a+1;unsigned*s=current()->a;for(unsigned i=0;i<3;i++)*d++=*s++;}'
        p=self.positive(body)
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->a['+str(i)+']' for i in (0,1,2)})
        self.assertEqual({w['path'] for w in p['state_writes']},{'current()->a['+str(i)+']' for i in (1,2,3)})
        self.native(body,p,'root();assert(object.a[0]==10&&object.a[1]==10&&object.a[2]==10&&object.a[3]==10);')
    def native(self,body,plan,checks):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);(stage/'capture.h').write_text(capture_header([plan]));source=stage/'run.c'
            source.write_text(body+'\n#include "capture.h"\n#include <assert.h>\n#include <string.h>\nstatic struct Obj object={{10,20,30,40,50,60,70,80},{101,102,103,104,105,106,107,108},{0},{0}};struct Obj*current(void){return &object;}\nint main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s));'+checks+'return 0;}')
            binary=stage/'run';subprocess.run([basic.CLANG,'-std=c11','-I'+str(basic.ROOT/'include'),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)
    def test_native_copy_capture_preserves_inputs_and_untouched_data(self):
        body=MODEL+'void root(void){unsigned*d=current()->a;const unsigned*s=current()->b;for(unsigned i=0;i<4;i++)*d++=*s++;}'
        p=self.positive(body)
        self.native(body,p,'assert(s.object_count==1&&s.field_count==4);for(unsigned i=0;i<4;i++)assert(s.fields[i].size==sizeof(unsigned)&&memcmp(s.fields[i].bytes,&object.b[i],sizeof(unsigned))==0);root();unsigned expected[8]={101,102,103,104,50,60,70,80};assert(memcmp(object.a,expected,sizeof(expected))==0);for(unsigned i=0;i<8;i++)assert(object.b[i]==101+i);')

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
