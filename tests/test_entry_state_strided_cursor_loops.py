"""Literal strides bind body cursor uses to their per-iteration phase."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer,capture_header,entry_accesses
MODEL='struct Obj{unsigned a[8],b[8];};struct Obj*current(void);'

class StridedCursorLoopTests(unittest.TestCase):
    def plan(self,text,**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree)
            analyzer=Analyzer(tree,basic.POLICY,**options);p=analyzer.analyze('root')
            self.assertEqual(p,analyzer.fresh().analyze('root'));self.assertEqual(tree,before)
            self.assertNotIn('bounded-pointer:',json.dumps(p));return p
    def positive(self,text,**options):
        p=self.plan(text,**options);self.assertFalse(p['blockers'],p['blockers'])
        self.assertTrue(p['pointer_update_proofs']);capture_header([p]);return p
    def test_forward_stride_uses_before_values_and_checks_final_one_past(self):
        p=self.positive(MODEL+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++){*p+=i;p+=2;}}')
        expected={'current()->a['+str(i)+']' for i in (0,2,4,6)}
        self.assertEqual({r['path'] for r in p['entry_reads']},{w['path'] for w in p['state_writes']});self.assertEqual({r['path'] for r in p['entry_reads']},expected)
        proof=p['pointer_update_proofs'][0];self.assertEqual(proof['loop']['pointer_step'],2)
        self.assertEqual([o['element_offset'] for o in proof['after']],[2,4,6,8])
        self.assertEqual([b['version'] for b in proof['iteration_value_bindings']],['before'])
    def test_reverse_stride_uses_after_values_after_retreat(self):
        p=self.positive(MODEL+'void root(void){unsigned*p=current()->a+8;for(unsigned i=0;i<4;i++){p-=2u;*p+=i;}}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->a['+str(i)+']' for i in (0,2,4,6)})
        proof=p['pointer_update_proofs'][0];self.assertEqual(proof['loop']['pointer_step'],-2)
        self.assertEqual([b['version'] for b in proof['iteration_value_bindings']],['after'])
    def test_after_update_access_still_rejects_one_past(self):
        p=self.positive(MODEL+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<3;i++){p+=2;*p+=i;}}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->a['+str(i)+']' for i in (2,4,6)})
        p=self.plan(MODEL+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++){p+=2;*p+=i;}}')
        self.assertIn('array_bounds',{b['kind'] for b in p['blockers']})
    def test_unit_cursor_body_reads_also_gain_iteration_binding(self):
        p=self.positive('const unsigned a[4]={1,2,3,4};unsigned root(void){const unsigned*p=a;unsigned sum=0;for(unsigned i=0;i<4;i++){sum+=*p;p++;}return sum;}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:a['+str(i)+']' for i in range(4)})
        self.assertEqual(p['pointer_update_proofs'][0]['loop']['pointer_step'],1)
    def test_indexed_source_and_stride_destination_cooperate(self):
        p=self.positive(MODEL+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++){*p=current()->b[i];p+=2;}}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->b['+str(i)+']' for i in range(4)})
        self.assertEqual({w['path'] for w in p['state_writes']},{'current()->a['+str(i)+']' for i in (0,2,4,6)})
    def test_multiple_ordinary_refs_and_loop_local_pointer_copy(self):
        p=self.positive(MODEL+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++){*p=*p+1;p+=2;}}')
        self.assertEqual(len(p['pointer_update_proofs'][0]['iteration_value_bindings']),2)
        p=self.positive(MODEL+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<3;i++){p+=2;unsigned*q=p;*q+=i;}}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->a['+str(i)+']' for i in (2,4,6)})
    def test_nonliteral_zero_wrapped_and_self_assignment_steps_stay_blocked(self):
        # A zero step keeps the cursor on its first element; that offset is proven.
        p=self.plan(MODEL+'void root(unsigned n){unsigned*p=current()->a;for(unsigned i=0;i<2;i++){*p+=i;p+=0;}}')
        self.assertFalse(p['blockers'],p['blockers']);self.assertEqual({w['path'] for w in p['state_writes']},{'current()->a[0]'})
        for update in ('p+=n;','p+=i;','p+=-1u;','p+=-2;','p=p+2;'):
            with self.subTest(update=update):
                p=self.plan(MODEL+'void root(unsigned n){unsigned*p=current()->a;for(unsigned i=0;i<2;i++){*p+=i;'+update+'}}')
                self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
        p=self.plan(MODEL+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++)*p++=*p;}')
        self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
    def test_every_formation_bound_is_checked_even_after_last_access(self):
        for initial,step,count in (('current()->a','p+=3;',3),('current()->a','p+=2;',5),('current()->a+6','p-=2;',4)):
            with self.subTest(initial=initial,step=step,count=count):
                p=self.plan(MODEL+'void root(void){unsigned*p='+initial+';for(unsigned i=0;i<'+str(count)+';i++){*p+=i;'+step+'}}')
                self.assertTrue(p['blockers']);self.assertIn('array_bounds',{b['kind'] for b in p['blockers']})
    def test_pruning_and_alias_caps_preserve_rmw_requirements(self):
        body=MODEL+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++){*p+=i;p+=2;}}'
        p=self.positive(body,prune_written=True,preserve_write_state=True)
        self.assertEqual({r['path'] for r in entry_accesses(p)},{'current()->a['+str(i)+']' for i in (0,2,4,6)})
        p=self.plan(body,max_alias_paths=3);self.assertTrue(p['analysis_limits']['alias_path_limit_observed']);self.assertTrue(p['blockers'])
    def test_native_capture_preserves_sparse_inputs_and_untouched_elements(self):
        body=MODEL+'unsigned twice(unsigned n){return 2*n;}void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++){*p+=twice(i);p+=2;}}'
        p=self.positive(body)
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);(stage/'capture.h').write_text(capture_header([p]));source=stage/'run.c'
            source.write_text(body+'\n#include "capture.h"\n#include <assert.h>\n#include <string.h>\nstatic struct Obj object={{10,20,30,40,50,60,70,80},{0}};struct Obj*current(void){return &object;}\nint main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s));assert(s.object_count==1&&s.field_count==4);for(unsigned i=0;i<4;i++)assert(s.fields[i].size==sizeof(unsigned)&&memcmp(s.fields[i].bytes,&object.a[2*i],sizeof(unsigned))==0);root();unsigned expected[8]={10,20,32,40,54,60,76,80};assert(memcmp(object.a,expected,sizeof(expected))==0);return 0;}')
            binary=stage/'run';subprocess.run([basic.CLANG,'-std=c11','-I'+str(basic.ROOT/'include'),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
