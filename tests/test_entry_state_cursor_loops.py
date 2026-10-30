"""Literal counted loops retain all cursor iterations and the final formation."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer,capture_header,entry_accesses
MODEL='struct Obj{unsigned a[4],b[4];};struct Obj*current(void);'

class CursorLoopTests(unittest.TestCase):
    def plan(self,text,**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree)
            analyzer=Analyzer(tree,basic.POLICY,**options);p=analyzer.analyze('root')
            self.assertEqual(p,analyzer.fresh().analyze('root'));self.assertEqual(tree,before)
            self.assertNotIn('bounded-pointer:',json.dumps(p));return p
    def positive(self,text,**options):
        p=self.plan(text,**options);self.assertFalse(p['blockers'],p['blockers'])
        self.assertTrue(any(v['kind']=='bounded_counted_loop_pointer_update' for v in p['pointer_update_proofs']))
        capture_header([p]);return p
    def test_forward_postfix_loop_keeps_every_read_write_and_final_one_past(self):
        p=self.positive(MODEL+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++)*p+++=i;}')
        paths={'current()->a['+str(i)+']' for i in range(4)}
        self.assertEqual({r['path'] for r in p['entry_reads']},paths);self.assertEqual({w['path'] for w in p['state_writes']},paths)
        proof=p['pointer_update_proofs'][0];self.assertEqual(proof['loop']['iterations'],4)
        self.assertEqual([o['element_offset'] for o in proof['before']],[0,1,2,3]);self.assertEqual([o['element_offset'] for o in proof['after']],[1,2,3,4])
    def test_reverse_prefix_loop_retreats_before_each_access(self):
        p=self.positive(MODEL+'void root(void){unsigned*p=current()->a+4;for(int i=0;i<4;++i)*--p+=i;}')
        proof=p['pointer_update_proofs'][0];self.assertEqual(proof['loop']['pointer_step'],-1)
        self.assertEqual(proof['result_version'],'after');self.assertEqual([o['element_offset'] for o in proof['result_origins']],[0,1,2,3])
    def test_cursor_store_and_existing_counter_subscript_proofs_cooperate(self):
        p=self.positive(MODEL+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++)*p++=current()->b[i];}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->b['+str(i)+']' for i in range(4)})
        self.assertEqual({w['path'] for w in p['state_writes']},{'current()->a['+str(i)+']' for i in range(4)})
        self.assertTrue(any(r.get('index_proof',{}).get('kind')=='canonical_for_induction' for r in p['memory_ranges']))
    def test_nonzero_counter_and_surrounding_sequenced_updates(self):
        p=self.positive('const unsigned a[6]={1,2,3,4,5,6};unsigned root(void){const unsigned*p=a;p++;for(unsigned i=2;i<4;i++){unsigned x=*p++;}return *p++;}')
        proofs=p['pointer_update_proofs'];loop=next(v for v in proofs if v['kind']=='bounded_counted_loop_pointer_update')['loop']
        self.assertEqual((loop['initial'],loop['exclusive_limit'],loop['iterations']),(2,4,2))
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:a[1]','global:a[2]','global:a[3]'})
    def test_guards_counter_writes_escapes_and_early_exits_stay_blocked(self):
        loops=('for(unsigned i=0;i<n;i++)*p++=i;',
            'for(unsigned i=0;i<=3;i++)*p++=i;', 'for(unsigned i=0;i<4;i++){i++;*p++=i;}',
            'for(unsigned i=0;i<4;i++){use(&i);*p++=i;}', 'for(unsigned i=0;i<4;i++){*p++=i;break;}',
            'for(unsigned i=0;i<4;i++){*p++=i;continue;}', 'for(unsigned i=0;i<4;i++){if(n)*p++=i;}',
            'for(unsigned i=0;i<4;i++){*p++=i;return;}')
        for loop in loops:
            with self.subTest(loop=loop):
                p=self.plan(MODEL+'void use(unsigned*);void root(unsigned n){unsigned*p=current()->a;'+loop+'}')
                self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
    def test_multiple_updates_nested_loops_and_non_unit_cursor_steps_stay_blocked(self):
        loops=('for(unsigned i=0;i<2;i++){*p++=i;*p++=i;}',
            'for(unsigned i=0;i<2;i++)for(unsigned j=0;j<2;j++)*p++=j;',
            'for(unsigned i=0;i<1;i++)*p++=i;for(unsigned j=0;j<1;j++)*p++=j;')
        for loop in loops:
            with self.subTest(loop=loop):
                p=self.plan(MODEL+'void root(void){unsigned*p=current()->a;'+loop+'}')
                self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
    def test_bounds_zero_trip_iteration_and_alias_caps(self):
        for initial,loop in (('current()->a','for(unsigned i=0;i<5;i++)*p++=i;'),
            ('current()->a+3','for(unsigned i=0;i<4;i++)*p--=i;'),
            ('current()->a','for(unsigned i=4;i<4;i++)*p++=i;'),
            ('current()->a','for(unsigned i=0;i<17;i++)*p++=i;')):
            with self.subTest(initial=initial,loop=loop):
                p=self.plan(MODEL+'void root(void){unsigned*p='+initial+';'+loop+'}')
                self.assertTrue(p['blockers'])
        p=self.plan(MODEL+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++)*p++=i;}',max_alias_paths=3)
        self.assertTrue(p['analysis_limits']['alias_path_limit_observed']);self.assertTrue(p['blockers'])
    def test_unknown_escaped_cursors_and_cursor_dependent_rhs_remain_review(self):
        for text in ('void root(unsigned*arg){unsigned*p=arg;for(unsigned i=0;i<4;i++)*p++=i;}',
            MODEL+'void root(void){unsigned*p=current()->a;unsigned**q=&p;for(unsigned i=0;i<4;i++)*p++=i;}',
            MODEL+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++)*p++=*p;}'):
            with self.subTest(text=text):
                p=self.plan(text);self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
    def test_write_pruning_preserves_every_rmw_entry_value(self):
        p=self.positive(MODEL+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++)*p+++=i;}',prune_written=True,preserve_write_state=True)
        self.assertEqual({r['path'] for r in entry_accesses(p)},{'current()->a['+str(i)+']' for i in range(4)})
    def test_native_capture_and_original_loop_results(self):
        body=MODEL+'unsigned twice(unsigned n){return 2*n;}void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++)*p+++=twice(i);}'
        p=self.positive(body)
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);(stage/'capture.h').write_text(capture_header([p]));source=stage/'run.c'
            source.write_text(body+'\n#include "capture.h"\n#include <assert.h>\n#include <string.h>\nstatic struct Obj object={{10,20,30,40},{1,2,3,4}};struct Obj*current(void){return &object;}\nint main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s));assert(s.object_count==1&&s.field_count==4);for(unsigned i=0;i<4;i++)assert(s.fields[i].size==sizeof(unsigned)&&memcmp(s.fields[i].bytes,&object.a[i],sizeof(unsigned))==0);root();assert(object.a[0]==10&&object.a[1]==22&&object.a[2]==34&&object.a[3]==46);return 0;}')
            binary=stage/'run';subprocess.run([basic.CLANG,'-std=c11','-I'+str(basic.ROOT/'include'),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
