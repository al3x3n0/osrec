"""Portable constant expressions bound cursor loops without runtime folding."""
import json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
import test_entry_state_bounded_count_cursor_loops as bounded
MODEL=bounded.MODEL;STRONG=bounded.STRONG
from entry_state import Analyzer,entry_accesses
from entry_state_program import load_program

class ConstantCursorLoopTests(unittest.TestCase):
    plan=bounded.BoundedCountCursorLoopTests.plan
    positive=bounded.BoundedCountCursorLoopTests.positive
    native=bounded.BoundedCountCursorLoopTests.native
    def test_enum_and_nonwrapping_expression_capacities(self):
        for bound in ('CAP','CAP-1+1','1U<<2','12U/3U','(7U&3U)+1U'):
            with self.subTest(bound=bound):
                p=self.positive(MODEL+'enum{CAP=4};void root(void){unsigned*p=current()->a;for(unsigned i=0;i<'+bound+';i++)*p+++=i;}')
                proof=p['pointer_update_proofs'][0]['loop']
                self.assertEqual(proof['iterations'],4)
                self.assertEqual(proof['constant_bounds']['guards'][0]['value'],4)
                self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->a['+str(i)+']' for i in range(4)})
    def test_constant_initial_counter_and_tighter_cap(self):
        p=self.positive(MODEL+'enum{START=2,CAP=6};void root(void){unsigned*p=current()->a;for(unsigned i=START;i<CAP&&i<8;i++)*p+++=i;}')
        loop=p['pointer_update_proofs'][0]['loop']
        self.assertEqual((loop['initial'],loop['exclusive_limit'],loop['iterations']),(2,6,4))
        self.assertEqual(loop['constant_bounds']['initial']['value'],2)
    def test_independent_constant_strides_and_reverse_traversal(self):
        body='struct Obj{unsigned a[8],b[5];};struct Obj*current(void);enum{CAP=4,STEP=2};void root(void){unsigned*d=current()->a;const unsigned*s=current()->b+4;for(unsigned i=0;i<CAP;i++){*d=*s;d+=STEP;s-=3U-2U;}}'
        p=self.positive(body)
        proofs=p['pointer_update_proofs'];self.assertEqual({v['loop']['pointer_step'] for v in proofs},{2,-1})
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->b['+str(i)+']' for i in range(1,5)})
        self.assertEqual({r['path'] for r in p['state_writes']},{'current()->a['+str(i)+']' for i in (0,2,4,6)})
        self.assertTrue(all(v['loop']['constant_bounds']['pointer_step']['value'] in (1,2) for v in proofs))
    def test_dynamic_counts_keep_zero_and_post_loop_prefixes(self):
        p=self.positive('enum{CAP=2+2};const unsigned a[6]={10,20,30,40,50,60};unsigned root(unsigned n){const unsigned*p=a;for(unsigned i=0;i<n&&i<CAP;i++)p++;return *p++;}')
        loop=p['pointer_update_proofs'][0]['loop']
        self.assertNotIn('iterations',loop);self.assertEqual(loop['maximum_iterations'],4)
        self.assertEqual(loop['condition']['constant_capacity_guards'],1)
        self.assertEqual(loop['condition']['literal_capacity_guards'],0)
        self.assertEqual([o['element_offset'] for o in p['pointer_update_proofs'][0]['exit_prefix_origins']],[0,1,2,3,4])
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:a['+str(i)+']' for i in range(5)})
    def test_invalid_constant_caps_and_steps_remain_blocked(self):
        declarations='unsigned cap;const unsigned fixed=4;unsigned limit(void);'
        for bound in ('0xffffffffU+5U','2147483647+5','1U/0U','1U<<32','(unsigned char)260','4ULL','fixed','limit()','(cap=4)'):
            with self.subTest(bound=bound):
                p=self.plan(MODEL+declarations+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<'+bound+';i++)*p++=i;}')
                self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
        # A zero step keeps the cursor on its first element; that offset is proven.
        p=self.plan(MODEL+declarations+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++){*p=1;p+=0;}}')
        self.assertFalse(p['blockers'],p['blockers']);self.assertEqual({w['path'] for w in p['state_writes']},{'current()->a[0]'})
        for step in ('1U/0U','1U<<32','0xffffffffU+2U','(unsigned char)257','fixed'):
            with self.subTest(step=step):
                p=self.plan(MODEL+declarations+'void root(void){unsigned*p=current()->a;for(unsigned i=0;i<4;i++){*p=1;p+='+step+';}}')
                self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
    def test_extents_alias_and_iteration_budgets_are_enforced(self):
        body=MODEL+'enum{CAP=2*2};void root(void){unsigned*p=current()->a;for(unsigned i=0;i<CAP;i++)*p++=i;}'
        p=self.plan(body,max_alias_paths=3);self.assertTrue(p['blockers']);self.assertTrue(p['analysis_limits']['alias_path_limit_observed'])
        for cap in ('5','17'):
            p=self.plan(MODEL+'enum{CAP='+cap+'};void root(void){unsigned*p=current()->a;for(unsigned i=0;i<CAP;i++)*p++=i;}')
            self.assertTrue(p['blockers'])
        p=self.plan(MODEL+'enum{CAP=4,STEP=2};void root(void){unsigned*p=current()->a;for(unsigned i=0;i<CAP;i++){*p=1;p+=STEP;}}')
        self.assertIn('array_bounds',{b['kind'] for b in p['blockers']})
    def test_native_partial_copy_preserves_destination_and_source(self):
        body=MODEL+'enum{START=1,CAP=5,STEP=1};void root(unsigned n){unsigned*d=current()->a;const unsigned*s=current()->b;for(unsigned i=START;i<n&&i<CAP;i++){*d=*s;d+=STEP;s+=2U-1U;}}'
        p=self.positive(body,policy=STRONG,prune_written=True,preserve_write_state=True)
        self.assertEqual(len(entry_accesses(p)),8)
        checks='static struct Obj object;struct Obj*current(void){return &object;}int main(void){unsigned counts[]={0,1,2,4,5,99,~0u};for(unsigned k=0;k<7;k++){object=(struct Obj){{10,20,30,40},{101,102,103,104}};struct Obj old=object;struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s)&&s.field_count==8);for(unsigned i=0;i<8;i++){unsigned v=i<4?old.a[i]:old.b[i-4];assert(s.fields[i].size==sizeof(unsigned)&&memcmp(s.fields[i].bytes,&v,sizeof(unsigned))==0);}root(counts[k]);for(unsigned i=0;i<4;i++){assert(object.a[i]==(i+1<counts[k]?old.b[i]:old.a[i]));assert(object.b[i]==old.b[i]);}}return 0;}'
        self.native(body,p,checks)
    def test_enum_identity_is_retained_across_translation_units(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);files=[];commands=[]
            for name,code in [('root.c','enum{CAP=2};void helper(void);void root(void){unsigned*p=current()->a;for(unsigned i=0;i<CAP;i++)*p+++=i;helper();}'),('helper.c','enum{CAP=4};void helper(void){unsigned*p=current()->b;for(unsigned i=0;i<CAP;i++)*p+++=i;}')]:
                source=stage/name;source.write_text(MODEL+code);files.append(source)
                commands.append(dict(directory=str(stage),file=str(source),arguments=[basic.CLANG,'-std=c11','-c',str(source),'-o',str(source.with_suffix('.o'))]))
            database=stage/'compile_commands.json';database.write_text(json.dumps(commands))
            tree,_=load_program(database,files[0],all_sources=True);analyzer=Analyzer(tree,basic.POLICY);p=analyzer.analyze('root')
            self.assertFalse(p['blockers'],p['blockers']);self.assertEqual(p,analyzer.fresh().analyze('root'))
            self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->a[0]','current()->a[1]',*('current()->b['+str(i)+']' for i in range(4))})
            self.assertEqual({v['loop']['iterations'] for v in p['pointer_update_proofs']},{2,4})

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
