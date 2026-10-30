"""Capacity guards bound cursor prefixes without promising a complete loop."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer,capture_header,entry_accesses
MODEL='struct Obj{unsigned a[4],b[4];};struct Obj*current(void);'
STRONG={'current':{**basic.POLICY['current'],'stable_identity':True,'exclusive_state':True,'preserves_entry_state':True}}

class BoundedCountCursorLoopTests(unittest.TestCase):
    def plan(self,text,**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree)
            analyzer=Analyzer(tree,options.pop('policy',basic.POLICY),**options);p=analyzer.analyze('root')
            self.assertEqual(p,analyzer.fresh().analyze('root'));self.assertEqual(tree,before)
            self.assertNotIn('bounded-pointer:',json.dumps(p));return p
    def positive(self,text,**options):
        p=self.plan(text,**options);self.assertFalse(p['blockers'],p['blockers'])
        self.assertTrue(p['pointer_update_proofs']);capture_header([p]);return p
    def test_both_guard_orders_retain_zero_and_every_exit_prefix(self):
        for guard in ('i<n&&i<4','i<4&&i<n'):
            with self.subTest(guard=guard):
                p=self.positive(MODEL+'void root(unsigned n){unsigned*p=current()->a;for(unsigned i=0;'+guard+';i++)*p+++=i;}')
                proof=p['pointer_update_proofs'][0];loop=proof['loop']
                self.assertEqual(loop['kind'],'bounded_count_cursor_for');self.assertEqual(loop['maximum_iterations'],4)
                self.assertTrue(loop['zero_trip_possible'] and loop['all_exit_prefixes_retained']);self.assertNotIn('iterations',loop)
                self.assertEqual([o['element_offset'] for o in proof['exit_prefix_origins']],[0,1,2,3,4])
    def test_partial_copy_preserves_destination_inputs_when_requested(self):
        p=self.positive(MODEL+'void root(unsigned n){unsigned*d=current()->a;const unsigned*s=current()->b;for(unsigned i=0;i<n&&i<4;i++)*d++=*s++;}',policy=STRONG,prune_written=True,preserve_write_state=True)
        self.assertEqual({r['path'] for r in entry_accesses(p)},{'current()->'+name+'['+str(i)+']' for name in ('a','b') for i in range(4)})
        self.assertFalse(p['write_state_preservation']['guaranteed_exit_stores'])
    def test_post_loop_consumed_updates_use_all_prefixes_not_the_capacity(self):
        p=self.positive('const unsigned a[7]={10,20,30,40,50,60,70};unsigned root(unsigned n){const unsigned*p=a;for(unsigned i=0;i<n&&i<4;i++)p++;unsigned x=*p++;unsigned y=*p++;return x+y;}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:a['+str(i)+']' for i in range(6)})
        after=[v for v in p['pointer_update_proofs'] if 'loop' not in v]
        self.assertEqual([[o['element_offset'] for o in v['before']] for v in after],[[0,1,2,3,4],[1,2,3,4,5]])
    def test_body_phases_and_nonzero_initial_counter_remain_bounded(self):
        p=self.positive('struct Obj{unsigned a[8];};struct Obj*current(void);void root(unsigned n){unsigned*p=current()->a;for(unsigned i=2;i<n&&i<6;i++){*p+=i;p+=2;}}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->a['+str(i)+']' for i in (0,2,4,6)})
        loop=p['pointer_update_proofs'][0]['loop'];self.assertEqual((loop['initial'],loop['exclusive_limit'],loop['maximum_iterations']),(2,6,4))
    def test_count_may_change_but_counter_and_capacity_remain_protected(self):
        p=self.positive(MODEL+'void root(unsigned n){unsigned*p=current()->a;for(unsigned i=0;i<n&&i<4;i++){*p+++=n;n--;}}')
        self.assertEqual(p['pointer_update_proofs'][0]['loop']['maximum_iterations'],4)
        p=self.positive(MODEL+'void root(const unsigned n){unsigned*p=current()->a;for(unsigned i=0;i<n&&i<4;i++)*p+++=i;}')
        self.assertTrue(p['pointer_update_proofs'][0]['loop']['condition']['side_effect_free'])
        p=self.positive(MODEL+'void root(unsigned char n){unsigned*p=current()->a;for(unsigned i=0;i<n&&i<4;i++)*p+++=i;}')
        self.assertEqual(p['pointer_update_proofs'][0]['loop']['maximum_iterations'],4)
    def test_missing_caps_or_side_effecting_and_unsupported_guards_stay_review(self):
        for guard in ('i<n','i<n||i<4','i<n--&&i<4','i++<n&&i<4','i<limit()&&i<4','i<=n&&i<4'):
            with self.subTest(guard=guard):
                p=self.plan(MODEL+'unsigned limit(void);void root(unsigned n){unsigned*p=current()->a;for(unsigned i=0;'+guard+';i++)*p++=i;}')
                self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
    def test_bounds_and_post_loop_formation_include_maximum_possible_count(self):
        p=self.plan('struct Obj{unsigned a[3];};struct Obj*current(void);void root(unsigned n){unsigned*p=current()->a;for(unsigned i=0;i<n&&i<4;i++)*p++=i;}')
        self.assertIn('array_bounds',{b['kind'] for b in p['blockers']})
        p=self.plan(MODEL+'unsigned root(unsigned n){unsigned*p=current()->a;for(unsigned i=0;i<n&&i<4;i++)p++;return *p++;}')
        self.assertIn('array_bounds',{b['kind'] for b in p['blockers']})
    def test_alias_iteration_and_expanded_version_budgets_are_not_raised(self):
        p=self.plan(MODEL+'void root(unsigned n){unsigned*p=current()->a;for(unsigned i=0;i<n&&i<4;i++)*p++=i;}',max_alias_paths=3)
        self.assertTrue(p['analysis_limits']['alias_path_limit_observed']);self.assertTrue(p['blockers'])
        for cap in (8,17):
            with self.subTest(cap=cap):
                p=self.plan('unsigned root(unsigned n){unsigned a[32]={};unsigned*p=a;for(unsigned i=0;i<n&&i<'+str(cap)+';i++)p++;return *p++;}')
                self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
    def test_native_post_loop_values_distinguish_zero_short_and_full_traversal(self):
        body='const unsigned a[6]={10,20,30,40,50,60};unsigned root(unsigned n){const unsigned*p=a;for(unsigned i=0;i<n&&i<4;i++)p++;return *p++;}'
        p=self.positive(body)
        self.native(body,p,'unsigned counts[6]={0,1,3,4,99,~0u};unsigned expected[6]={10,20,40,50,50,50};for(unsigned k=0;k<6;k++)assert(root(counts[k])==expected[k]);')
    def native(self,body,plan,checks):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);(stage/'capture.h').write_text(capture_header([plan]));source=stage/'run.c'
            source.write_text(body+'\n#include "capture.h"\n#include <assert.h>\n#include <string.h>\n'+checks+'\n')
            # Value-only checks use a minimal main; the provider test below
            # supplies its full native object and capture harness explicitly.
            if not checks.startswith('static '):source.write_text(body+'\n#include "capture.h"\n#include <assert.h>\nint main(void){'+checks+'return 0;}')
            binary=stage/'run';subprocess.run([basic.CLANG,'-std=c11','-I'+str(basic.ROOT/'include'),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)
    def test_native_partial_copy_capture_preserves_zero_trip_and_tail_state(self):
        body=MODEL+'void root(unsigned n){unsigned*d=current()->a;const unsigned*s=current()->b;for(unsigned i=0;i<n&&i<4;i++)*d++=*s++;}'
        p=self.positive(body,policy=STRONG,prune_written=True,preserve_write_state=True)
        checks='static struct Obj object;struct Obj*current(void){return &object;}int main(void){unsigned counts[6]={0,1,3,4,99,~0u};for(unsigned k=0;k<6;k++){for(unsigned i=0;i<4;i++){object.a[i]=10*(i+1);object.b[i]=101+i;}struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s));assert(s.object_count==1&&s.field_count==8);for(unsigned i=0;i<4;i++){assert(s.fields[i].size==sizeof(unsigned)&&memcmp(s.fields[i].bytes,&object.a[i],sizeof(unsigned))==0);assert(s.fields[i+4].size==sizeof(unsigned)&&memcmp(s.fields[i+4].bytes,&object.b[i],sizeof(unsigned))==0);}root(counts[k]);for(unsigned i=0;i<4;i++){assert(object.a[i]==(i<counts[k]?101+i:10*(i+1)));assert(object.b[i]==101+i);}}return 0;}'
        self.native(body,p,checks)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
