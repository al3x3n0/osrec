"""Unused straight-line local updates retain all bounded pointer versions."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer,capture_header

class PointerUpdateTests(unittest.TestCase):
    def plan(self,text,**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree)
            analyzer=Analyzer(tree,basic.POLICY,**options);p=analyzer.analyze('root')
            self.assertEqual(p,analyzer.fresh().analyze('root'));self.assertEqual(tree,before)
            self.assertNotIn('bounded-pointer:',json.dumps(p));return p
    def positive(self,text,**options):
        p=self.plan(text,**options);self.assertFalse(p['blockers'],p['blockers'])
        self.assertTrue(p['pointer_update_proofs']);capture_header([p]);return p
    def test_increment_decrement_compound_and_self_assignment_forms(self):
        p=self.positive('const unsigned a[8]={1,2,3,4,5,6,7,8};unsigned root(void){const unsigned*p=a;++p;p++;p+=2;p--;--p;p=p+1;p=1+p;p=p-1;return *p;}')
        self.assertEqual(len(p['pointer_update_proofs']),8)
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:a['+str(n)+']' for n in range(5)})
        proofs=p['pointer_update_proofs'];self.assertTrue(all(v['all_versions_retained'] and not v['statement_result_used'] and v['max_updates']==16 for v in proofs))
        self.assertEqual(proofs[-1]['after'][0]['element_offset'],3)
    def test_all_versions_are_used_before_and_after_update(self):
        p=self.positive('const unsigned a[4]={11,22,33,44};unsigned root(void){const unsigned*p=a;unsigned x=*p;p++;return x+*p;}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:a[0]','global:a[1]'})
        self.assertEqual(p['pointer_update_proofs'][0]['may_alias_origins_retained'],2)
    def test_alias_ranges_and_multiple_arrays_keep_every_origin(self):
        p=self.positive('const unsigned a[4]={1,2,3,4},b[4]={5,6,7,8};unsigned root(unsigned n,unsigned m){const unsigned*p=n?a:b;p+=m%2;return *p;}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:'+name+'['+str(i)+']' for name in ('a','b') for i in (0,1)})
        proof=p['pointer_update_proofs'][0];self.assertEqual(len(proof['before']),2);self.assertEqual(len(proof['after']),4)
    def test_one_past_formation_and_conservative_dereference(self):
        p=self.positive('unsigned a[4];long root(void){unsigned*p=a;p+=4;return p-a;}')
        self.assertEqual(p['pointer_update_proofs'][0]['after'][0]['element_offset'],4)
        p=self.plan('unsigned a[4];unsigned root(void){unsigned*p=a+4;p--;return *p;}')
        self.assertTrue(p['pointer_update_proofs']);self.assertIn('array_bounds',{b['kind'] for b in p['blockers']})
    def test_unknown_invalid_and_escaped_values_remain_blocked(self):
        bodies=(
            'unsigned*p=a;p+=4;return *p;',
            'unsigned*p=a+3;p+=2;return 0;',
            'unsigned*p=a;--p;return 0;',
            'unsigned*p=a;p+=n;return *p;',
            'unsigned*p=n?a:0;p++;return *p;',
            'unsigned*p;p=a;p++;return *p;',
            'unsigned*p=a;unsigned**q=&p;p++;return *p;',
            'unsigned*p=a;p=(unsigned*)(unsigned long)(p+1);return *p;',
            'unsigned*p=a;p+=p-a;return *p;',
        )
        for body in bodies:
            with self.subTest(body=body):
                p=self.plan('unsigned root(unsigned n){unsigned a[4]={1,2,3,4};'+body+'}')
                self.assertTrue(p['blockers'])
                with self.assertRaises(ValueError):capture_header([p])
    def test_loops_branches_nested_consumed_and_parameter_updates_stay_blocked(self):
        bodies=(
            'unsigned*p=a;if(n)p++;return *p;',
            'unsigned*p=a;{p++;}return *p;',
            'unsigned*p=a;unsigned*q=++p;return *q;',
            'unsigned*p=a;unsigned*q=(p+=1);return *q;',
        )
        for body in bodies:
            with self.subTest(body=body):
                p=self.plan('unsigned root(unsigned n){unsigned a[4]={1,2,3,4};'+body+'}')
                self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
        p=self.plan('unsigned root(unsigned*p){p++;return *p;}')
        self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
    def test_update_and_alias_caps_are_enforced(self):
        p=self.plan('unsigned root(void){unsigned a[32];unsigned*p=a;'+'p++;'*17+'return *p;}')
        self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
        p=self.plan('unsigned root(unsigned n){unsigned a[8];unsigned*p=a;p+=n%4;return *p;}',max_alias_paths=3)
        self.assertTrue(p['analysis_limits']['alias_path_limit_observed']);self.assertTrue(p['blockers'])
    def test_effects_qualifiers_and_pointed_storage_writes_are_preserved(self):
        p=self.plan('unsigned a[4],counter;unsigned root(void){unsigned*p=a;counter++;p+=counter%2;*p=7;return *p;}')
        self.assertFalse(p['blockers']);self.assertTrue(p['pointer_update_proofs'])
        self.assertEqual({r['path'] for r in p['state_writes']},{'global:counter','global:a[0]','global:a[1]'})
        self.assertIn('global:counter',{r['path'] for r in p['entry_reads']})
        p=self.plan('unsigned a[4];unsigned ext(void);unsigned root(void){unsigned*p=a;p+=ext()%2;return *p;}')
        self.assertIn('unmodeled_external',{b['kind'] for b in p['blockers']});self.assertEqual([c['callee'] for c in p['call_sites']],['ext'])
        p=self.plan('unsigned root(void){unsigned a[4];unsigned*volatile p=a;p++;return *p;}')
        self.assertIn('volatile_memory',{b['kind'] for b in p['blockers']})
    def test_native_zero_field_capture_preserves_update_results(self):
        body='const unsigned a[6]={10,20,30,40,50,60};unsigned root(void){const unsigned*p=a;p++;p+=2;p--;return *p+(unsigned)(p-a);}'
        p=self.positive(body)
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);(stage/'capture.h').write_text(capture_header([p]));source=stage/'run.c'
            source.write_text(body+'\n#include "capture.h"\n#include <assert.h>\nint main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s));assert(s.object_count==0&&s.field_count==0);assert(root()==32);return 0;}')
            binary=stage/'run';subprocess.run([basic.CLANG,'-std=c11','-I'+str(basic.ROOT/'include'),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
