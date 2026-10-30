"""Subtraction needs one live numeric array for every may-alias pair."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer,capture_header

class PointerDifferenceTests(unittest.TestCase):
    def plan(self,text,root='root',**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree)
            analyzer=Analyzer(tree,basic.POLICY,**options);plan=analyzer.analyze(root)
            self.assertEqual(plan,analyzer.fresh().analyze(root));self.assertEqual(tree,before)
            self.assertNotIn('bounded-pointer:',json.dumps(plan));return plan
    def positive(self,text,**options):
        p=self.plan(text,**options);self.assertFalse(p['blockers'],p['blockers'])
        self.assertTrue(p['pointer_difference_proofs']);capture_header([p]);return p
    def test_local_global_negative_and_one_past_differences(self):
        p=self.positive('unsigned values[4];long root(void){unsigned a[4];unsigned*p=a+4;return (p-a)+((a+1)-(a+3))+((values+3)-values);}')
        self.assertFalse(p['entry_reads']);self.assertFalse(p['state_writes'])
        self.assertEqual({tuple(v['bounds']) for v in p['pointer_difference_proofs']},{(4,4),(-2,-2),(3,3)})
        self.assertTrue(all(v['all_may_alias_pairs_checked'] and v['portable_result_range']==[-32767,32767] for v in p['pointer_difference_proofs']))
    def test_alias_ranges_are_all_retained(self):
        p=self.positive('long root(unsigned n,unsigned m){unsigned a[8];unsigned*p=a+(n%4);unsigned*q=a+2+(m%3);return p-q;}')
        proof=p['pointer_difference_proofs'][0]
        self.assertEqual(proof['left_offsets'],[0,1,2,3]);self.assertEqual(proof['right_offsets'],[2,3,4]);self.assertEqual(proof['bounds'],[-4,1])
    def test_helper_parameters_and_nested_automatic_fields(self):
        p=self.positive('long distance(unsigned*p,unsigned*q){return p-q;}long root(void){struct T{unsigned a[4];}item;return distance(item.a+4,item.a);}')
        self.assertEqual(p['pointer_difference_proofs'][0]['call_path'],['root','distance'])
        self.assertEqual(p['pointer_difference_proofs'][0]['owner_call_path'],['root'])
        self.assertEqual(p['pointer_difference_proofs'][0]['storage'],'local:item.a')
    def test_distinct_mixed_unknown_and_provider_arrays_remain_blocked(self):
        bodies=(
            'unsigned a[4],b[4];return (a+1)-b;',
            'unsigned a[4],b[4];unsigned*p=n?a:b;return p-a;',
            'unsigned a[4];unsigned*p=n?a:0;return p-a;',
            'unsigned a[4];unsigned*p;return p-a;',
            'unsigned a[4];return ((unsigned*)((char*)a+1))-a;',
            'return (current()->a+1)-current()->a;',
            'return (global_pointer->a+1)-global_pointer->a;',
        )
        for body in bodies:
            with self.subTest(body=body):
                p=self.plan('struct T{unsigned a[4];};struct T*current(void);struct T*global_pointer;long root(unsigned n){'+body+'}')
                self.assertIn('pointer_arithmetic',{b['kind'] for b in p['blockers']})
                self.assertNotIn('pointer_difference_proofs',p)
                with self.assertRaises(ValueError):capture_header([p])
    def test_expired_shadowed_and_escaped_automatic_storage_remains_blocked(self):
        bodies=(
            'unsigned*p,*q;{unsigned a[4];p=a;q=a+1;}return q-p;',
            'unsigned a[4];unsigned*p=a;{unsigned a[4];return (a+1)-p;}',
        )
        for body in bodies:
            with self.subTest(body=body):
                p=self.plan('long root(void){'+body+'}')
                self.assertTrue(p['blockers']);self.assertNotIn('pointer_difference_proofs',p)
    def test_portable_signed_result_bound_and_formation_limits(self):
        self.positive('unsigned a[40000];long root(void){return (a+32767)-a;}')
        for body in ('return (a+32768)-a;','return a-(a+32768);','return (a+40001)-a;','return (a-1)-a;'):
            with self.subTest(body=body):
                p=self.plan('unsigned a[40000];long root(void){'+body+'}')
                self.assertTrue(p['blockers']);self.assertNotIn('pointer_difference_proofs',p)
        p=self.plan('long root(unsigned n){unsigned a[8];return (a+(n%8))-a;}',max_alias_paths=3)
        self.assertTrue(p['analysis_limits']['alias_path_limit_observed']);self.assertTrue(p['blockers'])
    def test_effects_reads_writes_and_unmodeled_calls_are_preserved(self):
        p=self.plan('unsigned a[4],counter;long root(void){counter++;a[1]=7;return (a+1)-a+a[2];}')
        self.assertFalse(p['blockers']);self.assertTrue(p['pointer_difference_proofs'])
        with self.assertRaises(ValueError):capture_header([p])
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:counter','global:a[2]'})
        self.assertEqual({r['path'] for r in p['state_writes']},{'global:counter','global:a[1]'})
        p=self.plan('unsigned a[4];unsigned ext(void);long root(void){return (a+(ext()%4))-a;}')
        self.assertIn('unmodeled_external',{b['kind'] for b in p['blockers']});self.assertEqual([c['callee'] for c in p['call_sites']],['ext'])
    def test_difference_does_not_prove_an_index_and_sizeof_is_unevaluated(self):
        p=self.plan('unsigned a[4];unsigned root(void){unsigned*p=a+1;return a[p-a];}')
        self.assertIn('dynamic_extent',{b['kind'] for b in p['blockers']})
        p=self.plan('long root(unsigned*p,unsigned*q){return sizeof(p-q);}')
        self.assertFalse(p['blockers']);self.assertNotIn('pointer_difference_proofs',p)
    def test_native_zero_field_capture_preserves_signed_results(self):
        body='long root(unsigned n){unsigned a[8];unsigned*p=a+(n%4);unsigned*q=a+4;return p-q;}'
        p=self.positive(body)
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);(stage/'capture.h').write_text(capture_header([p]))
            source=stage/'run.c';source.write_text(body+'\n#include "capture.h"\n#include <assert.h>\nint main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s));assert(s.object_count==0&&s.field_count==0);for(unsigned n=0;n<8;n++)assert(root(n)==(long)(n%4)-4);return 0;}')
            binary=stage/'run';subprocess.run([basic.CLANG,'-std=c11','-I'+str(basic.ROOT/'include'),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
