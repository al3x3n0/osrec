"""Same-array comparisons preserve runtime evaluation and all may aliases."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer,capture_header

class PointerComparisonTests(unittest.TestCase):
    def plan(self,text,root='root',**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree)
            analyzer=Analyzer(tree,basic.POLICY,**options);p=analyzer.analyze(root)
            self.assertEqual(p,analyzer.fresh().analyze(root));self.assertEqual(tree,before)
            self.assertNotIn('bounded-pointer:',json.dumps(p));return p
    def positive(self,text,**options):
        p=self.plan(text,**options);self.assertFalse(p['blockers'],p['blockers'])
        self.assertTrue(p['pointer_comparison_proofs']);capture_header([p]);return p
    def test_all_six_operators_and_one_past(self):
        for op in ('==','!=','<','>','<=','>='):
            with self.subTest(op=op):
                p=self.positive('int root(void){unsigned a[4];unsigned*p=a+4;return p'+op+'a;}')
                proof=p['pointer_comparison_proofs'][0]
                self.assertEqual(proof['operator'],op);self.assertEqual(proof['left_offsets'],[4]);self.assertEqual(proof['right_offsets'],[0])
                self.assertEqual(proof['result_range'],[0,1]);self.assertFalse(proof['branch_pruning']);self.assertFalse(proof['index_bounds_inferred'])
    def test_all_offset_alternatives_are_retained_without_subtracting(self):
        p=self.positive('unsigned a[40000];int root(unsigned n,unsigned m){unsigned*p=a+(n%4);unsigned*q=a+39997+(m%4);return p<q;}')
        proof=p['pointer_comparison_proofs'][0]
        self.assertEqual(proof['left_offsets'],[0,1,2,3]);self.assertEqual(proof['right_offsets'],[39997,39998,39999,40000])
        self.assertNotIn('pointer_difference_proofs',p)
    def test_helpers_and_direct_global_record_fields(self):
        p=self.positive('struct T{unsigned a[4];}object;int before(unsigned*p,unsigned*q){return p<q;}int root(void){return before(object.a,object.a+4);}')
        proof=p['pointer_comparison_proofs'][0]
        self.assertEqual(proof['storage'],'global:object.a');self.assertEqual(proof['call_path'],['root','before'])
        self.assertFalse(proof['automatic_storage'])
    def test_different_mixed_unknown_null_and_indirect_arrays_remain_blocked(self):
        bodies=(
            'unsigned a[4],b[4];return a==b;',
            'unsigned a[4],b[4];unsigned*p=n?a:b;return p<a;',
            'unsigned a[4];unsigned*p=n?a:0;return p!=a;',
            'unsigned a[4];unsigned*p;return p==a;',
            'unsigned a[4];return a==0;',
            'return current()->a<current()->a+1;',
            'return pointer->a==pointer->a;',
            'unsigned a[4];return ((unsigned*)((char*)a+1))<a;',
        )
        for body in bodies:
            with self.subTest(body=body):
                p=self.plan('struct T{unsigned a[4];};struct T*current(void);struct T*pointer;int root(unsigned n){'+body+'}')
                self.assertIn('pointer_arithmetic',{b['kind'] for b in p['blockers']});self.assertNotIn('pointer_comparison_proofs',p)
                with self.assertRaises(ValueError):capture_header([p])
    def test_lifetime_shadowing_bounds_and_alias_caps(self):
        for body in ('unsigned*p,*q;{unsigned a[4];p=a;q=a+1;}return p<q;',
                     'unsigned a[4];unsigned*p=a;{unsigned a[4];return p==a;}',
                     'unsigned a[4];return (a+5)>a;'):
            with self.subTest(body=body):
                p=self.plan('int root(void){'+body+'}');self.assertTrue(p['blockers']);self.assertNotIn('pointer_comparison_proofs',p)
        p=self.plan('int root(unsigned n){unsigned a[8];unsigned*p=a+(n%8);return p<a+8;}',max_alias_paths=3)
        self.assertTrue(p['analysis_limits']['alias_path_limit_observed']);self.assertTrue(p['blockers'])
    def test_comparisons_do_not_prune_branches_or_supply_index_bounds(self):
        p=self.plan('unsigned root(void){unsigned a[4];if(a+1<a)return a[5];return 0;}')
        self.assertIn('array_bounds',{b['kind'] for b in p['blockers']});self.assertTrue(p['pointer_comparison_proofs'])
        # A comparison result is 0 or 1; the pointer relation itself is never folded.
        p=self.plan('unsigned root(void){unsigned a[4];return a[a<a+1];}')
        self.assertEqual([r['index_bounds'] for r in p['memory_ranges']],[[0,1]])
    def test_effects_and_legacy_raw_pointer_comparisons_are_unchanged(self):
        p=self.plan('unsigned a[4];unsigned ext(void);int root(void){return (a+(ext()%4))<a+4;}')
        self.assertIn('unmodeled_external',{b['kind'] for b in p['blockers']});self.assertEqual([c['callee'] for c in p['call_sites']],['ext'])
        p=self.plan('unsigned a[4],counter;int root(void){counter++;a[1]=7;return a<a+4;}')
        self.assertFalse(p['blockers']);self.assertTrue(p['pointer_comparison_proofs'])
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:counter'})
        self.assertEqual({r['path'] for r in p['state_writes']},{'global:counter','global:a[1]'})
        p=self.plan('int root(unsigned*p,unsigned*q){return p<q;}')
        self.assertFalse(p['blockers']);self.assertNotIn('pointer_comparison_proofs',p)
        p=self.plan('unsigned root(unsigned*p,unsigned*q){return sizeof(p<q);}')
        self.assertFalse(p['blockers']);self.assertNotIn('pointer_comparison_proofs',p)
    def test_native_capture_preserves_all_comparison_results(self):
        body='int root(unsigned n){unsigned a[8];unsigned*p=a+(n%4);unsigned*q=a+4;return (p==q)+2*(p!=q)+4*(p<q)+8*(p>q)+16*(p<=q)+32*(p>=q);}'
        p=self.positive(body)
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);(stage/'capture.h').write_text(capture_header([p]));source=stage/'run.c'
            source.write_text(body+'\n#include "capture.h"\n#include <assert.h>\nint main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s));assert(s.object_count==0&&s.field_count==0);for(unsigned n=0;n<8;n++)assert(root(n)==22);return 0;}')
            binary=stage/'run';subprocess.run([basic.CLANG,'-std=c11','-I'+str(basic.ROOT/'include'),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
