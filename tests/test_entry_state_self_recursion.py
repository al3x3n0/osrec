"""Direct self-recursive memory footprints with invariant pointer parameters."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer,capture_header,entry_accesses
class SelfRecursionTests(unittest.TestCase):
    def plan(self,text,root='root',**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree);a=Analyzer(tree,basic.POLICY,**options);p=a.analyze(root)
            self.assertEqual(tree,before);self.assertEqual(p,a.fresh().analyze(root));return p
    def positive(self,text,**options):
        p=self.plan(text,**options);self.assertFalse(p['blockers'],p['blockers']);capture_header([p]);return p
    def rejected(self,text):
        p=self.plan(text);self.assertIn('recursion',{b['kind'] for b in p['blockers']});self.assertNotIn('recursion_footprint_proofs',p);return p
    def test_numeric_recursion_closes_each_direct_self_edge(self):
        p=self.positive('unsigned root(unsigned n){if(n<2)return n;return root(n-1)+root(n-2);}')
        self.assertEqual(len(p['recursion_footprint_proofs']),2)
        for proof in p['recursion_footprint_proofs']:
            self.assertFalse(proof['pointer_parameters']);self.assertFalse(proof['termination_proven']);self.assertTrue(proof['runtime_execution_unchanged'])
    def test_unchanged_output_pointer_uses_existing_scalar_storage(self):
        p=self.positive('unsigned sum(unsigned n,unsigned*out){if(n)return sum(n-1,out)+n;*out=7;return 0;}unsigned root(unsigned n){unsigned out;unsigned s=sum(n,&out);return s+out;}')
        self.assertEqual(p['recursion_footprint_proofs'][0]['pointer_parameters'],[dict(index=1,name='out',type='unsigned int *')])
        self.assertFalse(entry_accesses(p));self.assertTrue(p['scalar_address_proofs'])
    def test_numeric_arguments_do_not_prune_memory_ranges(self):
        p=self.positive('const unsigned a[4]={1,2,3,4};unsigned root(unsigned n){if(n)return a[n%4]+root(n-1);return a[0];}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:a['+str(i)+']' for i in range(4)})
        self.assertTrue(p['recursion_footprint_proofs'][0]['numeric_arguments_not_folded'])
    def test_pointer_parameter_mutation_anywhere_disables_summary(self):
        for statement in ('p++;','p=p+1;','p=q;'):
            self.rejected('unsigned walk(unsigned n,unsigned*p,unsigned*q){'+statement+'if(n)return walk(n-1,p,q);return *p;}unsigned root(unsigned n){unsigned a[2]={1,2};return walk(n,a,a);}')
    def test_changed_swapped_and_conditional_pointer_arguments_reject(self):
        for arguments in ('p+1,q','q,p','n?p:q,q'):
            self.rejected('unsigned walk(unsigned n,unsigned*p,unsigned*q){if(n)return walk(n-1,'+arguments+');return *p;}unsigned root(unsigned n){unsigned a[4]={1,2,3,4};return walk(n,a,a);}')
    def test_explicit_function_or_pointer_casts_do_not_gain_summary(self):
        for call in ('walk(n-1,(unsigned*)p)','((unsigned(*)(unsigned,unsigned*))walk)(n-1,p)'):
            self.rejected('unsigned walk(unsigned n,unsigned*p){if(n)return '+call+';return *p;}unsigned root(unsigned n){unsigned a=1;return walk(n,&a);}')
        # Array declarators decay to the same pointer type in Clang JSON, but
        # their hidden bounds can mutate shared state at every invocation.
        self.rejected('unsigned count;unsigned root(unsigned n,unsigned p[++count]){if(n)return root(n-1,p);return 0;}')
        self.rejected('unsigned root(unsigned n,unsigned p[n]){if(n)return root(n-1,p);return 0;}')
    def test_mutual_pointer_return_and_frame_address_cases_stay_blocked(self):
        self.rejected('unsigned b(unsigned);unsigned root(unsigned n){if(n)return b(n-1);return n;}unsigned b(unsigned n){return root(n);}')
        self.rejected('unsigned a[2];unsigned*get(unsigned n){if(n)return get(n-1);return a;}unsigned root(unsigned n){return *get(n);}')
        self.rejected('unsigned walk(unsigned n,unsigned*p){unsigned q=0;if(n)return walk(n-1,&q);return *p;}unsigned root(unsigned n){unsigned a=1;return walk(n,&a);}')
        self.rejected('unsigned walk(unsigned n,unsigned*p){unsigned*q=p;if(n)return walk(n-1,p);return *q;}unsigned root(unsigned n){unsigned a=1;return walk(n,&a);}')
    def test_other_effect_blockers_survive_closed_self_edges(self):
        p=self.plan('unsigned unknown(void);unsigned root(unsigned n){unsigned x=unknown();if(n)return root(n-1)+x;return x;}')
        self.assertIn('unmodeled_external',{b['kind'] for b in p['blockers']});self.assertTrue(p['recursion_footprint_proofs'])
        p=self.plan('volatile unsigned device;unsigned root(unsigned n){if(n)return root(n-1);return device;}')
        self.assertIn('volatile_memory',{b['kind'] for b in p['blockers']})
    def test_alias_and_context_limits_are_not_raised(self):
        text='unsigned walk(unsigned n,unsigned*p){if(n)return walk(n-1,p);return *p;}unsigned root(unsigned n){unsigned a=1,b=2;return walk(n,n?&a:&b);}'
        p=self.plan(text,max_alias_paths=1);self.assertTrue(p['analysis_limits']['alias_path_limit_observed']);self.assertTrue(p['blockers'])
        p=self.plan(text,max_contexts=1);self.assertIn('analysis_limit',{b['kind'] for b in p['blockers']});self.assertNotIn('recursion_footprint_proofs',p)
    def test_footprint_closure_does_not_claim_termination_and_roots_are_isolated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),'unsigned root(unsigned n){return root(n+1);}unsigned plain(void){return 3;}')[0];a=Analyzer(tree)
            p=a.fresh().analyze('root');self.assertFalse(p['blockers']);self.assertFalse(p['recursion_footprint_proofs'][0]['recursion_depth_bound_proven'])
            self.assertNotIn('recursion_footprint_proofs',a.fresh().analyze('plain'));self.assertEqual(p,a.fresh().analyze('root'))
    def test_cross_file_static_recursive_helper_keeps_its_namespace(self):
        import test_discovered_call_closure as fixture
        from discover_call_closure import discover
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);db,index=fixture.setup(d,{'root.c':'unsigned helper(unsigned);unsigned root(unsigned n){return helper(n);}', 'helper.c':'static unsigned sum(unsigned n,unsigned*p){if(n)return sum(n-1,p)+n;*p=7;return 0;}unsigned helper(unsigned n){unsigned q;unsigned s=sum(n,&q);return s+q;}'})
            r=discover(db,d/'root.c','root',index);self.assertEqual(r['status'],'candidate');self.assertTrue(r['capture_schema_accepted'])
            self.assertEqual(r['plan']['recursion_footprint_proofs'][0]['function'],'tu1:sum')
    def test_native_capture_does_not_execute_recursion_or_remove_its_effects(self):
        text='struct Obj{unsigned calls,value;};struct Obj*current(void);unsigned sum(unsigned n,unsigned*out){current()->calls++;if(n)return sum(n-1,out)+n;*out=current()->value;return 0;}unsigned root(unsigned n){unsigned out;unsigned s=sum(n,&out);return s+out;}'
        p=self.positive(text);self.assertEqual(len(entry_accesses(p)),2)
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);(d/'capture.h').write_text(capture_header([p]));source=d/'run.c';source.write_text(text+'\n#include "capture.h"\n#include <assert.h>\n#include <string.h>\nstatic struct Obj object;struct Obj*current(void){return &object;}int main(void){for(unsigned n=0;n<8;n++){object=(struct Obj){10+n,7+n};struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s)&&s.field_count==2);assert(object.calls==10+n);assert(root(n)==7+n+n*(n+1)/2);assert(object.calls==11+2*n&&object.value==7+n);}return 0;}')
            binary=d/'run';subprocess.run([basic.CLANG,'-std=c11','-O1','-I'+str(basic.ROOT/'include'),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True);subprocess.run([str(binary)],check=True,capture_output=True)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
