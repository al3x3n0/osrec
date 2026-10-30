"""Structured definite assignment for private volatile numeric storage."""
import json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
import test_entry_state_local_volatile as owned
from entry_state import Analyzer,capture_header,entry_accesses
class AssignedVolatileTests(unittest.TestCase):
    plan=owned.LocalVolatileTests.plan
    positive=owned.LocalVolatileTests.positive
    def proof(self,p):
        proofs=p['local_volatile_storage_proofs'];self.assertEqual(len(proofs),1)
        proof=proofs[0];self.assertEqual(proof['kind'],'definitely_assigned_nonescaping_volatile_scalar')
        self.assertNotIn('initializer',proof);self.assertTrue(proof['initialization_proof']['assignments']);return proof
    def test_straight_line_assignments_use_the_shared_certificate(self):
        for typ,value in [('unsigned','3'),('float','1.5f'),('double','2.5'),('long double','3.5L'),('_Bool','1')]:
            with self.subTest(typ=typ):
                p=self.positive(typ+' root(void){volatile '+typ+' y;y='+value+';return y;}')
                proof=self.proof(p);self.assertEqual(proof['initialization_proof']['branch_joins'],'intersection')
                self.assertFalse(entry_accesses(p));self.assertTrue(proof['original_operations_retained'])
    def test_both_branches_and_returning_paths_prove_continuation(self):
        for body,assignments in [('if(n)y=3;else y=5;return y;',2),('if(n)return 9;y=3;return y;',1),('if(n)y=3;else return 9;return y;',1)]:
            p=self.positive('unsigned root(unsigned n){volatile unsigned y;'+body+'}')
            self.assertEqual(len(self.proof(p)['initialization_proof']['assignments']),assignments)
    def test_missing_conditional_assignment_or_read_before_store_reject(self):
        for body in ('return y;','if(n)y=3;return y;','if(n)return y;y=3;return y;','unsigned x=y;y=3;return x;','y=y+1;return y;'):
            p=self.plan('unsigned root(unsigned n){volatile unsigned y;'+body+'}')
            self.assertIn('volatile_memory',{b['kind'] for b in p['blockers']});self.assertNotIn('local_volatile_storage_proofs',p)
    def test_unsequenced_operands_cannot_initialize_each_other(self):
        for expression in ('use(y=3,y)','(y=3)+y','y+(y=3)'):
            p=self.plan('unsigned use(unsigned a,unsigned b){return a+b;}unsigned root(void){volatile unsigned y;return '+expression+';}')
            self.assertTrue(p['blockers']);self.assertNotIn('local_volatile_storage_proofs',p)
    def test_comma_and_completed_call_assignments_are_sequenced(self):
        for body in ('return (y=3,y);','use(y=3,0);return y;','y=(1 ? 3 : 4);return y;'):
            p=self.positive('unsigned use(unsigned a,unsigned b){return a+b;}unsigned root(void){volatile unsigned y;'+body+'}')
            self.proof(p)
    def test_compound_and_unary_updates_require_prior_assignment(self):
        p=self.positive('unsigned root(void){volatile unsigned y;y=3;y++;y*=2;return y;}');self.proof(p)
        for body in ('y++;return y;','y+=3;return y;','y+=(y=3);return y;'):
            p=self.plan('unsigned root(void){volatile unsigned y;'+body+'}')
            self.assertTrue(p['blockers']);self.assertNotIn('local_volatile_storage_proofs',p)
    def test_loop_body_assignment_does_not_initialize_after_the_loop(self):
        for body in ('while(n){y=3;n--;}return y;','for(unsigned i=0;i<n;i++)y=3;return y;','do{y=3;}while(n);return y;'):
            p=self.plan('unsigned root(unsigned n){volatile unsigned y;'+body+'}')
            self.assertTrue(p['blockers']);self.assertNotIn('local_volatile_storage_proofs',p)
        p=self.positive('unsigned root(unsigned n){volatile unsigned y;unsigned result=0;while(n){y=n;result+=y;n--;}return result;}')
        self.proof(p)
    def test_address_escape_and_bypassed_initialization_remain_blocked(self):
        for body in ('y=3;sink(&y);return y;','goto after;y=3;after:return y;','y=3;__asm__ volatile("" : "+m"(y));return y;'):
            p=self.plan('void sink(volatile unsigned*);unsigned root(void){volatile unsigned y;'+body+'}')
            self.assertTrue(p['blockers']);self.assertNotIn('local_volatile_storage_proofs',p)
    def test_assignment_rhs_effects_and_unknown_calls_remain_visible(self):
        p=self.positive(owned.MODEL+'unsigned root(void){volatile unsigned y;y=current()->value++;return y;}',policy=basic.POLICY)
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->value'})
        self.assertEqual({r['path'] for r in p['state_writes']},{'current()->value'})
        p=self.plan('unsigned unknown(void);unsigned root(void){volatile unsigned y;y=unknown();return y;}')
        self.assertIn('unmodeled_external',{b['kind'] for b in p['blockers']});self.proof(p)
    def test_declaration_budget_is_not_unbounded(self):
        for count in (64,65):
            p=self.plan('unsigned root(void){'+''.join('volatile unsigned y'+str(i)+';' for i in range(count))+'y0=3;return y0;}')
            if count==64:self.assertFalse(p['blockers']);self.proof(p)
            else:self.assertTrue(p['blockers']);self.assertNotIn('local_volatile_storage_proofs',p)
    def test_fresh_root_proofs_do_not_leak_between_functions(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),'unsigned first(void){volatile unsigned a=3;return a;}unsigned plain(void){return 4;}unsigned other(void){volatile unsigned b;b=5;return b;}')[0]
            analyzer=Analyzer(tree);first=analyzer.fresh().analyze('first');plain=analyzer.fresh().analyze('plain');other=analyzer.fresh().analyze('other')
            self.assertNotIn('local_volatile_storage_proofs',plain)
            self.assertEqual({p['function'] for p in other['local_volatile_storage_proofs']},{'other'})
            self.assertEqual(analyzer.fresh().analyze('first'),first);self.assertEqual(analyzer.local_volatile_proofs,[])
    def test_cross_file_and_native_capture_keep_original_stores(self):
        import test_discovered_call_closure as fixture
        from discover_call_closure import discover
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);db,index=fixture.setup(d,{'root.c':'unsigned helper(unsigned);unsigned root(unsigned x){return helper(x);}', 'helper.c':'unsigned helper(unsigned x){volatile unsigned y;y=x;y++;return y;}'})
            r=discover(db,d/'root.c','root',index);self.assertEqual(r['status'],'candidate');self.assertTrue(r['capture_schema_accepted']);self.proof(r['plan'])
            (d/'capture.h').write_text(capture_header([r['plan']]));main=d/'run.c';main.write_text('#include "capture.h"\n#include <assert.h>\nunsigned root(unsigned);int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s)&&s.field_count==0);for(unsigned i=0;i<8;i++)assert(root(i)==i+1);return 0;}')
            binary=d/'run';subprocess.run([basic.CLANG,'-std=c11','-O1','-I'+str(basic.ROOT/'include'),str(main),str(d/'root.c'),str(d/'helper.c'),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
