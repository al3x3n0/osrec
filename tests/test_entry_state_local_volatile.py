"""Ownership proofs for initialized, address-free volatile numeric locals."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer,capture_header,entry_accesses
MODEL='struct Obj{unsigned value,other;};struct Obj*current(void);'
class LocalVolatileTests(unittest.TestCase):
    def plan(self,text,root='root',policy=None):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree)
            a=Analyzer(tree,policy or {});p=a.fresh().analyze(root)
            self.assertEqual(p,a.fresh().analyze(root));self.assertEqual(tree,before);return p
    def positive(self,text,**options):
        p=self.plan(text,**options);self.assertFalse(p['blockers'],p['blockers']);capture_header([p]);return p
    def test_initialized_numeric_types_reads_writes_and_updates(self):
        for typ,value in [('unsigned','3'),('int','-2'),('const unsigned','4'),('double','1.5'),('float','2.5f'),('long double','3.5L'),('_Bool','1')]:
            with self.subTest(typ=typ):
                mutation='' if 'const' in typ else 'y+=1;y++;'
                p=self.positive(typ+' root(void){volatile '+typ+' y='+value+';'+mutation+'return y;}')
                self.assertFalse(entry_accesses(p));self.assertEqual(len(p['local_volatile_storage_proofs']),1)
                proof=p['local_volatile_storage_proofs'][0];self.assertTrue(proof['original_operations_retained']);self.assertFalse(proof['value_folding'])
    def test_initializer_and_later_shared_effects_are_retained(self):
        body=MODEL+'unsigned helper(void){return current()->other++;}unsigned root(void){volatile unsigned y=current()->value++;y+=helper();return y;}'
        p=self.positive(body,policy=basic.POLICY)
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->value','current()->other'})
        self.assertEqual({r['path'] for r in p['state_writes']},{'current()->value','current()->other'})
        self.assertTrue(any(c['callee']=='helper' for c in p['call_sites']))
    def test_unknown_calls_and_volatile_global_inputs_remain_blocked(self):
        for text,kind in [('unsigned unknown(void);unsigned root(void){volatile unsigned y=unknown();return y;}','unmodeled_external'),('volatile unsigned device;unsigned root(void){volatile unsigned y=device;return y;}','volatile_memory')]:
            p=self.plan(text);self.assertIn(kind,{b['kind'] for b in p['blockers']});self.assertTrue(p['local_volatile_storage_proofs'])
    def test_address_taking_aliasing_return_and_even_later_escape_reject(self):
        for suffix in ('volatile unsigned*p=&y;return *p;','sink(&y);return y;','return (unsigned long)&y;','unsigned x=y;sink(&y);return x;'):
            p=self.plan('void sink(volatile unsigned*);unsigned long root(void){volatile unsigned y=3;'+suffix+'}')
            self.assertIn('volatile_memory',{b['kind'] for b in p['blockers']});self.assertNotIn('local_volatile_storage_proofs',p)
    def test_uninitialized_self_initialized_static_tls_pointer_and_atomic_reject(self):
        cases=['volatile unsigned y;return y;','volatile unsigned y=y;return y;',
               'static volatile unsigned y=3;return y;','_Thread_local static volatile unsigned y=3;return y;',
               'unsigned x=3;unsigned*volatile y=&x;return *y;','volatile _Atomic(unsigned) y=3;return y;']
        for body in cases:
            p=self.plan('unsigned root(void){'+body+'}')
            self.assertTrue(p['blockers']);self.assertNotIn('local_volatile_storage_proofs',p)
    def test_arrays_records_and_compound_literals_remain_blocked(self):
        for body in ('volatile unsigned y[1]={3};return y[0];','struct V{volatile unsigned x;};struct V y={3};return y.x;','return (volatile unsigned){3};'):
            p=self.plan('unsigned root(void){'+body+'}')
            self.assertIn('volatile_memory',{b['kind'] for b in p['blockers']});self.assertNotIn('local_volatile_storage_proofs',p)
    def test_jumps_switch_entries_asm_and_cleanup_reject_ownership_proof(self):
        bodies=['goto label;volatile unsigned y=3;label:return y;',
                'volatile unsigned y=3;switch(n){case 0:return y;default:return 0;}',
                'volatile unsigned y=3;__asm__ volatile("" : "+m"(y));return y;',
                'volatile unsigned y __attribute__((cleanup(clean)))=3;return y;']
        for body in bodies:
            p=self.plan('void clean(volatile unsigned*);unsigned root(unsigned n){'+body+'}')
            self.assertTrue(p['blockers']);self.assertNotIn('local_volatile_storage_proofs',p)
    def test_shadowed_names_nested_scope_and_helper_calls_keep_ownership(self):
        p=self.positive('unsigned helper(unsigned x){volatile unsigned y=x+1;return y;}unsigned root(unsigned n){volatile unsigned y=n;{volatile unsigned y=helper(n);n=y;}return y+n;}')
        proofs=p['local_volatile_storage_proofs'];self.assertEqual(len(proofs),3)
        self.assertEqual({p['function'] for p in proofs},{'root','helper'})
        self.assertEqual(len({json.dumps(p['declaration'],sort_keys=True) for p in proofs}),3)
    def test_native_capture_preserves_effects_and_observes_original_result(self):
        text=MODEL+'unsigned root(void){volatile unsigned y=current()->value++;y+=current()->other++;return y;}'
        p=self.positive(text,policy=basic.POLICY);self.assertEqual(len(entry_accesses(p)),2)
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);(d/'capture.h').write_text(capture_header([p]));source=d/'run.c'
            source.write_text(text+'\n#include "capture.h"\n#include <assert.h>\n#include <string.h>\nstatic struct Obj object={7,11};struct Obj*current(void){return &object;}int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s)&&s.field_count==2);unsigned seen[2]={0,0};for(unsigned i=0;i<2;i++)memcpy(&seen[i],s.fields[i].bytes,sizeof(unsigned));assert((seen[0]==7&&seen[1]==11)||(seen[0]==11&&seen[1]==7));assert(root()==18);assert(object.value==8&&object.other==12);return 0;}')
            binary=d/'run';subprocess.run([basic.CLANG,'-std=c11','-O1','-I'+str(basic.ROOT/'include'),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)
    def test_cross_file_closure_retains_initialized_local_and_nested_reads(self):
        import test_discovered_call_closure as fixture
        from discover_call_closure import discover
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);db,index=fixture.setup(d,{'root.c':'unsigned helper(unsigned);unsigned root(unsigned x){return helper(x);}', 'helper.c':'unsigned helper(unsigned x){volatile unsigned y=x;y+=1;return y;}'})
            r=discover(db,d/'root.c','root',index)
            self.assertEqual(r['status'],'candidate');self.assertTrue(r['capture_schema_accepted']);self.assertFalse(r['history'][-1]['missing_bodies'])
            self.assertEqual(len(r['plan']['local_volatile_storage_proofs']),1)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
