"""Automatic numeric scalar addresses retain bounded storage and lifetimes."""
import json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
import test_entry_state_bounded_pointers as pointers
from entry_state import Analyzer,capture_header,entry_accesses
class ScalarAddressTests(unittest.TestCase):
    plan=pointers.BoundedPointerTests.plan
    parse=pointers.BoundedPointerTests.parse
    def positive(self,text,**options):
        p=self.plan(text,**options);self.assertFalse(p['blockers'],p['blockers']);capture_header([p]);return p
    def test_helper_output_parameters_preserve_one_element_storage(self):
        for typ,value in [('unsigned','7'),('int','-3'),('double','2.5'),('long double','3.5L')]:
            p=self.positive('void fill('+typ+'*p){*p='+value+';}'+typ+' root(void){'+typ+' q;fill(&q);return q;}')
            proof=p['scalar_address_proofs'][0];self.assertEqual(proof['elements'],1);self.assertEqual(proof['storage'],'local:q')
            self.assertTrue(proof['value_aliases_not_used_as_storage']);self.assertFalse(proof['initializer_value_assumed']);self.assertFalse(entry_accesses(p))
    def test_address_does_not_borrow_the_initializers_global_value_path(self):
        p=self.positive('struct Obj{unsigned value;};struct Obj*current(void);void fill(unsigned*p){*p=9;}unsigned root(void){unsigned q=current()->value;fill(&q);return q;}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->value'});self.assertFalse(p['state_writes'])
        self.assertEqual(p['scalar_address_proofs'][0]['storage'],'local:q')
    def test_one_past_formation_and_retreat_use_existing_bounds(self):
        p=self.positive('unsigned root(void){unsigned q=7;unsigned*p=&q+1;return p[-1];}')
        self.assertTrue(any(r.get('pointer_provenance',{}).get('storage_kind')=='automatic_scalar' for r in p['memory_ranges']))
        for body in ('unsigned*p=&q+2;return 0;','unsigned*p=&q+1;return *p;','unsigned*p=&q;return p[-1];'):
            p=self.plan('unsigned root(void){unsigned q=7;'+body+'}')
            self.assertIn('array_bounds',{b['kind'] for b in p['blockers']})
    def test_mixed_scalar_and_array_origins_check_every_alternative(self):
        p=self.positive('unsigned root(unsigned n){unsigned q=7;unsigned a[2]={8,9};unsigned*p=n?&q:a;return p[0];}')
        self.assertFalse(entry_accesses(p))
        p=self.plan('unsigned root(unsigned n){unsigned q=7;unsigned a[2]={8,9};unsigned*p=n?&q:a;return p[1];}')
        self.assertIn('array_bounds',{b['kind'] for b in p['blockers']})
        p=self.plan('unsigned root(unsigned n){unsigned q=7;unsigned*p=n?&q:0;return *p;}');self.assertTrue(p['blockers'])
    def test_lexical_and_call_lifetimes_and_pointer_escapes_remain_checked(self):
        texts=['unsigned root(void){unsigned outer=0;unsigned*p=&outer;{unsigned q=7;p=&q;}return *p;}',
               'unsigned*bad(void){unsigned q=7;return &q;}unsigned root(void){return *bad();}',
               'unsigned*g;unsigned root(void){unsigned q=7;g=&q;return 0;}',
               'struct Box{unsigned*p;};unsigned root(void){unsigned q=7;struct Box b={&q};return *b.p;}']
        for text in texts:
            p=self.plan(text);self.assertTrue(p['blockers']);self.assertRaises(ValueError,capture_header,[p])
        p=self.positive('unsigned read(unsigned*p){return *p;}unsigned root(void){unsigned result;{unsigned q=7;result=read(&q);}return result;}')
        self.assertFalse(entry_accesses(p))
    def test_pointer_casts_and_qualified_scalars_do_not_gain_provenance(self):
        for text in ['unsigned root(void){unsigned q=7;unsigned char*p=(unsigned char*)&q;return *p;}',
                     'unsigned read(volatile unsigned*p){return *p;}unsigned root(void){volatile unsigned q=7;return read(&q);}',
                     'unsigned read(const unsigned*p){return *p;}unsigned root(void){const unsigned q=7;return read(&q);}']:
            p=self.plan(text);self.assertTrue(p['blockers'])
    def test_unknown_calls_and_boundary_pointer_arguments_stay_blocked(self):
        p=self.plan('void unknown(unsigned*p);unsigned root(void){unsigned q=7;unknown(&q);return q;}')
        self.assertIn('unmodeled_external',{b['kind'] for b in p['blockers']})
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),'void external(unsigned*p);unsigned root(void){unsigned q=7;external(&q);return q;}')
            p=Analyzer(tree,{'external':dict(kind='memory_model',reason='fixture',implementation='fixture',snapshot_safe=True)}).analyze('root')
            self.assertIn('boundary_memory_effect',{b['kind'] for b in p['blockers']})
    def test_declared_boundary_reads_accept_void_views_of_scalars(self):
        # LiteOS getresuid: LOS_ArchCopyToUser(user, &value, sizeof(int)) reads its source argument.
        copy=dict(kind='memory_model',reads=[1],reason='fixture',implementation='fixture',snapshot_safe=True)
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),'int copy(void*dst,const void*src,unsigned long n);int root(int*out){int q=7;return copy(out,&q,sizeof(int));}')
            p=Analyzer(tree,{'copy':copy}).analyze('root')
            self.assertFalse(p['blockers'],p['blockers']);self.assertEqual([r['paths'] for r in p['memory_ranges']],[['local:q']])
            for body,kind in (('return copy(out,(const char*)(const void*)&q+1,1);','pointer_arithmetic'),
                              ('return copy(out,(const void*)&q+1,1);',None),
                              ('return copy(&q,out,sizeof(int));','boundary_memory_effect')):
                tree=self.parse(Path(tmp),'int copy(void*dst,const void*src,unsigned long n);int root(int*out){int q=7;'+body+'}')
                p=Analyzer(tree,{'copy':copy}).analyze('root');self.assertTrue(p['blockers'],body)
                if kind:self.assertIn(kind,{b['kind'] for b in p['blockers']})
    def test_distinct_storage_and_call_frames_keep_separate_origins(self):
        p=self.positive('void fill(unsigned*p){*p=9;}unsigned helper(void){unsigned q=2;fill(&q);return q;}unsigned root(void){unsigned q=1;fill(&q);return q+helper();}')
        proofs=p['scalar_address_proofs'];self.assertEqual({tuple(p['owner_call_path']) for p in proofs},{('root',),('root','helper')})
        p=self.plan('long root(unsigned n){unsigned x=1,y=2;unsigned*p=n?&x:&y;return p-&x;}');self.assertTrue(p['blockers'])
    def test_global_parameter_and_record_addresses_are_not_reclassified(self):
        texts=['unsigned global;unsigned root(void){unsigned*p=&global;return *p;}',
               'unsigned root(unsigned q){unsigned*p=&q;return *p;}',
               'struct Box{unsigned value;};unsigned read(unsigned*p){return *p;}unsigned root(void){struct Box q={7};return read(&q.value);}']
        for text in texts:
            p=self.plan(text);self.assertNotIn('scalar_address_proofs',p)
    def test_alias_budget_and_fresh_root_isolation_are_unchanged(self):
        p=self.plan('unsigned root(unsigned n){unsigned a=1,b=2,c=3,d=4;unsigned*p=n==0?&a:n==1?&b:n==2?&c:&d;return *p;}',max_alias_paths=3)
        self.assertTrue(p['analysis_limits']['alias_path_limit_observed']);self.assertTrue(p['blockers'])
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),'unsigned root(void){unsigned q=1;unsigned*p=&q;return *p;}unsigned plain(void){return 2;}');a=Analyzer(tree)
            first=a.fresh().analyze('root');self.assertNotIn('scalar_address_proofs',a.fresh().analyze('plain'));self.assertEqual(first,a.fresh().analyze('root'))
    def test_cross_file_output_parameter_closure(self):
        import test_discovered_call_closure as fixture
        from discover_call_closure import discover
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);db,index=fixture.setup(d,{'root.c':'void fill(unsigned*);unsigned root(void){unsigned q;fill(&q);return q;}', 'helper.c':'void fill(unsigned*p){*p=7;}'})
            r=discover(db,d/'root.c','root',index);self.assertEqual(r['status'],'candidate');self.assertTrue(r['capture_schema_accepted']);self.assertEqual(r['program']['translation_units'],2)
    def test_native_capture_separates_temporary_writes_from_shared_state(self):
        text='struct Obj{unsigned value;};struct Obj*current(void);void fill(unsigned*p){*p=9;}unsigned root(void){unsigned q=current()->value;fill(&q);return q;}'
        p=self.positive(text);self.assertEqual(len(entry_accesses(p)),1)
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);(d/'capture.h').write_text(capture_header([p]));main=d/'run.c';main.write_text(text+'\n#include "capture.h"\n#include <assert.h>\n#include <string.h>\nstatic struct Obj object={7};struct Obj*current(void){return &object;}int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s)&&s.field_count==1);assert(memcmp(s.fields[0].bytes,&object.value,sizeof(unsigned))==0);assert(root()==9&&object.value==7);return 0;}')
            binary=d/'run';subprocess.run([basic.CLANG,'-std=c11','-I'+str(basic.ROOT/'include'),str(main),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True);subprocess.run([str(binary)],check=True,capture_output=True)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
