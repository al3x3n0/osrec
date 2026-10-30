"""A sequenced numeric dereference selects the correct pointer-update version."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_entry_state as basic
from entry_state import Analyzer,capture_header

class ConsumedPointerUpdateTests(unittest.TestCase):
    def plan(self,text,**options):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree)
            analyzer=Analyzer(tree,basic.POLICY,**options);p=analyzer.analyze('root')
            self.assertEqual(p,analyzer.fresh().analyze('root'));self.assertEqual(tree,before)
            self.assertNotIn('bounded-pointer:',json.dumps(p));return p
    def positive(self,text,**options):
        p=self.plan(text,**options);self.assertFalse(p['blockers'],p['blockers'])
        self.assertTrue(p['pointer_update_proofs']);capture_header([p]);return p
    def test_prefix_and_postfix_increment_decrement_choose_correct_versions(self):
        for expression,initial,index,version in (('*p++','a',0,'before'),('*++p','a',1,'after'),('*p--','a+2',2,'before'),('*--p','a+2',1,'after')):
            with self.subTest(expression=expression):
                p=self.positive('const unsigned a[4]={10,20,30,40};unsigned root(void){const unsigned*p='+initial+';return '+expression+';}')
                self.assertEqual({r['path'] for r in p['entry_reads']},{'global:a['+str(index)+']'})
                proof=p['pointer_update_proofs'][0];self.assertTrue(proof['statement_result_used'])
                self.assertEqual(proof['result_version'],version);self.assertEqual(proof['result_origins'],proof[version])
                self.assertEqual(proof['result_context'],'sequenced_numeric_dereference')
    def test_sequenced_initializers_assignments_and_mixed_standalone_updates(self):
        p=self.positive('const unsigned a[6]={10,20,30,40,50,60};unsigned root(void){const unsigned*p=a;unsigned x=*p++;unsigned y;y=*++p;p++;unsigned z=*p--;return x+y+z;}')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:a[0]','global:a[2]','global:a[3]'})
        proofs=p['pointer_update_proofs'];self.assertEqual(len(proofs),4)
        self.assertEqual([v['statement_result_used'] for v in proofs],[True,True,False,True])
    def test_scalar_promotions_and_live_automatic_arrays(self):
        p=self.positive('int root(void){unsigned char a[3]={1,2,3};unsigned char*p=a;int x=*p++;return x;}')
        self.assertFalse(p['entry_reads']);self.assertEqual(p['pointer_update_proofs'][0]['result_version'],'before')
        p=self.positive('unsigned long root(void){unsigned a[3]={1,2,3};unsigned*p=a;return *++p;}')
        self.assertFalse(p['entry_reads'])
    def test_one_past_formation_dereference_and_formation_failures(self):
        for expression,initial,index in (('*p++','a+3',3),('*--p','a+4',3)):
            p=self.positive('const unsigned a[4]={1,2,3,4};unsigned root(void){const unsigned*p='+initial+';return '+expression+';}')
            self.assertEqual({r['path'] for r in p['entry_reads']},{'global:a['+str(index)+']'})
        for expression,initial in (('*++p','a+3'),('*p++','a+4'),('*p--','a')):
            with self.subTest(expression=expression,initial=initial):
                p=self.plan('unsigned root(void){unsigned a[4]={1,2,3,4};unsigned*p='+initial+';return '+expression+';}')
                self.assertIn('array_bounds',{b['kind'] for b in p['blockers']})
                with self.assertRaises(ValueError):capture_header([p])
    def test_mixed_unsequenced_escaped_and_unsupported_value_contexts_remain_blocked(self):
        bodies=(
            'unsigned*p=a;return *p++ + *p;',
            'unsigned*p=a;return use(p++,p);',
            'unsigned*p=a;unsigned*q=p++;return *q;',
            'unsigned*p=a;return *(p+=1);',
            'unsigned*p=a;unsigned x=*p++,y=*p++;return x+y;',
            'unsigned*p=a;if(n)return *p++;return 0;',
            'unsigned*p=a;unsigned**q=&p;return *p++;',
        )
        for body in bodies:
            with self.subTest(body=body):
                p=self.plan('unsigned use(unsigned*,unsigned*);unsigned root(unsigned n){unsigned a[4]={1,2,3,4};'+body+'}')
                self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
    def test_unknown_values_qualifiers_and_unmodeled_initializer_effects(self):
        for declaration in ('unsigned*p=n?a:0;','unsigned*p;','unsigned*volatile p=a;'):
            with self.subTest(declaration=declaration):
                p=self.plan('unsigned root(unsigned n){unsigned a[4]={1,2,3,4};'+declaration+'return *p++;}')
                self.assertTrue(p['blockers'])
        p=self.plan('unsigned ext(void);unsigned root(void){unsigned a[4]={1,2,3,4};unsigned*p=a+(ext()%2);return *p++;}')
        self.assertIn('unmodeled_external',{b['kind'] for b in p['blockers']});self.assertEqual([c['callee'] for c in p['call_sites']],['ext'])
        p=self.plan('unsigned root(void){volatile unsigned a[4]={1,2,3,4};volatile unsigned*p=a;return *p++;}')
        self.assertIn('volatile_memory',{b['kind'] for b in p['blockers']})
    def test_caps_and_unevaluated_operands(self):
        p=self.plan('unsigned root(unsigned n){unsigned a[8]={};unsigned*p=a+(n%4);return *p++;}',max_alias_paths=3)
        self.assertTrue(p['analysis_limits']['alias_path_limit_observed']);self.assertTrue(p['blockers'])
        p=self.plan('unsigned root(void){unsigned a[32]={};unsigned*p=a;'+'unsigned x'+str(0)+'=*p++;'+''.join('unsigned x'+str(i)+'=*p++;' for i in range(1,17))+'return 0;}')
        self.assertTrue(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
        p=self.plan('unsigned root(void){unsigned a[4];unsigned*p=a;return sizeof(*p++);}')
        self.assertFalse(p['blockers']);self.assertNotIn('pointer_update_proofs',p)
    def test_native_values_preserve_all_four_update_forms(self):
        body='const unsigned a[6]={10,20,30,40,50,60};unsigned root(void){const unsigned*p=a;unsigned x=*p++;unsigned y=*++p;unsigned z=*p--;unsigned w=*--p;return x+y+z+w;}'
        p=self.positive(body)
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);(stage/'capture.h').write_text(capture_header([p]));source=stage/'run.c'
            source.write_text(body+'\n#include "capture.h"\n#include <assert.h>\nint main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s));assert(s.object_count==0&&s.field_count==0);assert(root()==80);return 0;}')
            binary=stage/'run';subprocess.run([basic.CLANG,'-std=c11','-I'+str(basic.ROOT/'include'),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
