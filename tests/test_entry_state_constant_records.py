"""Fixed numeric struct data requires complete, pure, compatible definitions."""
import copy,json,subprocess,sys,tempfile
from pathlib import Path
import unittest
import test_entry_state as basic
import test_entry_state_global_arrays as arrays
from entry_state import Analyzer,capture_header,entry_accesses,digest
class ConstantRecordTests(unittest.TestCase):
    def plan(self,text,root='root'):
        with tempfile.TemporaryDirectory() as tmp:
            tree=basic.EntryStateTests().parse(Path(tmp),text)[0];before=copy.deepcopy(tree)
            a=Analyzer(tree);p=a.analyze(root)
            self.assertEqual(tree,before);self.assertEqual(p,a.fresh().analyze(root));return p
    def positive(self,text):
        p=self.plan(text);self.assertFalse(p['blockers'],p['blockers'])
        self.assertTrue(p['entry_reads']);self.assertFalse(entry_accesses(p));capture_header([p]);return p
    def test_nested_structs_anonymous_rows_and_numeric_typedefs(self):
        p=self.positive('''typedef unsigned long long Word;struct Table{struct{double x,y;} rows[2];Word values[2];};
const struct Table data={{{1,2},{3,4}},{5,6}};double root(void){return data.rows[1].x+data.values[0];}''')
        self.assertEqual({r['path'] for r in p['entry_reads']},{'global:data.rows[1].x','global:data.values[0]'})
        self.assertTrue(all(r['immutable_global']['kind']=='defined_const_numeric_record' for r in p['entry_reads']))
    def test_bounded_selection_array_roots_and_pointer_views(self):
        self.positive('''struct Item{unsigned value;};const struct Item items[3]={{1},{2},{3}};
unsigned root(unsigned n){return items[n%3].value;}''')
        self.positive('''struct Item{unsigned values[4];};const struct Item data={{1,2,3,4}};
unsigned root(unsigned n){const unsigned*p=data.values;return p[n%4];}''')
    def test_designated_partial_and_zero_initializers(self):
        self.positive('''struct Item{unsigned a[5];struct{unsigned x,y;} row[3];};
const struct Item data={.a={[3]=9},.row={[1]={.y=7}}};unsigned root(void){return data.a[0]+data.a[3]+data.row[0].x+data.row[1].y;}''')
    def test_mutable_extern_volatile_pointer_union_and_bitfield_data_are_not_omitted(self):
        texts=(
            'struct T{unsigned x;};struct T data={1};unsigned root(void){return data.x;}',
            'struct T{unsigned x;};extern const struct T data;unsigned root(void){return data.x;}',
            'struct T{volatile unsigned x;};const struct T data={1};unsigned root(void){return data.x;}',
            'struct T{unsigned x;unsigned*p;};const struct T data={1,0};unsigned root(void){return data.x;}',
            'union T{unsigned x;double d;};const union T data={.x=1};unsigned root(void){return data.x;}',
            'struct T{unsigned x:3;};const struct T data={1};unsigned root(void){return data.x;}',
            'struct T{char text[3];unsigned x;};const struct T data={"ab",1};unsigned root(void){return data.x;}',
            'struct __attribute__((packed)) T{unsigned x;};const struct T data={1};unsigned root(void){return data.x;}',
        )
        for text in texts:
            with self.subTest(text=text):
                p=self.plan(text);self.assertFalse(any('immutable_global' in r for r in p['entry_reads']))
                with self.assertRaises(ValueError):capture_header([p])
    def test_loaded_definition_is_required_and_type_compatibility_is_checked(self):
        header='struct T{unsigned x;unsigned a[2];};extern const struct T data;'
        with tempfile.TemporaryDirectory() as tmp:
            tree=arrays.GlobalArrayTests().parse(Path(tmp),{'root.c':header+'unsigned root(void){return data.x+data.a[1];}','data.c':header+'const struct T data={7,{11,22}};'})
            p=Analyzer(tree).analyze('root');self.assertFalse(p['blockers']);self.assertFalse(entry_accesses(p));capture_header([p])
        with tempfile.TemporaryDirectory() as tmp,self.assertRaisesRegex(ValueError,'incompatible configured record'):
            arrays.GlobalArrayTests().parse(Path(tmp),{'root.c':header+'unsigned root(void){return data.x;}',
                'data.c':'struct T{float x;unsigned a[2];};const struct T data={7,{11,22}};'})
        with tempfile.TemporaryDirectory() as tmp:
            files={'root.c':'typedef unsigned Word;struct T{Word a[2];};extern const struct T data;unsigned root(void){return data.a[1];}',
                   'data.c':'typedef float Word;struct T{Word a[2];};const struct T data={{1,2}};'}
            try:tree=arrays.GlobalArrayTests().parse(Path(tmp),files)
            except ValueError:pass
            else:
                p=Analyzer(tree).analyze('root');self.assertFalse(any('immutable_global' in r for r in p['entry_reads']))
                with self.assertRaises(ValueError):capture_header([p])
    def test_conflicting_definitions_and_static_objects_do_not_bind_external(self):
        header='struct T{unsigned x;};extern const struct T data;'
        for files in (
            {'root.c':header+'unsigned root(void){return data.x;}','a.c':header+'const struct T data={1};','b.c':header+'const struct T data={2};'},
            {'root.c':header+'unsigned root(void){return data.x;}','a.c':'struct T{unsigned x;};static const struct T data={1};'},
        ):
            with self.subTest(files=files),tempfile.TemporaryDirectory() as tmp:
                tree=arrays.GlobalArrayTests().parse(Path(tmp),files);p=Analyzer(tree).analyze('root')
                self.assertTrue(entry_accesses(p))
                with self.assertRaises(ValueError):capture_header([p])
    def test_any_write_to_the_object_prevents_fixed_data_omission(self):
        p=self.plan('struct T{unsigned x,y;};const struct T data={1,2};unsigned root(void){((struct T*)&data)->y=7;return data.x;}')
        self.assertTrue(any('immutable_global' in r for r in p['entry_reads']))
        with self.assertRaises(ValueError):capture_header([p])
    def test_tampered_paths_shapes_and_initializers_are_rejected(self):
        p=self.positive('struct T{unsigned a[2];};const struct T data={{1,2}};unsigned root(void){return data.a[1];}')
        for change in ('path','index','type','schema_hash','initializer_hash','call','pointer_shape','bad_fields'):
            q=copy.deepcopy(p);r=q['entry_reads'][0];proof=r['immutable_global']
            if change=='path':r['path']='global:data.missing[1]'
            elif change=='index':r['path']='global:data.a[2]'
            elif change=='type':r['type']='const float'
            elif change=='schema_hash':proof['schema']['fields'][0]['shape']['elements']=3
            elif change=='initializer_hash':proof['initializer']['inner']=[]
            elif change=='call':
                proof['initializer']['inner'][0]['inner'][0]={'kind':'CallExpr','type':{'qualType':'unsigned int'}}
                proof['initializer_sha256']=digest(json.dumps(proof['initializer'],sort_keys=True).encode())
            elif change=='pointer_shape':
                proof['schema']['fields'][0]['shape']['element']['type']='unsigned int *'
                proof['schema_sha256']=digest(json.dumps(proof['schema'],sort_keys=True).encode())
            elif change=='bad_fields':proof['schema']['fields']=[{'name':[],'shape':{}}]
            with self.subTest(change=change),self.assertRaises(ValueError):capture_header([q])
    def test_bounds_and_root_pointer_escapes_remain_guarded(self):
        for body in ('return data.a[n];','return data.a[2];'):
            p=self.plan('struct T{unsigned a[2];};const struct T data={{1,2}};unsigned root(unsigned n){'+body+'}')
            self.assertTrue(p['blockers'])
            with self.assertRaises(ValueError):capture_header([p])
    def test_native_capture_omits_fixed_records_and_keeps_original_results(self):
        text='struct T{struct{unsigned x,y;} rows[2];unsigned a[2];};const struct T data={{{11,22},{33,44}},{55,66}};unsigned root(unsigned n){return data.rows[n%2].x+data.a[1];}'
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);tree=basic.EntryStateTests().parse(stage,text)[0];p=Analyzer(tree).analyze('root')
            self.assertFalse(entry_accesses(p));(stage/'capture.h').write_text(capture_header([p]));source=stage/'native.c'
            source.write_text(text+'''
#include "capture.h"
int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);if(!osrec_snapshot_root(&s)||s.object_count||s.field_count)return 1;
return root(0)!=77||root(1)!=99;}
''')
            exe=stage/'native';subprocess.run([basic.CLANG,'-std=c11','-I',str(basic.ROOT/'include'),'-I',str(stage),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(exe)],check=True,capture_output=True)
            subprocess.run([str(exe)],check=True,timeout=10)
if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
