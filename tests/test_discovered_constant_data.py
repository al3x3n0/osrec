"""Discover const record sources without selecting linker precedence or models."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_discovered_call_closure as fixture
from discover_call_closure import DefinitionIndex,discover
from discover_kernel_state import survey_unit,write
from entry_state import Analyzer,capture_header,digest,entry_accesses,load_ast
from entry_state_program import merge_translation_units

HEADER='struct T{unsigned values[3];};extern const struct T data;'
ROOT=HEADER+'unsigned root(unsigned n){return data.values[n%3];}'
DATA=HEADER+'const struct T data={{7,11,13}};'


def configured(stage,texts):
    stage=stage.resolve();stage.mkdir(exist_ok=True);entries=[];rows=[];objects=[]
    for name,text in texts.items():
        source=stage/name;source.parent.mkdir(parents=True,exist_ok=True);source.write_text(text)
        entries.append(dict(directory=str(stage),file=str(source),arguments=[fixture.CLANG,'--target=arm-none-eabi','-std=c11','-I',str(stage),'-c',str(source)]))
    db=stage/'compile_commands.json'
    write(db,entries)
    for i,entry in enumerate(entries):
        source=Path(entry['file']);obj=source.with_suffix('.o');dep=obj.with_suffix('.d')
        subprocess.run([*entry['arguments'],'-MD','-MF',str(dep),'-o',str(obj)],check=True,capture_output=True)
        unit=survey_unit(db,source,100);path=stage/(str(i)+'.json');write(path,unit)
        rows.append(dict(source=str(source),status='analyzed',report=path.name,report_sha256=digest(path.read_bytes())))
        objects.append(dict(source=str(source),source_sha256=digest(source.read_bytes()),language='c',
            object=str(obj),object_sha256=digest(obj.read_bytes()),dependency_file_sha256=digest(dep.read_bytes())))
    write(stage/'report.json',dict(format='osrec-kernel-state-discovery-v1',compilation_database_sha256=digest(db.read_bytes()),units=rows))
    write(stage/'objects.json',objects)
    return db,DefinitionIndex.from_survey(stage,db)


class ConstantDataDiscoveryTests(unittest.TestCase):
    def test_numeric_scalar_and_multidimensional_array_sources_are_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);header='extern const unsigned scale;extern const double data[2][2];'
            db,index=configured(stage,{'root.c':header+'double root(unsigned n){return scale+data[n%2][1];}',
                'data.c':header+'const unsigned scale=7;const double data[2][2]={{1,2},{3,4}};'})
            result=discover(db,stage/'root.c','root',index)
            self.assertTrue(result['capture_schema_accepted']);self.assertFalse(entry_accesses(result['plan']))
            self.assertEqual(len(result['history']),2)
            self.assertEqual(result['history'][0]['missing_constant_data'],['data','scale'])
            self.assertEqual({r['immutable_global']['kind'] for r in result['plan']['entry_reads']},
                {'defined_const_numeric_scalar','defined_const_numeric_array'})
            self.assertTrue(all(r['immutable_global']['declaration_location']['translation_unit']==str((stage/'data.c').resolve()) for r in result['plan']['entry_reads']))

    def test_incomplete_arrays_gain_only_verified_definition_extents(self):
        for expression,header,definition in (
            ('data[n%3]','extern const unsigned data[];','const unsigned data[3]={[1]=11};'),
            ('data[n%2][1]','extern const unsigned data[][2];','const unsigned data[2][2]={{1,2},{3,4}};'),
            ('p[n%3]','extern const unsigned data[];','const unsigned data[3]={7,11,13};')):
            with self.subTest(expression=expression),tempfile.TemporaryDirectory() as tmp:
                stage=Path(tmp);local='const unsigned*p=data;' if expression.startswith('p') else ''
                db,index=configured(stage,{'root.c':header+'unsigned root(unsigned n){'+local+'return '+expression+';}',
                    'data.c':definition})
                result=discover(db,stage/'root.c','root',index)
                self.assertTrue(result['capture_schema_accepted'],result['events']);self.assertFalse(entry_accesses(result['plan']))
                self.assertTrue(result['history'][0]['blocker_counts']);self.assertFalse(result['history'][-1]['blocker_counts'])
                self.assertEqual(result['history'][0]['missing_constant_data'],['data'])
                self.assertTrue(all(r['immutable_global']['kind']=='defined_const_numeric_array' for r in result['plan']['entry_reads']))

    def test_loaded_numeric_declarations_must_agree_in_constness_type_and_shape(self):
        for header,definition in (
            ('extern const unsigned data;','const double data=7;'),
            ('extern const unsigned data;','unsigned data=7;'),
            ('extern const unsigned data[2];','const unsigned data[3]={1,2,3};'),
            ('extern const unsigned data[][2];','const unsigned data[2][3]={{1,2,3},{4,5,6}};')):
            with self.subTest(definition=definition),tempfile.TemporaryDirectory() as tmp:
                stage=Path(tmp);expression='data[0][0]' if '[][2]' in header else 'data[0]' if '[' in header else 'data'
                db,index=configured(stage,{'root.c':header+'unsigned root(void){return '+expression+';}', 'data.c':definition})
                result=discover(db,stage/'root.c','root',index)
                self.assertFalse(result['capture_schema_accepted'])
                self.assertFalse(any('immutable_global' in r for r in result['plan']['entry_reads']))

    def test_multiple_loaded_numeric_definitions_and_weak_objects_have_no_proof(self):
        for declaration,definition in (('extern const unsigned data;','const unsigned data=7;'),
            ('extern const unsigned data[2];','const unsigned data[2]={7,11};')):
            for mode in ('duplicate','weak','alias'):
                with self.subTest(declaration=declaration,mode=mode),tempfile.TemporaryDirectory() as tmp:
                    stage=Path(tmp);expression='data[0]' if '[' in declaration else 'data'
                    files={'root.c':declaration+'unsigned root(void){return '+expression+';}', 'a.c':definition}
                    if mode=='duplicate':files['b.c']=definition
                    elif mode=='weak':files['a.c']='__attribute__((weak)) '+definition
                    else:files['a.c']=definition.replace('data','other')+declaration.replace(';',' __attribute__((alias("other")));')
                    db,_=configured(stage,files)
                    tree,_=merge_translation_units([load_ast(db,stage/name) for name in files],roots=['root'])
                    analyzer=Analyzer(tree);before=copy.deepcopy(tree);p=analyzer.analyze('root')
                    self.assertFalse(any('immutable_global' in r for r in p['entry_reads']))
                    with self.assertRaises(ValueError):capture_header([p])
                    self.assertEqual(tree,before);self.assertEqual(p,analyzer.fresh().analyze('root'))

    def test_numeric_data_discovery_does_not_prove_dynamic_or_invalid_indexes(self):
        for expression,blocker in (('data[n]','dynamic_extent'),('data[3]','array_bounds'),('data[-1]','array_bounds')):
            with self.subTest(expression=expression),tempfile.TemporaryDirectory() as tmp:
                stage=Path(tmp);db,index=configured(stage,{'root.c':'extern const unsigned data[];unsigned root(unsigned n){return '+expression+';}',
                    'data.c':'const unsigned data[3]={7,11,13};'})
                result=discover(db,stage/'root.c','root',index)
                self.assertFalse(result['capture_schema_accepted']);self.assertEqual(result['status'],'blocked')
                self.assertIn(blocker,{b['kind'] for b in result['plan']['blockers']})

    def test_numeric_object_writes_and_tampered_cross_file_proofs_are_rejected(self):
        for array in (False,True):
            with self.subTest(array=array),tempfile.TemporaryDirectory() as tmp:
                stage=Path(tmp);declaration='extern const unsigned data'+('[2]' if array else '')+';'
                definition='const unsigned data'+('[2]={7,11};' if array else '=7;');expression='data[1]' if array else 'data'
                db,index=configured(stage,{'root.c':declaration+'unsigned root(void){return '+expression+';}', 'data.c':definition})
                result=discover(db,stage/'root.c','root',index);self.assertTrue(result['capture_schema_accepted'])
                p=result['plan'];r=p['entry_reads'][0]
                for field,value in (('object','wrong'),('initializer_sha256','0'*64)):
                    q=copy.deepcopy(p);q['entry_reads'][0]['immutable_global'][field]=value
                    with self.assertRaises(ValueError):capture_header([q])
                q=copy.deepcopy(p);q['state_writes'].append(dict(r,path='global:data[0]' if array else 'global:data',entry_candidate=False))
                with self.assertRaisesRegex(ValueError,'also written'):capture_header([q])

    def test_native_cross_file_hook_has_no_fields_and_preserves_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);header='extern const unsigned scale;extern const unsigned data[];'
            db,index=configured(stage,{'root.c':header+'unsigned root(unsigned n){const unsigned*p=data;return scale+p[n%3];}',
                'data.c':'const unsigned scale=5;const unsigned data[3]={[1]=11};'})
            result=discover(db,stage/'root.c','root',index);self.assertTrue(result['capture_schema_accepted'])
            (stage/'capture.h').write_text(capture_header([result['plan']]))
            (stage/'run.c').write_text('#include <assert.h>\n#include "capture.h"\nunsigned root(unsigned);\nint main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s));assert(s.object_count==0&&s.field_count==0);assert(root(0)==5&&root(1)==16&&root(2)==5);return 0;}')
            binary=stage/'run';subprocess.run([fixture.CLANG,'-std=c11','-I',str(fixture.ROOT/'include'),'-I',str(stage),str(stage/'run.c'),str(stage/'root.c'),str(stage/'data.c'),str(fixture.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)

    def test_function_and_data_expansion_share_the_unit_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);db,index=configured(stage,{
                'root.c':'unsigned helper(unsigned);unsigned root(unsigned n){return helper(n);}',
                'helper.c':HEADER+'unsigned helper(unsigned n){return data.values[n%3];}',
                'data.c':DATA})
            result=discover(db,stage/'root.c','root',index,max_units=3)
            self.assertTrue(result['capture_schema_accepted']);self.assertEqual(len(result['history']),3)
            self.assertEqual([e['kind'] for e in result['events']],['body_source_loaded','data_source_selected','data_source_loaded'])
            capped=discover(db,stage/'root.c','root',index,max_units=2)
            self.assertFalse(capped['capture_schema_accepted']);self.assertTrue(entry_accesses(capped['plan']))

    def test_automatic_source_preserves_reads_and_proves_constants(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);db,index=configured(stage,{'root.c':ROOT,'data.c':DATA})
            self.assertIsNone(index.data_index)
            result=discover(db,stage/'root.c','root',index)
            self.assertTrue(result['capture_schema_accepted']);self.assertEqual(len(result['program']['source_identities']),2)
            self.assertEqual(len(result['plan']['entry_reads']),3);self.assertFalse(entry_accesses(result['plan']))
            self.assertEqual(result['history'][0]['missing_constant_records'],['data'])
            self.assertEqual(result['history'][-1]['missing_constant_records'],[])
            self.assertTrue(all(r['immutable_global']['kind']=='defined_const_numeric_record' for r in result['plan']['entry_reads']))
            selection=next(e for e in result['events'] if e['kind']=='data_source_selected')
            self.assertEqual(selection['index_evidence']['objects'],2)
            capped=discover(db,stage/'root.c','root',index,max_units=1)
            self.assertFalse(capped['capture_schema_accepted']);self.assertTrue(entry_accesses(capped['plan']))
            self.assertTrue(any(e['kind']=='translation_unit_limit' and e['remaining_data'] for e in capped['events']))

    def test_duplicate_weak_and_unsupported_definitions_remain_review(self):
        for mode in ('duplicate','weak','assembly','unverified'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as tmp:
                stage=Path(tmp);texts={'root.c':ROOT,'data.c':DATA}
                if mode=='duplicate':texts['other.c']=DATA
                if mode=='weak':texts['data.c']=HEADER+'__attribute__((weak)) const struct T data={{7,11,13}};'
                db,index=configured(stage,texts)
                if mode in ('assembly','unverified'):
                    objects=json.loads((stage/'objects.json').read_text())
                    if mode=='assembly':objects[1]['language']='assembly';write(stage/'objects.json',objects)
                    else:
                        report=json.loads((stage/'report.json').read_text());report['units']=report['units'][:1];write(stage/'report.json',report)
                    index=DefinitionIndex.from_survey(stage,db)
                result=discover(db,stage/'root.c','root',index)
                self.assertFalse(result['capture_schema_accepted']);self.assertEqual(len(result['history']),1)
                kind='ambiguous_data_definition' if mode=='duplicate' else 'unsupported_data_definition'
                self.assertTrue(any(e['kind']==kind for e in result['events']))

    def test_manifest_object_source_and_dependency_tampering_fail_closed(self):
        for target in ('manifest','object','source','dependency'):
            with self.subTest(target=target),tempfile.TemporaryDirectory() as tmp:
                stage=Path(tmp);db,index=configured(stage,{'root.c':ROOT,'data.c':DATA})
                path=stage/{'manifest':'objects.json','object':'data.o','source':'data.c','dependency':'data.d'}[target]
                path.write_bytes(path.read_bytes()+b' ')
                result=discover(db,stage/'root.c','root',index)
                self.assertFalse(result['capture_schema_accepted']);self.assertTrue(entry_accesses(result['plan']))
                self.assertTrue(any(e['kind']=='data_index_failed' for e in result['events']))

    def test_loaded_initializer_must_still_pass_record_proof(self):
        for definition in ('struct T{unsigned values[3];};struct T data={{1,2,3}};',
                           'struct T{unsigned long long values[3];};const struct T data={{1,2,3}};'):
            with self.subTest(definition=definition),tempfile.TemporaryDirectory() as tmp:
                stage=Path(tmp);db,index=configured(stage,{'root.c':ROOT,'data.c':definition})
                result=discover(db,stage/'root.c','root',index)
                self.assertFalse(result['capture_schema_accepted']);self.assertTrue(entry_accesses(result['plan']))

    def test_irrelevant_mutable_and_pointer_records_do_not_scan_objects(self):
        for text in ('unsigned root(void){return 1;}',
                     'struct T{unsigned x;};extern struct T data;unsigned root(void){return data.x;}',
                     'struct T{unsigned x;unsigned*p;};extern const struct T data;unsigned root(void){return data.x;}'):
            with self.subTest(text=text),tempfile.TemporaryDirectory() as tmp:
                stage=Path(tmp);db,index=fixture.setup(stage,{'root.c':text})
                def forbidden():raise AssertionError('unnecessary data index')
                index.data_loader=forbidden
                discover(db,stage/'root.c','root',index);self.assertIsNone(index.data_index)


if __name__=='__main__':
    sys.argv=sys.argv[:1];unittest.main()
