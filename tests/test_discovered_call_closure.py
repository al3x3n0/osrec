"""Automatic cross-file expansion must preserve provenance, limits and state."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,children,load_ast,digest
from discover_call_closure import DefinitionIndex,discover,abi_identity,eligible_roots
from entry_state_program import merge_translation_units
from discover_kernel_state import survey_unit,write
from entry_capture import generate,import_session
from export_entry_state import export,RequestError
import test_entry_state_loops as fixture
import test_entry_state_enum_operators as operators
CLANG=str(fixture.LLVM/'clang');RETAIN=None
EXPECTED=operators.EXPECTED


def setup(stage,texts):
    stage.mkdir(exist_ok=True);entries=[];definitions={}
    for name,text in texts.items():
        source=(stage/name).resolve();source.parent.mkdir(parents=True,exist_ok=True);source.write_text(text)
        entries.append({'directory':str(stage.resolve()),'file':str(source),'arguments':[CLANG,'-std=c11','-I',str(stage.resolve()),'-c',str(source)]})
    db=stage/'compile_commands.json';write(db,entries)
    for entry in entries:
        source=Path(entry['file']);tree,_=load_ast(db,source)
        for name,node in Analyzer(tree).functions.items():
            if node.get('storageClass')!='static':definitions.setdefault(name,[]).append(str(source))
    return db,DefinitionIndex(definitions)


def project(stage,mode):
    model=fixture.MODEL+"""
void paint(State *,unsigned,unsigned);unsigned total(State *);
void fill(State *,unsigned,unsigned);unsigned sum(State *);
"""
    stage.mkdir();(stage/'entry_model.h').write_text(model)
    bodies={
        'root.c':'#include "entry_model.h"\nvoid paint(State *state,unsigned count,unsigned value){fill(state,count,value);}\nunsigned total(State *state){return sum(state);}\n',
        'helpers.c':'#include "entry_model.h"\nvoid fill(State *state,unsigned count,unsigned value){for(unsigned i=0;i<count && i<8;++i)state->values[i]=value+i;}\nunsigned sum(State *state){unsigned value=0;for(unsigned i=0;i<8;++i)value+=state->values[i];return value;}\n'
    }
    bodies['root.c']+='unsigned irrelevant(unsigned);\n'
    bodies['helpers.c']+='unsigned irrelevant(const char *);\n'
    db,index=setup(stage,bodies);plans=[];closures=[]
    for root in ('paint','total'):
        result=discover(db,stage/'root.c',root,index,analysis_options={'argument_objects':{root:{'state':fixture.CONTRACT}},'prune_written':True,'preserve_write_state':True})
        if result['plan']['blockers']:raise ValueError(result['plan']['blockers'])
        plans.append(result['plan']);closures.append(result)
    write(stage/'closures.json',closures);plan=stage/'plan.json';write(plan,{'format':'osrec-entry-state-plan-v1','plans':plans})
    spec={'format':'osrec-entry-capture-spec-v1','mode':mode,'max_calls':8,'replay_dispatch':'generated',
          'contract':{'fixed_lifetimes':True,'exclusive_capture':True,'reason':'fixed fixture object','implementation':'single owner for all calls'},
          'sites':[{'root':'paint','number':201,'return_kind':'void'},{'root':'total','number':202,'return_kind':'u32'}],
          'model_header':'entry_model.h','adapter_header':'adapter.h','files':{name:name for name in bodies},'translation_units':list(bodies)}
    sp=stage/'spec.json';write(sp,spec);(stage/'adapter.h').write_text('/* Generated typed routing. */\n')
    (stage/'capture.h').write_text(generate(plan,sp))
    native=stage/'native.c';native.write_text("""
#include <stdio.h>
#include "entry_model.h"
#include "capture.h"
static struct osrec_capture_session session;
static int emit(void *p,const char *data,size_t n){(void)p;return fwrite(data,1,n,stdout)==n;}
"""+operators.MAIN)
    binary=stage/'native'
    fixture.run([CLANG,'-std=c11','-Wall','-Wextra','-Werror','-DOSREC_CAPTURE_CALLS=8','-I',ROOT/'include','-I',stage,
                 native,*[stage/name for name in bodies],ROOT/'runtime/entry_snapshot.c',ROOT/'runtime/entry_capture.c','-o',binary])
    capture=stage/'capture.json';capture.write_text(fixture.run([binary]).stdout)
    return plan,sp,capture,closures


class DiscoveryClosureTests(unittest.TestCase):
    def test_worker_timeout_recovers_empty_truncated_and_nonobject_checkpoints(self):
        from unittest.mock import patch
        import discover_call_closure as closure
        for raw in (b'',b'{"status":',b'[]'):
            with self.subTest(raw=raw),tempfile.TemporaryDirectory() as name:
                stage=Path(name);survey=stage/'survey';survey.mkdir();write(survey/'report.json',{});write(survey/'compile_commands.json',[])
                requests=stage/'requests.json';write(requests,[{'source':str(stage/'root.c'),'root':'root'}]);out=stage/'out'
                def timeout(command,**kwargs):
                    Path(command[7]).write_bytes(raw);raise subprocess.TimeoutExpired(command,1)
                with patch.object(sys,'argv',['discover_call_closure','--survey',str(survey),'--roots',str(requests),'--out',str(out)]),patch.object(closure.DefinitionIndex,'from_survey',return_value=DefinitionIndex({})),patch.object(closure.subprocess,'run',side_effect=timeout):closure.main()
                report=json.loads((out/'report.json').read_text());self.assertEqual(report['summary']['status'],{'failed':1})
                self.assertFalse(report['summary']['capture_schema_candidates'])
                self.assertEqual((out/'roots/0000.invalid-checkpoint').read_bytes(),raw)
                self.assertIn('checkpoint_error',json.loads((out/'roots/0000.json').read_text()))

    def test_worker_timeout_invalidates_a_previously_written_capture_flag(self):
        from unittest.mock import patch
        import discover_call_closure as closure
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);survey=stage/'survey';survey.mkdir();write(survey/'report.json',{});write(survey/'compile_commands.json',[])
            requests=stage/'requests.json';write(requests,[{'source':str(stage/'root.c'),'root':'root'}]);out=stage/'out'
            def timeout(command,**kwargs):
                write(Path(command[7]),{'status':'candidate','capture_schema_accepted':True})
                raise subprocess.TimeoutExpired(command,1)
            with patch.object(sys,'argv',['discover_call_closure','--survey',str(survey),'--roots',str(requests),'--out',str(out)]),patch.object(closure.DefinitionIndex,'from_survey',return_value=DefinitionIndex({})),patch.object(closure.subprocess,'run',side_effect=timeout):
                closure.main()
            report=json.loads((out/'report.json').read_text());self.assertEqual(report['summary']['status'],{'failed':1})
            self.assertEqual(report['summary']['capture_schema_candidates'],0)
            self.assertFalse(json.loads((out/'roots/0000.json').read_text())['capture_schema_accepted'])

    def test_unused_function_conflicts_are_sliced_and_used_conflicts_block(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name).resolve();db,index=setup(stage,{
                'a.c':'unsigned irrelevant(unsigned);unsigned helper(void);unsigned root(void){return helper();}',
                'b.c':'unsigned irrelevant(const char *);unsigned helper(void){return 7;}'})
            result=discover(db,stage/'a.c','root',index)
            self.assertFalse(result['plan']['blockers'])
            self.assertNotIn('irrelevant',result['program']['function_slice']['retained_function_names'])
            self.assertGreater(result['program']['function_slice']['removed_function_declarations'],0)
            strict=discover(db,stage/'a.c','root',index,slice_functions=False)
            self.assertTrue(strict['plan']['blockers'])
            self.assertIn('merge_or_analysis_failed',{e['kind'] for e in strict['events']})
            (stage/'b.c').write_text('unsigned irrelevant(const char *);unsigned helper(void){return irrelevant("x");}')
            used=discover(db,stage/'a.c','root',index)
            self.assertTrue(used['plan']['blockers'])
            self.assertTrue(any('incompatible configured function' in e.get('detail','') for e in used['events']))
            db,index=setup(stage,{'a.c':'unsigned leaf(void);unsigned helper(void){return 1;}unsigned root(void){return leaf()+helper();}',
                                  'b.c':'unsigned helper(void){return 2;}unsigned leaf(void){return 3;}'})
            duplicate=discover(db,stage/'a.c','root',index)
            self.assertTrue(any('multiple configured function' in e.get('detail','') for e in duplicate['events']))

    def test_slice_retains_finite_callbacks_and_used_global_initializers(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name).resolve();db,index=setup(stage,{
                'a.c':'unsigned first(void);unsigned second(void);unsigned invoke(unsigned(*)(void));unsigned root(unsigned choose){unsigned(*fn)(void)=choose?first:second;return invoke(fn);}',
                'b.c':'unsigned x,y;unsigned first(void){return x;}unsigned second(void){return y;}unsigned invoke(unsigned(*fn)(void)){return fn();}'})
            result=discover(db,stage/'a.c','root',index)
            self.assertFalse(result['plan']['blockers'])
            self.assertEqual({r['path'] for r in result['plan']['entry_reads']},{'global:x','global:y'})
            self.assertTrue({'first','second','invoke','root'}<=set(result['program']['function_slice']['retained_function_names']))
            db,index=setup(stage,{
                'a.c':'unsigned first(void);unsigned ignored(void);unsigned(*callback)(void)=first;static unsigned(*unused)(void)=ignored;unsigned root(void){return callback();}',
                'b.c':'unsigned first(void){return 7;}unsigned ignored(void){return 9;}'})
            tree,program=merge_translation_units([load_ast(db,stage/name) for name in ('a.c','b.c')],roots=['root'])
            self.assertIn('first',program['function_slice']['retained_function_names'])
            self.assertNotIn('ignored',program['function_slice']['retained_function_names'])
            self.assertTrue(any(b['kind']=='indirect_call' for b in Analyzer(tree).analyze('root')['blockers']))

    def test_record_conflicts_remain_checked_without_references(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name).resolve();db,index=setup(stage,{
                'a.c':'struct Unused{unsigned x;};unsigned helper(void);unsigned root(void){return helper();}',
                'b.c':'struct Unused{unsigned x,y;};unsigned helper(void){return 7;}'})
            result=discover(db,stage/'a.c','root',index)
            self.assertTrue(result['plan']['blockers'])
            self.assertTrue(any('incompatible configured record' in e.get('detail','') for e in result['events']))

    def test_eligible_selection_is_interleaved_and_filters_inactive_objects(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name).resolve();db,index=setup(stage,{
                'g1/a.c':'unsigned helper(void);unsigned a(void){return helper();}unsigned b(void){return helper();}',
                'g2/c.c':'unsigned helper(void);unsigned c(void){return helper();}unsigned d(void){return helper();}',
                'helper.c':'unsigned helper(void){return 7;}'})
            survey=stage/'survey';survey.mkdir();rows=[]
            for i,entry in enumerate(json.loads(db.read_text())):
                path=survey/(str(i)+'.json');unit=survey_unit(db,Path(entry['file']),100);write(path,unit)
                rows.append({'source':entry['file'],'status':'analyzed','report':path.name,'report_sha256':digest(path.read_bytes())})
            write(survey/'report.json',{'format':'osrec-kernel-state-discovery-v1','compilation_database_sha256':digest(db.read_bytes()),'units':rows})
            verified=DefinitionIndex.from_survey(survey,db);requests,info=eligible_roots(survey,verified)
            self.assertEqual([r['root'] for r in requests],['a','c','b','d'])
            self.assertFalse(info['active_module_filter'])
            write(survey/'objects.json',[{'language':'c','source':str(stage/'g1/a.c'),'object':'a.o'},{'language':'c','source':str(stage/'g2/c.c'),'object':'c.o'}])
            write(survey/'module-ownership.json',{'objects':{'a.o':'active_module'}})
            requests,info=eligible_roots(survey,verified)
            self.assertEqual([r['root'] for r in requests],['a','b']);self.assertTrue(info['active_module_filter'])

    def test_transitive_bodies_and_static_identity(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name).resolve();db,index=setup(stage,{
                'a.c':'unsigned middle(void);static unsigned local=3;static unsigned root(void){return local+middle();}',
                'b.c':'unsigned leaf(void);static unsigned local=7;unsigned middle(void){return local+leaf();}',
                'c.c':'unsigned shared;unsigned leaf(void){return shared;}'
            })
            r=discover(db,stage/'a.c','root',index)
            self.assertFalse(r['plan']['blockers']);self.assertEqual([h['translation_units'] for h in r['history']],[1,2,3])
            self.assertEqual(r['merged_root'],'tu0:root')
            self.assertEqual({x['path'] for x in r['plan']['entry_reads']},{'global:tu0:local','global:tu1:local','global:shared'})
            strict=discover(db,stage/'a.c','root',index,slice_functions=False)
            self.assertEqual(r['plan'],strict['plan'])
            static=discover(db,stage/'b.c','middle',index);self.assertFalse(static['plan']['blockers'])
            self.assertEqual(static['program']['translation_units'],2)

    def test_ambiguous_missing_limits_and_type_conflicts_stay_blocked(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name).resolve();db,index=setup(stage,{
                'a.c':'unsigned helper(void);unsigned root(void){return helper();}',
                'b.c':'unsigned helper(void){return 7;}',
                'c.c':'unsigned helper(void){return 8;}'
            })
            r=discover(db,stage/'a.c','root',index)
            self.assertTrue(r['plan']['blockers']);self.assertIn('ambiguous_definition',{e['kind'] for e in r['events']})
            index=DefinitionIndex({'helper':[str(stage/'b.c')]})
            limited=discover(db,stage/'a.c','root',index,max_units=1)
            self.assertIn('translation_unit_limit',{e['kind'] for e in limited['events']})
            missing=discover(db,stage/'a.c','root',DefinitionIndex({}))
            self.assertIn('body_unavailable',{e['kind'] for e in missing['events']})
            (stage/'b.c').write_text('int helper(void){return 7;}')
            conflict=discover(db,stage/'a.c','root',index)
            self.assertTrue(conflict['plan']['blockers'])
            self.assertIn('merge_or_analysis_failed',{e['kind'] for e in conflict['events']})

    def test_survey_hashes_and_changed_dependencies_fail_closed(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name).resolve();(stage/'header.h').write_text('#define VALUE 7\n')
            db,_=setup(stage,{'a.c':'#include "header.h"\nunsigned root(void){return VALUE;}\n'})
            survey=stage/'survey';survey.mkdir();unit=survey_unit(db,stage/'a.c',100);write(survey/'a.json',unit)
            write(survey/'report.json',{'format':'osrec-kernel-state-discovery-v1','compilation_database_sha256':digest(db.read_bytes()),
                  'units':[{'source':str(stage/'a.c'),'report':'a.json','report_sha256':digest((survey/'a.json').read_bytes())}]})
            DefinitionIndex.from_survey(survey,db)
            (stage/'header.h').write_text('#define VALUE 8\n')
            with self.assertRaisesRegex(ValueError,'dependency changed'):DefinitionIndex.from_survey(survey,db)

    def test_abi_effective_flags_and_mixed_targets(self):
        identity={'compile_arguments':['-target','arm-none-eabi','-fsigned-char','-mfloat-abi=softfp'],'compiler':'fixture clang'}
        duplicate=identity|{'compile_arguments':identity['compile_arguments']+['-fsigned-char']}
        self.assertEqual(abi_identity(identity),abi_identity(duplicate))
        a=identity|{'compile_arguments':['-fsigned-char','-funsigned-char']}
        b=identity|{'compile_arguments':['-funsigned-char','-fsigned-char']}
        self.assertNotEqual(abi_identity(a),abi_identity(b))
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name).resolve();db,index=setup(stage,{'a.c':'unsigned helper(void);unsigned root(void){return helper();}','b.c':'unsigned helper(void){return 7;}'})
            records=json.loads(db.read_text());records[1]['arguments'].insert(1,'--target=arm-none-eabi');write(db,records)
            r=discover(db,stage/'a.c','root',index)
            self.assertTrue(r['plan']['blockers'])
            self.assertIn('body_source_failed',{e['kind'] for e in r['events']})

    def test_native_capture_modes_relocation_and_portable_rebuild(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for mode in ('independent','continuous'):
                inputs=stage/(mode+'-inputs');plan,spec,capture,closures=project(inputs,mode)
                self.assertTrue(all(c['program']['translation_units']==2 for c in closures))
                self.assertEqual(len(closures[0]['plan']['preserved_entry_fields']),8)
                self.assertEqual(len(closures[1]['plan']['entry_reads']),8)
                self.assertEqual([c['history'][0]['missing_bodies'] for c in closures],[['fill'],['sum']])
                if RETAIN is not None:shutil.copytree(inputs,RETAIN/'native-captures'/mode)
                imported=stage/(mode+'-request');import_session(plan,spec,capture,imported)
                for address in (0x40200000,0x40400000):
                    output=stage/(mode+hex(address));m=export(fixture.args_for(imported/'request.json',output,address));o=m['target_observations']
                    self.assertEqual([c['raw_bits'] for c in o['actual_calls']],EXPECTED)
                    self.assertEqual((o['abi_version'],o['states_restored'],o['states_verified']),(30,1 if mode=='continuous' else 8,8))
                    if RETAIN is not None:shutil.copytree(output,RETAIN/mode/hex(address))
                shutil.rmtree(inputs);shutil.rmtree(imported)
                rebuilt=stage/(mode+'-portable');export(fixture.args_for(output/'request.json',rebuilt,0x40400000))
                self.assertEqual((rebuilt/'entry-state.bin').read_bytes(),(output/'entry-state.bin').read_bytes())
                if RETAIN is not None:shutil.copytree(rebuilt,RETAIN/mode/'portable-rebuild')

    def test_correct_return_wrong_cross_file_effect_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);plan,spec,capture,_=project(stage/'inputs','continuous');imported=stage/'request'
            import_session(plan,spec,capture,imported);request=imported/'request.json'
            bodies=imported/'support-helpers.c';original=bodies.read_text();faults=[]
            for label,replacement,error,index,raw in [
                ('capacity',original.replace('i<8;++i)state','i<4;++i)state'),0x20004,4,0),
                ('tail',original.replace('return value;}','state->values[7]++;return value;}'),0x20001,1,36)]:
                try:
                    bodies.write_text(replacement);out=stage/label
                    with self.assertRaises(RequestError) as caught:export(fixture.args_for(request,out))
                    o=json.loads(str(caught.exception).removeprefix('target replay diverged: '))
                    self.assertEqual((o['error'],o['actual_calls'][index]['raw_bits']),(error,raw));self.assertFalse(out.exists())
                    faults.append({'mutation':label,'observations':o})
                finally:bodies.write_text(original)
            if RETAIN is not None:write(RETAIN/'fault-verification.json',faults)

if __name__=='__main__':
    if '--out' in sys.argv:
        i=sys.argv.index('--out');RETAIN=Path(sys.argv[i+1]).resolve();del sys.argv[i:i+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:fixture.LLVM=Path(sys.argv[1]);fixture.QEMU=sys.argv[2];CLANG=str(fixture.LLVM/'clang');sys.argv=sys.argv[:1]
    unittest.main()
