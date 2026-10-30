"""Expand available C bodies without hiding mixed blockers or cohort coverage."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from discover_call_closure import DefinitionIndex,discover,eligible_roots,mixed_roots,aggregate_batches
from discover_kernel_state import survey_unit,write
from entry_state import digest
import test_discovered_call_closure as fixture


def project(stage):
    db,_=fixture.setup(stage,{
        'a.c':'''unsigned helper(void),unknown(void),choice(void);
unsigned pure(void){return helper();}
unsigned architecture(void){__asm__ volatile("" ::: "memory");return helper();}
unsigned partial(void){return helper()+unknown();}
unsigned ambiguous(void){return helper()+choice();}
unsigned indirect(unsigned (*fn)(void)){return helper()+fn();}
unsigned unavailable(void){return unknown();}
''',
        'helper.c':'unsigned state;unsigned helper(void){return state;}',
        'x.c':'unsigned choice(void){return 1;}',
        'y.c':'unsigned choice(void){return 2;}'})
    survey=stage/'survey';survey.mkdir();(survey/'compile_commands.json').write_bytes(db.read_bytes());rows=[]
    for number,entry in enumerate(json.loads(db.read_text())):
        path=survey/(str(number)+'.json');write(path,survey_unit(db,Path(entry['file']),100))
        rows.append({'source':entry['file'],'status':'analyzed','report':path.name,'report_sha256':digest(path.read_bytes())})
    write(survey/'report.json',{'format':'osrec-kernel-state-discovery-v1','compilation_database_sha256':digest(db.read_bytes()),'units':rows})
    return survey,DefinitionIndex.from_survey(survey,db)


def batch(stage,survey,index,start=0,maximum=None):
    requests,_=mixed_roots(survey,index);requests=requests[start:start+maximum if maximum else None]
    directory=stage/'batch';directory.mkdir();write(directory/'requests.json',requests);rows=[]
    for number,request in enumerate(requests):
        path=directory/(str(number)+'.json')
        result=discover(survey/'compile_commands.json',Path(request['source']),request['root'],index)
        write(path,result);rows.append({'source':request['source'],'root':request['root'],'status':result['status'],
            'report':path.name,'sha256':digest(path.read_bytes()),'capture_schema_accepted':result['capture_schema_accepted']})
    write(directory/'report.json',{'format':'osrec-call-closure-batch-v1','survey_sha256':digest((survey/'report.json').read_bytes()),
        'compilation_database_sha256':digest((survey/'compile_commands.json').read_bytes()),
        'options':{'all_mixed':True,'start_root':start,'max_roots':maximum,'max_translation_units':4,'max_contexts':100,'root_timeout':10},'roots':rows})
    return directory


class MixedClosureTests(unittest.TestCase):
    def test_selection_is_disjoint_and_keeps_missing_and_ambiguous_evidence(self):
        with tempfile.TemporaryDirectory() as name:
            survey,index=project(Path(name).resolve())
            eligible,_=eligible_roots(survey,index);requests,info=mixed_roots(survey,index)
            self.assertEqual([r['root'] for r in eligible],['pure'])
            by_name={r['root']:r for r in requests}
            self.assertEqual(set(by_name),{'architecture','partial','ambiguous','indirect'})
            self.assertEqual(info['excluded_eligible_roots'],1)
            self.assertTrue(all(r['available_callees']==['helper'] for r in requests))
            self.assertEqual(by_name['partial']['unavailable_callees'],['unknown'])
            self.assertEqual(by_name['ambiguous']['ambiguous_callees'],['choice'])
            self.assertIn('architecture_or_ordering',by_name['architecture']['baseline_blockers'])
            self.assertIn('indirect_call',by_name['indirect']['baseline_blockers'])

    def test_expansion_adds_state_and_preserves_other_blockers(self):
        with tempfile.TemporaryDirectory() as name:
            survey,index=project(Path(name).resolve());requests,_=mixed_roots(survey,index)
            for request in requests:
                with self.subTest(root=request['root']):
                    result=discover(survey/'compile_commands.json',Path(request['source']),request['root'],index)
                    self.assertEqual(result['status'],'blocked')
                    self.assertEqual(result['program']['translation_units'],2)
                    self.assertIn('global:state',{r['path'] for r in result['plan']['entry_reads']})
                    self.assertNotIn('helper',result['history'][-1]['missing_bodies'])
                    self.assertFalse(result['limits']['boundary_models_invented'])
                    self.assertFalse(result['limits']['runtime_validated'])
                    expected={'architecture':'architecture_or_ordering','indirect':'indirect_call',
                              'partial':'unmodeled_external','ambiguous':'unmodeled_external'}[request['root']]
                    self.assertIn(expected,{b['kind'] for b in result['plan']['blockers']})

    def test_coverage_denominator_partial_and_failed_results(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name).resolve();survey,index=project(stage);directory=batch(stage,survey,index,maximum=2)
            coverage=aggregate_batches(survey,index,[directory],cohort='mixed')
            self.assertEqual(coverage['summary']['mixed_roots'],4)
            self.assertEqual(coverage['summary']['requested_roots'],2)
            self.assertEqual(coverage['summary']['unrequested_roots'],2)
            self.assertEqual(coverage['summary']['status'],{'blocked':2})
            with self.assertRaisesRegex(ValueError,'cohort differs'):aggregate_batches(survey,index,[directory])
            path=directory/'report.json';report=json.loads(path.read_text());row=report['roots'][0]
            result=directory/row['report'];value=json.loads(result.read_text());value.update(status='failed',error='fixture timeout');write(result,value)
            row.update(status='failed',sha256=digest(result.read_bytes()));write(path,report)
            failed=aggregate_batches(survey,index,[directory],cohort='mixed')
            self.assertEqual(failed['summary']['status'],{'failed':1,'blocked':1})
            self.assertEqual(failed['summary']['unrequested_roots'],2)
            with self.assertRaisesRegex(ValueError,'at least one'):aggregate_batches(survey,index,[],cohort='mixed')

    def test_active_filter_and_failed_root_exclusion(self):
        with tempfile.TemporaryDirectory() as name:
            survey,index=project(Path(name).resolve());report=json.loads((survey/'report.json').read_text())
            row=next(r for r in report['units'] if r['source'].endswith('/a.c'));path=survey/row['report'];unit=json.loads(path.read_text())
            next(r for r in unit['roots'] if r['name']=='architecture')['status']='analysis_failed'
            write(path,unit);row['report_sha256']=digest(path.read_bytes());write(survey/'report.json',report)
            index=DefinitionIndex.from_survey(survey,survey/'compile_commands.json')
            self.assertNotIn('architecture',{r['root'] for r in mixed_roots(survey,index)[0]})
            write(survey/'objects.json',[{'language':'c','source':row['source'],'object':'inactive.o'}])
            write(survey/'module-ownership.json',{'objects':{}})
            requests,info=mixed_roots(survey,index)
            self.assertFalse(requests);self.assertTrue(info['active_module_filter'])

    def test_cli_mixed_batch_and_explicit_coverage_cohort(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name).resolve();survey,index=project(stage);directory=stage/'cli'
            command=[sys.executable,str(ROOT/'tools/discover_call_closure.py'),'--survey',str(survey)]
            result=subprocess.run(command+['--all-mixed','--max-roots','1','--root-timeout','10','--out',str(directory)],capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            output=stage/'coverage'
            result=subprocess.run(command+['--aggregate-batches',str(directory),'--coverage-cohort','mixed','--out',str(output)],capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads((output/'report.json').read_text())['summary']['unrequested_roots'],3)


if __name__=='__main__':
    if len(sys.argv)==2:fixture.CLANG=sys.argv.pop()
    unittest.main()
