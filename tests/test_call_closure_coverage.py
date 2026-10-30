"""Continuation and aggregation must preserve the eligible-root denominator."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from discover_call_closure import DefinitionIndex,discover,eligible_roots,select_batch,aggregate_batches
from discover_kernel_state import survey_unit,write
from entry_state import digest
import test_discovered_call_closure as fixture


def project(stage):
    db,_=fixture.setup(stage,{
        'a.c':'unsigned helper(void);unsigned first(void){return helper();}',
        'b.c':'unsigned helper(void){return 7;}',
        'c.c':'unsigned helper(void);unsigned second(void){return helper();}'})
    survey=stage/'survey';survey.mkdir();(survey/'compile_commands.json').write_bytes(db.read_bytes());units=[]
    for i,entry in enumerate(json.loads(db.read_text())):
        path=survey/(str(i)+'.json');write(path,survey_unit(db,Path(entry['file']),100))
        units.append({'source':entry['file'],'status':'analyzed','report':path.name,'report_sha256':digest(path.read_bytes())})
    write(survey/'report.json',{'format':'osrec-kernel-state-discovery-v1','compilation_database_sha256':digest(db.read_bytes()),'units':units})
    index=DefinitionIndex.from_survey(survey,survey/'compile_commands.json');requests,_=eligible_roots(survey,index)
    batches=[]
    for i,request in enumerate(requests):
        directory=stage/('batch'+str(i));directory.mkdir();write(directory/'requests.json',[request])
        result=discover(db,Path(request['source']),request['root'],index)
        write(directory/'root.json',result)
        row={'source':request['source'],'root':request['root'],'status':result['status'],'report':'root.json',
             'sha256':digest((directory/'root.json').read_bytes()),'capture_schema_accepted':result['capture_schema_accepted']}
        write(directory/'report.json',{'format':'osrec-call-closure-batch-v1','survey_sha256':digest((survey/'report.json').read_bytes()),
              'compilation_database_sha256':digest(db.read_bytes()),'options':{'all_eligible':True,'start_root':i,'max_roots':1,
              'max_translation_units':4,'max_contexts':100,'root_timeout':10},'roots':[row]})
        batches.append(directory)
    return survey,index,batches


def alter(directory,mutate):
    path=directory/'report.json';value=json.loads(path.read_text());mutate(value);write(path,value)


class ClosureCoverageTests(unittest.TestCase):
    def test_ranges_partition_without_repeating_roots(self):
        values=list(range(507));first=select_batch(values,0,128);remaining=select_batch(values,128)
        self.assertEqual(first+remaining,values);self.assertEqual((len(first),len(remaining)),(128,379))
        for start,maximum in [(-1,None),(507,None),(0,0)]:
            with self.assertRaises(ValueError):select_batch(values,start,maximum)

    def test_partial_complete_and_failed_results_stay_in_denominator(self):
        with tempfile.TemporaryDirectory() as name:
            survey,index,batches=project(Path(name).resolve())
            partial=aggregate_batches(survey,index,batches[:1]);self.assertEqual(partial['summary']['unrequested_roots'],1)
            complete=aggregate_batches(survey,index,batches)
            self.assertEqual(complete['summary']['status'],{'candidate':2})
            self.assertEqual(complete['summary']['requested_roots'],2);self.assertFalse(complete['unrequested'])
            self.assertTrue(complete['limits']['recorded_results_only']);self.assertFalse(complete['limits']['runtime_validated'])
            root=batches[1]/'root.json';result=json.loads(root.read_text())
            result.update(status='failed',error='fixture worker timeout');write(root,result)
            def update(report):
                report['roots'][0].update(status='failed',sha256=digest(root.read_bytes()),capture_schema_accepted=False)
            alter(batches[1],update)
            failed=aggregate_batches(survey,index,batches)
            self.assertEqual(failed['summary']['status'],{'candidate':1,'failed':1})
            self.assertEqual(failed['summary']['unrequested_roots'],0)

    def test_overlaps_omissions_and_mismatched_limits_are_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            survey,index,batches=project(Path(name).resolve())
            with self.assertRaisesRegex(ValueError,'overlapping'):aggregate_batches(survey,index,[batches[0],batches[0]])
            saved=(batches[1]/'report.json').read_bytes()
            alter(batches[1],lambda report:report['options'].update(root_timeout=20))
            with self.assertRaisesRegex(ValueError,'limits differ'):aggregate_batches(survey,index,batches)
            (batches[1]/'report.json').write_bytes(saved)
            alter(batches[1],lambda report:report['options'].update(max_alias_paths=2))
            with self.assertRaisesRegex(ValueError,'limits differ'):aggregate_batches(survey,index,batches)
            (batches[1]/'report.json').write_bytes(saved)
            alter(batches[1],lambda report:report.update(roots=[]))
            with self.assertRaisesRegex(ValueError,'omits or duplicates'):aggregate_batches(survey,index,batches)

    def test_modified_results_selection_and_input_identities_are_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            survey,index,batches=project(Path(name).resolve());directory=batches[0];path=directory/'root.json';original=path.read_bytes()
            path.write_text('{}')
            with self.assertRaisesRegex(ValueError,'hash differs'):aggregate_batches(survey,index,batches)
            path.write_bytes(original)
            saved=(directory/'report.json').read_bytes()
            alter(directory,lambda report:report['options'].update(start_root=1))
            with self.assertRaisesRegex(ValueError,'selection differs'):aggregate_batches(survey,index,batches)
            (directory/'report.json').write_bytes(saved)
            alter(directory,lambda report:report.update(compilation_database_sha256='changed'))
            with self.assertRaisesRegex(ValueError,'identity differs'):aggregate_batches(survey,index,batches)

    def test_root_status_sources_and_report_paths_are_checked(self):
        with tempfile.TemporaryDirectory() as name:
            survey,index,batches=project(Path(name).resolve());directory=batches[0];path=directory/'root.json'
            original=path.read_bytes();report_original=(directory/'report.json').read_bytes()
            root=json.loads(original);root['status']='failed';write(path,root)
            alter(directory,lambda report:report['roots'][0].update(sha256=digest(path.read_bytes())))
            with self.assertRaisesRegex(ValueError,'identity/status differs'):aggregate_batches(survey,index,batches)
            path.write_bytes(original);(directory/'report.json').write_bytes(report_original)
            root=json.loads(original);root['program']['source_identities'][0]['source_sha256']='changed';write(path,root)
            alter(directory,lambda report:report['roots'][0].update(sha256=digest(path.read_bytes())))
            with self.assertRaisesRegex(ValueError,'source identity differs'):aggregate_batches(survey,index,batches)
            path.write_bytes(original);(directory/'report.json').write_bytes(report_original)
            alter(directory,lambda report:report['roots'][0].update(report='../root.json'))
            with self.assertRaisesRegex(ValueError,'escapes batch'):aggregate_batches(survey,index,batches)


if __name__=='__main__':
    if len(sys.argv)==2:fixture.CLANG=sys.argv.pop()
    unittest.main()
