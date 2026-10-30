"""Manifest checks, argument construction and result comparison of the KLEE state-discovery batch runner."""
import json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from klee_state_batch import FORMAT,EXPECT,load,discovery_args,observed,compare,run_entry

EXPECTED=dict(complete=True,required=['creds.uid'],control_without_effect=[],split_inputs=[],validation='consistent',not_demonstrated=[])
DEFAULTS=dict(slice='build/slice',binding='binding.json',contracts='contracts.json',max_time=1200)

def manifest(entries):return dict(format=FORMAT,defaults=DEFAULTS,entries=entries)

class BatchTests(unittest.TestCase):
    def write(self,data):
        path=Path(self.enterContext(tempfile.TemporaryDirectory()))/'manifest.json';path.write_text(json.dumps(data));return path

    def test_manifest_shape_is_checked(self):
        entry=dict(name='getuid',boundary='b.json',boundary_sha256='0'*64,tier='quick',expect=EXPECTED)
        self.assertEqual(len(load(self.write(manifest([entry])))['entries']),1)
        for bad in ([entry,entry],[dict(entry,extra=1)],[{k:v for k,v in entry.items() if k!='tier'}],
                    [dict(entry,expect={k:v for k,v in EXPECTED.items() if k!='not_demonstrated'})]):
            with self.assertRaises(ValueError):load(self.write(manifest(bad)))
        with self.assertRaises(ValueError):load(self.write(dict(manifest([entry]),format='other')))

    def test_entry_arguments_follow_defaults_and_may_override_them(self):
        entry=dict(name='read',boundary='b/boundary.json',args=['--symbolic-arg','0:0:70:split','--max-time','3600'])
        args=discovery_args(entry,DEFAULTS,Path('/r'))
        self.assertEqual(args[:8],['--boundary','/r/b/boundary.json','--slice','/r/build/slice','--binding','/r/binding.json','--contracts','/r/contracts.json'])
        # argparse keeps the last value, so the entry's --max-time wins.
        self.assertEqual(args[8:],['--max-time','1200','--symbolic-arg','0:0:70:split','--max-time','3600'])

    def test_comparison_ignores_list_order_and_reports_each_difference(self):
        report=dict(klee=dict(exploration_complete=True),required=['b','a'],control_without_effect=['c'],split_inputs=[])
        validation=dict(status='consistent',necessity=dict(not_demonstrated=[]))
        result=observed(report,validation)
        self.assertEqual(set(result),set(EXPECT))
        self.assertEqual(compare(dict(EXPECTED,required=['a','b'],control_without_effect=['c']),result),{})
        self.assertEqual(compare(EXPECTED,result),{'required':[['creds.uid'],['b','a']],'control_without_effect':[[],['c']]})
        self.assertEqual(compare(EXPECTED,observed(dict(report,required=['creds.uid'],control_without_effect=[]),None)),
                         {'validation':['consistent',None],'not_demonstrated':[[],None]})

    def test_missing_or_changed_boundaries_are_not_run(self):
        root=Path(self.enterContext(tempfile.TemporaryDirectory()));work=root/'work';work.mkdir()
        entry=dict(name='getuid',boundary='boundary.json',boundary_sha256='0'*64,tier='quick',expect=EXPECTED)
        self.assertEqual(run_entry(entry,DEFAULTS,root,work,{},False)['status'],'missing')
        (root/'boundary.json').write_text('{}')
        self.assertEqual(run_entry(entry,DEFAULTS,root,work,{},False)['status'],'stale')
        self.assertFalse((work/'getuid').exists())

if __name__=='__main__':unittest.main()
