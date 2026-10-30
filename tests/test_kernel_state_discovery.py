"""Coverage denominators, failure accounting and isolated root state."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,load_ast
from discover_kernel_state import built_objects,survey_unit
from prepare_entry_state import compile_record
CLANG='/opt/homebrew/opt/llvm@16/bin/clang'


def database(stage,files):
    path=stage/'compile_commands.json'
    path.write_text(json.dumps([{'directory':str(stage),'file':str(f),'arguments':[CLANG,'-std=c11','-c',str(f)]} for f in files]))
    return path


class KernelDiscoveryTests(unittest.TestCase):
    def test_checkpoint_write_preserves_prior_value_if_commit_is_interrupted(self):
        import discover_kernel_state as survey
        with tempfile.TemporaryDirectory() as name:
            path=Path(name)/'checkpoint.json';survey.write(path,{'state':'complete'})
            original=path.read_bytes()
            with patch.object(survey.os,'replace',side_effect=OSError('interrupted commit')):
                with self.assertRaisesRegex(OSError,'interrupted commit'):survey.write(path,{'state':'new'})
            self.assertEqual(path.read_bytes(),original);self.assertEqual(list(path.parent.glob('*.tmp')),[])
            survey.write(path,{'state':'new'});self.assertEqual(json.loads(path.read_text()),{'state':'new'})

    def test_artifact_denominator_keeps_assembly_and_failed_provenance(self):
        with tempfile.TemporaryDirectory() as name:
            tree=Path(name).resolve();(tree/'out/obj').mkdir(parents=True)
            for source in ('good.c','entry.S'):
                path=tree/source;path.write_text('/* fixture */')
                obj=tree/'out/obj'/Path(source).with_suffix('.o');obj.write_bytes(b'fixture object')
                obj.with_suffix('.d').write_text(str(obj)+': '+str(path)+'\n')
            (tree/'out/obj/missing.o').write_bytes(b'missing deps')
            rows=built_objects(tree);self.assertEqual(len(rows),3)
            self.assertEqual(sorted(r['language'] for r in rows),['assembly','c','unknown'])
            self.assertTrue(all(r['object_sha256'] for r in rows))

    def test_fresh_roots_match_independent_analysis_without_state_leakage(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name).resolve();source=stage/'a.c'
            source.write_text('unsigned global;unsigned read(void){return global;}void write(void){global=4;}unsigned pure(void){return 7;}')
            db=database(stage,[source]);tree,_=load_ast(db,source);index=Analyzer(tree)
            for root in ('read','write','pure','read'):
                self.assertEqual(index.fresh().analyze(root),Analyzer(tree).analyze(root))
            self.assertFalse(index.reads);self.assertFalse(index.writes);self.assertEqual(index.contexts,0)
            used=index.fresh();used.analyze('read')
            self.assertEqual(used.fresh().analyze('pure'),Analyzer(tree).analyze('pure'))

    def test_primary_source_roots_exclude_header_definitions(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name).resolve();(stage/'helper.h').write_text('static inline unsigned helper(void){return 7;}\n')
            source=stage/'a.c';source.write_text('#include "helper.h"\nunsigned root(void){return helper();}\nunsigned second(void){return 9;}\n')
            db=database(stage,[source]);unit=survey_unit(db,source,100)
            self.assertEqual([r['name'] for r in unit['roots']],['root','second'])
            self.assertEqual(unit['available_bodies_including_headers'],3)
            self.assertTrue(all(r['capture_schema_accepted'] for r in unit['roots']))
            record=json.loads(db.read_text());record[0]['file']='a.c';record[0]['arguments'][-1]='a.c';db.write_text(json.dumps(record))
            self.assertEqual([r['name'] for r in survey_unit(db,source,100)['roots']],['root','second'])

    def test_root_timeout_keeps_root_in_denominator_and_continues(self):
        class SlowAnalyzer(Analyzer):
            def analyze(self,root):
                if root=='a_slow':time.sleep(0.1)
                return super().analyze(root)
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name).resolve();source=stage/'a.c'
            source.write_text('unsigned a_slow(void){return 1;}unsigned b_fast(void){return 2;}')
            db=database(stage,[source])
            with patch('discover_kernel_state.Analyzer',SlowAnalyzer):unit=survey_unit(db,source,100,0.01)
            self.assertEqual([r['status'] for r in unit['roots']],['analysis_failed','candidate'])
            self.assertIn('RootTimeout',unit['roots'][0]['error'])

    def test_cli_accounts_for_parse_failures_and_cross_file_gaps(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name).resolve();files=[stage/(n+'.c') for n in ('a','b','broken')]
            files[0].write_text('unsigned other(void);unsigned root(void){return other();}')
            files[1].write_text('unsigned other(void){return 7;}')
            files[2].write_text('this is not valid C;')
            db=database(stage,files);out=stage/'survey'
            subprocess.run([sys.executable,str(ROOT/'tools/discover_kernel_state.py'),'--compile-commands',str(db),'--out',str(out),'--jobs','2'],check=True,capture_output=True,text=True,timeout=60)
            report=json.loads((out/'report.json').read_text());summary=report['summary']
            self.assertEqual(summary['translation_units'],3)
            self.assertEqual(summary['unit_status'],{'analyzed':2,'unit_failed':1})
            self.assertEqual(summary['function_bodies'],2)
            gap=next(r for r in summary['unresolved_calls'] if r['callee']=='other')
            self.assertEqual(gap['resolution'],'cross_translation_unit_body_available')
            self.assertEqual(gap['definition_sources_in_inventory'],[str(files[1])])
            self.assertFalse(report['limits']['whole_program_call_closure'])
            self.assertEqual(len(report['units']),3)
            failed=next(u for u in report['units'] if u['status']=='unit_failed')
            self.assertIn('configured Clang parse failed',failed['error'])

    def test_compile_recovery_uses_dry_run_without_building(self):
        with tempfile.TemporaryDirectory() as name:
            tree=Path(name).resolve();module=tree/'kernel/liteos_a/example';module.mkdir(parents=True)
            source=module/'a.c';source.write_text('unsigned root(void){return 7;}')
            target=tree/'out/obj/kernel/liteos_a/example/a.o'
            (module/'Makefile').write_text(str(target)+': '+str(source)+'\n\t'+CLANG+' -c '+str(source)+' -o '+str(target)+'\n')
            record=compile_record(tree,source,Path(CLANG).parent)
            self.assertEqual(record['file'],str(source));self.assertFalse(target.exists())

if __name__=='__main__':
    if len(sys.argv)==2:CLANG=sys.argv.pop()
    unittest.main()
