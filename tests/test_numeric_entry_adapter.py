"""Typed numeric caller adapters: provenance, bounded payloads and replay effects."""
import json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from numeric_entry_adapter import prepare,schema,render
from entry_state import load_ast
from entry_capture import generate,import_session
from export_entry_state import export,prepare_request,RequestError
from freestanding_armv7 import run
from test_discovered_constant_data import configured
import test_entry_state_loops as fixture
CLANG=str(fixture.LLVM/'clang');RETAIN=None
RECURSIVE='unsigned root(unsigned n,int *out){if(n){*out+=2;return root(n-1,out)+n;}*out+=3;return (unsigned)*out;}'

class NumericAdapterTests(unittest.TestCase):
    def project(self,stage,text=RECURSIVE,extra=None):
        texts={'root.c':text};texts.update(extra or {})
        db,index=configured(stage/'inputs',texts)
        result=prepare(db,stage/'inputs/root.c','root',stage/'adapter',index)
        return result,db,index

    def test_recursive_capture_schema_and_original_identity(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);r,db,index=self.project(stage)
            self.assertEqual(r['status'],'candidate');self.assertEqual(r['snapshot_generation'],'generated')
            self.assertEqual(r['target_syntax_check']['returncode'],0)
            self.assertEqual(r['original_source_identity'],index.source_evidence[str((stage/'inputs/root.c').resolve())])
            self.assertFalse(r['adapter']['counted_as_original_kernel_root'])
            self.assertFalse(r['plan']['blockers']);self.assertTrue(r['plan']['recursion_footprint_proofs'])
            self.assertEqual({w['path'] for w in r['plan']['state_writes']},
                {'osrec_argument_state()->arg_out[0]','osrec_argument_state()->result[0]'})

    def test_numeric_typedef_const_pointer_and_void(self):
        for text in ('typedef double Real;Real root(Real x,const int *p){return x+*p;}',
                     'void root(int *p){*p+=1;}',
                     'long double root(long double x,int *p){*p=2;return x;}'):
            with self.subTest(text=text),tempfile.TemporaryDirectory() as name:
                r,_,_=self.project(Path(name),text)
                self.assertEqual(r['snapshot_generation'],'generated');self.assertEqual(r['target_syntax_check']['returncode'],0)
                self.assertEqual(r['adapter']['result_field'],None if text.startswith('void') else 'result')

    def test_unsafe_or_unrepresented_parameter_domains_rejected(self):
        texts=['unsigned root(int **p){return 0;}','unsigned root(volatile int *p){return 0;}',
               'unsigned root(_Atomic(int) *p){return 0;}','unsigned root(void *p){return 0;}',
               'unsigned root(int *p,...){return 0;}','unsigned root(int p[2]){return 0;}',
               'unsigned count;unsigned root(int p[++count]){return 0;}',
               'unsigned root(int (*p)(void)){return 0;}','struct T{int x;};unsigned root(struct T*p){return 0;}',
               'unsigned root(unsigned n){return n;}']
        for text in texts:
            with self.subTest(text=text),tempfile.TemporaryDirectory() as name:
                stage=Path(name);db,_=configured(stage/'inputs',{'root.c':text})
                tree,_=load_ast(db,stage/'inputs/root.c')
                with self.assertRaises(ValueError):schema(tree,'root')

    def test_extent_is_never_inferred_from_original_access(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);r,_,_=self.project(stage,'unsigned root(int *p){return (unsigned)p[1];}')
            self.assertEqual(r['status'],'blocked');self.assertEqual(r['snapshot_generation'],'unsupported')
            self.assertFalse((stage/'adapter/capture.h').exists())

    def test_name_collisions_and_call_macros_rejected(self):
        for text in ('unsigned numeric_root;unsigned root(int*p){return *p;}',
                     'struct numeric_root_state{int x;};unsigned root(int*p){return *p;}',
                     'unsigned root(unsigned n,int*p){return n+*p;}\n#define root(n,p) root(9,p)\n',
                     'unsigned root(int*p){return *p;}\n#define arg_p renamed\n'):
            with self.subTest(text=text),tempfile.TemporaryDirectory() as name:
                with self.assertRaises(ValueError):self.project(Path(name),text)

    def test_include_context_cannot_change_original_body(self):
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaisesRegex(ValueError,'changed configured'):
                self.project(Path(name),'unsigned root(int*p){return *p+__INCLUDE_LEVEL__;}')

    def test_static_root_and_verified_cross_file_closure(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);r,_,_=self.project(stage,
                'unsigned helper(int*);static unsigned root(int*p){return helper(p);}',
                {'helper.c':'unsigned helper(int*p){*p+=3;return (unsigned)*p;}'})
            self.assertEqual(r['snapshot_generation'],'generated');self.assertEqual(r['program']['translation_units'],2)
            self.assertEqual(r['history'][0]['missing_bodies'],['helper'])

    def test_stale_verified_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);db,index=configured(stage/'inputs',{'root.c':RECURSIVE})
            source=stage/'inputs/root.c';source.write_text(RECURSIVE+'\n')
            with self.assertRaisesRegex(ValueError,'verified configured-source'):prepare(db,source,'root',stage/'adapter',index)

    def test_cli_uses_verified_survey_and_preserves_compiler_arguments(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);db,index=configured(stage/'inputs',{'root.c':RECURSIVE})
            command=[sys.executable,ROOT/'tools/numeric_entry_adapter.py','--survey',db.parent,'--source',stage/'inputs/root.c',
                     '--root','root','--wrapper','caller_root','--out',stage/'cli']
            outcome=json.loads(run(command).stdout)
            self.assertEqual(outcome['snapshot_generation'],'generated');self.assertEqual(outcome['adapter_root'],'caller_root')
            r=json.loads((stage/'cli/result.json').read_text())
            expected=index.source_evidence[str((stage/'inputs/root.c').resolve())]
            actual=r['generated_source_identity']
            self.assertEqual(actual['compiler'],expected['compiler']);self.assertEqual(actual['compile_directory'],expected['compile_directory'])
            self.assertEqual(actual['compile_arguments'],[str((stage/'cli/numeric_adapter.c').resolve()) if a==str((stage/'inputs/root.c').resolve()) else a for a in expected['compile_arguments']])
            for path,sha in expected['dependencies'].items():self.assertEqual(actual['dependencies'][path],sha)

    def test_syntax_failure_does_not_publish_an_accepted_capture(self):
        from unittest.mock import patch
        import numeric_entry_adapter as tool
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);original=subprocess.run
            def checked(command,**kwargs):
                if any(str(a).endswith('capture-check.c') for a in command):
                    return subprocess.CompletedProcess(command,1,'','injected target syntax failure')
                return original(command,**kwargs)
            with patch.object(tool.subprocess,'run',side_effect=checked),self.assertRaisesRegex(ValueError,'syntax check'):
                self.project(stage)
            result=json.loads((stage/'adapter/result.json').read_text())
            self.assertEqual(result['status'],'failed');self.assertFalse(result['capture_schema_accepted'])
            self.assertFalse((stage/'adapter/capture.h').exists())

    def capture(self,stage,text=RECURSIVE):
        stage.mkdir();r,_,_=self.project(stage,text);adapter=stage/'adapter'
        # Portable fixture body uses the same original C text, with the generated
        # carrier and wrapper. Kernel adapter probes retain configured includes.
        model,body=render(r['adapter']);(adapter/'entry_model.h').write_text(model+'unsigned numeric_root(struct numeric_root_state *);\n')
        (adapter/'bodies.c').write_text('#include "entry_model.h"\n'+text+'\n'+body)
        (adapter/'adapter.h').write_text('/* Typed routing generated by importer. */\n')
        spec={'format':'osrec-entry-capture-spec-v1','mode':'independent','max_calls':8,'replay_dispatch':'generated',
          'contract':{'fixed_lifetimes':True,'exclusive_capture':True,'reason':'caller owns complete initialized carrier',
                      'implementation':'single-thread fixture with distinct one-element payload arrays'},
          'sites':[{'root':'numeric_root','number':201,'return_kind':'u32'}],
          'model_header':'entry_model.h','adapter_header':'adapter.h','files':{'bodies.c':'bodies.c'},'translation_units':['bodies.c']}
        sp=adapter/'spec.json';sp.write_text(json.dumps(spec));(adapter/'session.h').write_text(generate(adapter/'plan.json',sp))
        floating=text.startswith('double')
        main='''int main(void){osrec_capture_init(&session);
 for(unsigned n=0;n<7;++n){struct numeric_root_state s={n,{7},{99}};
 if(osrec_capture_numeric_root(&session,&s)!=0 || s.arg_out[0]!=(int)(10+2*n) || s.result[0]!=10+2*n+n*(n+1)/2)return 1;}
 if(osrec_capture_numeric_root(&session,0)!=1)return 2;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
'''
        if floating:main='''int main(void){osrec_capture_init(&session);
 for(unsigned n=0;n<7;++n){struct numeric_root_state s={n+0.5,{7},{99}};
 if(osrec_capture_numeric_root(&session,&s)!=0 || s.arg_out[0]!=9 || s.result[0]!=n+0.75)return 1;}
 if(osrec_capture_numeric_root(&session,0)!=1)return 2;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
'''
        native=adapter/'native.c';native.write_text('''#include <stdio.h>
#include "entry_model.h"
#include "session.h"
static struct osrec_capture_session session;
static int emit(void*p,const char*d,size_t n){(void)p;return fwrite(d,1,n,stdout)==n;}
'''+main)
        binary=adapter/'native';run([CLANG,'-std=c11','-Wall','-Wextra','-Werror','-DOSREC_CAPTURE_CALLS=8','-I',ROOT/'include','-I',adapter,
          native,adapter/'bodies.c',ROOT/'runtime/entry_snapshot.c',ROOT/'runtime/entry_capture.c','-o',binary])
        capture=adapter/'capture.json';capture.write_text(run([binary]).stdout)
        imported=stage/'request';import_session(adapter/'plan.json',sp,capture,imported)
        return imported

    def replay(self,stage,text,mutations):
        request=self.capture(stage/'capture-inputs',text);out=stage/'replay'
        m=export(fixture.args_for(request/'request.json',out));o=m['target_observations']
        self.assertEqual([c['raw_bits'] for c in o['actual_calls']],[0]*7+[1]);self.assertEqual(o['states_verified'],8)
        source=request/'support-bodies.c';original=source.read_text();faults=[]
        for label,before,after in mutations:
            changed=original.replace(before,after);self.assertNotEqual(changed,original)
            try:
                source.write_text(changed)
                with self.assertRaises(RequestError) as caught:export(fixture.args_for(request/'request.json',stage/label))
                observations=json.loads(str(caught.exception).removeprefix('target replay diverged: '))
                self.assertEqual(observations['actual_calls'][0]['raw_bits'],0)
                self.assertNotEqual(observations['error'],0);faults.append({'mutation':label,'observations':observations})
            finally:source.write_text(original)
        (stage/'faults.json').write_text(json.dumps(faults,indent=2)+'\n')
        if RETAIN is not None:shutil.copytree(stage,RETAIN/('floating' if text.startswith('double') else 'recursive'))

    def test_recursive_native_capture_and_aarch64_replay_reject_wrong_output_and_result(self):
        with tempfile.TemporaryDirectory() as name:
            self.replay(Path(name),RECURSIVE,[('wrong-output','*out+=3','*out+=4'),('wrong-result','return (unsigned)*out','return 1+(unsigned)*out')])

    def test_floating_native_reconstruction_rejects_wrong_fp_result(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);request=self.capture(stage/'capture-inputs','double root(double x,int*out){*out+=2;return x+0.25;}')
            prepared=prepare_request(request/'request.json')
            (stage/'entry_model.h').write_bytes(prepared['model']);(stage/'reconstruction.h').write_text(prepared['header'])
            original=(request/'support-bodies.c').read_text();checks=[]
            for label,body in [('correct',original),('wrong-fp-result',original.replace('x+0.25','x+0.5'))]:
                source=stage/(label+'.c');source.write_text('#include <stdint.h>\n#include "entry_model.h"\n#include "reconstruction.h"\n'+body+\
                    'int main(void){for(unsigned i=0;i<8;++i){if(!osrec_restore(i))return 1;unsigned r=numeric_root(osrec_bound_osrec_argument_state);if(r!=(i==7?1U:0U))return 2;if(!osrec_state_matches(i))return 3;}return 0;}')
                binary=stage/label;run([CLANG,'-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary])
                result=subprocess.run([binary],capture_output=True,text=True)
                self.assertEqual(result.returncode,0 if label=='correct' else 3)
                checks.append({'case':label,'returncode':result.returncode})
            (stage/'host-reconstruction-checks.json').write_text(json.dumps(checks,indent=2)+'\n')
            if RETAIN is not None:shutil.copytree(stage,RETAIN/'floating')

if __name__=='__main__':
    if '--out' in sys.argv:
        i=sys.argv.index('--out');RETAIN=Path(sys.argv[i+1]).resolve();del sys.argv[i:i+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:fixture.LLVM=Path(sys.argv[1]);fixture.QEMU=sys.argv[2];CLANG=str(fixture.LLVM/'clang');sys.argv=sys.argv[:1]
    unittest.main()
