"""Generated typed calls from capture specifications and generic replay requests."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import test_entry_capture as fixture
from entry_capture import generate,import_session
from entry_state import Analyzer,load_ast
from entry_state_dispatch import generate_dispatch
from export_entry_state import export,prepare_request,RequestError
from freestanding_armv7 import run

LLVM=fixture.LLVM;QEMU=fixture.QEMU;RETAIN=None


def setup(stage,mode='independent',roots=('update','query')):
    plan,spec=fixture.setup(stage,mode,roots)
    configuration=json.loads(spec.read_text());configuration['replay_dispatch']='generated'
    spec.write_text(json.dumps(configuration,indent=2)+'\n')
    (stage/'capture.h').write_text(generate(plan,spec))
    (stage/'adapter.h').write_text('Obj *current(void){return osrec_bound_current;}\n' if 'update' in roots else '/* Original bodies are in a separate translation unit. */\n')
    return plan,spec


def capture_mixed(project):
    return fixture.native(project,'''int main(void){a.next=&b;osrec_capture_init(&session);
 if(osrec_capture_update(&session,0)!=100)return 1;
 if(osrec_capture_query(&session)!=141)return 2;
 if(osrec_capture_update(&session,7)!=101)return 3;
 if(osrec_capture_query(&session)!=108)return 4;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
''')


class EntryStateDispatchTests(unittest.TestCase):
    def test_capture_import_modes_relocation_and_portable_rebuild(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for mode in ('independent','continuous'):
                project=stage/(mode+'-project');plan,spec=setup(project,mode)
                capture=capture_mixed(project);imported=stage/(mode+'-request')
                import_session(plan,spec,capture,imported)
                request=imported/'request.json';prepared=prepare_request(request)
                self.assertNotIn('osrec_invoke',prepared['inputs']['adapter_header']['data'].decode())
                self.assertIsNotNone(prepared['dispatch'])
                for address in (0x40200000,0x40400000):
                    output=stage/(mode+hex(address));report=export(fixture.image_args(request,output,address))
                    self.assertIn('generated_dispatch',report)
                    self.assertEqual([c['raw_bits'] for c in report['target_observations']['actual_calls']],[100,141,101,108])
                    self.assertEqual(report['target_observations']['states_restored'],1 if mode=='continuous' else 4)
                    if RETAIN is not None:shutil.copytree(output,RETAIN/mode/hex(address))
                portable=output/'request.json';shutil.rmtree(project);shutil.rmtree(imported)
                rebuilt=stage/(mode+'-portable');export(fixture.image_args(portable,rebuilt,0x40400000))
                self.assertEqual((rebuilt/'entry-state.bin').read_bytes(),(output/'entry-state.bin').read_bytes())
                if RETAIN is not None:shutil.copytree(rebuilt,RETAIN/mode/'portable-rebuild')

    def test_object_void_signed_and_null_arguments(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);project=stage/'project';plan,spec=setup(project,roots=('put','signed_value'))
            capture=fixture.native(project,'''int main(void){a.next=&b;osrec_capture_init(&session);
 osrec_capture_put(&session,&a,7);if(a.value!=7)return 1;
 if(osrec_capture_signed_value(&session,&a,INT32_MIN)!=INT32_MIN)return 2;
 if(osrec_capture_signed_value(&session,&a,-1)!=-1)return 3;
 osrec_capture_put(&session,0,99);if(a.value!=7)return 4;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
''')
            imported=stage/'request';import_session(plan,spec,capture,imported)
            output=stage/'image';report=export(fixture.image_args(imported/'request.json',output))
            self.assertEqual([c['raw_bits'] for c in report['target_observations']['actual_calls']],[0,0x80000000,0xffffffff,0])
            if RETAIN is not None:shutil.copytree(output,RETAIN/'void-signed-null')

    def test_multiple_pointer_arguments_const_aliases_and_nulls(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);project=stage/'project';project.mkdir()
            body='unsigned combine(const Obj *left,Obj *right,int input){return right?right->value+(left?left->value:0)+(unsigned)input:0;}\n'
            source=project/'functions.c';source.write_text(fixture.MODEL+body)
            db=project/'compile_commands.json';db.write_text(json.dumps([{'directory':str(project),'file':str(source),
                'arguments':[str(LLVM/'clang'),'-std=c11','-c',str(source)]}]))
            tree,_=load_ast(db,source)
            plan=Analyzer(tree,argument_objects={'combine':{'left':fixture.ARGUMENT,'right':fixture.ARGUMENT}}).analyze('combine')
            self.assertFalse(plan['blockers'])
            plan_path=project/'plan.json';plan_path.write_text(json.dumps({'format':'osrec-entry-state-plan-v1','plans':[plan]}))
            spec={'format':'osrec-entry-capture-spec-v1','mode':'independent','replay_dispatch':'generated',
                'contract':{'fixed_lifetimes':True,'exclusive_capture':True,'reason':'fixed fixture objects','implementation':'single capture owner'},
                'sites':[{'root':'combine','number':106,'return_kind':'u32'}],
                'model_header':'model.h','adapter_header':'adapter.h','files':{'bodies.c':'bodies.c'},'translation_units':['bodies.c']}
            spec_path=project/'spec.json';spec_path.write_text(json.dumps(spec))
            (project/'capture.h').write_text(generate(plan_path,spec_path))
            (project/'model.h').write_text(fixture.MODEL+'unsigned combine(const Obj *left,Obj *right,int input);\n')
            (project/'adapter.h').write_text('/* No handwritten invocation adapter. */\n')
            (project/'bodies.c').write_text('#include "entry_model.h"\n'+body)
            capture=fixture.native(project,'''int main(void){a.next=&b;osrec_capture_init(&session);
 if(osrec_capture_combine(&session,&a,&a,-1)!=197)return 1;
 if(osrec_capture_combine(&session,&a,&b,-1)!=139)return 2;
 if(osrec_capture_combine(&session,0,&b,INT32_MIN)!=UINT32_C(0x80000029))return 3;
 if(osrec_capture_combine(&session,&a,0,5)!=0)return 4;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
''')
            imported=stage/'request';import_session(plan_path,spec_path,capture,imported)
            output=stage/'image';report=export(fixture.image_args(imported/'request.json',output))
            self.assertEqual([c['raw_bits'] for c in report['target_observations']['actual_calls']],[197,139,0x80000029,0])
            if RETAIN is not None:shutil.copytree(output,RETAIN/'const-multiple-alias-null')

    def test_dispatch_schema_and_function_abi_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);project=stage/'project';plan,spec=setup(project)
            capture=capture_mixed(project);imported=stage/'request';import_session(plan,spec,capture,imported)
            path=imported/'request.json';original=json.loads(path.read_text())
            changes=('format','empty','missing','unknown','duplicate_route','duplicate_root','wrong_route','wrong_root','bad_kind','bool_route','extra','unsafe_root')
            for change in changes:
                document=copy.deepcopy(original);d=document['dispatch']
                if change=='format':d['format']='unknown'
                elif change=='empty':d['sites']=[]
                elif change=='missing':d['sites'].pop()
                elif change=='unknown':d['sites'][0]['root']='missing'
                elif change=='duplicate_route':d['sites'][1]['number']=101
                elif change=='duplicate_root':d['sites'][1]['root']='update'
                elif change=='wrong_route':d['sites'][0]['number']=999
                elif change=='wrong_root':d['sites'][0]['root'],d['sites'][1]['root']='query','update'
                elif change=='bad_kind':d['sites'][0]['return_kind']='pointer'
                elif change=='bool_route':d['sites'][0]['number']=True
                elif change=='extra':d['sites'][0]['unexpected']=1
                else:d['sites'][0]['root']='update();'
                path.write_text(json.dumps(document))
                with self.subTest(change=change),self.assertRaises(RequestError) as caught:prepare_request(path)
                self.assertEqual(caught.exception.stage,'dispatch')
            # The original type, not just the observed return bits, must match.
            bad=copy.deepcopy(original);bad['dispatch']['sites'][0]['return_kind']='i32';path.write_text(json.dumps(bad))
            output=stage/'bad-result-abi'
            with self.assertRaises(RequestError) as caught:export(fixture.image_args(path,output))
            self.assertIn('dispatch function ABI differs',str(caught.exception));self.assertFalse(output.exists())
            path.write_text(json.dumps(original))
            model=imported/'model_header.h';model.write_text(model.read_text().replace('update(unsigned input)','update(int input)'))
            bodies=imported/'support-bodies.c';bodies.write_text(bodies.read_text().replace('update(unsigned input)','update(int input)'))
            output=stage/'bad-argument-abi'
            with self.assertRaises(RequestError) as caught:export(fixture.image_args(path,output))
            self.assertIn('dispatch function ABI differs',str(caught.exception));self.assertFalse(output.exists())

    def test_invalid_route_and_exhaustion_fault_even_for_all_bits_result(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,wrong_route in [('all_bits',False),('all_bits',True),('number',False)]:
                plan={'root':root,'arguments':[],'object_providers':[]}
                dispatch={'format':'osrec-entry-dispatch-v1','sites':[{'root':root,'number':105,'return_kind':'u32'}]}
                generated=generate_dispatch({root:plan},[{'root':root,'number':105,'raw_bits':0xffffffff}],dispatch)
                body=('if(osrec_invoke(999)!=0||faults!=1||calls!=0)return 1;' if wrong_route else
                      'if(osrec_invoke(105)!=UINT32_MAX||faults||calls!=1)return 1;if(osrec_invoke(105)!=0||faults!=1||calls!=1)return 2;')
                source=stage/'guard.c';source.write_text('#include <stdint.h>\nstatic unsigned calls,faults;unsigned '+root+'(void){++calls;return UINT32_MAX;}\nvoid replay_fault(void){++faults;}\n'+generated+'int main(void){'+body+'return 0;}\n')
                binary=stage/'guard';run([LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary]);run([binary])


if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:
        LLVM=Path(sys.argv[1]);QEMU=sys.argv[2];fixture.LLVM=LLVM;fixture.QEMU=QEMU;sys.argv=sys.argv[:1]
    unittest.main()
