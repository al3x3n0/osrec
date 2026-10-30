"""Generated call sites to shared session serialization, import and target replay."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,load_ast,digest
from entry_capture import generate,import_session
from export_entry_state import export,prepare_request
from freestanding_armv7 import run

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64';RETAIN=None
MODEL='#include <stdint.h>\ntypedef struct Obj{unsigned value;struct Obj *next;}Obj;\nObj *current(void);\n'
BODIES={
    'update':'unsigned update(unsigned input){if(current()->next&&(input&1U))current()->next->value=input;current()->value+=1;return current()->value;}\n',
    'query':'unsigned query(void){return current()->value+(current()->next?current()->next->value:0);}\n',
    'put':'void put(Obj *left,unsigned input){if(left)left->value=input;}\n',
    'signed_value':'int signed_value(Obj *left,int input){if(left&&left->value==0)return input;return input;}\n'}
CONTRACT={'kind':'object_provider','snapshot_safe':True,'stable_identity':True,'exclusive_state':True,'preserves_entry_state':True,
          'reason':'fixture owns a fixed isolated graph','implementation':'single-threaded fixture for the entire session'}
ARGUMENT={**CONTRACT,'kind':'object_argument'}
TRANSPORT='static int emit(void *p,const char *data,size_t n){(void)p;return fwrite(data,1,n,stdout)==n;}\n'


def setup(stage,mode='independent',roots=('update','query')):
    stage.mkdir();source=stage/'functions.c';source.write_text(MODEL+''.join(BODIES[r] for r in roots))
    db=stage/'compile_commands.json';db.write_text(json.dumps([{'directory':str(stage),'file':str(source),
        'arguments':[str(LLVM/'clang'),'-std=c11','-c',str(source)]}]))
    tree,_=load_ast(db,source);plans=[]
    for root in roots:
        plan=Analyzer(tree,{'current':CONTRACT},prune_written=True,preserve_write_state=True,
            argument_objects={r:{'left':ARGUMENT} for r in ('put','signed_value')}).analyze(root)
        assert not plan['blockers'],plan['blockers'];plans.append(plan)
    plan_path=stage/'plan.json';plan_path.write_text(json.dumps({'format':'osrec-entry-state-plan-v1','plans':plans},indent=2)+'\n')
    routes={'update':101,'query':102,'put':103,'signed_value':104};kinds={'put':'void','signed_value':'i32'}
    spec={'format':'osrec-entry-capture-spec-v1','mode':mode,
        'contract':{'fixed_lifetimes':True,'exclusive_capture':True,'reason':'all fixture objects live across the session',
                    'implementation':'one capture owner; no concurrent writers'},
        'sites':[{'root':root,'number':routes[root],'return_kind':kinds.get(root,'u32')} for root in roots],
        'model_header':'model.h','adapter_header':'adapter.h','files':{'bodies.c':'bodies.c'},'translation_units':['bodies.c']}
    spec_path=stage/'spec.json';spec_path.write_text(json.dumps(spec,indent=2)+'\n')
    (stage/'capture.h').write_text(generate(plan_path,spec_path))
    declarations=''.join(BODIES[r].split('{',1)[0]+';\n' for r in roots)
    (stage/'model.h').write_text(MODEL+declarations)
    (stage/'bodies.c').write_text('#include "entry_model.h"\n'+''.join(BODIES[r] for r in roots))
    adapter='Obj *current(void){return osrec_bound_current;}\n' if 'update' in roots or 'query' in roots else ''
    adapter+='uint32_t osrec_invoke(uint32_t number){static unsigned i;unsigned index=i++;(void)index;\n'
    for root in roots:
        args={'update':'osrec_argument(index,0)','query':'','put':'osrec_bound_osrec_argument_left,osrec_argument(index,1)',
              'signed_value':'osrec_bound_osrec_argument_left,osrec_argument(index,1)'}[root]
        adapter+='if(number=='+str(routes[root])+'){'+(root+'('+args+');return 0;' if root=='put' else 'return (uint32_t)'+root+'('+args+');')+'}\n'
    (stage/'adapter.h').write_text(adapter+'return UINT32_MAX;}\n')
    return plan_path,spec_path


def native(stage,body,stdout=True):
    source=stage/'native.c';source.write_text((stage/'functions.c').read_text()+
        '#include <stdio.h>\n#include "capture.h"\nstatic Obj a={99,0},b={41,0};Obj *current(void){return &a;}\n'
        'static struct osrec_capture_session session;\n'+TRANSPORT+body)
    binary=stage/'native';run([LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror','-I',ROOT/'include','-I',stage,source,
        ROOT/'runtime/entry_snapshot.c',ROOT/'runtime/entry_capture.c','-o',binary])
    result=run([binary])
    if stdout:
        path=stage/'capture.json';path.write_text(result.stdout);return path


def image_args(request,out,address=0x40200000):
    return SimpleNamespace(request=request.resolve(),out=out.resolve(),arch='aarch64',entry_address=address,
        result_address=address-0x80000,llvm_bin=LLVM,qemu=QEMU)


class EntryCaptureTests(unittest.TestCase):
    def test_mixed_sites_import_and_two_replay_modes(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for mode in ('independent','continuous'):
                project=stage/mode;plan,spec=setup(project,mode)
                capture=native(project,'''int main(void){a.next=&b;osrec_capture_init(&session);
 unsigned n=0;if(osrec_capture_update(&session,n++)!=100||n!=1)return 1;
 if(osrec_capture_query(&session)!=141)return 2;
 if(osrec_capture_update(&session,7)!=101)return 3;
 if(osrec_capture_query(&session)!=108||a.value!=101||b.value!=7)return 4;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
''')
                data=json.loads(capture.read_text());self.assertEqual([c['raw_bits'] for c in data['calls']],[100,141,101,108])
                self.assertEqual(data['plan_sha256'],digest(plan.read_bytes()))
                self.assertNotIn('address',capture.read_text())
                imported=stage/(mode+'-request');manifest=import_session(plan,spec,capture,imported)
                self.assertTrue(manifest['typed_reconstruction_validated']);prepare_request(imported/'request.json')
                for address in (0x40200000,0x40400000):
                    output=stage/(mode+hex(address));report=export(image_args(imported/'request.json',output,address))
                    self.assertEqual(report['target_observations']['states_restored'],1 if mode=='continuous' else 4)
                    if RETAIN is not None:shutil.copytree(output,RETAIN/mode/hex(address))
                if RETAIN is not None:
                    shutil.copytree(imported,RETAIN/mode/'imported');shutil.copytree(project,RETAIN/mode/'capture-project')

    def test_argument_void_signed_and_null_capture(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);project=stage/'project';plan,spec=setup(project,roots=('put','signed_value'))
            capture=native(project,'''int main(void){a.next=&b;osrec_capture_init(&session);
 osrec_capture_put(&session,&a,7);if(a.value!=7)return 1;
 if(osrec_capture_signed_value(&session,&a,INT32_MIN)!=INT32_MIN)return 2;
 osrec_capture_put(&session,0,99);if(a.value!=7)return 3;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
''')
            data=json.loads(capture.read_text());self.assertEqual([c['raw_bits'] for c in data['calls']],[0,0x80000000,0])
            self.assertFalse(data['calls'][2]['entry']['objects'])
            imported=stage/'request';import_session(plan,spec,capture,imported)
            output=stage/'image';export(image_args(imported/'request.json',output))
            if RETAIN is not None:
                shutil.copytree(output,RETAIN/'argument-void-signed');shutil.copytree(project,RETAIN/'argument-capture-project')

    def test_failures_do_not_suppress_original_calls_or_emit_sessions(self):
        with tempfile.TemporaryDirectory() as name:
            project=Path(name)/'project';setup(project)
            native(project,'''static unsigned writes;
static int reject(void *p,const char *data,size_t n){(void)p;(void)data;(void)n;++writes;return 0;}
int main(void){a.next=&b;osrec_capture_init(&session);
 if(osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,reject,0))return 1;
 for(unsigned i=0;i<8;++i)if(osrec_capture_update(&session,0)!=100+i)return 2;
 if(a.value!=107||!session.failed||session.count!=7)return 3;
 if(osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,reject,0)||writes)return 4;
 osrec_capture_init(&session);if(!osrec_capture_begin(&session,"outer",999))return 5;
 if(osrec_capture_update(&session,0)!=108||!session.failed)return 6;
 if(osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,reject,0)||writes)return 7;
 osrec_capture_init(&session);osrec_capture_query(&session);
 if(osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,reject,0)||writes!=1)return 8;
 (void)emit;return 0;}
''',stdout=False)

    def test_plan_spec_binding_and_malformed_sessions_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);project=stage/'project';plan,spec=setup(project)
            capture=native(project,'''int main(void){a.next=&b;osrec_capture_init(&session);osrec_capture_update(&session,0);
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
''')
            original=json.loads(capture.read_text())
            for change in ('plan','spec','root','route','result','invocation','arguments','field'):
                data=copy.deepcopy(original)
                if change in ('plan','spec'):data[change+'_sha256']='0'*64
                elif change=='root':data['calls'][0]['root']='query'
                elif change=='route':data['calls'][0]['number']=999
                elif change=='result':data['calls'][0]['raw_bits']=-1
                elif change=='invocation':data['calls'][0]['post']['invocation']=1
                elif change=='arguments':data['calls'][0]['post']['arguments'][0]['data']='01000000'
                else:data['calls'][0]['entry']['fields']=[]
                capture.write_text(json.dumps(data));out=stage/change
                with self.subTest(change=change),self.assertRaises(ValueError):import_session(plan,spec,capture,out)
                self.assertFalse(out.exists())
            configuration=json.loads(spec.read_text());configuration['contract']['fixed_lifetimes']=False;spec.write_text(json.dumps(configuration))
            with self.assertRaisesRegex(ValueError,'contracts'):generate(plan,spec)
            configuration['contract']['fixed_lifetimes']=True;configuration['sites'][0]['return_kind']='void';spec.write_text(json.dumps(configuration))
            (project/'capture.h').write_text(generate(plan,spec))
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                native(project,'int main(void){a.next=&b;osrec_capture_init(&session);osrec_capture_update(&session,0);(void)emit;return 0;}\n',stdout=False)
            self.assertIn('capture return ABI differs',caught.exception.stderr)
            # C permits a parameter with the same name as its function.
            # Generated locals must not shadow the original callee.
            source=project/'functions.c';source.write_text(source.read_text()+'unsigned collision(unsigned collision){return collision+1;}\n')
            tree,_=load_ast(project/'compile_commands.json',source)
            report={'format':'osrec-entry-state-plan-v1','plans':[Analyzer(tree).analyze('collision')]}
            plan.write_text(json.dumps(report));configuration['sites']=[{'root':'collision','number':107,'return_kind':'u32'}]
            spec.write_text(json.dumps(configuration));(project/'capture.h').write_text(generate(plan,spec))
            capture=native(project,'int main(void){a.next=&b;osrec_capture_init(&session);if(osrec_capture_collision(&session,41)!=42)return 1;return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}\n')
            self.assertEqual(json.loads(capture.read_text())['calls'][0]['entry']['arguments'][0]['name'],'collision')


if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:LLVM=Path(sys.argv[1]);QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
