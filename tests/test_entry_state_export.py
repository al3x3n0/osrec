"""Request-driven mixed-root replay, portable exports and rejection before publication."""
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
from entry_state import Analyzer,load_ast,capture_header,digest
from automated_entry_state import effect_plan
from export_entry_state import prepare_request,export,RequestError
from freestanding_armv7 import run

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64';RETAIN=None
MODEL='#include <stdint.h>\ntypedef struct Obj {unsigned value;struct Obj *next;} Obj;\nObj *current(void);\nunsigned update(unsigned input);unsigned query(void);\n'
BODY='''unsigned update(unsigned input){if(current()->next && (input&1U))current()->next->value=input;return current()->value;}
unsigned query(void){return current()->value+(current()->next?current()->next->value:0);}
'''
POLICY={'current':{'kind':'object_provider','reason':'fixture owns the complete stable graph',
    'implementation':'fixed provider binding with no concurrent writers','snapshot_safe':True,
    'stable_identity':True,'exclusive_state':True,'preserves_entry_state':True}}


def fixture(stage):
    stage.mkdir();source=stage/'input.c';source.write_text(MODEL+BODY)
    db=stage/'compile_commands.json';db.write_text(json.dumps([{'directory':str(stage),'file':str(source),
        'arguments':[str(LLVM/'clang'),'-std=c11','-c',str(source)]}]))
    tree,_=load_ast(db,source)
    plans=[Analyzer(tree,POLICY,prune_written=True,preserve_write_state=True).analyze(root) for root in ('update','query')]
    (stage/'capture.h').write_text(capture_header(plans+[{**effect_plan(p),'root':'effects_'+p['root']} for p in plans]))
    native=stage/'native.c';native.write_text(MODEL+BODY+r'''
#include <stdio.h>
#include "capture.h"
static Obj a={99,0},b={41,0};static struct osrec_entry_snapshot ids;
Obj *current(void){return &a;}
static void emit(struct osrec_entry_snapshot *s,unsigned invocation,unsigned number,unsigned input){
 printf("{\"format\":\"osrec-entry-snapshot-v1\",\"invocation\":%u,\"syscall\":%u,\"objects\":[",invocation,number);
 for(unsigned i=0;i<s->object_count;++i){struct osrec_snapshot_object *o=&s->objects[i];
  printf("%s{\"id\":%u,\"session_id\":%u,\"type\":\"%s\"}",i?",":"",o->id,osrec_snapshot_identity(&ids,o->address,o->type),o->type);}
 printf("],\"roots\":[");for(unsigned i=0;i<s->root_count;++i)printf("%s{\"name\":\"%s\",\"object_id\":%u}",i?",":"",s->roots[i].name,s->roots[i].object_id);
 printf("],\"arguments\":[");if(number==101)printf("{\"name\":\"input\",\"bytes\":4,\"data\":\"%02x000000\"}",input);
 printf("],\"fields\":[");for(unsigned i=0;i<s->field_count;++i){struct osrec_snapshot_field *f=&s->fields[i];
  printf("%s{\"object_id\":%u,\"name\":\"%s\",",i?",":"",f->object_id,f->name);
  if(f->is_edge)printf("\"kind\":\"edge\",\"target_id\":%u}",f->target_id);
  else{printf("\"kind\":\"scalar\",\"bytes\":%u,\"data\":\"",f->size);for(unsigned j=0;j<f->size;++j)printf("%02x",f->bytes[j]);printf("\"}");}}
 printf("]}");}
int main(void){a.next=&b;osrec_snapshot_init(&ids);puts("[");for(unsigned i=0;i<4;++i){
 unsigned number=(i&1)?102:101,input=i==2?7:0,raw;struct osrec_entry_snapshot e,p;osrec_snapshot_init(&e);osrec_snapshot_init(&p);
 if(i&1){if(!osrec_snapshot_query(&e))return 1;raw=query();if(!osrec_snapshot_effects_query(&p))return 2;}
 else{if(!osrec_snapshot_update(&e))return 3;raw=update(input);if(!osrec_snapshot_effects_update(&p))return 4;}
 if(i)puts(",");printf("{\"entry\":");emit(&e,i,number,input);printf(",\"post\":");emit(&p,i,number,input);printf(",\"raw\":%u}",raw);}
 puts("]");return 0;}
''')
    executable=stage/'native';run([LLVM/'clang','-std=c11','-I',ROOT/'include',native,ROOT/'runtime/entry_snapshot.c','-o',executable])
    rows=json.loads(run([executable]).stdout);assert [r['raw'] for r in rows]==[99,140,99,106]
    (stage/'plan.json').write_text(json.dumps({'format':'osrec-entry-state-plan-v1','plans':plans}))
    (stage/'entries.json').write_text(json.dumps([r['entry'] for r in rows]));(stage/'posts.json').write_text(json.dumps([r['post'] for r in rows]))
    (stage/'model.h').write_text(MODEL);(stage/'functions.c').write_text('#include "entry_model.h"\n'+BODY)
    (stage/'adapter.h').write_text('Obj *current(void){return osrec_bound_current;}\n'
        'uint32_t osrec_invoke(uint32_t number){static unsigned i;unsigned index=i++;'
        'if(number==101)return update(osrec_argument(index,0));if(number==102)return query();return UINT32_MAX;}\n')
    request={'format':'osrec-entry-replay-request-v1','mode':'independent','plan':'plan.json','entries':'entries.json',
        'post_states':'posts.json','model_header':'model.h','adapter_header':'adapter.h','files':{'functions.c':'functions.c'},
        'translation_units':['functions.c'],'calls':[{'root':'query' if i&1 else 'update','number':r['entry']['syscall'],'raw_bits':r['raw']} for i,r in enumerate(rows)]}
    path=stage/'request.json';path.write_text(json.dumps(request));return path


def arguments(request,out,address=0x40200000):
    return SimpleNamespace(request=request.resolve(),out=out.resolve(),arch='aarch64',entry_address=address,
        result_address=address-0x80000,llvm_bin=LLVM,qemu=QEMU)


class EntryExportTests(unittest.TestCase):
    def test_preflight_diagnostics(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)/'inputs';path=fixture(stage);base=json.loads(path.read_text())
            self.assertEqual([p['root'] for p in prepare_request(path)['plans']],['update','query','update','query'])
            for change,expected in [('mode','inputs'),('calls','calls'),('root','calls'),('route','calls'),('posts','calls'),
                                    ('effects','reconstruction'),('translation','inputs'),('reserved','inputs'),('invocation','calls'),('field','reconstruction')]:
                request=copy.deepcopy(base)
                if change=='mode':request['mode']='unknown'
                elif change=='calls':request['calls']*=2
                elif change=='root':request['calls'][0]['root']='missing'
                elif change=='route':request['calls'][0]['number']=102
                elif change=='posts':request['post_states']='empty.json';(stage/'empty.json').write_text('[]')
                elif change=='effects':request.pop('post_states')
                elif change=='translation':request['translation_units']=['missing.c']
                elif change=='reserved':request['files']['entry_model.h']='model.h'
                else:
                    document=json.loads((stage/('posts.json' if change=='invocation' else 'entries.json')).read_text())
                    if change=='invocation':document[0]['invocation']=99;request['post_states']='changed.json'
                    else:document[0]['fields']=[f for f in document[0]['fields'] if f['object_id']!=2];request['entries']='changed.json'
                    (stage/'changed.json').write_text(json.dumps(document))
                path.write_text(json.dumps(request))
                with self.subTest(change=change),self.assertRaises(RequestError) as caught:prepare_request(path)
                self.assertEqual(caught.exception.stage,expected)
            path.write_text(json.dumps(base))
            checked=subprocess.run([sys.executable,ROOT/'tools/export_entry_state.py','--request',path,'--check-only'],capture_output=True,text=True)
            self.assertEqual(checked.returncode,0,checked.stderr);self.assertEqual(json.loads(checked.stdout)['status'],'validated')
            path.write_text('[]')
            rejected=subprocess.run([sys.executable,ROOT/'tools/export_entry_state.py','--request',path,'--check-only'],capture_output=True,text=True)
            self.assertEqual(rejected.returncode,2);self.assertEqual(json.loads(rejected.stderr)['stage'],'inputs')

    def test_mixed_roots_modes_relocation_and_portability(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);request=fixture(stage/'inputs');portable=None
            for mode in ('independent','continuous'):
                document=json.loads(request.read_text());document['mode']=mode;request.write_text(json.dumps(document))
                for address in (0x40200000,0x40400000):
                    output=stage/(mode+hex(address));report=export(arguments(request,output,address))
                    self.assertEqual(report['target_observations']['actual_calls'],[{'number':c['number'],'raw_bits':c['raw_bits']} for c in document['calls']])
                    self.assertFalse(report['native_capture_attested']);self.assertTrue(report['raw_image_execution_match'])
                    self.assertEqual(report['request_sha256'],digest((output/'inputs/original-request.json').read_bytes()))
                    self.assertEqual(report['portable_request_sha256'],digest((output/'request.json').read_bytes()))
                    prepare_request(output/'request.json');portable=output/'request.json'
                    if RETAIN is not None:shutil.copytree(output,RETAIN/mode/hex(address))
            shutil.rmtree(stage/'inputs')
            # The published request must rebuild without original input paths.
            export(arguments(portable,stage/'portable-rebuild'))

    def test_faults_do_not_publish(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);request=fixture(stage/'inputs');source=request.parent/'functions.c';original=source.read_text()
            faults=[]
            for mutation,body in [('missing_store',original.replace('current()->next->value=input;','(void)input;')),
                                  ('compile_error','this is not C;')]:
                source.write_text(body);output=stage/mutation
                with self.subTest(mutation=mutation),self.assertRaises(RequestError) as caught:export(arguments(request,output))
                self.assertEqual(caught.exception.stage,'build_or_verify');self.assertFalse(output.exists())
                if mutation=='missing_store':
                    observed=json.loads(str(caught.exception).removeprefix('target replay diverged: '))
                    self.assertEqual((observed['status'],observed['error'],observed['actual_calls'][2]['raw_bits']),(3,22,99))
                else:self.assertIn('error:',str(caught.exception))
                faults.append({'mutation':mutation,'stage':caught.exception.stage,'detail':str(caught.exception),'published':False})
            if RETAIN is not None:(RETAIN/'fault-verification.json').write_text(json.dumps(faults,indent=2)+'\n')


if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:LLVM=Path(sys.argv[1]);QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
