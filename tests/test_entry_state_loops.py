"""Counted-loop discovery through generated native capture and standalone replay."""
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
from entry_state import Analyzer,load_ast,capture_header
from entry_capture import generate,import_session
from export_entry_state import export,prepare_request,RequestError
from freestanding_armv7 import run

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64';RETAIN=None
MODEL='#include <stdint.h>\ntypedef struct State{unsigned values[8];}State;\n'
PAINT='void paint(State *state,unsigned count,unsigned value){for(unsigned i=0;i<8;++i){if(i>=count)break;state->values[i]=value+i;}}\n'
TOTAL='unsigned total(State *state){unsigned result=0;for(int i=0;i<8;i++)result+=state->values[i];return result;}\n'
CONTRACT={'kind':'object_argument','snapshot_safe':True,'stable_identity':True,'exclusive_state':True,'preserves_entry_state':True,
          'reason':'one fixture owns a fixed isolated State','implementation':'no concurrent writers or lifetime changes during the session'}


def parse(stage,body):
    source=stage/'input.c';source.write_text(MODEL+body)
    db=stage/'compile_commands.json';db.write_text(json.dumps([{'directory':str(stage),'file':str(source),
        'arguments':[str(LLVM/'clang'),'-std=c11','-Wno-array-bounds','-c',str(source)]}]))
    return load_ast(db,source)[0]


def analyze(tree,root,limit=64):
    return Analyzer(tree,argument_objects={root:{'state':CONTRACT}},max_range_elements=limit,
                    prune_written=True,preserve_write_state=True).analyze(root)


def project(stage,mode,paint=PAINT,total=TOTAL,native_main=None):
    stage.mkdir();tree=parse(stage,paint+total);plans=[analyze(tree,r) for r in ('paint','total')]
    for p in plans:
        if p['blockers']:raise ValueError(p['blockers'])
    plan=stage/'plan.json';plan.write_text(json.dumps({'format':'osrec-entry-state-plan-v1','plans':plans},indent=2)+'\n')
    spec={'format':'osrec-entry-capture-spec-v1','mode':mode,'max_calls':8,'replay_dispatch':'generated',
        'contract':{'fixed_lifetimes':True,'exclusive_capture':True,'reason':'fixed fixture array object','implementation':'single owner for all eight calls'},
        'sites':[{'root':'paint','number':201,'return_kind':'void'},{'root':'total','number':202,'return_kind':'u32'}],
        'model_header':'model.h','adapter_header':'adapter.h','files':{'bodies.c':'bodies.c'},'translation_units':['bodies.c']}
    sp=stage/'spec.json';sp.write_text(json.dumps(spec,indent=2)+'\n');(stage/'capture.h').write_text(generate(plan,sp))
    (stage/'model.h').write_text(MODEL+'void paint(State *state,unsigned count,unsigned value);unsigned total(State *state);\n')
    (stage/'adapter.h').write_text('/* Typed invocation routing is generated. */\n')
    (stage/'bodies.c').write_text('#include "entry_model.h"\n'+paint+total)
    if native_main is None:native_main='''
int main(void){State object={{1,2,3,4,5,6,7,8}};osrec_capture_init(&session);
 osrec_capture_paint(&session,&object,0,50);if(osrec_capture_total(&session,&object)!=36)return 1;
 osrec_capture_paint(&session,&object,3,100);if(osrec_capture_total(&session,&object)!=333)return 2;
 osrec_capture_paint(&session,&object,100,7);if(osrec_capture_total(&session,&object)!=84)return 3;
 osrec_capture_paint(&session,&object,0,UINT32_MAX);if(osrec_capture_total(&session,&object)!=84)return 4;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
'''
    native=stage/'native.c';native.write_text((stage/'input.c').read_text()+'''
#include <stdio.h>
#include "capture.h"
static struct osrec_capture_session session;
static int emit(void *p,const char *data,size_t n){(void)p;return fwrite(data,1,n,stdout)==n;}
'''+native_main)
    binary=stage/'native';run([LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror','-DOSREC_CAPTURE_CALLS=8',
        '-I',ROOT/'include','-I',stage,native,ROOT/'runtime/entry_snapshot.c',ROOT/'runtime/entry_capture.c','-o',binary])
    capture=stage/'capture.json';capture.write_text(run([binary]).stdout)
    return plan,sp,capture,plans


def args_for(request,out,address=0x40200000):
    return SimpleNamespace(request=request.resolve(),out=out.resolve(),arch='aarch64',entry_address=address,
        result_address=address-0x80000,llvm_bin=LLVM,qemu=QEMU)


class EntryStateLoopTests(unittest.TestCase):
    def test_counted_loop_bounds_and_write_preservation(self):
        positives={
            'unsigned_loop':'unsigned result=0;for(unsigned i=0;i<8;++i)result+=state->values[i];return result;',
            'signed_loop':'unsigned result=0;for(int i=2;i<8U;i++)result+=state->values[i];return result;',
            'partial':'for(unsigned i=0;i<8;++i){if(i>=count)break;state->values[i]=count;}return 0;',
            'continue_loop':'unsigned result=0;for(unsigned i=0;i<8;++i){if(i==count)continue;result+=state->values[i];}return result;',
            'nested':'unsigned result=0;for(unsigned i=0;i<8;++i){for(unsigned j=0;j<2;++j)result+=state->values[i];}return result;',
            'shadow':'unsigned result=0;for(unsigned i=0;i<8;++i){for(unsigned i=2;i<4;++i)result+=state->values[i];}return result;',
            'any_start':'unsigned result=0;for(unsigned i=count;i<8;++i)result+=state->values[i];return result;'}
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,body in positives.items():
                tree=parse(stage,'unsigned '+root+'(State *state,unsigned count){(void)count;'+body+'}\n')
                plan=analyze(tree,root);self.assertFalse(plan['blockers'],(root,plan['blockers']))
                self.assertTrue(all(r.get('index_proof',{}).get('kind')=='canonical_for_induction' for r in plan['memory_ranges']))
                expected=range(2,8) if root=='signed_loop' else range(2,4) if root=='shadow' else range(8)
                rows=plan['preserved_entry_fields'] if root=='partial' else plan['entry_reads']
                self.assertEqual({r['path'] for r in rows},{'osrec_argument_state()->values['+str(i)+']' for i in expected})
                if root=='partial':
                    self.assertTrue(plan['write_state_preservation']['unsupported_control_flow'])
                    self.assertFalse(plan['write_state_preservation']['guaranteed_exit_stores'])
                    self.assertFalse(plan['dominated_reads'])
                capture_header([plan])
            tree=parse(stage,'unsigned local(void){unsigned i=0;++i;return i;}\nunsigned global_value;unsigned global_tick(void){return ++global_value;}\n')
            local=Analyzer(tree).analyze('local');self.assertFalse(local['blockers']);self.assertEqual(local['entry_reads'],[])
            global_plan=Analyzer(tree).analyze('global_tick');self.assertTrue(global_plan['entry_reads']);self.assertTrue(global_plan['state_writes'])

    def test_unsafe_or_unproved_induction_remains_blocked(self):
        cell=lambda *ns:{'osrec_argument_state()->values[%d]'%n for n in ns}
        EVALUATED={'nonunit':cell(*range(8)),'cast_index':cell(*range(8)),'narrow_counter':cell(*range(8)),'reused_counter':cell(*range(8)),'wide_bound':cell(*range(8))}
        bodies={
            'body_assign':'for(unsigned i=0;i<8;++i){i=count;state->values[i]=1;}',
            'body_increment':'for(unsigned i=0;i<8;++i){++i;state->values[i]=1;}',
            'compound':'for(unsigned i=0;i<8;++i){i+=count;state->values[i]=1;}',
            'address':'for(unsigned i=0;i<8;++i){touch(&i);state->values[i]=1;}',
            'dynamic_limit':'for(unsigned i=0;i<count;++i)state->values[i]=1;',
            'nonunit':'for(unsigned i=0;i<8;i+=2)state->values[i]=1;',
            'outside':'for(unsigned i=0;i<9;++i)state->values[i]=1;',
            'inclusive_outside':'for(unsigned i=0;i<=8;++i)state->values[i]=1;',
            'cast_index':'for(unsigned i=0;i<8;++i)state->values[(unsigned char)i]=1;',
            'narrow_counter':'for(unsigned char i=0;i<8;++i)state->values[i]=1;',
            'static_counter':'static unsigned i;for(i=0;i<8;++i)state->values[i]=1;',
            'reused_counter':'unsigned i=0;for(i=0;i<8;++i)state->values[i]=1;',
            'descending':'for(unsigned i=7;i>0;--i)state->values[i]=1;',
            'negative':'for(int i=-1;i<8;++i)state->values[i]=1;',
            'signed_any_start':'for(int i=count;i<8;++i)state->values[i]=1;',
            'zero_trip':'for(unsigned i=8;i<8;++i)state->values[i]=1;',
            'label':'for(unsigned i=0;i<8;++i){label:state->values[i]=1;}',
            'case_label':'switch(count){for(unsigned i=0;i<8;++i){case 1:state->values[i]=1;}}',
            'index_increment':'for(unsigned i=0;i<8;++i)state->values[i++]=1;',
            'cast_bound':'for(unsigned i=0;i<(unsigned char)264;++i)state->values[i]=1;',
            'wide_bound':'for(unsigned i=0;i<8ULL;++i)state->values[i]=1;',
            'wrapped_init':'for(unsigned i=0xffffffffU;i<8;++i)state->values[i]=1;',
            'pointer_cast':'for(unsigned i=0;i<8;++i)((unsigned *)state->values)[i]=1;'}
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,body in bodies.items():
                tree=parse(stage,'void touch(unsigned *p);void '+root+'(State *state,unsigned count){'+body+'}\n')
                plan=analyze(tree,root)
                with self.subTest(root=root):
                    if root in EVALUATED:
                        # Outside the induction certificate, the condition i<8 still bounds i in the body.
                        self.assertFalse(plan['blockers'],plan['blockers'])
                        self.assertEqual({w['path'] for w in plan['state_writes']},EVALUATED[root]);continue
                    self.assertTrue(plan['blockers'])
                    if root=='address':self.assertTrue(any(b['kind']=='dynamic_extent' for b in plan['blockers']))
                    with self.assertRaises(ValueError):capture_header([plan])
            tree=parse(stage,TOTAL);limited=analyze(tree,'total',4)
            self.assertTrue(any(b['kind']=='range_limit' for b in limited['blockers']))

    def test_native_capture_relocation_modes_and_portable_rebuild(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for mode in ('independent','continuous'):
                inputs=stage/(mode+'-inputs');plan,spec,capture,plans=project(inputs,mode)
                self.assertEqual(len(plans[0]['preserved_entry_fields']),8)
                imported=stage/(mode+'-request');import_session(plan,spec,capture,imported)
                for address in (0x40200000,0x40400000):
                    output=stage/(mode+hex(address));report=export(args_for(imported/'request.json',output,address));o=report['target_observations']
                    self.assertEqual([c['raw_bits'] for c in o['actual_calls']],[0,36,0,333,0,84,0,84])
                    self.assertEqual((o['abi_version'],o['states_restored'],o['states_verified']),(30,1 if mode=='continuous' else 8,8))
                    if RETAIN is not None:shutil.copytree(output,RETAIN/mode/hex(address))
                shutil.rmtree(inputs);shutil.rmtree(imported)
                rebuilt=stage/(mode+'-portable');export(args_for(output/'request.json',rebuilt,0x40400000))
                self.assertEqual((rebuilt/'entry-state.bin').read_bytes(),(output/'entry-state.bin').read_bytes())
                if RETAIN is not None:shutil.copytree(rebuilt,RETAIN/mode/'portable-rebuild')

    def test_missing_entry_element_and_correct_return_wrong_store_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);plan,spec,capture,_=project(stage/'inputs','continuous');imported=stage/'request'
            import_session(plan,spec,capture,imported);request=imported/'request.json';document=json.loads(request.read_text())
            entries=imported/document['entries'];original_entries=entries.read_bytes();data=json.loads(original_entries)
            data[0]['fields'].pop();entries.write_text(json.dumps(data))
            with self.assertRaises(RequestError) as caught:prepare_request(request)
            self.assertEqual(caught.exception.stage,'reconstruction');entries.write_bytes(original_entries)
            bodies=imported/'support-bodies.c';original=bodies.read_text();faults=[]
            for mutation,replacement,error,raw,index in [
                ('missing_element_store',original.replace('state->values[i]=value+i;','if(i!=2)state->values[i]=value+i;'),0x20000+2,0,2),
                ('query_writes_tail',original.replace('return result;}','state->values[7]++;return result;}'),0x20000+1,36,1)]:
                try:
                    bodies.write_text(replacement);output=stage/mutation
                    with self.assertRaises(RequestError) as caught:export(args_for(request,output))
                    o=json.loads(str(caught.exception).removeprefix('target replay diverged: '))
                    self.assertEqual((o['error'],o['actual_calls'][index]['raw_bits']),(error,raw));self.assertFalse(output.exists())
                    faults.append({'mutation':mutation,'observations':o})
                finally:bodies.write_text(original)
            if RETAIN is not None:(RETAIN/'fault-verification.json').write_text(json.dumps(faults,indent=2)+'\n')


if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:LLVM=Path(sys.argv[1]);QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
