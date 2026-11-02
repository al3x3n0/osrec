"""Portable enum and sizeof-count bounds, including target extent guards."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import test_entry_state_loops as fixture
from entry_state import capture_header
from entry_capture import import_session
from export_entry_state import export,RequestError
from freestanding_armv7 import run

RETAIN=None
PAINT='void paint(State *state,unsigned count,unsigned value){enum{BEGIN=0,CAPACITY=4+4};for(unsigned i=BEGIN;i<count && i<CAPACITY;++i)state->values[i]=value+i;}\n'
TOTAL='unsigned total(State *state){unsigned result=0;for(unsigned i=0;i<sizeof(state->values)/sizeof(state->values[0]);++i)result+=state->values[i];return result;}\n'
MAIN='''
int main(void){State object={{1,2,3,4,5,6,7,8}};osrec_capture_init(&session);
 osrec_capture_paint(&session,&object,0,50);if(osrec_capture_total(&session,&object)!=36)return 1;
 osrec_capture_paint(&session,&object,3,100);if(osrec_capture_total(&session,&object)!=333)return 2;
 osrec_capture_paint(&session,&object,UINT32_MAX,7);if(osrec_capture_total(&session,&object)!=84)return 3;
 osrec_capture_paint(&session,&object,8,0);if(osrec_capture_total(&session,&object)!=28)return 4;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
'''
EXPECTED=[0,36,0,333,0,84,0,28]


def project(stage,mode):return fixture.project(stage,mode,PAINT,TOTAL,MAIN)


class ConstantBoundTests(unittest.TestCase):
    def test_portable_enums_and_structural_array_counts(self):
        forms={
            'global_enum':('enum{BEGIN,CAPACITY=4+4};','', 'BEGIN','CAPACITY',0,8),
            'implicit_enum':('enum{BASE=7,CAPACITY};','enum{BEGIN=2};','BEGIN','CAPACITY',2,8),
            'dependent_enum':('enum{BASE=2,CAPACITY=BASE*4};','', '0','CAPACITY',0,8),
            'shadowed_enum':('enum{CAPACITY=1};','enum{CAPACITY=8};','0','CAPACITY',0,8),
            'shift_enum':('enum{CAPACITY=1<<3};','','0','CAPACITY',0,8),
            'sizeof_arrow':('','','0','sizeof(state->values)/sizeof(state->values[0])',0,8),
            'sizeof_dot':('','','0','sizeof((*state).values)/sizeof((*state).values[0])',0,8),
            'tightest_constant':('enum{CAPACITY=4};','','0','CAPACITY && i<sizeof(state->values)/sizeof(state->values[0])',0,4),
        }
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,(prefix,local,initial,limit,low,high) in forms.items():
                tree=fixture.parse(stage,prefix+'unsigned '+root+'(State *state){'+local+'unsigned result=0;for(unsigned i='+initial+';i<'+limit+';++i)result+=state->values[i];return result;}')
                plan=fixture.analyze(tree,root)
                with self.subTest(root=root):
                    self.assertFalse(plan['blockers'],plan['blockers'])
                    self.assertEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_state()->values['+str(i)+']' for i in range(low,high)})
                    proof=plan['memory_ranges'][0]['index_proof'];self.assertEqual((proof['initial'],proof['exclusive_limit']),(low,high))
                    self.assertTrue(proof['constant_bounds']['guards'])
                    header=capture_header([plan])
                    self.assertEqual('loop array extent differs' in header,root.startswith('sizeof_') or root=='tightest_constant')
            tree=fixture.parse(stage,PAINT+TOTAL);paint=fixture.analyze(tree,'paint')
            self.assertEqual(len(paint['preserved_entry_fields']),8)
            self.assertEqual(paint['memory_ranges'][0]['index_proof']['condition']['constant_guards'],1)
            self.assertFalse(paint['write_state_preservation']['guaranteed_exit_stores'])
            self.assertTrue(any(b['kind']=='range_limit' for b in fixture.analyze(tree,'total',4)['blockers']))

    def test_nonportable_or_unmatched_constants_remain_blocked(self):
        cases={
            'negative_enum':('enum{CAPACITY=-1};','CAPACITY'),
            'large_enum':('enum{CAPACITY=0xffffffffU};','CAPACITY'),
            'empty_enum':('enum{CAPACITY=0};','CAPACITY'),
            'outside_enum':('enum{CAPACITY=9};','CAPACITY'),
            'wrapped_enum':('enum{CAPACITY=(0xffffffffU+9U)};','CAPACITY'),
            'cast_enum':('enum{CAPACITY=(unsigned char)264};','CAPACITY'),
            'wide_enum':('enum{CAPACITY=8ULL};','CAPACITY'),
            'sizeof_enum':('enum{CAPACITY=sizeof(void *)};','CAPACITY'),
            'unknown_previous':('enum{BASE=(unsigned char)263,CAPACITY};','CAPACITY'),
            'const_variable':('const unsigned CAPACITY=8;','CAPACITY'),
            'nonzero_element':('','sizeof(state->values)/sizeof(state->values[1])'),
            'type_denominator':('','sizeof(state->values)/sizeof(unsigned)'),
            'pointer_numerator':('','sizeof(state)/sizeof(state->values[0])'),
            'cast_numerator':('','sizeof((unsigned *)state->values)/sizeof(state->values[0])'),
            'different_member':('typedef struct Other{unsigned other[8];}Other;','sizeof(state->values)/sizeof(((Other *)0)->other[0])'),
        }
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,(prefix,limit) in cases.items():
                tree=fixture.parse(stage,prefix+'unsigned '+root+'(State *state){unsigned result=0;for(unsigned i=0;i<'+limit+';++i)result+=state->values[i];return result;}')
                plan=fixture.analyze(tree,root)
                with self.subTest(root=root):
                    if root=='empty_enum':
                        # A zero bound gives a zero-trip loop; its may-reads stay inside the array.
                        self.assertFalse(plan['blockers'],plan['blockers'])
                        self.assertLessEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_state()->values[%d]'%n for n in range(8)});continue
                    self.assertTrue(any(b['kind'] in ('dynamic_extent','array_bounds') for b in plan['blockers']),plan['blockers'])
                    with self.assertRaises(ValueError):capture_header([plan])
            for body in (
                'for(unsigned i=0;i<sizeof(state->values)/sizeof(state->values[0]);++i){i=count;state->values[i]=1;}',
                'enum{CAPACITY=8};for(unsigned i=0;i<CAPACITY;++i)((unsigned *)state->values)[i]=1;',
                'enum{CAPACITY=8};for(unsigned i=0;i<CAPACITY && (i=count);++i)state->values[i]=1;',
            ):
                plan=fixture.analyze(fixture.parse(stage,'void bad(State *state,unsigned count){'+body+'}'),'bad')
                self.assertTrue(plan['blockers'])

    def test_native_capture_modes_relocation_and_portable_rebuild(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for mode in ('independent','continuous'):
                inputs=stage/(mode+'-inputs');plan,spec,capture,_=project(inputs,mode)
                if RETAIN is not None:shutil.copytree(inputs,RETAIN/'native-captures'/mode)
                imported=stage/(mode+'-request');import_session(plan,spec,capture,imported)
                for address in (0x40200000,0x40400000):
                    output=stage/(mode+hex(address));m=export(fixture.args_for(imported/'request.json',output,address));o=m['target_observations']
                    self.assertEqual([c['raw_bits'] for c in o['actual_calls']],EXPECTED)
                    self.assertEqual((o['abi_version'],o['states_restored'],o['states_verified']),(30,1 if mode=='continuous' else 8,8))
                    self.assertIn('loop array extent differs',(output/'sources/entry_reconstruction.h').read_text())
                    if RETAIN is not None:shutil.copytree(output,RETAIN/mode/hex(address))
                shutil.rmtree(inputs);shutil.rmtree(imported)
                rebuilt=stage/(mode+'-portable');export(fixture.args_for(output/'request.json',rebuilt,0x40400000))
                self.assertEqual((rebuilt/'entry-state.bin').read_bytes(),(output/'entry-state.bin').read_bytes())
                if RETAIN is not None:shutil.copytree(rebuilt,RETAIN/mode/'portable-rebuild')

    def test_changed_extent_is_rejected_at_capture_and_replay_compilation(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);inputs=stage/'inputs';plan,spec,capture,plans=project(inputs,'continuous')
            source=stage/'wrong-model.c';source.write_text(fixture.MODEL.replace('values[8]','values[16]')+'\n'+capture_header(plans))
            compiled=subprocess.run([str(fixture.LLVM/'clang'),'-std=c11','-I',str(fixture.ROOT/'include'),'-fsyntax-only',str(source)],capture_output=True,text=True,timeout=60)
            self.assertNotEqual(compiled.returncode,0);self.assertIn('loop array extent differs',compiled.stderr)
            # On this host sizeof(pointer)/sizeof(unsigned)==2. A ratio-only
            # assertion would accidentally accept a pointer for unsigned[2].
            tree=fixture.parse(stage,'unsigned short_count(State *state){unsigned result=0;for(unsigned i=0;i<sizeof(state->values)/sizeof(state->values[0]);++i)result+=state->values[i];return result;}')
            input_source=stage/'input.c';input_source.write_text(input_source.read_text().replace('unsigned values[8]','unsigned values[2]'))
            tree=fixture.load_ast(stage/'compile_commands.json',input_source)[0];small=fixture.analyze(tree,'short_count')
            source.write_text(fixture.MODEL.replace('unsigned values[8]','unsigned *values')+'\n'+capture_header([small]))
            pointer=subprocess.run([str(fixture.LLVM/'clang'),'-std=c11','-I',str(fixture.ROOT/'include'),'-fsyntax-only',str(source)],capture_output=True,text=True,timeout=60)
            self.assertNotEqual(pointer.returncode,0);self.assertIn('loop array extent differs',pointer.stderr)
            imported=stage/'request';import_session(plan,spec,capture,imported)
            request=imported/'request.json';document=json.loads(request.read_text());model=imported/document['model_header']
            model.write_text(model.read_text().replace('values[8]','values[16]'))
            output=stage/'bad-replay'
            with self.assertRaises(RequestError) as caught:export(fixture.args_for(request,output))
            self.assertEqual(caught.exception.stage,'build_or_verify')
            self.assertIn('loop array extent differs',str(caught.exception));self.assertFalse(output.exists())
            if RETAIN is not None:(RETAIN/'extent-fault-verification.json').write_text(json.dumps({'capture_model_16_rejected':True,'replay_model_16_rejected':True,'pointer_model_with_matching_size_ratio_rejected':True,'diagnostic':'loop array extent differs'},indent=2)+'\n')


if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:fixture.LLVM=Path(sys.argv[1]);fixture.QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
