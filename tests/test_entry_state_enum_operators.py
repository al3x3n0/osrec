"""Portable constant operators feeding bounded-loop capture and replay."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

import test_entry_state_loops as fixture
from entry_state import capture_header
from entry_capture import import_session
from export_entry_state import export,RequestError

RETAIN=None
PAINT='void paint(State *state,unsigned count,unsigned value){enum{BEGIN=0U&7U,CAPACITY=(1U<<4)/2U};for(unsigned i=BEGIN;i<count && i<CAPACITY;++i)state->values[i]=value+i;}\n'
TOTAL='unsigned total(State *state){enum{BEGIN=18U%3U,CAPACITY=(~0U>>29)+1U};unsigned result=0;for(unsigned i=BEGIN;i<CAPACITY;++i)result+=state->values[i];return result;}\n'
MAIN='''
int main(void){State object={{1,2,3,4,5,6,7,8}};osrec_capture_init(&session);
 osrec_capture_paint(&session,&object,0,50);if(osrec_capture_total(&session,&object)!=36)return 1;
 osrec_capture_paint(&session,&object,3,100);if(osrec_capture_total(&session,&object)!=333)return 2;
 osrec_capture_paint(&session,&object,UINT32_MAX,7);if(osrec_capture_total(&session,&object)!=84)return 3;
 osrec_capture_paint(&session,&object,8,0);if(osrec_capture_total(&session,&object)!=28)return 4;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
'''
EXPECTED=[0,36,0,333,0,84,0,28]
POSITIVE={
    'signed_left':'1<<3','unsigned_left':'1U<<3','signed_right':'64>>3','unsigned_right':'0x80000000U>>28',
    'high_unsigned_bit':'(1U<<31)>>28','bit_and':'0xffU&8U','bit_or':'(4U|8U)-4U','bit_xor':'12U^4U',
    'unsigned_complement':'(~0U>>29)+1U','division':'16U/2U','remainder':'18U%10U',
    'negative_dividend':'(-17/2)+16','negative_remainder':'(-17%3)+10','negative_divisor':'(17/-2)+16',
    'both_negative':'-17/-2','minimum_dividend':'(((-2147483647-1)/1)+2147483647)+9',
}
NEGATIVE={
    'unsigned_shift_wrap':'(0x80000000U<<1)+8U',
    'negative_right_shift':'(-4>>1)+10','negative_left_shift':'(-1<<3)+16',
    'signed_sign_bit':'((1<<31)>>31)+9',
    'negative_bit_and':'-1&8','negative_bit_or':'(-1|1)+9','negative_bit_xor':'(-1^7)+16',
    'signed_complement':'~(-9)',
    'zero_divisor':'16U/0U','zero_modulus':'16U%0U',
    'minimum_division_overflow':'(-2147483647-1)/-1',
    'minimum_remainder_overflow':'((-2147483647-1)%-1)+8',
    'negative_shift_count':'(16U>>-1)+8U','width_shift_count':'(1U<<32)+8U',
    'wide_shift':'1ULL<<3','explicit_cast':'(unsigned char)(1U<<3)',
    'wrapped_mask':'(0xffffffffU+1U)|8U','expression_budget':'0U+'*40+'8U',
    'zero_bound':'8U&0U','large_bound':'1U<<31','outside_array':'1U<<4',
}


def project(stage,mode):return fixture.project(stage,mode,PAINT,TOTAL,MAIN)


class EnumOperatorTests(unittest.TestCase):
    def test_operator_constants_and_c99_negative_division(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,expression in POSITIVE.items():
                tree=fixture.parse(stage,'unsigned '+root+'(State *state){enum{CAPACITY='+expression+'};unsigned result=0;for(unsigned i=0;i<CAPACITY;++i)result+=state->values[i];return result;}')
                plan=fixture.analyze(tree,root)
                with self.subTest(root=root):
                    self.assertFalse(plan['blockers'],plan['blockers'])
                    self.assertEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_state()->values['+str(i)+']' for i in range(8)})
                    proof=plan['memory_ranges'][0]['index_proof']
                    self.assertEqual(proof['constant_bounds']['guards'][0]['value'],8)
                    capture_header([plan])
            tree=fixture.parse(stage,'enum{BASE=(1U<<3)-1U,CAPACITY};unsigned chained(State *state){unsigned result=0;for(unsigned i=0;i<CAPACITY;++i)result+=state->values[i];return result;}')
            self.assertFalse(fixture.analyze(tree,'chained')['blockers'])
            tree=fixture.parse(stage,PAINT+TOTAL);paint=fixture.analyze(tree,'paint')
            self.assertEqual((len(paint['entry_reads']),len(paint['preserved_entry_fields'])),(0,8))
            self.assertFalse(paint['write_state_preservation']['guaranteed_exit_stores'])
            self.assertTrue(any(b['kind']=='range_limit' for b in fixture.analyze(tree,'paint',4)['blockers']))

    def test_invalid_or_nonportable_constants_reject_at_frontend_or_analysis(self):
        outcomes=[]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,expression in NEGATIVE.items():
                with self.subTest(root=root):
                    try:tree=fixture.parse(stage,'unsigned '+root+'(State *state){enum{CAPACITY='+expression+'};unsigned result=0;for(unsigned i=0;i<CAPACITY;++i)result+=state->values[i];return result;}')
                    except ValueError as error:
                        self.assertIn('configured Clang parse failed:',str(error))
                        self.assertIn('error:',str(error))
                        outcomes.append({'case':root,'stage':'clang_frontend'})
                        continue
                    plan=fixture.analyze(tree,root)
                    if root=='zero_bound':
                        # CAPACITY is 0: a zero-trip loop whose may-reads stay inside the array.
                        self.assertFalse(plan['blockers'],plan['blockers'])
                        self.assertLessEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_state()->values[%d]'%n for n in range(8)})
                        outcomes.append({'case':root,'stage':'configured_ast_analysis','blocker':None});continue
                    expected='array_bounds' if root=='outside_array' else 'dynamic_extent'
                    self.assertTrue(any(b['kind']==expected for b in plan['blockers']),plan['blockers'])
                    with self.assertRaises(ValueError):capture_header([plan])
                    outcomes.append({'case':root,'stage':'configured_ast_analysis','blocker':expected})
            for source in (
                'void bad(State *state,unsigned count){enum{CAPACITY=1U<<3};for(unsigned i=0;i<CAPACITY;++i){i=count;state->values[i]=1;}}',
                'void bad(State *state,unsigned count){enum{CAPACITY=1U<<3};for(unsigned i=0;i<count || i<CAPACITY;++i)state->values[i]=1;}',
            ):
                self.assertTrue(fixture.analyze(fixture.parse(stage,source),'bad')['blockers'])
        if RETAIN is not None:(RETAIN/'negative-admission.json').write_text(json.dumps(outcomes,indent=2)+'\n')

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
                    if RETAIN is not None:shutil.copytree(output,RETAIN/mode/hex(address))
                shutil.rmtree(inputs);shutil.rmtree(imported)
                rebuilt=stage/(mode+'-portable');export(fixture.args_for(output/'request.json',rebuilt,0x40400000))
                self.assertEqual((rebuilt/'entry-state.bin').read_bytes(),(output/'entry-state.bin').read_bytes())
                if RETAIN is not None:shutil.copytree(rebuilt,RETAIN/mode/'portable-rebuild')

    def test_correct_return_wrong_capacity_or_state_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);plan,spec,capture,_=project(stage/'inputs','continuous');imported=stage/'request'
            import_session(plan,spec,capture,imported);request=imported/'request.json';bodies=imported/'support-bodies.c';original=bodies.read_text();faults=[]
            for mutation,replacement,error,raw,index in [
                ('wrong_capacity',original.replace('CAPACITY=(1U<<4)/2U','CAPACITY=(1U<<4)/4U'),0x20000+4,0,4),
                ('query_writes_tail',original.replace('return result;}','state->values[7]++;return result;}'),0x20000+1,36,1)]:
                try:
                    bodies.write_text(replacement);output=stage/mutation
                    with self.assertRaises(RequestError) as caught:export(fixture.args_for(request,output))
                    o=json.loads(str(caught.exception).removeprefix('target replay diverged: '))
                    self.assertEqual((o['error'],o['actual_calls'][index]['raw_bits']),(error,raw));self.assertFalse(output.exists())
                    faults.append({'mutation':mutation,'observations':o})
                finally:bodies.write_text(original)
            if RETAIN is not None:(RETAIN/'fault-verification.json').write_text(json.dumps(faults,indent=2)+'\n')


if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:fixture.LLVM=Path(sys.argv[1]);fixture.QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
