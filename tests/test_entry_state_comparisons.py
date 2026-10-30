"""Inclusive and reversed capacity comparisons through capture and replay."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import test_entry_state_loops as fixture
import test_entry_state_enum_operators as operators
from entry_state import capture_header
from entry_capture import import_session
from export_entry_state import export,RequestError
RETAIN=None
PAINT='void paint(State *state,unsigned count,unsigned value){for(unsigned i=(2U-2U);count>i && ((1U<<3)-1U)>=i;++i)state->values[i]=value+i;}\n'
TOTAL='unsigned total(State *state){unsigned result=0;for(unsigned i=(18U%3U);7>=i;++i)result+=state->values[i];return result;}\n'
EXPECTED=operators.EXPECTED

def project(stage,mode):return fixture.project(stage,mode,PAINT,TOTAL,operators.MAIN)

class ComparisonTests(unittest.TestCase):
    def test_comparison_normalization_and_constant_bounds(self):
        cases=[('i<=7',8),('8>i',8),('7>=i',8),('i<=0',1),('0>=i',1),
               ('i<=((1U<<3)-1U)',8),('((1U<<3)-1U)>=i',8),
               ('CAP>=i',8),('i<=CAP',8),('sizeof(state->values)/sizeof(state->values[0])>i',8),
               ('count>i && 7>=i',8),('i<=7 && 3>=i',4)]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for condition,size in cases:
                with self.subTest(condition=condition):
                    tree=fixture.parse(stage,'enum{CAP=7};unsigned sum(State *state,unsigned count){unsigned result=0;for(unsigned i=0;'+condition+';++i)result+=state->values[i];return result;}')
                    plan=fixture.analyze(tree,'sum');self.assertFalse(plan['blockers'],plan['blockers'])
                    self.assertEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_state()->values['+str(i)+']' for i in range(size)})
                    proof=plan['memory_ranges'][0]['index_proof'];self.assertEqual(proof['exclusive_limit'],size)
                    self.assertTrue(proof['comparison_guards']);capture_header([plan])
            for typ in ('int','unsigned'):
                tree=fixture.parse(stage,'unsigned edge(State *state){unsigned result=0;for('+typ+' i=2147483645;i<=2147483646;++i)result+=state->values[2147483646-i];return result;}')
                plan=fixture.analyze(tree,'edge');self.assertFalse(plan['blockers'],plan['blockers'])
                self.assertEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_state()->values[0]','osrec_argument_state()->values[1]'})
                self.assertEqual(plan['memory_ranges'][0]['index_proof']['exclusive_limit'],2147483647)
            tree=fixture.parse(stage,PAINT+TOTAL);paint=fixture.analyze(tree,'paint')
            self.assertEqual((len(paint['entry_reads']),len(paint['preserved_entry_fields'])),(0,8))
            self.assertFalse(paint['write_state_preservation']['guaranteed_exit_stores'])
            self.assertTrue(any(b['kind']=='range_limit' for b in fixture.analyze(tree,'paint',4)['blockers']))

    def test_overflow_dynamic_and_unsafe_comparisons_remain_blocked(self):
        cases={
            'signed_max':'i<=2147483647','reversed_signed_max':'2147483647>=i',
            'unsigned_max':'i<=0xffffffffU','wide':'8ULL>i','cast':'(unsigned char)8>i',
            'negative':'i<=-1','dynamic':'count>=i','bypass':'count>i || 7>=i',
            'not_equal':'i!=8','lower_bound':'i>=7','indirect_counter':'7>=(i+0U)',
            'outside':'8>=i','zero_trip':'0>i','runtime_bound':'(count*0U+7U)>=i',
        }
        outcomes=[]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for case,condition in cases.items():
                with self.subTest(case=case):
                    tree=fixture.parse(stage,'void bad(State *state,unsigned count){for(unsigned i=0;'+condition+';++i)state->values[i]=1;}')
                    plan=fixture.analyze(tree,'bad');self.assertTrue(plan['blockers'])
                    self.assertTrue(any(b['kind']==('array_bounds' if case=='outside' else 'dynamic_extent') for b in plan['blockers']),plan['blockers'])
                    with self.assertRaises(ValueError):capture_header([plan])
                    outcomes.append({'case':case,'stage':'configured_ast_analysis','blockers':sorted({b['kind'] for b in plan['blockers']})})
            for body in [
                'for(unsigned i=0;7>=i;++i){i=count;state->values[i]=1;}',
                'for(unsigned i=0;7>=i;++i){touch(&i);state->values[i]=1;}',
                'for(unsigned i=7;i>=0;--i)state->values[i]=1;',
                'for(unsigned i=0;(i=count)<=7;++i)state->values[i]=1;',
            ]:
                plan=fixture.analyze(fixture.parse(stage,'void touch(unsigned *p);void bad(State *state,unsigned count){'+body+'}'),'bad')
                self.assertTrue(plan['blockers'])
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
                ('wrong_capacity',original.replace('((1U<<3)-1U)>=i','3U>=i'),0x20000+4,0,4),
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
