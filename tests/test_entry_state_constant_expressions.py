"""Direct portable constant-expression initializers and loop capacity guards."""
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
PAINT='void paint(State *state,unsigned count,unsigned value){for(unsigned i=(0U&7U);i<count && i<((1U<<4)/2U);++i)state->values[i]=value+i;}\n'
TOTAL='unsigned total(State *state){unsigned result=0;for(unsigned i=(18U%3U);i<((~0U>>29)+1U);++i)result+=state->values[i];return result;}\n'
EXPECTED=operators.EXPECTED


def project(stage,mode):return fixture.project(stage,mode,PAINT,TOTAL,operators.MAIN)


class ConstantExpressionTests(unittest.TestCase):
    def test_direct_expressions_and_enum_dependencies(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,expression in operators.POSITIVE.items():
                tree=fixture.parse(stage,'unsigned '+root+'(State *state){unsigned result=0;for(unsigned i=(2U-2U);i<('+expression+');++i)result+=state->values[i];return result;}')
                plan=fixture.analyze(tree,root)
                with self.subTest(root=root):
                    self.assertFalse(plan['blockers'],plan['blockers'])
                    self.assertEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_state()->values['+str(i)+']' for i in range(8)})
                    proof=plan['memory_ranges'][0]['index_proof']['constant_bounds']
                    self.assertEqual((proof['initial']['kind'],proof['initial']['value']),('integer_constant_expression',0))
                    self.assertEqual((proof['guards'][0]['kind'],proof['guards'][0]['value']),('integer_constant_expression',8))
                    capture_header([plan])
            for root,prefix,local,limit,size in [
                ('enum_arithmetic','enum{BASE=4};','','BASE+4',8),
                ('shadowed','enum{BASE=1};','enum{BASE=4};','BASE+4',8),
                ('conjunction','','','(1U<<3) && i<(2U+2U)',4),
                ('macro','','#define CAPACITY ((1U<<4)/2U)\n','CAPACITY',8),
            ]:
                # Macro directives must start on a separate source line.
                source=prefix+'unsigned '+root+'(State *state){\n'+local+'unsigned result=0;for(unsigned i=0;i<'+limit+';++i)result+=state->values[i];return result;}\n'
                plan=fixture.analyze(fixture.parse(stage,source),root)
                with self.subTest(root=root):
                    self.assertFalse(plan['blockers'],plan['blockers'])
                    self.assertEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_state()->values['+str(i)+']' for i in range(size)})
            for initial,low in [('1U<<1',2),('(-17/2)+9',1)]:
                tree=fixture.parse(stage,'unsigned offset(State *state){unsigned result=0;for(unsigned i=('+initial+');i<(1U<<3);++i)result+=state->values[i];return result;}')
                plan=fixture.analyze(tree,'offset');self.assertFalse(plan['blockers'],plan['blockers'])
                self.assertEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_state()->values['+str(i)+']' for i in range(low,8)})
            tree=fixture.parse(stage,PAINT+TOTAL);paint=fixture.analyze(tree,'paint')
            self.assertEqual((len(paint['entry_reads']),len(paint['preserved_entry_fields'])),(0,8))
            self.assertFalse(paint['write_state_preservation']['guaranteed_exit_stores'])
            self.assertTrue(any(b['kind']=='range_limit' for b in fixture.analyze(tree,'paint',4)['blockers']))

    def test_nonconstant_side_effecting_and_invalid_expressions_remain_blocked(self):
        outcomes=[]
        # Bounds that are not portable constant expressions get no loop certificate, but the
        # loop condition still bounds i where the interval evaluator can decide its value.
        evaluated={'negative_bit_and':8,'wide_shift':8,'explicit_cast':8,'expression_budget':8,'zero_bound':None,
            'cancelled_argument':8,'conditional_argument':8,'comma':8,'function_call':8}
        expressions={**{k:v for k,v in operators.NEGATIVE.items() if k not in evaluated},
            'runtime_argument':'count+0U',
            'assignment':'(count=8U)','increment':'count++',
            'const_variable':'CAPACITY+0U',
            'negative_implicit_conversion':'(-1)+9U',
        }
        values={**operators.NEGATIVE,'cancelled_argument':'count*0U+8U','conditional_argument':'count?8U:8U','comma':'(count,8U)','function_call':'capacity()'}
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,size in evaluated.items():
                with self.subTest(root=root):
                    tree=fixture.parse(stage,'const unsigned CAPACITY=8;unsigned capacity(void){return 8;}unsigned '+root+'(State *state,unsigned count){unsigned result=0;for(unsigned i=0;i<('+values[root]+');++i)result+=state->values[i];return result;}')
                    plan=fixture.analyze(tree,root);self.assertFalse(plan['blockers'],plan['blockers'])
                    reads={r['path'] for r in plan['entry_reads']};cells={'osrec_argument_state()->values[%d]'%n for n in range(8)}
                    # A zero-trip loop may still be over-approximated by a may-read.
                    self.assertEqual(reads,cells) if size==8 else self.assertLessEqual(reads,cells)
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,expression in expressions.items():
                with self.subTest(root=root):
                    try:tree=fixture.parse(stage,'const unsigned CAPACITY=8;unsigned capacity(void){return 8;}unsigned '+root+'(State *state,unsigned count){unsigned result=0;for(unsigned i=0;i<('+expression+');++i)result+=state->values[i];return result;}')
                    except ValueError as error:
                        self.assertIn('configured Clang parse failed:',str(error));outcomes.append({'case':root,'stage':'clang_frontend'});continue
                    plan=fixture.analyze(tree,root)
                    expected='array_bounds' if root=='outside_array' else 'dynamic_extent'
                    self.assertTrue(any(b['kind']==expected for b in plan['blockers']),plan['blockers'])
                    with self.assertRaises(ValueError):capture_header([plan])
                    outcomes.append({'case':root,'stage':'configured_ast_analysis','blocker':expected})
            # Wrapped starts are defined unsigned arithmetic (both are 0), and i+0U cannot wrap:
            # no loop certificate, but the condition fact proves the writes exactly.
            for body in (
                'for(unsigned i=(0xffffffffU+1U);i<(1U<<3);++i)state->values[i]=1;',
                'for(unsigned i=(unsigned char)256;i<(1U<<3);++i)state->values[i]=1;',
                'for(unsigned i=0;(i+0U)<8U;++i)state->values[i]=1;',
            ):
                plan=fixture.analyze(fixture.parse(stage,'void good(State *state){'+body+'}'),'good')
                self.assertFalse(plan['blockers'],plan['blockers'])
                self.assertEqual({w['path'] for w in plan['state_writes']},{'osrec_argument_state()->values[%d]'%n for n in range(8)})
            # A condition false on entry: the body never runs and writes nothing.
            plan=fixture.analyze(fixture.parse(stage,'void never(State *state){for(unsigned i=(1U<<3);i<(1U<<3);++i)state->values[i]=1;}'),'never')
            self.assertFalse(plan['blockers'],plan['blockers']);self.assertFalse(plan['state_writes'])
            for body in (
                'for(unsigned i=0;i<(1U<<3);++i){i=count;state->values[i]=1;}',
                'for(unsigned i=0;i<(1U<<3);++i)((unsigned *)state->values)[i]=1;',
                'for(unsigned i=0;i<count || i<(1U<<3);++i)state->values[i]=1;',
            ):
                plan=fixture.analyze(fixture.parse(stage,'void bad(State *state,unsigned count){'+body+'}'),'bad')
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
                ('wrong_capacity',original.replace('(1U<<4)/2U','(1U<<4)/4U'),0x20000+4,0,4),
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
