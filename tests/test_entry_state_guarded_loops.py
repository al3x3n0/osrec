"""Count-dependent loops: capacity guards, condition effects, capture and replay."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

import test_entry_state_loops as fixture
from entry_state import capture_header
from entry_capture import import_session
from export_entry_state import export,prepare_request,RequestError

RETAIN=None
PAINT='void paint(State *state,unsigned count,unsigned value){for(unsigned i=0;i<count && i<8;++i)state->values[i]=value+i;}\n'
TOTAL='unsigned total(State *state){unsigned result=0;for(unsigned i=0;i<8 && i<state->values[7];i++)result+=state->values[i];return result;}\n'
MAIN='''
int main(void){State object={{1,2,3,4,5,6,7,8}};osrec_capture_init(&session);
 osrec_capture_paint(&session,&object,0,50);if(osrec_capture_total(&session,&object)!=36)return 1;
 osrec_capture_paint(&session,&object,3,100);if(osrec_capture_total(&session,&object)!=333)return 2;
 osrec_capture_paint(&session,&object,UINT32_MAX,7);if(osrec_capture_total(&session,&object)!=84)return 3;
 osrec_capture_paint(&session,&object,8,0);if(osrec_capture_total(&session,&object)!=21)return 4;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
'''
EXPECTED=[0,36,0,333,0,84,0,21]


def project(stage,mode):return fixture.project(stage,mode,PAINT,TOTAL,MAIN)


class GuardedLoopTests(unittest.TestCase):
    def test_conjunctive_capacity_guards_and_condition_footprint(self):
        positives={
            'right':('i<count && i<8',8,2,1),
            'left':('i<8 && i<count',8,2,1),
            'nested':('(i<count && i<8) && count!=0',8,3,1),
            'tighter':('i<8 && i<4 && i<count',4,3,2),
            'object_limit':('i<state->values[7] && i<8',8,2,1),
            'disjunction_inside_conjunct':('i<8 && (i<count || count==0)',8,2,1),
            'condition_effect':('state->values[7]++ && i<8 && i<count',8,3,1),
        }
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,(condition,limit,terms,literals) in positives.items():
                tree=fixture.parse(stage,'unsigned '+root+'(State *state,unsigned count){unsigned result=0;for(unsigned i=0;'+condition+';++i)result+=state->values[i];return result;}')
                plan=fixture.analyze(tree,root)
                with self.subTest(root=root):
                    self.assertFalse(plan['blockers'],plan['blockers'])
                    self.assertEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_state()->values['+str(i)+']' for i in range(limit)})
                    proof=next(r['index_proof'] for r in plan['memory_ranges'] if 'index_proof' in r)
                    self.assertEqual(proof['exclusive_limit'],limit)
                    self.assertEqual(proof['condition'],{'kind':'conjunction','terms':terms,'literal_guards':literals,'counter_immutable':True,'zero_trip_possible':True})
                    self.assertEqual(bool(plan['state_writes']),root=='condition_effect')
                    self.assertFalse(plan['write_state_preservation']['guaranteed_exit_stores'])
                    capture_header([plan])
            # A dynamic argument remains unconstrained when no capacity guard
            # is present; the literal guard never supplies pointer storage.
            tree=fixture.parse(stage,PAINT+TOTAL)
            paint=fixture.analyze(tree,'paint');total=fixture.analyze(tree,'total')
            self.assertEqual(len(paint['preserved_entry_fields']),8)
            self.assertFalse(paint['entry_reads'])
            self.assertEqual(len({r['path'] for r in total['entry_reads']}),8)
            limited=fixture.analyze(tree,'paint',4)
            self.assertTrue(any(b['kind']=='range_limit' for b in limited['blockers']))

    def test_bypassed_or_invalidated_guards_remain_blocked(self):
        conditions={
            'unbounded':'i<count',
            'or_bypass':'i<8 || i<count',
            'nested_or_bypass':'(i<8 && count) || i<count',
            'conditional':'count ? i<8 : i<count',
            'comma':'(i<8,i<count)',
            'bitwise_and':'(i<8) & (i<count)',
            'assign_after':'i<8 && (i=count)',
            'assign_before':'(i=count) && i<8',
            'increment_after':'i<8 && ++i',
            'increment_before':'i++ && i<8',
            'compound':'i<8 && (i+=count)',
            'escape_after':'i<8 && touch(&i)',
            'escape_before':'touch(&i) && i<8',
            'different_counter':'j<8 && i<count',
            'cast_guard':'(unsigned char)i<8 && i<count',
            'cast_limit':'i<(unsigned char)264 && i<count',
            'wide_limit':'i<8ULL && i<count',
            'outside':'i<count && i<9',
            'loose_limit':'i<count && i<16',
            'empty':'i<count && i<0',
            'negated':'!(i>=8) && i<count',
            'unevaluated':'sizeof(i<8) && i<count',
            'overflow_limit':'i<0xffffffffU && i<count',
        }
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,condition in conditions.items():
                tree=fixture.parse(stage,'int touch(unsigned *p);void '+root+'(State *state,unsigned count){unsigned j=0;for(unsigned i=0;'+condition+';++i)state->values[i]=1;}')
                plan=fixture.analyze(tree,root)
                with self.subTest(root=root):
                    if root in ('wide_limit','negated','empty'):
                        # The conjunction holds in the body, and these conjuncts give i<8 (or never hold).
                        self.assertFalse(plan['blockers'],plan['blockers'])
                        self.assertLessEqual({w['path'] for w in plan['state_writes']},{'osrec_argument_state()->values[%d]'%n for n in range(8)});continue
                    self.assertTrue(plan['blockers'])
                    self.assertTrue(any(b['kind'] in ('dynamic_extent','array_bounds') for b in plan['blockers']))
                    with self.assertRaises(ValueError):capture_header([plan])
            for body in ('i=count;state->values[i]=1;','touch(&i);state->values[i]=1;',
                         '((unsigned *)state->values)[i]=1;'):
                tree=fixture.parse(stage,'int touch(unsigned *p);void bad(State *state,unsigned count){for(unsigned i=0;i<count && i<8;++i){'+body+'}}')
                self.assertTrue(fixture.analyze(tree,'bad')['blockers'])
            # Guarding a body access does not prove accesses in the condition,
            # which can execute before the guard or after the final increment.
            tree=fixture.parse(stage,'void bad(State *state,unsigned count){for(unsigned i=0;state->values[i] && i<8 && i<count;++i)state->values[i]=1;}')
            self.assertTrue(any(b['kind']=='dynamic_extent' for b in fixture.analyze(tree,'bad')['blockers']))
            # A condition access to the right of its own `&&` bound is a dominated path fact.
            tree=fixture.parse(stage,'void good(State *state,unsigned count){for(unsigned i=0;i<8 && state->values[i] && i<count;++i)state->values[i]=1;}')
            self.assertFalse(fixture.analyze(tree,'good')['blockers'])

    def test_native_guarded_capture_modes_relocation_and_portable_rebuild(self):
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

    def test_missing_preserved_element_and_correct_return_wrong_state_fail(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);plan,spec,capture,_=project(stage/'inputs','continuous');imported=stage/'request'
            import_session(plan,spec,capture,imported);request=imported/'request.json';document=json.loads(request.read_text())
            entries=imported/document['entries'];original_entries=entries.read_bytes();data=json.loads(original_entries)
            data[0]['fields'].pop();entries.write_text(json.dumps(data))
            with self.assertRaises(RequestError) as caught:prepare_request(request)
            self.assertEqual(caught.exception.stage,'reconstruction');entries.write_bytes(original_entries)
            bodies=imported/'support-bodies.c';original=bodies.read_text();faults=[]
            for mutation,replacement,error,raw,index in [
                ('skipped_tail_store',original.replace('i<count && i<8','i<count && i<7'),0x20000+4,0,4),
                ('query_writes_tail',original.replace('return result;}','state->values[7]++;return result;}'),0x20000+1,36,1)]:
                # The first mutation narrows the guard: it avoids undefined
                # out-of-bounds C while testing an omitted final element store.
                try:
                    bodies.write_text(replacement);output=stage/mutation
                    with self.assertRaises(RequestError) as caught:export(fixture.args_for(request,output))
                    o=json.loads(str(caught.exception).removeprefix('target replay diverged: '))
                    self.assertEqual((o['error'],o['actual_calls'][index]['raw_bits']),(error,raw));self.assertFalse(output.exists())
                    faults.append({'mutation':mutation,'observations':o})
                finally:bodies.write_text(original)
            if RETAIN is not None:(RETAIN/'fault-verification.json').write_text(json.dumps(faults,indent=2)+'\n')

    def test_condition_writes_including_failed_guard_are_replayed(self):
        paint=PAINT.replace('i<count && i<8','state->values[7]++ && i<8 && i<count')
        main=MAIN.replace('!=36','!=37').replace('!=333','!=338').replace('!=84','!=85').replace('!=21','!=29')
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);inputs=stage/'inputs'
            plan,spec,capture,plans=fixture.project(inputs,'continuous',paint,TOTAL,main)
            self.assertEqual({r['path'] for r in plans[0]['entry_reads']},{'osrec_argument_state()->values[7]'})
            self.assertEqual(len(plans[0]['preserved_entry_fields']),7)
            if RETAIN is not None:shutil.copytree(inputs,RETAIN/'native-captures/condition-effects')
            imported=stage/'request';import_session(plan,spec,capture,imported)
            entries=json.loads((imported/'entries.json').read_text())
            self.assertEqual(len(entries[0]['fields']),8)
            output=stage/'image';m=export(fixture.args_for(imported/'request.json',output));o=m['target_observations']
            self.assertEqual([c['raw_bits'] for c in o['actual_calls']],[0,37,0,338,0,85,0,29])
            self.assertEqual((o['states_restored'],o['states_verified'],o['entry_states_checked']),(1,8,8))
            if RETAIN is not None:shutil.copytree(output,RETAIN/'condition-effects/0x40200000')


if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:fixture.LLVM=Path(sys.argv[1]);fixture.QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
