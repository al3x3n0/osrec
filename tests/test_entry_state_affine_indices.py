"""Nonwrapping single-counter arithmetic through typed capture and replay."""
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
PAINT='void paint(State *state,unsigned count,unsigned value){for(unsigned i=0;i<count && i<4;++i)state->values[2U*i]=value+i;}\n'
TOTAL='unsigned total(State *state){unsigned result=0;for(unsigned i=0;i<4;++i)result+=state->values[6U-2U*i];return result;}\n'
MAIN='''
int main(void){State object={{1,2,3,4,5,6,7,8}};osrec_capture_init(&session);
 osrec_capture_paint(&session,&object,0,50);if(osrec_capture_total(&session,&object)!=16)return 1;
 osrec_capture_paint(&session,&object,2,100);if(osrec_capture_total(&session,&object)!=213)return 2;
 osrec_capture_paint(&session,&object,UINT32_MAX,7);if(osrec_capture_total(&session,&object)!=34)return 3;
 osrec_capture_paint(&session,&object,4,0);if(osrec_capture_total(&session,&object)!=6)return 4;
 if(object.values[1]!=2 || object.values[3]!=4 || object.values[5]!=6 || object.values[7]!=8)return 5;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
'''
EXPECTED=[0,16,0,213,0,34,0,6]


def project(stage,mode):return fixture.project(stage,mode,PAINT,TOTAL,MAIN)


class AffineIndexTests(unittest.TestCase):
    def test_affine_intervals_and_preserved_holes(self):
        positives={
            'odd':('unsigned',0,4,'2U*i+1U',(1,7),2,1),
            'even':('unsigned',0,4,'i*2U',(0,6),2,0),
            'reverse':('unsigned',0,4,'6U-2U*i',(0,6),-2,6),
            'offset':('unsigned',2,8,'i-2U',(0,5),1,-2),
            'correlated':('unsigned',0,8,'(i+i)-i',(0,7),1,0),
            'cancelled':('unsigned',0,8,'i-i+3U',(3,3),0,3),
            'signed_reverse':('int',0,8,'7 + -i',(0,7),-1,7),
            'large_safe_intermediate':('unsigned',0,8,'(i+2147483647U)-2147483647U',(0,7),1,0),
            'constant_factor':('unsigned',0,4,'i*(i-i+2U)',(0,6),2,0),
            'signed_nested':('int',0,4,'2*(i+1)-1',(1,7),2,1),
            'implicit_conversion':('int',0,4,'i*2U+1U',(1,7),2,1),
            'signed_negation':('int',0,8,'-(-i)',(0,7),1,0),
        }
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,(typ,initial,limit,index,bounds,a,b) in positives.items():
                source='unsigned '+root+'(State *state){unsigned result=0;for('+typ+' i='+str(initial)+';i<'+str(limit)+';++i)result+=state->values['+index+'];return result;}'
                plan=fixture.analyze(fixture.parse(stage,source),root)
                with self.subTest(root=root):
                    self.assertFalse(plan['blockers'],plan['blockers'])
                    self.assertEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_state()->values['+str(i)+']' for i in range(bounds[0],bounds[1]+1)})
                    proof=plan['memory_ranges'][0]['index_proof']['arithmetic']
                    self.assertEqual((proof['kind'],proof['coefficient'],proof['offset'],proof['bounds']),('affine_32bit',a,b,list(bounds)))
                    self.assertTrue(proof['steps']);self.assertEqual(proof['implicit_conversions'],'value_preserving_only')
                    for step in proof['steps']:
                        low,high=(-0x80000000,0x7fffffff) if step['type']=='int' else (0,0xffffffff)
                        self.assertLessEqual(low,step['bounds'][0]);self.assertLessEqual(step['bounds'][1],high)
                    capture_header([plan])
            tree=fixture.parse(stage,PAINT+TOTAL);paint=fixture.analyze(tree,'paint');total=fixture.analyze(tree,'total')
            self.assertFalse(paint['blockers']);self.assertFalse(total['blockers'])
            self.assertEqual((len(paint['entry_reads']),len(paint['preserved_entry_fields']),len(paint['state_writes'])),(0,7,7))
            self.assertEqual(len(total['entry_reads']),7)
            self.assertEqual(paint['memory_ranges'][0]['index_proof']['condition']['kind'],'conjunction')
            self.assertFalse(paint['write_state_preservation']['guaranteed_exit_stores'])
            # The interval contains holes. The expansion limit counts all seven
            # projected cells rather than the four actually visited cells.
            limited=fixture.analyze(tree,'paint',6)
            self.assertTrue(any(b['kind']=='range_limit' for b in limited['blockers']))

    def test_overflow_wrap_casts_and_unproved_expressions_remain_blocked(self):
        negatives={
            'unsigned_underflow':('unsigned','i-1U'),
            'wrapped_then_cancelled':('unsigned','(i+4294967295U)-4294967295U'),
            'signed_overflow_cancelled':('int','(i+2147483647)-2147483647'),
            'unsigned_product_wrap':('unsigned','(i*2147483648U)-(i*2147483648U)'),
            'signed_product_overflow':('int','(i*1073741824)-(i*1073741824)'),
            'unsigned_negation':('unsigned','-i'),
            'underflow_then_add':('unsigned','(i-1U)+1U'),
            'negative_implicit_conversion':('int','(i-1)+1U'),
            'negative_result':('int','i-8'),
            'outside':('unsigned','2U*i+1U'),
            'nonlinear':('unsigned','i*i'),
            'shift':('unsigned','i<<1'),
            'floating':('unsigned','(unsigned)(i*0.5)'),
            'explicit_cast':('unsigned','(unsigned)i+1U'),
            'narrow_cast':('unsigned','(unsigned char)(i*256U)'),
            'unrelated_argument':('unsigned','i+count'),
            'post_increment':('unsigned','i++'),
            'assignment':('unsigned','(i=count)'),
        }
        # Outside the affine certificate, the loop condition (a path fact in the body)
        # still bounds i; interval evaluation then proves or refutes the index exactly.
        evaluated={'division':('i/2U',range(4)),'wide_operation':('i+0ULL',range(8)),'expression_budget':('i'+'+0U'*40,range(8))}
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,(typ,index) in negatives.items():
                tree=fixture.parse(stage,'unsigned '+root+'(State *state,unsigned count){unsigned result=0;for('+typ+' i=0;i<8;++i)result+=state->values['+index+'];return result;}')
                plan=fixture.analyze(tree,root)
                with self.subTest(root=root):
                    expected='array_bounds' if root in ('negative_result','outside','nonlinear','shift','explicit_cast') else 'dynamic_extent'
                    self.assertTrue(any(b['kind']==expected for b in plan['blockers']),plan['blockers'])
                    with self.assertRaises(ValueError):capture_header([plan])
            for root,(index,cells) in evaluated.items():
                plan=fixture.analyze(fixture.parse(stage,'unsigned '+root+'(State *state,unsigned count){unsigned result=0;for(unsigned i=0;i<8;++i)result+=state->values['+index+'];return result;}'),root)
                with self.subTest(root=root):
                    self.assertFalse(plan['blockers'],plan['blockers'])
                    self.assertEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_state()->values[%d]'%n for n in cells})
            plan=fixture.analyze(fixture.parse(stage,'void nested(State *state){for(unsigned i=0;i<4;++i)for(unsigned j=0;j<2;++j)state->values[i+j]=1;}'),'nested')
            self.assertFalse(plan['blockers'],plan['blockers'])
            self.assertEqual({w['path'] for w in plan['state_writes']},{'osrec_argument_state()->values[%d]'%n for n in range(5)})
            for body in (
                'for(unsigned i=0;i<count;++i)state->values[2U*i]=1;',
                'for(unsigned i=0;i<4;++i)((unsigned *)state->values)[2U*i]=1;',
            ):
                plan=fixture.analyze(fixture.parse(stage,'void bad(State *state,unsigned count){'+body+'}'),'bad')
                self.assertTrue(plan['blockers'])
                with self.assertRaises(ValueError):capture_header([plan])

    def test_native_strided_capture_modes_relocation_and_portable_rebuild(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for mode in ('independent','continuous'):
                inputs=stage/(mode+'-inputs');plan,spec,capture,_=project(inputs,mode)
                if RETAIN is not None:shutil.copytree(inputs,RETAIN/'native-captures'/mode)
                imported=stage/(mode+'-request');import_session(plan,spec,capture,imported)
                entries=json.loads((imported/'entries.json').read_text())
                self.assertTrue(all(len(e['fields'])==7 for e in entries))
                for address in (0x40200000,0x40400000):
                    output=stage/(mode+hex(address));m=export(fixture.args_for(imported/'request.json',output,address));o=m['target_observations']
                    self.assertEqual([c['raw_bits'] for c in o['actual_calls']],EXPECTED)
                    self.assertEqual((o['abi_version'],o['states_restored'],o['states_verified']),(30,1 if mode=='continuous' else 8,8))
                    if RETAIN is not None:shutil.copytree(output,RETAIN/mode/hex(address))
                shutil.rmtree(inputs);shutil.rmtree(imported)
                rebuilt=stage/(mode+'-portable');export(fixture.args_for(output/'request.json',rebuilt,0x40400000))
                self.assertEqual((rebuilt/'entry-state.bin').read_bytes(),(output/'entry-state.bin').read_bytes())
                if RETAIN is not None:shutil.copytree(rebuilt,RETAIN/mode/'portable-rebuild')

    def test_missing_incoming_hole_and_correct_return_wrong_state_fail(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);plan,spec,capture,_=project(stage/'inputs','continuous');imported=stage/'request'
            import_session(plan,spec,capture,imported);request=imported/'request.json';document=json.loads(request.read_text())
            entries=imported/document['entries'];original_entries=entries.read_bytes();data=json.loads(original_entries)
            data[0]['fields']=[f for f in data[0]['fields'] if f['name']!='values[1]'];entries.write_text(json.dumps(data))
            with self.assertRaises(RequestError) as caught:prepare_request(request)
            self.assertEqual(caught.exception.stage,'reconstruction');entries.write_bytes(original_entries)
            bodies=imported/'support-bodies.c';original=bodies.read_text();faults=[]
            for mutation,replacement,error,raw,index in [
                ('missing_selected_store',original.replace('state->values[2U*i]=value+i;','if(i!=1)state->values[2U*i]=value+i;'),0x20000+2,0,2),
                ('query_writes_gap',original.replace('return result;}','state->values[1]++;return result;}'),0x20000+1,16,1)]:
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
