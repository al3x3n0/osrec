"""Per-dimension bounds through native capture and standalone matrix replay."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_entry_state_loops as host
from entry_state import Analyzer,capture_header
from entry_capture import import_session
from export_entry_state import export,prepare_request,RequestError

MODEL='#include <stdint.h>\ntypedef struct State {unsigned values[2][4];} State;\n'
PAINT='void paint(State *state,unsigned count,unsigned value){for(unsigned r=0;r<2;++r){for(unsigned c=0;c<4;++c){if(r*4+c<count)state->values[r][c]=value+r*4+c;}}}\n'
TOTAL='unsigned total(State *state){unsigned result=0;for(unsigned r=0;r<2;++r){for(unsigned c=0;c<4;++c)result+=state->values[r][c];}return result;}\n'
MAIN='''
int main(void){State object={{{1,2,3,4},{5,6,7,8}}};osrec_capture_init(&session);
 osrec_capture_paint(&session,&object,0,50);if(osrec_capture_total(&session,&object)!=36)return 1;
 osrec_capture_paint(&session,&object,3,100);if(osrec_capture_total(&session,&object)!=333)return 2;
 osrec_capture_paint(&session,&object,100,7);if(osrec_capture_total(&session,&object)!=84)return 3;
 osrec_capture_paint(&session,&object,0,UINT32_MAX);if(osrec_capture_total(&session,&object)!=84)return 4;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
'''
RETAIN=None

class MultidimensionalTests(unittest.TestCase):
    def parse(self,stage,source,model=MODEL):
        with patch.object(host,'MODEL',model):return host.parse(stage,source)

    def test_fixed_dimensions_masks_typedefs_and_three_dimensions(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            tree=self.parse(stage,'''unsigned element(State *state){return state->values[1][3];}
unsigned bounded(State *state,unsigned r,unsigned c){return state->values[r%2U][c&3U];}
unsigned cube(State *state){return state->cube[1][0][2];}
unsigned typedef_element(State *state){return state->rows[1][2];}
''','typedef unsigned Row[4];typedef struct State{unsigned values[2][4];unsigned cube[2][2][3];Row rows[2];}State;\n')
            expected={'element':{'osrec_argument_state()->values[1][3]'},
                'bounded':{'osrec_argument_state()->values['+str(r)+']['+str(c)+']' for r in range(2) for c in range(4)},
                'cube':{'osrec_argument_state()->cube[1][0][2]'},'typedef_element':{'osrec_argument_state()->rows[1][2]'}}
            for root,paths in expected.items():
                with self.subTest(root=root):
                    plan=host.analyze(tree,root)
                    self.assertFalse(plan['blockers'],plan['blockers']);self.assertEqual({r['path'] for r in plan['entry_reads']},paths)
                    capture_header([plan])

    def test_local_initializers_and_global_storage_keep_their_identity(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),'''unsigned shared[2][4];
unsigned private(State *state){unsigned local[2][4]={{state->values[0][1]},{0}};local[1][3]=7;return local[0][0]+local[1][3];}
unsigned global(void){return shared[1][3];}
unsigned persistent(void){static unsigned local[2][4];return local[1][3];}
unsigned pointer_array(State *state){unsigned (*p)[4]=state->values;return p[1][3];}
unsigned anonymous(State *state){struct {unsigned value;} local[2][4]={{{state->values[0][1]}}};return local[0][0].value;}
''')
            plan=host.analyze(tree,'private');self.assertFalse(plan['blockers'],plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_state()->values[0][1]'})
            self.assertFalse(plan['state_writes']);capture_header([plan])
            plan=Analyzer(tree).analyze('global');self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'global:shared[1][3]'})
            self.assertTrue(Analyzer(tree).analyze('persistent')['blockers'])
            self.assertTrue(host.analyze(tree,'pointer_array')['blockers'])
            plan=host.analyze(tree,'anonymous');self.assertFalse(plan['blockers'],plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_state()->values[0][1]'})

    def test_each_extent_unknown_indices_and_total_selection_limit(self):
        sources={
            'outer':'return state->values[2][0];','inner':'return state->values[0][4];',
            'negative':'return state->values[-1][0];','unknown':'return state->values[r][c];',
            'cast':'return ((unsigned (*)[4])state->values)[0][0];',
            'jump':'goto inside;for(unsigned r=0;r<2;++r){for(unsigned c=0;c<4;++c){inside:state->values[r][c]=1;}}return 0;'}
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for root,body in sources.items():
                with self.subTest(root=root):
                    tree=self.parse(stage,'unsigned '+root+'(State *state,unsigned r,unsigned c){'+body+'}')
                    plan=host.analyze(tree,root);self.assertTrue(plan['blockers'])
                    if root in ('outer','inner','negative'):self.assertIn('array_bounds',{b['kind'] for b in plan['blockers']})
                    with self.assertRaises(ValueError):capture_header([plan])
            tree=self.parse(stage,'unsigned bounded(State *state,unsigned r,unsigned c){return state->values[r%2U][c%4U];}')
            plan=host.analyze(tree,'bounded',4)
            self.assertIn('range_limit',{b['kind'] for b in plan['blockers']})
            self.assertFalse(plan['entry_reads'])
            self.assertFalse(host.analyze(tree,'bounded',8)['blockers'])

    def test_const_volatile_and_atomic_storage_remain_restricted(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for qualifier,blocker in (('const',None),('volatile','volatile_memory'),('_Atomic','architecture_or_ordering')):
                tree=self.parse(stage,'unsigned query(State *state){return state->values[1][3];}',
                    'typedef struct State{'+qualifier+' unsigned values[2][4];}State;')
                plan=host.analyze(tree,'query')
                if blocker:self.assertIn(blocker,{b['kind'] for b in plan['blockers']})
                else:
                    self.assertFalse(plan['blockers']);self.assertTrue(plan['entry_reads'][0]['storage_const'])
                with self.assertRaises(ValueError):capture_header([plan])

    def test_full_store_omission_and_partial_write_preservation(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),'''unsigned overwrite(State *state){state->values[1][2]=7;return state->values[1][2];}
unsigned partial(State *state,unsigned x){if(x)state->values[1][2]=7;return 0;}
''')
            plan=host.analyze(tree,'overwrite');self.assertFalse(plan['blockers'])
            self.assertFalse(plan['entry_reads']);self.assertFalse(plan['preserved_entry_fields'])
            self.assertEqual([r['path'] for r in plan['dominated_reads']],['osrec_argument_state()->values[1][2]'])
            plan=host.analyze(tree,'partial');self.assertFalse(plan['blockers'])
            self.assertEqual([r['path'] for r in plan['preserved_entry_fields']],['osrec_argument_state()->values[1][2]'])
            capture_header([plan])

    def test_native_capture_and_relocated_replay_with_fault_rejection(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for mode in ('independent','continuous'):
                with patch.object(host,'MODEL',MODEL):
                    plan,spec,capture,plans=host.project(stage/(mode+'-inputs'),mode,PAINT,TOTAL,MAIN)
                expected={'osrec_argument_state()->values['+str(r)+']['+str(c)+']' for r in range(2) for c in range(4)}
                self.assertEqual({r['path'] for r in plans[0]['preserved_entry_fields']},expected)
                imported=stage/(mode+'-request');import_session(plan,spec,capture,imported)
                request=imported/'request.json'
                for address in (0x40200000,0x40400000):
                    output=stage/(mode+hex(address));report=export(host.args_for(request,output,address));o=report['target_observations']
                    self.assertEqual([c['raw_bits'] for c in o['actual_calls']],[0,36,0,333,0,84,0,84])
                    self.assertEqual(o['states_verified'],8)
                    if RETAIN is not None:shutil.copytree(output,RETAIN/mode/hex(address))
                document=json.loads(request.read_text());entries=imported/document['entries'];original=entries.read_bytes()
                data=json.loads(original);data[0]['fields'].pop();entries.write_text(json.dumps(data))
                with self.assertRaises(RequestError):prepare_request(request)
                entries.write_bytes(original)
                bodies=imported/'support-bodies.c';original=bodies.read_text()
                bodies.write_text(original.replace('state->values[r][c]=value+r*4+c;','if(r!=0 || c!=2)state->values[r][c]=value+r*4+c;'))
                with self.assertRaises(RequestError) as caught:export(host.args_for(request,stage/(mode+'-wrong-store')))
                self.assertIn('target replay diverged',str(caught.exception))
                if RETAIN is not None:(RETAIN/mode/'fault.txt').write_text(str(caught.exception))

if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:host.LLVM=Path(sys.argv[1]);host.QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
