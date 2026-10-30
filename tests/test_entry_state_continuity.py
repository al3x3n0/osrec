"""Capture-scoped identities carry scalar state without per-call restoration."""
import copy
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import test_entry_state_effects as fixtures
from reconstruct_entry_state import reconstruction_header
from entry_state_continuity import validate_continuity

class ContinuityTests(unittest.TestCase):
    compile=fixtures.EffectTests.compile
    def session(self):
        first,post,plan=fixtures.EffectTests.fixture(self)
        for frame in (first,post):frame['objects'][0]['session_id']=100
        second=copy.deepcopy(post);last=copy.deepcopy(second)
        last['fields'][1]['data']='07000000'
        # Frame-local IDs can differ while capture-scoped identity remains.
        for frame in (second,last):
            frame['objects'][0]['id']=17;frame['roots'][0]['object_id']=17
            for field in frame['fields']:field['object_id']=17
        return [first,second],[post,last],[plan,copy.deepcopy(plan)]

    def test_one_restoration_shared_storage_and_transition_checks(self):
        frames,posts,plans=self.session()
        header=reconstruction_header(frames,plans,post_states=posts,continuous=True)
        self.assertEqual(header.count('static __typeof__'),1)
        self.compile(header,'''int main(void){
 if(!osrec_restore(0) || !osrec_entry_matches(0) || osrec_bound_current->value!=55) return 1;
 Obj *original=osrec_bound_current;
 original->value=4;if(!osrec_state_matches(0) || !osrec_entry_matches(1)) return 2;
 if(osrec_restore(1) || osrec_bound_current!=original || original->value!=4) return 3;
 original->value=5;if(osrec_entry_matches(1)) return 4;
 original->value=7;if(!osrec_state_matches(1) || osrec_bound_current!=original) return 5;
 return 0;}
''')

    def test_missing_identity_transitions_and_graph_changes_fail_closed(self):
        for change in ('missing','duplicate','identity','type','fields','transition','width'):
            with self.subTest(change=change):
                frames,posts,plans=self.session()
                if change=='missing':frames[0]['objects'][0].pop('session_id')
                elif change=='duplicate':frames[0]['objects'].append({'id':18,'session_id':100,'type':'Obj'})
                elif change=='identity':frames[1]['objects'][0]['session_id']=101
                elif change=='type':frames[1]['objects'][0]['type']='Other'
                elif change=='fields':frames[1]['fields'].pop()
                elif change=='transition':frames[1]['fields'][1]['data']='05000000'
                elif change=='width':frames[1]['fields'][1].update(bytes=2,data='0400')
                with self.assertRaises(ValueError):reconstruction_header(frames,plans,post_states=posts,continuous=True)
        frames,_,_=self.session()
        with self.assertRaises(ValueError):validate_continuity(frames,None)

    def test_pruned_footprint_cannot_be_silently_filled_from_later_state(self):
        first,post,plan=fixtures.EffectTests.fixture(self,omitted=True)
        for frame in (first,post):frame['objects'][0]['session_id']=100
        with self.assertRaisesRegex(ValueError,'complete field footprint'):
            reconstruction_header([first],[plan],post_states=[post],continuous=True)

if __name__=='__main__':
    if len(sys.argv)==2:fixtures.CLANG=sys.argv.pop()
    unittest.main()
