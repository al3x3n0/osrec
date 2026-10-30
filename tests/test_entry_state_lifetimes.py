import copy
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state_lifetimes import validate_lifetimes
class LifetimeTests(unittest.TestCase):
    def fixture(self):
        bundle={'format':'osrec-object-lifetimes-v1','events':[
            {'ordinal':0,'id':1,'kind':'existing','size':0},
            {'ordinal':1,'id':2,'kind':'allocate','size':16},
            {'ordinal':2,'id':2,'kind':'release','size':0},
            {'ordinal':3,'id':3,'kind':'allocate','size':16}]}
        frames=[{'lifetime_cursor':cursor,'objects':[{'session_id':identity}]} for cursor,identity in ((1,1),(2,2),(4,3))]
        return bundle,frames
    def test_snapshot_identities_at_their_event_cursor(self):
        bundle,frames=self.fixture();states=validate_lifetimes(bundle,frames)
        self.assertEqual(states,[frozenset(),frozenset({1}),frozenset({1,2}),frozenset({1}),frozenset({1,3})])
    def test_event_and_snapshot_corruption_rejected(self):
        for change in ('reuse','release','ordinal','address','size','kind','unborn','retired','cursor','bool','duplicate'):
            with self.subTest(change=change):
                bundle,frames=self.fixture()
                if change=='reuse':bundle['events'][3]['id']=2
                elif change=='release':bundle['events'][2]['id']=3
                elif change=='ordinal':bundle['events'][1]['ordinal']=3
                elif change=='address':bundle['events'][0]['address']=123
                elif change=='size':bundle['events'][1]['size']=0
                elif change=='kind':bundle['events'][1]['kind']='realloc'
                elif change=='unborn':frames[1]['lifetime_cursor']=1
                elif change=='retired':frames[1]['lifetime_cursor']=3
                elif change=='cursor':frames[0]['lifetime_cursor']=5
                elif change=='bool':frames[0]['objects'][0]['session_id']=True
                else:frames[0]['objects'].append(copy.deepcopy(frames[0]['objects'][0]))
                with self.assertRaises(ValueError):validate_lifetimes(bundle,frames)
if __name__=='__main__':unittest.main()
