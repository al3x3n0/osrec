"""Input mapping and domain shaping for KLEE state-discovery validation."""
import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from klee_state_validation import set_input,get_input,shaped,shaping_of,ktest_inputs,domains_of,kept_outputs

STATE={'scalars':{'files.next_fd':3,'files.fdtab.open_fds[0]':23},'pool':[{'f_count':3,'f_pos':0},{'f_count':1,'f_pos':5}],
       'file_data':{'size':8,'bytes':'00'*64}}
OBJECTS=[{'object_id':1,'bytes':'00'*8,'size':8}]

class ValidationTests(unittest.TestCase):
    def test_inputs_reach_scalars_pool_members_file_and_user_bytes(self):
        import copy
        state,objects=copy.deepcopy(STATE),copy.deepcopy(OBJECTS)
        set_input(state,objects,'files.fdtab.open_fds[0]',7);set_input(state,objects,'file_pool[1].f_pos',9)
        set_input(state,objects,'file_data.size',2);set_input(state,objects,'user_object.1',b'abcdefgh')
        self.assertEqual(state['scalars']['files.fdtab.open_fds[0]'],7);self.assertEqual(state['pool'][1]['f_pos'],9)
        self.assertEqual(state['file_data']['size'],2);self.assertEqual(get_input(state,objects,'user_object.1'),b'abcdefgh')
        self.assertEqual(STATE['pool'][1]['f_pos'],5)

    def test_arguments_are_inputs_with_their_own_shaping(self):
        import copy
        state=copy.deepcopy(STATE);state['_arguments']=[4,0,8,0,0,0]
        set_input(state,[],'argument:2',3);self.assertEqual(get_input(state,[],'argument:2'),3)
        report={'invariants':{'assumed':[]},'ranged_inputs':{},'fixed_by_binding':[],'symbolic_arguments':{'2':[0,32]}}
        shaping=shaping_of(report);self.assertEqual(domains_of(report),{'argument:2':(0,32,False)})
        self.assertEqual(shaped('argument:2',(7).to_bytes(8,'little'),8,shaping),7)
        self.assertEqual(shaped('argument:2',(40).to_bytes(8,'little'),8,shaping),40%33)

    def test_ktest_outputs_never_replace_inputs(self):
        names={'s1':'file_pool[1].f_pos','o2':'file_pool[1].f_pos'}
        self.assertEqual(ktest_inputs({'s1':b'\1','o2':b'\3'},names),{'file_pool[1].f_pos':b'\1'})

    def test_shaping_matches_the_driver(self):
        # Driver order: fold into the declared range, then max(v, 1) for referenced files.
        shaping={'f_count':[('range',0,1<<32),('min',1)],'max_fds':[('range',0,64)]}
        b=lambda v,n=8:(v&((1<<8*n)-1)).to_bytes(n,'little')
        self.assertEqual(shaped('f_count',b(0),8,shaping),1)
        self.assertEqual(shaped('f_count',b(7),8,shaping),7)
        self.assertEqual(shaped('f_count',b((1<<32)+1),8,shaping),((1<<32)+1)%((1<<32)+1) or 1)
        self.assertEqual(shaped('f_count',b(-5),8,shaping),((1<<64)-5)%((1<<32)+1) or 1)
        self.assertEqual(shaped('max_fds',b(64,4),4,shaping),64)
        self.assertEqual(shaped('max_fds',b(65,4),4,shaping),65%65)
        self.assertEqual(shaped('user_object.1',b'xy',2,shaping),b'xy')

    def test_shaping_follows_the_report(self):
        report={'invariants':{'assumed':['file_pool[1].f_count>=1']},'ranged_inputs':{'file_pool[1].f_count':[0,1<<32]},'fixed_by_binding':[]}
        self.assertEqual(shaping_of(report),{'file_pool[1].f_count':[('range',0,1<<32),('min',1)]})
        self.assertEqual(domains_of(report),{'file_pool[1].f_count':(1,1<<32,False)})

    def test_domains_skip_fields_fixed_by_the_binding(self):
        report={'invariants':{'assumed':['file_pool[1].f_count>=1']},'ranged_inputs':{'files.fdtab.max_fds':[0,64]},'fixed_by_binding':['files.fdtab.max_fds']}
        self.assertEqual(domains_of(report),{'file_pool[1].f_count':(1,None,True)})

    def test_outputs_kept_on_paths_with_the_observed_result(self):
        ok=lambda result,size,**more:dict(test='t',fault='never',errors=[],outputs={'result':(result&(1<<64)-1).to_bytes(8,'little').hex(),'file_data.size':size,**more})
        einval=ok(-22,'unchanged');truncate=ok(0,'0000000000000000')
        observed={'file_data.size','file_pool[0].f_count'}
        self.assertEqual(kept_outputs([einval,truncate],observed,-22),{'file_data.size'})
        self.assertEqual(kept_outputs([einval,truncate],observed,0),set())
        # A data-dependent path with any result, a faulting path and no matching path decide nothing / are ignored.
        self.assertEqual(kept_outputs([einval,dict(einval,outputs=None)],observed,-22),set())
        self.assertEqual(kept_outputs([einval,dict(truncate,fault='always')],observed,-22),{'file_data.size'})
        self.assertEqual(kept_outputs([truncate],observed,5),set())

if __name__=='__main__':unittest.main()
