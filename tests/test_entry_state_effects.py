"""Captured post-state verifies scalar writes without restoring expected output."""
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from reconstruct_entry_state import reconstruction_header
CLANG='/opt/homebrew/opt/llvm@16/bin/clang'
class EffectTests(unittest.TestCase):
    def fixture(self,omitted=False):
        def access(name):return {'path':'current()->'+name,'type':'unsigned int','pointer_edge':False,'volatile':False,'bitfield':False}
        plan={'blockers':[],'arguments':[],'object_providers':[{'function':'current','return_type':'Obj *'}],
            'entry_reads':[access('other')]+([] if omitted else [access('value')]),'state_writes':[access('value')]}
        def field(name,value):return {'object_id':9,'name':name,'kind':'scalar','bytes':4,'data':value.to_bytes(4,'little').hex()}
        frame={'format':'osrec-entry-snapshot-v1','objects':[{'id':9,'type':'Obj'}],
            'roots':[{'name':'current()','object_id':9}],'fields':[field('other',99)]+([] if omitted else [field('value',55)])}
        post=copy.deepcopy(frame);post['fields']=[field('other',99),field('value',4)]
        return frame,post,plan

    def compile(self,header,body):
        with tempfile.TemporaryDirectory() as name:
            source=Path(name)/'run.c';binary=Path(name)/'run'
            source.write_text('typedef struct {unsigned value,other;} Obj;\n'+header+body)
            result=subprocess.run([CLANG,'-std=c11','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr);subprocess.run([binary],check=True)

    def test_captured_and_omitted_entry_fields(self):
        for omitted in (False,True):
            with self.subTest(omitted=omitted):
                frame,post,plan=self.fixture(omitted)
                header=reconstruction_header([frame],[plan],post_states=[post])
                self.compile(header,f'''int main(void){{
 if(!osrec_restore(0) || osrec_bound_current->value!={0 if omitted else 55}) return 1;
 if(osrec_state_matches(0)) return 2;
 osrec_bound_current->value=4;if(!osrec_state_matches(0)) return 3;
 ++osrec_bound_current->other;if(osrec_state_matches(0)) return 4;
 return 0;}}''')

    def test_unwritten_fields_graph_and_width_are_checked(self):
        frame,post,plan=self.fixture()
        for change in ('unwritten','width','graph','extra','missing','pointer','nested','volatile'):
            with self.subTest(change=change):
                f=copy.deepcopy(frame);p=copy.deepcopy(post);schema=copy.deepcopy(plan)
                if change=='unwritten':p['fields'][0]['data']='64000000'
                elif change=='width':p['fields'][1].update(bytes=2,data='0400')
                elif change=='graph':
                    p['objects'][0]['id']=10;p['roots'][0]['object_id']=10
                    for row in p['fields']:row['object_id']=10
                elif change=='extra':p['fields'].append({'object_id':9,'name':'extra','kind':'scalar','bytes':1,'data':'01'})
                elif change=='missing':p['fields'].pop()
                elif change=='pointer':schema['state_writes'][0]['pointer_edge']=True
                elif change=='nested':schema['state_writes'][0]['path']='current()->parent->value'
                elif change=='volatile':schema['state_writes'][0]['volatile']=True
                with self.assertRaises(ValueError):reconstruction_header([f],[schema],post_states=[p])
        with self.assertRaisesRegex(ValueError,'post-state count'):reconstruction_header([frame],[plan],post_states=[])
        with self.assertRaisesRegex(ValueError,'write-effect'):reconstruction_header([frame],[plan])

    def test_scalar_arguments_use_captured_bits(self):
        frame,post,plan=self.fixture()
        plan['arguments']=[{'name':'mask','type':'unsigned int','pointer':False}]
        frame['arguments']=[{'name':'mask','bytes':4,'data':'ffffffff'}]
        header=reconstruction_header([frame],[plan],post_states=[post],scalar_arguments=True)
        self.compile(header,'''int main(void){if(!osrec_restore(0) || osrec_argument(0,0)!=0xffffffffU) return 1;
 osrec_bound_current->value=4;return !osrec_state_matches(0);}''')
        for change in ('name','size','pointer'):
            f=copy.deepcopy(frame);schema=copy.deepcopy(plan)
            if change=='name':f['arguments'][0]['name']='other'
            elif change=='size':f['arguments'][0].update(bytes=1,data='ff')
            else:schema['arguments'][0]['pointer']=True
            with self.assertRaises(ValueError):reconstruction_header([f],[schema],post_states=[post],scalar_arguments=True)

if __name__=='__main__':
    if len(sys.argv)==2:CLANG=sys.argv.pop()
    unittest.main()
