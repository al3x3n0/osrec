"""Exercise generated reconstruction with aliases, cycles and rejected footprints."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from reconstruct_entry_state import reconstruction_header,load_reconstruction
from klee_liteos import digest

class ReconstructionTests(unittest.TestCase):
    def fixture(self):
        plan={'blockers':[],'arguments':[],'object_providers':[
            {'function':'Current','return_type':'Node *'}],
            'entry_reads':[{'path':p,'pointer_edge':edge,'volatile':False,'bitfield':False}
                for p,edge in [('Current()->next',True),('Current()->next->value',False),('Current()->value',False)]]}
        frame={'format':'osrec-entry-snapshot-v1','objects':[{'id':9,'type':'Node'}],
            'roots':[{'name':'Current()','object_id':9}],
            'fields':[{'object_id':9,'name':'next','kind':'edge','target_id':9},
                      {'object_id':9,'name':'value','kind':'scalar','bytes':4,'data':'78563412'}]}
        return frame,plan

    def compile(self,header,body,success=True):
        clang=sys.argv[1] if len(sys.argv)>1 else '/opt/homebrew/opt/llvm@16/bin/clang'
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'test.c';binary=Path(directory)/'test'
            source.write_text('#include <stdint.h>\ntypedef struct Node { struct Node *next; uint32_t value; } Node;\n'+header+body)
            result=subprocess.run([clang,'-std=c11','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],capture_output=True,text=True)
            if success:
                self.assertEqual(result.returncode,0,result.stderr)
                subprocess.run([binary],check=True)
            else:self.assertNotEqual(result.returncode,0)

    def test_alias_cycle_null_and_independent_invocations(self):
        frame,plan=self.fixture();null=copy.deepcopy(frame)
        null['roots'][0]['object_id']=0;null['objects']=[];null['fields']=[]
        header=reconstruction_header([frame,null,frame],[plan]*3)
        self.compile(header,'''int main(void) {
            if(!osrec_restore(0) || !osrec_state_unchanged(0)) return 1;
            Node *first=osrec_bound_Current;
            if(first->next!=first || first->value!=0x12345678) return 2;
            first->value=0; if(osrec_state_unchanged(0)) return 3;
            if(!osrec_restore(1) || osrec_bound_Current) return 4;
            if(!osrec_restore(2) || osrec_bound_Current==first || !osrec_state_unchanged(2)) return 5;
            if(osrec_restore(3) || osrec_state_unchanged(3)) return 6;
            return 0;
        }''')

    def test_extra_field_and_missing_target_rejected(self):
        frame,plan=self.fixture()
        frame['fields'].append({'object_id':9,'name':'extra','kind':'scalar','bytes':1,'data':'00'})
        with self.assertRaises(ValueError):reconstruction_header([frame],[plan])
        frame,plan=self.fixture();frame['fields'][0]['target_id']=8
        with self.assertRaises(ValueError):reconstruction_header([frame],[plan])

    def test_target_width_checked_by_compiler(self):
        frame,plan=self.fixture();frame['fields'][1].update(bytes=2,data='7856')
        self.compile(reconstruction_header([frame],[plan]),'int main(void){return !osrec_restore(0) || !osrec_state_unchanged(0);}',False)

    def test_capture_provenance_and_sequence_rejected(self):
        for change in ('none','hash','source','sequence'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as directory:
                capture=Path(directory);frame,plan=self.fixture()
                frame.update(syscall=42,invocation=0);plan['root']='Query'
                source=capture/'source.c';source.write_text('/* fixture */')
                bundle={'format':'osrec-entry-state-plan-v1','plans':[plan],
                    'capture_abi':{'endianness':'little','pointer_bits':32,'address_serialization':False},
                    'boundary_policy_sha256':digest((ROOT/'integrations/liteos_a/entry-state-boundaries.json').read_bytes()),
                    'source_identities':[{'source':str(source),'source_sha256':digest(source.read_bytes()),'dependencies':{}}]}
                (capture/'entry-state-plan.json').write_text(json.dumps(bundle))
                if change=='sequence':frame['invocation']=1
                (capture/'entry-state-snapshots.json').write_text(json.dumps({'format':'osrec-live-entry-state-v1','snapshots':[frame]}))
                (capture/'entry-state-capture.h').write_text('/* fixture hook */')
                hashes={key:digest((capture/file).read_bytes()) for key,file in
                    [('plan','entry-state-plan.json'),('snapshots','entry-state-snapshots.json'),('generated_hooks','entry-state-capture.h')]}
                (capture/'report.json').write_text(json.dumps({'automated_capture_hashes':hashes}))
                if change=='hash':(capture/'entry-state-capture.h').write_text('changed')
                if change=='source':source.write_text('changed')
                if change=='none':self.assertIn('osrec_restore',load_reconstruction(capture,{42:'Query'},(42,))[0])
                else:
                    with self.assertRaises(ValueError):load_reconstruction(capture,{42:'Query'},(42,))

    def test_blocked_plan_rejected(self):
        frame,plan=self.fixture();plan['blockers']=['unknown call']
        with self.assertRaises(ValueError):reconstruction_header([frame],[plan])

if __name__=='__main__':unittest.main(argv=[sys.argv[0]])
