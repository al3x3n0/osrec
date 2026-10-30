"""Long generated capture/replay sessions and bounded ABI 30 result transcripts."""
import copy
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import test_entry_capture as fixture
import test_entry_state_dispatch as dispatch_fixture
from entry_capture import generate,import_session
from entry_state import Analyzer,load_ast
from entry_state_result import decode_transcript,transcript_bytes
from export_entry_state import export,prepare_request,RequestError
from freestanding_armv7 import run
from run_freestanding_armv7 import observe,require_success

LLVM=fixture.LLVM;QEMU=fixture.QEMU;RETAIN=None


def native(project,body,capacity=33,stdout=True):
    source=project/'native.c';source.write_text((project/'functions.c').read_text()+
        '#include <stdio.h>\n#include "capture.h"\nstatic Obj a={99,0},b={41,0};Obj *current(void){return &a;}\n'
        'static struct osrec_capture_session session;\n'+fixture.TRANSPORT+body)
    binary=project/'native';run([LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror','-DOSREC_CAPTURE_CALLS='+str(capacity),
        '-I',ROOT/'include','-I',project,source,ROOT/'runtime/entry_snapshot.c',ROOT/'runtime/entry_capture.c','-o',binary])
    result=run([binary])
    if stdout:
        path=project/'capture.json';path.write_text(result.stdout);return path


def setup(project,mode='continuous'):
    plan,spec=dispatch_fixture.setup(project,mode)
    document=json.loads(spec.read_text());document['max_calls']=33;spec.write_text(json.dumps(document,indent=2)+'\n')
    (project/'capture.h').write_text(generate(plan,spec))
    return plan,spec


def mixed_capture(project):
    return native(project,'''int main(void){a.next=&b;osrec_capture_init(&session);
 for(unsigned i=0;i<16;++i){osrec_capture_update(&session,2*i+1);osrec_capture_query(&session);}
 if(osrec_capture_query(&session)!=146||a.value!=115||b.value!=31)return 1;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
''')


class EntryStateLongSessionTests(unittest.TestCase):
    def test_mixed_capture_modes_relocation_and_portable_rebuild(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for mode in ('independent','continuous'):
                project=stage/(mode+'-project');plan,spec=setup(project,mode);capture=mixed_capture(project)
                imported=stage/(mode+'-request');import_session(plan,spec,capture,imported)
                for address in (0x40200000,0x40400000):
                    output=stage/(mode+hex(address));report=export(fixture.image_args(imported/'request.json',output,address))
                    observations=report['target_observations'];require_success(observations)
                    self.assertEqual((observations['abi_version'],observations['completed_calls']),(30,33))
                    self.assertEqual(report['target']['result_bytes'],128+33*8)
                    self.assertEqual(len((output/'target-result.bin').read_bytes()),128+33*8)
                    self.assertEqual(observations['actual_calls'][-1],{'number':102,'raw_bits':146})
                    self.assertEqual(observations['states_restored'],1 if mode=='continuous' else 33)
                    if RETAIN is not None:shutil.copytree(output,RETAIN/mode/hex(address))
                shutil.rmtree(project);shutil.rmtree(imported)
                rebuilt=stage/(mode+'-portable');export(fixture.image_args(output/'request.json',rebuilt,0x40400000))
                self.assertEqual((rebuilt/'entry-state.bin').read_bytes(),(output/'entry-state.bin').read_bytes())
                if RETAIN is not None:shutil.copytree(rebuilt,RETAIN/mode/'portable-rebuild')

    def test_late_return_and_state_faults_have_distinct_errors(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);project=stage/'project';plan,spec=setup(project);capture=mixed_capture(project)
            imported=stage/'request';import_session(plan,spec,capture,imported)
            bodies=imported/'support-bodies.c';original=bodies.read_text();query=fixture.BODIES['query']
            self.assertIn(query,original);faults=[]
            replacement='unsigned query(void){static unsigned calls;unsigned raw=current()->value+(current()->next?current()->next->value:0);++calls;ACTION;return raw;}\n'
            for mutation,action,error in [('late_return','if(calls==13)++raw',0x10000+25),
                                          ('late_store','if(calls==13)++current()->value',0x20000+25)]:
                try:
                    bodies.write_text(original.replace(query,replacement.replace('ACTION',action)));output=stage/mutation
                    with self.assertRaises(RequestError) as caught:export(fixture.image_args(imported/'request.json',output))
                    observation=json.loads(str(caught.exception).removeprefix('target replay diverged: '))
                    self.assertEqual((observation['abi_version'],observation['error'],observation['completed_calls']),(30,error,25))
                    self.assertEqual(observation['last_invocation'],25);self.assertEqual(len(observation['actual_calls']),33)
                    self.assertFalse(output.exists());faults.append({'mutation':mutation,'observations':observation})
                finally:bodies.write_text(original)
            if RETAIN is not None:(RETAIN/'fault-verification.json').write_text(json.dumps(faults,indent=2)+'\n')

    def test_capture_capacity_overflow_and_configuration_fail_closed(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);project=stage/'project';plan,spec=setup(project)
            native(project,'''static unsigned writes;
static int reject(void *p,const char *data,size_t n){(void)p;(void)data;(void)n;++writes;return 0;}
int main(void){a.next=&b;osrec_capture_init(&session);
 for(unsigned i=0;i<34;++i)if(osrec_capture_update(&session,0)!=100+i)return 1;
 if(a.value!=133||!session.failed||session.count!=33)return 2;
 if(osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,reject,0)||writes)return 3;
 (void)emit;return 0;}
''',stdout=False)
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                native(project,'int main(void){a.next=&b;(void)emit;return 0;}\n',capacity=7,stdout=False)
            self.assertIn('capture capacity differs from specification',caught.exception.stderr)
            original=json.loads(spec.read_text())
            for invalid in (0,True,257,-1,'33'):
                document=copy.deepcopy(original);document['max_calls']=invalid;spec.write_text(json.dumps(document))
                with self.subTest(capacity=invalid),self.assertRaisesRegex(ValueError,'max_calls'):generate(plan,spec)
            spec.write_text(json.dumps(original));(project/'capture.h').write_text(generate(plan,spec))
            capture=mixed_capture(project);data=json.loads(capture.read_text())
            data['calls'].append(copy.deepcopy(data['calls'][-1]));capture.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,'1 through 33'):import_session(plan,spec,capture,stage/'oversized-import')
            self.assertFalse((stage/'oversized-import').exists())

    def test_maximum_scalar_session_and_over_limit_request(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);project=stage/'project';project.mkdir()
            body='unsigned echo_bits(unsigned input){return input;}\n';source=project/'functions.c';source.write_text(fixture.MODEL+body)
            db=project/'compile_commands.json';db.write_text(json.dumps([{'directory':str(project),'file':str(source),
                'arguments':[str(LLVM/'clang'),'-std=c11','-c',str(source)]}]))
            tree,_=load_ast(db,source);plan=Analyzer(tree).analyze('echo_bits');self.assertFalse(plan['blockers'])
            plan_path=project/'plan.json';plan_path.write_text(json.dumps({'format':'osrec-entry-state-plan-v1','plans':[plan]}))
            spec={'format':'osrec-entry-capture-spec-v1','max_calls':256,'replay_dispatch':'generated',
                'contract':{'fixed_lifetimes':True,'exclusive_capture':True,'reason':'no object arguments','implementation':'one capture owner'},
                'sites':[{'root':'echo_bits','number':107,'return_kind':'u32'}],'model_header':'model.h','adapter_header':'adapter.h',
                'files':{'bodies.c':'bodies.c'},'translation_units':['bodies.c']}
            spec_path=project/'spec.json';spec_path.write_text(json.dumps(spec));(project/'capture.h').write_text(generate(plan_path,spec_path))
            (project/'model.h').write_text(fixture.MODEL+'unsigned echo_bits(unsigned input);\n')
            (project/'adapter.h').write_text('/* Generated calls only. */\n');(project/'bodies.c').write_text('#include "entry_model.h"\n'+body)
            capture=native(project,'''int main(void){a.next=&b;osrec_capture_init(&session);
 for(unsigned i=0;i<256;++i)if(osrec_capture_echo_bits(&session,UINT32_MAX-i)!=UINT32_MAX-i)return 1;
 return !osrec_capture_json(&session,OSREC_CAPTURE_PLAN_SHA256,OSREC_CAPTURE_SPEC_SHA256,emit,0);}
''',capacity=256)
            imported=stage/'request';import_session(plan_path,spec_path,capture,imported)
            output=stage/'maximum';report=export(fixture.image_args(imported/'request.json',output))
            self.assertEqual((report['target_observations']['completed_calls'],report['target']['result_bytes']),(256,2176))
            self.assertEqual([c['raw_bits'] for c in report['target_observations']['actual_calls']],[0xffffffff-i for i in range(256)])
            if RETAIN is not None:shutil.copytree(output,RETAIN/'maximum-256')
            request=imported/'request.json';d=json.loads(request.read_text());d['calls'].append(d['calls'][0]);request.write_text(json.dumps(d))
            with self.assertRaises(RequestError) as caught:prepare_request(request)
            self.assertEqual(caught.exception.stage,'calls')

    def test_transcript_header_extent_and_progress_validation(self):
        words=[0]*32;words[:10]=[0x4f535243,30,2,0,33,33,1,33,32,1]
        words[10:14]=[33,8,128,1];words[24:26]=[1,33]
        raw=struct.pack('<32I',*words)+b''.join(struct.pack('<2I',101,0x80000000+i) for i in range(33))
        decoded=decode_transcript(raw);self.assertEqual(decoded['actual_calls'][-1]['raw_bits'],0x80000020)
        report={'status':2,'error':0,'abi_version':30,'completed_calls':33,**decoded};require_success(report)
        changes=[(0,0),(1,8),(2,1),(4,34),(5,7),(5,257),(6,34),(7,32),(8,33),(9,2),(10,32),(11,4),(12,132),(13,2),(14,1),(24,2),(25,34),(26,1),(31,1)]
        for index,value in changes:
            changed=bytearray(raw);struct.pack_into('<I',changed,index*4,value)
            with self.subTest(index=index,value=value),self.assertRaises(ValueError):decode_transcript(bytes(changed))
        for changed in (raw[:127],raw[:-1],raw+b'\0'*8):
            with self.assertRaises(ValueError):decode_transcript(changed)
        for size in (None,128,2176,0xffffffff):
            with self.assertRaises(ValueError):transcript_bytes(tuple(words),size)

    def test_elf_result_extent_must_cover_and_match_transcript(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);project=stage/'project';plan,spec=setup(project);capture=mixed_capture(project)
            imported=stage/'request';import_session(plan,spec,capture,imported)
            output=stage/'image';export(fixture.image_args(imported/'request.json',output))
            image=output/'entry-state.elf';original=image.read_bytes()
            # Modify the actual ELF64 result symbol, leaving its writable
            # segment and executable unchanged. Inspection must reject an
            # oversized symbol; observation must reject an undersized one.
            shoff=struct.unpack_from('<Q',original,40)[0];shsize,shcount=struct.unpack_from('<HH',original,58)
            sections=[struct.unpack_from('<IIQQQQIIQQ',original,shoff+i*shsize) for i in range(shcount)]
            size_offset=None
            for section in sections:
                if section[1]!=2:continue
                strings=sections[section[6]];table=original[strings[4]:strings[4]+strings[5]]
                for pos in range(section[4],section[4]+section[5],section[9]):
                    name_offset=struct.unpack_from('<I',original,pos)[0]
                    if table[name_offset:].split(b'\0',1)[0]==b'osrec_result':size_offset=pos+16
            self.assertIsNotNone(size_offset)
            for size,message in [(128,'layout differs'),(384,'layout differs'),(400,'outside writable'),(3000,'bounded osrec_result')]:
                changed=bytearray(original);struct.pack_into('<Q',changed,size_offset,size)
                broken=stage/('result-'+str(size)+'.elf');broken.write_bytes(changed)
                with self.subTest(size=size),self.assertRaisesRegex(ValueError,message):observe(broken,qemu=QEMU)


if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:
        LLVM=Path(sys.argv[1]);QEMU=sys.argv[2];fixture.LLVM=LLVM;fixture.QEMU=QEMU;dispatch_fixture.LLVM=LLVM;sys.argv=sys.argv[:1]
    unittest.main()
