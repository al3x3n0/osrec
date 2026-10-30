"""Configured original-helper sequences in live LiteOS, with independent witnesses."""
import copy
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,load_ast,digest
from live_argument_state import profile_settings,prepare_source
from live_configured_capture import validate_session,spec_for,schedule,validate_capture,parse_witness,WRITER,READER
from live_shared_capture import load_capture,export_verified
from export_entry_state import export,RequestError
import test_live_argument_session as fixture

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64';RETAIN=None
EXAMPLE=ROOT/'integrations/liteos_qemu/shared-session-example.json'


def args_for(capture,out,address=0x40200000):
    return SimpleNamespace(capture=capture,kernel_root=ROOT/'build/kernel_liteos_a',out=out,arch='aarch64',
        entry_address=address,result_address=address-0x80000,llvm_bin=LLVM,qemu=QEMU)


def synthetic(stage):
    writer,entries,_,_,_=fixture.LiveArgumentSessionTests().fixture(stage,0)
    query=profile_settings('exit-code');source=stage/'query.c';source.write_text(query['model']+prepare_source(ROOT/'build/kernel_liteos_a','exit-code')[0])
    db=stage/'query_commands.json';db.write_text(json.dumps([{'directory':str(stage),'file':str(source),
        'arguments':[str(LLVM/'clang'),'-std=c11','-c',str(source)]}]))
    tree,_=load_ast(db,source);reader=Analyzer(tree,argument_objects=json.loads(query['policy'].read_text())['argument_objects']).analyze(READER)
    report={'format':'osrec-entry-state-plan-v1','plans':[writer,reader],'shared_query_boundary_policy_sha256':digest(query['policy'].read_bytes())}
    session=json.loads(EXAMPLE.read_text());spec=spec_for(session);records=[];rows=[];state=0
    for index,call in enumerate(session['calls']):
        root=call['root'];number=65539 if root==WRITER else 65536;signal=call['arguments'].get('signal',0)
        after=state|(signal&127) if root==WRITER else state;raw=0 if root==WRITER else state&127
        frame=copy.deepcopy(entries[0]);frame.update(invocation=index,syscall=number)
        frame['objects'][0]['session_id']=1;frame['fields'][0]['data']=struct.pack('<I',state).hex()
        frame['arguments']=[{'name':'signal','bytes':4,'data':struct.pack('<I',signal).hex()}] if root==WRITER else []
        post=copy.deepcopy(frame);post['fields'][0]['data']=struct.pack('<I',after).hex()
        records.append({'root':root,'number':number,'raw_bits':raw,'entry':frame,'post':post})
        rows.extend([index,number,signal,state,raw,after]);state=after
    pb=json.dumps(report).encode();sb=json.dumps(spec).encode()
    data={'format':'osrec-entry-capture-v1','plan_sha256':digest(pb),'spec_sha256':digest(sb),'calls':records}
    witness=struct.pack('<'+str(5+len(rows))+'I',1,len(records),0,state,0,*rows)
    return data,pb,sb,witness


class LiveConfiguredCaptureTests(unittest.TestCase):
    def test_session_admission_and_schedule_bounds(self):
        session=json.loads(EXAMPLE.read_text());self.assertEqual(len(validate_session(session)['calls']),33)
        self.assertEqual(spec_for(session)['max_calls'],33);self.assertIn('UINT32_C(4294967295)',schedule(session))
        cases=[]
        for count in (0,257):cases.append({'format':'osrec-live-helper-session-v1','calls':[{'root':READER,'arguments':{}}]*count})
        for call in ({'root':'unknown','arguments':{}},{'root':READER,'arguments':{'signal':1}},
                     {'root':WRITER,'arguments':{}},{'root':WRITER,'arguments':{'signal':True}},
                     {'root':WRITER,'arguments':{'signal':-1}},{'root':WRITER,'arguments':{'signal':0x100000000}}):
            cases.append({'format':'osrec-live-helper-session-v1','calls':[call]})
        for bad in cases:
            with self.subTest(session=bad),self.assertRaises(ValueError):validate_session(bad)
        validate_session({'format':'osrec-live-helper-session-v1','calls':[{'root':READER,'arguments':{}}]*256})

    def test_native_witness_and_cross_root_snapshot_rejections(self):
        with tempfile.TemporaryDirectory() as name:
            data,pb,sb,witness=synthetic(Path(name));calls=validate_capture(data,pb,sb,witness)
            self.assertEqual((len(calls),calls[-1]['raw_bits'],calls[-1]['after']),(33,127,127))
            changes=('pid','count','initial','final','restored','position','route','signal','before','raw','after','length',
                     'extra_call','root','result','bool_result','entry','post','arguments','identity','plan','spec','policy','writable_query')
            offsets={'pid':0,'count':1,'initial':2,'final':3,'restored':4,'position':5,'route':6,'signal':7,'before':8,'raw':9,'after':10}
            for change in changes:
                d=copy.deepcopy(data);p=json.loads(pb);w=bytearray(witness)
                if change in offsets:
                    offset=offsets[change];value=struct.unpack_from('<I',w,4*offset)[0];struct.pack_into('<I',w,4*offset,value^1)
                elif change=='length':w.pop()
                elif change=='extra_call':d['calls'].append(copy.deepcopy(d['calls'][-1]))
                elif change=='root':d['calls'][3]['root']=WRITER
                elif change=='result':d['calls'][3]['raw_bits']=1
                elif change=='bool_result':d['calls'][0]['raw_bits']=False
                elif change in ('entry','post'):d['calls'][3][change]['fields'][0]['data']='07000000'
                elif change=='arguments':d['calls'][3]['entry']['arguments']=[{'name':'signal','bytes':4,'data':'01000000'}]
                elif change=='identity':
                    for frame in (d['calls'][3]['entry'],d['calls'][3]['post']):frame['objects'][0]['session_id']=99
                elif change in ('plan','spec'):d[change+'_sha256']='0'*64
                elif change=='policy':p['shared_query_boundary_policy_sha256']='0'*64
                else:p['plans'][1]['state_writes']=copy.deepcopy(p['plans'][1]['entry_reads'])
                changed=json.dumps(p).encode()
                if change!='plan':d['plan_sha256']=digest(changed)
                with self.subTest(change=change),self.assertRaises(ValueError):validate_capture(d,changed,sb,bytes(w))
            line='OSREC_SHARED_SESSION_KERNEL '+witness.hex()+'\n';self.assertEqual(parse_witness(line),witness)
            for text in ('',line+line):
                with self.assertRaises(ValueError):parse_witness(text)

    def test_live_configured_33_call_session_and_late_faults(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture'
            result=subprocess.run([sys.executable,ROOT/'tools/liteos_qemu_demo.py','--shared-session',EXAMPLE,'--out',capture],capture_output=True,text=True,timeout=300)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            data,calls=load_capture(capture,ROOT/'build/kernel_liteos_a');self.assertEqual(len(calls),33)
            self.assertEqual(struct.unpack('<5I',(capture/'shared-session-kernel.bin').read_bytes()[:20]),(1,33,0,127,0))
            self.assertEqual(struct.unpack('<3I',(capture/'argument-entry-kernel.bin').read_bytes()[-12:]),(0,31,0))
            for address in (0x40200000,0x40400000):
                output=stage/hex(address);report=export_verified(args_for(capture,output,address));o=report['target_observations']
                self.assertEqual((o['abi_version'],o['states_restored'],o['entry_states_checked'],o['states_verified']),(30,1,33,33))
                proof=json.loads((output/'native-capture-verification.json').read_text());self.assertTrue(proof['native_witness_verified'])
                self.assertEqual(proof['initial_final_restored'],[0,127,0]);self.assertIn('generated_dispatch',proof)
                if RETAIN is not None:shutil.copytree(output,RETAIN/hex(address))
            for filename in ('shared-session.json','shared-session-schedule.h','shared-session-sources.json','shared-session-kernel.bin'):
                path=capture/filename;original=path.read_bytes()
                try:
                    path.write_bytes(original+b' ')
                    with self.assertRaises(ValueError):load_capture(capture,ROOT/'build/kernel_liteos_a')
                finally:path.write_bytes(original)
            request=capture/'shared-request/request.json';document=json.loads(request.read_text());adapter=request.parent/document['adapter_header'];original=adapter.read_text()
            query='return (processCB->exitCode) & 0x7FU;';self.assertIn(query,original);faults=[]
            for mutation,action,error in [('late_read_result','++raw',0x10000+25),('late_read_store','processCB->exitCode=0',0x20000+25)]:
                try:
                    replacement='static UINT32 queries;UINT32 raw=(processCB->exitCode)&0x7FU;if(++queries==13){'+action+';}return raw;'
                    adapter.write_text(original.replace(query,replacement));args=args_for(capture,stage/mutation);args.request=request
                    with self.assertRaises(RequestError) as caught:export(args)
                    observation=json.loads(str(caught.exception).removeprefix('target replay diverged: '))
                    self.assertEqual((observation['error'],observation['completed_calls']),(error,25));self.assertFalse(args.out.exists())
                    faults.append({'mutation':mutation,'observations':observation})
                finally:adapter.write_text(original)
            load_capture(capture,ROOT/'build/kernel_liteos_a')
            if RETAIN is not None:
                shutil.copytree(capture,RETAIN/'capture');(RETAIN/'fault-verification.json').write_text(json.dumps(faults,indent=2)+'\n')

    def test_live_single_read_selects_short_abi_and_unused_writer_site(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);session=stage/'session.json'
            session.write_text(json.dumps({'format':'osrec-live-helper-session-v1','calls':[{'root':READER,'arguments':{}}]}))
            capture=stage/'capture';result=subprocess.run([sys.executable,ROOT/'tools/liteos_qemu_demo.py','--shared-session',session,'--out',capture],capture_output=True,text=True,timeout=300)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            data,calls=load_capture(capture,ROOT/'build/kernel_liteos_a');self.assertEqual(len(calls),1)
            output=stage/'image';report=export_verified(args_for(capture,output))
            self.assertEqual((report['target_observations']['abi_version'],report['target_observations']['write_effects']),(8,False))
            if RETAIN is not None:shutil.copytree(capture,RETAIN/'single-read/capture');shutil.copytree(output,RETAIN/'single-read/image')

    def test_live_maximum_read_session(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);session=stage/'session.json'
            session.write_text(json.dumps({'format':'osrec-live-helper-session-v1','calls':[{'root':READER,'arguments':{}}]*256}))
            capture=stage/'capture';result=subprocess.run([sys.executable,ROOT/'tools/liteos_qemu_demo.py','--shared-session',session,'--out',capture],capture_output=True,text=True,timeout=300)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            data,calls=load_capture(capture,ROOT/'build/kernel_liteos_a');self.assertEqual(len(calls),256)
            self.assertEqual(struct.unpack('<5I',(capture/'shared-session-kernel.bin').read_bytes()[:20]),(1,256,0,0,0))
            output=stage/'image';report=export_verified(args_for(capture,output))
            self.assertEqual((report['target_observations']['abi_version'],report['target_observations']['completed_calls'],report['target']['result_bytes']),(30,256,2176))
            if RETAIN is not None:shutil.copytree(capture,RETAIN/'maximum-read/capture');shutil.copytree(output,RETAIN/'maximum-read/image')


if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:LLVM=Path(sys.argv[1]);QEMU=sys.argv[2];fixture.LLVM=LLVM;sys.argv=sys.argv[:1]
    unittest.main()
