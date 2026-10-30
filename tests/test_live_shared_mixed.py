"""Interleave original write/read helpers in one live shared capture session."""
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
from live_shared_capture import capture_spec,validate_shared,parse_query_log,load_capture,export_verified
from export_entry_state import export,RequestError
import test_live_argument_session as fixture

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64';RETAIN=None


class LiveSharedMixedTests(unittest.TestCase):
    def test_query_witness_root_order_and_cross_root_continuity(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);writer,entries,posts,witness,_=fixture.LiveArgumentSessionTests().fixture(stage,0)
            query=profile_settings('exit-code');body,_=prepare_source(ROOT/'build/kernel_liteos_a','exit-code')
            source=stage/'query.c';source.write_text(query['model']+body)
            db=stage/'query_commands.json';db.write_text(json.dumps([{'directory':str(stage),'file':str(source),
                'arguments':[str(LLVM/'clang'),'-std=c11','-c',str(source)]}]))
            tree,_=load_ast(db,source)
            reader=Analyzer(tree,argument_objects=json.loads(query['policy'].read_text())['argument_objects']).analyze(query['helper'])
            report={'format':'osrec-entry-state-plan-v1','plans':[writer,reader],'shared_query_boundary_policy_sha256':digest(query['policy'].read_bytes())}
            plan_bytes=json.dumps(report).encode();spec_bytes=json.dumps(capture_spec(True)).encode()
            records=[{'root':writer['root'],'number':65539,'raw_bits':0,'entry':copy.deepcopy(e),'post':copy.deepcopy(p)} for e,p in zip(entries,posts)]
            query_frame=copy.deepcopy(posts[2]);query_frame.update(syscall=65536,arguments=[])
            records.insert(3,{'root':reader['root'],'number':65536,'raw_bits':3,'entry':copy.deepcopy(query_frame),'post':copy.deepcopy(query_frame)})
            for index,record in enumerate(records):
                for frame in (record['entry'],record['post']):frame['invocation']=index;frame['objects'][0]['session_id']=1
            data={'format':'osrec-entry-capture-v1','plan_sha256':digest(plan_bytes),'spec_sha256':digest(spec_bytes),'calls':records}
            query_witness=struct.pack('<4I',3,3,3,3)
            self.assertEqual([c['raw_bits'] for c in validate_shared(data,plan_bytes,spec_bytes,witness,entries,posts,query_witness)],[0,0,0,3,0,0,0])
            for change in ('extra','order','route','result','argument','mutation','identity','position','raw_witness','state_witness','length','missing','policy','write_plan'):
                d=copy.deepcopy(data);q=bytearray(query_witness);p=copy.deepcopy(report)
                if change=='extra':d['calls'].append(copy.deepcopy(records[0]))
                elif change=='order':d['calls'][2],d['calls'][3]=d['calls'][3],d['calls'][2]
                elif change=='route':d['calls'][3]['number']=65537
                elif change=='result':d['calls'][3]['raw_bits']=1
                elif change=='argument':d['calls'][3]['entry']['arguments']=[{'name':'signal','bytes':4,'data':'00000000'}]
                elif change=='mutation':d['calls'][3]['post']['fields'][0]['data']='07000000'
                elif change=='identity':
                    for state in (d['calls'][3]['entry'],d['calls'][3]['post']):state['objects'][0]['session_id']=99
                elif change=='position':struct.pack_into('<I',q,0,2)
                elif change=='raw_witness':struct.pack_into('<I',q,8,1)
                elif change=='state_witness':struct.pack_into('<I',q,12,7)
                elif change=='length':q.pop()
                elif change=='missing':q=None
                elif change=='policy':p['shared_query_boundary_policy_sha256']='0'*64
                else:p['plans'][1]['state_writes']=copy.deepcopy(reader['entry_reads'])
                pb=json.dumps(p).encode();d['plan_sha256']=digest(pb)
                with self.subTest(change=change),self.assertRaises(ValueError):validate_shared(d,pb,spec_bytes,witness,entries,posts,bytes(q) if q is not None else None)
            text='OSREC_SHARED_QUERY_KERNEL '+query_witness.hex()+'\n'
            self.assertEqual(parse_query_log(text,True),query_witness)
            for bad,mixed in (('',True),(text+text,True),(text,False)):
                with self.assertRaises(ValueError):parse_query_log(bad,mixed)

    def test_live_mixed_capture_and_read_faults(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture'
            result=subprocess.run([sys.executable,ROOT/'tools/liteos_qemu_demo.py','--shared-mixed-capture','--out',capture],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            data,calls=load_capture(capture,ROOT/'build/kernel_liteos_a')
            self.assertEqual([c['number'] for c in calls],[65539]*3+[65536]+[65539]*3)
            self.assertEqual([c['raw_bits'] for c in calls],[0,0,0,3,0,0,0])
            self.assertEqual(struct.unpack('<4I',(capture/'shared-query-kernel.bin').read_bytes()),(3,3,3,3))
            self.assertEqual(struct.unpack_from('<3I',(capture/'argument-entry-kernel.bin').read_bytes(),96),(0,31,0))
            request=capture/'shared-request/request.json';document=json.loads(request.read_text())
            for address in (0x40200000,0x40400000):
                output=stage/hex(address);args=SimpleNamespace(request=request,out=output,arch='aarch64',entry_address=address,
                    result_address=address-0x80000,llvm_bin=LLVM,qemu=QEMU,capture=capture,kernel_root=ROOT/'build/kernel_liteos_a')
                report=export_verified(args);r=report['target_observations']
                self.assertEqual((r['states_restored'],r['entry_states_checked'],r['states_verified']),(1,7,7))
                proof=json.loads((output/'native-capture-verification.json').read_text())
                self.assertTrue(proof['mixed_roots'] and proof['query_native_witness_verified'])
                if RETAIN is not None:shutil.copytree(output,RETAIN/hex(address))
            for filename in ('shared-query-kernel.bin','shared-query-source.json'):
                path=capture/filename;original=path.read_bytes()
                try:
                    path.write_bytes(original+b' ')
                    with self.assertRaises(ValueError):load_capture(capture,ROOT/'build/kernel_liteos_a')
                finally:path.write_bytes(original)
            adapter=capture/'shared-request'/document['adapter_header'];original=adapter.read_text()
            call='return OsProcessExitCodeSignalIsSet(osrec_bound_osrec_argument_processCB);'
            mutations=[('booleanized_read','return !!OsProcessExitCodeSignalIsSet(osrec_bound_osrec_argument_processCB);',13,1),
                ('read_writes_state','uint32_t raw=OsProcessExitCodeSignalIsSet(osrec_bound_osrec_argument_processCB);osrec_bound_osrec_argument_processCB->exitCode|=4U;return raw;',23,3)]
            faults=[]
            try:
                for mutation,replacement,error,raw in mutations:
                    faulty=original.replace(call,replacement);self.assertNotEqual(original,faulty);adapter.write_text(faulty);args.out=stage/mutation
                    with self.assertRaises(RequestError) as caught:export(args)
                    failed=json.loads(str(caught.exception).removeprefix('target replay diverged: '))
                    self.assertEqual((failed['status'],failed['error'],failed['actual_calls'][3]['raw_bits']),(3,error,raw))
                    self.assertFalse(args.out.exists());faults.append({'mutation':mutation,'observations':failed})
            finally:adapter.write_text(original)
            load_capture(capture,ROOT/'build/kernel_liteos_a')
            if RETAIN is not None:
                shutil.copytree(capture,RETAIN/'capture');(RETAIN/'fault-verification.json').write_text(json.dumps(faults,indent=2)+'\n')


if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:LLVM=Path(sys.argv[1]);QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
