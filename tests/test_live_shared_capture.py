"""Live generated wrappers checked against direct witnesses and legacy snapshots."""
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
from klee_liteos import digest
from live_shared_capture import capture_spec,validate_shared,parse_log,load_capture,export_verified
from export_entry_state import export,RequestError
import test_live_argument_session as fixture

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64';RETAIN=None


class LiveSharedCaptureTests(unittest.TestCase):
    def test_direct_witness_legacy_comparison_and_hash_bindings(self):
        with tempfile.TemporaryDirectory() as name:
            plan,entries,posts,witness,_=fixture.LiveArgumentSessionTests().fixture(Path(name),0)
            plan_bytes=json.dumps({'format':'osrec-entry-state-plan-v1','plans':[plan]}).encode()
            spec_bytes=json.dumps(capture_spec()).encode()
            records=[{'root':plan['root'],'number':65539,'raw_bits':0,'entry':copy.deepcopy(e),'post':copy.deepcopy(p)} for e,p in zip(entries,posts)]
            for record in records:
                for frame in (record['entry'],record['post']):frame['objects'][0]['session_id']=1
            data={'format':'osrec-entry-capture-v1','plan_sha256':digest(plan_bytes),'spec_sha256':digest(spec_bytes),'calls':records}
            self.assertEqual(len(validate_shared(data,plan_bytes,spec_bytes,witness,entries,posts)),6)
            for change in ('plan','spec','missing','order','route','result','signal','field','identity','witness','legacy'):
                d=copy.deepcopy(data);w=bytearray(witness);legacy=copy.deepcopy(entries)
                if change in ('plan','spec'):d[change+'_sha256']='0'*64
                elif change=='missing':d['calls'].pop()
                elif change=='order':d['calls'][0],d['calls'][1]=d['calls'][1],d['calls'][0]
                elif change=='route':d['calls'][0]['number']=65538
                elif change=='result':d['calls'][0]['raw_bits']=1
                elif change=='signal':d['calls'][0]['entry']['arguments'][0]['data']='02000000'
                elif change=='field':d['calls'][0]['post']['fields'][0]['data']='00000000'
                elif change=='identity':d['calls'][0]['post']['objects'][0]['session_id']=2
                elif change=='witness':struct.pack_into('<I',w,104,1)
                else:legacy[0]['fields'][0]['data']='02000000'
                with self.subTest(change=change),self.assertRaises(ValueError):validate_shared(d,plan_bytes,spec_bytes,bytes(w),legacy,posts)
            text='OSREC_SHARED_CAPTURE '+json.dumps(data)+'\n';self.assertEqual(parse_log(text),data)
            for text in ('',text+text):
                with self.assertRaises(ValueError):parse_log(text)

    def test_live_wrapper_import_replay_and_corruption_checks(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture'
            result=subprocess.run([sys.executable,ROOT/'tools/liteos_qemu_demo.py','--shared-argument-capture','--out',capture],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            data,calls=load_capture(capture,ROOT/'build/kernel_liteos_a')
            self.assertEqual([c['before'] for c in calls],[0,1,3,3,7,15]);self.assertEqual([c['after'] for c in calls],[1,3,3,7,15,31])
            self.assertEqual(struct.unpack_from('<3I',(capture/'argument-entry-kernel.bin').read_bytes(),96),(0,31,0))
            request=capture/'shared-request/request.json';document=json.loads(request.read_text())
            for address in (0x40200000,0x40400000):
                output=stage/hex(address);args=SimpleNamespace(request=request,out=output,arch='aarch64',entry_address=address,
                    result_address=address-0x80000,llvm_bin=LLVM,qemu=QEMU,capture=capture,kernel_root=ROOT/'build/kernel_liteos_a')
                report=export_verified(args);r=report['target_observations']
                self.assertEqual((r['states_restored'],r['entry_states_checked'],r['states_verified']),(1,6,6))
                proof=json.loads((output/'native-capture-verification.json').read_text());self.assertTrue(proof['native_witness_verified'])
                if RETAIN is not None:shutil.copytree(output,RETAIN/hex(address))
            imported_model=capture/'shared-request'/document['model_header']
            files=[capture/'shared-capture.json',capture/'shared-capture.h',capture/'boot.log',capture/'argument-entry-kernel.bin',
                   capture/'liteos.bin',capture/'liteos.elf',request,imported_model,capture/'shared-request/import-manifest.json']
            for path in files:
                original=path.read_bytes()
                try:
                    path.write_bytes(original+b' ' if path.suffix not in ('.bin',) else bytes([original[0]^1])+original[1:])
                    with self.subTest(file=path.name),self.assertRaises(ValueError):load_capture(capture,ROOT/'build/kernel_liteos_a')
                finally:path.write_bytes(original)
            adapter=capture/'shared-request'/document['adapter_header'];original=adapter.read_text()
            faulty=original.replace('processCB->exitCode |= signal & 0x7FU;','(void)processCB;(void)signal;')
            self.assertNotEqual(original,faulty)
            try:
                adapter.write_text(faulty);args.out=stage/'missing-write'
                with self.assertRaises(RequestError) as caught:export(args)
                failed=json.loads(str(caught.exception).removeprefix('target replay diverged: '))
                self.assertEqual((failed['status'],failed['error'],failed['actual_calls'][0]['raw_bits']),(3,20,0))
                self.assertFalse(args.out.exists())
                if RETAIN is not None:(RETAIN/'fault-verification.json').write_text(json.dumps(failed,indent=2)+'\n')
            finally:adapter.write_text(original)
            load_capture(capture,ROOT/'build/kernel_liteos_a')
            if RETAIN is not None:shutil.copytree(capture,RETAIN/'capture')


if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:LLVM=Path(sys.argv[1]);QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
