"""Native-backed original helper replay using generated call dispatch."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from live_shared_capture import export_verified
from export_entry_state import export,RequestError
from run_freestanding_armv7 import observe,require_success

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64';RETAIN=None


class LiveGeneratedDispatchTests(unittest.TestCase):
    def test_retained_native_sessions_generated_dispatch_and_faults(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);faults=[]
            for profile,capture in [('single','build/live-shared-final-v2/capture'),('mixed','build/live-mixed-final-v1/capture')]:
                capture=ROOT/capture
                # This test checks retained native provenance; fresh capture is
                # exercised by the existing live shared/mixed regression suites.
                if not capture.exists():
                    capture=stage/(profile+'-capture')
                    result=subprocess.run([sys.executable,ROOT/'tools/liteos_qemu_demo.py',
                        '--shared-mixed-capture' if profile=='mixed' else '--shared-argument-capture','--out',capture],
                        capture_output=True,text=True,timeout=240)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                for address in (0x40200000,0x40400000):
                    output=stage/(profile+hex(address))
                    args=SimpleNamespace(capture=capture,kernel_root=ROOT/'build/kernel_liteos_a',out=output,
                        arch='aarch64',entry_address=address,result_address=address-0x80000,llvm_bin=LLVM,qemu=QEMU,generated_dispatch=True)
                    report=export_verified(args);proof=json.loads((output/'native-capture-verification.json').read_text())
                    self.assertEqual(proof['generated_dispatch'],report['generated_dispatch'])
                    self.assertTrue(proof['native_witness_verified']);self.assertEqual(report['target_observations']['completed_calls'],7 if profile=='mixed' else 6)
                    before=ROOT/('build/live-mixed-final-v1' if profile=='mixed' else 'build/live-shared-final-v2')/hex(address)
                    if not before.exists():
                        before=stage/(profile+'-reviewed-'+hex(address));args.out=before;args.generated_dispatch=False
                        export_verified(args);args.out=output;args.generated_dispatch=True
                    self.assertEqual((output/'target-result.bin').read_bytes(),(before/'target-result.bin').read_bytes())
                    for kind in ('elf','bin'):
                        observed,raw=observe(output/('entry-state.'+kind),qemu=QEMU,descriptor=output/'entry-state.elf');require_success(observed)
                        self.assertEqual(raw,(output/'target-result.bin').read_bytes())
                    if RETAIN is not None:shutil.copytree(output,RETAIN/profile/hex(address))
                    if profile!='mixed' or address!=0x40200000:continue
                    document=json.loads((output/'request.json').read_text());adapter=output/document['adapter_header'];original=adapter.read_text()
                    query='return (processCB->exitCode) & 0x7FU;'
                    self.assertIn(query,original)
                    for mutation,replacement,error in [('booleanized_read','return !!(processCB->exitCode & 0x7FU);',13),
                        ('read_writes_state','UINT32 raw=processCB->exitCode & 0x7FU;processCB->exitCode|=4U;return raw;',23)]:
                        try:
                            adapter.write_text(original.replace(query,replacement));args.request=output/'request.json';args.out=stage/mutation
                            with self.assertRaises(RequestError) as caught:export(args)
                            observation=json.loads(str(caught.exception).removeprefix('target replay diverged: '))
                            self.assertEqual(observation['error'],error);self.assertFalse(args.out.exists())
                            faults.append({'mutation':mutation,'observations':observation})
                        finally:adapter.write_text(original)
            if RETAIN is not None:(RETAIN/'fault-verification.json').write_text(json.dumps(faults,indent=2)+'\n')


if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:LLVM=Path(sys.argv[1]);QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
