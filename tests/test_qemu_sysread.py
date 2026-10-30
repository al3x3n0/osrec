"""Boot a real ARM guest, vary external file bytes, and compare native replay."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
KERNEL,CLANG,QEMU,COMPILER=sys.argv[1:5]
sys.argv=sys.argv[:1]
ROOT=Path(__file__).resolve().parents[1]

class QemuTests(unittest.TestCase):
    def test_guest_reads_and_faults_match_native_reconstruction(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory)
            manifest=json.loads((ROOT/'examples/sysread_session_entry.json').read_bytes())
            # Real reads, invalid range, invalid descriptor, EOF, and no-backend zero count.
            requests=[(3,4,10,2),(4,2,10,4),(3,2,10,7),(0,1,10,0),(3,2,10,6),(0,0,0,0)]
            manifest['calls']=[{'syscall':'SysRead','fd':fd,'count':count,'buffer':{'object':obj,'offset':offset}}
                               for fd,count,obj,offset in requests]
            entry=stage/'entry.json'; entry.write_text(json.dumps(manifest))
            for label,data,expected in [('payload',b'0123456789XYZpq',[4,1,-14,-9,0,0]),
                                        ('empty',b'0123456789',[0,0,-14,-9,0,0])]:
                with self.subTest(label=label):
                    fixture=stage/(label+'.bin'); fixture.write_bytes(data)
                    output=stage/label
                    result=subprocess.run([sys.executable,str(ROOT/'tools/qemu_sysread_demo.py'),
                        '--kernel-root',KERNEL,'--clang',CLANG,'--qemu',QEMU,'--compiler',COMPILER,
                        '--entry',str(entry),'--input',str(fixture),'--out',str(output)],
                        text=True,capture_output=True,timeout=180)
                    self.assertEqual(result.returncode,0,result.stderr)
                    report=json.loads((output/'report.json').read_bytes())
                    self.assertTrue(report['guest_native_observations_match'])
                    self.assertEqual(report['raw_returns'],expected)
                    self.assertEqual(report['calls'],6)
                    self.assertFalse(report['guest_mmu'])
                    self.assertFalse(report['scheduler_irq_execution'])
                    self.assertEqual(fixture.read_bytes(),data)
                    described=json.loads(subprocess.check_output([str(output/'replay'),'--describe']))
                    self.assertEqual(described['capture']['read_source']['kind'],'qemu')
                    captured=described['capture']
                    self.assertEqual(captured['expected'][2]['errno'],14)
                    self.assertEqual(captured['expected'][3]['errno'],9)
                    if label=='payload':
                        self.assertEqual(captured['expected'][-1]['memory'],'0011585971706677')
                    else:
                        self.assertEqual(captured['expected'][-1]['memory'],'0011223344556677')

if __name__=='__main__': unittest.main()
