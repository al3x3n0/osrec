"""Real file capture, C-hook interoperability and incomplete stream rejection."""
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
KERNEL,COMPILER,HOOK=sys.argv[1:4]
sys.argv=sys.argv[:1]
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from syscall_checkpoint import identity, validate_entry
from read_observations import context_hash, decode

class ReadTests(unittest.TestCase):
    def run_tool(self,*args):
        result=subprocess.run([sys.executable,*map(str,args)],capture_output=True,text=True,timeout=90)
        self.assertEqual(result.returncode,0,result.stderr)
        return result

    def test_real_file_to_independent_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory)
            entry=stage/'entry.json'; shutil.copy2(ROOT/'examples/sysread_session_entry.json',entry)
            data=stage/'device-data'; data.write_bytes(b'0123456789ABCDE')
            wire=stage/'reads.osrec'; capture=stage/'capture.json'; binary=stage/'scenario'
            self.run_tool(ROOT/'tools/record_host_reads.py','--kernel-root',KERNEL,'--entry',entry,'--file',f'20={data}','--out',wire)
            self.run_tool(ROOT/'tools/syscall_checkpoint.py','capture','--kernel-root',KERNEL,'--compiler',COMPILER,
                          '--case',entry,'--reads',wire,'--source-kind','host-file','--out',capture)
            document=json.loads(capture.read_bytes())
            self.assertEqual([o['raw'] for o in document['expected']],[4,1,0,0])
            self.assertEqual([o['file_positions']['20'] for o in document['expected']],[14,15,15,15])
            self.assertEqual(document['expected'][-1]['memory'],'0011414245446677')
            self.assertEqual(document['read_source']['kind'],'host-file')
            self.assertNotIn('environment',document)
            self.run_tool(ROOT/'tools/syscall_checkpoint.py','export','--kernel-root',KERNEL,'--compiler',COMPILER,
                          '--capture',capture,'--out',binary)
            with tempfile.TemporaryDirectory() as isolated:
                copied=Path(isolated)/'scenario'; shutil.copy2(binary,copied)
                data.unlink(); wire.unlink(); entry.unlink(); capture.unlink()
                output=subprocess.check_output([str(copied)],cwd=isolated,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},text=True)
                self.assertEqual(output.strip(),'syscall session verified: 4 calls')
                self.assertEqual(list(Path(isolated).iterdir()),[copied])

    def test_c_hook_stream_and_binding_failures(self):
        case=json.loads((ROOT/'examples/sysread_session_entry.json').read_bytes())
        objects=validate_entry(case['entry'],case['calls'])
        bound=context_hash(case['entry'],case['calls'],identity(Path(KERNEL))[0])
        with tempfile.TemporaryDirectory() as directory:
            wire=Path(directory)/'hook.osrec'
            subprocess.run([HOOK,str(wire),bound],check=True)
            raw=wire.read_bytes()
            outcomes=decode(raw,bound,case['entry'],case['calls'],objects)
            self.assertEqual(outcomes[:3],[{'result':2,'errno':0,'payload':'4142'},
                                         {'result':0,'errno':0,'payload':''},
                                         {'result':-1,'errno':11,'payload':''}])
            self.assertEqual(outcomes[3],{'result':0,'errno':0,'payload':''})
            # Header 8 + BEGIN 76 + EXTERNAL header 12; first argument at 96.
            bad_invocation=bytearray(raw); struct.pack_into('<Q',bad_invocation,96,1)
            bad_size=bytearray(raw); struct.pack_into('<Q',bad_size,96+56,3)
            variants=[raw[:-1],raw+b'x',raw[:84]+raw[162:],bytes(bad_invocation),bytes(bad_size)]
            for damaged in variants:
                with self.subTest(length=len(damaged)):
                    with self.assertRaises(ValueError): decode(damaged,bound,case['entry'],case['calls'],objects)
            with self.assertRaises(ValueError): decode(raw,'0'*64,case['entry'],case['calls'],objects)
            # Import the C hook's EAGAIN outcome through the actual kernel-body pipeline.
            entry=Path(directory)/'entry.json'; entry.write_text(json.dumps(case))
            capture=Path(directory)/'capture.json'
            self.run_tool(ROOT/'tools/syscall_checkpoint.py','capture','--kernel-root',KERNEL,'--compiler',COMPILER,
                          '--case',entry,'--reads',wire,'--source-kind','emulator','--out',capture)
            document=json.loads(capture.read_bytes())
            self.assertEqual([o['raw'] for o in document['expected']],[2,0,-11,0])
            self.assertEqual([o['errno'] for o in document['expected']],[0,0,11,11])
            original=capture.read_bytes()
            for damaged in variants:
                wire.write_bytes(damaged)
                result=subprocess.run([sys.executable,str(ROOT/'tools/syscall_checkpoint.py'),'capture',
                    '--kernel-root',KERNEL,'--compiler',COMPILER,'--case',str(entry),'--reads',str(wire),
                    '--source-kind','emulator','--out',str(capture)],capture_output=True,text=True,timeout=90)
                self.assertNotEqual(result.returncode,0,result.stdout)
                self.assertEqual(capture.read_bytes(),original)
            binary=Path(directory)/'scenario'
            self.run_tool(ROOT/'tools/syscall_checkpoint.py','export','--kernel-root',KERNEL,'--compiler',COMPILER,
                          '--capture',capture,'--out',binary)

if __name__=='__main__': unittest.main()
