"""Live kernel argument snapshots, provenance checks and standalone replay."""
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
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,load_ast
from freestanding_armv7 import run
from freestanding_elf import prepare_target
from run_freestanding_armv7 import observe,require_success
from live_argument_state import (HELPER,ROUTE,MODEL,ARGUMENT_POLICY,prepare_source,
    SOURCE_LOCK,validate_capture,parse_capture,load_capture,export)
from klee_liteos import digest

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'


class LiveArgumentTests(unittest.TestCase):
    def test_profile_exclusions_and_source_pins(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for option in ('--getgroups','--async-wait','--file-operations'):
                output=stage/option[2:]
                completed=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),
                    '--argument-entry-state',option,'--out',str(output)],capture_output=True,text=True,timeout=30)
                self.assertEqual(completed.returncode,2)
                self.assertIn('requires the default live workload',completed.stderr)
                self.assertFalse(output.exists())
            lock=json.loads(SOURCE_LOCK.read_text());kernel=stage/'kernel'
            for file in lock['files']:
                dest=kernel/file;dest.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(ROOT/'build/kernel_liteos_a'/file,dest)
            for file in lock['files']:
                path=kernel/file;original=path.read_bytes();path.write_bytes(original+b'\n/* changed */\n')
                with patch('freestanding_armv7.run',return_value=SimpleNamespace(stdout=lock['revision'])):
                    with self.assertRaisesRegex(ValueError,'source/type changed'):prepare_source(kernel)
                path.write_bytes(original)

    def fixture(self,stage):
        body,identity=prepare_source(ROOT/'build/kernel_liteos_a')
        source=stage/'helper.c';source.write_text(MODEL+body)
        database=stage/'compile_commands.json';database.write_text(json.dumps([{
            'directory':str(stage),'file':str(source),'arguments':[str(LLVM/'clang'),'-std=c11','-c',str(source)]}]))
        tree,_=load_ast(database,source)
        plan=Analyzer(tree,argument_objects=json.loads(ARGUMENT_POLICY.read_text())['argument_objects']).analyze(HELPER)
        values=[0,1,127,128,0xffffffff,0x80000040]
        frames=[{'format':'osrec-entry-snapshot-v1','syscall':ROUTE,'invocation':i,
            'objects':[{'id':1,'session_id':9,'type':'LosProcessCB'}],
            'roots':[{'name':'osrec_argument_processCB()','object_id':1}],
            'fields':[{'object_id':1,'name':'exitCode','kind':'scalar','bytes':4,'data':v.to_bytes(4,'little').hex()}]} for i,v in enumerate(values)]
        witness=b''.join(struct.pack('<3I',i,v,v&0x7f) for i,v in enumerate(values))
        return plan,frames,witness,body

    def test_original_helper_nonzero_values_and_witness_rejections(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);plan,frames,witness,body=self.fixture(stage)
            calls=validate_capture(frames,plan,witness)
            self.assertEqual([c['raw_bits'] for c in calls],[0,1,127,0,127,64])
            # Compile the same pinned source body, rather than a replacement model.
            runner=stage/'reference.c';runner.write_text(MODEL+body+'''int main(void) {
 unsigned values[6]={0,1,127,128,0xffffffffU,0x80000040U};
 unsigned expected[6]={0,1,127,0,127,64};
 for(unsigned i=0;i<6;++i) {LosProcessCB p={values[i]};if(OsProcessExitCodeSignalIsSet(&p)!=expected[i]) return 1;}
 return 0;
}''')
            binary=stage/'reference';run([LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror',runner,'-o',binary]);run([binary])
            for change in ('value','raw','ordinal','length','duplicate','missing','session','null','extra','pointer','argument','policy','write','path'):
                f=copy.deepcopy(frames);p=copy.deepcopy(plan);w=bytearray(witness)
                if change=='value':w[4]^=1
                if change=='raw':w[8]^=1
                if change=='ordinal':w[0]=1
                if change=='length':w.pop()
                if change=='duplicate':f[1]['invocation']=0
                if change=='missing':f.pop()
                if change=='session':f[1]['objects'][0]['session_id']=10
                if change=='null':f[0]['roots'][0]['object_id']=0
                if change=='extra':f[0]['fields'].append({'object_id':1,'name':'other','kind':'scalar','bytes':4,'data':'00000000'})
                if change=='pointer':f[0]['fields'][0].update(kind='edge',target_id=1)
                if change=='argument':f[0]['arguments']=[{'name':'processCB','bytes':4,'data':'00000000'}]
                if change=='policy':p['object_providers'][0]['contract']['snapshot_safe']=False
                if change=='write':p['state_writes']=copy.deepcopy(p['entry_reads'])
                if change=='path':p['entry_reads'][0]['path']='osrec_argument_processCB()->other'
                with self.subTest(change=change),self.assertRaises(ValueError):validate_capture(f,p,bytes(w))
            log='\n'.join('OSREC_ARGUMENT_ENTRY '+json.dumps(f) for f in frames)+'\nOSREC_ARGUMENT_KERNEL '+witness.hex()+'\n'
            self.assertEqual(parse_capture(log,plan),(frames,witness))
            for bad in (log+'OSREC_ARGUMENT_KERNEL '+witness.hex()+'\n',log.replace('OSREC_ARGUMENT_KERNEL','WRONG_MARKER')):
                with self.assertRaises(ValueError):parse_capture(bad,plan)

    def test_live_capture_relocated_replay_provenance_and_runtime_mutants(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture'
            completed=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),
                '--argument-entry-state','--out',str(capture)],capture_output=True,text=True,timeout=240)
            self.assertEqual(completed.returncode,0,completed.stdout+completed.stderr)
            report=json.loads((capture/'report.json').read_text())
            self.assertEqual(report['argument_entry_capture']['calls'],6)
            self.assertTrue(report['automated_entry_state'])
            header,frames,calls,_,_,_=load_capture(capture,ROOT/'build/kernel_liteos_a')
            self.assertEqual(len(frames),6);self.assertEqual({c['exit_code'] for c in calls},{0})
            self.assertIn('osrec_bound_osrec_argument_processCB',header)
            snapshots=capture/'entry-state-snapshots.json';original=snapshots.read_bytes()
            for file,mutation in (
                ('argument-entry-kernel.bin',lambda b:b[:-1]),
                ('entry-state-snapshots.json',lambda b:b+b' '),
                ('boot.log',lambda b:b+b' ')):
                path=capture/file;raw=path.read_bytes();path.write_bytes(mutation(raw))
                with self.subTest(file=file),self.assertRaises(ValueError):load_capture(capture,ROOT/'build/kernel_liteos_a')
                path.write_bytes(raw)
            # Rehashing a mismatched native witness still cannot bypass the log check.
            witness_path=capture/'argument-entry-kernel.bin';witness=witness_path.read_bytes()
            value=bytearray(witness);value[4]=128  # Same helper return, changed input.
            bundle=json.loads(snapshots.read_text())
            row=next(f for f in bundle['snapshots'] if f['syscall']==ROUTE);row['fields'][0]['data']='80000000'
            snapshots.write_text(json.dumps(bundle));witness_path.write_bytes(value)
            metadata=copy.deepcopy(report);metadata['automated_capture_hashes']['snapshots']=digest(snapshots.read_bytes())
            metadata['argument_entry_capture']['sha256']=digest(bytes(value))
            (capture/'report.json').write_text(json.dumps(metadata))
            with self.assertRaisesRegex(ValueError,'native log'):load_capture(capture,ROOT/'build/kernel_liteos_a')
            snapshots.write_bytes(original);witness_path.write_bytes(witness)
            (capture/'report.json').write_text(json.dumps(report))
            outputs=[]
            for address in (0x40200000,0x40400000):
                args=SimpleNamespace(capture=capture,kernel_root=ROOT/'build/kernel_liteos_a',llvm_bin=LLVM,
                    qemu=QEMU,arch='aarch64',entry_address=address,result_address=address-0x80000,
                    out=stage/('image-'+hex(address)))
                verified=export(args);self.assertEqual(verified['target_observations']['completed_calls'],6)
                self.assertTrue(verified['raw_image_execution_match']);outputs.append(args.out)
            # Replay checks helper results and readonly state independently.
            sources=outputs[0]/'sources';adapter=sources/'entry_adapter.h';original_adapter=adapter.read_text()
            args=SimpleNamespace(arch='aarch64',entry_address=0x40200000,result_address=0x40180000)
            flags=prepare_target(args,sources)
            for change,error in (('return',10),('state',20)):
                if change=='return':modified=original_adapter.replace('return (uint32_t)OsProcessExitCodeSignalIsSet(', 'return 1U+(uint32_t)OsProcessExitCodeSignalIsSet(')
                else:modified=original_adapter.replace('return (uint32_t)OsProcessExitCodeSignalIsSet(',
                    'osrec_bound_osrec_argument_processCB->exitCode^=256U; return (uint32_t)OsProcessExitCodeSignalIsSet(')
                adapter.write_text(modified);image=stage/(change+'.elf')
                run([LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                    '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
                    '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c','-o',image])
                failed,_=observe(image,QEMU);self.assertEqual((failed['status'],failed['error']),(3,error))
            shutil.rmtree(capture)
            for output in outputs:
                shutil.rmtree(output/'sources')
                result,raw=observe(output/'arguments.elf',QEMU);require_success(result)
                other,raw_binary=observe(output/'arguments.bin',QEMU,descriptor=output/'arguments.elf');require_success(other)
                self.assertEqual(raw,raw_binary)


if __name__=='__main__':
    if len(sys.argv)==3:LLVM=Path(sys.argv[1]);QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
