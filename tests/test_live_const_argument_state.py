"""Const-qualified original kernel helper discovery, native capture and replay."""
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
from entry_state import Analyzer,load_ast
from live_argument_state import profile_settings,prepare_source,validate_capture,load_capture,export
from freestanding_armv7 import run
from freestanding_elf import prepare_target
from run_freestanding_armv7 import observe,require_success

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64';PROFILE='process-group-leader'


class LiveConstArgumentTests(unittest.TestCase):
    def test_const_helper_source_and_synthetic_status_boundaries(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);s=profile_settings(PROFILE)
            source,identity=prepare_source(ROOT/'build/kernel_liteos_a',PROFILE)
            path=stage/'helper.c';path.write_text(s['model']+source)
            database=stage/'compile_commands.json';database.write_text(json.dumps([{'directory':str(stage),
                'file':str(path),'arguments':[str(LLVM/'clang'),'-std=c11','-c',str(path)]}]))
            tree,_=load_ast(database,path);policy=json.loads(s['policy'].read_text())['argument_objects']
            plan=Analyzer(tree,argument_objects=policy).analyze(s['helper'])
            self.assertEqual(plan['arguments'][0]['type'],'const LosProcessCB *')
            values=[0,0x800,0x801,0xffff,0x400,0x8800];expected=[0,1,1,1,0,1]
            frames=[{'format':'osrec-entry-snapshot-v1','syscall':s['route'],'invocation':i,
                'objects':[{'id':1,'session_id':8,'type':'LosProcessCB'}],
                'roots':[{'name':'osrec_argument_processCB()','object_id':1}],
                'fields':[{'object_id':1,'name':'processStatus','kind':'scalar','bytes':2,'data':v.to_bytes(2,'little').hex()}]} for i,v in enumerate(values)]
            witness=b''.join(struct.pack('<3I',i,v,r) for i,(v,r) in enumerate(zip(values,expected)))
            self.assertEqual([c['raw_bits'] for c in validate_capture(frames,plan,witness,PROFILE)],expected)
            for change in ('width','const','profile','result','wide_value','state_write','unsafe'):
                f=copy.deepcopy(frames);p=copy.deepcopy(plan);w=bytearray(witness)
                if change=='width':f[0]['fields'][0].update(bytes=4,data='00000000')
                if change=='const':p['object_providers'][0]['return_type']='LosProcessCB *'
                if change=='result':w[8]=1
                if change=='wide_value':struct.pack_into('<I',w,4,65536)
                if change=='state_write':p['state_writes']=copy.deepcopy(p['entry_reads'])
                if change=='unsafe':p['object_providers'][0]['contract']['snapshot_safe']=False
                with self.subTest(change=change),self.assertRaises(ValueError):
                    validate_capture(f,p,bytes(w),'exit-code' if change=='profile' else PROFILE)
            path.write_text(s['model']+source+'''int main(void){
 uint16_t values[6]={0,0x800,0x801,0xffff,0x400,0x8800};unsigned expected[6]={0,1,1,1,0,1};
 for(unsigned i=0;i<6;++i){LosProcessCB p={values[i]};if(OsProcessIsPGroupLeader(&p)!=expected[i]) return 1;}
 return 0;
}''')
            binary=stage/'reference';run([LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror',path,'-o',binary]);run([binary])
            rejected=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),
                '--const-argument-entry-state','--argument-entry-state','--out',str(stage/'bad')],capture_output=True,text=True)
            self.assertEqual(rejected.returncode,2);self.assertFalse((stage/'bad').exists())

    def test_live_const_capture_and_relocated_elf_raw_replay(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture'
            completed=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),
                '--const-argument-entry-state','--out',str(capture)],capture_output=True,text=True,timeout=240)
            self.assertEqual(completed.returncode,0,completed.stdout+completed.stderr)
            report=json.loads((capture/'report.json').read_text());self.assertEqual(report['argument_entry_capture']['profile'],PROFILE)
            header,frames,calls,_,_,_=load_capture(capture,ROOT/'build/kernel_liteos_a')
            self.assertIn('static const LosProcessCB * osrec_bound_osrec_argument_processCB;',header)
            self.assertEqual(len(frames),6);self.assertEqual({f['fields'][0]['bytes'] for f in frames},{2})
            self.assertEqual([c['raw_bits'] for c in calls],[int(bool(c['process_status']&2048)) for c in calls])
            outputs=[]
            for address in (0x40200000,0x40400000):
                args=SimpleNamespace(capture=capture,kernel_root=ROOT/'build/kernel_liteos_a',llvm_bin=LLVM,qemu=QEMU,
                    arch='aarch64',entry_address=address,result_address=address-0x80000,out=stage/str(address))
                verified=export(args);self.assertEqual(verified['target_observations']['completed_calls'],6)
                self.assertEqual(verified['profile'],PROFILE);self.assertTrue(verified['raw_image_execution_match']);outputs.append(args.out)
            # Mutate owned replay storage without casting away the const binding.
            sources=outputs[0]/'sources';adapter=sources/'entry_adapter.h';original=adapter.read_text()
            reconstruction=(sources/'entry_reconstruction.h').read_text()
            self.assertIn('osrec_frame_0_object_1',reconstruction)
            args=SimpleNamespace(arch='aarch64',entry_address=0x40200000,result_address=0x40180000)
            flags=prepare_target(args,sources)
            for change,error in (('return',10),('state',20)):
                modified=original.replace('return (uint32_t)OsProcessIsPGroupLeader(',
                    'return 1U+(uint32_t)OsProcessIsPGroupLeader(') if change=='return' else original.replace(
                    'return (uint32_t)OsProcessIsPGroupLeader(',
                    'osrec_frame_0_object_1.processStatus^=0x4000U; return (uint32_t)OsProcessIsPGroupLeader(')
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
