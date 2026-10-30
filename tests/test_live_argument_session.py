"""One native locked helper batch; one reconstructed object across all calls."""
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
from reconstruct_entry_state import reconstruction_header
from freestanding_armv7 import run
from freestanding_elf import prepare_target
from run_freestanding_armv7 import observe,require_success
from live_argument_state import profile_settings,prepare_source,load_capture,export
from live_argument_effects import SESSION_PROFILE as PROFILE,SESSION_SIGNALS as SIGNALS,validate_capture,parse_capture
from klee_liteos import digest

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'


class LiveArgumentSessionTests(unittest.TestCase):
    def fixture(self,stage,initial=0x80000000):
        s=profile_settings(PROFILE);body,_=prepare_source(ROOT/'build/kernel_liteos_a',PROFILE)
        source=stage/'input.c';source.write_text(s['model']+body)
        database=stage/'compile_commands.json';database.write_text(json.dumps([{'directory':str(stage),
            'file':str(source),'arguments':[str(LLVM/'clang'),'-std=c11','-c',str(source)]}]))
        tree,_=load_ast(database,source)
        plan=Analyzer(tree,argument_objects=json.loads(s['policy'].read_text())['argument_objects']).analyze(s['helper'])
        frames=[];effects=[];witness=bytearray();value=initial
        for i,signal in enumerate(SIGNALS):
            after=value|(signal&127)
            entry={'format':'osrec-entry-snapshot-v1','syscall':s['route'],'invocation':i,
                'objects':[{'id':1,'session_id':9,'type':'LosProcessCB'}],
                'roots':[{'name':'osrec_argument_processCB()','object_id':1}],
                'fields':[{'object_id':1,'name':'exitCode','kind':'scalar','bytes':4,'data':value.to_bytes(4,'little').hex()}],
                'arguments':[{'name':'signal','bytes':4,'data':signal.to_bytes(4,'little').hex()}]}
            post=copy.deepcopy(entry);post['fields'][0]['data']=after.to_bytes(4,'little').hex()
            frames.append(entry);effects.append(post);witness+=struct.pack('<4I',i,signal,value,after);value=after
        witness+=struct.pack('<3I',initial,value,initial)
        return plan,frames,effects,bytes(witness),body

    def test_single_initialization_preserves_nonzero_native_model_state(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);plan,entries,effects,witness,body=self.fixture(stage)
            calls=validate_capture(entries,effects,plan,witness,PROFILE)
            self.assertEqual([c['after'] for c in calls],[0x80000000|v for v in (1,3,3,7,15,31)])
            header=reconstruction_header(entries,[plan]*6,post_states=effects,scalar_arguments=True,continuous=True)
            source=stage/'session.c';source.write_text(profile_settings(PROFILE)['model']+header+body+'''int main(void){
 if(!osrec_restore(0) || osrec_restore(1)) return 1;
 for(unsigned i=0;i<6;++i){
  if(!osrec_entry_matches(i)) return 2;
  OsProcessExitCodeSignalSet(osrec_bound_osrec_argument_processCB,osrec_argument(i,1));
  if(!osrec_state_matches(i)) return 3;
 }
 return osrec_bound_osrec_argument_processCB->exitCode!=0x8000001fU;
}''')
            binary=stage/'session';run([LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary]);run([binary])
            # Invocation-local IDs may change without changing capture-scoped identity.
            for i,(entry,post) in enumerate(zip(entries,effects)):
                for frame in (entry,post):
                    frame['objects'][0]['id']=i+1;frame['roots'][0]['object_id']=i+1;frame['fields'][0]['object_id']=i+1
            validate_capture(entries,effects,plan,witness,PROFILE)

    def test_session_discontinuities_and_boundary_corruptions_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);plan,entries,effects,witness,_=self.fixture(stage,0)
            for change in ('missing','order','signal','identity','initial','final','restore','length','old_format','route','missing_write'):
                p=copy.deepcopy(plan);f=copy.deepcopy(entries);e=copy.deepcopy(effects);w=bytearray(witness)
                if change=='missing':e.pop()
                if change=='order':f[0],f[1]=f[1],f[0]
                if change=='signal':f[0]['arguments'][0]['data']='02000000'
                if change=='identity':e[1]['objects'][0]['session_id']=10
                if change=='initial':struct.pack_into('<I',w,96,1)
                if change=='final':struct.pack_into('<I',w,100,0)
                if change=='restore':struct.pack_into('<I',w,104,1)
                if change=='length':w.pop()
                if change=='old_format':w+=b'\0'*12
                if change=='route':f[0]['syscall']=65538
                if change=='missing_write':p['state_writes']=[]
                with self.subTest(change=change),self.assertRaises(ValueError):validate_capture(f,e,p,bytes(w),PROFILE)
            # Make every call locally consistent, but insert a state change between calls.
            f=copy.deepcopy(entries);e=copy.deepcopy(effects);w=bytearray(witness)
            for i in range(2,6):
                for frame in (f[i],e[i]):
                    row=frame['fields'][0];v=int.from_bytes(bytes.fromhex(row['data']),'little')|256;row['data']=v.to_bytes(4,'little').hex()
                before=int.from_bytes(bytes.fromhex(f[i]['fields'][0]['data']),'little')
                after=int.from_bytes(bytes.fromhex(e[i]['fields'][0]['data']),'little')
                struct.pack_into('<2I',w,16*i+8,before,after)
            struct.pack_into('<I',w,100,287)
            with self.assertRaisesRegex(ValueError,'previous post-state'):validate_capture(f,e,plan,bytes(w),PROFILE)
            log='\n'.join('OSREC_ARGUMENT_ENTRY '+json.dumps(f) for f in entries)+'\n'+\
                '\n'.join('OSREC_ARGUMENT_EFFECT '+json.dumps(f) for f in effects)+'\nOSREC_ARGUMENT_KERNEL '+witness.hex()+'\n'
            self.assertEqual(parse_capture(log,plan,PROFILE),(entries,effects,witness))
            with self.assertRaises(ValueError):parse_capture(log,plan,'exit-signal-write')

    def test_live_continuous_elf_raw_and_initialization_mutants(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture'
            completed=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),
                '--argument-write-session','--out',str(capture)],capture_output=True,text=True,timeout=240)
            self.assertEqual(completed.returncode,0,completed.stdout+completed.stderr)
            header,entries,calls,_,_,_=load_capture(capture,ROOT/'build/kernel_liteos_a')
            self.assertEqual([c['before'] for c in calls],[0,1,3,3,7,15])
            self.assertEqual([c['after'] for c in calls],[1,3,3,7,15,31]);self.assertNotIn('restored',calls[0])
            self.assertIn('#define OSREC_CONTINUOUS_REPLAY 1',header)
            report_path=capture/'report.json';original_report=report_path.read_bytes();r=json.loads(original_report)
            for change in ('contract','lifetime','restoration'):
                bad=copy.deepcopy(r)
                if change=='contract':del bad['argument_entry_capture']['session_contract']
                if change=='lifetime':bad['automated_session_identity']['stable_lifetimes_for_syscalls']=[60]
                if change=='restoration':bad['argument_entry_capture']['session_contract']['restoration']='after_each_call'
                report_path.write_text(json.dumps(bad))
                with self.subTest(change=change),self.assertRaises(ValueError):load_capture(capture,ROOT/'build/kernel_liteos_a')
            report_path.write_bytes(original_report)
            # A consistent rehashed chain still must match the retained native log.
            entry_path=capture/'entry-state-snapshots.json';post_path=capture/'entry-state-effects.json';wpath=capture/'argument-entry-kernel.bin'
            eraw=entry_path.read_bytes();praw=post_path.read_bytes();wraw=wpath.read_bytes()
            for path,raw in ((entry_path,eraw),(post_path,praw)):
                bundle=json.loads(raw)
                for frame in bundle['snapshots']:
                    if frame['syscall']==65539:
                        field=frame['fields'][0];v=int.from_bytes(bytes.fromhex(field['data']),'little')|256
                        field['data']=v.to_bytes(4,'little').hex()
                path.write_text(json.dumps(bundle))
            w=bytearray(wraw)
            for offset in [i*16+j for i in range(6) for j in (8,12)]+[96,100,104]:
                v=struct.unpack_from('<I',w,offset)[0];struct.pack_into('<I',w,offset,v|256)
            wpath.write_bytes(w);bad=copy.deepcopy(r)
            bad['automated_capture_hashes']['snapshots']=digest(entry_path.read_bytes());bad['automated_capture_hashes']['effects']=digest(post_path.read_bytes())
            bad['argument_entry_capture']['sha256']=digest(wpath.read_bytes());report_path.write_text(json.dumps(bad))
            with self.assertRaisesRegex(ValueError,'native log'):load_capture(capture,ROOT/'build/kernel_liteos_a')
            entry_path.write_bytes(eraw);post_path.write_bytes(praw);wpath.write_bytes(wraw);report_path.write_bytes(original_report)
            outputs=[]
            for address in (0x40200000,0x40400000):
                args=SimpleNamespace(capture=capture,kernel_root=ROOT/'build/kernel_liteos_a',llvm_bin=LLVM,qemu=QEMU,
                    arch='aarch64',entry_address=address,result_address=address-0x80000,out=stage/str(address))
                report=export(args);obs=report['target_observations']
                self.assertEqual((obs['states_restored'],obs['entry_states_checked'],obs['states_verified']),(1,6,6))
                self.assertTrue(obs['continuous_replay']);self.assertFalse(report['entry_states_restored_independently'])
                self.assertTrue(report['native_field_restored_after_session']);outputs.append(args.out)
            sources=outputs[0]/'sources';adapter=sources/'entry_adapter.h';runner=sources/'entry_state_replay.c'
            original_adapter=adapter.read_text();original_runner=runner.read_text()
            args=SimpleNamespace(arch='aarch64',entry_address=0x40200000,result_address=0x40180000);flags=prepare_target(args,sources)
            call='OsProcessExitCodeSignalSet(osrec_bound_osrec_argument_processCB,osrec_argument(osrec_invocation,1));'
            for change,error in (('reset',21),('omit',20),('wrong_argument',20),('restore_again',1),('entry_corruption',41)):
                a=original_adapter;c=original_runner
                if change=='reset':a=a.replace(call,'if(osrec_invocation) osrec_bound_osrec_argument_processCB->exitCode=0;'+call)
                if change=='omit':a=a.replace(call,'(void)osrec_argument(osrec_invocation,1);')
                if change=='wrong_argument':a=a.replace('osrec_argument(osrec_invocation,1)','osrec_argument(osrec_invocation,0)')
                if change=='restore_again':c=c.replace('if(!OSREC_CONTINUOUS_REPLAY || i==0)','if(1)')
                if change=='entry_corruption':c=c.replace('if(!osrec_entry_matches(i))',
                    'if(i==1) osrec_bound_osrec_argument_processCB->exitCode^=128U; if(!osrec_entry_matches(i))')
                self.assertTrue(a!=original_adapter or c!=original_runner)
                adapter.write_text(a);runner.write_text(c);image=stage/(change+'.elf')
                run([LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                    '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
                    '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',runner,'-o',image])
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
