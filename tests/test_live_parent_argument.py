"""Live nested scalar writes: explicit adapter, original helper, two processes."""
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
from live_argument_state import profile_settings,prepare_source,load_capture,export
from live_argument_effects import validate_capture,SESSION_SIGNALS
from reconstruct_entry_state import reconstruction_header
from freestanding_armv7 import run,audit
from freestanding_elf import prepare_target
from run_freestanding_armv7 import observe,require_success
from klee_liteos import digest

PROFILE='parent-exit-signal-session';LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'

class ParentArgumentTests(unittest.TestCase):
    def fixture(self,stage):
        s=profile_settings(PROFILE);body,identity=prepare_source(ROOT/'build/kernel_liteos_a',PROFILE)
        source=stage/'input.c';source.write_text(s['model']+body)
        database=stage/'compile_commands.json';database.write_text(json.dumps([{'directory':str(stage),
            'file':str(source),'arguments':[str(LLVM/'clang'),'-std=c11','-c',str(source)]}]))
        tree,_=load_ast(database,source)
        plan=Analyzer(tree,argument_objects=json.loads(s['policy'].read_text())['argument_objects']).analyze(s['helper'])
        entries=[];posts=[];witness=bytearray();value=0x80000000
        for i,signal in enumerate(SESSION_SIGNALS):
            after=value|(signal&127)
            entry={'format':'osrec-entry-snapshot-v1','syscall':s['route'],'invocation':i,
                'objects':[{'id':1,'session_id':9,'type':'LosProcessCB'},{'id':2,'session_id':10,'type':'struct ProcessCB'}],
                'roots':[{'name':'osrec_argument_processCB()','object_id':1}],
                'fields':[{'object_id':1,'name':'parentProcess','kind':'edge','target_id':2},
                          {'object_id':2,'name':'exitCode','kind':'scalar','bytes':4,'data':value.to_bytes(4,'little').hex()}],
                'arguments':[{'name':'signal','bytes':4,'data':signal.to_bytes(4,'little').hex()}]}
            post=copy.deepcopy(entry);post['fields'][1]['data']=after.to_bytes(4,'little').hex()
            entries.append(entry);posts.append(post);witness+=struct.pack('<4I',i,signal,value,after);value=after
        witness+=struct.pack('<5I',0x80000000,value,0x80000000,3,1)
        return plan,entries,posts,bytes(witness),body,identity

    def test_original_helper_and_nested_nonzero_state(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);p,e,x,w,body,identity=self.fixture(stage)
            self.assertEqual(identity['function'],'OsProcessExitCodeSignalSet')
            self.assertEqual(identity['capture_root'],'OsrecParentExitSignalSet')
            calls=validate_capture(e,x,p,w,PROFILE)
            self.assertEqual([c['after'] for c in calls],[0x80000000|n for n in (1,3,3,7,15,31)])
            # Local IDs may change while each object's capture identity persists.
            for i,(entry,post) in enumerate(zip(e,x)):
                ids={1:2*i+11,2:2*i+12}
                for state in (entry,post):
                    for obj in state['objects']:obj['id']=ids[obj['id']]
                    state['roots'][0]['object_id']=ids[1]
                    for field in state['fields']:
                        field['object_id']=ids[field['object_id']]
                        if field['kind']=='edge':field['target_id']=ids[field['target_id']]
            validate_capture(e,x,p,w,PROFILE)
            header=reconstruction_header(e,[p]*6,post_states=x,scalar_arguments=True,continuous=True)
            source=stage/'replay.c';source.write_text(profile_settings(PROFILE)['model']+header+body+'''int main(void){
 if(!osrec_restore(0) || osrec_restore(1))return 1;
 for(unsigned i=0;i<6;++i){if(!osrec_entry_matches(i))return 2;
  OsrecParentExitSignalSet(osrec_bound_osrec_argument_processCB,osrec_argument(i,1));
  if(!osrec_state_matches(i))return 3;}
 return osrec_bound_osrec_argument_processCB->parentProcess->exitCode!=0x8000001fU;
}''')
            binary=stage/'replay';run([LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary]);run([binary])

    def test_graph_schema_and_native_boundaries_reject(self):
        with tempfile.TemporaryDirectory() as name:
            p,e,x,w,_,_=self.fixture(Path(name))
            changes=('null_root','null','alias','wrong_owner','post_edge','session','missing_session','type','width',
                     'root_pid','parent_pid','restore','length','missing_write','missing_call','signal','route')
            for change in changes:
                plan,entries,posts,raw=copy.deepcopy((p,e,x,bytearray(w)))
                if change=='null_root':entries[0]['roots'][0]['object_id']=0
                elif change=='null':entries[0]['fields'][0]['target_id']=0
                elif change=='alias':entries[0]['fields'][0]['target_id']=1
                elif change=='wrong_owner':posts[0]['fields'][1]['object_id']=1
                elif change=='post_edge':posts[0]['fields'][0]['target_id']=1
                elif change=='session':posts[0]['objects'][1]['session_id']=9
                elif change=='missing_session':entries[0]['objects'][1].pop('session_id')
                elif change=='type':entries[0]['objects'][1]['type']='User'
                elif change=='width':entries[0]['fields'][1].update(bytes=2,data='0000')
                elif change=='root_pid':struct.pack_into('<I',raw,108,1)
                elif change=='parent_pid':struct.pack_into('<I',raw,112,2)
                elif change=='restore':struct.pack_into('<I',raw,104,0)
                elif change=='length':raw.pop()
                elif change=='missing_write':plan['state_writes']=[]
                elif change=='missing_call':plan['call_sites']=[]
                elif change=='signal':entries[0]['arguments'][0]['data']='02000000'
                elif change=='route':entries[0]['syscall']=65539
                with self.subTest(change=change),self.assertRaises(ValueError):validate_capture(entries,posts,plan,bytes(raw),PROFILE)
            # Locally valid updates do not admit a hidden inter-call mutation.
            entries,posts,raw=copy.deepcopy((e,x,bytearray(w)))
            for i in range(2,6):
                for state in (entries[i],posts[i]):
                    scalar=state['fields'][1];v=int.from_bytes(bytes.fromhex(scalar['data']),'little')|256
                    scalar['data']=v.to_bytes(4,'little').hex()
                before=int.from_bytes(bytes.fromhex(entries[i]['fields'][1]['data']),'little')
                after=int.from_bytes(bytes.fromhex(posts[i]['fields'][1]['data']),'little')
                struct.pack_into('<2I',raw,16*i+8,before,after)
            struct.pack_into('<I',raw,100,0x8000011f)
            with self.assertRaisesRegex(ValueError,'previous post-state'):validate_capture(entries,posts,p,bytes(raw),PROFILE)
            with self.assertRaises(ValueError):validate_capture(e,x,p,w,'exit-signal-session')

    def test_live_capture_provenance_and_standalone_replay(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture'
            result=subprocess.run([sys.executable,ROOT/'tools/liteos_qemu_demo.py','--parent-argument-session',
                '--out',capture],capture_output=True,text=True,timeout=240)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            header,entries,calls,_,_,identity=load_capture(capture,ROOT/'build/kernel_liteos_a')
            self.assertEqual([c['after'] for c in calls],[1,3,3,7,15,31])
            self.assertEqual({len(e['objects']) for e in entries},{2})
            report= json.loads((capture/'report.json').read_text());original=copy.deepcopy(report)
            for change in ('parent_contract','lifetime','adapter'):
                report=copy.deepcopy(original)
                if change=='parent_contract':report['argument_entry_capture'].pop('parent_contract')
                elif change=='lifetime':report['automated_session_identity']['stable_lifetimes_for_syscalls'].remove(65540)
                else:report['argument_entry_capture']['source_identity']['capture_adapter_sha256']='0'*64
                (capture/'report.json').write_text(json.dumps(report))
                with self.subTest(metadata=change),self.assertRaises(ValueError):load_capture(capture,ROOT/'build/kernel_liteos_a')
            (capture/'report.json').write_text(json.dumps(original))
            # Rehash the helper witness and log consistently. Separate native
            # task observations must still reject a forged child process ID.
            witness=(capture/'argument-entry-kernel.bin').read_bytes();log=(capture/'boot.log').read_bytes()
            forged=bytearray(witness);struct.pack_into('<I',forged,108,struct.unpack_from('<I',witness,108)[0]+1)
            forged_log=log.replace(witness.hex().encode(),forged.hex().encode())
            (capture/'argument-entry-kernel.bin').write_bytes(forged);(capture/'boot.log').write_bytes(forged_log)
            report=copy.deepcopy(original);report['boot_log_sha256']=digest(forged_log);report['argument_entry_capture']['sha256']=digest(forged)
            (capture/'report.json').write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError,'native task observations'):load_capture(capture,ROOT/'build/kernel_liteos_a')
            (capture/'argument-entry-kernel.bin').write_bytes(witness);(capture/'boot.log').write_bytes(log)
            (capture/'report.json').write_text(json.dumps(original))
            outputs=[]
            for address in (0x40200000,0x40400000):
                args=SimpleNamespace(capture=capture,kernel_root=ROOT/'build/kernel_liteos_a',llvm_bin=LLVM,qemu=QEMU,
                    arch='aarch64',entry_address=address,result_address=address-0x80000,out=stage/hex(address))
                m=export(args);o=m['target_observations'];self.assertEqual((o['states_restored'],o['entry_states_checked'],o['states_verified']),(1,6,6))
                self.assertTrue(m['nested_scalar_write_effects']);self.assertEqual(m['original_helper'],identity['function']);outputs.append(args.out)
            sources=outputs[0]/'sources';adapter=sources/'entry_adapter.h';body=adapter.read_text()
            flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40200000,result_address=0x40180000),sources)
            mutants=[body.replace('OsProcessExitCodeSignalSet(processCB->parentProcess, signal);','OsProcessExitCodeSignalSet(processCB, signal);'),
                     body.replace('processCB->exitCode |= signal & 0x7FU;','(void)processCB; (void)signal;'),
                     body.replace(' ++osrec_invocation;',
                         ' osrec_bound_osrec_argument_processCB->parentProcess=osrec_bound_osrec_argument_processCB; ++osrec_invocation;')]
            for i,mutant in enumerate(mutants):
                self.assertNotEqual(mutant,body);adapter.write_text(mutant);image=stage/('mutant'+str(i)+'.elf')
                run([LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                    '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
                    '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c','-o',image])
                audit(image,LLVM);failed,_=observe(image,QEMU);self.assertEqual((failed['status'],failed['error']),(3,20))
            shutil.rmtree(capture)
            for output in outputs:
                shutil.rmtree(output/'sources')
                result,raw=observe(output/'arguments.elf',QEMU);require_success(result)
                other,raw_binary=observe(output/'arguments.bin',QEMU,descriptor=output/'arguments.elf');require_success(other)
                self.assertEqual(raw,raw_binary)

if __name__=='__main__':
    if len(sys.argv)==3:LLVM=Path(sys.argv[1]);QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
