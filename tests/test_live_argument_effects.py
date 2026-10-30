"""Original mutable helper: live entry/post discovery and controlled restoration."""
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
from freestanding_armv7 import run
from freestanding_elf import prepare_target
from run_freestanding_armv7 import observe,require_success
from live_argument_state import profile_settings,prepare_source,export,load_capture
from live_argument_effects import PROFILE,SIGNALS,validate_capture,parse_capture
from klee_liteos import digest

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'


class LiveArgumentEffectTests(unittest.TestCase):
    def fixture(self,stage):
        s=profile_settings(PROFILE);body,_=prepare_source(ROOT/'build/kernel_liteos_a',PROFILE)
        source=stage/'input.c';source.write_text(s['model']+body)
        database=stage/'compile_commands.json';database.write_text(json.dumps([{'directory':str(stage),
            'file':str(source),'arguments':[str(LLVM/'clang'),'-std=c11','-c',str(source)]}]))
        tree,_=load_ast(database,source)
        plan=Analyzer(tree,argument_objects=json.loads(s['policy'].read_text())['argument_objects']).analyze(s['helper'])
        before=[0,0x80,0xff00,0xffffffff,0x80000000,0x12345678]
        entries=[];effects=[];witness=bytearray()
        for i,(value,signal) in enumerate(zip(before,SIGNALS)):
            after=value|(signal&127)
            frame={'format':'osrec-entry-snapshot-v1','syscall':s['route'],'invocation':i,
                'objects':[{'id':1,'session_id':9,'type':'LosProcessCB'}],
                'roots':[{'name':'osrec_argument_processCB()','object_id':1}],
                'fields':[{'object_id':1,'name':'exitCode','kind':'scalar','bytes':4,'data':value.to_bytes(4,'little').hex()}],
                'arguments':[{'name':'signal','bytes':4,'data':signal.to_bytes(4,'little').hex()}]}
            post=copy.deepcopy(frame);post['fields'][0]['data']=after.to_bytes(4,'little').hex()
            entries.append(frame);effects.append(post);witness+=struct.pack('<5I',i,signal,value,after,value)
        return plan,entries,effects,bytes(witness),body

    def test_discovery_and_original_body_preserves_unselected_bits(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);plan,frames,effects,witness,body=self.fixture(stage)
            self.assertFalse(plan['blockers']);self.assertEqual(len(plan['state_writes']),1)
            self.assertEqual(plan['state_writes'][0]['path'],'osrec_argument_processCB()->exitCode')
            calls=validate_capture(frames,effects,plan,witness)
            s=profile_settings(PROFILE);source=stage/'reference.c'
            source.write_text(s['model']+body+'int main(void){\n'+''.join(
                ' {LosProcessCB p={UINT32_C('+str(c['before'])+')};OsProcessExitCodeSignalSet(&p,UINT32_C('+str(c['signal'])+'));if(p.exitCode!=UINT32_C('+str(c['after'])+'))return 1;}\n' for c in calls)+' return 0;}\n')
            binary=stage/'reference';run([LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary]);run([binary])
            for flag in ('--argument-entry-state','--const-argument-entry-state','--getgroups'):
                rejected=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),
                    '--argument-write-state',flag,'--out',str(stage/'bad')],capture_output=True,text=True)
                self.assertEqual(rejected.returncode,2);self.assertFalse((stage/'bad').exists())

    def test_entry_effect_argument_and_restoration_corruptions_reject(self):
        with tempfile.TemporaryDirectory() as name:
            plan,frames,effects,witness,_=self.fixture(Path(name))
            for change in ('entry','effect','signal','argument_index','pointer_bytes','missing_effect','post_order','post_identity',
                           'post_root','extra_field','missing_write','extra_read','const','width','witness_signal','witness_after','restore','length'):
                p=copy.deepcopy(plan);f=copy.deepcopy(frames);e=copy.deepcopy(effects);w=bytearray(witness)
                if change=='entry':f[0]['fields'][0]['data']='01000000'
                if change=='effect':e[0]['fields'][0]['data']='01000000'
                if change=='signal':f[1]['arguments'][0]['data']='02000000'
                if change=='argument_index':p['object_providers'][0]['argument_index']=1
                if change=='pointer_bytes':f[0]['arguments'].insert(0,{'name':'processCB','bytes':4,'data':'00000000'})
                if change=='missing_effect':e.pop()
                if change=='post_order':e[0],e[1]=e[1],e[0]
                if change=='post_identity':e[0]['objects'][0]['session_id']=10
                if change=='post_root':e[0]['roots'][0]['object_id']=0
                if change=='extra_field':e[0]['fields'].append({'object_id':1,'name':'other','kind':'scalar','bytes':4,'data':'00000000'})
                if change=='missing_write':p['state_writes']=[]
                if change=='extra_read':p['entry_reads'].append(copy.deepcopy(p['entry_reads'][0]))
                if change=='const':p['object_providers'][0]['return_type']='const LosProcessCB *'
                if change=='width':e[0]['fields'][0].update(bytes=2,data='0000')
                if change=='witness_signal':w[4]=1
                if change=='witness_after':w[12]=1
                if change=='restore':w[16]=1
                if change=='length':w.pop()
                with self.subTest(change=change),self.assertRaises(ValueError):validate_capture(f,e,p,bytes(w))
            log='\n'.join('OSREC_ARGUMENT_ENTRY '+json.dumps(f) for f in frames)+'\n'+\
                '\n'.join('OSREC_ARGUMENT_EFFECT '+json.dumps(f) for f in effects)+'\nOSREC_ARGUMENT_KERNEL '+witness.hex()+'\n'
            self.assertEqual(parse_capture(log,plan),(frames,effects,witness))
            with self.assertRaises(ValueError):parse_capture(log+'OSREC_ARGUMENT_KERNEL '+witness.hex()+'\n',plan)

    def test_live_original_write_replay_and_mutants(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);capture=stage/'capture'
            completed=subprocess.run([sys.executable,str(ROOT/'tools/liteos_qemu_demo.py'),
                '--argument-write-state','--out',str(capture)],capture_output=True,text=True,timeout=240)
            self.assertEqual(completed.returncode,0,completed.stdout+completed.stderr)
            header,frames,calls,_,_,_=load_capture(capture,ROOT/'build/kernel_liteos_a')
            self.assertEqual([c['before'] for c in calls],[0]*6)
            self.assertEqual([c['after'] for c in calls],[0,1,127,0,1,127])
            self.assertEqual([c['restored'] for c in calls],[0]*6)
            self.assertIn('#define OSREC_HAS_WRITE_EFFECTS 1',header)
            for file in ('entry-state-effects.json','argument-entry-kernel.bin'):
                path=capture/file;raw=path.read_bytes();path.write_bytes(raw+b' ')
                with self.subTest(file=file),self.assertRaises(ValueError):load_capture(capture,ROOT/'build/kernel_liteos_a')
                path.write_bytes(raw)
            report_path=capture/'report.json';original_report=report_path.read_bytes();r=json.loads(original_report)
            r['argument_entry_capture']['controlled_restore']=False;report_path.write_text(json.dumps(r))
            with self.assertRaises(ValueError):load_capture(capture,ROOT/'build/kernel_liteos_a')
            report_path.write_bytes(original_report)
            # A rehashed but mismatched post-state/witness cannot bypass the native log.
            entry_path=capture/'entry-state-snapshots.json';post_path=capture/'entry-state-effects.json';witness_path=capture/'argument-entry-kernel.bin'
            original_entry=entry_path.read_bytes();original_post=post_path.read_bytes();original_witness=witness_path.read_bytes()
            entry_bundle=json.loads(original_entry);post_bundle=json.loads(original_post)
            for bundle in (entry_bundle,post_bundle):
                f=next(f for f in bundle['snapshots'] if f['syscall']==65538);f['fields'][0]['data']='00010000'
            entry_path.write_text(json.dumps(entry_bundle));post_path.write_text(json.dumps(post_bundle))
            w=bytearray(original_witness)
            for offset in (8,12,16):struct.pack_into('<I',w,offset,256)
            witness_path.write_bytes(w)
            r=json.loads(original_report)
            r['automated_capture_hashes']['snapshots']=digest(entry_path.read_bytes());r['automated_capture_hashes']['effects']=digest(post_path.read_bytes())
            r['argument_entry_capture']['sha256']=digest(witness_path.read_bytes());report_path.write_text(json.dumps(r))
            with self.assertRaisesRegex(ValueError,'native log'):load_capture(capture,ROOT/'build/kernel_liteos_a')
            entry_path.write_bytes(original_entry);post_path.write_bytes(original_post);witness_path.write_bytes(original_witness);report_path.write_bytes(original_report)
            outputs=[]
            for address in (0x40200000,0x40400000):
                args=SimpleNamespace(capture=capture,kernel_root=ROOT/'build/kernel_liteos_a',llvm_bin=LLVM,qemu=QEMU,
                    arch='aarch64',entry_address=address,result_address=address-0x80000,out=stage/str(address))
                report=export(args);self.assertTrue(report['captured_scalar_write_effects'])
                self.assertEqual(report['target_observations']['completed_calls'],6);self.assertTrue(report['target_observations']['write_effects']);outputs.append(args.out)
            sources=outputs[0]/'sources';adapter=sources/'entry_adapter.h';original=adapter.read_text()
            args=SimpleNamespace(arch='aarch64',entry_address=0x40200000,result_address=0x40180000)
            flags=prepare_target(args,sources)
            invocation='OsProcessExitCodeSignalSet(osrec_bound_osrec_argument_processCB,osrec_argument(osrec_invocation,1));'
            for change,error in (('omit_write',21),('wrong_argument',21),('extra_write',20)):
                if change=='omit_write':modified=original.replace(invocation,'(void)osrec_argument(osrec_invocation,1);')
                elif change=='wrong_argument':modified=original.replace('osrec_argument(osrec_invocation,1)','osrec_argument(osrec_invocation,0)')
                else:modified=original.replace(invocation,invocation+'osrec_bound_osrec_argument_processCB->exitCode^=0x80000000U;')
                self.assertNotEqual(modified,original);adapter.write_text(modified);image=stage/(change+'.elf')
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
