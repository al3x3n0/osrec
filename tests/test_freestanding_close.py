"""Close capture validation, descriptor lifecycle and closed AArch64 replay."""
import copy
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from close_capture import decode,prepare_source
from export_freestanding_close import export,load_capture
from klee_liteos import digest
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
from rtl_load_bundle import prepare
from rtl_boot_bundle import prepare as prepare_boot
from verify_qemu_bundle import verify
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');KERNEL=ROOT/'build/kernel_liteos_a';QEMU='qemu-system-aarch64'


def fixture(directory,system=73):
    directory.mkdir();user=[];kernel=[];events=[];state=[system,1,1]
    for i in range(5):
        fd=0xffffffff if i==3 else 1024 if i==4 else 4
        error=5 if i==0 else 0 if i==1 else 9;raw=(-error)&0xffffffff;before=list(state)
        mapped=system if i<2 else 0xffffffff;detached=[0xffffffff,*state[1:]]
        def event(kind,arg,arg2,ret,err,after):
            nonlocal state
            events.append([i,kind,arg,arg2,ret,err,*state,*after]);state=list(after)
        event(1,fd,0,mapped,0,detached);event(2,mapped,0,0 if i==1 else 0xffffffff,error,detached)
        if i==1:event(5,fd,0,0,0,[0xffffffff,0,0])
        else:event(4,fd,mapped,0,error,before)
        user.append([6,fd,raw,16]);kernel.append([6,fd,raw,error,*before,*state,0x113])
    blobs=[b''.join(struct.pack('<'+str(len(row))+'I',*row) for row in rows) for rows in (user,kernel,events)]
    checkpoint=decode(*blobs);_,identity=prepare_source(KERNEL)
    metadata={'format':'osrec-live-close-checkpoint-v1','source_identity':identity,'checkpoint':checkpoint,
        'kernel_image_sha256':digest(b'synthetic unit fixture'),'entry_errno_fixture':0,'provenance':'synthetic unit fixture','injected_first_close_failure':True}
    for name,blob in zip(('user','kernel','dependencies'),blobs):
        (directory/('close-'+name+'.bin')).write_bytes(blob);metadata[name+'_sha256']=digest(blob)
    (directory/'close-checkpoint.manifest.json').write_text(json.dumps(metadata))
    (directory/'auto-entry-config.h').write_text('#define OSREC_CLOSE_CAPTURE 1\n')
    return blobs,identity


class CloseTests(unittest.TestCase):
    def test_bad_capture_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);blobs,identity=fixture(stage/'capture')
            self.assertEqual(decode(*blobs)['calls'][0]['after'],[73,1,1])
            self.assertEqual(decode(*blobs)['calls'][1]['after'],[0xffffffff,0,0])
            for index,offset in ((0,0),(0,4),(0,8),(0,12),(1,12),(1,16),(1,20),(1,24),(1,28),(1,32),(1,36),(1,40),(2,0),(2,4),(2,8),(2,12),(2,16),(2,20),(2,24),(2,28),(2,32),(2,36),(2,40),(2,44),(2,96),(2,240)):
                bad=[bytearray(b) for b in blobs];bad[index][offset]^=1
                with self.subTest(index=index,offset=offset),self.assertRaises(ValueError):decode(*[bytes(b) for b in bad])
            for i in range(3):
                bad=list(blobs);bad[i]=bad[i][:-1]
                with self.assertRaises(ValueError):decode(*bad)
            original=json.loads((stage/'capture/close-checkpoint.manifest.json').read_text())
            for mutate in ('hash','checkpoint','fixture','injection'):
                bad=copy.deepcopy(original)
                if mutate=='hash':bad['user_sha256']='0'*64
                if mutate=='checkpoint':bad['checkpoint']['calls'][0]['after'][1]=True
                if mutate=='fixture':bad['entry_errno_fixture']=False
                if mutate=='injection':bad['injected_first_close_failure']=1
                (stage/'capture/close-checkpoint.manifest.json').write_text(json.dumps(bad))
                with self.assertRaises(ValueError):load_capture(stage/'capture',identity)
            (stage/'capture/close-checkpoint.manifest.json').write_text(json.dumps(original))
            for config in ('#define OSREC_CLOSE_CAPTURE 0\n','#define OSREC_CLOSE_CAPTURE 1\n#undef OSREC_CLOSE_CAPTURE\n'):
                (stage/'capture/auto-entry-config.h').write_text(config)
                args=SimpleNamespace(arch='aarch64',capture=stage/'capture',kernel_root=KERNEL,out=stage/'image',llvm_bin=LLVM,qemu=QEMU)
                with self.assertRaises(ValueError):export(args)
                self.assertFalse(args.out.exists())

    def test_descriptor_states_and_relocated_bundles(self):
        for entry,result in ((0x40200000,0x40180000),(0x40400000,0x40380000)):
            with self.subTest(entry=entry),tempfile.TemporaryDirectory() as name:
                stage=Path(name);fixture(stage/'capture',system=73 if entry==0x40200000 else 801)
                args=SimpleNamespace(arch='aarch64',capture=stage/'capture',kernel_root=KERNEL,out=stage/'image',llvm_bin=LLVM,qemu=QEMU,entry_address=entry,result_address=result)
                exported=export(args);self.assertEqual(exported['target_observations']['abi_version'],15)
                self.assertEqual(exported['target_observations']['restore_calls'],4)
                self.assertEqual(exported['target_observations']['final_cloexec'],0)
                expected=(args.out/'target-result.bin').read_bytes();shutil.rmtree(args.capture);shutil.rmtree(args.out/'sources')
                for raw in (False,True):
                    replay=stage/('raw' if raw else 'elf');prepare(args.out/'close.elf',[{'address':0x40000000,'bytes':64*1024*1024}],replay,args.out/'close.bin' if raw else None)
                    boot=stage/(replay.name+'-boot');prepare_boot(replay,boot,LLVM)
                    for bundle,label in ((replay,'el1'),(boot,'el3')):
                        evidence=stage/(replay.name+'-'+label);checked=verify(bundle,evidence,QEMU)
                        self.assertEqual(checked['status'],'verified');self.assertEqual((evidence/'target-result.bin').read_bytes(),expected)

    def test_bad_dependency_copy_and_output_fail_in_target(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);fixture(stage/'capture')
            args=SimpleNamespace(arch='aarch64',capture=stage/'capture',kernel_root=KERNEL,out=stage/'image',llvm_bin=LLVM,qemu=QEMU)
            export(args);sources=args.out/'sources';target=sources/'close_replay.c';original=target.read_text()
            changes=[('e->kind!=kind','e->kind==kind'),('mapped=(uint32_t)system;','mapped=UINT32_MAX;'),
                ('allocated=0;cloexec=0;','allocated=0;cloexec=1;'),('return (int)error;','return 0;'),('live=0;ret=0;','live=1;ret=0;')]
            for before,after in changes:
                with self.subTest(before=before):
                    self.assertIn(before,original);target.write_text(original.replace(before,after,1));elf=stage/'bad.elf'
                    run([LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-std=c11','-O1','-ffreestanding','-fno-builtin','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',target,sources/'close_syscalls.c','-o',elf])
                    audit(elf,LLVM);observed,_=observe(elf,QEMU)
                    self.assertEqual(observed['status'],3)
                    with self.assertRaises(ValueError):require_success(observed)


if __name__=='__main__':
    if len(sys.argv)==4:KERNEL=Path(sys.argv[1]);LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
