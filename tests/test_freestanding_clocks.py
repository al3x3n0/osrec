"""Clock capture validation and isolated AArch64 execution of the original bodies."""
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
from clock_capture import decode,prepare_source
from export_freestanding_clocks import export,load_capture
from klee_liteos import digest
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
from rtl_load_bundle import prepare
from rtl_boot_bundle import prepare as prepare_boot
from verify_qemu_bundle import verify
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');KERNEL=ROOT/'build/kernel_liteos_a';QEMU='qemu-system-aarch64'


def fixture(directory):
    directory.mkdir();user=[];kernel=[];events=[]
    before=[0x11223344,0x55667788,0x99aabbcc,0xddeeff00]
    for i in range(10):
        local=i%5;number=263 if i<5 else 264;kind=1 if i<5 else 2
        id=1 if local==1 else 0xffffffff if local==2 else 0
        error=22 if local in (2,3) else 14 if local==4 else 0
        raw=(-error)&0xffffffff;out=before
        payload=[0xffffffff,0x123,999999999,0] if i<5 else [0,0,1000,0]
        if local!=3:
            events.append([i,kind,id,0xffffffff if local==2 else 0,22 if local==2 else 0,*([0]*4 if local==2 else payload),0])
            if local!=2:
                events.append([i,3,2 if local==4 else 0,16 if local==4 else 0,0,*payload,16])
                if local!=4:out=payload
        user.append([number,id,raw,16,*out]);kernel.append([number,id,raw,error])
    blobs=[b''.join(struct.pack('<'+str(len(row))+'I',*row) for row in rows) for rows in (user,kernel,events)]
    checkpoint=decode(*blobs);_,identity=prepare_source(KERNEL)
    metadata={'format':'osrec-live-clock-checkpoint-v1','source_identity':identity,'checkpoint':checkpoint,
        'kernel_image_sha256':digest(b'synthetic unit fixture'),'entry_errno_fixture':0,'provenance':'synthetic unit fixture'}
    for name,blob in zip(('user','kernel','dependencies'),blobs):
        (directory/('clock-'+name+'.bin')).write_bytes(blob);metadata[name+'_sha256']=digest(blob)
    (directory/'clock-checkpoint.manifest.json').write_text(json.dumps(metadata))
    (directory/'auto-entry-config.h').write_text('#define OSREC_CLOCK_CAPTURE 1\n')
    return blobs,identity


class ClockTests(unittest.TestCase):
    def test_invalid_capture_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);blobs,identity=fixture(stage/'capture')
            self.assertEqual(decode(*blobs)['calls'][0]['after'][1],0x123)
            for index,offset in ((0,0),(0,12),(0,16),(0,28),(1,12),(2,0),(2,4),(2,8),(2,32),(2,36),(2,76)):
                bad=[bytearray(b) for b in blobs];bad[index][offset]^=1
                with self.subTest(index=index,offset=offset),self.assertRaises(ValueError):decode(*[bytes(b) for b in bad])
            for i in range(3):
                bad=list(blobs);bad[i]=bad[i][:-1]
                with self.assertRaises(ValueError):decode(*bad)
            original=json.loads((stage/'capture/clock-checkpoint.manifest.json').read_text())
            for mutate in ('hash','checkpoint','fixture'):
                bad=copy.deepcopy(original)
                if mutate=='hash':bad['user_sha256']='0'*64
                if mutate=='checkpoint':bad['checkpoint']['calls'][0]['pointer_kind']=False
                if mutate=='fixture':bad['entry_errno_fixture']=False
                (stage/'capture/clock-checkpoint.manifest.json').write_text(json.dumps(bad))
                with self.assertRaises(ValueError):load_capture(stage/'capture',identity)
            (stage/'capture/clock-checkpoint.manifest.json').write_text(json.dumps(original))
            (stage/'capture/auto-entry-config.h').write_text('#define OSREC_CLOCK_CAPTURE 0\n')
            args=SimpleNamespace(arch='aarch64',capture=stage/'capture',kernel_root=KERNEL,out=stage/'image',llvm_bin=LLVM,qemu=QEMU)
            with self.assertRaises(ValueError):export(args)
            self.assertFalse(args.out.exists())

    def test_closed_relocated_images_and_bundles(self):
        for entry,result in ((0x40200000,0x40180000),(0x40400000,0x40380000)):
            with self.subTest(entry=entry),tempfile.TemporaryDirectory() as name:
                stage=Path(name);fixture(stage/'capture')
                args=SimpleNamespace(arch='aarch64',capture=stage/'capture',kernel_root=KERNEL,out=stage/'image',
                    llvm_bin=LLVM,qemu=QEMU,entry_address=entry,result_address=result)
                report=export(args);self.assertEqual(report['target_observations']['abi_version'],11)
                self.assertEqual(report['target_observations']['user_copy_bytes'],64)
                expected=(args.out/'target-result.bin').read_bytes();shutil.rmtree(args.capture);shutil.rmtree(args.out/'sources')
                for raw in (False,True):
                    replay=stage/('raw' if raw else 'elf');prepare(args.out/'clocks.elf',[{'address':0x40000000,'bytes':64*1024*1024}],replay,args.out/'clocks.bin' if raw else None)
                    checked=verify(replay,stage/(replay.name+'-el1'),QEMU)
                    self.assertEqual(checked['status'],'verified');self.assertEqual((stage/(replay.name+'-el1')/'target-result.bin').read_bytes(),expected)
                    boot=stage/(replay.name+'-boot');prepare_boot(replay,boot,LLVM)
                    checked=verify(boot,stage/(replay.name+'-el3'),QEMU)
                    self.assertEqual(checked['status'],'verified');self.assertEqual((stage/(replay.name+'-el3')/'target-result.bin').read_bytes(),expected)

    def test_changed_dependency_and_output_fail_in_guest(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);fixture(stage/'capture')
            args=SimpleNamespace(arch='aarch64',capture=stage/'capture',kernel_root=KERNEL,out=stage/'image',llvm_bin=LLVM,qemu=QEMU)
            export(args);sources=args.out/'sources';target=sources/'clock_replay.c';original=target.read_text()
            changes=[('e->kind!=kind','e->kind==kind'),('clock_errno=(int)e->error','clock_errno=(int)e->error+1'),
                ('source[i]!=','source[i]=='),('++verified;','witness[0]^=1; if(witness[0]!=call->after[0])fail(9); ++verified;')]
            for before,after in changes:
                with self.subTest(before=before):
                    self.assertIn(before,original);target.write_text(original.replace(before,after,1));elf=stage/'bad.elf'
                    run([LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-std=c11','-O1','-ffreestanding','-fno-builtin','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',target,sources/'clock_syscalls.c','-o',elf])
                    audit(elf,LLVM);observed,_=observe(elf,QEMU)
                    self.assertEqual(observed['status'],3)
                    with self.assertRaises(ValueError):require_success(observed)


if __name__=='__main__':
    if len(sys.argv)==4:KERNEL=Path(sys.argv[1]);LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
