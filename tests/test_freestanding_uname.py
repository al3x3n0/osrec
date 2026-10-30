"""Uname capture validation, complete identity ABI and closed AArch64 replay."""
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
from uname_capture import decode,prepare_source
from export_freestanding_uname import export,load_capture
from klee_liteos import digest
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
from rtl_load_bundle import prepare
from rtl_boot_bundle import prepare as prepare_boot
from verify_qemu_bundle import verify
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');KERNEL=ROOT/'build/kernel_liteos_a';QEMU='qemu-system-aarch64'


def fixture(directory,fault=False):
    directory.mkdir();user=[];kernel=[];events=[]
    identity_fields=[b'LiteOS',b'OHOS',b'3.2',b'captured build',b'A'*64,b'']
    for i in range(8 if fault else 4):
        pointer=i-1 if i in (2,3) else 0;raw=0 if i<2 else 0xfffffffb if i==5 else 0xfffffff2
        before=bytes([0xa1+i])*390;after=bytearray(before)
        if i not in (2,3,4,5):
            for j,value in enumerate(identity_fields):after[65*j:65*j+len(value)+1]=value+b'\0'
        def event(kind,arg,ret,payload):
            events.append(struct.pack('<6I',i,kind,arg,ret,390,0x113)+payload+b'\0\0')
        input_raw=390 if i in (2,3) else 195 if i==4 else 0
        event(1,pointer,input_raw,before[:390-input_raw]+bytes(input_raw))
        if not input_raw:
            event(2,0,0xfffffffb if i==5 else 0,after)
            if i!=5:
                output_raw=390 if i==6 else 195 if i==7 else 0
                event(3,0,output_raw,after)
                after=after[:390-output_raw]+before[390-output_raw:]
        user.append(struct.pack('<4I',122,pointer,raw,16)+after+b'\x5a\xc3')
        kernel.append(struct.pack('<4I',122,pointer,raw,0))
    blobs=[b''.join(rows) for rows in (user,kernel,events)]
    checkpoint=decode(*blobs);_,identity=prepare_source(KERNEL)
    metadata={'format':'osrec-live-uname-checkpoint-v1','source_identity':identity,'checkpoint':checkpoint,
        'kernel_image_sha256':digest(b'synthetic unit fixture'),'entry_errno_fixture':0,'provenance':'synthetic unit fixture','injected_boundary_faults':fault}
    for name,blob in zip(('user','kernel','dependencies'),blobs):
        (directory/('uname-'+name+'.bin')).write_bytes(blob);metadata[name+'_sha256']=digest(blob)
    (directory/'uname-checkpoint.manifest.json').write_text(json.dumps(metadata))
    (directory/'auto-entry-config.h').write_text('#define OSREC_UNAME_CAPTURE 1\n'+('#define OSREC_UNAME_FAULTS 1\n' if fault else ''))
    return blobs,identity


class UnameTests(unittest.TestCase):
    def test_bad_capture_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);blobs,identity=fixture(stage/'capture')
            self.assertEqual(bytes.fromhex(decode(*blobs)['calls'][0]['after'])[260:325],b'A'*64+b'\0')
            for index,offset in ((0,0),(0,4),(0,8),(0,12),(0,16),(0,406),(1,12),(2,0),(2,4),(2,8),(2,12),(2,16),(2,20),(2,24),(2,414),(2,452),(2,2460)):
                bad=[bytearray(b) for b in blobs];bad[index][offset]^=1
                with self.subTest(index=index,offset=offset),self.assertRaises(ValueError):decode(*[bytes(b) for b in bad])
            for i in range(3):
                bad=list(blobs);bad[i]=bad[i][:-1]
                with self.assertRaises(ValueError):decode(*bad)
            original=json.loads((stage/'capture/uname-checkpoint.manifest.json').read_text())
            for mutate in ('hash','checkpoint','fixture'):
                bad=copy.deepcopy(original)
                if mutate=='hash':bad['user_sha256']='0'*64
                if mutate=='checkpoint':bad['checkpoint']['calls'][0]['pointer_kind']=False
                if mutate=='fixture':bad['entry_errno_fixture']=False
                (stage/'capture/uname-checkpoint.manifest.json').write_text(json.dumps(bad))
                with self.assertRaises(ValueError):load_capture(stage/'capture',identity)
            (stage/'capture/uname-checkpoint.manifest.json').write_text(json.dumps(original))
            for config in ('#define OSREC_UNAME_CAPTURE 0\n','#define OSREC_UNAME_CAPTURE 1\n#undef OSREC_UNAME_CAPTURE\n'):
                (stage/'capture/auto-entry-config.h').write_text(config)
                args=SimpleNamespace(arch='aarch64',capture=stage/'capture',kernel_root=KERNEL,out=stage/'image',llvm_bin=LLVM,qemu=QEMU)
                with self.assertRaises(ValueError):export(args)
                self.assertFalse(args.out.exists())

    def test_complete_identity_and_relocated_bundles(self):
        for entry,result in ((0x40200000,0x40180000),(0x40400000,0x40380000)):
            with self.subTest(entry=entry),tempfile.TemporaryDirectory() as name:
                stage=Path(name);fixture(stage/'capture')
                args=SimpleNamespace(arch='aarch64',capture=stage/'capture',kernel_root=KERNEL,out=stage/'image',llvm_bin=LLVM,qemu=QEMU,entry_address=entry,result_address=result)
                exported=export(args);self.assertEqual(exported['target_observations']['abi_version'],13)
                self.assertEqual(exported['target_observations']['user_copy_bytes'],1560)
                expected=(args.out/'target-result.bin').read_bytes();shutil.rmtree(args.capture);shutil.rmtree(args.out/'sources')
                for raw in (False,True):
                    replay=stage/('raw' if raw else 'elf');prepare(args.out/'uname.elf',[{'address':0x40000000,'bytes':64*1024*1024}],replay,args.out/'uname.bin' if raw else None)
                    boot=stage/(replay.name+'-boot');prepare_boot(replay,boot,LLVM)
                    for bundle,label in ((replay,'el1'),(boot,'el3')):
                        evidence=stage/(replay.name+'-'+label);checked=verify(bundle,evidence,QEMU)
                        self.assertEqual(checked['status'],'verified');self.assertEqual((evidence/'target-result.bin').read_bytes(),expected)

    def test_fault_boundaries_and_provenance(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);blobs,identity=fixture(stage/'capture',True)
            checkpoint=decode(*blobs)
            self.assertEqual([c['raw_bits'] for c in checkpoint['calls']],[0,0,0xfffffff2,0xfffffff2,0xfffffff2,0xfffffffb,0xfffffff2,0xfffffff2])
            args=SimpleNamespace(arch='aarch64',capture=stage/'capture',kernel_root=KERNEL,out=stage/'image',llvm_bin=LLVM,qemu=QEMU,entry_address=0x40400000,result_address=0x40380000)
            exported=export(args)
            self.assertEqual(exported['target_observations']['abi_version'],14)
            self.assertEqual(exported['target_observations']['user_copy_bytes'],3120)
            expected=(args.out/'target-result.bin').read_bytes()
            for raw in (False,True):
                replay=stage/('raw' if raw else 'elf');prepare(args.out/'uname.elf',[{'address':0x40000000,'bytes':64*1024*1024}],replay,args.out/'uname.bin' if raw else None)
                boot=stage/(replay.name+'-boot');prepare_boot(replay,boot,LLVM)
                for bundle,label in ((replay,'el1'),(boot,'el3')):
                    evidence=stage/(replay.name+'-'+label);checked=verify(bundle,evidence,QEMU)
                    self.assertEqual(checked['status'],'verified');self.assertEqual((evidence/'target-result.bin').read_bytes(),expected)
            sources=args.out/'sources';target=sources/'uname_replay.c';original=target.read_text()
            for before,after in (('if(j<390-e->raw)','if(j<390)'),('return (int32_t)e->raw;','return 0;'),('return e->raw;','return 0;')):
                with self.subTest(target_change=before):
                    self.assertIn(before,original);target.write_text(original.replace(before,after,1));elf=stage/'fault-bad.elf'
                    run([LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-std=c11','-O1','-ffreestanding','-fno-builtin','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',target,sources/'uname_syscalls.c','-o',elf])
                    audit(elf,LLVM);observed,_=observe(elf,QEMU)
                    self.assertEqual(observed['status'],3)
                    with self.assertRaises(ValueError):require_success(observed)
            # Partial-input suffix, provider-error payload, partial-output outcome and caller suffix.
            for index,offset in ((2,8*416+24+195),(2,10*416+24),(2,16*416+12),(0,7*408+16+195)):
                bad=[bytearray(b) for b in blobs];bad[index][offset]^=1
                with self.subTest(index=index,offset=offset),self.assertRaises(ValueError):decode(*[bytes(b) for b in bad])
            metadata=json.loads((args.capture/'uname-checkpoint.manifest.json').read_text())
            for value in (False,1):
                bad=copy.deepcopy(metadata);bad['injected_boundary_faults']=value
                (args.capture/'uname-checkpoint.manifest.json').write_text(json.dumps(bad))
                with self.assertRaises(ValueError):load_capture(args.capture,identity)
            (args.capture/'uname-checkpoint.manifest.json').write_text(json.dumps(metadata))
            (args.capture/'auto-entry-config.h').write_text('#define OSREC_UNAME_CAPTURE 1\n')
            with self.assertRaises(ValueError):load_capture(args.capture,identity)

    def test_bad_dependency_copy_and_output_fail_in_target(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);fixture(stage/'capture')
            args=SimpleNamespace(arch='aarch64',capture=stage/'capture',kernel_root=KERNEL,out=stage/'image',llvm_bin=LLVM,qemu=QEMU)
            export(args);sources=args.out/'sources';target=sources/'uname_replay.c';original=target.read_text()
            changes=[('e->kind!=kind','e->kind==kind'),('((unsigned char *)out)[j]=e->memory[j];','((unsigned char *)out)[j]=0;'),
                ('((const unsigned char *)in)[j]!=e->memory[j]','((const unsigned char *)in)[j]==e->memory[j]'),
                ('++verified;','witness[390]^=1; if(witness[390]!=0x5a)fail(12); ++verified;')]
            for before,after in changes:
                with self.subTest(before=before):
                    self.assertIn(before,original);target.write_text(original.replace(before,after,1));elf=stage/'bad.elf'
                    run([LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-std=c11','-O1','-ffreestanding','-fno-builtin','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',target,sources/'uname_syscalls.c','-o',elf])
                    audit(elf,LLVM);observed,_=observe(elf,QEMU)
                    self.assertEqual(observed['status'],3)
                    with self.assertRaises(ValueError):require_success(observed)


if __name__=='__main__':
    if len(sys.argv)==4:KERNEL=Path(sys.argv[1]);LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
