"""Recorded native file-session validation and independent target fault detection."""
import copy,json,shutil,struct,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from files_capture import decode,prepare_source
from export_freestanding_files import export,load_capture
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
from rtl_load_bundle import prepare
from rtl_boot_bundle import prepare as prepare_boot
from verify_qemu_bundle import verify
KERNEL=ROOT/'build/kernel_liteos_a';LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/files-native'

def args(stage,entry=0x40400000,result=0x40380000):
    capture=stage/'capture';shutil.copytree(FIXTURE,capture)
    return SimpleNamespace(arch='aarch64',capture=capture,kernel_root=KERNEL,out=stage/'image',llvm_bin=LLVM,qemu=QEMU,entry_address=entry,result_address=result)

class FilesTests(unittest.TestCase):
    def test_corruption_rejected(self):
        blobs=[(FIXTURE/('files-'+n+'.bin')).read_bytes() for n in ('user','kernel','dependencies','abi')]
        checkpoint=decode(*blobs);self.assertEqual(checkpoint['final_file_bytes'],'61625859')
        offsets=[(0,0),(0,4),(0,24),(0,28),(0,32),(0,223),(1,28),(1,32),(1,48),(1,108),(2,0),(2,4),(2,8),(2,20),(2,24),(2,28),(2,32),(2,92),(2,152),(2,343),(3,0),(3,4),(3,8),(3,12),(3,20),(3,24),(3,28)]
        # Metadata size and copied payload, shared position, descriptor replacement, final reference release.
        for e in checkpoint['dependency_transcript']:
            n=checkpoint['dependency_transcript'].index(e)
            if e['kind'] in (10,11,12,15,19):offsets.extend([(2,n*344+92),(2,n*344+152)])
        for index,offset in offsets:
            bad=[bytearray(b) for b in blobs];bad[index][offset]^=1
            with self.subTest(index=index,offset=offset),self.assertRaises(ValueError):decode(*bad)
        for index in range(4):
            bad=list(blobs);bad[index]=bad[index][:-1]
            with self.assertRaises(ValueError):decode(*bad)
        with tempfile.TemporaryDirectory() as name:
            a=args(Path(name));_,identity=prepare_source(KERNEL);original=json.loads((a.capture/'files-checkpoint.manifest.json').read_text())
            for kind in ('hash','checkpoint','fixture','source'):
                m=copy.deepcopy(original)
                if kind=='hash':m['abi_sha256']='0'*64
                elif kind=='checkpoint':m['checkpoint']['calls'][0]['after'][1]=True
                elif kind=='fixture':m['entry_errno_fixture']=False
                else:m['source_identity']['generated_source_sha256']='0'*64
                (a.capture/'files-checkpoint.manifest.json').write_text(json.dumps(m))
                with self.assertRaises(ValueError):load_capture(a.capture,identity)
            (a.capture/'files-checkpoint.manifest.json').write_text(json.dumps(original))
            (a.capture/'auto-entry-config.h').write_text('#define OSREC_FILE_CAPTURE 0\n')
            with self.assertRaises(ValueError):export(a)
            self.assertFalse(a.out.exists())

    def test_relocated_loading_and_target_faults(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);a=args(stage,0x40200000,0x40180000);report=export(a)
            self.assertEqual(report['target_observations']['completed_calls'],32)
            expected=(a.out/'target-result.bin').read_bytes()
            for raw in (False,True):
                replay=stage/('raw' if raw else 'elf');prepare(a.out/'files.elf',[{'address':0x40000000,'bytes':64*1024*1024}],replay,a.out/'files.bin' if raw else None)
                boot=stage/(replay.name+'-boot');prepare_boot(replay,boot,LLVM)
                for bundle,label in ((replay,'el1'),(boot,'el3')):
                    evidence=stage/(replay.name+'-'+label);self.assertEqual(verify(bundle,evidence,QEMU)['status'],'verified');self.assertEqual((evidence/'target-result.bin').read_bytes(),expected)
            sources=a.out/'sources';target=sources/'files_replay.c';original=target.read_text()
            changes=[('++state[i];','state[i]+=2;'),('--state[i];','state[i]=0;'),('state[i]=(uint32_t)system;','state[i]=(uint32_t)fd;'),('position(i,pos+n);','position(i,pos);'),('bytes(content+pos,in,(unsigned)size);','memset(content+pos,0,size);'),('path_allocated=0;effect','path_allocated=1;effect'),('lock_depth=0;effect','lock_depth=1;effect'),('bytes(out,in,(unsigned)n);','bytes(out,in,(unsigned)n-1);')]
            for old,new in changes:
                with self.subTest(old=old):
                    self.assertIn(old,original);target.write_text(original.replace(old,new,1));elf=stage/'bad.elf'
                    run([LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-std=c11','-O1','-ffreestanding','-fno-builtin','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',target,sources/'files_syscalls.c','-o',elf])
                    audit(elf,LLVM);observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],3)
                    with self.assertRaises(ValueError):require_success(observed)

if __name__=='__main__':
    if len(sys.argv)==4:KERNEL=Path(sys.argv[1]);LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
