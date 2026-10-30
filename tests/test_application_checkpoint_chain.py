"""Successive joint snapshots advance only their interval in fresh QEMU images."""
import json,shutil,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from test_callable_slices import options,LLVM,QEMU
from export_syscall_slices import export
from build_c_file_application_fixture import build
from run_c_application_checkpoint_chain import run_pipeline,verify_chain,checked_ordinals
from application_pause import verify_joint,decode_frame
from export_application_replay import export as compose
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success

class CheckpointChainTests(unittest.TestCase):
    def test_fresh_image_chain_and_invalid_advancement(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);a=options(stage);kernel=export(a);build(a.out,stage/'fixture',LLVM,prefix_calls=5)
            spec=stage/'fixture/spec.json';document=json.loads(spec.read_text());vectors=[[i+0x1020304050607080,i+0xaabbccdd11223300] for i in range(32)]
            document['frame'].update(v=vectors,fpcr=0x400000,fpsr=0x10);spec.write_text(json.dumps(document))
            args=SimpleNamespace(slices=a.out,source=[stage/'fixture/application.c'],spec=spec,pause_ordinals=[5,16,31],out=stage/'chain',llvm_bin=LLVM,qemu=QEMU)
            result=run_pipeline(args);self.assertEqual(result['logical_calls'],32);self.assertEqual(len(result['stages']),4)
            self.assertEqual([(r['input_ordinal'],r['output_ordinal']) for r in result['stages']],[(0,5),(5,16),(16,31),(31,32)])
            self.assertEqual([r['observations']['completed_calls'] for r in result['stages']],[5,22,30,2])
            for i,row in enumerate(result['stages']):
                self.assertEqual(row['qemu_executions'],4);self.assertFalse(row['observations']['guest_host_services'])
                if i<3:
                    checkpoint=args.out/row['stage']/'checkpoint';joint=verify_joint(checkpoint,kernel)
                    self.assertEqual(joint['generation'],i+1);self.assertEqual(joint['pause_ordinal'],row['output_ordinal'])
                    cp=json.loads((checkpoint/'application/checkpoint.json').read_text());self.assertEqual(len(cp['completed_calls']),joint['pause_ordinal'])
                    self.assertEqual(cp['frame']['v'],vectors);self.assertEqual(cp['frame']['fpcr'],0x400000);self.assertEqual(cp['frame']['fpsr'],0x10)
                    producer=args.out/row['stage']/'image';self.assertEqual(decode_frame((producer/'pause-records/frame.bin').read_bytes()),cp['frame'])
            self.assertEqual(verify_chain(args.out)['status'],'verified')
            first=args.out/'stage-0/checkpoint'
            base=dict(slices=a.out,application=first/'application',llvm_bin=LLVM,qemu=QEMU,arch='aarch64',result_address=0x40380000,window_calls=0,checkpoint_mode='advance',checkpoint=first,entry_address=0x40600000)
            for ordinal in (0,4,5,32,33,True,None):
                with self.subTest(ordinal=ordinal):
                    with self.assertRaisesRegex(ValueError,'advance'):compose(SimpleNamespace(**base,pause_ordinal=ordinal,out=stage/'invalid'))
            for points in ([5,5],[16,5],[0,5],[5,32],[],[True]):
                with self.assertRaisesRegex(ValueError,'increase'):checked_ordinals(points,32)
            # Target mutations cannot replace checkpoint restoration with an ordinal.
            image=args.out/'stage-1/image';sources=image/'sources';driver=sources/'slice_driver.c';original=driver.read_text()
            compiler=[LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align','-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-I'+str(sources)]
            for old,new in [('if(osrec_slice_checkpoint_load(&session,','session.next=5;\nif(0 && osrec_slice_checkpoint_load(&session,'),('if(session.next!=16)','session.adapter->restore(session.state);\nif(session.next!=16)')]:
                self.assertIn(old,original);driver.write_text(original.replace(old,new,1));elf=stage/'bad.elf'
                run([*compiler,'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',driver,sources/'application_checkpoint.c',image/'slices.a','-o',elf]);audit(elf,LLVM)
                observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],3)
                with self.assertRaises(ValueError):require_success(observed)
            driver.write_text(original)
            # Offline chain verification catches parent, interval and payload damage.
            workflow=args.out/'workflow.json';raw=workflow.read_bytes();broken=json.loads(raw);broken['stages'][1]['input_ordinal']=4;workflow.write_text(json.dumps(broken))
            with self.assertRaisesRegex(ValueError,'interval'):verify_chain(args.out)
            workflow.write_bytes(raw)
            checkpoint=args.out/'stage-1/checkpoint';metadata=checkpoint/'manifest.json';saved=metadata.read_bytes();broken=json.loads(saved);broken['generation']=7;metadata.write_text(json.dumps(broken))
            with self.assertRaisesRegex(ValueError,'parent identity'):verify_joint(checkpoint,kernel)
            metadata.write_bytes(saved)
            payload=image/'slices.bin';saved=payload.read_bytes();payload.write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError,'identity mismatch'):verify_chain(args.out)
            payload.write_bytes(saved);verify_chain(args.out)

if __name__=='__main__':unittest.main()
