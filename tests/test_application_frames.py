"""Saved AArch64 app frames -> returning slices, validated on QEMU."""
import json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from test_callable_slices import options,LLVM,QEMU
from export_syscall_slices import export,validate_port
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
from verify_syscall_slices import verify_matrix

class ApplicationFrameTests(unittest.TestCase):
    def test_saved_frames_bundles_and_mutations(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);args=options(stage,0x40400000,0x40380000);args.application_frame=True
            report=export(args);result=report['target_observations']
            self.assertEqual(result['abi_version'],19);self.assertEqual(result['preserved_frames'],96)
            self.assertEqual(result['input_rejections'],20);self.assertEqual(result['register_abi_variants'],2)
            self.assertTrue(report['application_frame_bridge']);self.assertTrue(report['application_frame_proof'])
            self.assertFalse(report['hardware_cpu_restore_integrated'])
            members=run([LLVM/'llvm-ar','t',args.out/'slices.a']).stdout
            self.assertIn('slice_frame.o',members);self.assertIn('slice_application_abi.o',members)
            symbols=run([LLVM/'llvm-nm','--defined-only',args.out/'slices.a']).stdout
            self.assertIn('osrec_aarch64_syscall',symbols);self.assertIn('osrec_application_abi',symbols)
            matrix=verify_matrix(args.out,stage/'matrix',qemu=QEMU,llvm_bin=LLVM)
            self.assertEqual(matrix['status'],'verified');self.assertEqual(len(matrix['executions']),4)
            self.assertTrue(matrix['application_frame_proof'])
            header=args.out/'sources/osrec/aarch64_frame.h';saved=header.read_text();header.write_text(saved+'\n/* changed */\n')
            with self.assertRaisesRegex(ValueError,'source hash'):verify_matrix(args.out,stage/'tampered')
            self.assertFalse((stage/'tampered').exists());header.write_text(saved)
            sources=args.out/'sources';runtime=sources/'slice_frame.c';original=runtime.read_text()
            compiled=[sources/n for n in ('files_models.c','files_syscalls.c','slice_adapter.c','slice_checkpoint.c','slice_runtime.c','slice_bytes.c','slice_guard.S','slice_frame.c','slice_application_abi.c','slice_driver.c')]
            mutations=[('f->pc=site->continuation_pc;','f->pc=site->continuation_pc;f->sp=0;'),
                ('f->pc=site->continuation_pc;','f->pc=site->continuation_pc;f->v[31].hi=0;'),
                ('f->pc=site->continuation_pc;','f->pc=site->svc_pc;'),
                ('in.args[i]=f->x[a->argument_registers[i]];','in.args[i]=f->x[i];'),
                ('!=UINT32_C(0xd4000001)', '==UINT32_C(0xd4000001)'),
                ('site->continuation_pc!=site->svc_pc+4','site->continuation_pc==site->svc_pc+4')]
            for old,new in mutations:
                with self.subTest(mutation=new):
                    self.assertIn(old,original);runtime.write_text(original.replace(old,new,1));elf=stage/'bad.elf'
                    run([LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-std=c11','-O1','-ffreestanding','-fno-builtin','-I'+str(sources),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',*compiled,'-o',elf])
                    audit(elf,LLVM);observed,_=observe(elf,QEMU)
                    self.assertEqual(observed['status'],3)
                    with self.assertRaises(ValueError):require_success(observed)

    def test_invalid_register_recipes(self):
        port=json.loads((ROOT/'integrations/liteos_a/files-slice-port.json').read_text())
        changes=[('number_register',31),('number_register',True),('number_register',0),('result_register',-1),
            ('argument_registers',[0,1,2,3,4]),('argument_registers',[0,0,2,3,4,5]),
            ('argument_registers',[0,1,2,3,4,31]),('continuation','guess'),('format','other')]
        for key,value in changes:
            with self.subTest(key=key,value=value):
                bad=json.loads(json.dumps(port));bad['application_abi'][key]=value
                with self.assertRaises(ValueError):validate_port(bad)
        del port['application_abi'];validate_port(port) # Session-only older ports remain supported.

if __name__=='__main__':unittest.main()
