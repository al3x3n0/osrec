"""Real EL0 CPU routing, private slice stacks, stateful calls and embedded recovery."""
import sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from test_callable_slices import options,LLVM,QEMU
from export_syscall_slices import export
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
from verify_syscall_slices import verify_matrix

class CpuGatewayTests(unittest.TestCase):
    def test_live_cpu_roundtrip_bundles_audit_and_mutations(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);args=options(stage,0x40400000,0x40380000);args.cpu_gateway=True
            report=export(args);result=report['target_observations']
            self.assertEqual(result['abi_version'],20);self.assertEqual(result['completed_calls'],96)
            for key in ('hardware_frame_checks','container_restore_checks','stack_guard_checks'):self.assertEqual(result[key],96)
            self.assertEqual(result['input_rejections'],10);self.assertEqual(result['gateway_paths_verified'],15)
            self.assertTrue(report['cpu_gateway_proof']);self.assertTrue(report['hardware_cpu_restore_integrated'])
            self.assertFalse(report['runtime_host_interaction']);self.assertFalse(report['app_checkpoint_loader_integrated'])
            members=run([LLVM/'llvm-ar','t',args.out/'slices.a']).stdout
            self.assertIn('slice_gateway_aarch64.o',members);self.assertIn('slice_gateway.o',members);self.assertNotIn('slice_app.o',members)
            self.assertEqual(report['gateway_layout']['F_STACK_BYTES'],816)
            def reviewed(elf):
                symbols={r.split()[0]:int(r.split()[2],16) for r in run([LLVM/'llvm-nm','--defined-only','--format=posix',elf]).stdout.splitlines() if len(r.split())>=3}
                return {symbols[n]:v for n,v in report['cpu_breakpoint_contract'].items()}
            allowed=reviewed(args.out/'slices.elf');self.assertEqual(len(allowed),9)
            self.assertTrue(report['image_audit']['service_trap_instructions']);self.assertFalse(report['image_audit']['external_service_instructions'])
            with self.assertRaisesRegex(ValueError,'service/trap'):audit(args.out/'slices.elf',LLVM)
            missing=dict(allowed);missing.pop(next(iter(missing)))
            with self.assertRaisesRegex(ValueError,'service/trap'):audit(args.out/'slices.elf',LLVM,missing)
            with self.assertRaisesRegex(ValueError,'absent'):audit(args.out/'slices.elf',LLVM,{**allowed,0x40000004:0x5353})
            matrix=verify_matrix(args.out,stage/'matrix',qemu=QEMU,llvm_bin=LLVM)
            self.assertEqual(matrix['status'],'verified');self.assertTrue(matrix['cpu_gateway_proof']);self.assertEqual(matrix['embedded_breakpoints'],9)
            self.assertEqual(len(matrix['executions']),4)
            sources=args.out/'sources';objects=stage/'objects';objects.mkdir()
            names=('files_models.c','files_syscalls.c','slice_adapter.c','slice_checkpoint.c','slice_runtime.c','slice_bytes.c','slice_guard.S','slice_frame.c','slice_application_abi.c','slice_gateway.c','slice_gateway_aarch64.S','slice_app.S','slice_driver.c')
            flags=[LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-mstrict-align','-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-I'+str(sources)]
            def compile_one(filename):
                src=sources/filename;obj=objects/(src.stem+'.o')
                run([*flags,*([] if src.suffix=='.S' else ['-mgeneral-regs-only']),'-c',src,'-o',obj]);return obj
            compiled=[compile_one(n) for n in names]
            mutations=[('slice_gateway_aarch64.S','ins v31.d[1],x3','ins v31.d[1],xzr'),
                ('slice_gateway_aarch64.S','msr tpidr_el0,x2','nop'),
                ('slice_gateway_aarch64.S','msr tpidr_el1,x2','nop'),
                ('slice_gateway_aarch64.S','ldr x0,[x0,#G_APP]\n    ldr x2,[x0,#F_SP]','ldr x0,[x0,#G_APP]\n    str xzr,[x0,#240]\n    ldr x2,[x0,#F_SP]'),
                ('slice_gateway.c','++g->cursor;return 0;','return 0;'),
                ('slice_gateway.c','g->session->active=0;','g->session->active=1;'),
                ('slice_gateway.c','if((f->pstate&15)!=0){g->status','if((f->pstate&15)!=0){*g->application=*f;g->status'),
                ('slice_app.S','str x0,[sp,#-16]','str x1,[sp,#-16]')]
            for filename,old,new in mutations:
                with self.subTest(filename=filename,mutation=new):
                    source=sources/filename;original=source.read_text();self.assertIn(old,original)
                    source.write_text(original.replace(old,new,1));compile_one(filename);elf=stage/'bad.elf'
                    run([*flags,'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',*compiled,'-o',elf])
                    audit(elf,LLVM,reviewed(elf));observed,_=observe(elf,QEMU)
                    self.assertEqual(observed['status'],3)
                    with self.assertRaises(ValueError):require_success(observed)
                    source.write_text(original);compile_one(filename)

if __name__=='__main__':unittest.main()
