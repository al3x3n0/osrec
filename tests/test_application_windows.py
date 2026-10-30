"""Compiled C applications pause/resume with persistent kernel and user state."""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from test_callable_slices import options,LLVM,QEMU
from export_syscall_slices import export
from build_c_file_application_fixture import build
from import_application_checkpoint import import_checkpoint,verify_package
from export_application_replay import export as compose
from verify_syscall_slices import verify_matrix
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success

class ApplicationWindowTests(unittest.TestCase):
    def test_c_application_windows_state_continuity_and_mutations(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);a=options(stage);report=export(a)
            self.assertTrue(report['hardware_cpu_windows_included'])
            build(a.out,stage/'fixture',LLVM);fixture=stage/'fixture/compiled'
            routes=stage/'routes';route=import_checkpoint(fixture/'application.elf',fixture/'checkpoint.json',routes)
            self.assertEqual(route['snapshot_count'],0);self.assertTrue(route['window_bindings'])
            self.assertIn('app_count', (fixture/'sources/application-0.c').read_text())
            args=SimpleNamespace(slices=a.out,application=routes,out=stage/'windows-1',llvm_bin=LLVM,qemu=QEMU,arch='aarch64',entry_address=0x40400000,result_address=0x40380000,window_calls=1)
            for limit in (1,5,64):
                with self.subTest(limit=limit):
                    args.window_calls=limit;args.out=stage/('windows-'+str(limit));r=compose(args)
                    v=r['target_observations'];count=(32+limit-1)//limit
                    self.assertEqual(v['abi_version'],22);self.assertEqual(v['completed_calls'],64)
                    self.assertEqual(v['window_count'],count);self.assertEqual(v['window_pauses'],2*(count-1))
                    self.assertEqual(v['resume_checks'],2*(count-1));self.assertEqual(v['state_progress_checks'],2*count)
                    self.assertEqual(v['initial_memory_checks'],2);self.assertEqual(v['assertions'],5)
                    self.assertEqual(v['stack_guard_checks'],2*count);self.assertFalse(r['runtime_host_interaction'])
                    matrix=verify_matrix(args.out,stage/('matrix-'+str(limit)),qemu=QEMU,llvm_bin=LLVM)
                    self.assertEqual(len(matrix['executions']),4);self.assertEqual(matrix['application_window_call_limit'],limit)
            for limit in (-1,65537,True):
                bad=SimpleNamespace(**vars(args));bad.out=stage/'invalid';bad.window_calls=limit
                with self.assertRaisesRegex(ValueError,'limit'):compose(bad)
            image=stage/'windows-1';sources=image/'sources';driver=sources/'slice_driver.c';original=driver.read_text();archive=stage/'bad.a'
            flags=[LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align','-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-I'+str(sources)]
            def check_bad():
                elf=stage/'bad.elf'
                run([*flags,'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',driver,sources/'application_checkpoint.c',archive,'-o',elf]);audit(elf,LLVM)
                v,_=observe(elf,QEMU);self.assertEqual(v['status'],3)
                with self.assertRaises(ValueError):require_success(v)
            for old,new in [('if(first){if(frame.pc!=gateway.sites[0].svc_pc)', 'if(first){session.adapter->restore(session.state);if(frame.pc!=gateway.sites[0].svc_pc)'),
                            ('if(osrec_import_bind_window(&gateway,', 'if(first)osrec_import_restore(&frame);\n            if(osrec_import_bind_window(&gateway,'),
                            ('first+=count;', 'first+=count+1;')]:
                with self.subTest(driver_mutation=new):
                    self.assertIn(old,original);driver.write_text(original.replace(old,new,1));shutil.copyfile(image/'slices.a',archive);check_bad()
            driver.write_text(original)
            kernel=sources.parent/'kernel-sources';gateway=kernel/'slice_gateway.c';text=gateway.read_text()
            for old,new in [('g->active=1u|(pause ? PAUSE_AT_SVC : 0u);','g->active=1u;'),
                            ('&& g->cursor==g->site_count){++g->exits;return 1;', '){++g->exits;return 1;'),
                            ('++g->exits;return 1;', '++g->exits;g->application->pc+=4;return 1;')]:
                with self.subTest(gateway_mutation=new):
                    self.assertIn(old,text);gateway.write_text(text.replace(old,new,1))
                    obj=stage/'slice_gateway.o';run([*flags,'-I'+str(kernel),'-c',gateway,'-o',obj]);shutil.copyfile(image/'slices.a',archive);run([LLVM/'llvm-ar','r',archive,obj]);check_bad()
            gateway.write_text(text)
            # Exercise generated binding and runtime rejection paths on the target.
            rejected='''
        struct osrec_aarch64_frame saved_frame=frame;
        unsigned char saved_state[OSREC_SLICE_STATE_BYTES];
        for(size_t j=0;j<sizeof(state);++j)saved_state[j]=state[j];
        if(osrec_import_bind_window(&gateway,&session,&osrec_application_abi,&frame,stack,sizeof(stack),0,0)!=OSREC_SLICE_BAD_INPUT)fail(40);
        if(osrec_import_bind_window(&gateway,&session,&osrec_application_abi,&frame,stack,sizeof(stack),32,1)!=OSREC_SLICE_BAD_INPUT)fail(41);
        if(osrec_import_bind_window(&gateway,&session,&osrec_application_abi,&frame,stack,sizeof(stack),0,33)!=OSREC_SLICE_BAD_INPUT)fail(42);
        if(osrec_import_bind_window(&gateway,&session,&osrec_application_abi,&frame,stack,sizeof(stack),1,1)!=OSREC_SLICE_BAD_INPUT)fail(43);
        gateway.active=1;
        if(osrec_import_bind_window(&gateway,&session,&osrec_application_abi,&frame,stack,sizeof(stack),0,1)!=OSREC_SLICE_BUSY)fail(44);
        gateway.active=0;session.active=1;
        if(osrec_import_bind_window(&gateway,&session,&osrec_application_abi,&frame,stack,sizeof(stack),0,1)!=OSREC_SLICE_BUSY)fail(45);
        session.active=0;
        if(osrec_import_bind_window(&gateway,&session,&osrec_application_abi,&frame,stack,sizeof(stack),0,1))fail(46);
        gateway.exit_pc='''+str(route['exit_pc'])+''';
        if(osrec_aarch64_gateway_run_window(&gateway)!=OSREC_SLICE_BAD_INPUT)fail(47);
        if(osrec_import_bind_window(&gateway,&session,&osrec_application_abi,&frame,stack,sizeof(stack),0,32))fail(48);
        if(osrec_aarch64_gateway_run_window(&gateway)!=OSREC_SLICE_BAD_INPUT)fail(49);
        if(session.next || session.poisoned || session.active)fail(50);
        for(size_t j=0;j<sizeof(state);++j)if(state[j]!=saved_state[j])fail(51);
        for(size_t j=0;j<sizeof(frame);++j)if(((unsigned char *)&frame)[j]!=((unsigned char *)&saved_frame)[j])fail(52);
'''
            driver.write_text(original.replace('        const size_t total=','        if(!run){'+rejected+'}\n        const size_t total=',1));shutil.copyfile(image/'slices.a',archive)
            elf=stage/'rejections.elf'
            run([*flags,'-nostdlib','-static','-fuse-ld=lld','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',driver,sources/'application_checkpoint.c',archive,'-o',elf]);v,_=observe(elf,QEMU);require_success(v)
            driver.write_text(original)
            manifest=json.loads((image/'manifest.json').read_text());manifest['application_execution_windows'][0]['count']=2
            (image/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'windows differ'):verify_matrix(image,stage/'bad-matrix',qemu=QEMU,llvm_bin=LLVM)

    def test_c_wrapper_preserves_aapcs_with_alternate_registers(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);a=options(stage);port=json.loads(a.port.read_text())
            port['application_abi'].update(number_register=30,argument_registers=[19,20,21,22,23,24],result_register=25)
            a.port=stage/'port.json';a.port.write_text(json.dumps(port));export(a)
            build(a.out,stage/'fixture',LLVM,prefix_calls=5);f=stage/'fixture/compiled';routes=stage/'routes'
            import_checkpoint(f/'application.elf',f/'checkpoint.json',routes);verify_package(routes)
            args=SimpleNamespace(slices=a.out,application=routes,out=stage/'image-alt',llvm_bin=LLVM,qemu=QEMU,arch='aarch64',entry_address=0x40400000,result_address=0x40380000,window_calls=5)
            v=compose(args)['target_observations'];self.assertEqual(v['completed_calls'],64);self.assertEqual(v['window_pauses'],12)
            wrapper=(f/'sources/syscall.S').read_text();self.assertIn('ldr x30,[sp]',wrapper);self.assertIn('mov x0,x25',wrapper)
            matrix=verify_matrix(args.out,stage/'matrix',qemu=QEMU,llvm_bin=LLVM);self.assertEqual(matrix['status'],'verified')

if __name__=='__main__':unittest.main()
