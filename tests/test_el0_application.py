"""Admission and captured page-table consistency for supplied user ELFs."""
import hashlib,json,shutil,struct,subprocess,sys,tempfile,unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from el0_application import inspect_user,constructor_abi,load_kernel,lower_application,linux_baseline,scalar_count_sites,scalar_flag_sites,scalar_bitmap_sites,shared_directory_aliases,FORMAT

class UserELF(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cc=next((p for p in ['/opt/homebrew/opt/llvm@16/bin/clang',shutil.which('clang-19')] if p and Path(p).is_file()),None)
        if not cc:raise unittest.SkipTest('AArch64 clang/lld toolchain required')
        cls.temp=tempfile.TemporaryDirectory();cls.path=Path(cls.temp.name)/'program'
        subprocess.run([cc,'--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-O2','-ffreestanding','-fno-builtin',
                        '-fno-stack-protector','-nostdlib','-static','-fuse-ld=lld','-Wl,-e,_start,-z,max-page-size=4096',
                        str(ROOT/'examples/el0-user/start.S'),str(ROOT/'examples/el0-user/program.c'),'-o',str(cls.path)],
                       check=True,capture_output=True,text=True)
        cls.data=cls.path.read_bytes()
    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,'temp'):cls.temp.cleanup()
    def mutation(self,change):
        data=bytearray(self.data);change(data);p=Path(self.temp.name)/'bad';p.write_bytes(data);return p
    def test_static_elf_admitted_with_code_identity(self):
        info=inspect_user(self.path)
        self.assertEqual(info['sha256'],hashlib.sha256(self.data).hexdigest())
        self.assertTrue(info['code']);self.assertTrue(any(s['flags']&1 for s in info['segments']))
    def test_wrong_architecture_or_dynamic_type_rejected(self):
        for offset,value in [(16,3),(18,62)]:
            with self.subTest(offset=offset),self.assertRaisesRegex(ValueError,'AArch64 ET_EXEC'):
                inspect_user(self.mutation(lambda b:struct.pack_into('<H',b,offset,value)))
    def test_interpreter_and_writable_code_rejected(self):
        phoff=struct.unpack_from('<Q',self.data,32)[0];stride,count=struct.unpack_from('<HH',self.data,54)
        with self.assertRaisesRegex(ValueError,'interpreters'):
            inspect_user(self.mutation(lambda b:struct.pack_into('<I',b,phoff,3)))
        executable=next(phoff+i*stride for i in range(count) if struct.unpack_from('<II',self.data,phoff+i*stride)==(1,5))
        with self.assertRaisesRegex(ValueError,'writable executable'):
            inspect_user(self.mutation(lambda b:struct.pack_into('<I',b,executable+4,7)))
    def test_truncation_and_invalid_entry_rejected(self):
        with self.assertRaisesRegex(ValueError,'program headers'):
            inspect_user(self.mutation(lambda b:struct.pack_into('<Q',b,32,(1<<64)-1)))
        with self.assertRaisesRegex(ValueError,'entry'):
            inspect_user(self.mutation(lambda b:struct.pack_into('<Q',b,24,0x1000)))
    def test_code_data_mapping_metadata_required(self):
        bad=Path(self.temp.name)/'stripped';bad.write_bytes(self.data.replace(b'$x',b'$z'))
        with self.assertRaisesRegex(ValueError,'mapping symbols'):inspect_user(bad)

class CapsuleIdentity(unittest.TestCase):
    def test_constructor_capabilities_read_from_supplied_binary(self):
        data=bytearray(64);struct.pack_into('<HH',data,16,2,183);struct.pack_into('<H',data,54,56)
        marker=dict(name='osrec_prepare_application_abi',shndx=2,size=8,value=0x600000001000)
        image=SimpleNamespace(data=data,symbols=[],read=lambda va,n:struct.pack('<Q',2))
        with patch('el0_application.Elf',return_value=image):
            self.assertEqual(constructor_abi('legacy'),1)
            image.symbols=[marker];self.assertEqual(constructor_abi('current'),2)
            image.read=lambda va,n:struct.pack('<Q',3)
            with self.assertRaisesRegex(ValueError,'unsupported constructor ABI'):constructor_abi('future')
            struct.pack_into('<H',data,18,62)
            with self.assertRaisesRegex(ValueError,'AArch64'):constructor_abi('wrong-architecture')
    def capsule(self,root):
        names=['template/native.bin','template/memory.bin','kernel.elf','prepare-application']
        for name in names:p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(name.encode())
        m=dict(format=FORMAT,architecture='aarch64',constructor_abi=1,state_abi=1,
               process_layout=dict(task_slot=0x200000001000,**{k:8 for k in ('task_mm','mm_mt','vma_start','vma_end','vma_flags','r_pivot','a_pivot','a_slot')}),
               hardware=dict(counter_base=123,counter_step=1024,uart_va=0x80008000e000),
               result_hook=0x800080010000,stop_pc=0x800080020000,parent_source_image_sha256='a'*64,
               assets={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in names})
        (root/'libkernel.json').write_text(json.dumps(m));return m
    def test_assets_bound_and_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);self.capsule(root);self.assertEqual(load_kernel(root)[0],root.resolve())
            (root/'kernel.elf').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'identity mismatch'):load_kernel(root)
    def test_path_escape_and_missing_assets_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)/'capsule';root.mkdir();m=self.capsule(root)
            outside=Path(name)/'outside';outside.write_bytes(b'secret')
            m['assets']['../outside']=hashlib.sha256(b'secret').hexdigest();(root/'libkernel.json').write_text(json.dumps(m))
            with self.assertRaisesRegex(ValueError,'identity mismatch'):load_kernel(root)
            del m['assets']['../outside'];del m['assets']['kernel.elf'];(root/'libkernel.json').write_text(json.dumps(m))
            with self.assertRaisesRegex(ValueError,'incomplete'):load_kernel(root)
    def test_invalid_hardware_or_layout_metadata_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);m=self.capsule(root)
            for section,key,value in [('hardware','counter_step',0),('hardware','uart_va',1),('process_layout','task_mm',-1)]:
                original=m[section][key];m[section][key]=value;(root/'libkernel.json').write_text(json.dumps(m))
                with self.subTest(key=key),self.assertRaisesRegex(ValueError,'metadata'):load_kernel(root)
                m[section][key]=original

class KernelPreparation(unittest.TestCase):
    def test_scalar_review_requires_count_loop_pattern(self):
        pc=0x800080368154;original=0xb26187fb
        words={pc:original,pc-8:0xaa1f03f8,pc+20:0xd1000718,pc+96:0xeb1b031f}
        kernel=SimpleNamespace(symbols=[dict(name='do_execveat_common',shndx=2,value=(pc-64)|0xffff000000000000,size=512)],
                               read=lambda va,n:struct.pack('<I',words[va&((1<<48)-1)]))
        package=SimpleNamespace(sites={pc:(original,0x20000000)},word=lambda va:0xd421e000)
        self.assertEqual(len(scalar_count_sites(kernel,package)),1)
        words[pc+20]=0x91000718 # incrementing pointer is not the reviewed counter loop
        self.assertEqual(scalar_count_sites(kernel,package),[])
    def test_scalar_flag_review_checks_full_mask_construction(self):
        pc=0x8000802d05d8;word=0x929f266a
        words={pc:word,pc+4:0x92400f2b,pc+8:0xf2b07e0a,pc+20:0xb26d014c,pc+28:0x9a8a0189}
        kernel=SimpleNamespace(symbols=[dict(name='do_mmap',shndx=2,value=(pc-64)|0xffff000000000000,size=512)],
                               read=lambda va,n:struct.pack('<I',words[va&((1<<48)-1)]))
        package=SimpleNamespace(sites={pc:(word,0x20000000)},word=lambda va:0xd421e000)
        self.assertEqual(len(scalar_flag_sites(kernel,package)),1)
        words[pc+8]^=1<<5
        self.assertEqual(scalar_flag_sites(kernel,package),[])
    def tables(self):
        base=0x40000000;data=bytearray(8*4096);put=lambda pa,v:struct.pack_into('<Q',data,pa-base,v)
        target=2<<39;put(base+3*8,base+4096|3);put(base+4096,base+8192|3);put(base+8192,base+12288|3)
        put(base+12288,base+16384|0x743)
        p=SimpleNamespace(h=(0,0,base,len(data)),memory=data,maps=[(target,base+16384,4096,0x740)])
        return p,base,put
    def test_bitmap_review_requires_first_zero_bit_search(self):
        pc=0x8000800a0540;word=0xb2689d08
        words={pc:word,pc+4:0xaa2803e9,pc+8:0xb100051f,pc+12:0xdac00129,pc+16:0xdac0112a}
        kernel=SimpleNamespace(symbols=[dict(name='mm_cid_get',shndx=2,value=(pc-64)|0xffff000000000000,size=512)],
                               read=lambda va,n:struct.pack('<I',words[va&((1<<48)-1)]))
        package=SimpleNamespace(sites={pc:(word,0x20000000)},word=lambda va:0xd421e000)
        self.assertEqual(len(scalar_bitmap_sites(kernel,package)),1)
        words[pc+16]=0xd61f0100 # branch through the candidate would not be a scalar search
        self.assertEqual(scalar_bitmap_sites(kernel,package),[])
    def test_shared_pgd_slot_recovered_only_from_equivalent_view(self):
        p,root,put=self.tables();before=bytes(p.memory)
        repair=shared_directory_aliases(p,root)
        self.assertEqual([(r['slot'],r['source_slot'],r['pages']) for r in repair],[(2,3,1)])
        self.assertEqual(bytes(p.memory),before) # planning never edits the source checkpoint
        put(root+12288,root+20480|0x743)
        self.assertEqual(shared_directory_aliases(p,root),[])
    def test_permission_mismatch_prevents_repair(self):
        p,root,put=self.tables();put(root+12288,root+16384|0x7c3)
        self.assertEqual(shared_directory_aliases(p,root),[])

class CoverageExpansion(unittest.TestCase):
    def test_native_macos_delivery_uses_native_loader_and_whole_kernel(self):
        with tempfile.TemporaryDirectory() as name:
            out=Path(name)
            user=out/'user'
            def emit(package,kernel,user,reference,image,extra,coverage,**options):
                self.assertTrue(options['whole_kernel_text'])
                self.assertTrue(options['no_model_page_tables'])
                image.mkdir()
                return {'whole_kernel_text':True}
            def build(command,**kwargs):
                self.assertIn('MACOS_NATIVE=1',command)
                (out/'runtime-attempt-0').mkdir()
            def validate(image,destination,*,user_elf,reference):
                self.assertEqual(user_elf,user)
                self.assertEqual(reference,out/'calls.json')
                destination.mkdir()
                return {'verified':True,'hypervisor':False}
            with patch('el0_application.export',side_effect=emit),patch('el0_application.subprocess.run',side_effect=build),\
                 patch('el0_macos_native.run',side_effect=validate) as native,patch('el0_macos.run') as hypervisor:
                _,reports,_=lower_application(out,out,out,user,out,'test-image',True,
                                              macos_cc='/usr/bin/clang',macos_native=True)
            self.assertFalse(reports['macos']['hypervisor'])
            native.assert_called_once()
            hypervisor.assert_not_called()
            self.assertTrue((out/'macos-validation').is_dir())

    def test_default_export_includes_whole_kernel_without_workload_coverage(self):
        with tempfile.TemporaryDirectory() as name:
            out=Path(name)
            (out/'coverage.log').write_text('0x800080000000: ret\n')
            def emit(package,kernel,user,reference,image,extra,coverage,*,whole_kernel_text):
                self.assertTrue(whole_kernel_text)
                self.assertEqual(extra,[])
                self.assertIsNone(coverage)
                image.mkdir()
                return {'whole_kernel_text':True}
            def build(command,**kwargs):
                (out/'runtime-attempt-0').mkdir()
            with patch('el0_application.export',side_effect=emit),patch('el0_application.subprocess.run',side_effect=build),\
                 patch('check_el0_program.run',return_value={'verified':True}),\
                 patch('check_el0_program.run_qemu',return_value={'verified':True}):
                result=lower_application(out,out,out,out/'user',out,'test-image',True)
            self.assertTrue(result[0]['whole_kernel_text'])
            self.assertEqual(result[2],[])

    def lower(self,reports):
        with tempfile.TemporaryDirectory() as name:
            out=Path(name);pc=0x80008026dd20;original=pc|0xffff000000000000
            code=SimpleNamespace(text=(original-64,original+512),containing=lambda p:original-64,
                                 extent=lambda p:(original-64,original+512),name=lambda p:'filemap_map_pages')
            extras=[]
            runtimes=[]
            def emit(package,kernel,user,reference,image,extra,coverage):
                image.mkdir();extras.append(list(extra));return {'source_instructions':100}
            def build(command,**kwargs):
                runtime=next(arg.rsplit('/',1)[-1] for arg in command if arg.startswith('OUT='))
                (out/runtime).mkdir()
                runtimes.append(runtime)
            with patch('el0_application.export',side_effect=emit),patch('el0_application.subprocess.run',side_effect=build),\
                 patch('check_el0_program.run',side_effect=reports),patch('check_el0_program.run_qemu',return_value={'verified':True}),\
                 patch('kernel_code_closure.Code',return_value=code):
                result=lower_application(out,out,out,out/'user',out,'test-image',True,kernel_slice=True)
                self.assertTrue((out/'program').is_dir())
                self.assertTrue((out/'runtime').is_dir())
                self.assertEqual(runtimes,[f'runtime-attempt-{attempt}' for attempt in range(len(extras))])
                return result,extras
    def test_missing_function_expands_and_reruns_from_same_state(self):
        result,extras=self.lower([{'verified':False,'result':{'reason':256,'missing_pc':0x80008026dd20}},
                                  {'verified':True,'result':{}}])
        self.assertEqual(extras,[[],[0x80008026dd20]])
        self.assertEqual(result[2][0]['function'],'filemap_map_pages')
    def test_unsupported_or_repeated_missing_target_does_not_loop(self):
        for reason,pc,count in [(3,0x80008026dd20,1),(256,0x80008026dd20,2),(256,0x80008026dd21,1),(256,0x1000,1)]:
            with self.subTest(reason=reason,pc=pc,count=count),self.assertRaisesRegex(ValueError,'continuation stopped'):
                self.lower([{'verified':False,'result':{'reason':reason,'missing_pc':pc}}]*count)

class LinuxBaseline(unittest.TestCase):
    def run_case(self,status=0,stdout=b'PASS\n',console=b'PASS\r\n',expect_exit=0,error=0,signal=0):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);reference=root/'reference';reference.mkdir();(reference/'console.txt').write_bytes(console)
            user=root/'user';user.write_bytes(b'ELF identity')
            def execute(command,**kwargs):
                self.assertIn('--read-only',command);self.assertIn('none',command)
                self.assertEqual(command[-2:],['demo','value with spaces'])
                process=dict(format='osrec-linux-user-baseline-v1',exec_errno=error,exit_status=status,signal=signal,
                             machine='aarch64',kernel_release='6.10.14-linuxkit')
                (root/'linux-baseline/process.json').write_text(json.dumps(process))
                return SimpleNamespace(returncode=0,stdout=stdout,stderr=b'')
            with patch('el0_application.subprocess.run',side_effect=execute):
                return linux_baseline(root,user,['demo','value with spaces'],reference,root,expect_exit)
    def test_exit_stdout_and_binary_identity_checked(self):
        result=self.run_case()
        self.assertTrue(result['verified']);self.assertEqual(result['arguments'],['program','demo','value with spaces'])
        self.assertEqual(result['user_sha256'],hashlib.sha256(b'ELF identity').hexdigest())
        self.assertTrue(self.run_case(status=10,stdout=b'',console=b'',expect_exit=10)['verified'])
    def test_disagreement_signal_and_exec_failure_rejected(self):
        cases=[dict(status=10),dict(stdout=b'FAIL\n'),dict(status=None,signal=11),dict(status=127,expect_exit=127,error=2),
               dict(stdout=b'PASS\r\n')] # only the captured TTY side is normalized
        for case in cases:
            with self.subTest(case=case),self.assertRaisesRegex(ValueError,'differs from captured'):self.run_case(**case)
    def test_timeout_stops_only_its_own_container(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            with patch('el0_application.subprocess.run',side_effect=[subprocess.TimeoutExpired('docker',1),SimpleNamespace(returncode=0)]) as run:
                with self.assertRaisesRegex(ValueError,'timed out'):linux_baseline(root,root/'user',[],root,root,0,timeout=1)
                launched=run.call_args_list[0].args[0];cleanup=run.call_args_list[1].args[0]
                self.assertEqual(cleanup,['docker','rm','--force',launched[launched.index('--name')+1]])

if __name__=='__main__':unittest.main()
