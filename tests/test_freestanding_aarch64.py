"""Execute all AArch64 replay ABIs at two independently selected ELF layouts."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from freestanding_elf import describe
from freestanding_armv7 import audit
from run_freestanding_armv7 import observe,require_success
from rtl_load_bundle import prepare as prepare_bundle
from rtl_boot_bundle import prepare as prepare_boot_bundle,check_loaded as check_boot_bundle
from verify_qemu_bundle import verify as verify_on_qemu
from aarch64_entry_state import capture_qemu_entry,check_entry_state
from aarch64_boot import validate as validate_boot,BOOT_ADDRESS
from export_freestanding_umask import export as umask
from export_freestanding_identity import export as identity
from export_freestanding_scalar import export as scalar
from export_freestanding_read import export as read
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
KERNEL=ROOT/'build/kernel_liteos_a'
QEMU='qemu-system-aarch64'
import test_freestanding_umask as mask_tests
import test_freestanding_identity as identity_tests
import test_freestanding_scalar as scalar_tests
import test_freestanding_read as read_tests

class AArch64Tests(unittest.TestCase):
    def test_observe_implemented_higher_levels_without_execution(self):
        with tempfile.TemporaryDirectory() as name:
            pipe=Path(name)/'registers'
            for suffix in ('.in','.out'):os.mkfifo(str(pipe)+suffix,0o600)
            command=[QEMU,'-M','virt-9.2,secure=on,virtualization=on','-cpu','cortex-a53',
                '-nodefaults','-display','none','-serial','none','-monitor','none','-S','-qmp','stdio',
                '-chardev',f'pipe,path={pipe},id=entryregs','-gdb','chardev:entryregs']
            process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                self.assertIn('QMP',json.loads(process.stdout.readline()))
                def request(name,arguments=None):
                    message={'execute':name,'id':name}
                    if arguments is not None:message['arguments']=arguments
                    process.stdin.write(json.dumps(message).encode()+b'\n');process.stdin.flush()
                    while True:
                        reply=json.loads(process.stdout.readline())
                        if reply.get('id')==name:
                            self.assertNotIn('error',reply);return reply['return']
                request('qmp_capabilities');cpu=request('query-cpus-fast')[0]
                implementation={f'el{level}_implemented':request('qom-get',{'path':cpu['qom-path'],'property':f'has_el{level}'}) for level in (2,3)}
                self.assertEqual(implementation,{'el2_implemented':True,'el3_implemented':True})
                self.assertFalse(request('query-status')['running'])
                state=capture_qemu_entry(pipe,implementation)
                self.assertEqual(state['format'],'osrec-aarch64-entry-state-v2')
                for key in ('mdscr_el1','hcr_el2','cptr_el2','mdcr_el2','scr_el3','cptr_el3','mdcr_el3'):
                    self.assertIs(type(state[key]),int)
                self.assertEqual(state['pstate']&31,13) # QEMU reset EL3h.
                self.assertFalse(request('query-status')['running'])
                with self.assertRaisesRegex(ValueError,'EL1t or EL1h'):
                    check_entry_state({'isa':'AArch64','entry':state['pc']},state)
            finally:
                process.terminate();process.wait(timeout=3)
                process.stdin.close();process.stdout.close();process.stderr.close()

    def test_relocated_images_without_construction_inputs(self):
        for entry,result in ((0x40200000,0x40180000),(0x40400000,0x40380000)):
            for name,export,version in (('umask',umask,1),('identity',identity,2),('scalar',scalar,3),('read',read,4)):
                with self.subTest(name=name,entry=entry),tempfile.TemporaryDirectory() as directory:
                    stage=Path(directory)
                    capture=stage/'capture'
                    if name=='umask':mask_tests.capture(capture,0xdeadbeef)
                    if name=='identity':
                        fixture=identity_tests.IdentityImageTests();fixture.setUp()
                        fixture.capture(capture,fixture.rows,fixture.results)
                    if name=='scalar':scalar_tests.ScalarImageTests().capture(capture,0xdeadbeef)
                    if name=='read':
                        capture=stage/'capture/capture.json'
                        read_tests.ReadImageTests().capture(SimpleNamespace(capture=capture),json.loads((ROOT/'examples/sysread_session_case.json').read_text()))
                    args=SimpleNamespace(arch='aarch64',entry_address=entry,result_address=result,capture=capture,
                        kernel_root=KERNEL,llvm_bin=LLVM,qemu=QEMU,out=stage/'image')
                    with contextlib.redirect_stdout(io.StringIO()):export(args)
                    elf=args.out/(name+'.elf');layout=describe(elf)
                    self.assertEqual(layout['isa'],'AArch64');self.assertEqual(layout['entry'],entry)
                    self.assertEqual(layout['result_address'],result)
                    validate_boot(layout)
                    with self.assertRaisesRegex(ValueError,'overlaps'):
                        validate_boot(layout,entry)
                    with self.assertRaisesRegex(ValueError,'page aligned'):
                        validate_boot(layout,BOOT_ADDRESS+1)
                    with self.assertRaisesRegex(ValueError,'requires CPU entry checking'):
                        observe(elf,'does-not-exist-qemu',boot_from_el3=True)
                    shutil.rmtree(stage/'capture')
                    shutil.rmtree(args.out/'sources')
                    (args.out/'checkpoint.json').unlink();(args.out/'manifest.json').unlink()
                    initial=stage/'elf-initial'
                    actual,raw=observe(elf,QEMU,initial_memory_dir=initial);require_success(actual)
                    binary_actual,binary_raw=observe(args.out/(name+'.bin'),QEMU,descriptor=elf,initial_memory_dir=stage/'raw-initial')
                    require_success(binary_actual);self.assertEqual(raw,binary_raw)
                    for raw_mode in (False,True):
                        bundle=stage/('raw-bundle' if raw_mode else 'elf-bundle')
                        prepare_bundle(elf,[{'address':0x40000000,'bytes':64*1024*1024}],bundle,args.out/(name+'.bin') if raw_mode else None)
                        bundled,bundled_raw=observe(bundle/'image.elf',QEMU,
                            initial_memory_dir=stage/(bundle.name+'-snapshot'),load_bundle=bundle,check_cpu_entry=True)
                        require_success(bundled);self.assertEqual(raw,bundled_raw)
                        self.assertTrue(bundled['initial_memory_verified'])
                        loaded=json.loads((stage/(bundle.name+'-snapshot')/'memory-preflight.json').read_text())
                        bundle_plan=json.loads((bundle/'load-plan.json').read_text())
                        self.assertEqual(loaded['format'],'osrec-rtl-loaded-bundle-verification-v2')
                        self.assertTrue(loaded['model_initial_memory_verified']);self.assertTrue(loaded['snapshot_phase_verified'])
                        self.assertTrue(loaded['cpu_entry_state_verified'])
                        self.assertTrue(loaded['cpu_entry_verification']['snapshot_phase_verified'])
                        self.assertTrue(loaded['cpu_entry_verification']['higher_el_trap_configuration_verified'])
                        self.assertEqual(loaded['cpu_entry_verification']['implementation'],{'el2_implemented':False,'el3_implemented':False})
                        self.assertEqual(loaded['cpu_entry_verification']['registers']['pc'],entry)
                        self.assertEqual(loaded['initial_memory_verification']['verified_bytes'],sum(b['bytes'] for b in bundle_plan['banks']))
                        plain_verification=stage/(bundle.name+'-qemu-verification')
                        verified=verify_on_qemu(bundle,plain_verification,QEMU)
                        self.assertEqual(verified['status'],'verified')
                        self.assertEqual(verified['boot_payload_bytes_verified'],0)
                        self.assertEqual((plain_verification/'target-result.bin').read_bytes(),raw)
                        boot_snapshot=stage/(bundle.name+'-boot-snapshot')
                        portable=stage/(bundle.name+'-portable')
                        boot_address=BOOT_ADDRESS-0x1000 if raw_mode else BOOT_ADDRESS
                        prepare_boot_bundle(bundle,portable,LLVM,boot_address)
                        moved=stage/(bundle.name+'-moved-portable')
                        portable.rename(moved);portable=moved
                        shutil.rmtree(bundle)
                        for auxiliary in (portable/'boot').iterdir():
                            if auxiliary.name not in ('boot.bin','boot-plan.json'):auxiliary.unlink()
                        with patch('aarch64_boot.build',side_effect=AssertionError('runtime compiler use')):
                            verified=verify_on_qemu(portable,boot_snapshot,QEMU)
                        booted=json.loads((boot_snapshot/'execution-report.json').read_text())
                        booted_raw=(boot_snapshot/'target-result.bin').read_bytes()
                        self.assertEqual(verified['status'],'verified')
                        self.assertTrue(verified['functional_result_verified'])
                        self.assertTrue(verified['checkpoint_phase_verified'])
                        self.assertEqual(verified['boot_payload_bytes_verified'],104)
                        with self.assertRaises(FileExistsError):verify_on_qemu(portable,boot_snapshot,QEMU)
                        if name=='umask' and entry==0x40200000 and not raw_mode:
                            failed=stage/'failed-verification'
                            with patch('verify_qemu_bundle.require_success',side_effect=ValueError('replay diverged')):
                                with self.assertRaisesRegex(ValueError,'replay diverged'):verify_on_qemu(portable,failed,QEMU)
                            self.assertEqual(json.loads((failed/'verification.json').read_text())['status'],'failed')
                            self.assertFalse((failed/'target-result.bin').exists())
                        require_success(booted);self.assertEqual(raw,booted_raw)
                        boot_loaded=json.loads((boot_snapshot/'memory-preflight.json').read_text())
                        for boot_phase in ('before_boot','at_replay_entry'):
                            boot_memory=boot_loaded['boot_memory_verification'][boot_phase]
                            self.assertTrue(boot_memory['model_boot_memory_verified'])
                            self.assertTrue(boot_memory['snapshot_phase_verified'])
                            self.assertEqual(boot_memory['initial_memory_verification']['verified_bytes'],104)
                        self.assertIn('after self-contained EL3 boot',boot_loaded['snapshot_phase'])
                        boot_cpu=boot_loaded['cpu_entry_verification']
                        self.assertEqual(boot_cpu['implementation'],{'el2_implemented':True,'el3_implemented':True})
                        self.assertTrue(boot_cpu['snapshot_phase_verified'])
                        self.assertTrue(boot_cpu['implementation_presence_observed'])
                        self.assertTrue(boot_cpu['higher_el_trap_configuration_verified'])
                        self.assertEqual(boot_cpu['registers']['pstate']&31,5)
                        self.assertEqual(boot_cpu['registers']['pc'],entry)
                        self.assertIn('after self-contained EL3 boot',boot_cpu['snapshot_backend'])
                        self.assertEqual(boot_loaded['initial_memory_verification']['verified_bytes'],sum(b['bytes'] for b in bundle_plan['banks']))
                        reset=json.loads((boot_snapshot/'boot-reset-state.json').read_text())
                        self.assertEqual(reset['pstate']&31,13)
                        self.assertEqual(reset['pc'],boot_address)
                        boot_plan=json.loads((boot_snapshot/'boot/boot-plan.json').read_text())
                        self.assertEqual(boot_plan['replay_entry'],entry)
                        self.assertFalse(boot_plan['runtime_host_interaction'])
                        dumps=[{'address':d['address'],'file':Path(d['file'])} for d in boot_loaded['initial_memory_verification']['dump_files']]
                        dumps.append({'address':boot_address,'file':boot_snapshot/'boot-replay-entry.bin'})
                        portable_checked=check_boot_bundle(portable,[{'address':0x40000000,'bytes':64*1024*1024}],dumps,boot_snapshot/'cpu-entry-state.json')
                        self.assertTrue(portable_checked['model_initial_memory_verified'])
                        self.assertTrue(portable_checked['cpu_entry_state_verified'])
                        self.assertFalse(portable_checked['snapshot_phase_verified'])
                    for directory in (initial,stage/'raw-initial'):
                        preflight=json.loads((directory/'memory-preflight.json').read_text())
                        self.assertTrue(preflight['initial_memory_verified'])
                        self.assertIn('CPU stopped before first instruction',preflight['snapshot_backend'])
                        self.assertTrue(all(Path(d['file']).is_file() for d in preflight['initial_memory_verification']['dump_files']))
                    with self.assertRaises(FileExistsError):observe(elf,'does-not-exist-qemu',initial_memory_dir=initial)
                    self.assertEqual(actual['abi_version'],version)
                    # ELF64 service traps, invalid entries, and dynamic segments are rejected.
                    original=elf.read_bytes();phoff=struct.unpack_from('<Q',original,32)[0]
                    segment=next(s for s in layout['load_segments'] if s['flags']&1)
                    bad=stage/'bad.elf'
                    data=bytearray(original)
                    struct.pack_into('<I',data,segment['file_offset']+entry-segment['address'],0xd4400000) # HLT
                    bad.write_bytes(data)
                    with self.assertRaisesRegex(ValueError,'service/trap'):audit(bad,LLVM)
                    data=bytearray(original);struct.pack_into('<Q',data,24,result);bad.write_bytes(data)
                    with self.assertRaisesRegex(ValueError,'entry'):describe(bad)
                    data=bytearray(original);struct.pack_into('<I',data,phoff,3);bad.write_bytes(data)
                    with self.assertRaisesRegex(ValueError,'dynamic loader'):describe(bad)

if __name__=='__main__':
    if len(sys.argv)==4:
        KERNEL=Path(sys.argv[1]);LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    for module in (mask_tests,identity_tests,scalar_tests,read_tests):module.KERNEL=KERNEL
    unittest.main()
