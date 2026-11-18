"""Execution-only exports omit evidence checks without accepting failed execution."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from kernel_source_verify import Elf
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')


class Ranges(unittest.TestCase):
    def test_trusted_abi_requires_explicit_execution_only_mode(self):
        from export_el0_program import export
        with self.assertRaisesRegex(ValueError,'requires --no-validation'):
            export(None,None,None,None,None,trust_syscall_abi=True)

    def test_resume_stack_intervals_exclude_readonly_and_immutable_physical_aliases(self):
        from el0_return import user_resume_ranges
        aliases=[dict(va=0x1000,pa=0x8000,bytes=0x4000,attrs=0x443),
                 dict(va=0x5000,pa=0xc000,bytes=0x1000,attrs=0x443),
                 dict(va=0x7000,pa=0xd000,bytes=0x1000,attrs=0x4c3)]
        self.assertEqual(user_resume_ranges(aliases,[(0x9000,0x1000),(0x9800,0x1000)]),
                         [(0x1000,0x2000),(0x3800,0x6000)])
        self.assertEqual(user_resume_ranges([dict(va=0,pa=0,bytes=32,attrs=0)],[]),[])


@unittest.skipUnless(shutil.which('cc'),'host C compiler required')
class Terminal(unittest.TestCase):
    def test_validation_is_default_and_only_execution_failures_reject_production(self):
        with tempfile.TemporaryDirectory() as directory:
            for validation in (None,0):
                with self.subTest(validation=validation):
                    binary=Path(directory)/('checked' if validation is None else 'production')
                    flags=[] if validation is None else ['-DOSREC_FLAT_VALIDATION=0']
                    dead_strip=['-Wl,-dead_strip'] if sys.platform=='darwin' else ['-Wl,--gc-sections']
                    build=subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror',
                        '-ffunction-sections','-fdata-sections','-DOSREC_LOWERED',*flags,
                        '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),
                        str(ROOT/'tests/el0_production_host.c'),str(ROOT/'runtime/el0_flat/memory.c'),
                        *dead_strip,'-o',str(binary)],capture_output=True,text=True)
                    self.assertEqual(build.returncode,0,build.stderr)
                    run=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
                    self.assertEqual(run.returncode,0,run.stderr)


@unittest.skipUnless((LLVM/'clang').exists() and shutil.which('make'),'cross compiler and make required')
class BuildMode(unittest.TestCase):
    def test_reused_object_directory_rejects_image_mode_and_profile_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            image=Path(directory)
            for validation,profile in ((0,0),(1,1),(1,0),(0,0)):
                with self.subTest(validation=validation,profile=profile):
                    objects=image/('objects-%d-%d'%(validation,profile))
                    (image/'runtime-config.h').write_text('#define OSREC_FLAT_VALIDATION %d\n'%validation)
                    command=['make','-s','-C',str(ROOT/'runtime/el0_flat'),
                        'CC='+str(LLVM/'clang')+' --target=aarch64-none-elf',
                        'IMAGE='+str(image),'OUT='+str(objects),'PROFILE=%d'%profile,
                        str(objects/'program.o'),str(objects/'gateway-asm.o')]
                    build=subprocess.run(command,capture_output=True,text=True,timeout=60)
                    self.assertEqual(build.returncode,0,build.stdout+build.stderr)
                    names={s['name'] for s in Elf(objects/'program.o').symbols if s['shndx']}
                    helpers={s['name'] for s in Elf(objects/'gateway-asm.o').symbols if s['shndx']}
                    self.assertEqual('flat_user_return_state' in names,bool(validation))
                    self.assertEqual('flat_copy_user_context' in helpers,bool(validation))
                    self.assertEqual('flat_memory_profile' in names,bool(profile))
                    changed_command=[('PROFILE=%d'%(1-profile)) if arg.startswith('PROFILE=') else arg for arg in command]
                    changed=subprocess.run(changed_command,capture_output=True,text=True,timeout=60)
                    self.assertNotEqual(changed.returncode,0)
                    self.assertIn('use a fresh OUT directory',changed.stderr)
                    (image/'runtime-config.h').write_text('#define OSREC_FLAT_VALIDATION %d\n'%(1-validation))
                    changed=subprocess.run(command,capture_output=True,text=True,timeout=60)
                    self.assertNotEqual(changed.returncode,0)
                    self.assertIn('use a fresh OUT directory',changed.stderr)


@unittest.skipUnless(os.environ.get('OSREC_EL0_PRODUCTION_IMAGE'),'execution-only full image not selected')
class FullImage(unittest.TestCase):
    def test_native_syscall_metadata_is_bound_to_writable_ranges_and_source_operations(self):
        import hashlib
        from el0_hardware_model import prepare
        image=Path(os.environ['OSREC_EL0_PRODUCTION_IMAGE']).resolve()
        original=json.loads((image/'hardware-memory.json').read_text())
        if not original.get('native_syscall_entry'):self.skipTest('native syscall entry not selected')
        with tempfile.TemporaryDirectory() as directory:
            for mode in ('range','source','count'):
                changed=Path(directory)/mode;changed.mkdir()
                (changed/'checkpoint').symlink_to(image/'checkpoint')
                metadata=json.loads(json.dumps(original));manifest=json.loads((image/'manifest.json').read_text())
                entry=metadata['native_syscall_entry']
                if mode=='range':entry['stack_range'][0]+=16
                elif mode=='source':entry['sites'][0][1]^=32
                else:manifest['native_syscall_sites']+=1
                raw=(json.dumps(metadata,indent=2)+'\n').encode();(changed/'hardware-memory.json').write_bytes(raw)
                manifest['hardware_memory_sha256']=hashlib.sha256(raw).hexdigest()
                (changed/'manifest.json').write_text(json.dumps(manifest))
                message='native syscall stack interval' if mode=='range' else 'native syscall source sites'
                with self.assertRaisesRegex(ValueError,message):prepare(changed,Path(directory)/(mode+'-model'),LLVM)

    def test_ledger_context_helpers_and_expected_outputs_are_absent_and_mode_is_bound(self):
        import struct
        from el0_hardware_model import prepare
        image=Path(os.environ['OSREC_EL0_PRODUCTION_IMAGE']).resolve()
        manifest=json.loads((image/'manifest.json').read_text());self.assertIs(manifest['runtime_validation'],False)
        elf=Elf(image/'checkpoint');syms={s['name']:s for s in elf.symbols if s['shndx']}
        for name in ('flat_events','flat_user_return_state','flat_copy_user_context','flat_user_context_difference'):
            self.assertNotIn(name,syms)
        self.assertEqual(struct.unpack('<Q',elf.read(syms['flat_validation_enabled']['value'],8))[0],0)
        self.assertEqual(struct.unpack('<Q',elf.read(syms['flat_program']['value']+88,8))[0],0)
        self.assertEqual((image/'expected.bin').read_bytes(),b'')
        self.assertEqual((image/'uart.bin').read_bytes(),b'')
        self.assertGreater((image/'counters.bin').stat().st_size,0)
        if not manifest.get('trust_syscall_abi',False):self.assertEqual(manifest['user_native_memory_instructions'],0)
        with tempfile.TemporaryDirectory() as directory:
            changed=Path(directory)/'changed';changed.mkdir()
            for p in image.iterdir():
                if p.name!='manifest.json':(changed/p.name).symlink_to(p)
            manifest['runtime_validation']=True
            (changed/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'runtime validation mode differs'):
                prepare(changed,Path(directory)/'model',LLVM)

    @unittest.skipUnless(shutil.which('qemu-system-aarch64'),'QEMU required')
    def test_invalid_return_stack_stops_before_native_access(self):
        import struct
        from el0_hardware_model import prepare,run
        image=Path(os.environ['OSREC_EL0_PRODUCTION_IMAGE']).resolve();elf=Elf(image/'checkpoint')
        syms={s['name']:s for s in elf.symbols if s['shndx']}
        count=struct.unpack('<Q',elf.read(syms['flat_kernel_direct_count']['value'],8))[0]
        rows=elf.read(syms['flat_kernel_direct_pcs']['value'],count*16)
        thunk=next(native for pc,native in struct.iter_unpack('<2Q',rows) if pc==0x80008001217c)
        word=struct.unpack('<I',elf.read(thunk+4,4))[0];self.assertEqual(word&0xfc000000,0x14000000)
        delta=word&0x3ffffff
        if delta&(1<<25):delta-=1<<26
        entry=thunk+4+4*delta
        words=struct.unpack('<20I',elf.read(entry,80))
        offset=words.index(0xf9400e2c)*4 # LDR X12,[X17,#24], after the shadow base is established.
        section=next(s for s in elf.sections if s['addr']<=entry+offset<s['addr']+s['size'])
        data=bytearray(elf.data)
        struct.pack_into('<I',data,section['offset']+entry+offset-section['addr'],0xf900023f) # STR XZR,[X17]: invalid SP_EL0.
        with tempfile.TemporaryDirectory() as directory:
            changed=Path(directory)/'image';changed.mkdir()
            for p in image.iterdir():
                if p.name!='checkpoint':(changed/p.name).symlink_to(p)
            (changed/'checkpoint').write_bytes(data)
            prepared=Path(directory)/'model';prepare(changed,prepared,LLVM)
            result=run(changed,prepared,Path(directory)/'execution')
            self.assertFalse(result['verified']);self.assertEqual(result['hardware_exceptions'],0)
            self.assertEqual(result['result']['detail'],0x104)
            self.assertFalse(result['runtime_el1_services'])


if __name__=='__main__':unittest.main()
