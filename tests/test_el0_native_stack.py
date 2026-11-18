"""Exercise native and logical stack transitions with the real context gateway."""
from pathlib import Path
import json
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from kernel_source_verify import Elf
from el0_flat_lower import decode
from el0_hardware import memory_path
from el0_user_memory import user_memory_path

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU=shutil.which('qemu-system-aarch64')


class NativeStackAddress(unittest.TestCase):
    def test_checked_exclusive_and_explicit_user_access_use_live_sp(self):
        from el0_flat_lower import atomic_group
        op,group=atomic_group({0:0x885f7feb,4:0x880affed},0)
        text=memory_path(0,op,'next',group,native_sp=True)
        self.assertIn('sp,#32',text)
        self.assertNotIn('flat_active',text)
        user=decode(0xb8400be0) # LDTR w0,[sp]
        text=user_memory_path(0,user,'next',0x40000000,0x33006000,0x100072b5503510,native_sp=True)
        self.assertIn('sp,#64',text)
        self.assertNotIn('flat_active',text)


@unittest.skipUnless(QEMU and (LLVM/'clang').exists(),'cross clang and system QEMU required')
class NativeStackGateway(unittest.TestCase):
    def test_switches_all_gprs_simd_flags_fp_state_native_sp_and_private_handler_stack(self):
        source='''#include "gateway.inc"
.arch armv8-a+simd
.text
.global _start
_start:
    mov x0,#0x300000
    msr cpacr_el1,x0
    isb
    adrp x0,host_stack_end
    add x0,x0,:lo12:host_stack_end
    mov sp,x0
    bl test_main
    mov x2,x0
    adrp x1,exit_status
    add x1,x1,:lo12:exit_status
    str x2,[x1,#8]
    mov x0,#0x20
    hlt #0xf000
    b .
native_body:
    stp x0,x1,[sp,#-32]!
    ldp x0,x1,[sp],#32
    sub sp,sp,#64
    str x16,[sp,#8]
    ldr x16,[sp,#8]
    add sp,sp,#64
flat_native_capture native_capture1,0x1000
flat_native_resume native_entry,native_body
native_body2:
    sub sp,sp,#64
    eor x0,x0,x30
    add x16,x16,x17
    eor v31.16b,v31.16b,v0.16b
flat_native_capture native_capture2,0x2000
flat_native_resume native_second,native_body2
flat_capture user_capture,0x3000
flat_resume user_entry,user_capture
flat_native_capture native_capture3,0x4000
flat_native_resume native_last,native_capture3
private_store:
    stp x29,x30,[x16]
flat_capture private_capture,0x5000
flat_resume private_entry,private_store
flat_native_capture native_capture4,0x6000
flat_native_resume native_final,native_capture4
.data
.balign 16
exit_status: .quad 0x20026,1
.bss
.balign 16
.space 65536
host_stack_end:
'''
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);(out/'fixture.S').write_text(source)
            built=subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                                  '-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                                  '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),
                                  '-Wl,-Ttext=0x40200000,-e,_start',str(out/'fixture.S'),
                                  str(ROOT/'tests/el0_native_stack_host.c'),str(ROOT/'runtime/el0_flat/gateway.c'),
                                  str(ROOT/'runtime/el0_flat/gateway.S'),str(ROOT/'runtime/el0_flat/bytes.c'),
                                  '-o',str(out/'fixture')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            def run(binary):
                return subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                                       '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                                       '-semihosting-config','enable=on,target=native','-device',
                                       'loader,file='+str(binary)+',cpu-num=0'],capture_output=True,text=True,timeout=30)
            process=run(out/'fixture');self.assertEqual(process.returncode,0,process.stderr)
            elf=Elf(out/'fixture');data=bytearray(elf.data)
            pc=next(s['value'] for s in elf.symbols if s['name']=='native_entry')+7*4
            section=next(s for s in elf.sections if s['addr']<=pc<s['addr']+s['size'])
            offset=section['offset']+pc-section['addr'];word,=struct.unpack_from('<I',data,offset)
            # Deliberately break the final native restore of x17. The same
            # independently checked context fixture must reject the image.
            struct.pack_into('<I',data,offset,(word&~(31<<10))|(31<<10))
            (out/'corrupted').write_bytes(data)
            self.assertEqual(run(out/'corrupted').returncode,1)


@unittest.skipUnless(os.environ.get('OSREC_EL0_NATIVE_STACK_IMAGE'),'set native-stack image for full negative checks')
class NativeStackImage(unittest.TestCase):
    def test_compiled_mode_cannot_receive_logical_stack_mapping_metadata(self):
        from el0_hardware_model import prepare
        image=Path(os.environ['OSREC_EL0_NATIVE_STACK_IMAGE']).resolve()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);changed=root/'changed';changed.mkdir()
            (changed/'checkpoint').symlink_to(image/'checkpoint')
            metadata=json.loads((image/'hardware-memory.json').read_text());del metadata['native_kernel_stack']
            raw=(json.dumps(metadata,indent=2)+'\n').encode();(changed/'hardware-memory.json').write_bytes(raw)
            manifest=json.loads((image/'manifest.json').read_text());manifest['native_kernel_stack']=False
            manifest['hardware_memory_sha256']=hashlib.sha256(raw).hexdigest()
            (changed/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'stack mode differs'):
                prepare(changed,root/'model',LLVM)

    def test_bad_sp_and_cross_domain_vector_stop_before_native_access(self):
        from el0_hardware_model import prepare,run
        image=Path(os.environ['OSREC_EL0_NATIVE_STACK_IMAGE']).resolve()
        manifest=json.loads((image/'manifest.json').read_text())
        self.assertTrue(manifest['native_kernel_stack'])
        elf=Elf(image/'checkpoint')
        shadow=next(s['value'] for s in elf.symbols if s['name']=='flat_shadow')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for label,field,value,detail in [('bad-sp',8,0x123400001000,0x104),
                                             ('bad-vector',64,int(manifest['initial_pc'],0)-0x400,0x103)]:
                changed=root/label;changed.mkdir()
                data=bytearray(elf.data);va=shadow+field
                section=next(s for s in elf.sections if s['addr']<=va<s['addr']+s['size'])
                struct.pack_into('<Q',data,section['offset']+va-section['addr'],value)
                (changed/'checkpoint').write_bytes(data)
                for name in ('manifest.json','hardware-memory.json'):(changed/name).symlink_to(image/name)
                prepared=root/(label+'-model');prepare(changed,prepared,LLVM)
                checked=run(changed,prepared,root/(label+'-validation'))
                self.assertFalse(checked['verified'])
                self.assertEqual(checked['hardware_exceptions'],0)
                self.assertFalse(checked['runtime_el1_services'])
                self.assertEqual(checked['host_calls_before_completion'],0)
                self.assertEqual(checked['result']['detail'],detail)


if __name__=='__main__':unittest.main()
