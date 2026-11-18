"""Exercise runtime SIMD context helpers and immutable-map admission indexing."""
from pathlib import Path
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
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU=shutil.which('qemu-system-aarch64')


class RuntimeProfileCounters(unittest.TestCase):
    @unittest.skipUnless(shutil.which('cc'),'host C compiler required')
    def test_cached_keys_row_order_overflow_and_counter_wrap_match_original(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/'profile'
            built=subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror',
                '-I'+str(ROOT/'runtime/el0_flat'),str(ROOT/'tests/el0_runtime_profile_host.c'),'-o',str(binary)],
                capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            run=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)

    @unittest.skipUnless(shutil.which('cc'),'host C compiler required')
    def test_warm_target_cache_retains_domain_stack_mapping_and_legacy_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/'targets'
            dead_strip=['-Wl,-dead_strip'] if sys.platform=='darwin' else ['-Wl,--gc-sections']
            built=subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror',
                '-ffunction-sections','-fdata-sections','-DOSREC_LOWERED','-I'+str(ROOT/'runtime/el0_flat'),
                '-I'+str(ROOT/'runtime/el0'),str(ROOT/'tests/el0_target_cache_host.c'),*dead_strip,'-o',str(binary)],
                capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            run=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)


@unittest.skipUnless(QEMU and (LLVM/'clang').exists(),'cross clang and QEMU required')
class RuntimeHotPaths(unittest.TestCase):
    def test_bit_exact_context_checks_fp_state_and_mapping_revalidation(self):
        assembly='''.text
.global _start
_start:
    mov x0,#0x300000
    msr cpacr_el1,x0
    isb
    adrp x0,identity_root
    add x0,x0,:lo12:identity_root
    adrp x1,identity_l1
    add x1,x1,:lo12:identity_l1
    orr x1,x1,#3
    str x1,[x0]
    msr ttbr0_el1,x0
    ldr x0,=0x80103510
    msr tcr_el1,x0
    mov x0,#255
    msr mair_el1,x0
    dsb sy
    tlbi vmalle1
    dsb sy
    isb
    ldr x0,=0x30d01805
    msr sctlr_el1,x0
    isb
    adrp x0,stack_end
    add x0,x0,:lo12:stack_end
    mov sp,x0
    bl test_main
    mov x2,x0
    adrp x1,exit_status
    add x1,x1,:lo12:exit_status
    str x2,[x1,#8]
    mov x0,#0x20
    hlt #0xf000
.global checked_context_difference
checked_context_difference:
    stp x29,x30,[sp,#-16]!
    bl seed_state
    bl flat_user_context_difference
    b check_state
.global checked_context_copy
checked_context_copy:
    stp x29,x30,[sp,#-16]!
    bl seed_state
    bl flat_copy_user_context
    mov x0,#0
check_state:
    mrs x9,nzcv
    mov x10,#0xa0000000
    cmp x9,x10
    b.ne broken
    mrs x9,fpsr
    mov x10,#1
    movk x10,#0x800,lsl #16
    cmp x9,x10
    b.ne broken
    mrs x9,fpcr
    mov x10,#0x400000
    cmp x9,x10
    b.ne broken
    ldp x29,x30,[sp],#16
    ret
broken:
    mov x0,#65535
    ldp x29,x30,[sp],#16
    ret
seed_state:
    mov x9,#0xa0000000
    msr nzcv,x9
    mov x9,#1
    movk x9,#0x800,lsl #16
    msr fpsr,x9
    mov x9,#0x400000
    msr fpcr,x9
    ret
.data
.balign 16
exit_status: .quad 0x20026,1
.balign 4096
identity_root: .zero 4096
identity_l1: .quad 0,0x40000701
.zero 4080
.bss
.balign 16
.space 65536
stack_end:
'''
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);(out/'fixture.S').write_text(assembly)
            built=subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                '-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                '-I'+str(ROOT/'runtime/el0'),'-I'+str(ROOT/'runtime/el0_flat'),'-Wl,-Ttext=0x40200000,-e,_start',
                str(out/'fixture.S'),str(ROOT/'tests/el0_runtime_hot_host.c'),str(ROOT/'runtime/el0_flat/gateway.S'),
                str(ROOT/'runtime/el0_flat/gateway.c'),str(ROOT/'runtime/el0_flat/bytes.c'),'-o',str(out/'fixture')],
                capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            run=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                '-nodefaults','-display','none','-monitor','none','-serial','none',
                '-semihosting-config','enable=on,target=native','-device','loader,file='+str(out/'fixture')+',cpu-num=0'],
                capture_output=True,text=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)


@unittest.skipUnless(os.environ.get('OSREC_EL0_RUNTIME_FAST_IMAGE'),'full optimized runtime ELF not selected')
class RuntimeImageDiagnostics(unittest.TestCase):
    def test_corrupted_remembered_gpr_and_pc_retain_stop_diagnostics(self):
        from el0_hardware_model import prepare,run
        image=Path(os.environ['OSREC_EL0_RUNTIME_FAST_IMAGE']).resolve();elf=Elf(image/'checkpoint')
        helper=next(s['value'] for s in elf.symbols if s['name']=='flat_copy_user_context')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name,delta,expected in (('gpr',4,0x106),('pc',68,0x107)):
                changed=root/name;changed.mkdir();data=bytearray(elf.data);va=helper+delta
                section=next(s for s in elf.sections if s['addr']<=va<s['addr']+s['size'])
                offset=section['offset']+va-section['addr'];word,=struct.unpack_from('<I',data,offset)
                if name=='gpr':
                    self.assertEqual(word&31,0);self.assertEqual(word>>10&31,1)
                    word=(word&~31)|1 # Remember X2/X3 in place of X0/X1.
                else:
                    self.assertEqual(word,0xf9008002)
                    word=(word&~31)|31 # Remember PC as zero.
                struct.pack_into('<I',data,offset,word);(changed/'checkpoint').write_bytes(data)
                for file in ('manifest.json','hardware-memory.json'):(changed/file).symlink_to(image/file)
                prepared=root/(name+'-model');prepare(changed,prepared,LLVM)
                checked=run(changed,prepared,root/(name+'-validation'))
                self.assertFalse(checked['verified']);self.assertEqual(checked['result']['detail'],expected)
                if name=='gpr':self.assertEqual(checked['result']['far'],1)
                self.assertEqual(checked['hardware_exceptions'],0)
                self.assertFalse(checked['runtime_el1_services']);self.assertEqual(checked['host_calls_before_completion'],0)


if __name__=='__main__':unittest.main()
