"""Generated ERET-to-user context switching against the shared emulator."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from el0_calls_fixture import save_context
from el0_hardware import indirect_resume, pc_index_data
from el0_return import descriptor_check_path,user_return_path

LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
CC=str(LLVM/'clang') if (LLVM/'clang').exists() else shutil.which('clang')
QEMU=shutil.which('qemu-system-aarch64')


class Admission(unittest.TestCase):
    def test_only_plain_eret_with_a_user_index_is_inlined(self):
        for word,metadata,index in ((0xd69f03e0,1,('index',0x2000,14)),
                                    (0xd65f03c0,0,('index',0x2000,14)),(0xd69f03e0,0,None)):
            self.assertEqual(user_return_path(0x8000,word,metadata,index),'')

    def test_descriptor_specialization_is_bounded_and_keeps_generic_fallback(self):
        for count in (None,-1,33,1000000):
            self.assertNotIn('hint_unrolled:',descriptor_check_path('hint_','slow',count))
        for count in (0,1,11,32):
            code=descriptor_check_path('hint_','slow',count)
            self.assertIn('cmp x16,#%d'%count,code)
            self.assertIn('b.eq hint_unrolled',code)
            self.assertEqual(code.count('ldr x12,[x12]'),count+1)
            self.assertIn('b.ne hint_checks',code)


@unittest.skipUnless(CC and QEMU,'AArch64 cross compiler and system QEMU required')
class Instructions(unittest.TestCase):
    def test_descriptor_counts_masks_early_rejection_and_no_overreads(self):
        lines=['.text','.global _start','_start:',
               'adrp x0,stack_end','add x0,x0,:lo12:stack_end','mov sp,x0',
               'bl test_main','adrp x1,exit_status','add x1,x1,:lo12:exit_status',
               'str x0,[x1,#8]','mov x0,#0x20','hlt #0xf000','b .']
        header=[]
        for i,count in enumerate((None,0,1,2,11,32,33)):
            prefix='probe%d_'%i
            lines+=['.global probe%d'%i,'probe%d:'%i]
            lines+=descriptor_check_path(prefix,prefix+'slow',count)
            lines+=['mov x0,#1','ret',prefix+'slow:','mov x0,#0','ret']
            header+=['extern int probe%d(void);'%i]
        header+=['static int (*const probes[])(void)={probe0,probe1,probe2,probe3,probe4,probe5,probe6};']
        lines+=['.data','.balign 16','exit_status: .quad 0x20026,1',
                '.bss','.balign 16','.space 65536','stack_end:']
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'test.S').write_text('\n'.join(lines)+'\n')
            (root/'cases.h').write_text('\n'.join(header)+'\n')
            compiled=subprocess.run([CC,'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                                     '-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                                     '-I'+str(root),'-Wl,-Ttext=0x40200000,-e,_start',str(root/'test.S'),
                                     str(ROOT/'tests/el0_descriptor_checks_host.c'),'-o',str(root/'test.elf')],capture_output=True)
            self.assertEqual(compiled.returncode,0,compiled.stderr.decode())
            result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                                   '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                                   '-semihosting-config','enable=on,target=native',
                                   '-device','loader,file=%s,cpu-num=0'%(root/'test.elf')],capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr.decode())

    def test_live_return_context_spsr_descriptors_indices_and_side_effect_free_fallback(self):
        self.return_fixture(validation=True)

    def test_execution_only_returns_ignore_saved_context_and_keep_architectural_checks(self):
        self.return_fixture(validation=False)

    def test_tracked_returns_keep_dirty_fallback_and_live_architectural_checks(self):
        for validation in (False,True):self.return_fixture(validation=validation,tracked=True)

    def return_fixture(self,validation,tracked=False):
        counts=(None,0,1,2,11,32,33)
        words=(0xd69f03e0,)*len(counts)
        lines=['.arch armv8-a+simd','.text','.global _start','_start:',
               'mov x1,#0x300000','msr cpacr_el1,x1','isb',
               'adrp x0,host_stack_end','add x0,x0,:lo12:host_stack_end','mov sp,x0',
               'bl test_main','mov x2,x0','adrp x1,exit_status','add x1,x1,:lo12:exit_status',
               'str x2,[x1,#8]','mov x0,#0x20','hlt #0xf000','b .']
        header=[]
        for i,word in enumerate(words):
            lines+=['.global probe%d'%i,'probe%d:'%i,'sub sp,sp,#96']
            lines+=['stp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
            lines+=['adrp x9,test_host_sp','mov x10,sp','str x10,[x9,:lo12:test_host_sp]',
                    'adrp x9,test_after','str x1,[x9,:lo12:test_after]',
                    'mov x9,#0x400000','msr fpcr,x9','mov x9,#1','movk x9,#0x800,lsl #16',
                    'msr fpsr,x9','mov x30,x0','ldr x9,[x30,#264]','msr nzcv,x9','ldr x9,[x30,#248]','mov sp,x9']
            lines+=['ldp x%d,x%d,[x30,#%d]'%(r,r+1,r*8) for r in range(0,30,2)]
            lines+=['ldr x30,[x30,#240]','movi v0.16b,#0x5a','movi v31.16b,#0xa5']
            lines+=user_return_path(0x8000+4*i,word,0,('user_index',0x2000,14),counts[i],validation=validation,tracked=tracked).splitlines()+['b common_slow']
            header+=['extern void probe%d(const struct osrec_context *,struct osrec_context *);'%i]
        for pc in (0x2000,0x3000):
            lines+=indirect_resume('.Li%x'%pc,'common_fast').splitlines()+['.Lr%x:'%pc,'b common_fast']
        lines+=['common_slow:','sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#0','b status',
                'common_fast:','sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#1',
                'status:','adrp x1,test_fast','str x0,[x1,:lo12:test_fast]',
                'adrp x1,test_vector','add x1,x1,:lo12:test_vector','stp q0,q31,[x1]',
                'mrs x0,fpsr','str x0,[x1,#32]','mrs x0,fpcr','str x0,[x1,#40]','ldp x0,x1,[sp]','add sp,sp,#16']
        lines+=save_context()
        lines+=['mov x0,sp','adrp x1,test_after','ldr x1,[x1,:lo12:test_after]','mov x2,#34',
                '1: ldr x3,[x0],#8','str x3,[x1],#8','subs x2,x2,#1','b.ne 1b',
                'adrp x9,test_host_sp','ldr x9,[x9,:lo12:test_host_sp]','mov sp,x9']
        lines+=['ldp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
        lines+=['add sp,sp,#96','ret','.data','.balign 16','exit_status: .quad 0x20026,1',
                '.bss','.balign 16','test_host_sp: .zero 8','test_after: .zero 8','.space 65536','host_stack_end:']
        lines+=['.section .rodata,"a"']+pc_index_data('user_index',(0x2000,0x3000),(0x2000,14)).splitlines()
        header+=['static const struct fixture fixtures[]={']
        for i,word in enumerate(words):header+=['{0x%x,0x%x,probe%d},'%(0x8000+4*i,word,i)]
        header+=['};']
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'test.S').write_text('\n'.join(lines)+'\n');(root/'cases.h').write_text('\n'.join(header))
            compiled=subprocess.run([CC,'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                                     '-DOSREC_FLAT_VALIDATION=%d'%validation,
                                     '-DOSREC_TRACK_PRETRANSLATED_WRITES=%d'%tracked,
                                     '-ffunction-sections','-fdata-sections','-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                                     '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),'-I'+str(root),
                                     '-Wl,-Ttext=0x40200000,-e,_start,--gc-sections',str(root/'test.S'),
                                     str(ROOT/'tests/el0_return_host.c'),str(ROOT/'runtime/el0/emulate.c'),str(ROOT/'runtime/el0_flat/bytes.c'),
                                     '-o',str(root/'test.elf')],capture_output=True)
            self.assertEqual(compiled.returncode,0,compiled.stderr.decode())
            result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                                   '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                                   '-semihosting-config','enable=on,target=native',
                                   '-device','loader,file=%s,cpu-num=0'%(root/'test.elf')],
                                  capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr.decode())


if __name__=='__main__':unittest.main()
