"""Compare inline syscall entry with the shared architecture emulator."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from el0_calls_fixture import save_context
from el0_hardware import indirect_resume, immediate, pc_index_data
from el0_syscall import syscall_path,native_syscall_path

LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
CC=str(LLVM/'clang') if (LLVM/'clang').exists() else shutil.which('clang')
QEMU=shutil.which('qemu-system-aarch64')


class Admission(unittest.TestCase):
    def test_invalid_encodings_metadata_and_pc_keep_the_handler(self):
        for pc,word,metadata in ((0x1001,0xd4000001,0),(0x1000,0xd69f03e0,0),
                                 (0x1000,0xd4000001,1),((1<<64)-4,0xd4000001,0)):
            self.assertEqual(syscall_path(pc,word,metadata),'')

    def test_native_entry_requires_a_plain_svc_index_and_bounded_stack_interval(self):
        index=('kernel_index',0x4000,14)
        for pc,word,metadata,idx,span in ((0x1001,0xd4000001,0,index,(0,4096)),
                (0x1000,0xd69f03e0,0,index,(0,4096)),(0x1000,0xd4000001,1,index,(0,4096)),
                (0x1000,0xd4000001,0,None,(0,4096)),(0x1000,0xd4000001,0,index,None),
                (0x1000,0xd4000001,0,index,(0,63)),((1<<64)-4,0xd4000001,0,index,(0,4096)),
                (0x1000,0xd4000001,0,index,((1<<64)-64,1<<64))):
            self.assertEqual(native_syscall_path(pc,word,metadata,idx,span),'')


@unittest.skipUnless(CC and QEMU,'AArch64 cross compiler and system QEMU required')
class Instructions(unittest.TestCase):
    def test_native_sp_entry_vectors_stack_aliases_flags_and_atomic_rejection(self):
        words=(0xd4000001,0xd4024681)
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
            lines+=native_syscall_path(0x1000+4*i,word,0,('kernel_index',0x4000,14),(0x41000000,0x41004000)).splitlines()+['b common_slow']
            header+=['extern void probe%d(const struct osrec_context *,struct osrec_context *);'%i]
        for pc in (0x5000,0x6000):
            lines+=indirect_resume('.Li%x'%pc,'hit%x'%pc,compact=True).splitlines()+['.Lr%x:'%pc,'b hit%x'%pc]
            lines+=['hit%x:'%pc,'sub sp,sp,#16','stp x0,x1,[sp]']+immediate(0,pc)
            lines+=['adrp x1,test_target','str x0,[x1,:lo12:test_target]',
                    'ldp x0,x1,[sp]','add sp,sp,#16','b common_fast']
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
        lines+=['.section .rodata,"a"']+pc_index_data('kernel_index',(0x5000,0x6000),(0x4000,14)).splitlines()
        header+=['static const struct fixture fixtures[]={']
        for i,word in enumerate(words):header+=['{0x%x,0x%x,probe%d},'%(0x1000+4*i,word,i)]
        header+=['};']
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'test.S').write_text('\n'.join(lines)+'\n');(root/'cases.h').write_text('\n'.join(header))
            compiled=subprocess.run([CC,'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                '-ffunction-sections','-fdata-sections','-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),'-I'+str(root),
                '-Wl,-Ttext=0x40200000,-e,_start,--gc-sections,--section-start=.kernel_stack=0x41000000',
                str(root/'test.S'),str(ROOT/'tests/el0_native_syscall_host.c'),str(ROOT/'runtime/el0/emulate.c'),
                str(ROOT/'runtime/el0_flat/bytes.c'),'-o',str(root/'test.elf')],capture_output=True)
            self.assertEqual(compiled.returncode,0,compiled.stderr.decode())
            result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                '-semihosting-config','enable=on,target=native','-device','loader,file=%s,cpu-num=0'%(root/'test.elf')],
                capture_output=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr.decode())

    def test_syscall_events_shadow_stack_flags_vectors_and_rejections(self):
        words=(0xd4000001,0xd4024681)
        lines=['.text','.global _start','_start:',
               'adrp x0,host_stack_end','add x0,x0,:lo12:host_stack_end','mov sp,x0',
               'bl test_main','mov x2,x0','adrp x1,exit_status','add x1,x1,:lo12:exit_status',
               'str x2,[x1,#8]','mov x0,#0x20','hlt #0xf000','b .']
        for i,word in enumerate(words):
            lines+=['.global probe%d'%i,'probe%d:'%i,'sub sp,sp,#96']
            lines+=['stp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
            lines+=['adrp x9,test_host_sp','mov x10,sp','str x10,[x9,:lo12:test_host_sp]',
                    'adrp x9,test_after','str x1,[x9,:lo12:test_after]',
                    'mov x30,x0','ldr x9,[x30,#264]','msr nzcv,x9',
                    'ldr x9,[x30,#248]','mov sp,x9']
            lines+=['ldp x%d,x%d,[x30,#%d]'%(r,r+1,r*8) for r in range(0,30,2)]
            lines+=['ldr x30,[x30,#240]']
            lines+=syscall_path(0x1000+4*i,word).splitlines()+['b common_slow']
        for i,pc in enumerate((0,0x5000,0xa000)):
            lines+=['.global resume%d'%i]+indirect_resume('resume%d'%i,'hit%d'%i).splitlines()
            lines+=['hit%d:'%i,'sub sp,sp,#16','stp x0,x1,[sp]']+immediate(0,pc)
            lines+=['adrp x1,test_target','str x0,[x1,:lo12:test_target]',
                    'ldp x0,x1,[sp]','add sp,sp,#16','b common_fast']
        lines+=['common_slow:','sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#0','b status',
                'common_fast:','sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#1',
                'status:','adrp x1,test_fast','str x0,[x1,:lo12:test_fast]',
                'ldp x0,x1,[sp]','add sp,sp,#16']
        lines+=save_context()
        lines+=['mov x0,sp','adrp x1,test_after','ldr x1,[x1,:lo12:test_after]','mov x2,#34',
                '1: ldr x3,[x0],#8','str x3,[x1],#8','subs x2,x2,#1','b.ne 1b',
                'adrp x9,test_host_sp','ldr x9,[x9,:lo12:test_host_sp]','mov sp,x9']
        lines+=['ldp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
        lines+=['add sp,sp,#96','ret','.data','.balign 16','exit_status: .quad 0x20026,1',
                '.bss','.balign 16','test_host_sp: .zero 8','test_after: .zero 8',
                '.space 65536','host_stack_end:']
        header='\n'.join('extern void probe%d(const struct osrec_context *,struct osrec_context *);'%i for i in range(len(words)))
        header+='\nstatic const struct fixture fixtures[]={\n'
        header+=''.join('{0x%x,0x%x,probe%d},\n'%(0x1000+4*i,word,i) for i,word in enumerate(words))+'};\n'
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'test.S').write_text('\n'.join(lines)+'\n');(root/'cases.h').write_text(header)
            compiled=subprocess.run([CC,'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                                     '-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                                     '-ffunction-sections','-fdata-sections','-I'+str(ROOT/'runtime/el0_flat'),
                                     '-I'+str(ROOT/'runtime/el0'),'-I'+str(root),'-Wl,-Ttext=0x40200000,-e,_start,--gc-sections',
                                     str(root/'test.S'),str(ROOT/'tests/el0_syscall_host.c'),
                                     str(ROOT/'runtime/el0/emulate.c'),str(ROOT/'runtime/el0_flat/bytes.c'),
                                     '-o',str(root/'test.elf')],capture_output=True)
            self.assertEqual(compiled.returncode,0,compiled.stderr.decode())
            result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                                   '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                                   '-semihosting-config','enable=on,target=native',
                                   '-device','loader,file=%s,cpu-num=0'%(root/'test.elf')],
                                  capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr.decode())


if __name__=='__main__':unittest.main()
