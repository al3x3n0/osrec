"""Native UART register-buffer operations and evidence recording contracts."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from el0_calls_fixture import save_context
from el0_flat_lower import decode, atomic_group
from el0_uart import uart_path

LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
CC=str(LLVM/'clang') if (LLVM/'clang').exists() else shutil.which('clang')
QEMU=shutil.which('qemu-system-aarch64')


class Admission(unittest.TestCase):
    def test_wide_user_exclusive_and_disabled_uart_keep_handler(self):
        for word in (0xf9400020,0xa9400820,0xb8400820,0xf9800020):
            self.assertEqual(uart_path(0x1000,decode(word),'next',0x2000000),'')
        op,_=atomic_group({0:0x885f7d0b,4:0x880afd09},0)
        self.assertEqual(uart_path(0,op,'next',0x2000000),'')
        self.assertEqual(uart_path(0,decode(0xb9400020),'next',0),'')


@unittest.skipUnless(CC and QEMU,'AArch64 cross compiler and system QEMU required')
class Instructions(unittest.TestCase):
    def test_registers_privilege_offsets_writeback_flags_capacity_and_uart_bytes(self):
        words=(0xb9400020,0xb9000020,0x39400030,0x39000030,0x79400020,0x79000020,
               0xb9800020,0xb8008c30,0xb8008430,0xb94003e0,0xb90003e0,
               0xb862d820,0x88dffc20,0xb80087e0,0xbd400020,0xbd000020,0xb940003f,0xb900003f)
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
                    'mov x30,x0','ldr x9,[x30,#264]','msr nzcv,x9','ldr x9,[x30,#248]','mov sp,x9']
            lines+=['ldp x%d,x%d,[x30,#%d]'%(r,r+1,r*8) for r in range(0,30,2)]
            lines+=['ldr x30,[x30,#240]','movi v0.16b,#0x5a']
            lines+=uart_path(0x1000+4*i,decode(word),'common_fast',0x2000000).splitlines()+['b common_slow']
            header+=['extern void probe%d(const struct osrec_context *,struct osrec_context *);'%i]
        lines+=['common_slow:','sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#0','b status',
                'common_fast:','sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#1',
                'status:','adrp x1,test_fast','str x0,[x1,:lo12:test_fast]',
                'adrp x1,test_vector','str q0,[x1,:lo12:test_vector]','ldp x0,x1,[sp]','add sp,sp,#16']
        lines+=save_context()
        lines+=['mov x0,sp','adrp x1,test_after','ldr x1,[x1,:lo12:test_after]','mov x2,#34',
                '1: ldr x3,[x0],#8','str x3,[x1],#8','subs x2,x2,#1','b.ne 1b',
                'adrp x9,test_host_sp','ldr x9,[x9,:lo12:test_host_sp]','mov sp,x9']
        lines+=['ldp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
        lines+=['add sp,sp,#96','ret','.data','.balign 16','exit_status: .quad 0x20026,1',
                '.bss','.balign 16','test_host_sp: .zero 8','test_after: .zero 8','.space 65536','host_stack_end:']
        header+=['static const struct fixture fixtures[]={']
        for i,word in enumerate(words):header+=['{0x%x,probe%d},'%(word,i)]
        header+=['};']
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'test.S').write_text('\n'.join(lines)+'\n');(root/'cases.h').write_text('\n'.join(header))
            compiled=subprocess.run([CC,'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                                     '-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                                     '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),'-I'+str(root),
                                     '-Wl,-Ttext=0x40200000,-e,_start',str(root/'test.S'),
                                     str(ROOT/'tests/el0_uart_host.c'),str(ROOT/'runtime/el0_flat/bytes.c'),
                                     '-o',str(root/'test.elf')],capture_output=True)
            self.assertEqual(compiled.returncode,0,compiled.stderr.decode())
            result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                                   '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                                   '-semihosting-config','enable=on,target=native',
                                   '-device','loader,file=%s,cpu-num=0'%(root/'test.elf')],
                                  capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr.decode())


if __name__=='__main__':unittest.main()
