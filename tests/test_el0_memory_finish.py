"""Exercise memory completion without a second full-context gateway."""
from pathlib import Path
import itertools
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from el0_flat_lower import decode, atomic_group, WB
from el0_hardware import immediate, memory_finish_path

LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
CC=str(LLVM/'clang') if (LLVM/'clang').exists() else shutil.which('clang')
QEMU=shutil.which('qemu-system-aarch64')


class Admission(unittest.TestCase):
    def test_exclusive_windows_keep_their_existing_completion(self):
        op,body=atomic_group({0:0x885f7d0b,4:0x880afd09},0)
        self.assertEqual(memory_finish_path(0,op,'.Lnext'),'')


@unittest.skipUnless(CC and QEMU,'AArch64 cross compiler and system QEMU required')
class Instructions(unittest.TestCase):
    def test_writeback_scratch_results_flags_simd_and_uart_fallback(self):
        source=['.text','.global _start','_start:',
                'mov x0,#0x300000','msr cpacr_el1,x0','isb',
                'adrp x0,stack_end','add x0,x0,:lo12:stack_end','mov sp,x0']
        # Plain and paired accesses, scratch aliases, logical SP and both
        # indexed modes. Values represent the registers after native execution.
        words=(0xf9400020,0xf9400030,0xf9400200,0xf9000030,0x3dc00020,
               0xf8008c30,0xa8c10820,0xf81f0ff0,0xa8c10be1,0xf8400c20)
        for i,(word,uart,flags) in enumerate(itertools.product(words,(False,True),range(16))):
            op=decode(word)
            base,temp=op.info&31,op.info>>10&31
            source+=['adrp x20,flat_memory_pending','add x20,x20,:lo12:flat_memory_pending',
                     'mov x21,#777','str x21,[x20,#8]',
                     'mov x21,#999','str x21,[x20,#16]',
                     'mov x21,#%d'%uart,'str x21,[x20,#40]',
                     'adrp x20,control','add x20,x20,:lo12:control',
                     'mov x21,#555','str x21,[x20]',
                     'movi v0.16b,#0x55','movi v31.16b,#0xaa']
            source+=immediate(21,flags<<28)+['msr nzcv,x21']
            for r in range(31):source+=immediate(r,100+r)
            source+=memory_finish_path(0x1000+i*4,op,'.Lfast%d'%i).splitlines()
            source+=['b '+('.Lcheck%d'%i if uart else 'fail'),'.Lfast%d:'%i,
                     'b '+('fail' if uart else '.Lcheck%d'%i),'.Lcheck%d:'%i,
                     'stp x20,x21,[sp,#-16]!','mrs x20,nzcv']
            source+=immediate(21,flags<<28)+['cmp x20,x21','b.ne fail','ldp x20,x21,[sp],#16']
            expected={r:100+r for r in range(31)}
            if not uart:
                expected[temp]=777
                if op.info&WB and base!=31:expected[base]=999
            source+=['str x0,[sp,#-16]!']
            for r in range(1,31):source+=immediate(0,expected[r])+['cmp x%d,x0'%r,'b.ne fail']
            source+=['ldr x1,[sp],#16']+immediate(0,expected[0])+['cmp x1,x0','b.ne fail',
                     'adrp x0,control','add x0,x0,:lo12:control','ldr x1,[x0]',
                     'cmp x1,#%d'%(999 if not uart and op.info&WB and base==31 else 555),'b.ne fail',
                     'adrp x0,stack_end','add x0,x0,:lo12:stack_end','mov x1,sp','cmp x0,x1','b.ne fail']
            # Native load results in SIMD lanes must survive completion too.
            for vector,value in ((0,0x5555555555555555),(31,0xaaaaaaaaaaaaaaaa)):
                for lane in (0,1):
                    source+=['umov x1,v%d.d[%d]'%(vector,lane)]+immediate(0,value)+['cmp x0,x1','b.ne fail']
        source+=['mov x2,#0','b exit','fail:','mov x2,#1','exit:',
                 'adrp x1,exit_status','add x1,x1,:lo12:exit_status','str x2,[x1,#8]',
                 'mov x0,#0x20','hlt #0xf000','b .','.data','.balign 16',
                 'exit_status: .quad 0x20026,1','flat_memory_pending: .zero 48',
                 'flat_active: .quad control','control: .zero 16',
                 '.bss','.balign 16','.space 16384','stack_end:']
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'test.S').write_text('\n'.join(source)+'\n')
            subprocess.run([CC,'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib',
                            '-Wl,-Ttext=0x40200000,-e,_start',str(root/'test.S'),'-o',str(root/'test.elf')],
                           check=True,capture_output=True)
            result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                                   '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                                   '-semihosting-config','enable=on,target=native',
                                   '-device','loader,file=%s,cpu-num=0'%(root/'test.elf')],
                                  capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr.decode())


if __name__=='__main__':unittest.main()
