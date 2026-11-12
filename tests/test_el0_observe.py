"""Inline result observation preserves event evidence and fallback state."""
from pathlib import Path
import itertools
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from el0_hardware import immediate, observe_path

LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
CC=str(LLVM/'clang') if (LLVM/'clang').exists() else shutil.which('clang')
QEMU=shutil.which('qemu-system-aarch64')


@unittest.skipUnless(CC and QEMU,'AArch64 cross compiler and system QEMU required')
class Instructions(unittest.TestCase):
    def test_event_fields_ranges_page_crossing_flags_registers_and_fallback(self):
        source=['.text','.global _start','_start:',
                'adrp x0,stack_end','add x0,x0,:lo12:stack_end','mov sp,x0']
        offsets=(-8,0,1,4088,4089,4096,8184,8185,8192)
        cases=itertools.product((False,True),((0,0),(0,8192),(0,4096),(4096,8192)),offsets,range(16))
        for i,(pending,(lo,hi),offset,flags) in enumerate(cases):
            admitted=lo<=offset<=hi-8 and offset%8==0 and hi!=0
            observed=pending and admitted
            slow=pending and not admitted
            source+=['adrp x20,event','add x20,x20,:lo12:event']
            for field in range(10):source+=['mov x21,#%d'%(1000+field),'str x21,[x20,#%d]'%(8*field)]
            source+=['adrp x21,flat_observer_pending','add x21,x21,:lo12:flat_observer_pending',
                     'str %s,[x21]'%('x20' if pending else 'xzr'),
                     'adrp x22,buffer','add x22,x22,:lo12:buffer']
            source+=immediate(23,offset)+['add x22,x22,x23','str x22,[x21,#8]']
            # Populate only admitted source addresses. Rejected addresses can
            # point outside RAM; the fallback must never dereference them.
            if admitted:source+=['mov x23,#777','str x23,[x22]']
            source+=['adrp x21,flat_direct_read','add x21,x21,:lo12:flat_direct_read']
            if hi:
                source+=['adrp x22,buffer','add x22,x22,:lo12:buffer']
                source+=immediate(23,lo)+['add x23,x22,x23','str x23,[x21]']
                source+=immediate(23,hi)+['add x23,x22,x23','str x23,[x21,#8]']
            else:source+=['str xzr,[x21]','str xzr,[x21,#8]']
            source+=immediate(21,flags<<28)+['msr nzcv,x21']
            for r in range(31):source+=immediate(r,100+r)
            source+=observe_path(0x1000+i*4,'.Lfast%d'%i).splitlines()
            source+=['b '+('.Lcheck%d'%i if slow else 'fail'),'.Lfast%d:'%i,
                     'b '+('fail' if slow else '.Lcheck%d'%i),'.Lcheck%d:'%i,
                     'stp x20,x21,[sp,#-16]!','mrs x20,nzcv']
            source+=immediate(21,flags<<28)+['cmp x20,x21','b.ne fail','ldp x20,x21,[sp],#16']
            source+=['str x0,[sp,#-16]!']
            for r in range(1,31):source+=immediate(0,100+r)+['cmp x%d,x0'%r,'b.ne fail']
            source+=['ldr x1,[sp],#16','cmp x1,#100','b.ne fail',
                     'adrp x20,event','add x20,x20,:lo12:event']
            for field in range(10):
                expected=777 if observed and field==8 else 1 if observed and field==9 else 1000+field
                source+=['ldr x21,[x20,#%d]'%(field*8),'cmp x21,#%d'%expected,'b.ne fail']
            source+=['adrp x21,flat_observer_pending','add x21,x21,:lo12:flat_observer_pending',
                     'ldr x22,[x21]','cmp x22,%s'%('x20' if slow else 'xzr'),'b.ne fail',
                     'ldr x22,[x21,#8]','adrp x23,buffer','add x23,x23,:lo12:buffer']
            source+=immediate(0,offset)+['add x23,x23,x0','cmp x22,x23','b.ne fail',
                     'adrp x0,stack_end','add x0,x0,:lo12:stack_end','mov x1,sp','cmp x0,x1','b.ne fail']
        source+=['mov x2,#0','b exit','fail:','mov x2,#1','exit:',
                 'adrp x1,exit_status','add x1,x1,:lo12:exit_status','str x2,[x1,#8]',
                 'mov x0,#0x20','hlt #0xf000','b .','.data','.balign 16',
                 'exit_status: .quad 0x20026,1','flat_observer_pending: .zero 16',
                 'event: .zero 80','flat_direct_read: .zero 32',
                 '.balign 4096','buffer: .zero 8192',
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
