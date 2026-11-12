"""Execute inline lowered branches against boundary/scalar/pointer cases."""
import itertools
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from el0_hardware import immediate, lowered_branch_path

LLVM = Path('/opt/homebrew/opt/llvm@16/bin')
CC = str(LLVM / 'clang') if (LLVM / 'clang').exists() else shutil.which('clang')
QEMU = shutil.which('qemu-system-aarch64')


class Admission(unittest.TestCase):
    def test_only_reviewed_lowering_encodings_are_admitted(self):
        for word, metadata in ((0xb7f80040, 0), (0xb7f80040, 0xc0000000),
                               (0xb7f80040, 0x40000002), (0xd69f03e0, 0x40000000),
                               (0xb7000040, 0x40000000)):
            self.assertEqual(lowered_branch_path(0x100, word, metadata, str), '')


@unittest.skipUnless(CC and QEMU, 'AArch64 cross compiler and system QEMU required')
class Instructions(unittest.TestCase):
    def test_ranges_flags_register_aliases_branch_directions_and_ambiguous_stop(self):
        source=['.text', '.global _start', '_start:',
                'adrp x0,stack_end', 'add x0,x0,:lo12:stack_end', 'mov sp,x0']
        # Half-open ranges, holes, ordinary signed integers and tagged pointers.
        values=(0,0xfff,0x1000,0x1fff,0x2000,0x3000,0x4000,0x4fff,0x5000,
                1<<55,1<<63,(1<<64)-1)
        cases=itertools.product((55,63),(False,True),(False,True),(0,15,16,17,30,31),values,(0,1,2))
        for i,(bit,nonzero,reviewed,rt,value,range_count) in enumerate(cases):
            pc=0x1000+4*i
            displacement=-8 if i&1 else 8
            word=0xb6000000|((bit-32)<<19)|(int(nonzero)<<24)|((displacement//4&0x3fff)<<5)|rt
            metadata=0x40000000|int(reviewed)
            operand=value if rt!=31 else 0
            pointer=(range_count>=1 and 0x1000<=operand<0x2000) or (range_count==2 and 0x4000<=operand<0x5000)
            slow=pointer and bit==63 and not reviewed
            branch=(pointer or bool(operand&(1<<bit)))==nonzero
            expected='.Lslow%d'%i if slow else '.Ltaken%d'%i if branch else '.Lfall%d'%i
            registers={r:100+r for r in range(31)}
            if rt!=31:registers[rt]=operand
            # Test counter wraparound and each NZCV combination.
            count=(1<<64)-1 if i&1 else 41
            source+=['adrp x20,osrec_kernel_range_count',
                     'add x20,x20,:lo12:osrec_kernel_range_count','mov x21,#%d'%range_count,'str x21,[x20]',
                     'adrp x20,flat_shadow','add x20,x20,:lo12:flat_shadow']
            source+=immediate(21,count)+['str x21,[x20,#88]']
            source+=immediate(21,(i&15)<<28)+['msr nzcv,x21']
            for r,value in registers.items():source+=immediate(r,value)
            labels={pc+displacement:'.Ltaken%d'%i,pc+4:'.Lfall%d'%i}
            source+=lowered_branch_path(pc,word,metadata,labels.__getitem__).splitlines()
            source+=['b .Lslow%d'%i]
            for label in ('.Ltaken%d'%i,'.Lfall%d'%i,'.Lslow%d'%i):
                source+=[label+':','b '+('.Lcheck%d'%i if label==expected else 'fail')]
            source+=['.Lcheck%d:'%i, 'stp x20,x21,[sp,#-16]!', 'mrs x20,nzcv']
            source+=immediate(21,(i&15)<<28)+['cmp x20,x21','b.ne fail']
            source+=['ldp x20,x21,[sp],#16']
            for r,value in registers.items():
                # Store X0 first so it can become the comparison scratch.
                if r==0:source+=['str x0,[sp,#-16]!']
                else:source+=immediate(0,value)+['cmp x%d,x0'%r,'b.ne fail']
            source+=['ldr x1,[sp],#16']+immediate(0,registers[0])+['cmp x1,x0','b.ne fail',
                     'adrp x20,flat_shadow','add x20,x20,:lo12:flat_shadow','ldr x21,[x20,#88]']
            source+=immediate(0,(count+int(not slow))&((1<<64)-1))+['cmp x21,x0','b.ne fail',
                     'adrp x0,stack_end','add x0,x0,:lo12:stack_end','mov x1,sp','cmp x0,x1','b.ne fail']
        source+=['mov x2,#0','b exit','fail:','mov x2,#1','exit:',
                 'adrp x1,exit_status','add x1,x1,:lo12:exit_status','str x2,[x1,#8]',
                 'mov x0,#0x20','hlt #0xf000','b .', '.data','.balign 16',
                 'exit_status: .quad 0x20026,1', 'osrec_kernel_range_count: .quad 2',
                 'osrec_kernel_ranges: .quad 0x1000,0x2000,0x4000,0x5000',
                 'flat_shadow: .zero 96','.bss','.balign 16','.space 16384','stack_end:']
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'test.S').write_text('\n'.join(source)+'\n')
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
