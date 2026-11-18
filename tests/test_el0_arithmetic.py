"""Execute address lowering against an independent C arithmetic oracle."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from el0_hardware import immediate,add_immediate,add_register_offset
from el0_user_memory import ram_offset_path
from el0_calls_fixture import save_context

CC=Path('/opt/homebrew/opt/llvm@16/bin/clang')
QEMU=shutil.which('qemu-system-aarch64')
MASK=(1<<64)-1


@unittest.skipUnless(CC.exists() and QEMU,'AArch64 compiler and QEMU required')
class Arithmetic(unittest.TestCase):
    def test_wide_constants_offsets_aliases_bounds_and_all_flags(self):
        # Tuple fields match the independent host fixture, followed by scratch.
        constants=(0,1,0xffff,1<<16,1<<32,1<<48,0x800080000000,
                   MASK-7,0xffffffff00000000,0xffff0000ffff0000,
                   0xfffefffffffdfffc,0x123456789abcdef0,MASK)
        cases=[(0,r,0,0,0,0,v,0,0,0,16) for r in range(32) for v in constants]
        offsets=(-1,-8,-4095,-4096,-4097,-0xfff000,-0xfff001,-(1<<63),
                 0,1,8,4095,4096,4097,0xfff000,0xfff001)
        cases += [(1,d,b,0,0,0,v&MASK,0,0,0,s) for d,b,s in
                  ((0,0,16),(1,0,16),(16,0,16),(0,16,17),(30,0,16)) for v in offsets]
        cases += [(2,d,b,r,e,shift,0,0,0,0,s) for d,b,r,s in
                  ((0,0,1,16),(1,0,1,16),(16,0,1,17),(0,0,31,16),
                   (30,17,16,14),(17,17,0,16),(0,0,0,16))
                  for e in (2,3,6,7) for shift in (0,3,4,5,31,63)]
        for base,length in ((0x40000000,0x33000000),(0x40000000,65536),
                (0x40001000,65536),(0x40000000,0x40001000),(0,65536),
                (1<<63,65536),(0x10000,0x10000)):
            for size in (1,8,32,4096):
                for address in (base-1,base,base+1,base+length-size,
                        base+length-size+1,base+length-1,base+length,0,MASK,
                        base^(1<<63),base|(1<<62)):
                    cases.append((3,0,0,0,0,0,address&MASK,base,length,size,16))
        lines=['.text','.global _start','_start:','adrp x0,host_stack_end',
               'add x0,x0,:lo12:host_stack_end','mov sp,x0','bl test_main',
               'adrp x1,exit_status','add x1,x1,:lo12:exit_status','str x0,[x1,#8]',
               'mov x0,#0x20','hlt #0xf000','b .']
        header=[]
        for i,(kind,d,b,r,e,shift,value,ram_base,length,size,scratch) in enumerate(cases):
            lines+=['.global probe%d'%i,'probe%d:'%i,'sub sp,sp,#96']
            lines+=['stp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
            lines+=['adrp x9,test_host_sp','mov x10,sp','str x10,[x9,:lo12:test_host_sp]',
                    'adrp x9,test_after','str x1,[x9,:lo12:test_after]','mov x30,x0',
                    'ldr x9,[x30,#264]','msr nzcv,x9','ldr x9,[x30,#248]','mov sp,x9']
            lines+=['ldp x%d,x%d,[x30,#%d]'%(r,r+1,r*8) for r in range(0,30,2)]
            lines+=['ldr x30,[x30,#240]']
            if kind==0:lines+=immediate(d,value)
            elif kind in (1,2):
                if scratch!=d:lines+=['str x%d,[sp,#-16]!'%scratch]
                lines += add_immediate(d,b,value,scratch) if kind==1 else add_register_offset(d,b,r,e,shift,scratch)
                if scratch!=d:lines+=['ldr x%d,[sp],#16'%scratch]
            else:
                lines+=['stp x16,xzr,[sp,#-16]!','mrs x16,nzcv','str x16,[sp,#8]']
                lines+=ram_offset_path(0,16,ram_base,length,size,'reject%d'%i)
                lines+=['b bounds%d'%i,'reject%d:'%i]+immediate(0,MASK)
                lines+=['bounds%d:'%i,'ldr x16,[sp,#8]','msr nzcv,x16','ldr x16,[sp],#16']
            lines+=['b capture']
            header+=['extern void probe%d(const struct osrec_context *,struct osrec_context *);'%i]
        lines+=['capture:']+save_context()+['mov x0,sp','adrp x1,test_after',
                'ldr x1,[x1,:lo12:test_after]','mov x2,#34','1: ldr x3,[x0],#8',
                'str x3,[x1],#8','subs x2,x2,#1','b.ne 1b','adrp x9,test_host_sp',
                'ldr x9,[x9,:lo12:test_host_sp]','mov sp,x9']
        lines+=['ldp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
        lines+=['add sp,sp,#96','ret','.data','.balign 16','exit_status: .quad 0x20026,1',
                '.bss','.balign 16','test_host_sp: .zero 8','test_after: .zero 8',
                '.space 65536','host_stack_end:']
        header+=['static const struct fixture fixtures[]={']
        for i,case in enumerate(cases):
            header+=['{'+','.join('0x%xull'%v for v in case[:-1])+',probe%d},'%i]
        header+=['};']
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'test.S').write_text('\n'.join(lines)+'\n')
            (root/'cases.h').write_text('\n'.join(header)+'\n')
            compiled=subprocess.run([str(CC),'--target=aarch64-none-elf','-fuse-ld=lld',
                '-nostdlib','-O2','-ffreestanding','-fno-builtin','-mgeneral-regs-only',
                '-Wall','-Wextra','-Werror','-I'+str(ROOT/'runtime/el0_flat'),
                '-I'+str(ROOT/'runtime/el0'),'-I'+str(root),'-Wl,-Ttext=0x40200000,-e,_start',
                str(root/'test.S'),str(ROOT/'tests/el0_arithmetic_host.c'),
                str(ROOT/'runtime/el0_flat/bytes.c'),'-o',str(root/'test.elf')],capture_output=True)
            self.assertEqual(compiled.returncode,0,compiled.stderr.decode())
            result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off',
                '-cpu','cortex-a53','-accel','tcg','-nodefaults','-display','none',
                '-monitor','none','-serial','none','-semihosting-config','enable=on,target=native',
                '-device','loader,file=%s,cpu-num=0'%(root/'test.elf')],capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr.decode())
        print('%d probes, %d full-context comparisons'%(len(cases),len(cases)*160))


if __name__=='__main__':unittest.main()
