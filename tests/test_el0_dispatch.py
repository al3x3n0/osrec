"""Guarded dispatch must preserve every GPR, SP and NZCV on hits and misses."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from el0_calls_fixture import save_context
from el0_hardware import indirect_resume
from el0_dispatch import Dispatch,dispatch_path,dispatch_data

LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
QEMU=shutil.which('qemu-system-aarch64')


@unittest.skipUnless(QEMU and (LLVM/'clang').exists(),'cross clang and system QEMU required')
class GuardedDispatch(unittest.TestCase):
    def test_live_pointer_index_aliases_holes_links_flags_and_fallback(self):
        self.exercise(False)

    def test_compact_live_pointer_index_aliases_holes_links_flags_and_fallback(self):
        self.exercise(True)

    def exercise(self,compact):
        lines=['.text','.global _start','_start:',
               'adrp x0,host_stack_end','add x0,x0,:lo12:host_stack_end','mov sp,x0',
               'bl test_main','mov x2,x0','adrp x1,exit_status','add x1,x1,:lo12:exit_status',
               'str x2,[x1,#8]','mov x0,#0x20','hlt #0xf000','b .']
        header=[];cases=[];plans={}
        for base in (0xd61f0000,0xd63f0000):
            for rn in (0,12,16,17,30):
                for index in (0,16,17,30,31):
                    i=len(cases);word=base|(rn<<5);pc=0x1000+4*i
                    cases.append((word,pc,index))
                    lines+=['.global probe%d'%i,'probe%d:'%i,'sub sp,sp,#96']
                    lines+=['stp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
                    lines+=['adrp x9,test_host_sp','mov x10,sp','str x10,[x9,:lo12:test_host_sp]',
                            'adrp x9,test_after','str x1,[x9,:lo12:test_after]',
                            'mov x30,x0','ldr x9,[x30,#264]','msr nzcv,x9',
                            'ldr x9,[x30,#248]','mov sp,x9']
                    lines+=['ldp x%d,x%d,[x30,#%d]'%(r,r+1,r*8) for r in range(0,30,2)]
                    lines+=['ldr x30,[x30,#240]']
                    plan=Dispatch(pc,word,pc-4,index,0x10000,'fixture',((0x100,0x100),(0x200,None),(0x300,0x300)))
                    lines+=dispatch_path(plan,compact=compact).splitlines()+['b common_slow']
                    plans[pc]=plan
                    header+=['extern void probe%d(const struct osrec_context *,struct osrec_context *);'%i]
        lines+=dispatch_data(plans).splitlines()
        for pc in (0x100,0x300):
            lines+=indirect_resume('.Li%x'%pc,'common_fast',compact=compact).splitlines()
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
                '.bss','.balign 16','test_host_sp: .zero 8','test_after: .zero 8','.space 65536','host_stack_end:']
        header+=['static const struct fixture fixtures[]={']
        header+=['{0x%x,0x%x,%d,probe%d},'%(word,pc,index,i) for i,(word,pc,index) in enumerate(cases)]
        header+=['};']
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);(out/'fixture.S').write_text('\n'.join(lines)+'\n');(out/'cases.h').write_text('\n'.join(header))
            built=subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                                  '-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                                  '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),'-I'+str(out),
                                  '-Wl,-Ttext=0x40200000,-e,_start',str(out/'fixture.S'),
                                  str(ROOT/'tests/el0_dispatch_host.c'),str(ROOT/'runtime/el0_flat/bytes.c'),
                                  '-o',str(out/'fixture')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            process=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                                    '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                                    '-semihosting-config','enable=on,target=native','-device',
                                    'loader,file='+str(out/'fixture')+',cpu-num=0'],capture_output=True,text=True,timeout=30)
            self.assertEqual(process.returncode,0,process.stderr)


if __name__=='__main__':unittest.main()
