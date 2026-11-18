"""Range proofs and executable semantics for compact native control lowering."""
from pathlib import Path
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from el0_control import gateway_sizes,layout,relax_branches
from el0_flat_lower import local_conditional
from el0_hardware import immediate
from el0_calls_fixture import save_context
from kernel_source_verify import Elf

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');CC=LLVM/'clang'
QEMU=shutil.which('qemu-system-aarch64');GATEWAY=ROOT/'runtime/el0_flat/gateway.inc'


def long_branch(word,target):
    bits=14 if word&0x7e000000==0x36000000 else 19
    inverse=(word^1) if word&0xff000010==0x54000000 else word^(1<<24)
    inverse=(inverse&~(((1<<bits)-1)<<5))|(2<<5)
    return '    .inst 0x%x\n    b %s\n'%(inverse,target)


class RangeProofs(unittest.TestCase):
    def test_forward_backward_signed_range_edges_and_conservative_rejections(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'test.S'
            for word,bits in ((0x54000000,19),(0x34000000,19),(0x36000000,14)):
                limit=1<<(bits+1)
                for delta,accepted in ((limit-4,True),(limit,False),(-limit,True),(-limit-4,False)):
                    with self.subTest(word=hex(word),delta=delta):
                        if delta>0:
                            source='.text\n.Lp1000:\n'+long_branch(word,'.Lp2000')+'    nop\n'*((delta-8)//4)+'.Lp2000:\n    ret\n'
                        else:
                            source='.text\n.Lp2000:\n'+'    nop\n'*((-delta)//4)+'.Lp1000:\n'+long_branch(word,'.Lp2000')
                        path.write_text(source);proof=relax_branches(path,GATEWAY)
                        self.assertEqual(proof['shortened'],int(accepted))
                        self.assertEqual(proof['text_bytes_before']-proof['text_bytes_after'],4*int(accepted))
                        if accepted:self.assertEqual(proof['branches'][0]['distance_bound'],delta)
                        compact=path.read_bytes();again=relax_branches(path,GATEWAY)
                        self.assertEqual(again['shortened'],0);self.assertEqual(path.read_bytes(),compact)

    def test_unresolved_targets_and_unmodelled_growth_keep_or_reject_the_long_form(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'test.S'
            source='.text\n.Lp1000:\n'+long_branch(0x54000000,'.Lp2000')
            path.write_text(source);self.assertEqual(relax_branches(path,GATEWAY)['shortened'],0)
            for extra in ('.balign 16\n','.space 8\n','flat_unknown x0\n','ldr x0,=0x1234\n'):
                path.write_text(source+extra)
                with self.assertRaises(ValueError):relax_branches(path,GATEWAY)
                self.assertEqual(path.read_text(),source+extra)

    def test_conditional_gateway_growth_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'gateway.inc'
            path.write_text('.macro bad\n.if \\export\n nop\n.endif\n.endm\n')
            with self.assertRaises(ValueError):gateway_sizes(path)


@unittest.skipUnless(CC.exists(),'AArch64 compiler required')
class GatewayLayout(unittest.TestCase):
    def test_measured_macro_sizes_match_actual_assembled_expansions(self):
        sizes=gateway_sizes(GATEWAY)
        lines=['#include "gateway.inc"','.text']
        for i,name in enumerate(sizes):
            lines+=['.global begin%d,end%d'%(i,i),'begin%d:'%i,
                    '%s probe%d,0,0'%(name,i) if name in ('flat_capture','flat_native_capture') else '%s probe%d,done,0'%(name,i),
                    'end%d:'%i]
        lines+=['done: ret']
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'test.S').write_text('\n'.join(lines)+'\n')
            subprocess.run([str(CC),'--target=aarch64-none-elf','-I'+str(GATEWAY.parent),'-c',str(root/'test.S'),'-o',str(root/'test.o')],check=True,capture_output=True)
            syms={s['name']:s['value'] for s in Elf(root/'test.o').symbols}
            for i,(name,size) in enumerate(sizes.items()):self.assertEqual(syms['end%d'%i]-syms['begin%d'%i],size,name)


@unittest.skipUnless(CC.exists() and QEMU,'AArch64 compiler and QEMU required')
class Instructions(unittest.TestCase):
    def test_conditions_registers_constants_flags_and_all_control_outcomes(self):
        words=list(range(0x54000000,0x5400000e))
        words += [base|r for base in (0x34000000,0x35000000,0xb4000000,0xb5000000) for r in (0,16,17,30,31)]
        words += [0x36000000|((bit>>5)<<31)|((bit&31)<<19)|(nz<<24)|r for bit in (0,31,32,63) for nz in (0,1) for r in (0,16,17,30,31)]
        values=(0,1,0xffff,1<<16,1<<32,1<<48,0x201234,0x800080001000,0xffff800000001234,0x123456789abcdef0,(1<<64)-1)
        cases=[(w,None,None) for w in words]+[(0,r,v) for r in range(31) for v in values]
        lines=['.text','.global _start','_start:','adrp x0,host_stack_end','add x0,x0,:lo12:host_stack_end','mov sp,x0',
               'bl test_main','adrp x1,exit_status','add x1,x1,:lo12:exit_status','str x0,[x1,#8]','mov x0,#0x20','hlt #0xf000','b .']
        header=[]
        for i,(word,register,value) in enumerate(cases):
            pc=0x1000+8*i;target=pc+4
            lines+=['.global probe%d'%i,'probe%d:'%i,'sub sp,sp,#96']
            lines+=['stp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
            lines+=['adrp x9,test_host_sp','mov x10,sp','str x10,[x9,:lo12:test_host_sp]',
                    'adrp x9,test_after','str x1,[x9,:lo12:test_after]','mov x30,x0',
                    'ldr x9,[x30,#264]','msr nzcv,x9','ldr x9,[x30,#248]','mov sp,x9']
            lines+=['ldp x%d,x%d,[x30,#%d]'%(r,r+1,r*8) for r in range(0,30,2)]
            lines+=['ldr x30,[x30,#240]','.Lp%x:'%pc]
            if value is None:
                lines+=long_branch(word,'.Lp%x'%target).splitlines()+['b common_fall','.Lp%x:'%target,'b common_taken']
            else:lines+=immediate(register,value)+['b common_fall']
            header+=['extern void probe%d(const struct osrec_context *,struct osrec_context *);'%i]
        lines+=['common_taken:','sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#1','b status',
                'common_fall:','sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#0',
                'status:','adrp x1,test_taken','str x0,[x1,:lo12:test_taken]','ldp x0,x1,[sp]','add sp,sp,#16']
        lines+=save_context()+['mov x0,sp','adrp x1,test_after','ldr x1,[x1,:lo12:test_after]','mov x2,#34',
                              '1: ldr x3,[x0],#8','str x3,[x1],#8','subs x2,x2,#1','b.ne 1b',
                              'adrp x9,test_host_sp','ldr x9,[x9,:lo12:test_host_sp]','mov sp,x9']
        lines+=['ldp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
        lines+=['add sp,sp,#96','ret','.data','.balign 16','exit_status: .quad 0x20026,1',
                '.bss','.balign 16','test_host_sp: .zero 8','test_after: .zero 8','.space 65536','host_stack_end:']
        header+=['static const struct fixture fixtures[]={']
        header+=['{0x%x,%d,0x%xull,probe%d},'%(w,-1 if r is None else r,0 if v is None else v,i) for i,(w,r,v) in enumerate(cases)]
        header+=['};']
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'test.S').write_text('\n'.join(lines)+'\n');(root/'cases.h').write_text('\n'.join(header)+'\n')
            proof=relax_branches(root/'test.S',GATEWAY);self.assertEqual(proof['shortened'],len(words))
            compiled=subprocess.run([str(CC),'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                '-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),'-I'+str(root),
                '-Wl,-Ttext=0x40200000,-e,_start',str(root/'test.S'),str(ROOT/'tests/el0_control_host.c'),
                str(ROOT/'runtime/el0_flat/bytes.c'),'-o',str(root/'test.elf')],capture_output=True)
            self.assertEqual(compiled.returncode,0,compiled.stderr.decode())
            result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53','-accel','tcg',
                '-nodefaults','-display','none','-monitor','none','-serial','none','-semihosting-config','enable=on,target=native',
                '-device','loader,file=%s,cpu-num=0'%(root/'test.elf')],capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr.decode())


if __name__=='__main__':unittest.main()
