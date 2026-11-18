"""Converted exclusive windows must retain reservation and branch semantics."""
from pathlib import Path
import shutil,subprocess,tempfile,unittest
from el0_flat_lower import atomic_group
from el0_hardware import COMPACT_WIDTH_BOUNDS,memory_path

CC=Path('/opt/homebrew/opt/llvm@16/bin/clang');QEMU=shutil.which('qemu-system-aarch64')


@unittest.skipUnless(CC.exists() and QEMU,'cross compiler and QEMU required')
class Execution(unittest.TestCase):
    def test_exclusive_pairs_early_exits_and_failed_admission(self):
        single=[0x885f7d0b,0x880afd09]
        pair=[0xc87f0480,0xeb16001f,0xfa480020,0x54000061,0xc8290c82]
        cases=[(single,False,0,False,0),(pair,False,0,False,0),
               (pair,False,0,False,1),(pair,False,0,False,2),
               ([single[0],0x3500004b,single[1]],False,0,False,3),
               ([single[0],0x3700004b,single[1]],False,0,False,3),
               (single,True,0,False,0),(single,False,1,False,0),
               (pair,False,8,False,0),(single,False,0,True,0)]
        lines=['.text','.global _start','_start:',
               'adr x0,vectors','msr vbar_el1,x0','adrp x0,root_table','add x0,x0,:lo12:root_table',
               'msr ttbr0_el1,x0','mov x0,#255','msr mair_el1,x0','mov x0,#0x3510','msr tcr_el1,x0',
               'isb','mrs x0,sctlr_el1','bic x0,x0,#2','orr x0,x0,#1','msr sctlr_el1,x0','isb',
               'adrp x0,stack_end','add x0,x0,:lo12:stack_end','mov sp,x0']
        for i,(words,readonly,offset,user,mismatch) in enumerate(cases):
            pc=0x4000+i*64
            op,body=atomic_group({pc+4*k:w for k,w in enumerate(words)},pc)
            fast=memory_path(pc,op,'good%d'%i,body,lambda dest:'exit%d'%i,compact=COMPACT_WIDTH_BOUNDS,native_sp=True)
            self.assertTrue(fast)
            window=fast.split('.Lhw%x_insn%x:'%(pc,pc))[1].split('.Lhw%x_insn%x:'%(pc,pc+4*(len(words)-1)))[0]
            self.assertNotIn('bl ',window);self.assertNotIn('[sp',window)
            is_pair=words is pair;slow=readonly or bool(offset) or user
            exit_expected=bool(mismatch) and not slow;stored=not slow and not mismatch
            logical=(0xffffc39f9000 if readonly else 0xffffc39f7000)+offset
            lines+=['adrp x20,flat_phys','add x20,x20,:lo12:flat_phys','mov x21,#123','str x21,[x20]',
                    'mov x21,#456','str x21,[x20,#8]','adrp x18,flat_shadow','mov x19,#%d'%(not user),
                    'str x19,[x18,:lo12:flat_shadow+80]']
            expected={r:100+r for r in range(31)}
            expected.update({2:777,3:888,9:99 if is_pair else 777,10:99,11:42,
                             22:124 if is_pair and mismatch==1 else 123})
            lines+=['mov x%d,#%d'%(r,value) for r,value in expected.items()]
            base=4 if is_pair else 8
            lines+=['ldr x%d,=0x%x'%(base,logical)]
            if is_pair:lines+=['mov x8,#%d'%(457 if mismatch==2 else 456)]
            lines+=['cmp xzr,xzr','retry%d:'%i]+fast.splitlines()
            lines+=['b '+('check%d'%i if slow else 'failed'),'good%d:'%i,
                    'b '+('check%d'%i if stored else 'failed'),'exit%d:'%i,
                    'b '+('check%d'%i if exit_expected else 'failed'),'check%d:'%i,
                    'b.eq failed' if exit_expected and is_pair else 'b.ne failed']
            if stored:lines+=['cbnz w%d,retry%d'%(9 if is_pair else 10,i)]
            for r in range(12,31):lines+=['cmp x%d,#%d'%(r,expected[r]),'b.ne failed']
            if is_pair:
                if not slow:lines+=['cmp x0,#123','b.ne failed','cmp x1,#456','b.ne failed']
                lines+=['cmp x9,#%d'%(0 if stored else 99),'b.ne failed']
            else:lines+=['cmp x11,#%d'%(42 if slow else 123),'b.ne failed',
                         'cmp x10,#%d'%(0 if stored else 99),'b.ne failed']
            lines+=['ldr x20,=0x%x'%logical,'cmp x%d,x20'%base,'b.ne failed',
                    'adrp x20,flat_phys','add x20,x20,:lo12:flat_phys','ldr x21,[x20]',
                    'cmp x21,#%d'%(777 if stored else 123),'b.ne failed','ldr x21,[x20,#8]',
                    'cmp x21,#%d'%(888 if stored and is_pair else 456),'b.ne failed',
                    'adrp x20,stack_end','add x20,x20,:lo12:stack_end','mov x21,sp',
                    'cmp x20,x21','b.ne failed','b next%d'%i,'.ltorg','next%d:'%i]
        lines+=['mov x2,#0','b finish','failed:','mov x2,#1','finish:',
                'adrp x1,exit_status','add x1,x1,:lo12:exit_status','str x2,[x1,#8]',
                'mov x0,#0x20','hlt #0xf000','b .','.balign 2048','vectors:',
                '.rept 16','b failed','.space 124','.endr','.section .rodata,"a"',
                '.balign 32','flat_compact_write_4: .quad 0xffffc39f7000,0xffffc39f7ffc,flat_phys-0xffffc39f7000,0,0,0',
                '.balign 32','flat_compact_write_16: .quad 0xffffc39f7000,0xffffc39f7ff0,flat_phys-0xffffc39f7000,0,0,0',
                '.data','.balign 4096','root_table: .quad level1+3','.space 4088',
                'level1: .quad 0,0x40000701','.space 4080','flat_phys: .space 4096',
                'flat_shadow: .space 4096','exit_status: .quad 0x20026,1','.balign 16','.space 16384','stack_end:']
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'fixture.S').write_text('\n'.join(lines)+'\n')
            built=subprocess.run([str(CC),'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib',
                '-Wl,-Ttext=0x40200000,-e,_start',str(root/'fixture.S'),'-o',str(root/'fixture')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            run=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                '-nodefaults','-display','none','-monitor','none','-serial','none','-d','int','-D',str(root/'exceptions.log'),
                '-semihosting-config','enable=on,target=native','-device','loader,file='+str(root/'fixture')+',cpu-num=0'],
                capture_output=True,text=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr+(root/'exceptions.log').read_text()[:2000])
