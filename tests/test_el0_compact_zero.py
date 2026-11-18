"""Native zeroing must use compact backing and preserve rejected accesses."""
from pathlib import Path
import shutil,subprocess,tempfile,unittest
from el0_hardware import COMPACT_WIDTH_BOUNDS,compact_ranges,compact_width_ranges,zero_path

CC=Path('/opt/homebrew/opt/llvm@16/bin/clang');QEMU=shutil.which('qemu-system-aarch64')


class Admission(unittest.TestCase):
    def test_invalid_geometry_metadata_and_nonzero_opcodes_stay_checked(self):
        for size in (0,3,63,4096):
            self.assertEqual(zero_path(0,0xd50b7420,0,'next',size,compact=True),'')
        self.assertEqual(zero_path(0,0xd50b7420,1,'next',64,compact=True),'')
        self.assertEqual(zero_path(0,0xd503201f,0,'next',64,compact=True),'')


@unittest.skipUnless(CC.exists() and QEMU,'cross compiler and QEMU required')
class Execution(unittest.TestCase):
    def test_all_registers_block_rounding_aliases_protection_and_flags(self):
        maps=[(0x10000,0x400000,4096,1024),(0x11000,0x401000,4096,1152),
              (0x12000,0x402000,4096,1024),(0xffffc39f7000,0x400000,4096,1024)]
        _,writes=compact_ranges(maps,0x400000,16384,[(0x402000,4096)])
        addresses=[0x10000,0x10001,0x1003f,0x10040,0x10fff,0x11000,0x12000,
                   0x13000,0xffffc39f7043,0xffffc39f7fff,0xffffffffc39f7000,0xffffffffffffffff]
        lines=['.text','.global _start','_start:',
               'adr x0,vectors','msr vbar_el1,x0','adrp x0,root_table','add x0,x0,:lo12:root_table',
               'msr ttbr0_el1,x0','mov x0,#255','msr mair_el1,x0','mov x0,#0x3510','msr tcr_el1,x0',
               'isb','mrs x0,sctlr_el1','bic x0,x0,#2','orr x0,x0,#1','msr sctlr_el1,x0','isb',
               'mrs x0,dczid_el0','and x0,x0,#31','cmp x0,#4','b.ne failed',
               'adrp x0,stack_end','add x0,x0,:lo12:stack_end','mov sp,x0']
        count=0
        for rt in range(32):
            for va in addresses:
                for mode in (0,1):
                    address=(va if rt!=31 else 0)&-64
                    offset=next((off+address-lo for lo,hi,off in writes if lo<=address and address+64<=hi),None)
                    fast=mode==1 and offset is not None
                    prefix='case%d_'%count;flags=((count//2)%16)<<28
                    lines+=['adrp x0,flat_phys','add x0,x0,:lo12:flat_phys','mov x1,#2048',
                            'ldr x2,=0xa5a5a5a5a5a5a5a5',prefix+'reset:',
                            'str x2,[x0],#8','subs x1,x1,#1','b.ne '+prefix+'reset',
                            'adrp x0,flat_shadow','mov x1,#%d'%mode,'str x1,[x0,:lo12:flat_shadow+80]',
                            'mov x1,#40','str x1,[x0,:lo12:flat_shadow+88]',
                            'mov x0,#0x%x'%flags,'msr nzcv,x0']
                    lines+=['mov x%d,#%d'%(r,100+r) for r in range(31)]
                    if rt!=31:lines+=['ldr x%d,=0x%x'%(rt,va)]
                    lines+=zero_path(0x1000+count*4,0xd50b7420|rt,0,prefix+'fast',64,compact=COMPACT_WIDTH_BOUNDS).splitlines()
                    lines+=['b '+('failed' if fast else prefix+'capture'),prefix+'fast:',
                            'b '+(prefix+'capture' if fast else 'failed'),prefix+'capture:',
                            'msr tpidr_el0,x30','adrp x30,snapshot','add x30,x30,:lo12:snapshot']
                    lines+=['str x%d,[x30,#%d]'%(r,r*8) for r in range(30)]
                    lines+=['mrs x0,tpidr_el0','str x0,[x30,#240]','mrs x0,nzcv',
                            'mov x1,#0x%x'%flags,'cmp x0,x1','b.ne failed',
                            'adrp x0,stack_end','add x0,x0,:lo12:stack_end','mov x1,sp','cmp x0,x1','b.ne failed']
                    for r in range(31):
                        expected=va if r==rt else 100+r
                        lines+=['ldr x0,[x30,#%d]'%(r*8),'ldr x1,=0x%x'%expected,'cmp x0,x1','b.ne failed']
                    lines+=['adrp x0,flat_shadow','ldr x1,[x0,:lo12:flat_shadow+88]',
                            'cmp x1,#%d'%(40+int(fast)),'b.ne failed',
                            'adrp x0,flat_phys','add x0,x0,:lo12:flat_phys','mov x1,#0',
                            'mov x2,#16384',prefix+'bytes:','ldrb w3,[x0,x1]']
                    if fast:
                        lines+=['ldr x4,=%d'%offset,'cmp x1,x4','b.lo '+prefix+'unchanged',
                                'add x4,x4,#64','cmp x1,x4','b.hs '+prefix+'unchanged',
                                'cbnz w3,failed','b '+prefix+'advance']
                    lines+=[prefix+'unchanged:','cmp w3,#165','b.ne failed',prefix+'advance:',
                            'add x1,x1,#1','cmp x1,x2','b.lo '+prefix+'bytes',
                            'b '+prefix+'next','.ltorg',prefix+'next:']
                    count+=1
        lines+=['mov x2,#0','b finish','failed:','mov x2,#1','finish:',
                'adrp x1,exit_status','add x1,x1,:lo12:exit_status','str x2,[x1,#8]',
                'mov x0,#0x20','hlt #0xf000','b .','.balign 2048','vectors:',
                '.rept 16','b failed','.space 124','.endr','.section .rodata,"a"','.balign 32',
                'flat_compact_write_64:']
        lines+=['.quad %d,%d,flat_phys%+d'%(lo,last,offset-lo)
                for lo,last,offset in compact_width_ranges(writes,64)]+['.quad 0,0,0']
        lines+=['.data','.balign 4096','root_table: .quad level1+3','.space 4088',
                'level1: .quad 0,0x40000701','.space 4080','flat_phys: .space 16384',
                'flat_shadow: .space 4096','snapshot: .space 248','exit_status: .quad 0x20026,1',
                '.balign 16','.space 16384','stack_end:']
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
        print('%d compact zeroing cases'%count)
