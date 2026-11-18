from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import os
from unittest.mock import patch

from el0_flat_lower import decode
from el0_compact_access import compact_load_proof, compact_load_path

CC=Path('/opt/homebrew/opt/llvm@16/bin/clang')
QEMU=shutil.which('qemu-system-aarch64')


class Admission(unittest.TestCase):
    def test_rejects_ambiguous_targets_writeback_vectors_pairs_and_stores(self):
        proof=dict(physical=[0x400000],bytes=8,addresses=[0xffffc39f7000])
        self.assertIsNotNone(compact_load_proof(decode(0xf9400020),proof,0x400000,4096))
        for word in (0xf9000020,0xf8408420,0xa9400820,0xfd400020,0xf940003f):
            self.assertIsNone(compact_load_proof(decode(word),proof,0x400000,4096))
        self.assertIsNone(compact_load_proof(decode(0xf9400020),dict(proof,physical=[0x400000,0x400008]),0x400000,4096))
        self.assertIsNone(compact_load_proof(decode(0xf9400020),dict(proof,physical=[0x400ffc]),0x400000,4096))


@unittest.skipUnless(CC.exists() and QEMU, 'cross compiler and QEMU required')
class Execution(unittest.TestCase):
    def test_integer_loads_preserve_registers_flags_and_need_no_guest_stack(self):
        # Width, sign extension, and W/X destination semantics are independent
        # of the relocation. Include destination/base overlap and page crossings.
        variants=[(0x39400000,1,False,32),(0x79400000,2,False,32),
                  (0xb9400000,4,False,32),(0xf9400000,8,False,64),
                  (0x39800000,1,True,64),(0x39c00000,1,True,32),
                  (0x79800000,2,True,64),(0x79c00000,2,True,32),
                  (0xb9800000,4,True,64)]
        lines=['.text','.global _start','_start:', 'adr x0,vectors','msr vbar_el1,x0',
               'adrp x0,root_table','add x0,x0,:lo12:root_table','msr ttbr0_el1,x0',
               'mov x0,#255','msr mair_el1,x0','mov x0,#0x3510','msr tcr_el1,x0',
               'isb','mrs x0,sctlr_el1','bic x0,x0,#2','orr x0,x0,#1','msr sctlr_el1,x0',
               'isb','mov x0,#0','mov sp,x0']
        count=0
        for dest in range(31):
            for word,size,signed,width in variants:
                for offset in (0,4093,8192):
                    base=dest if offset==0 else (dest+1)%31
                    word=(word&~1023)|(base<<5)|dest
                    proof=compact_load_proof(decode(word),dict(physical=[0x400000+offset],
                        bytes=size,addresses=[0xffffc39f7000+offset]),0x400000,16384)
                    self.assertIsNotNone(proof)
                    flags=(count%16)<<28
                    lines+=['mov x0,#0x%x'%flags,'msr nzcv,x0']
                    lines+=['mov x%d,#%d'%(r,100+r) for r in range(31)]
                    lines+=compact_load_path(proof,'capture%d'%count).splitlines()
                    lines+=['capture%d:'%count,'msr tpidr_el0,x30','adrp x30,snapshot',
                            'add x30,x30,:lo12:snapshot']
                    lines+=['str x%d,[x30,#%d]'%(r,r*8) for r in range(30)]
                    lines+=['mrs x0,tpidr_el0','str x0,[x30,#240]',
                            'mrs x0,nzcv','mov x1,#0x%x'%flags,'cmp x0,x1','b.ne failed',
                            'mov x0,sp','cbnz x0,failed']
                    value=int.from_bytes(bytes([128])*size,'little',signed=signed)&((1<<width)-1)
                    for r in range(31):
                        expected=value if r==dest else 100+r
                        lines+=['ldr x0,[x30,#%d]'%(r*8),'ldr x1,=0x%x'%expected,'cmp x0,x1','b.ne failed']
                    lines+=['b next%d'%count,'.ltorg','next%d:'%count]
                    count+=1
        lines+=['mov x2,#0','b finish','failed:','mov x2,#1','finish:',
                'adrp x1,exit_status','add x1,x1,:lo12:exit_status','str x2,[x1,#8]',
                'mov x0,#0x20','hlt #0xf000','b .','.balign 2048','vectors:', '.rept 16','b failed','.space 124','.endr','.data','.balign 4096',
                'flat_phys: .fill 16384,1,128','snapshot: .space 248',
                'exit_status: .quad 0x20026,1','.balign 4096','root_table: .quad level1+3',
                '.space 4088','level1: .quad 0,0x40000701','.space 4080']
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'fixture.S').write_text('\n'.join(lines)+'\n')
            result=subprocess.run([str(CC),'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib',
                '-Wl,-Ttext=0x40200000,-e,_start',str(root/'fixture.S'),'-o',str(root/'fixture')],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                '-d','int','-D',str(root/'exceptions.log'),'-nodefaults','-display','none','-monitor','none','-serial','none',
                '-semihosting-config','enable=on,target=native','-device',
                'loader,file='+str(root/'fixture')+',cpu-num=0'],capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr+(root/'exceptions.log').read_text()[:2000])
        print('%d compact integer-load executions'%count)


@unittest.skipUnless(os.environ.get('OSREC_COMPACT_IMAGE'), 'set OSREC_COMPACT_IMAGE for linked-image negative audits')
class LinkedAudit(unittest.TestCase):
    def test_wrong_destination_and_backing_offset_are_rejected(self):
        from el0_compact_access import verify_compiled
        from kernel_source_verify import Elf
        original=Elf.read
        for byte,mask,error in ((0,1,'clobber unexpected state'),(5,4,'operand differs')):
            def corrupted(elf,address,size):
                data=original(elf,address,size)
                if size==12:
                    data=bytearray(data);data[byte]^=mask;data=bytes(data)
                return data
            with self.subTest(byte=byte),patch.object(Elf,'read',corrupted):
                with self.assertRaisesRegex(ValueError,error):
                    verify_compiled(os.environ['OSREC_COMPACT_IMAGE'])
