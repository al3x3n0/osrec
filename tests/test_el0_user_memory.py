"""Differential checks of live user translation and native memory execution."""
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from el0_flat_lower import decode, atomic_group
from el0_user_memory import user_memory_path, excluded_ranges,immutable_page_bitmap
from el0_calls_fixture import save_context

LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
CC=str(LLVM/'clang') if (LLVM/'clang').exists() else shutil.which('clang')
QEMU=shutil.which('qemu-system-aarch64')


class Admission(unittest.TestCase):
    def test_bitmap_boundaries_partial_pages_overlaps_and_ram_bounds(self):
        base=0x40000000
        spans=[(base,1),(base+4095,2),(base+7*4096,4096),(base+15*4096,4096)]
        self.assertEqual(immutable_page_bitmap(base,16*4096,spans),bytes((0x83,0x80)))
        self.assertEqual(immutable_page_bitmap(base,4097,[(base+4096,1)]),b'\x02')
        self.assertEqual(immutable_page_bitmap(base,4096,[(base+4096,0)]),b'\0')
        for start,size,values in ((base+1,4096,[]),(base,0,[]),(base,4096,[(base-1,1)]),
                                   (base,4096,[(base+4095,2)]),(base,4096,[(base,-1)])):
            with self.assertRaises(ValueError):immutable_page_bitmap(start,size,values)

    def test_static_ranges_include_devices_and_merge_adjacent_aliases(self):
        self.assertEqual(excluded_ranges([(0,0,4096,0),(4096,0,4096,0),
                                         (1<<40,0x9000000,4096,0)]),
                         [(0,8192),(1<<40,(1<<40)+4096)])

    def test_exclusives_and_unsupported_geometry_stay_checked(self):
        op,_=atomic_group({0:0x885f7d0b,4:0x880afd09},0)
        self.assertEqual(user_memory_path(0,op,'next',0x40000000,65536,16),'')
        for tcr in (0,40,16|(1<<14)):
            self.assertEqual(user_memory_path(0,decode(0xf9400020),'next',0x40000000,65536,tcr),'')


@unittest.skipUnless(CC and QEMU,'AArch64 cross compiler and system QEMU required')
class Instructions(unittest.TestCase):
    def test_fresh_tables_permissions_faults_aliases_registers_and_writeback(self):
        words=(0xf9400020,0xf9000020,0xf8400820,0xf8000820,0xf8408420,
               0xf8408c20,0xf94003e0,0xf84087e0,0xf9400030,0xf9400200,
               0xa9400820,0xb862d820,0xc8dffc20,0x3dc00020,0x3d800020)
        lines=['.arch armv8-a+simd','.text','.global _start','_start:',
               'mov x1,#0x300000','msr cpacr_el1,x1','isb','adrp x1,vectors','add x1,x1,:lo12:vectors','msr vbar_el1,x1',
               'adrp x1,identity_root','add x1,x1,:lo12:identity_root',
               'adrp x2,identity_l1','add x2,x2,:lo12:identity_l1','orr x2,x2,#3','str x2,[x1]',
               'msr ttbr0_el1,x1','ldr x1,=0x80103510','msr tcr_el1,x1',
               'mov x1,#255','msr mair_el1,x1','dsb sy','tlbi vmalle1','dsb sy','isb',
               'ldr x1,=0x30d01805','msr sctlr_el1,x1','isb',
               'adrp x0,host_stack_end','add x0,x0,:lo12:host_stack_end','mov sp,x0',
               'bl test_main','mov x2,x0','.Lexit:','adrp x1,exit_status','add x1,x1,:lo12:exit_status',
               'str x2,[x1,#8]','mov x0,#0x20','hlt #0xf000','b .']
        variants=[(word,tcr,bitmap,False) for bitmap in (False,True) for tcr in (16,25,39) for word in words]
        variants += [(0xf8400820,tcr,bitmap,True) for bitmap in (False,True) for tcr in (16,25,39)]
        variants=[(*row,buckets) for buckets in (False,True) for row in variants]
        for i,(word,tcr,bitmap,group,buckets) in enumerate(variants):
            lines+=['.global probe%d'%i,'probe%d:'%i,'sub sp,sp,#96']
            lines+=['stp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
            lines+=['adrp x9,test_host_sp','mov x10,sp','str x10,[x9,:lo12:test_host_sp]',
                    'adrp x9,test_after','str x1,[x9,:lo12:test_after]',
                    'mov x30,x0','ldr x9,[x30,#264]','msr nzcv,x9',
                    'ldr x9,[x30,#248]','mov sp,x9']
            lines+=['ldp x%d,x%d,[x30,#%d]'%(r,r+1,r*8) for r in range(0,30,2)]
            lines+=['ldr x30,[x30,#240]','movi v0.16b,#0x5a']
            # The captured-memory C walker supplies translation expectations.
            lines+=user_memory_path(0x1000+i*4,decode(word),'.Lfast%d'%i,0x40000000,65536,tcr,immutable_bitmap=bitmap,
                accesses=(decode(0xf8400820),decode(0xf8408822)) if group else None,exclusion_buckets=buckets).splitlines()
            lines+=['sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#0','b .Lstatus%d'%i,
                    '.Lfast%d:'%i,'sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#1',
                    '.Lstatus%d:'%i,'adrp x1,test_vector','str q0,[x1,:lo12:test_vector]','adrp x1,test_fast','str x0,[x1,:lo12:test_fast]',
                    'ldp x0,x1,[sp]','add sp,sp,#16']
            lines+=save_context()
            lines+=['mov x0,sp','adrp x1,test_after','ldr x1,[x1,:lo12:test_after]','mov x2,#34',
                    '1: ldr x3,[x0],#8','str x3,[x1],#8','subs x2,x2,#1','b.ne 1b',
                    'adrp x9,test_host_sp','ldr x9,[x9,:lo12:test_host_sp]','mov sp,x9']
            lines+=['ldp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
            lines+=['add sp,sp,#96','ret']
        lines+=['unexpected:','mrs x2,esr_el1','and x2,x2,#255','add x2,x2,#128','b .Lexit',
                '.balign 2048','vectors:','.rept 16','b unexpected','.space 124','.endr',
                '.section .rodata,"a"','.balign 16','.global flat_user_exclusion_buckets','flat_user_exclusion_buckets:']
        from el0_user_exclusion import exclusion_buckets
        table=exclusion_buckets([(1<<40,(1<<40)+4096)])
        lines+=['.quad 0x%x,0x%x'%row for row in struct.iter_unpack('<2Q',table)]
        lines+=[
                '.data','.balign 16','exit_status: .quad 0x20026,1',
                '.balign 4096','identity_root: .zero 4096','identity_l1: .quad 0,0x40000701','.zero 4080',
                '.bss','.balign 16','test_host_sp: .zero 8','test_after: .zero 8',
                '.space 65536','host_stack_end:']
        header='\n'.join('extern void probe%d(const struct osrec_context *,struct osrec_context *);'%i for i in range(len(variants)))
        header+='\nstatic const struct fixture fixtures[]={\n'
        header+=''.join('{0x%x,%d,%d,probe%d},\n'%(word,tcr,group,i) for i,(word,tcr,bitmap,group,buckets) in enumerate(variants))+'};\n'
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'test.S').write_text('\n'.join(lines)+'\n');(root/'cases.h').write_text(header)
            compiled=subprocess.run([CC,'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                            '-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                            '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),'-I'+str(root),
                            '-Wl,--image-base=0x40200000,-Ttext=0x40210000,-e,_start',str(root/'test.S'),
                            str(ROOT/'tests/el0_user_memory_host.c'),str(ROOT/'runtime/el0_flat/memory.c'),
                            str(ROOT/'runtime/el0_flat/bytes.c'),
                            '-o',str(root/'test.elf')],capture_output=True)
            self.assertEqual(compiled.returncode,0,compiled.stderr.decode())
            result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                                   '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                                   '-semihosting-config','enable=on,target=native',
                                   '-device','loader,file=%s,cpu-num=0'%(root/'test.elf')],
                                  capture_output=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr.decode())


if __name__=='__main__':unittest.main()
