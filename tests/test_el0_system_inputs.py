"""Executable ordered-input and thread-register gateway elimination contracts."""
from pathlib import Path
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from el0_calls_fixture import save_context
from el0_hardware import counter_path, guarded_system_path
from kernel_source_verify import Elf

LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
CC=str(LLVM/'clang') if (LLVM/'clang').exists() else shutil.which('clang')
QEMU=shutil.which('qemu-system-aarch64')


class Admission(unittest.TestCase):
    def test_only_ordered_counter_reads_without_lowering_are_inlined(self):
        for word in (0xd51be040,0xd53be060,0xd69f03e0):
            self.assertEqual(counter_path(0x1000,word,0,'next'),'')
        self.assertEqual(counter_path(0x1000,0xd53be040,1,'next'),'')
        self.assertEqual(guarded_system_path(0x1000,0xd51bd068,1,'next'),'')


@unittest.skipUnless(CC and QEMU,'AArch64 cross compiler and system QEMU required')
class Instructions(unittest.TestCase):
    def test_ordered_inputs_thread_shadow_aliases_flags_and_fallback(self):
        words=tuple(base|rt for base in (0xd53be020,0xd53be040,0xd51bd060,0xd53bd060,
                    *(0xd5200000|(key<<5) for key in (0x8000,0x9fff,0xc684,0xde82,0xfffe)))
                    for rt in (0,14,15,16,17,30,31))
        lines=['.arch armv8-a+simd','.text','.global _start','_start:',
               'mov x1,#0x300000','msr cpacr_el1,x1','isb',
               'adrp x0,host_stack_end','add x0,x0,:lo12:host_stack_end','mov sp,x0',
               'bl test_main','mov x2,x0','adrp x1,exit_status','add x1,x1,:lo12:exit_status',
               'str x2,[x1,#8]','mov x0,#0x20','hlt #0xf000','b .']
        header=[]
        for i,word in enumerate(words):
            lines+=['.global probe%d'%i,'probe%d:'%i,'sub sp,sp,#96']
            lines+=['stp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
            lines+=['adrp x9,test_host_sp','mov x10,sp','str x10,[x9,:lo12:test_host_sp]',
                    'adrp x9,test_after','str x1,[x9,:lo12:test_after]',
                    'mov x30,x0','ldr x9,[x30,#264]','msr nzcv,x9','ldr x9,[x30,#248]','mov sp,x9']
            lines+=['ldp x%d,x%d,[x30,#%d]'%(r,r+1,r*8) for r in range(0,30,2)]
            lines+=['ldr x30,[x30,#240]','movi v0.16b,#0x5a']
            lines+=(counter_path(0x800000001000+4*i,word,0,'common_fast') or
                     guarded_system_path(0x800000001000+4*i,word,0,'common_fast')).splitlines()+['b common_slow']
            header+=['extern void probe%d(const struct osrec_context *,struct osrec_context *);'%i]
        lines+=['common_slow:','sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#0','b status',
                'common_fast:','sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#1',
                'status:','adrp x1,test_fast','str x0,[x1,:lo12:test_fast]',
                'adrp x1,test_vector','str q0,[x1,:lo12:test_vector]','ldp x0,x1,[sp]','add sp,sp,#16']
        lines+=save_context()
        lines+=['mov x0,sp','adrp x1,test_after','ldr x1,[x1,:lo12:test_after]','mov x2,#34',
                '1: ldr x3,[x0],#8','str x3,[x1],#8','subs x2,x2,#1','b.ne 1b',
                'adrp x9,test_host_sp','ldr x9,[x9,:lo12:test_host_sp]','mov sp,x9']
        lines+=['ldp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
        lines+=['add sp,sp,#96','ret','.data','.balign 16','exit_status: .quad 0x20026,1',
                '.bss','.balign 16','test_host_sp: .zero 8','test_after: .zero 8','.space 65536','host_stack_end:']
        header+=['static const struct fixture fixtures[]={']
        for i,word in enumerate(words):header+=['{0x%x,0x%x,probe%d},'%(0x800000001000+4*i,word,i)]
        header+=['};']
        for placement in (0,3968,4088):
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder);(root/'test.S').write_text('\n'.join(lines)+'\n.bss\n.balign 4096\n.space %d\n.global flat_shadow\nflat_shadow: .zero 532584\n'%placement);(root/'cases.h').write_text('\n'.join(header))
                compiled=subprocess.run([CC,'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                                         '-ffunction-sections','-fdata-sections','-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                                         '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),'-I'+str(root),
                                         '-Wl,-Ttext=0x40200000,-e,_start,--gc-sections',str(root/'test.S'),
                                         str(ROOT/'tests/el0_system_inputs_host.c'),str(ROOT/'runtime/el0/emulate.c'),str(ROOT/'runtime/el0_flat/bytes.c'),
                                         '-o',str(root/'test.elf')],capture_output=True)
                self.assertEqual(compiled.returncode,0,compiled.stderr.decode())
                elf=Elf(root/'test.elf')
                self.assertEqual(next(s['value'] for s in elf.symbols if s['name']=='flat_shadow')&4095,placement)
                result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                                       '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                                       '-semihosting-config','enable=on,target=native',
                                       '-device','loader,file=%s,cpu-num=0'%(root/'test.elf')],
                                      capture_output=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stderr.decode())


@unittest.skipUnless(os.environ.get('OSREC_EL0_SYSTEM_INPUTS_IMAGE'),'inline system-input image not selected')
class FullImage(unittest.TestCase):
    def test_order_mismatch_and_exhaustion_keep_runtime_stop_details(self):
        from el0_hardware_model import prepare,run
        from kernel_source_verify import Elf
        image=Path(os.environ['OSREC_EL0_SYSTEM_INPUTS_IMAGE']).resolve();elf=Elf(image/'checkpoint')
        symbols={s['name']:s for s in elf.symbols if s['shndx']}
        pc,key,_=struct.unpack('<3Q',elf.read(symbols['flat_counters']['value'],24))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name,address,value in (
                    ('pc',symbols['flat_counters']['value'],pc+4),
                    ('key',symbols['flat_counters']['value']+8,key^3),
                    ('empty',symbols['flat_program']['value']+104,0)):
                changed=root/name;changed.mkdir();data=bytearray(elf.data)
                section=next(s for s in elf.sections if s['addr']<=address<s['addr']+s['size'])
                struct.pack_into('<Q',data,section['offset']+address-section['addr'],value)
                (changed/'checkpoint').write_bytes(data)
                for file in ('manifest.json','hardware-memory.json'):(changed/file).symlink_to(image/file)
                prepared=root/(name+'-model');prepare(changed,prepared,LLVM)
                checked=run(changed,prepared,root/(name+'-validation'))
                self.assertFalse(checked['verified']);self.assertEqual(checked['result']['reason'],3)
                self.assertEqual(checked['result']['pc'],pc);self.assertEqual(checked['result']['detail'],key)
                self.assertEqual(checked['result']['far'],0)
                self.assertEqual(checked['hardware_exceptions'],0)
                self.assertFalse(checked['runtime_el1_services']);self.assertEqual(checked['host_calls_before_completion'],0)


if __name__=='__main__':unittest.main()
