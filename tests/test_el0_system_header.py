"""Execute base and page-offset shadow accesses against the shared emulator."""
from pathlib import Path
import os
import shutil
import struct
import json
import hashlib
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from el0_calls_fixture import save_context
from el0_hardware import system_path
from source_image_calls import FIELDS
from kernel_source_verify import Elf
from unittest.mock import patch

LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
CC=str(LLVM/'clang') if (LLVM/'clang').exists() else shutil.which('clang')
QEMU=shutil.which('qemu-system-aarch64')


class Admission(unittest.TestCase):
    def test_platform_actions_and_lowering_keep_the_handler_in_both_backends(self):
        for page in (False,True):
            for word in (0xd5182000,0xd69f03e0,0xd50b7420,0xd5087800):
                self.assertEqual(system_path(word,page_offsets=page),'')
            self.assertEqual(system_path(0xd5384100,1,page_offsets=page),'')

    def test_fields_outside_the_aligned_header_keep_the_base_backend(self):
        key=0xc777;word=0xd5200000|(key<<5)
        with patch.dict(FIELDS,{key:(128,'plain')}):
            self.assertEqual(system_path(word,page_offsets=True),'')
            self.assertTrue(system_path(word))


@unittest.skipUnless(CC and QEMU,'AArch64 cross compiler and system QEMU required')
class Instructions(unittest.TestCase):
    def test_shadow_fields_masks_register_aliases_flags_and_page_ends(self):
        words=[]
        for key in FIELDS:
            for read in (True,False):
                for rt in range(32):
                    word=(0xd5200000 if read else 0xd5000000)|(key<<5)|rt
                    if system_path(word):words.append(word)
        for op1,op2 in ((3,6),(3,7),(0,4),(0,3),(3,1),(3,2),(3,4)):
            for imm in range(16):words.append(0xd500401f|(op1<<16)|(op2<<5)|(imm<<8))
        for base in (0xd50883a0,0xd50b7520,0xd50b7b20,0xd5087500,0xd50b7620,0xd50b7a20,0xd50b7e20):
            for rt in range(32):words.append((base&~31)|rt)
        cases=[(word,page) for page in (False,True) for word in words]
        lines=['.arch armv8-a+simd','.text','.global _start','_start:',
               'mov x1,#0x300000','msr cpacr_el1,x1','isb',
               'adrp x0,host_stack_end','add x0,x0,:lo12:host_stack_end','mov sp,x0',
               'bl test_main','mov x2,x0','adrp x1,exit_status','add x1,x1,:lo12:exit_status',
               'str x2,[x1,#8]','mov x0,#0x20','hlt #0xf000','b .']
        header=[]
        for i,(word,page) in enumerate(cases):
            lines+=['.global probe%d'%i,'probe%d:'%i,'sub sp,sp,#96']
            lines+=['stp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
            lines+=['adrp x9,test_host_sp','mov x10,sp','str x10,[x9,:lo12:test_host_sp]',
                    'adrp x9,test_after','str x1,[x9,:lo12:test_after]',
                    'mov x9,#0x400000','msr fpcr,x9','mov x9,#1','movk x9,#0x800,lsl #16',
                    'msr fpsr,x9','mov x30,x0','ldr x9,[x30,#264]','msr nzcv,x9','ldr x9,[x30,#248]','mov sp,x9']
            lines+=['ldp x%d,x%d,[x30,#%d]'%(r,r+1,r*8) for r in range(0,30,2)]
            lines+=['ldr x30,[x30,#240]','movi v0.16b,#0x5a']
            lines+=system_path(word,page_offsets=page).splitlines()+['b common_fast']
            header+=['extern void probe%d(const struct osrec_context *,struct osrec_context *);'%i]
        lines+=['common_slow:','sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#0','b status',
                'common_fast:','sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#1',
                'status:','adrp x1,test_fast','str x0,[x1,:lo12:test_fast]',
                'adrp x1,test_vector','add x1,x1,:lo12:test_vector','str q0,[x1]',
                'mrs x0,fpsr','str x0,[x1,#16]','mrs x0,fpcr','str x0,[x1,#24]',
                'ldp x0,x1,[sp]','add sp,sp,#16']
        lines+=save_context()
        lines+=['mov x0,sp','adrp x1,test_after','ldr x1,[x1,:lo12:test_after]','mov x2,#34',
                '1: ldr x3,[x0],#8','str x3,[x1],#8','subs x2,x2,#1','b.ne 1b',
                'adrp x9,test_host_sp','ldr x9,[x9,:lo12:test_host_sp]','mov sp,x9']
        lines+=['ldp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
        lines+=['add sp,sp,#96','ret','.data','.balign 16','exit_status: .quad 0x20026,1',
                '.bss','.balign 16','test_host_sp: .zero 8','test_after: .zero 8','.space 65536','host_stack_end:']
        header+=['static const struct fixture fixtures[]={']
        for i,(word,page) in enumerate(cases):header+=['{0x%x,0x%x,probe%d},'%(0x800000001000+4*i,word,i)]
        header+=['};']
        for placement in (0,3968):
            with self.subTest(placement=placement):
                with tempfile.TemporaryDirectory() as folder:
                    root=Path(folder);(root/'test.S').write_text('\n'.join(lines)+'\n.data\n.balign 4096\n.space %d\n.global flat_shadow\nflat_shadow: .zero 532584\n'%placement);(root/'cases.h').write_text('\n'.join(header))
                    compiled=subprocess.run([CC,'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                                             '-ffunction-sections','-fdata-sections','-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                                             '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),'-I'+str(root),
                                             '-Wl,-Ttext=0x40200000,-e,_start,--gc-sections',str(root/'test.S'),
                                             str(ROOT/'tests/el0_system_header_host.c'),str(ROOT/'runtime/el0/emulate.c'),str(ROOT/'runtime/el0_flat/bytes.c'),
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


@unittest.skipUnless(os.environ.get('OSREC_EL0_SHADOW_HEADER_IMAGE'),'page-offset image not selected')
class FullImage(unittest.TestCase):
    def test_misalignment_binding_permissions_and_metadata_downgrade_are_rejected(self):
        from el0_hardware_model import prepare
        image=Path(os.environ['OSREC_EL0_SHADOW_HEADER_IMAGE']).resolve();elf=Elf(image/'checkpoint')
        syms={s['name']:s for s in elf.symbols if s['shndx']}
        def offset(address):
            section=next(s for s in elf.sections if s['addr']<=address<s['addr']+s['size'])
            return section['offset']+address-section['addr']
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for mode in ('alignment','binding','permissions','metadata'):
                changed=root/mode;changed.mkdir();data=bytearray(elf.data)
                metadata=json.loads((image/'hardware-memory.json').read_text())
                manifest=json.loads((image/'manifest.json').read_text())
                if mode=='alignment':
                    for section in elf.sections:
                        if section['type']!=2:continue
                        strings=elf.sections[section['link']]
                        for at in range(section['offset'],section['offset']+section['size'],24):
                            name,=struct.unpack_from('<I',data,at)
                            if elf.string(strings,name)=='flat_shadow':
                                struct.pack_into('<Q',data,at+8,syms['flat_shadow']['value']+8)
                elif mode=='binding':
                    struct.pack_into('<Q',data,offset(syms['flat_program']['value']+48),syms['flat_shadow']['value']+128)
                elif mode=='permissions':
                    start,=struct.unpack_from('<Q',data,32);stride,count=struct.unpack_from('<HH',data,54)
                    for i in range(count):
                        kind,flags,off,va,pa,size,mem,align=struct.unpack_from('<II6Q',data,start+i*stride)
                        if kind==1 and va<=syms['flat_shadow_header_alignment']['value']<va+mem:
                            struct.pack_into('<I',data,start+i*stride+4,flags|2)
                else:
                    metadata.pop('shadow_header_alignment');manifest.pop('shadow_access_backend')
                (changed/'checkpoint').write_bytes(data)
                raw=(json.dumps(metadata,indent=2)+'\n').encode();(changed/'hardware-memory.json').write_bytes(raw)
                manifest['hardware_memory_sha256']=hashlib.sha256(raw).hexdigest()
                (changed/'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError,'shadow header'):
                    prepare(changed,root/(mode+'-model'),LLVM)


if __name__=='__main__':unittest.main()
