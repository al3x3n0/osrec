"""Grouped shadow operations against sequential shared-emulator execution."""
from pathlib import Path
import shutil,subprocess,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from el0_calls_fixture import save_context
from el0_system_groups import system_groups,system_group_path
from el0_hardware import system_path
from el0_flat_lower import Op,SYSTEM,NATIVE
from source_image_calls import FIELDS,sysreg
from kernel_source_verify import Elf
CC=Path('/opt/homebrew/opt/llvm@16/bin/clang');QEMU=shutil.which('qemu-system-aarch64')


class Admission(unittest.TestCase):
    def test_groups_stop_before_metadata_platform_actions_holes_and_ordinary_code(self):
        words=(0xd5384100,0xd5384101,0xd5384102)
        desc={0x1000+4*i:(Op(SYSTEM,w),0) for i,w in enumerate(words)}
        self.assertEqual(system_groups(desc)[0x1000],words)
        for entry in ((Op(SYSTEM,0xd5182000),0),(Op(SYSTEM,words[1]),1),(Op(NATIVE,0xd503201f),0)):
            desc[0x1004]=entry;self.assertNotIn(0x1000,system_groups(desc))
        desc.pop(0x1004);self.assertNotIn(0x1000,system_groups(desc))
        for words in ((0xd5384100,),tuple([0xd5384100]*9),(0xd5384100,0xd5182000)):
            with self.assertRaises(ValueError):system_group_path(0x1000,words,'done')
        with self.assertRaises(ValueError):system_path(0xd5384100,registers=(0,16))


@unittest.skipUnless(CC.exists() and QEMU,'AArch64 compiler and QEMU required')
class Instructions(unittest.TestCase):
    def test_dependent_operations_all_operands_counter_wrap_flags_simd_and_page_ends(self):
        groups=[]
        for key,(_,kind) in FIELDS.items():
            for rt in range(32):
                read=0xd5200000|(key<<5)|rt;write=0xd5000000|(key<<5)|rt
                if system_path(write):groups.append((write,read,read^(1 if rt!=31 else 0)))
                elif system_path(read):groups.append((read,read))
        for imm in range(16):
            groups.append((0xd50340df|(imm<<8),0xd53b4220,0xd50340ff|(imm<<8),0xd53b4221))
            for rt in range(32):
                read=0xd53b4220|rt
                for update in (0xd50340df,0xd50340ff):
                    update|=imm<<8
                    groups.append((read,update,update,read))
                    groups.append((0xd51b4220|rt,update,read))
                # An intervening read may overwrite the forwarding source;
                # the following DAIF update must reload shadow state.
                groups.append((read,0xd5384100|rt,0xd50340ff|(imm<<8),read))
        for n in range(2,9):groups.append(tuple([0xd508871f,0xd50b7530,0xd50b7b31,0xd503405f]*2)[:n])
        lines=['.arch armv8-a+simd','.text','.global _start','_start:',
            'mov x1,#0x300000','msr cpacr_el1,x1','isb','adrp x0,host_stack_end','add x0,x0,:lo12:host_stack_end',
            'mov sp,x0','bl test_main','adrp x1,exit_status','add x1,x1,:lo12:exit_status','str x0,[x1,#8]',
            'mov x0,#0x20','hlt #0xf000','b .'];header=[]
        for i,words in enumerate(groups):
            lines+=['.global probe%d'%i,'probe%d:'%i,'sub sp,sp,#96']
            lines+=['stp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
            lines+=['adrp x9,test_host_sp','mov x10,sp','str x10,[x9,:lo12:test_host_sp]',
                'adrp x9,test_after','str x1,[x9,:lo12:test_after]','mov x9,#0x400000','msr fpcr,x9',
                'mov x9,#1','movk x9,#0x800,lsl #16','msr fpsr,x9','mov x30,x0',
                'ldr x9,[x30,#264]','msr nzcv,x9','ldr x9,[x30,#248]','mov sp,x9']
            lines+=['ldp x%d,x%d,[x30,#%d]'%(r,r+1,r*8) for r in range(0,30,2)]
            lines+=['ldr x30,[x30,#240]','movi v0.16b,#0x5a','movi v31.16b,#0xa5']
            lines+=system_group_path(0x1000+4*i,words,'capture').splitlines()
            header+=['extern void probe%d(const struct osrec_context *,struct osrec_context *);'%i]
        lines+=['capture:','stp x0,x1,[sp,#-16]!','adrp x1,test_vector','add x1,x1,:lo12:test_vector',
            'stp q0,q31,[x1]','mrs x0,fpsr','str x0,[x1,#32]','mrs x0,fpcr','str x0,[x1,#40]',
            'ldp x0,x1,[sp],#16']+save_context()+['mov x0,sp','adrp x1,test_after',
            'ldr x1,[x1,:lo12:test_after]','mov x2,#34','1: ldr x3,[x0],#8','str x3,[x1],#8',
            'subs x2,x2,#1','b.ne 1b','adrp x9,test_host_sp','ldr x9,[x9,:lo12:test_host_sp]','mov sp,x9']
        lines+=['ldp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
        lines+=['add sp,sp,#96','ret','.data','.balign 16','exit_status: .quad 0x20026,1',
            '.bss','.balign 16','test_host_sp: .zero 8','test_after: .zero 8','.space 65536','host_stack_end:']
        header+=['static const struct fixture fixtures[]={']
        header+=['{%d,{%s},probe%d},'%(len(words),','.join('0x%x'%w for w in words),i) for i,words in enumerate(groups)]+['};']
        for placement in (0,3968):
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder);(root/'test.S').write_text('\n'.join(lines)+'\n.bss\n.balign 4096\n.space %d\n.global flat_shadow\nflat_shadow: .zero 532584\n'%placement)
                (root/'cases.h').write_text('\n'.join(header)+'\n')
                built=subprocess.run([str(CC),'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                    '-ffunction-sections','-fdata-sections','-ffreestanding','-fno-builtin','-mgeneral-regs-only',
                    '-Wall','-Wextra','-Werror','-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),'-I'+str(root),
                    '-Wl,-Ttext=0x40200000,-e,_start,--gc-sections',str(root/'test.S'),str(ROOT/'tests/el0_system_groups_host.c'),
                    str(ROOT/'runtime/el0/emulate.c'),str(ROOT/'runtime/el0_flat/bytes.c'),'-o',str(root/'test.elf')],capture_output=True)
                self.assertEqual(built.returncode,0,built.stderr.decode())
                elf=Elf(root/'test.elf');self.assertEqual(next(s['value'] for s in elf.symbols if s['name']=='flat_shadow')&4095,placement)
                result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                    '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                    '-semihosting-config','enable=on,target=native','-device','loader,file=%s,cpu-num=0'%(root/'test.elf')],capture_output=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stderr.decode())
        print('%d groups; %d sequential-oracle full-context comparisons'%(len(groups),len(groups)*128))


if __name__=='__main__':unittest.main()
