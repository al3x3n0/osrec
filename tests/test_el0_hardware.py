"""Hardware alias admission and executable inline fast/slow-path contracts."""
import os
from pathlib import Path
import platform
import json
import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from el0_flat_lower import decode, STACK, atomic_group
from el0_hardware import direct_ranges, memory_path, stack_path, system_path, indirect_path, indirect_resume, guarded_system_path, zero_path


class ExceptionTrace(unittest.TestCase):
    def test_requires_bootstrap_control_and_rejects_later_exceptions(self):
        from el0_hardware_model import audit_exception_trace
        entry = 0x40200000
        bootstrap = b'Exception return from AArch64 EL1 to AArch64 EL0 PC 0x40200000\n'
        with tempfile.TemporaryDirectory() as folder:
            trace = Path(folder) / 'qemu-exceptions.log'
            for raw, expected in (
                (bootstrap, (True, 0, 0)),
                (b'', (False, 0, 0)),
                (bootstrap.replace(b'40200000', b'40201000'), (False, 1, 0)),
                (bootstrap + b'Taking exception 2 [SVC] on CPU 0\n...from EL0 to EL1\n', (True, 2, 1)),
                (bootstrap + bootstrap, (True, 1, 0)),
            ):
                with self.subTest(raw=raw):
                    trace.write_bytes(raw)
                    result = audit_exception_trace(trace, entry)
                    self.assertEqual((result['bootstrap_to_entry_observed'],
                                      result['unexpected_log_lines'], result['hardware_exceptions']), expected)
                    self.assertEqual(result['sha256'], hashlib.sha256(raw).hexdigest())


class Ranges(unittest.TestCase):
    def test_hardware_executor_cannot_receive_a_software_load_plan(self):
        from check_el0_program import make_load_plan
        with self.assertRaisesRegex(ValueError, 'hardware load plan'):
            make_load_plan({'memory_backend': 'hardware-kernel'})

    def test_devices_unbacked_pages_and_all_code_alias_writes_are_excluded(self):
        attrs = 1 << 10
        mappings = [(0x10000, 0x4000, 0x3000, attrs),
                    (0x20000, 0x5000, 0x1000, attrs),
                    (0x30000, 0x7000, 0x1000, attrs | (1 << 7)),
                    (0x40000, 0x9000000, 0x1000, attrs),
                    (0x50000, 0x8000, 0x1000, attrs),
                    (0x60000, 0x4000, 0x1000, 0)]
        aliases, reads, writes = direct_ranges(mappings, 0x4000, 0x4000, [(0x5000, 0x1000)])
        self.assertEqual(len(aliases), 3)
        self.assertEqual(reads, [(0x10000, 0x13000), (0x20000, 0x21000), (0x30000, 0x31000)])
        self.assertEqual(writes, [(0x10000, 0x11000), (0x12000, 0x13000)])

    def test_explicit_user_accesses_keep_permission_checked_software_path(self):
        self.assertEqual(memory_path(0x1000, decode(0xf8400820), '.Lnext'), '')

    def test_system_platform_actions_unknown_registers_and_lowering_stay_in_gateway(self):
        from source_image_calls import sysreg
        for word in (0xd5000000 | sysreg(3,0,2,0,0)<<5, # TTBR0 write
                     0xd5200000 | 0xffff<<5, 0xd69f03e0):
            self.assertEqual(system_path(word), '')
        self.assertEqual(system_path(0xd5384100, 0x40000000), '')

    def test_only_inert_maintenance_bypasses_gateway(self):
        for word in (0xd50883a1, 0xd50b7520, 0xd50b7b20, 0xd508751f,
                     0xd50b7620, 0xd50b7a20, 0xd50b7e20):
            inline=system_path(word)
            self.assertTrue(inline, hex(word))
            self.assertIn('[x16,#88]', inline)
            self.assertNotIn('.inst', inline)
            self.assertEqual(system_path(word, 0x40000000), '')
        # DC ZVA changes RAM; AT changes PAR; unsupported SYS must still stop.
        for word in (0xd50b7420, 0xd5087800, 0xd5087840, 0xd5087000):
            self.assertEqual(system_path(word), '')

    def test_guarded_registers_keep_ordered_inputs_and_platform_writes(self):
        for key in (0xdf01,0xdf02):
            self.assertEqual(guarded_system_path(0,0xd5200000|(key<<5),0,'.Lnext'),'')
        for key in (0xc100,0xc101,0xc080):
            self.assertEqual(guarded_system_path(0,0xd5000000|(key<<5),0,'.Lnext'),'')
        self.assertEqual(guarded_system_path(0,0xd538d080,0x40000000,'.Lnext'),'')


@unittest.skipUnless(platform.machine() in ('aarch64', 'arm64') and sys.platform == 'linux' and
                     (shutil.which('clang-19') or shutil.which('clang')), 'native AArch64 Linux compiler required')
class Execution(unittest.TestCase):
    def test_unknown_register_guard_restores_context_before_fallback(self):
        source='.text\n.global _start\n_start:\nadrp x0,stack_end\nadd x0,x0,:lo12:stack_end\nmov sp,x0\n'
        for i,(read,rt) in enumerate((read,rt) for read in (True,False) for rt in (0,16,17,30,31)):
            source+='adrp x20,flat_shadow\nadd x20,x20,:lo12:flat_shadow\nmov x21,#99\nstr x21,[x20,#88]\n'
            for r in range(31):source+='mov x%d,#%d\n'%(r,100+r)
            source+='cmp xzr,xzr\n'
            word=(0xd5200000 if read else 0xd5000000)|(0xc684<<5)|rt
            source+=guarded_system_path(0x1000+i*4,word,0,'fail')
            source+='b.ne fail\n'
            for r in range(31):source+='cmp x%d,#%d\nb.ne fail\n'%(r,100+r)
            source+='adrp x20,flat_shadow\nadd x20,x20,:lo12:flat_shadow\nldr x21,[x20,#88]\ncmp x21,#99\nb.ne fail\n'
            source+='adrp x20,stack_end\nadd x20,x20,:lo12:stack_end\nmov x21,sp\ncmp x20,x21\nb.ne fail\n'
        source+='mov x0,#0\nmov x8,#93\nsvc #0\nfail:\nmov x0,#1\nmov x8,#93\nsvc #0\n.bss\n.balign 16\nflat_shadow: .zero 532584\n.balign 16\n.space 16384\nstack_end:\n'
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'test.S').write_text(source)
            cc=shutil.which('clang-19') or shutil.which('clang')
            subprocess.run([cc,'-nostdlib','-static','-fuse-ld=lld','-Wl,-e,_start',str(root/'test.S'),'-o',str(root/'test')],check=True,capture_output=True)
            subprocess.run([str(root/'test')],check=True,timeout=10)

    def test_native_zero_block_alignment_permissions_registers_and_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);cc=shutil.which('clang-19') or shutil.which('clang')
            (root/'probe.S').write_text('.text\n.global _start\n_start:\nmrs x0,dczid_el0\nand x0,x0,#31\nmov x8,#93\nsvc #0\n')
            subprocess.run([cc,'-nostdlib','-static','-fuse-ld=lld','-Wl,-e,_start',str(root/'probe.S'),'-o',str(root/'probe')],check=True,capture_output=True)
            probe=subprocess.run([str(root/'probe')],timeout=10).returncode
            if probe<0 or probe&16:self.skipTest('native DC ZVA unavailable at EL0')
            block=4<<(probe&15)
            if block>2048:self.skipTest('native zero block outside supported contract')
            source='.text\n.global _start\n_start:\nadrp x0,stack_end\nadd x0,x0,:lo12:stack_end\nmov sp,x0\n'
            for i,(rt,readonly,user) in enumerate([(0,False,False),(16,False,False),(17,False,False),(30,False,False),(0,True,False),(0,False,True),(31,False,False)]):
                fast=not readonly and not user and rt!=31
                source+='adrp x20,testdata\nadd x20,x20,:lo12:testdata\nmov x21,#%d\nmov x22,#165\n.Lfill%d:\nstrb w22,[x20],#1\nsubs x21,x21,#1\nb.ne .Lfill%d\n'%(4*block,i,i)
                source+='adrp x20,flat_shadow\nadd x20,x20,:lo12:flat_shadow\nmov x21,#%d\nstr x21,[x20,#80]\nstr xzr,[x20,#88]\n'%(not user)
                source+='adrp x20,flat_direct_write\nadd x20,x20,:lo12:flat_direct_write\nadrp x21,testdata\nadd x21,x21,:lo12:testdata\nstr %s,[x20]\n'%('xzr' if readonly else 'x21')
                for r in range(31):source+='mov x%d,#%d\n'%(r,100+r)
                if rt!=31:source+='adrp x%d,testdata\nadd x%d,x%d,:lo12:testdata\nadd x%d,x%d,#%d\n'%(rt,rt,rt,rt,rt,block+3)
                source+='cmp xzr,xzr\n'
                source+=zero_path(0x2000+i*4,0xd50b7420|rt,0,'.Lgood%d'%i,block)
                source+='b fail\n' if fast else 'b .Lcheck%d\n'%i
                source+='.Lgood%d:\n'%i+('b .Lcheck%d\n'%i if fast else 'b fail\n')
                source+='.Lcheck%d:\nb.ne fail\n'%i
                for r in range(31):
                    if r!=rt:source+='cmp x%d,#%d\nb.ne fail\n'%(r,100+r)
                if rt!=31:
                    check=1 if rt==0 else 0
                    source+='adrp x%d,testdata\nadd x%d,x%d,:lo12:testdata\nadd x%d,x%d,#%d\ncmp x%d,x%d\nb.ne fail\n'%(check,check,check,check,check,block+3,rt,check)
                source+='adrp x20,flat_shadow\nadd x20,x20,:lo12:flat_shadow\nldr x21,[x20,#88]\ncmp x21,#%d\nb.ne fail\n'%(int(fast))
                source+='adrp x20,testdata\nadd x20,x20,:lo12:testdata\nmov x21,#0\nmov x23,#%d\n.Lbytes%d:\nldrb w22,[x20,x21]\n'%(4*block,i)
                if fast:source+='cmp x21,#%d\nb.lo .Lsentinel%d\ncmp x21,#%d\nb.hs .Lsentinel%d\ncbnz w22,fail\nb .Lbyte_next%d\n'%(block,i,2*block,i,i)
                source+='.Lsentinel%d:\ncmp w22,#165\nb.ne fail\n.Lbyte_next%d:\nadd x21,x21,#1\ncmp x21,x23\nb.lo .Lbytes%d\n'%(i,i,i)
                source+='adrp x20,stack_end\nadd x20,x20,:lo12:stack_end\nmov x21,sp\ncmp x20,x21\nb.ne fail\n'
            source+='mov x0,#0\nmov x8,#93\nsvc #0\nfail:\nmov x0,#1\nmov x8,#93\nsvc #0\n.data\n.balign 16\nflat_shadow: .zero 96\nflat_direct_write: .quad testdata,testdata+%d,0,0\n.balign %d\ntestdata: .zero %d\n.bss\n.balign 16\n.space 16384\nstack_end:\n'%(4*block,block,4*block)
            (root/'test.S').write_text(source)
            subprocess.run([cc,'-nostdlib','-static','-fuse-ld=lld','-Wl,-e,_start',str(root/'test.S'),'-o',str(root/'test')],check=True,capture_output=True)
            subprocess.run([str(root/'test')],check=True,timeout=10)

    def test_exclusive_windows_conditional_exits_permissions_alignment_and_flags(self):
        single=[0x885f7d0b,0x880afd09] # ldxr w11,[x8]; stlxr w10,w9,[x8]
        pair=[0xc87f0480,0xeb16001f,0xfa480020,0x54000061,0xc8290c82]
        cases=[(single,False,0,False,0), (pair,False,0,False,0),
               (pair,False,0,False,1), (pair,False,0,False,2),
               ([single[0],0x3500004b,single[1]],False,0,False,3),
               ([single[0],0x3700004b,single[1]],False,0,False,3),
               (single,True,0,False,0),(single,False,1,False,0),
               (pair,False,8,False,0),(single,False,0,True,0)]
        source='.text\n.global _start\n_start:\nadrp x0,stack_end\nadd x0,x0,:lo12:stack_end\nmov sp,x0\n'
        for i,(words,readonly,offset,user,mismatch) in enumerate(cases):
            pc=0x4000+i*64
            op,body=atomic_group({pc+4*k:w for k,w in enumerate(words)},pc)
            fast=memory_path(pc,op,'.Lgood%d'%i,body,lambda dest:'.Lexit%d'%i)
            self.assertTrue(fast)
            window=fast.split('.Lhw%x_insn%x:'%(pc,pc))[1].split('.Lhw%x_insn%x:'%(pc,pc+4*(len(words)-1)))[0]
            self.assertNotIn('bl ',window);self.assertNotIn('[sp',window)
            is_pair=words is pair
            slow=readonly or bool(offset) or user
            exit_expected=bool(mismatch) and not slow
            stored=not slow and not mismatch
            source+='''adrp x20,testdata
add x20,x20,:lo12:testdata
mov x21,#123
str x21,[x20]
mov x21,#456
str x21,[x20,#8]
adrp x18,flat_shadow
add x18,x18,:lo12:flat_shadow
mov x19,#%d
str x19,[x18,#80]
adrp x18,flat_direct_write
add x18,x18,:lo12:flat_direct_write
str %s,[x18]
'''%(not user,'xzr' if readonly else 'x20')
            expected={r:100+r for r in range(31)}
            expected.update({2:777,3:888,9:99 if is_pair else 777,10:99,11:42,
                             22:124 if is_pair and mismatch==1 else 123})
            for r,value in expected.items():source+='mov x%d,#%d\n'%(r,value)
            base=4 if is_pair else 8
            source+='adrp x%d,testdata\nadd x%d,x%d,:lo12:testdata\nadd x%d,x%d,#%d\n'%(base,base,base,base,base,offset)
            if is_pair:source+='mov x8,#%d\n'%(457 if mismatch==2 else 456)
            source+='cmp xzr,xzr\n.Lretry%d:\n'%i+fast
            source+='b .Lcheck%d\n'%i if slow else 'b fail\n'
            source+='.Lgood%d:\n'%i+('b .Lcheck%d\n'%i if stored else 'b fail\n')
            source+='.Lexit%d:\n'%i+('b .Lcheck%d\n'%i if exit_expected else 'b fail\n')
            source+='.Lcheck%d:\n'%i+('b.eq fail\n' if exit_expected and is_pair else 'b.ne fail\n')
            if stored:source+='cbnz w%d,.Lretry%d\n'%(9 if is_pair else 10,i)
            for r in range(12,31):source+='cmp x%d,#%d\nb.ne fail\n'%(r,expected[r])
            if is_pair:
                if not slow:source+='cmp x0,#123\nb.ne fail\ncmp x1,#456\nb.ne fail\n'
                source+='cmp x9,#%d\nb.ne fail\n'%(0 if stored else 99)
            else:
                source+='cmp x11,#%d\nb.ne fail\ncmp x10,#%d\nb.ne fail\n'%(42 if slow else 123,0 if stored else 99)
            source+='''adrp x20,testdata
add x20,x20,:lo12:testdata
ldr x21,[x20]
cmp x21,#%d
b.ne fail
ldr x21,[x20,#8]
cmp x21,#%d
b.ne fail
adrp x20,stack_end
add x20,x20,:lo12:stack_end
mov x21,sp
cmp x20,x21
b.ne fail
'''%(777 if stored else 123,888 if stored and is_pair else 456)
        source+='''mov x0,#0
mov x8,#93
svc #0
fail:
mov x0,#1
mov x8,#93
svc #0
.data
.balign 16
flat_shadow: .zero 88
flat_direct_read: .quad testdata,testdata+64,0,0
flat_direct_write: .quad testdata,testdata+64,0,0
.balign 16
testdata: .zero 64
.bss
.balign 16
.space 16384
stack_end:
'''
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'test.S').write_text(source)
            subprocess.run([shutil.which('clang-19') or shutil.which('clang'),'-nostdlib','-static','-fuse-ld=lld',
                            '-Wl,-e,_start',str(root/'test.S'),'-o',str(root/'test')],check=True,capture_output=True)
            subprocess.run([str(root/'test')],check=True,timeout=10)

    def test_shadow_registers_against_shared_emulator(self):
        from el0_calls_fixture import emit
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            emit(root,inline=True)
            binary=root/'test'
            subprocess.run([shutil.which('clang-19') or shutil.which('clang'), '-std=c11','-O2',
                            '-Wall','-Wextra','-Werror','-DOSREC_TEST_FLAT_MAINTENANCE','-mgeneral-regs-only','-mbranch-protection=none','-no-pie',
                            '-I'+str(ROOT/'runtime/el0'),'-I'+str(root),str(ROOT/'runtime/el0/emulate.c'),
                            str(ROOT/'tests/el0_calls_host.c'),str(root/'fixtures.S'),'-o',str(binary)],
                           check=True,capture_output=True,text=True)
            result=subprocess.run([str(binary)],check=True,capture_output=True,text=True,timeout=30)
            self.assertIn('native veneer/full-save comparisons passed',result.stdout)

    def test_indirect_targets_scratch_aliases_flags_links_and_misses(self):
        source='.text\n.global _start\n_start:\nadrp x0,stack_end\nadd x0,x0,:lo12:stack_end\nmov sp,x0\n'
        cases=[]
        for rn in (0,12,13,14,15,16,17,30,31):
            for opcode in (0xd61f0000,0xd63f0000,0xd65f0000):
                for key in (0x100,0x200,0x300,0x400):
                    cases.append((rn,opcode|(rn<<5),key,3))
        cases += [(17,0xd63f0000|(17<<5),0x100,0), (16,0xd61f0000|(16<<5),0x100,1),
                  (30,0xd65f0000|(30<<5),0x200,1)]
        for i,(rn,word,key,count) in enumerate(cases):
            pc=0x1000+i*4
            hit=rn!=31 and key in (0x100,0x200,0x300)[:count]
            registers={r:100+r for r in range(31)}
            if rn!=31:registers[rn]=key
            for r,value in registers.items():source+='mov x%d,#%d\n'%(r,value)
            source+='cmp xzr,xzr\n'
            source+=indirect_path(pc,word,'.Ltable%d'%i,'.Lcount%d'%i)
            source+='b fail\n' if hit else 'b .Lcheck%d\n'%i
            source+=indirect_resume('.Lresume%d'%i,'.Lgood%d'%i)
            source+='.Lgood%d:\n'%i
            source+='b .Lcheck%d\n'%i if hit else 'b fail\n'
            source+='.Lcheck%d:\nb.ne fail\n'%i
            if hit and word&0xfffffc1f==0xd63f0000:registers[30]=pc+4
            # Verify every GPR without sacrificing one to the comparison.
            for r in range(31):
                source+='cmp x%d,#%d\nb.ne fail\n'%(r,registers[r]) if registers[r]<4096 else 'sub x%d,x%d,#4096\ncmp x%d,#%d\nb.ne fail\n'%(r,r,r,registers[r]-4096)
            source+='adrp x0,stack_end\nadd x0,x0,:lo12:stack_end\nmov x1,sp\ncmp x0,x1\nb.ne fail\n'
            source+='.pushsection .rodata,"a"\n.balign 8\n.Lcount%d: .quad %d\n.Ltable%d:\n'%(i,count,i)
            source+=''.join('.quad %d,.Lresume%d\n'%(value,i) for value in (0x100,0x200,0x300))
            source+='.popsection\n'
        source+='mov x0,#0\nmov x8,#93\nsvc #0\nfail:\nmov x0,#1\nmov x8,#93\nsvc #0\n.bss\n.balign 16\n.space 16384\nstack_end:\n'
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'test.S').write_text(source)
            subprocess.run([shutil.which('clang-19') or shutil.which('clang'),'-nostdlib','-static','-fuse-ld=lld',
                            '-Wl,-e,_start',str(root/'test.S'),'-o',str(root/'test')],check=True,capture_output=True)
            subprocess.run([str(root/'test')],check=True,timeout=10)

    def test_scalar_vector_register_offset_sp_flags_and_slow_paths(self):
        cases = [
            (0xf9400020, 0, False, 'cmp x0,#123\nb.ne fail'), # ldr x0,[x1]
            (0xf9000030, 0, False, 'ldr x0,[x1]\ncmp x0,#116\nb.ne fail'), # str x16,[x1]
            (0xb862d820, 0, False, 'cmp x0,#456\nb.ne fail'), # ldr w0,[x1,w2,sxtw #2]
            (0x3dc00020, 0, False, 'umov x0,v0.d[0]\ncmp x0,#123\nb.ne fail'),
            (0xa9400820, 0, False, 'cmp x0,#123\nb.ne fail\nldr x0,[x1,#8]\ncmp x0,x2\nb.ne fail'),
            (0xf94003e0, 0, False, 'cmp x0,#123\nb.ne fail'), # logical SP
            (0xf8008c30, 0, False, 'ldr x0,[x1]\ncmp x0,#116\nb.ne fail'), # pre-index store
            (0xa8c10820, 0, False, 'cmp x0,#123\nb.ne fail\ncmp x2,#456\nb.ne fail'), # post-index pair
            (0x910003e0, 0, False, 'cmp x0,x1\nb.ne fail'), # mov x0,sp
            (0xf9800020, 0, False, 'ldr x0,[x1]\ncmp x0,#123\nb.ne fail'), # native prefetch hint
            (0xd10043ff, 0, False, 'ldr x0,[x5]\nadd x0,x0,#16\ncmp x0,x1\nb.ne fail'), # sub sp,sp,#16
            (0xf9400020, 0, True, ''), # user mode must use software
            (0xf9400020, 60, False, ''), # crossing the end is not admitted
        ]
        source = '.text\n.global _start\n_start:\nadrp x0,stack_end\nadd x0,x0,:lo12:stack_end\nmov sp,x0\n'
        for i, (word, offset, user, checks) in enumerate(cases):
            slow_expected = user or offset != 0
            source += '''adrp x1,testdata
add x1,x1,:lo12:testdata
adrp x5,control
add x5,x5,:lo12:control
str x1,[x5]
mov x0,#123
str x0,[x1]
mov x0,#456
str w0,[x1,#8]
mov x0,#0
mov x2,#2
mov x16,#116
mov x17,#117
mov x15,#115
mov x14,#114
adrp x3,flat_shadow
add x3,x3,:lo12:flat_shadow
mov x4,#%d
str x4,[x3,#80]
add x1,x1,#%d
cmp xzr,xzr
''' % (not user, offset)
            op = decode(word)
            if op.kind == STACK:
                source += stack_path(op) + 'b .Lgood%d\n' % i
            else:
                source += memory_path(0x1000 + i * 4, op, '.Lgood%d' % i)
            source += 'b .Lslow%d\n.Lgood%d:\n' % (i, i)
            source += 'b fail\n' if slow_expected else 'b .Lchecked%d\n' % i
            source += '.Lslow%d:\n' % i
            source += 'b fail\n' if not slow_expected else 'b .Lchecked%d\n' % i
            source += '.Lchecked%d:\nb.ne fail\n' % i
            source += checks + '\n'
            source += 'cmp x16,#116\nb.ne fail\ncmp x17,#117\nb.ne fail\ncmp x15,#115\nb.ne fail\ncmp x14,#114\nb.ne fail\n'
        source += '''mov x0,#0
mov x8,#93
svc #0
fail:
mov x0,#1
mov x8,#93
svc #0
.data
.balign 16
flat_shadow: .zero 88
flat_active: .quad control
control: .quad testdata
flat_direct_read: .quad testdata,testdata+64,0,0
flat_direct_write: .quad testdata,testdata+32,0,0
testdata: .zero 64
.bss
.balign 16
.space 16384
stack_end:
'''
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            (path / 'test.S').write_text(source)
            subprocess.run([shutil.which('clang-19') or shutil.which('clang'), '-nostdlib', '-static',
                            '-fuse-ld=lld', '-Wl,-e,_start', str(path / 'test.S'), '-o', str(path / 'test')],
                           check=True, capture_output=True)
            subprocess.run([str(path / 'test')], check=True, timeout=10)


@unittest.skipUnless(os.environ.get('OSREC_EL0_HARDWARE_IMAGE') and os.environ.get('OSREC_EL0_HARDWARE_PREPARED'),
                     'set hardware image and prepared paths for the complete QEMU workload')
class FullCheckpoint(unittest.TestCase):
    def test_zero_geometry_mismatch_is_rejected_before_elf_entry(self):
        from el0_hardware_model import run
        from kernel_source_verify import Elf
        import struct
        prepared=Path(os.environ['OSREC_EL0_HARDWARE_PREPARED'])
        plan=json.loads((prepared/'hardware-load-plan.json').read_text())
        if not plan.get('native_zero_bytes'):self.skipTest('executor has no native zero-block contract')
        setup=Elf(prepared/'setup.elf')
        pc=next(s['value'] for s in setup.symbols if s['name']=='hardware_zero_check')
        section=next(s for s in setup.sections if s['addr']<=pc<s['addr']+s['size'])
        offset=section['offset']+pc-section['addr']
        data=bytearray(setup.data);word,=struct.unpack_from('<I',data,offset)
        self.assertEqual(word&0xffe0001f,0xd2800001)
        struct.pack_into('<I',data,offset,word^(1<<5)) # require a different DCZID.BS
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'setup.elf').write_bytes(data)
            shutil.copyfile(prepared/'page-tables.bin',root/'page-tables.bin')
            plan['setup']['sha256']=hashlib.sha256(data).hexdigest()
            (root/'hardware-load-plan.json').write_text(json.dumps(plan))
            with self.assertRaisesRegex(ValueError,'before EL0 entry'):
                run(os.environ['OSREC_EL0_HARDWARE_IMAGE'],root,root/'run')

    def test_complete_workload_without_hardware_fault_services(self):
        from el0_hardware_model import run
        with tempfile.TemporaryDirectory() as folder:
            result = run(os.environ['OSREC_EL0_HARDWARE_IMAGE'], os.environ['OSREC_EL0_HARDWARE_PREPARED'], Path(folder) / 'run')
        self.assertTrue(result['verified'], result)
        self.assertTrue(result['el0_interval_verified'])
        self.assertEqual(result['hardware_exceptions'], 0)
        self.assertEqual((result['result']['events'], result['result']['counters'], result['result']['uart_bytes']), (2272, 9, 92))
        self.assertLess(result['result']['transitions'], 2261577)
        if 'gateway_profile' in result:
            self.assertEqual(sum(result['gateway_profile'].values()),result['result']['transitions'])

    def test_architectural_svc_at_entry_fails_whole_interval_check(self):
        from el0_hardware_model import run
        from kernel_source_verify import Elf
        import struct

        image = Path(os.environ['OSREC_EL0_HARDWARE_IMAGE'])
        prepared = Path(os.environ['OSREC_EL0_HARDWARE_PREPARED'])
        plan = json.loads((prepared / 'hardware-load-plan.json').read_text())
        entry = int(plan['entry'], 0)
        elf = Elf(image / 'checkpoint')
        text = next(section for section in elf.sections
                    if section['addr'] <= entry < section['addr'] + section['size'])
        data = bytearray(elf.data)
        struct.pack_into('<I', data, text['offset'] + entry - text['addr'], 0xd4000001)
        plan['image_sha256'] = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'checkpoint').write_bytes(data)
            shutil.copyfile(image / 'hardware-memory.json', root / 'hardware-memory.json')
            shutil.copyfile(prepared / 'setup.elf', root / 'setup.elf')
            if not plan['page_tables'].get('embedded'):
                shutil.copyfile(prepared / 'page-tables.bin', root / 'page-tables.bin')
            (root / 'hardware-load-plan.json').write_text(json.dumps(plan))
            result = run(root, root, root / 'run')
        self.assertFalse(result['verified'])
        self.assertFalse(result['el0_interval_verified'])
        self.assertTrue(result['exception_trace']['bootstrap_to_entry_observed'])
        self.assertEqual(result['hardware_exceptions'], 1)
        self.assertEqual(result['completion']['pc'], int(plan['unexpected_pc'], 0))

    def test_missing_kernel_alias_stops_instead_of_using_el1_services(self):
        from el0_hardware_model import run
        prepared = Path(os.environ['OSREC_EL0_HARDWARE_PREPARED'])
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            plan = json.loads((prepared / 'hardware-load-plan.json').read_text())
            if plan['page_tables'].get('embedded') or plan.get('original_va_aliases') == 0:
                self.skipTest('requires external page tables with original-address aliases')
            tables = bytearray((prepared / 'page-tables.bin').read_bytes())
            # Remove the captured kernel linear-map subtree. Identity mappings
            # of the executor/result remain available to report the failure.
            import struct
            struct.pack_into('<Q', tables, 8 * (0x200000000000 >> 39), 0)
            (root / 'page-tables.bin').write_bytes(tables)
            plan['page_tables']['sha256'] = hashlib.sha256(tables).hexdigest()
            (root / 'hardware-load-plan.json').write_text(json.dumps(plan))
            shutil.copyfile(prepared / 'setup.elf', root / 'setup.elf')
            result = run(os.environ['OSREC_EL0_HARDWARE_IMAGE'], root, root / 'run')
        self.assertFalse(result['verified'])
        self.assertFalse(result['el0_interval_verified'])
        self.assertEqual(result['hardware_exceptions'], 1)


if __name__ == '__main__':
    unittest.main()
