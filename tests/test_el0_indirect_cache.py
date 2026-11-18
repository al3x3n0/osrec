"""Execute hits, target changes and misses while checking every GPR/SP/NZCV."""
from pathlib import Path
import os
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from el0_calls_fixture import save_context
from el0_hardware import indirect_path,indirect_resume,pc_index_data,pc_index_layout
from kernel_source_verify import Elf

LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
QEMU=shutil.which('qemu-system-aarch64')


@unittest.skipUnless(QEMU and (LLVM/'clang').exists(),'cross clang and system QEMU required')
class CachedIndirect(unittest.TestCase):
    def test_hits_misses_zero_targets_aliases_links_flags_and_stack(self):
        self.exercise(False)

    def test_indexed_hits_holes_alignment_bounds_links_flags_and_stack(self):
        self.exercise(True)

    def test_compact_indexed_hits_holes_alignment_bounds_links_flags_and_stack(self):
        self.exercise(True,compact=True)

    def exercise(self,indexed,compact=False):
        lines=['.text','.global _start','_start:',
               'adrp x0,host_stack_end','add x0,x0,:lo12:host_stack_end','mov sp,x0',
               'bl test_main','mov x2,x0','adrp x1,exit_status','add x1,x1,:lo12:exit_status',
               'str x2,[x1,#8]','mov x0,#0x20','hlt #0xf000','b .']
        header=[];cases=[]
        for base in (0xd61f0000,0xd63f0000,0xd65f0000):
            for rn in range(32):
                for count in (0,2,3,6):
                    i=len(cases);word=base|(rn<<5);pc=0x1000+4*i
                    index_base=0x800080000000 if indexed and i%2 else 0
                    cases.append((word,pc,count,index_base))
                    lines+=['.global probe%d'%i,'probe%d:'%i,'sub sp,sp,#96']
                    lines+=['stp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
                    lines+=['adrp x9,test_host_sp','mov x10,sp','str x10,[x9,:lo12:test_host_sp]',
                            'adrp x9,test_after','str x1,[x9,:lo12:test_after]',
                            'mov x30,x0','ldr x9,[x30,#264]','msr nzcv,x9',
                            'ldr x9,[x30,#248]','mov sp,x9']
                    lines+=['ldp x%d,x%d,[x30,#%d]'%(r,r+1,r*8) for r in range(0,30,2)]
                    lines+=['ldr x30,[x30,#240]']
                    index=('.Lindex%d'%i,index_base,13) if indexed else None
                    # Exercise the two extreme aligned cache placements.
                    lines+=['.pushsection .data,"aw"','.balign 4096','.space %d'%(4080 if i%2 else 0),'.popsection']
                    lines+=indirect_path(pc,word,'.Ltable%d'%i,'.Lcount%d'%i,cache=True,index=index,compact=compact).splitlines()
                    lines+=['b common_slow']
                    lines+=indirect_resume('.Lresume%d'%i,'common_fast',compact=compact).splitlines()
                    lines+=['.pushsection .rodata,"a"','.balign 8','.Lcount%d: .quad %d'%(i,count),'.Ltable%d:'%i]
                    targets=(0x100,0x200,0x300,0xffc,0x1000,0x1ffc)
                    lines+=['.quad %d,.Lresume%d'%(target,i) for target in targets]
                    if indexed:
                        data=pc_index_data('.Lindex%d'%i,[index_base+target for target in targets[:count]],(index_base,13))
                        for target in targets:
                            data=data.replace('.Li%x'%(index_base+target),'.Lresume%d'%i).replace('.Lr%x'%(index_base+target),'.Lresume%d'%i)
                        lines+=data.splitlines()
                    lines+=['.popsection','.global cache%d'%i,'.set cache%d,.Lij%x_cache'%(i,pc)]
                    header+=['extern void probe%d(const struct osrec_context *,struct osrec_context *);'%i,
                             'extern uint64_t cache%d[2];'%i]
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
        header+=['{0x%x,0x%x,%d,probe%d,cache%d,0x%x},'%(word,pc,count,i,i,base) for i,(word,pc,count,base) in enumerate(cases)]
        header+=['};']
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);(out/'fixture.S').write_text('\n'.join(lines)+'\n');(out/'cases.h').write_text('\n'.join(header))
            built=subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                                  '-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                                  '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),'-I'+str(out),
                                  '-Wl,-Ttext=0x40200000,-e,_start',str(out/'fixture.S'),
                                  str(ROOT/'tests/el0_indirect_cache_host.c'),str(ROOT/'runtime/el0_flat/bytes.c'),
                                  '-o',str(out/'fixture')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            elf=Elf(out/'fixture');symbols={s['name']:s['value'] for s in elf.symbols if s['shndx']}
            for i in range(len(cases)):
                self.assertEqual(symbols['cache%d'%i]&4095,4080 if i%2 else 0)
            process=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                                    '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                                    '-semihosting-config','enable=on,target=native','-device',
                                    'loader,file='+str(out/'fixture')+',cpu-num=0'],capture_output=True,text=True,timeout=30)
            self.assertEqual(process.returncode,0,process.stderr)


class IndexLayout(unittest.TestCase):
    def test_sparse_high_addresses_and_rejected_layouts(self):
        pcs=[0x800080010000,0x800084005da8]
        base,bits=pc_index_layout(pcs)
        self.assertEqual(base,pcs[0]);self.assertEqual(bits,26)
        for values in ([],[1],[-4],[1<<64],[0,1<<31]):
            with self.assertRaises(ValueError):pc_index_layout(values)
        with self.assertRaises(ValueError):pc_index_data('bad',[0x1000],(0,12))
        with self.assertRaises(ValueError):pc_index_data('bad',[0x1004],(0x1004,12))
        with self.assertRaises(ValueError):indirect_path(0x1000,0xd61f0000,index=('bad',0x1004,12))


@unittest.skipUnless(os.environ.get('OSREC_EL0_INDEXED_IMAGE'),'full indexed ELF not selected')
class IndexedImage(unittest.TestCase):
    def test_all_context_targets_and_holes_match_the_complete_pc_table(self):
        image=Path(os.environ['OSREC_EL0_INDEXED_IMAGE']);elf=Elf(image/'checkpoint')
        manifest=json.loads((image/'manifest.json').read_text())
        syms={s['name']:s['value'] for s in elf.symbols if s['shndx']}
        pcs,count=struct.unpack('<2Q',elf.read(syms['flat_program']+56,16))
        expected=dict(struct.iter_unpack('<2Q',elf.read(pcs,count*16)))
        indices,=struct.unpack('<Q',elf.read(syms['flat_pc_index_count'],8))
        self.assertEqual(indices,2)
        found={}
        def branch(at,word):
            self.assertEqual(word&0xfc000000,0x14000000)
            delta=word&0x3ffffff
            if delta&0x2000000:delta-=0x4000000
            return at+4*delta
        def readonly(address,bytes):
            self.assertTrue(any(s['addr']<=address and address+bytes<=s['addr']+s['size'] and
                                s['flags']&2 and not s['flags']&1 for s in elf.sections))
        readonly(syms['flat_pc_indices'],indices*24)
        for base,bytes,root in struct.iter_unpack('<3Q',elf.read(syms['flat_pc_indices'],indices*24)):
            readonly(root,(bytes>>12)*8)
            for page,(pointer,) in enumerate(struct.iter_unpack('<Q',elf.read(root,(bytes>>12)*8))):
                if not pointer:continue
                readonly(pointer,16384)
                for slot,(direct,context) in enumerate(struct.iter_unpack('<2Q',elf.read(pointer,16384))):
                    pc=base+(page<<12)+(slot<<2)
                    if pc not in expected:
                        self.assertEqual((direct,context),(0,0));continue
                    self.assertNotIn(pc,found);self.assertEqual(context,expected[pc])
                    self.assertTrue(any(s['flags']&4 and s['addr']<=direct<s['addr']+s['size'] for s in elf.sections))
                    if manifest.get('pretranslated_memory'):
                        compact=(root==syms['flat_kernel_direct_index'] and manifest.get('kernel_indirect_frame_bytes',64)==32)
                        code=struct.unpack('<%dI'%(2 if compact else 3),elf.read(direct,8 if compact else 12))
                        if compact:self.assertEqual(code[0],0xa8c247f0) # LDP post-index #32
                        else:self.assertEqual(code[:2],(0xa94247f0,0x910103ff)) # LDP + ADD #64
                        destination=branch(direct+4*(len(code)-1),code[-1])
                        tail,=struct.unpack('<I',elf.read(context+32,4))
                        self.assertEqual(destination,branch(context+32,tail))
                    found[pc]=context
        self.assertEqual(found,expected)


if __name__=='__main__':unittest.main()
