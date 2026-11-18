"""Native stack-store guards must restore operands before the original store."""
from pathlib import Path
import shutil,subprocess,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from el0_flat_lower import decode,MEMORY,LOAD
from el0_hardware import memory_path
CC=Path('/opt/homebrew/opt/llvm@16/bin/clang');QEMU=shutil.which('qemu-system-aarch64')

class Admission(unittest.TestCase):
    def test_only_enabled_native_stack_stores_gain_writeback_fast_path(self):
        for word in (0xa9bf7bfd,0xf81f0fe0):
            op=decode(word)
            self.assertEqual(memory_path(0,op,'next',native_sp=True),'')
            self.assertIn('.inst 0x%08x'%word,memory_path(0,op,'next',native_sp=True,native_store=True))
        self.assertEqual(memory_path(0,decode(0xa8c17bfd),'next',native_sp=True,native_store=True),'')

@unittest.skipUnless(CC.exists() and QEMU,'AArch64 compiler and QEMU required')
class Instructions(unittest.TestCase):
    def test_pairs_scalars_vectors_operands_flags_writeback_and_excluded_pages(self):
        cases=[]
        for size,base,vector in ((1,0x38000000,0),(2,0x78000000,0),(4,0xb8000000,0),
                                 (8,0xf8000000,0),(16,0x3c800000,1)):
            for rt in range(32):
                for mode,offset in ((3,-16),(1,16),(0,-16),(3,32)):
                    word=base|((offset&511)<<12)|(mode<<10)|(31<<5)|rt
                    cases.append((word,size,1,offset,mode==1,mode in (1,3),vector))
        for size,base,vector in ((4,0x28000000,0),(8,0xa8000000,0),(16,0xac000000,1)):
            for rt in range(32):
                for rt2 in (16,17,31):
                    for mode,offset in ((3,-32),(1,32),(2,-16),(3,16)):
                        word=base|(mode<<23)|(((offset//size)&127)<<15)|(rt2<<10)|(31<<5)|rt
                        cases.append((word,size,2,offset,mode==1,mode in (1,3),vector))
        cases=[case for case in cases if decode(case[0]).kind==MEMORY]
        lines=['.arch armv8-a+simd','.text','.global _start','_start:',
               'mov x0,#0x300000','msr cpacr_el1,x0','isb',
               'adrp x0,host_stack_end','add x0,x0,:lo12:host_stack_end','mov sp,x0','bl test_main',
               'adrp x1,exit_status','add x1,x1,:lo12:exit_status','str x0,[x1,#8]',
               'mov x0,#0x20','hlt #0xf000','b .'];header=[]
        for i,case in enumerate(cases):
            word=case[0];op=decode(word);self.assertEqual(op.kind,MEMORY);self.assertFalse(op.info&LOAD)
            lines+=['.global probe%d'%i,'probe%d:'%i,'sub sp,sp,#96']
            lines+=['stp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
            lines+=['adrp x9,test_host_sp','mov x10,sp','str x10,[x9,:lo12:test_host_sp]',
                    'mov x30,x0','ldr x9,[x30,#264]','msr nzcv,x9','ldr x9,[x30,#248]','mov sp,x9',
                    'mov x9,#1','msr fpsr,x9','mov x9,#0x400000','msr fpcr,x9']
            lines+=['movi v%d.16b,#%d'%(r,(r*7+3)&255) for r in range(32)]
            lines+=['ldp x%d,x%d,[x30,#%d]'%(r,r+1,r*8) for r in range(0,30,2)]+['ldr x30,[x30,#240]']
            lines+=memory_path(0x1000+4*i,op,'capture_fast',native_sp=True,native_store=True).splitlines()+['b capture_slow']
            header.append('extern void probe%d(const struct osrec_context *);'%i)
        # Capture directly into a separate buffer. A capture frame below the
        # updated SP could itself overwrite a post-index store's payload.
        for fast in (0,1):
            lines+=['capture_'+('fast' if fast else 'slow')+':','msr tpidr_el0,x18',
                    'adrp x18,test_capture','add x18,x18,:lo12:test_capture']
            lines+=['stp x%d,x%d,[x18,#%d]'%(r,r+1,r*8) for r in range(0,30,2) if r!=18]
            lines+=['str x30,[x18,#240]','str x19,[x18,#152]','mrs x0,tpidr_el0','str x0,[x18,#144]',
                    'mov x0,sp','str x0,[x18,#248]','str xzr,[x18,#256]','mrs x0,nzcv','str x0,[x18,#264]',
                    'mov x0,#%d'%fast,'str x0,[x18,#272]','stp q0,q31,[x18,#288]',
                    'mrs x0,fpsr','str x0,[x18,#320]','mrs x0,fpcr','str x0,[x18,#328]','b finish']
        lines+=['finish:','adrp x9,test_host_sp','ldr x9,[x9,:lo12:test_host_sp]','mov sp,x9']
        lines+=['ldp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
        lines+=['add sp,sp,#96','ret','.data','.balign 16','exit_status: .quad 0x20026,1',
                '.bss','.balign 16','test_host_sp: .zero 8','.space 65536','host_stack_end:']
        header+=['static const struct fixture fixtures[]={']
        header+=['{%s,probe%d},'%(','.join(str(int(v)) for v in case),i) for i,case in enumerate(cases)]+['};']
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);(out/'fixture.S').write_text('\n'.join(lines)+'\n');(out/'cases.h').write_text('\n'.join(header)+'\n')
            built=subprocess.run([str(CC),'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                '-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),'-I'+str(out),
                '-Wl,-Ttext=0x40200000,-e,_start',str(out/'fixture.S'),str(ROOT/'tests/el0_stack_store_host.c'),
                str(ROOT/'runtime/el0_flat/bytes.c'),
                '-o',str(out/'fixture')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                '-semihosting-config','enable=on,target=native','-device','loader,file='+str(out/'fixture')+',cpu-num=0'],
                capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr)
        print('%d native stack-store comparisons'%(len(cases)*16*9))
