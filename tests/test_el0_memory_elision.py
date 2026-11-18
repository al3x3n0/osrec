"""Native literal and fixed-page admission semantics; no user-PTE cache."""
from pathlib import Path
import hashlib,json,os,shutil,struct,subprocess,sys,tempfile,unittest
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from el0_flat_lower import decode
from el0_hardware import memory_path,immediate
from el0_memory_elision import literal_proof,literal_path,page_cache_probe,page_cache_eligible,validate_page_cache_ranges,user_load_groups
from el0_calls_fixture import save_context
from el0_control import layout,gateway_sizes
CC=Path('/opt/homebrew/opt/llvm@16/bin/clang');QEMU=shutil.which('qemu-system-aarch64')


class Proofs(unittest.TestCase):
    def test_user_load_groups_require_contiguous_unmodified_pointer_and_single_loads(self):
        def group(words):return user_load_groups({0x1000+4*i:(decode(w),0) for i,w in enumerate(words)})
        self.assertEqual(len(group([0xf8400827,0xf8408828])[0x1000]),2)
        captured={0x1000:(decode(0xf8400827),0x80000595),0x1004:(decode(0xf8408828),0x80000596)}
        self.assertEqual(len(user_load_groups(captured)[0x1000]),2)
        captured[0x1004]=(decode(0xf8408828),0x40000596)
        self.assertFalse(user_load_groups(captured))
        self.assertFalse(group([0xf8400827,0xf8410828])) # hole
        self.assertFalse(group([0xf8400827,0xf8408848])) # different pointer
        self.assertFalse(group([0xf8400821,0xf8408828])) # first load changes X1
        self.assertFalse(group([0xf8400827,0xf8008828])) # store
        self.assertFalse(group([0xf8400827,0xb8408828])) # different width
        self.assertFalse(group([0xf8400827,0xf8408830])) # scratch destination
        self.assertFalse(group([0xf9400027,0xf9400428])) # ordinary accesses

    def test_literal_requires_immutable_readable_contiguous_ram_and_load_encoding(self):
        def prove(word=0x58000040,**changes):
            args=dict(pc=0x1000,op=decode(word),physical=lambda va:va+0x40000000,
                read=lambda pa,size:bytes(range(size)),immutable=[(0x40001000,4096)],
                ram_base=0x40000000,ram_bytes=0x4000,read_ranges=[(0x1000,0x2000)])
            args.update(changes);return literal_proof(**args)
        self.assertEqual(prove()['data'],bytes(range(8)))
        for changes in (dict(immutable=[]),dict(immutable=[(0x40001008,4)]),dict(read_ranges=[]),
                dict(read_ranges=[(0x1000,0x100f)]),dict(ram_bytes=4096),
                dict(physical=lambda va:0x40001008 if va==0x1008 else 0x40002000),dict(read=lambda pa,size:b'')):
            self.assertIsNone(prove(**changes))
        for word in (0xf9400020,0xf9000020,0xd8000040):self.assertIsNone(prove(word))
        for word in (0xf8400820,0xf9400020):self.assertFalse(page_cache_eligible(decode(word),True))
        self.assertFalse(page_cache_eligible(decode(0xc8dfffff),False))

    def test_cache_requires_readonly_bound_page_aligned_range_tables_and_mode(self):
        data={0x1000:struct.pack('<Q',1),0x2000:struct.pack('<4Q',0x4000,0x6000,0,0),
              0x3000:struct.pack('<4Q',0x5000,0x6000,0,0)}
        elf=SimpleNamespace(symbols=[dict(name=n,value=v,shndx=1) for n,v in
            (('flat_memory_page_cache_mode',0x1000),('flat_direct_read',0x2000),('flat_direct_write',0x3000))],
            sections=[{},dict(flags=2)],read=lambda at,size:data[at][:size])
        checked=dict(load_segments=[dict(address=0x1000,memory_bytes=0x3000,flags=4)])
        meta=dict(fixed_page_memory_cache=dict(sites=1,page_bytes=4096),read_ranges=[[0x4000,0x6000]],write_ranges=[[0x5000,0x6000]])
        validate_page_cache_ranges(elf,checked,meta)
        data[0x2000]=struct.pack('<4Q',0x4001,0x6000,0,0)
        with self.assertRaisesRegex(ValueError,'differ'):validate_page_cache_ranges(elf,checked,meta)
        data[0x2000]=struct.pack('<4Q',0x4000,0x6000,0,0)
        meta['read_ranges']=[[0x4001,0x6000]]
        with self.assertRaisesRegex(ValueError,'aligned'):validate_page_cache_ranges(elf,checked,meta)
        meta['read_ranges']=[[0x4000,0x6000]];checked['load_segments'][0]['flags']=6
        with self.assertRaisesRegex(ValueError,'writable'):validate_page_cache_ranges(elf,checked,meta)
        checked['load_segments'][0]['flags']=4;meta.pop('fixed_page_memory_cache')
        with self.assertRaisesRegex(ValueError,'mode'):validate_page_cache_ranges(elf,checked,meta)


@unittest.skipUnless(CC.exists() and QEMU,'AArch64 compiler and QEMU required')
class Instructions(unittest.TestCase):
    def test_literals_cache_hits_changes_permissions_modes_alignment_and_full_context(self):
        cases=[]
        for size in range(4):
            for load in (False,True):
                for rn in (0,16,17,30,31):
                    for rt in (0,16,17,30,31):
                        word=(size<<30)|(0x08dffc00 if load else 0x089ffc00)|(rn<<5)|rt
                        cases.append((word,0,1<<size,0,0))
        for base,size in ((0x18000040,4),(0x58000040,8),(0x98000040,4)):
            for rt in (0,16,17,30,31):
                for value in (0,0x80000000,0xffffffffffffffff,0x0123456789abcdef):
                    cases.append((base|rt,1,size,value,0))
        for base,size in ((0x1c000040,4),(0x5c000040,8),(0x9c000040,16)):
            cases.append((base,2,size,0xfedcba9876543210,0x0123456789abcdef))
        lines=['.arch armv8-a+simd','.text','.global _start','_start:',
            'mov x1,#0x300000','msr cpacr_el1,x1','isb',
            'adrp x1,vectors','add x1,x1,:lo12:vectors','msr vbar_el1,x1',
            'adrp x1,identity_root','add x1,x1,:lo12:identity_root',
            'adrp x2,identity_l1','add x2,x2,:lo12:identity_l1','orr x2,x2,#3','str x2,[x1]',
            'msr ttbr0_el1,x1']+immediate(1,0x80103510)+['msr tcr_el1,x1',
            'mov x1,#255','msr mair_el1,x1','dsb sy','tlbi vmalle1','dsb sy','isb']+immediate(1,0x30d01805)+[
            'msr sctlr_el1,x1','isb','adrp x0,host_stack_end','add x0,x0,:lo12:host_stack_end',
            'mov sp,x0','bl test_main','exit:','adrp x1,exit_status','add x1,x1,:lo12:exit_status','str x0,[x1,#8]',
            'mov x0,#0x20','hlt #0xf000','b .'];header=[]
        for i,(word,kind,size,lo,hi) in enumerate(cases):
            pc=0x1000+i*4
            lines+=['.global probe%d'%i,'probe%d:'%i,'sub sp,sp,#96']
            lines+=['stp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
            lines+=['adrp x9,test_host_sp','mov x10,sp','str x10,[x9,:lo12:test_host_sp]',
                'adrp x9,test_after','str x1,[x9,:lo12:test_after]','movi v0.16b,#0x5a','mov x30,x0',
                'ldr x9,[x30,#264]','msr nzcv,x9','ldr x9,[x30,#248]','mov sp,x9']
            lines+=['ldp x%d,x%d,[x30,#%d]'%(r,r+1,r*8) for r in range(0,30,2)]+['ldr x30,[x30,#240]']
            if kind:
                raw=(struct.pack('<2Q',lo,hi))[:size]
                lines+=literal_path(dict(word=word,data=raw),'.Lgood%d'%i).splitlines()
            else:
                lines+=page_cache_probe(pc,decode(word),'.Lgood%d'%i,True).splitlines()
                lines+=memory_path(pc,decode(word),'.Lgood%d'%i,native_sp=True,page_cache=True).splitlines()
                # Alias the cache for independent post-execution tag checks.
                lines+=['.pushsection .data,"aw"','.global cache%d'%i,'.set cache%d,.Lmpc%x'%(i,pc),'.popsection']
            lines+=['sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#0','b status',
                '.Lgood%d:'%i,'sub sp,sp,#16','stp x0,x1,[sp]','mov x0,#1','b status']
            header+=['extern void probe%d(const struct osrec_context *,struct osrec_context *);'%i]
            if not kind:header+=['extern uint64_t cache%d;'%i]
        lines+=['status:','adrp x1,test_fast','str x0,[x1,:lo12:test_fast]',
            'adrp x1,test_vector','str q0,[x1,:lo12:test_vector]','ldp x0,x1,[sp]','add sp,sp,#16']
        lines+=save_context()+['mov x0,sp','adrp x1,test_after','ldr x1,[x1,:lo12:test_after]','mov x2,#34',
            '1: ldr x3,[x0],#8','str x3,[x1],#8','subs x2,x2,#1','b.ne 1b',
            'adrp x9,test_host_sp','ldr x9,[x9,:lo12:test_host_sp]','mov sp,x9']
        lines+=['ldp x%d,x%d,[sp,#%d]'%(r,r+1,(r-19)*8) for r in range(19,31,2)]
        lines+=['add sp,sp,#96','ret','unexpected:','mrs x0,esr_el1','and x0,x0,#255','add x0,x0,#128','b exit',
            '.section .vectors,"ax"','.balign 2048','vectors:','.rept 16','b unexpected','.space 124','.endr',
            '.section .rodata,"a"','.balign 16',
            '.global flat_direct_read,flat_direct_write',
            'flat_direct_read: .quad test_data,test_data+12288,0,0',
            'flat_direct_write: .quad test_data,test_data+4096,test_data+8192,test_data+12288,0,0',
            '.data','.balign 16','exit_status: .quad 0x20026,1',
            '.balign 4096','identity_root: .zero 4096','identity_l1: .quad 0,0x40000701','.zero 4080',
            '.bss','.balign 16',
            'test_host_sp: .zero 8','test_after: .zero 8','.space 65536','host_stack_end:']
        header+=['static const struct fixture fixtures[]={']
        header+=['{0x%x,%d,%d,0x%xull,0x%xull,probe%d,%s},'%(w,k,s,lo,hi,i,'0' if k else '&cache%d'%i)
                 for i,(w,k,s,lo,hi) in enumerate(cases)]+['};']
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'test.S').write_text('\n'.join(lines)+'\n');(root/'cases.h').write_text('\n'.join(header)+'\n')
            # The layout pass must account for literal data without relaxation.
            layout(root/'test.S',gateway_sizes(ROOT/'runtime/el0_flat/gateway.inc'))
            built=subprocess.run([str(CC),'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib','-O2',
                '-ffreestanding','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
                '-I'+str(ROOT/'runtime/el0_flat'),'-I'+str(ROOT/'runtime/el0'),'-I'+str(root),
                '-Wl,-Ttext=0x40200000,-e,_start',str(root/'test.S'),str(ROOT/'tests/el0_memory_elision_host.c'),
                str(ROOT/'runtime/el0_flat/bytes.c'),'-o',str(root/'test.elf')],capture_output=True)
            self.assertEqual(built.returncode,0,built.stderr.decode())
            result=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                '-accel','tcg','-nodefaults','-display','none','-monitor','none','-serial','none',
                '-semihosting-config','enable=on,target=native','-device','loader,file=%s,cpu-num=0'%(root/'test.elf')],
                capture_output=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr.decode())
        print('%d acquire/release and %d literal probes'%(200,63))


@unittest.skipUnless(os.environ.get('OSREC_EL0_MEMORY_ELISION_IMAGE'),'set memory-elision image for negative admission checks')
class FullImage(unittest.TestCase):
    def test_modified_unaligned_and_unbound_page_ranges_are_rejected(self):
        from el0_hardware_model import prepare
        from kernel_source_verify import Elf
        image=Path(os.environ['OSREC_EL0_MEMORY_ELISION_IMAGE']).resolve();elf=Elf(image/'checkpoint')
        symbol=next(s for s in elf.symbols if s['name']=='flat_direct_read')
        section=elf.sections[symbol['shndx']];offset=section['offset']+symbol['value']-section['addr']
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for mode,message in (('modified','ranges differ'),('unaligned','not page aligned'),('unbound','mode differs')):
                out=root/mode;out.mkdir();data=bytearray(elf.data)
                metadata=json.loads((image/'hardware-memory.json').read_text())
                if mode=='unbound':metadata.pop('fixed_page_memory_cache')
                else:
                    data[offset]^=1
                    if mode=='unaligned':metadata['read_ranges'][0][0]^=1
                (out/'checkpoint').write_bytes(data)
                raw=(json.dumps(metadata,indent=2)+'\n').encode();(out/'hardware-memory.json').write_bytes(raw)
                manifest=json.loads((image/'manifest.json').read_text());manifest['hardware_memory_sha256']=hashlib.sha256(raw).hexdigest()
                (out/'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError,message):prepare(out,root/(mode+'-model'))


if __name__=='__main__':unittest.main()
