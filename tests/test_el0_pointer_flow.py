"""Conservative interval proofs and execution of a dynamically indexed rewrite."""
from pathlib import Path
from types import SimpleNamespace
import json,os,shutil,struct,subprocess,tempfile,unittest
from unittest.mock import patch
from el0_pointer_flow import Bound,analyze,arithmetic,extended,access_path,unsigned_bitfield,constrain_comparison
from el0_flat_lower import decode
from el0_pretranslate import user_proofs

CC=Path('/opt/homebrew/opt/llvm@16/bin/clang');QEMU=shutil.which('qemu-system-aarch64')
BASE=0xffffc39f7000


class Proofs(unittest.TestCase):
    def setUp(self):
        self.package=SimpleNamespace(h=[0,0,0x40000000,12288],memory=bytearray(12288))
        self.aliases=[dict(va=0x9000,pa=0x40002000,bytes=4096,attrs=0),
                      dict(va=BASE,pa=0x40000000,bytes=8192,attrs=0)]
        self.initial=[0]*34;self.initial[1]=BASE;self.initial[31]=0x9ff0;self.initial[32]=0x100
        # Unknown syscall result, bounded index, dynamically indexed LDR X3.
        self.words={0x100:0xd4000001,0x104:0x92401c02,0x108:0xf8627823,0x10c:0x14000000}

    def prove(self,words=None,immutable=()):
        return analyze(self.words if words is None else words,self.initial,self.package,self.aliases,immutable)

    def test_dynamic_index_outgrows_finite_enumeration(self):
        row=self.prove()['proofs'][0x108]
        self.assertEqual(row['bounds'],[BASE,BASE+255*8])
        self.assertNotIn(0x108,user_proofs(self.words,self.initial,self.package,self.aliases,[]))

    def test_export_requires_checked_compact_execution(self):
        from export_el0_program import export
        for options in ({},{'compact_dynamic_memory':True,'validation':False}):
            with self.assertRaisesRegex(ValueError,'requires --compact-dynamic-memory and runtime validation'):
                export(None,None,None,None,None,dataflow_memory=True,**options)
        with self.assertRaisesRegex(ValueError,'transfer form not admitted'):
            access_path(0,decode(0xf8408420),{},0,'next')

    def test_extensions_and_overflow(self):
        for ext,bits in enumerate((8,16,32,64,8,16,32,64)):
            for value in (0,127,128,255,65535,0xffffffff,0xffffffffffffffff):
                raw=value&((1<<bits)-1)
                signed=raw-(1<<bits) if ext&4 and raw>>(bits-1) else raw
                for shift in (0,3):self.assertEqual(extended(Bound.constant(value),ext,shift),Bound.constant(signed<<shift))
        self.assertIsNone(extended(Bound(0,255),4,0))
        self.assertEqual(extended(Bound(256,1024),0,0),Bound(0,255))
        self.assertIsNone(arithmetic(Bound((1<<64)-2,(1<<64)-1),Bound(1,2)))
        self.assertIsNone(arithmetic(Bound(0,10),Bound(1,2),True))

    def test_bitfields_bound_mutable_load_without_using_snapshot_value(self):
        # LDRB W0, [X1]; LSR X2, X0, #4; LDR X3,[X1,X2,LSL #3].
        words={0x100:0x39400020,0x104:0xd344fc02,0x108:0xf8627823,0x10c:0x14000000}
        self.assertEqual(self.prove(words)['proofs'][0x108]['bounds'],[BASE,BASE+15*8])
        self.assertNotIn(0x108,user_proofs(words,self.initial,self.package,self.aliases,[]))
        # Exhaustively check every 8-bit UBFM field and every concrete value in
        # several intervals; this exercises both forms and truncation wrap.
        for rotate in range(8):
            for last in range(8):
                for lo,hi in ((0,255),(0,15),(120,140),(250,255),(256,511)):
                    bound=unsigned_bitfield(Bound(lo,hi),rotate,last,8)
                    for value in range(lo,hi+1):
                        expected=((value>>rotate)&((1<<(last-rotate+1))-1)) if last>=rotate else ((value&((1<<(last+1))-1))<<(8-rotate))
                        self.assertLessEqual(bound.lo,expected)
                        self.assertLessEqual(expected,bound.hi)

    def test_join_unknown_indirect_and_widening(self):
        # Both conditional predecessors reach the load; one destroys its base.
        words={0x100:0xb4000060,0x104:0xf9400021,0x108:0x14000002,
               0x10c:0xd503201f,0x110:0xf9400023,0x114:0x14000000}
        self.assertNotIn(0x110,self.prove(words)['proofs'])
        words=dict(self.words);words[0x10c]=0xd61f0000 # unknown X0 BR can re-enter anywhere
        self.assertFalse(self.prove(words)['proofs'])
        words={0x100:0x91002021,0x104:0xf9400023,0x108:0x17fffffe}
        result=self.prove(words)
        self.assertGreater(result['widened_registers'],0)
        self.assertNotIn(0x104,result['proofs'])

    def test_loop_bound_survives_widening_without_enumeration(self):
        # Index starts at zero and traverses 256 elements. No execution trace
        # or observed loop count supplies the bound.
        words={0x100:0xf8627823,0x104:0x91000442,0x108:0xf104005f,
               0x10c:0x54ffffa1,0x110:0x14000000}
        result=self.prove(words)
        self.assertEqual(result['proofs'][0x100]['bounds'],[BASE,BASE+255*8])
        self.assertNotIn(0x100,user_proofs(words,self.initial,self.package,self.aliases,[]))
        self.assertGreater(result['widened_registers'],0)
        # Changing the condition to signed LT must not use unsigned bounds.
        words[0x10c]=0x54ffffab
        self.assertNotIn(0x100,self.prove(words)['proofs'])

    def test_comparison_requires_dominating_cmp_and_preserves_upper_word(self):
        words={0x100:0xd4000001,0x104:0xaa0003e2,0x108:0x14000002,
               0x10c:0xf104005f,0x110:0x54000062,0x114:0xf8627823,
               0x118:0x14000000,0x11c:0x14000000}
        self.assertNotIn(0x114,self.prove(words)['proofs'])
        state=(Bound(1<<32,(1<<32)+255),)+(None,)*31
        self.assertEqual(constrain_comparison(state,(0,8,32),3),state)
        predicates={0:lambda x,c:x==c,1:lambda x,c:x!=c,2:lambda x,c:x>=c,
                    3:lambda x,c:x<c,8:lambda x,c:x>c,9:lambda x,c:x<=c}
        for lo,hi in ((0,255),(5,10),(0,0),(255,255)):
            for constant in (0,5,8,10,255):
                for condition,predicate in predicates.items():
                    result=constrain_comparison((Bound(lo,hi),)+(None,)*31,(0,constant,64),condition)
                    values=[x for x in range(lo,hi+1) if predicate(x,constant)]
                    if values:
                        self.assertIsNotNone(result)
                        self.assertLessEqual(result[0].lo,min(values));self.assertGreaterEqual(result[0].hi,max(values))
                    elif result is not None:self.fail('impossible edge remained reachable')

    def test_late_bypass_invalidates_comparison_without_a_register_change(self):
        # The taken CBZ path reaches CMP first. The longer path reaches B.HS
        # with the same unknown index and NZCV from some other instruction.
        words={0x100:0xd4000001,0x104:0xaa0003e2,0x108:0xb4000080,
               0x10c:0xd503201f,0x110:0xd503201f,0x114:0x14000002,
               0x118:0xf104005f,0x11c:0x54000062,0x120:0xf8627823,
               0x124:0x14000000,0x128:0x14000000}
        self.assertNotIn(0x120,self.prove(words)['proofs'])
        words[0x114]=0x14000001 # Both paths execute the compare.
        self.assertEqual(self.prove(words)['proofs'][0x120]['bounds'],[BASE,BASE+255*8])
        adapted=analyze(words,self.initial,self.package,self.aliases,[],adapted_pcs={0x118})
        self.assertNotIn(0x120,adapted['proofs'])

    def test_mutable_pointer_load_permissions_bounds_and_spill_alias(self):
        struct.pack_into('<Q',self.package.memory,0,BASE+4096)
        words={0x100:0xf9400021,0x104:0xf9400023,0x108:0x14000000}
        self.assertNotIn(0x104,self.prove(words)['proofs'])
        self.assertIn(0x104,self.prove(words,[(0x40000000,4096)])['proofs'])
        self.words[0x108]=0xf8227823 # indexed STR
        self.assertIn(0x108,self.prove()['proofs'])
        self.aliases[1]['attrs']=128
        self.assertNotIn(0x108,self.prove()['proofs'])
        self.aliases[1]['attrs']=0;self.aliases[1]['bytes']=1024
        self.assertNotIn(0x108,self.prove()['proofs'])
        self.aliases[1]['bytes']=8192;self.aliases[0]['pa']=0x40000000
        self.initial[31]=0x9400
        self.assertEqual(self.prove()['rejected'][0x108],'payload may alias native scratch spill')

    def test_finite_jump_table_facts_survive_interval_analysis(self):
        self.initial[6]=BASE;self.initial[8]=0x2000;self.initial[32]=0xffc
        for i in range(16):struct.pack_into('<i',self.package.memory,4*i,0x100 if i&1 else 0)
        words={0xffc:0xd4000001,0x1000:0x92400c05,0x1004:0xb8a578d1,
               0x1008:0x8b110108,0x100c:0xd61f0100,
               0x2000:0xf9400023,0x2004:0x14000000,0x2100:0xf9400023,0x2104:0x14000000}
        result=self.prove(words,[(0x40000000,4096)])
        self.assertTrue({0x2000,0x2100}.issubset(result['proofs']))
        self.assertFalse({0x2000,0x2100}&self.prove(words)['proofs'].keys())


@unittest.skipUnless(CC.exists() and QEMU,'cross compiler and QEMU required')
class Execution(unittest.TestCase):
    setUp=Proofs.setUp
    prove=Proofs.prove
    def test_live_index_load_store_with_unmapped_logical_base(self):
        proof=self.prove()['proofs'][0x108]
        load=access_path(0x108,decode(0xf8627823),proof,0x40000000,'loaded')
        self.words[0x108]=0xf8227823
        store=access_path(0x108,decode(0xf8227823),self.prove()['proofs'][0x108],0x40000000,'stored')
        self.assertNotIn('cmp ',load+store)
        source='''.text
.global _start
_start:
    adrp x0,stack_end
    add x0,x0,:lo12:stack_end
    mov sp,x0
    mov x0,#255
    msr mair_el1,x0
    adrp x0,tables
    msr ttbr0_el1,x0
    mov x0,#0x3510
    msr tcr_el1,x0
    adrp x0,vectors
    msr vbar_el1,x0
    dsb sy
    isb
    mrs x0,sctlr_el1
    bic x0,x0,#2
    orr x0,x0,#1
    msr sctlr_el1,x0
    isb
    mov x1,#0x7000
    movk x1,#0xc39f,lsl #16
    movk x1,#0xffff,lsl #32
    mov x2,#0
    mov x16,#0x1616
    mov x17,#0x1717
    adrp x10,flat_phys
    add x10,x10,:lo12:flat_phys
loop:
    mov x3,x2
    lsl x11,x2,#28
    msr nzcv,x11
    mrs x11,nzcv
''' + store + '''stored:
    mrs x12,nzcv
    cmp x11,x12
    b.ne failed
    ldr x12,[x10,x2,lsl #3]
    cmp x12,x2
    b.ne failed
    mov x3,#0xffff
    msr nzcv,x11
''' + load + '''loaded:
    mrs x12,nzcv
    cmp x11,x12
    b.ne failed
    cmp x3,x2
    b.ne failed
    mov x12,#0x1616
    cmp x16,x12
    b.ne failed
    mov x12,#0x1717
    cmp x17,x12
    b.ne failed
    add x2,x2,#1
    cmp x2,#256
    b.ne loop
    mov x2,#0
    b finish
failed: mov x2,#1
finish:
    adrp x1,exit_status
    add x1,x1,:lo12:exit_status
    str x2,[x1,#8]
    mov x0,#0x20
    hlt #0xf000
.balign 2048
vectors:
.rept 16
    b failed
    .balign 128
.endr
.data
.balign 4096
tables: .quad level1+3
.space 4088
level1: .quad 0,0x40000701
.space 4080
exit_status: .quad 0x20026,1
.bss
.balign 4096
flat_phys: .space 12288
stack: .space 4096
stack_end:
'''
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'fixture.S').write_text(source)
            built=subprocess.run([str(CC),'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib',
                '-Wl,-Ttext=0x40200000,-e,_start',str(root/'fixture.S'),'-o',str(root/'checkpoint')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            ran=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                '-nodefaults','-display','none','-monitor','none','-serial','none','-semihosting-config','enable=on,target=native',
                '-device','loader,file='+str(root/'checkpoint')+',cpu-num=0'],capture_output=True,text=True,timeout=30)
            self.assertEqual(ran.returncode,0,ran.stderr)


@unittest.skipUnless(os.environ.get('OSREC_DATAFLOW_IMAGE'),'set OSREC_DATAFLOW_IMAGE for linked negative audits')
class LinkedAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from el0_pointer_flow import report_image
        cls.image=Path(os.environ['OSREC_DATAFLOW_IMAGE']).resolve()
        manifest=json.loads((cls.image/'manifest.json').read_text())
        cls.proofs=report_image(cls.image,version=manifest.get('dataflow_analysis_version',1))

    def test_changed_proof_is_rejected(self):
        from el0_pointer_flow import verify_compiled
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ('manifest.json','compact-loads.json'):(root/name).symlink_to(self.image/name)
            report=json.loads((self.image/'dataflow-memory.json').read_text())
            report['sites'][0]['bounds'][0]+=1
            (root/'dataflow-memory.json').write_text(json.dumps(report))
            with patch('el0_pointer_flow.report_image',return_value=self.proofs),patch('el0_compact_access.verify_compiled'):
                with self.assertRaisesRegex(ValueError,'differ from reconstructed proofs'):verify_compiled(root)

    def test_changed_linked_instruction_is_rejected(self):
        from el0_pointer_flow import verify_compiled
        from kernel_source_verify import Elf
        image=self.image
        class CorruptedElf(Elf):
            def __init__(self,path):
                super().__init__(path);self.corrupt=Path(path).resolve()==image/'checkpoint'
            def read(self,address,size):
                data=super().read(address,size)
                return bytes([data[0]^1])+data[1:] if self.corrupt and data else data
        # Reuse the separately reconstructed facts; only the ELF instruction
        # bytes change. The existing singleton-load verifier has its own tests.
        with patch('el0_pointer_flow.report_image',return_value=self.proofs),patch('el0_compact_access.verify_compiled'),patch('kernel_source_verify.Elf',CorruptedElf):
            with self.assertRaisesRegex(ValueError,'linked dataflow rewrite mismatch'):verify_compiled(image)
