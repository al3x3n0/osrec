"""Architectural cases used by the complete-checkpoint native lowering."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from el0_flat_lower import decode,atomic_group,MEMORY,STACK,SYSTEM,SVC,UNSUPPORTED,LOAD,WB,POST,REGISTER,SRC_SP,DST_SP
from export_el0_program import local_conditional

class Lower(unittest.TestCase):
    def test_unsigned_load_keeps_destination_and_redirects_only_address(self):
        o=decode(0xf9400820) # ldr x0,[x1,#16]
        self.assertEqual((o.kind,o.imm,o.info&31),(MEMORY,16,1))
        self.assertTrue(o.info&LOAD)
        self.assertEqual(o.native&31,0)
        self.assertEqual(o.native>>10&4095,0)
        self.assertNotIn(o.native>>5&31,(0,1,31))

    def test_pre_index_store_virtualizes_sp_writeback(self):
        o=decode(0xf81f0ff0) # str x16,[sp,#-16]!
        self.assertEqual((o.kind,o.imm,o.info&31),(MEMORY,-16,31))
        self.assertTrue(o.info&WB);self.assertFalse(o.info&POST)
        self.assertFalse(o.info&LOAD)
        self.assertEqual(o.native&31,16)
        self.assertEqual(o.native>>10&3,0)
        self.assertNotEqual(o.native>>5&31,16)

    def test_pair_post_index_restores_base_after_native_load(self):
        o=decode(0xa8c10be1) # ldp x1,x2,[sp],#16
        self.assertEqual((o.kind,o.imm,o.info&31),(MEMORY,16,31))
        self.assertTrue(o.info&POST and o.info&WB and o.info&LOAD)
        self.assertEqual((o.native&31,o.native>>10&31),(1,2))
        self.assertEqual(o.native>>23&3,2)

    def test_vector_load_size_and_register_offset(self):
        o=decode(0x3dc00020) # ldr q0,[x1]
        self.assertEqual(o.kind,MEMORY);self.assertEqual(o.info>>15&7,4)
        o=decode(0xb862d820) # ldr w0,[x1,w2,sxtw #2]
        self.assertTrue(o.info&REGISTER)
        self.assertEqual((o.info>>5&31,o.info>>24&7,o.info>>27&7),(2,6,2))
        self.assertEqual(o.native>>10&3,0)

    def test_stack_arithmetic_preserves_flags_and_other_registers(self):
        o=decode(0xd10043ff) # sub sp,sp,#16
        self.assertEqual(o.kind,STACK);self.assertTrue(o.info&SRC_SP and o.info&DST_SP)
        self.assertEqual(o.native&31,o.native>>5&31)
        self.assertEqual(o.native&~(31|(31<<5)),o.word&~(31|(31<<5)))
        o=decode(0x910003e0) # mov x0,sp
        self.assertTrue(o.info&SRC_SP);self.assertFalse(o.info&DST_SP)
        self.assertEqual(o.native&31,0)

    def test_privilege_and_unknown_memory_do_not_pass_through(self):
        self.assertEqual(decode(0xd5384240).kind,SYSTEM) # CurrentEL
        self.assertEqual(decode(0xd69f03e0).kind,SYSTEM) # ERET
        self.assertEqual(decode(0xd4000001).kind,SVC)
        self.assertEqual(decode(0x4c407020).kind,UNSUPPORTED) # ld1 {v0.16b},[x1]

    def test_exclusive_window_has_no_adaptation_between_load_and_store(self):
        words={0x1000:0x885f7d0b,0x1004:0x880afd09} # ldxr w11,[x8]; stlxr w10,w9,[x8]
        o,body=atomic_group(words,0x1000)
        self.assertEqual(o.length,2)
        temp=o.info>>10&31;self.assertNotIn(temp,(8,9,10,11))
        for original,native in zip(words.values(),body):
            self.assertEqual(native>>5&31,temp)
            self.assertEqual(native&~(31<<5),original&~(31<<5))
        words[0x1004]=0xd4000001
        self.assertIsNone(atomic_group(words,0x1000))

    def test_local_exclusive_branches_preserve_test_operands(self):
        self.assertEqual(local_conditional(0xb500000c,'.Lexit'),'    cbnz x12,.Lexit\n')
        self.assertEqual(local_conditional(0x3500000b,'.Lexit'),'    cbnz w11,.Lexit\n')
        self.assertEqual(local_conditional(0xb7f80000,'.Lexit'),'    tbnz x0,#63,.Lexit\n')
        self.assertEqual(local_conditional(0x54000001,'.Lexit'),'    b.ne .Lexit\n')

    def test_pair_exclusive_cas_keeps_both_data_registers_and_comparison(self):
        from el0_flat_lower import PAIR,EXCLUSIVE
        body=[0xc87f0480,0xeb16001f,0xfa480020,0x54000061,0xc8290c82]
        o,native=atomic_group({0x1000+4*i:w for i,w in enumerate(body)},0x1000)
        self.assertEqual(o.length,5);self.assertTrue(o.info&PAIR and o.info&EXCLUSIVE)
        self.assertEqual(o.info>>15&7,3)
        self.assertEqual(native[1:4],body[1:4])
        self.assertNotIn(o.info>>10&31,(0,1,2,3,4,8,9,22))
        self.assertEqual(native[0]&~(31<<5),body[0]&~(31<<5))
        self.assertEqual(native[4]&~(31<<5),body[4]&~(31<<5))

if __name__=='__main__':unittest.main()
