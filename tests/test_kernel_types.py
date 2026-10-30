"""DWARF type tables and source/binary layout correspondence."""
import json,shutil,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from kernel_btf import resolve
from kernel_dwarf import DWARF
from layout_correspondence import correspond

LITEOS=ROOT/'build/ohos/out/liteos';DATABASE=ROOT/'build/whole-kernel-discovery-v2/compile_commands.json'
DWARFDUMP=Path('/opt/homebrew/opt/llvm@22/bin/llvm-dwarfdump')

def unit(base,name,other_size):
    """One llvm-dwarfdump compile unit; `other_size` lets two units disagree on struct other."""
    o=lambda n:'0x%08x'%(base+n)
    return f'''{o(0)}: Compile Unit: length = 0x00000100, format = DWARF32, version = 0x0002, abbr_offset = 0x0000, addr_size = 0x04 (next unit at {o(0x100)})

{o(0)}: DW_TAG_compile_unit
              DW_AT_name\t("{name}")
              DW_AT_comp_dir\t("/src")

{o(0x10)}:   DW_TAG_base_type
                DW_AT_name\t("int")
                DW_AT_byte_size\t(0x04)

{o(0x20)}:   DW_TAG_structure_type
                DW_AT_name\t("inner")
                DW_AT_byte_size\t(0x08)

{o(0x30)}:     DW_TAG_member
                  DW_AT_name\t("b")
                  DW_AT_type\t({o(0x10)} "int")
                  DW_AT_data_member_location\t(DW_OP_plus_uconst 0x0)

{o(0x40)}:     DW_TAG_member
                  DW_AT_name\t("flag")
                  DW_AT_type\t({o(0x10)} "int")
                  DW_AT_bit_size\t(0x01)
                  DW_AT_bit_offset\t(0x1f)
                  DW_AT_data_member_location\t(DW_OP_plus_uconst 0x4)

{o(0x48)}:     NULL

{o(0x50)}:   DW_TAG_pointer_type
                DW_AT_type\t({o(0x20)} "inner")

{o(0x60)}:   DW_TAG_structure_type
                DW_AT_byte_size\t(0x0c)

{o(0x70)}:     DW_TAG_member
                  DW_AT_name\t("a")
                  DW_AT_type\t({o(0x10)} "int")
                  DW_AT_data_member_location\t(DW_OP_plus_uconst 0x0)

{o(0x80)}:     DW_TAG_member
                  DW_AT_name\t("p")
                  DW_AT_type\t({o(0x50)} "inner *")
                  DW_AT_data_member_location\t(DW_OP_plus_uconst 0x4)

{o(0x90)}:     DW_TAG_member
                  DW_AT_name\t("arr")
                  DW_AT_type\t({o(0xb0)} "int[1]")
                  DW_AT_data_member_location\t(DW_OP_plus_uconst 0x8)

{o(0xa0)}:     NULL

{o(0xa8)}:   DW_TAG_typedef
                DW_AT_type\t({o(0x60)} "struct {{...}}")
                DW_AT_name\t("Outer")

{o(0xb0)}:   DW_TAG_array_type
                DW_AT_type\t({o(0x10)} "int")

{o(0xb8)}:     DW_TAG_subrange_type
                  DW_AT_upper_bound\t(0x00)

{o(0xc0)}:     NULL

{o(0xc8)}:   DW_TAG_structure_type
                DW_AT_name\t("other")
                DW_AT_byte_size\t({other_size:#04x})

{o(0xd0)}:     DW_TAG_member
                  DW_AT_name\t("x")
                  DW_AT_type\t({o(0x10)} "int")
                  DW_AT_data_member_location\t(DW_OP_plus_uconst 0x0)

{o(0xd8)}:     NULL

{o(0xe0)}:   NULL
'''

class DwarfTests(unittest.TestCase):
    def table(self,second_other=4):return DWARF(None,text=unit(0x0b,'a.c',4)+'\n'+unit(0x20b,'b.c',second_other))
    def test_records_typedef_names_bitfields_and_unit_merging(self):
        d=self.table()
        self.assertEqual(d.pointer_bytes,4);self.assertEqual(len(d.records['inner']),1)
        outer=d.struct('Outer');self.assertEqual(d.sizeof(outer),12)
        self.assertEqual([(m[0],m[2]//8) for m in d.types[outer]['members']],[('a',0),('p',4),('arr',8)])
        with self.assertRaisesRegex(ValueError,'bitfield'):d.member(d.struct('inner'),'flag')
        self.assertEqual(d.unit_source(0x0b),'/src/a.c');self.assertEqual({r[0] for r in d.unit_records(0x20b)},{'inner','Outer','other'})
        with self.assertRaisesRegex(ValueError,'not unique'):self.table(second_other=8).struct('other')
    def test_paths_use_thirty_two_bit_pointers(self):
        d=self.table();cells={0x100:5,0x104:0x200,0x108:9,0x200:7}
        def read(address,size):
            if size!=4:raise AssertionError('64-bit read on a 32-bit table')
            return cells.get(address,0)
        get=lambda path:(lambda p:read(p[0],d.scalar(p[1])))(resolve(d,read,0x100,'Outer',path))
        self.assertEqual([get('.a'),get('.p->b'),get('.arr[0]')],[5,7,9])

@unittest.skipUnless(LITEOS.exists() and DATABASE.exists() and DWARFDUMP.exists() and shutil.which('/opt/homebrew/opt/llvm@16/bin/clang'),'LiteOS build, compile database and LLVM required')
class LiteOsLayoutTests(unittest.TestCase):
    def test_source_layout_matches_binary_and_packing_is_detected(self):
        units=r'kernel/base/core/los_(task|process)\.c$'
        r=correspond(LITEOS,DATABASE,DWARFDUMP,2,(),units)
        self.assertEqual((r['units_checked'],r['counts']['match']),(2,2));self.assertGreater(r['checks'],500)
        r=correspond(LITEOS,DATABASE,DWARFDUMP,2,('-fpack-struct=1',),units)
        self.assertEqual(r['counts']['mismatch'],2);self.assertIn('ProcessCB',r['mismatching_records'])

if __name__=='__main__':unittest.main()
