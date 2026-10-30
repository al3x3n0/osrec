"""Constant index proofs retain C arithmetic, effects and storage checks."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
import test_entry_state_ranges as fixture
from entry_state import Analyzer,capture_header,load_ast
from entry_state_program import load_program

CLANG=fixture.CLANG
MODEL='struct State { unsigned values[8]; }; struct State *current(void);\n'
POLICY=fixture.POLICY


class ConstantIndexTests(unittest.TestCase):
    def parse(self,stage,source):
        path=stage/'input.c';path.write_text(MODEL+source)
        database=stage/'compile_commands.json';database.write_text(json.dumps([{
            'directory':str(stage),'file':str(path),'arguments':[CLANG,'-std=c11','-Wno-array-bounds',
            '-Wno-division-by-zero','-Wno-shift-count-overflow','-c',str(path),'-o','input.o']}]))
        return load_ast(database,path)[0]

    def test_pure_constants_enums_and_global_storage(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            expressions={'enum':'SLOT','successor':'NEXT','arithmetic':'(2U*3U)-1U',
                'shift':'(1U<<3)-3U','division':'17/3','remainder':'17%6',
                'negative_division':'(-17/3)+10','mask':'13U&(3U+4U)','complement':'(~0U>>29)-2U'}
            for case,expression in expressions.items():
                with self.subTest(case=case):
                    tree=self.parse(stage,'enum { SLOT=5, BEFORE=4, NEXT };\nunsigned query(void){return current()->values['+expression+'];}')
                    plan=Analyzer(tree,POLICY).analyze('query')
                    self.assertFalse(plan['blockers'],plan['blockers'])
                    self.assertEqual([r['path'] for r in plan['entry_reads']],['current()->values[5]'])
                    self.assertEqual(plan['memory_ranges'][0]['index_proof']['kind'],'integer_constant_expression')
                    capture_header([plan])
            tree=self.parse(stage,'enum { SLOT=2 };unsigned values[8];\nvoid update(void){values[SLOT+3]=42;}')
            plan=Analyzer(tree).analyze('update');self.assertFalse(plan['blockers'])
            self.assertEqual([r['path'] for r in plan['state_writes']],['global:values[5]'])

    def test_constant_operands_keep_runtime_effects_and_range_limits(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),'''enum { WIDTH=1U<<3, MASK=(1U<<3)-1U };
unsigned count;
unsigned remainder(void){return current()->values[count++ % WIDTH];}
unsigned mask(unsigned i){return current()->values[i & MASK];}
unsigned call(void){extern unsigned unknown(void);return current()->values[unknown() & MASK];}
unsigned large(unsigned i){return current()->values[i & ((1U<<4)-1U)];}
''')
            for root,kind in [('remainder','unsigned_constant_remainder'),('mask','unsigned_constant_mask')]:
                plan=Analyzer(tree,POLICY).analyze(root);self.assertFalse(plan['blockers'],plan['blockers'])
                self.assertEqual(plan['memory_ranges'][0]['index_bounds'],[0,7])
                self.assertEqual(plan['memory_ranges'][0]['index_proof']['kind'],kind)
                self.assertTrue({f'current()->values[{i}]' for i in range(8)}<={r['path'] for r in plan['entry_reads']})
            remainder=Analyzer(tree,POLICY).analyze('remainder')
            self.assertEqual([r['path'] for r in remainder['state_writes']],['global:count'])
            self.assertIn('global:count',{r['path'] for r in remainder['entry_reads']})
            self.assertIn('unmodeled_external',{b['kind'] for b in Analyzer(tree,POLICY).analyze('call')['blockers']})
            self.assertIn('array_bounds',{b['kind'] for b in Analyzer(tree,POLICY).analyze('large')['blockers']})
            self.assertIn('range_limit',{b['kind'] for b in Analyzer(tree,POLICY,max_range_elements=4).analyze('mask')['blockers']})

    def test_invalid_constants_and_pointer_extents_remain_blocked(self):
        expressions={'wrapped':'0xffffffffU+6U','overflow':'2147483647+6','zero_division':'5U/0U',
            'bad_shift':'1U<<32','negative_shift':'(-1<<3)+13','signed_bitwise':'(-1&7)-2',
            'explicit_cast':'(unsigned char)261','wide':'5ULL+0ULL',
            'variable':'index','const_variable':'fixed','assignment':'(index=5)',
            'budget':'0U+'*40+'5U',
            'outside':'4U+4U','negative':'2-3','signed_modulo':'signed_index % WIDTH'}
        with tempfile.TemporaryDirectory() as name:
            for case,expression in expressions.items():
                with self.subTest(case=case):
                    tree=self.parse(Path(name),'enum{WIDTH=8};unsigned index;int signed_index;const unsigned fixed=5;\nunsigned query(void){return current()->values['+expression+'];}')
                    plan=Analyzer(tree,POLICY).analyze('query');self.assertTrue(plan['blockers'])
                    with self.assertRaises(ValueError):capture_header([plan])
            tree=self.parse(Path(name),'''enum { SLOT=5 }; unsigned *pointer;
unsigned cast(void){return ((unsigned *)current()->values)[SLOT];}
unsigned alias(void){return pointer[SLOT];}
''')
            for root in ('cast','alias'):
                self.assertIn('dynamic_extent',{b['kind'] for b in Analyzer(tree,POLICY).analyze(root)['blockers']})

    def test_enum_identity_across_translation_units_and_generated_capture(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);entries=[];files=[]
            for filename,index in [('root.c',1),('helper.c',5)]:
                path=stage/filename;files.append(path)
                text=MODEL+'enum { SLOT='+str(index)+' };\n'
                text+=('unsigned helper(void); unsigned query(void){return current()->values[SLOT]+helper();}' if index==1 else
                       'unsigned helper(void){return current()->values[SLOT];}')
                path.write_text(text);entries.append({'directory':str(stage),'file':str(path),
                    'arguments':[CLANG,'-std=c11','-c',str(path),'-o',filename+'.o']})
            database=stage/'compile_commands.json';database.write_text(json.dumps(entries))
            tree,_=load_program(database,files[0],all_sources=True)
            analyzer=Analyzer(tree,POLICY);plan=analyzer.analyze('query');self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'current()->values[1]','current()->values[5]'})
            self.assertEqual(plan,analyzer.fresh().analyze('query'))
            (stage/'capture.h').write_text(capture_header([plan]))
            runner=stage/'runner.c';runner.write_text(MODEL+'''
#include "capture.h"
static struct State state={{0,11,0,0,0,55,0,0}};
struct State *current(void){return &state;}
int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);
 if(!osrec_snapshot_query(&s)||s.field_count!=2) return 1;
 return s.fields[0].bytes[0]!=11 || s.fields[1].bytes[0]!=55;}
''')
            binary=stage/'runner'
            subprocess.run([CLANG,'-std=c11','-I',str(ROOT/'include'),str(runner),
                str(ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True,timeout=60)
            subprocess.run([binary],check=True,timeout=10)

    def test_native_capture_to_aarch64_with_enum_index_bounds(self):
        functions='''enum { WIDTH=1U<<3, BYTE_MASK=(1U<<4)-1U };
unsigned lookup(void){return current()->values[current()->index % WIDTH];}
unsigned byte_lookup(void){return current()->bytes[current()->index & BYTE_MASK];}
'''
        with patch.object(fixture,'FUNCTIONS',functions):
            fixture.RangeTests().test_native_capture_to_aarch64_elf_and_raw()


if __name__=='__main__':
    if len(sys.argv)==4:
        CLANG=sys.argv[1];fixture.CLANG=CLANG;fixture.LLVM=Path(sys.argv[2]);fixture.QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
