"""Configured global storage bounds must not become pointer contracts."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,capture_header,load_ast
from entry_state_program import load_program

CLANG='/opt/homebrew/opt/llvm@16/bin/clang'


class GlobalArrayTests(unittest.TestCase):
    def parse(self,stage,texts):
        entries=[];files=[]
        for name,text in texts.items():
            source=stage/name;source.write_text(text);files.append(source)
            entries.append({'directory':str(stage),'file':str(source),
                'arguments':[CLANG,'-std=c11','-Wno-array-bounds','-c',str(source),'-o',name+'.o']})
        database=stage/'compile_commands.json';database.write_text(json.dumps(entries))
        if len(files)==1:return load_ast(database,files[0])[0]
        return load_program(database,files[0],all_sources=True)[0]

    def test_reads_writes_records_and_storage_qualifiers(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),{'root.c':'''typedef unsigned Values[8];
Values values; extern unsigned external[3];
static const unsigned constants[2]={11,22};
struct Item { unsigned count; }; static struct Item items[2];
volatile unsigned device[2];
unsigned read(unsigned index){return values[index % 8U]+external[2]+constants[1]+items[0].count;}
void write(void){values[7]=19;items[1].count=4;}
unsigned mmio(void){return device[0];}
'''})
            plan=Analyzer(tree).analyze('read')
            self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},
                {f'global:values[{i}]' for i in range(8)}|
                {'global:external[2]','global:constants[1]','global:items[0].count'})
            self.assertTrue(all(r['bound_source']=='configured Clang global-array type' for r in plan['memory_ranges']))
            # Discovering storage does not supply a capture/replay binding.
            with self.assertRaisesRegex(ValueError,'provider field paths'):capture_header([plan])
            writes=Analyzer(tree).analyze('write')
            self.assertFalse(writes['blockers'])
            self.assertEqual({r['path'] for r in writes['state_writes']},{'global:values[7]','global:items[1].count'})
            with self.assertRaisesRegex(ValueError,'provider field paths'):
                capture_header([{**writes,'entry_reads':writes['state_writes']}])
            mmio=Analyzer(tree).analyze('mmio')
            self.assertIn('volatile_memory',{b['kind'] for b in mmio['blockers']})

    def test_counted_loop_bounds_and_element_limit(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),{'root.c':'''unsigned values[8];
unsigned sum(void){unsigned total=0;for(unsigned i=0;i<8;++i)total+=values[i];return total;}
void fill(void){for(unsigned i=1;i<=3;++i)values[2*i]=i;}
'''})
            plan=Analyzer(tree).analyze('sum')
            self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},{f'global:values[{i}]' for i in range(8)})
            self.assertEqual(plan['memory_ranges'][0]['index_proof']['kind'],'canonical_for_induction')
            fill=Analyzer(tree).analyze('fill');self.assertFalse(fill['blockers'])
            self.assertEqual({r['path'] for r in fill['state_writes']},{f'global:values[{i}]' for i in range(2,7)})
            limited=Analyzer(tree,max_range_elements=4).analyze('sum')
            self.assertIn('range_limit',{b['kind'] for b in limited['blockers']})

    def test_unknown_extents_casts_and_unproven_indexes_remain_blocked(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),{'root.c':'''unsigned values[8]; unsigned *pointer=values;
extern unsigned incomplete[]; unsigned matrix[2][3];
unsigned unknown(unsigned i){return values[i];}
unsigned negative(void){return values[-1];}
unsigned outside(void){return values[8];}
unsigned casted(void){return ((unsigned char *)values)[0];}
unsigned alias(void){return pointer[0];}
unsigned parameter(unsigned values[8]){return values[0];}
unsigned missing(void){return incomplete[0];}
unsigned truncated(void){return values[(unsigned char)257];}
unsigned signed_mod(int i){return values[i%8];}
unsigned multidimensional(void){return matrix[0][2];}
unsigned automatic(void){unsigned values[8]={0};return values[0];}
unsigned static_local(void){static unsigned values[8];return values[0];}
'''})
            for root in ('unknown','negative','outside','casted','alias','parameter','missing',
                         'truncated','signed_mod','static_local'):
                with self.subTest(root=root):
                    plan=Analyzer(tree).analyze(root)
                    self.assertTrue(plan['blockers'])
                    with self.assertRaises(ValueError):capture_header([plan])
            automatic=Analyzer(tree).analyze('automatic')
            self.assertFalse(automatic['blockers']);self.assertFalse(automatic['entry_reads'])
            matrix=Analyzer(tree).analyze('multidimensional')
            self.assertFalse(matrix['blockers']);self.assertEqual({r['path'] for r in matrix['entry_reads']},{'global:matrix[0][2]'})
            with self.assertRaises(ValueError):capture_header([matrix])

    def test_translation_unit_static_identity_and_external_reference(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),{
                'root.c':'''static unsigned values[2];extern unsigned shared[3];unsigned helper(void);
unsigned root(void){return values[0]+shared[1]+helper();}''',
                'helper.c':'''static unsigned values[4];unsigned shared[3];
unsigned helper(void){return values[3]+shared[2];}'''})
            analyzer=Analyzer(tree);plan=analyzer.analyze('root')
            self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},
                {'global:tu0:values[0]','global:tu1:values[3]','global:shared[1]','global:shared[2]'})
            self.assertEqual(plan,analyzer.fresh().analyze('root'))
            self.assertEqual(plan,Analyzer(tree).analyze('root'))


if __name__=='__main__':
    if len(sys.argv)==2:CLANG=sys.argv.pop()
    unittest.main()
