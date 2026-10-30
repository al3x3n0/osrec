"""Private fixed arrays are execution state, with persistent/effect cases blocked."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_entry_state_global_arrays as host
import test_entry_state_ranges as native
from entry_state import Analyzer,capture_header
from entry_state_program import merge_translation_units


class AutomaticArrayTests(unittest.TestCase):
    def parse(self,stage,text):
        return host.GlobalArrayTests().parse(stage,{'input.c':native.MODEL+text})

    def test_private_initializers_reads_and_writes_keep_external_inputs(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),'''unsigned query(unsigned index){
 unsigned values[8]={current()->index};values[7]=index;values[6]+=1;
 return values[index%8U];}
unsigned text(void){const char local[4]="abc";return local[0];}
unsigned record(void){struct Item{unsigned value;};struct Item local[2]={{current()->index},{7}};
 local[1].value+=1;return local[0].value;}
''')
            for root in ('query','record'):
                plan=Analyzer(tree,native.POLICY).analyze(root)
                self.assertFalse(plan['blockers'],plan['blockers'])
                self.assertEqual({r['path'] for r in plan['entry_reads']},{'current()->index'})
                self.assertFalse(plan['state_writes'])
                self.assertTrue(any(r['bound_source']=='configured Clang automatic-array type' for r in plan['memory_ranges']))
                capture_header([plan])
            text=Analyzer(tree).analyze('text');self.assertFalse(text['blockers'])
            self.assertFalse(text['entry_reads']);self.assertFalse(text['state_writes'])

    def test_local_bounds_and_element_limits_are_still_checked(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),'''unsigned outside(void){unsigned local[2]={0};return local[2];}
unsigned unknown(unsigned i){unsigned local[8]={0};return local[i];}
unsigned bounded(unsigned i){unsigned local[8]={0};return local[i&7U];}
unsigned loop(void){unsigned local[8]={0};for(unsigned i=0;i<8;++i)local[i]=i;return local[7];}
''')
            for root,kind in [('outside','array_bounds'),('unknown','dynamic_extent')]:
                plan=Analyzer(tree).analyze(root)
                self.assertIn(kind,{b['kind'] for b in plan['blockers']})
                with self.assertRaises(ValueError):capture_header([plan])
            self.assertFalse(Analyzer(tree).analyze('loop')['blockers'])
            self.assertIn('range_limit',{b['kind'] for b in Analyzer(tree,max_range_elements=4).analyze('bounded')['blockers']})

    def test_persistent_volatile_cleanup_and_pointer_accesses_remain_blocked(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),'''unsigned persistent(void){static unsigned local[2];return ++local[0];}
unsigned device(void){volatile unsigned local[2]={0};return local[0];}
typedef volatile unsigned DeviceWord;
unsigned typedef_device(void){DeviceWord local[2]={0};return local[0];}
typedef _Atomic(unsigned) AtomicWord;
unsigned typedef_atomic(void){AtomicWord local[2]={0};return local[0];}
unsigned volatile_member(void){struct Item{volatile unsigned value;};struct Item local[2]={{0},{0}};return local[0].value;}
void cleanup(unsigned (*value)[2]);
unsigned cleaned(void){unsigned local[2] __attribute__((cleanup(cleanup)))={0};return local[0];}
unsigned alias(void){unsigned local[2]={0};unsigned *p=local;return p[0];}
unsigned parameter(unsigned local[2]){return local[0];}
unsigned pointer(void){State *local[2]={current(),current()};return local[0]->index;}
unsigned indirect_read(unsigned *p){return *p;}
unsigned escaped(void){unsigned local[2]={0};return indirect_read(local);}
unsigned initializer(void){extern unsigned unknown(void);unsigned local[2]={unknown()};return local[0];}
''')
            for root in ('persistent','device','typedef_device','typedef_atomic','volatile_member',
                         'cleaned','parameter','pointer','initializer'):
                with self.subTest(root=root):
                    plan=Analyzer(tree,native.POLICY).analyze(root);self.assertTrue(plan['blockers'])
                    with self.assertRaises(ValueError):capture_header([plan])
            for root in ('alias','escaped'):
                plan=Analyzer(tree,native.POLICY).analyze(root);self.assertFalse(plan['blockers'],plan['blockers'])
                self.assertFalse(plan['entry_reads']);capture_header([plan])
            plan=Analyzer(tree,native.POLICY).analyze('initializer')
            self.assertIn('unmodeled_external',{b['kind'] for b in plan['blockers']})

    def test_multidimensional_member_types_cannot_use_the_last_extent(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),'''struct Matrix {unsigned values[2][4];};struct Matrix *matrix(void);
unsigned invalid(void){return *matrix()->values[3];}
unsigned valid(void){return matrix()->values[1][2];}
''')
            policy={'matrix':{**native.POLICY['current'],'implementation':'fixture matrix binding'}}
            plan=Analyzer(tree,policy).analyze('invalid')
            self.assertIn('array_bounds',{b['kind'] for b in plan['blockers']})
            self.assertFalse(plan['memory_ranges'])
            plan=Analyzer(tree,policy).analyze('valid')
            self.assertFalse(plan['blockers']);self.assertEqual({r['path'] for r in plan['entry_reads']},{'matrix()->values[1][2]'})
            capture_header([plan])

    def test_fresh_analysis_keeps_local_names_separate_from_globals(self):
        with tempfile.TemporaryDirectory() as name:
            tree=host.GlobalArrayTests().parse(Path(name),{
                'root.c':'unsigned values[2];unsigned helper(void);unsigned query(void){unsigned values[2]={1,2};return values[1]+helper();}',
                'helper.c':'static unsigned values[2];unsigned helper(void){return values[1];}'})
            analyzer=Analyzer(tree);plan=analyzer.analyze('query');self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'global:tu1:values[1]'})
            self.assertEqual(plan,analyzer.fresh().analyze('query'))

    def test_partial_initializer_calls_survive_function_reference_slicing(self):
        from entry_state import load_ast
        import json
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);files=[];entries=[]
            for filename,text in {
                'root.c':'unsigned helper(void);unsigned query(void){unsigned local[4]={helper()};return local[0];}',
                'helper.c':'unsigned state;unsigned helper(void){return state++;}'}.items():
                path=stage/filename;path.write_text(text);files.append(path)
                entries.append({'directory':str(stage),'file':str(path),
                    'arguments':[host.CLANG,'-std=c11','-c',str(path),'-o',filename+'.o']})
            database=stage/'compile_commands.json';database.write_text(json.dumps(entries))
            tree,program=merge_translation_units([load_ast(database,p) for p in files],roots=['query'])
            self.assertIn('helper',program['function_slice']['retained_function_names'])
            plan=Analyzer(tree).analyze('query');self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'global:state'})
            self.assertEqual({r['path'] for r in plan['state_writes']},{'global:state'})
            self.assertEqual({r['callee'] for r in plan['call_sites']},{'helper'})

    def test_native_capture_to_aarch64_with_private_scratch_arrays(self):
        functions='''unsigned lookup(void){unsigned scratch[2]={0};scratch[1]=current()->index;
return current()->values[scratch[1]%8U];}
unsigned byte_lookup(void){unsigned scratch[2]={current()->index};
return current()->bytes[scratch[0]&15U];}
'''
        with patch.object(native,'FUNCTIONS',functions):
            native.RangeTests().test_native_capture_to_aarch64_elf_and_raw()


if __name__=='__main__':
    if len(sys.argv)==4:
        host.CLANG=sys.argv[1];native.CLANG=sys.argv[1];native.LLVM=Path(sys.argv[2]);native.QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
