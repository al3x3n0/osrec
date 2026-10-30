"""Only visibly defined numeric const scalars are fixed program data."""
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import test_entry_state as basic
import test_entry_state_local_effects as local_effects
from entry_state import Analyzer,capture_header,entry_accesses,walk
from automated_entry_state import validate_snapshot


class ConstantGlobalTests(unittest.TestCase):
    def parse(self,stage,body):return basic.EntryStateTests().parse(stage,body)[0]

    def test_const_numeric_definitions_retain_reads_and_checked_evidence(self):
        body='''static const double scale=1.0/2.0,offset=-3.0;const unsigned mask=(1u<<4)-1;
double root(double x){return scale*x+offset+mask;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body)).analyze('root');self.assertFalse(p['blockers'])
            self.assertEqual({r['path'] for r in p['entry_reads']},{'global:scale','global:offset','global:mask'})
            self.assertTrue(all('immutable_global' in r for r in p['entry_reads']));self.assertFalse(entry_accesses(p));capture_header([p])
            validate_snapshot({'format':'osrec-entry-snapshot-v1','objects':[],'roots':[],'fields':[]},p)

    def test_mutable_or_declaration_only_globals_still_require_capture(self):
        body='''unsigned mutable=1;extern const unsigned external;
unsigned writeable(void){return mutable;}unsigned missing(void){return external;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body)
            for root in ('writeable','missing'):
                p=Analyzer(tree).analyze(root);self.assertFalse(p['blockers']);self.assertFalse(any('immutable_global' in r for r in p['entry_reads']))
                with self.assertRaises(ValueError):capture_header([p])

    def test_pointers_and_records_are_not_scalar_constants(self):
        body='''unsigned value;unsigned *const ptr=&value;
struct Pair{unsigned value;};const struct Pair record={1};
unsigned pointer(void){return *ptr;}unsigned member(void){return record.value;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body)
            p=Analyzer(tree).analyze('pointer');self.assertFalse(any('immutable_global' in r for r in p['entry_reads']))
            with self.assertRaises(ValueError):capture_header([p])
            p=Analyzer(tree).analyze('member');self.assertFalse(entry_accesses(p));capture_header([p])
            self.assertEqual(p['entry_reads'][0]['immutable_global']['kind'],'defined_const_numeric_record')

    def test_volatile_and_atomic_globals_remain_blocked(self):
        body='''const volatile unsigned value=1;const _Atomic(unsigned) atomic=2;
unsigned vol(void){return value;}unsigned atom(void){return atomic;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body)
            for root in ('vol','atom'):
                p=Analyzer(tree).analyze(root);self.assertTrue(p['blockers'])
                with self.assertRaises(ValueError):capture_header([p])

    def test_initializer_dependencies_are_not_assumed_to_be_numeric_literals(self):
        body='const unsigned value=1;unsigned root(void){return value;}'
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),body);decl=next(n for n in tree['inner'] if n.get('kind')=='VarDecl')
            decl['inner']=[{'kind':'CallExpr','type':{'qualType':'unsigned int'},'inner':[]}]
            p=Analyzer(tree).analyze('root');self.assertNotIn('immutable_global',p['entry_reads'][0])
            with self.assertRaises(ValueError):capture_header([p])

    def test_writes_to_the_same_const_object_prevent_omission(self):
        body='''const unsigned value=1;
unsigned root(void){*(unsigned*)&value=2;return value;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body)).analyze('root');self.assertTrue(p['state_writes'])
            with self.assertRaisesRegex(ValueError,'also written'):capture_header([p])

    def test_evidence_tampering_and_type_or_path_changes_fail_closed(self):
        body='const unsigned value=1;unsigned root(void){return value;}'
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body)).analyze('root')
            for field,value in [('object','other'),('type','unsigned int'),('initializer_sha256','0'*64),('initializer',{})]:
                q=copy.deepcopy(p);q['entry_reads'][0]['immutable_global'][field]=value
                with self.subTest(field=field),self.assertRaises(ValueError):capture_header([q])
            for field,value in [('path','global:other'),('type','const double'),('pointer_edge',True),('volatile',True),('entry_candidate',False)]:
                q=copy.deepcopy(p);q['entry_reads'][0][field]=value
                with self.subTest(field=field),self.assertRaises(ValueError):capture_header([q])

    def test_merged_static_constants_keep_separate_scopes(self):
        sources={'a.c':'''static const unsigned scale=2;unsigned helper(void);
unsigned root(void){return scale+helper();}
''','b.c':'''static const unsigned scale=3;unsigned helper(void){return scale;}
'''}
        with tempfile.TemporaryDirectory() as tmp:
            tree=local_effects.LocalEffectTests().parse(Path(tmp),sources);before=copy.deepcopy(tree);a=Analyzer(tree)
            p=a.fresh().analyze('root');self.assertFalse(p['blockers']);self.assertFalse(entry_accesses(p));capture_header([p])
            self.assertEqual(len({r['immutable_global']['object'] for r in p['entry_reads']}),2)
            self.assertEqual(p,a.fresh().analyze('root'));self.assertEqual(tree,before)

    def test_generated_hook_compiles_and_runs_with_fixed_program_constants(self):
        body='static const unsigned scale=3,offset=2;unsigned root(unsigned x){return scale*x+offset;}'
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);p=Analyzer(self.parse(stage,body)).analyze('root');(stage/'capture.h').write_text(capture_header([p]))
            source=stage/'run.c';source.write_text(body+'''\n#include <assert.h>
#include "capture.h"
int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s));assert(s.object_count==0&&s.field_count==0);assert(root(7)==23);return 0;}
''')
            binary=stage/'run';subprocess.run([basic.CLANG,'-std=c11','-I',str(basic.ROOT/'include'),'-I',str(stage),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True,text=True)
            subprocess.run([str(binary)],check=True,capture_output=True)


if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=local_effects.CLANG=sys.argv.pop()
    unittest.main()
