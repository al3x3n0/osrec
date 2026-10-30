"""Compiler-identified integer bit operations keep all evaluated effects."""
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import test_entry_state as basic
from entry_state import Analyzer,INTEGER_BIT_BUILTINS,capture_header,walk,children

HEADER='struct Obj{unsigned value,other;};struct Obj *current(void);'

class IntegerBuiltinTests(unittest.TestCase):
    def parse(self,stage,text,flags=()):return basic.EntryStateTests().parse(stage,HEADER+text,flags)[0]

    def test_all_integer_variants_on_host_and_kernel_target(self):
        body='\n'.join(f'{result} root{i}({argument} x){{return {name}(x);}}'
            for i,(name,(result,argument)) in enumerate(INTEGER_BIT_BUILTINS.items()))
        with tempfile.TemporaryDirectory() as tmp:
            for flags in ((),('--target=arm-none-eabi',)):
                tree=self.parse(Path(tmp),body,flags);a=Analyzer(tree)
                for i,name in enumerate(INTEGER_BIT_BUILTINS):
                    p=a.fresh().analyze('root'+str(i));self.assertFalse(p['blockers'],(name,p['blockers']))
                    self.assertFalse(p['entry_reads']);self.assertFalse(p['state_writes']);capture_header([p])
                    self.assertEqual(p['call_sites'][0]['intrinsic']['name'],name)
                    self.assertEqual(p['call_sites'][0]['resolution'],'compiler_builtin')

    def test_argument_reads_and_mutations_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),'unsigned root(void){return __builtin_clz(current()->value++);}');p=Analyzer(tree,basic.POLICY).analyze('root')
            self.assertFalse(p['blockers']);self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->value'})
            self.assertEqual({r['path'] for r in p['state_writes']},{'current()->value'});capture_header([p])

    def test_nested_argument_calls_keep_context_and_external_blockers(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),'unsigned unknown(void);unsigned helper(void){return current()->other;}unsigned root(void){return __builtin_ctz(helper())+__builtin_clz(unknown());}')
            p=Analyzer(tree,basic.POLICY).analyze('root');self.assertEqual({r['path'] for r in p['entry_reads']},{'current()->other'})
            self.assertTrue(any(b['kind']=='unmodeled_external' and 'unknown' in b['detail'] for b in p['blockers']))
            self.assertFalse(any(b['kind']=='unmodeled_external' and '__builtin_c' in b['detail'] for b in p['blockers']))
            with self.assertRaises(ValueError):capture_header([p])

    def test_volatile_and_unknown_memory_arguments_remain_blocked(self):
        body='unsigned root(volatile unsigned*p){return __builtin_clz(*p);}unsigned unknown(unsigned*p){return __builtin_ctz(p[3]);}'
        with tempfile.TemporaryDirectory() as tmp:
            a=Analyzer(self.parse(Path(tmp),body))
            for root in ('root','unknown'):
                p=a.fresh().analyze(root);self.assertTrue(p['blockers'])
                with self.assertRaises(ValueError):capture_header([p])

    def test_malformed_declaration_or_call_does_not_gain_intrinsic_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),'unsigned root(unsigned x){return __builtin_clz(x);}')
            for change in ('builtin_attr','const_attr','implicit','signature','reference','argument_type','arity','explicit_cast'):
                q=copy.deepcopy(tree);decl=next(n for n in children(q) if n.get('kind')=='FunctionDecl' and n.get('name')=='__builtin_clz')
                call=next(n for n in walk(q) if n.get('kind')=='CallExpr');ref=next(n for n in walk(call) if n.get('kind')=='DeclRefExpr' and n.get('referencedDecl',{}).get('kind')=='FunctionDecl')
                if change in ('builtin_attr','const_attr'):
                    kind='BuiltinAttr' if change=='builtin_attr' else 'ConstAttr';decl['inner']=[n for n in children(decl) if n.get('kind')!=kind]
                elif change=='implicit':decl['isImplicit']=False
                elif change=='signature':decl['type']['qualType']='int (int)'
                elif change=='reference':ref['referencedDecl']['id']='missing'
                elif change=='argument_type':call['inner'][1]['type']={'qualType':'unsigned int *'}
                elif change=='arity':call['inner'].append(copy.deepcopy(call['inner'][1]))
                else:call['inner'][0]['kind']='CStyleCastExpr'
                p=Analyzer(q).analyze('root');self.assertIn('unmodeled_external',{b['kind'] for b in p['blockers']},change)
                self.assertFalse(any(c.get('intrinsic') for c in p['call_sites']),change)

    def test_unlisted_builtins_and_user_const_functions_remain_external(self):
        body='unsigned pure(unsigned) __attribute__((const));unsigned root(unsigned x){return pure(x)+__builtin_abs((int)x)+__builtin_expect(x,0);}'
        with tempfile.TemporaryDirectory() as tmp:
            p=Analyzer(self.parse(Path(tmp),body)).analyze('root')
            self.assertEqual({b['detail'].split(': ')[-1] for b in p['blockers']},{'pure','__builtin_abs'})
            # __builtin_expect (likely/unlikely) is a branch hint returning its first operand.
            self.assertEqual([c['intrinsic']['kind'] for c in p['call_sites'] if c['callee']=='__builtin_expect'],['branch_hint'])

    def test_boundary_policy_takes_precedence(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),'unsigned root(unsigned x){return __builtin_clz(x);}')
            p=Analyzer(tree,{'__builtin_clz':{'kind':'scalar_transcript','reason':'fixture','implementation':'fixture','snapshot_safe':True}}).analyze('root')
            self.assertFalse(p['call_sites'][0].get('intrinsic'));self.assertEqual(p['call_sites'][0]['boundary']['kind'],'scalar_transcript')

    def test_fresh_roots_and_ast_are_isolated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),'unsigned root(void){return __builtin_popcount(current()->value);}unsigned other(void){return __builtin_parity(current()->other);}')
            before=copy.deepcopy(tree);a=Analyzer(tree,basic.POLICY);p=a.fresh().analyze('root');a.fresh().analyze('other')
            self.assertEqual(a.fresh().analyze('root'),p);self.assertEqual(tree,before)

    def test_cross_file_discovery_and_survey_do_not_request_builtin_bodies(self):
        import test_discovered_call_closure as closure
        from discover_call_closure import discover
        from discover_kernel_state import survey_unit
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);db,index=closure.setup(stage,{
                'root.c':'unsigned helper(unsigned);unsigned root(unsigned x){return helper(x);}',
                'helper.c':'unsigned helper(unsigned x){return __builtin_clz(x)+__builtin_ctz(x);}'})
            result=discover(db,stage/'root.c','root',index)
            self.assertEqual(result['status'],'candidate');self.assertTrue(result['capture_schema_accepted'])
            self.assertEqual(result['program']['translation_units'],2)
            self.assertFalse(result['history'][-1]['missing_bodies'])
            self.assertFalse(any(e.get('callee','').startswith('__builtin_') for e in result['events']))
            unit=survey_unit(db,stage/'helper.c',100)
            self.assertEqual(unit['roots'][0]['unresolved_direct_calls'],[])

    def test_native_capture_matches_direct_bit_operation(self):
        body='unsigned root(void){return __builtin_clz(current()->value)+__builtin_popcount(current()->other);}'
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);p=Analyzer(self.parse(stage,body),basic.POLICY).analyze('root');self.assertFalse(p['blockers'])
            (stage/'capture.h').write_text(capture_header([p]));source=stage/'run.c'
            source.write_text(HEADER+body+'''\n#include <assert.h>
static struct Obj state={16,7};struct Obj*current(void){return &state;}
#include "capture.h"
int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);assert(osrec_snapshot_root(&s));assert(s.field_count==2);assert(root()==30);return 0;}
''');binary=stage/'run'
            subprocess.run([basic.CLANG,'-std=c11','-I',str(basic.ROOT/'include'),'-I',str(stage),str(source),str(basic.ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True,text=True)
            subprocess.run([str(binary)],check=True,capture_output=True)

if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
