"""Pre-clone selection must match selecting the same namespaced full AST."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

import test_entry_state_program as basic
from entry_state import Analyzer,children,walk
from entry_state_program import function_reference_closure,merge_translation_units


def reference(units,roots):
    tree,program=merge_translation_units(units)
    declarations=children(tree);names=function_reference_closure(declarations,roots)
    selected=[n for n in declarations if n.get('kind')!='FunctionDecl' or n['name'] in names]
    program['defined_functions']=sum(n.get('kind')=='FunctionDecl' and any(c.get('kind')=='CompoundStmt' for c in children(n)) for n in selected)
    program['function_slice']=dict(kind='syntactic_function_and_global_reference_closure',roots=list(roots),retained_function_names=sorted(names),
        removed_function_declarations=len(declarations)-len(selected),record_checks='all configured records retained')
    return dict(kind='TranslationUnitDecl',inner=selected),program


class ProgramSlicingTests(unittest.TestCase):
    def units(self,stage,sources):
        db,files=basic.ProgramTests().sources(stage,sources)
        from entry_state import load_ast
        return [load_ast(db,f) for f in files]

    def equivalent(self,units,roots):
        before=copy.deepcopy(units)
        actual=merge_translation_units(units,roots=roots)
        self.assertEqual(actual,reference(units,roots));self.assertEqual(units,before)
        return actual

    def test_transitive_static_callbacks_and_global_initializer_chains(self):
        with tempfile.TemporaryDirectory() as tmp:
            units=self.units(Path(tmp),{
                'a.c':'''unsigned other(void);static unsigned local(void){return 1;}
static unsigned (*callbacks[3])(void)={local,other};
static unsigned (**alias)(void)=callbacks;
unsigned unused(void){return 3;}unsigned root(unsigned n){return alias[n]();}''',
                'b.c':'''static unsigned local(void){return 2;}unsigned other(void){return local();}
unsigned discarded(void){return 4;}'''})
            tree,program=self.equivalent(units,['root'])
            self.assertEqual(set(program['function_slice']['retained_function_names']),{'root','tu0:local','other','tu1:local'})
            self.assertTrue(any(n.get('kind')=='VarDecl' and n.get('name')=='tu0:alias' for n in children(tree)))

    def test_same_parsed_tree_can_be_used_in_distinct_unit_occurrences(self):
        with tempfile.TemporaryDirectory() as tmp:
            unit=self.units(Path(tmp),{'a.c':'static unsigned state;static unsigned helper(void){return state;}static unsigned root(void){return helper();}'})[0]
            for roots in (['tu0:root'],['tu1:root'],['tu0:root','tu1:root']):
                with self.subTest(roots=roots):self.equivalent([unit,unit],roots)

    def test_ids_from_separate_units_cannot_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            units=self.units(Path(tmp),{
                'a.c':'unsigned leaf(void);static unsigned (*cb)(void)=leaf;unsigned root(void){return cb();}',
                'b.c':'unsigned hidden(void);static unsigned (*cb)(void)=hidden;unsigned leaf(void){return 7;}unsigned hidden(void){return 9;}'})
            # Clang IDs are process-local. Force the two globals to share one
            # raw ID while their references still identify their own TU.
            for tree,_ in units:
                global_node=next(n for n in children(tree) if n.get('kind')=='VarDecl' and n.get('name')=='cb')
                original=global_node['id']
                for node in walk(tree):
                    if node.get('id')==original:node['id']='0xc0111de'
                    ref=node.get('referencedDecl',{})
                    if ref.get('id')==original:ref['id']='0xc0111de'
            _,program=self.equivalent(units,['root'])
            self.assertIn('leaf',program['function_slice']['retained_function_names'])
            self.assertNotIn('hidden',program['function_slice']['retained_function_names'])

    def test_unevaluated_references_and_array_fillers_stay_in_syntactic_slice(self):
        with tempfile.TemporaryDirectory() as tmp:
            units=self.units(Path(tmp),{'a.c':'''unsigned first(void),second(void),third(void);
static unsigned (*callbacks[8])(void)={first,second};
unsigned root(void){(void)sizeof(third());return callbacks[0]();}
unsigned first(void){return 1;}unsigned second(void){return 2;}unsigned third(void){return 3;}'''})
            _,program=self.equivalent(units,['root'])
            self.assertTrue({'first','second','third'}<=set(program['function_slice']['retained_function_names']))

    def test_full_records_and_nonfunction_declarations_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            units=self.units(Path(tmp),{'a.c':'struct Unused{unsigned x;};typedef struct Unused Alias;unsigned state;unsigned ignored(void){return state;}unsigned root(void){return 1;}'})
            tree,_=self.equivalent(units,['root'])
            self.assertEqual([n for n in children(tree) if n.get('kind')!='FunctionDecl'],
                [n for n in children(merge_translation_units(units)[0]) if n.get('kind')!='FunctionDecl'])

    def test_record_and_referenced_signature_conflicts_still_block(self):
        scenarios=[('struct Unused{unsigned x;};unsigned leaf(void);unsigned root(void){return leaf();}',
                    'struct Unused{unsigned x,y;};unsigned leaf(void){return 1;}','incompatible configured record'),
                   ('unsigned leaf(unsigned);unsigned root(void){return leaf(1);}',
                    'unsigned leaf(const char *p){return 1;}','incompatible configured function')]
        for a,b,message in scenarios:
            with self.subTest(message=message),tempfile.TemporaryDirectory() as tmp:
                units=self.units(Path(tmp),{'a.c':a,'b.c':b})
                with self.assertRaisesRegex(ValueError,message):merge_translation_units(units,roots=['root'])

    def test_plans_match_for_mutation_and_nonautomatic_storage_blockers(self):
        with tempfile.TemporaryDirectory() as tmp:
            units=self.units(Path(tmp),{'a.c':'struct Obj{unsigned value;};struct Obj *current(void);unsigned root(void){static unsigned n;struct Obj *p=current();p++;return p->value+n++;}'})
            a,_=self.equivalent(units,['root']);b,_=reference(units,['root'])
            self.assertEqual(Analyzer(a,basic.POLICY).analyze('root'),Analyzer(b,basic.POLICY).analyze('root'))

    def test_syntax_cache_matches_cold_merges_as_units_and_roots_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            units=self.units(Path(tmp),{
                'a.c':'struct Obj{unsigned value;};unsigned leaf(void);static unsigned local(void){return 1;}unsigned root(void){return leaf()+local();}',
                'b.c':'struct Obj{unsigned value;};static unsigned local(void){return 2;}unsigned leaf(void){return local();}'})
            original=copy.deepcopy(units);cache={}
            for selected,roots in ((units[:1],['root']),(units,['root']),(units,['leaf']),(units,['root'])):
                cold=merge_translation_units(selected,roots=roots)
                warm=merge_translation_units(selected,roots=roots,syntax_cache=cache)
                self.assertEqual(cold,warm)
                before=copy.deepcopy(warm[0]);Analyzer(warm[0]).analyze(roots[0]);self.assertEqual(warm[0],before)
            self.assertEqual(units,original)

    def test_syntax_cache_isolates_repeated_trees_and_colliding_decl_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            units=self.units(Path(tmp),{'a.c':'static unsigned hidden(void){return 1;}static unsigned root(void){return hidden();}',
                                       'b.c':'static unsigned other(void){return 2;}static unsigned root(void){return other();}'})
            for n in children(units[1][0]):
                if n.get('kind')=='FunctionDecl' and n.get('name')=='root':
                    first=next(x for x in children(units[0][0]) if x.get('kind')=='FunctionDecl' and x.get('name')=='root');n['id']=first['id']
            cache={}
            for selected,roots in (([units[0]],['tu0:root']),([units[1]],['tu0:root']),([units[0],units[0]],['tu1:root'])):
                self.assertEqual(merge_translation_units(selected,roots=roots),merge_translation_units(selected,roots=roots,syntax_cache=cache))

    def test_cached_declarations_still_participate_in_all_conflict_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            units=self.units(Path(tmp),{'a.c':'struct Obj{unsigned x;};unsigned leaf(unsigned);unsigned root(void){return leaf(1);}',
                                       'b.c':'struct Obj{unsigned x,y;};unsigned leaf(unsigned x){return x;}'})
            cache={};merge_translation_units(units[:1],roots=['root'],syntax_cache=cache)
            with self.assertRaisesRegex(ValueError,'incompatible configured record'):merge_translation_units(units,roots=['root'],syntax_cache=cache)

    def test_discovery_reuses_syntax_without_changing_closure_evidence(self):
        import test_discovered_call_closure as closure
        from discover_call_closure import discover
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);db,index=closure.setup(stage,{'a.c':'unsigned leaf(unsigned);unsigned root(unsigned x){return leaf(x);}',
                                                       'b.c':'static unsigned value=3;unsigned leaf(unsigned x){return value+x;}'})
            cold=discover(db,stage/'a.c','root',index,cache_merge_syntax=False)
            warm=discover(db,stage/'a.c','root',index,cache_merge_syntax=True)
            self.assertEqual(cold,warm)


if __name__=='__main__':
    if len(sys.argv)==2:basic.CLANG=sys.argv.pop()
    unittest.main()
