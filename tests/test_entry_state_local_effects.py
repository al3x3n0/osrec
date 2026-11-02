"""Implicit local effects and pointer mutation must not yield incomplete plans."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,capture_header,load_ast
from entry_state_program import load_program

CLANG='/opt/homebrew/opt/llvm@16/bin/clang'
POLICY={'current':dict(kind='object_provider',reason='fixture live object',implementation='fixture binding',snapshot_safe=True)}
HEADER='struct Obj{unsigned value;struct Obj *next;};struct Obj *current(void);'


class LocalEffectTests(unittest.TestCase):
    def parse(self,stage,sources):
        entries=[];files=[]
        for name,body in sources.items():
            source=stage/name;source.write_text(HEADER+body);files.append(source)
            entries.append(dict(directory=str(stage),file=str(source),arguments=[CLANG,'-std=gnu11','-c',str(source)]))
        db=stage/'compile_commands.json';db.write_text(json.dumps(entries))
        return load_program(db,files[0],all_sources=True)[0] if len(files)>1 else load_ast(db,files[0])[0]

    def blocked(self,tree,root,kind='unsupported_construct'):
        plan=Analyzer(tree,POLICY).analyze(root)
        self.assertIn(kind,{b['kind'] for b in plan['blockers']},plan)
        with self.assertRaises(ValueError):capture_header([plan])
        return plan

    def test_nonautomatic_local_storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),{'input.c':'''unsigned shared;
unsigned persistent(void){static unsigned count;return ++count;}
unsigned external(void){extern unsigned shared;return shared;}
unsigned thread(void){static _Thread_local unsigned count;return ++count;}
unsigned pointer(void){static struct Obj *p;return p->value;}
unsigned nested(void){{static unsigned count;count++;}return 0;}
'''})
            for root in ('persistent','external','thread','pointer','nested'):
                with self.subTest(root=root):self.blocked(tree,root)

    def test_cleanup_on_returns_and_nested_scopes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),{'input.c':'''void clean(unsigned *p);
unsigned cleanup(void){unsigned x __attribute__((cleanup(clean)))=1;return x;}
unsigned nested(void){{unsigned x __attribute__((cleanup(clean)))=1;}return 0;}
'''})
            for root in ('cleanup','nested'):self.blocked(tree,root)

    def test_variably_modified_bound_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),{'input.c':'''unsigned extent(void);
unsigned array(void){unsigned a[extent()];return 0;}
unsigned alias(void){typedef unsigned A[extent()];return 0;}
unsigned pointer(void){unsigned (*p)[extent()];return 0;}
unsigned size_type(void){return sizeof(unsigned[extent()]);}
unsigned size_expr(void){return sizeof *(unsigned (*)[extent()])0;}
unsigned parameter(unsigned n,unsigned (*p)[n]){return n;}
'''})
            for root in ('array','alias','pointer','size_type','size_expr','parameter'):
                with self.subTest(root=root):self.blocked(tree,root)

    def test_pointer_mutations_poison_alias_origins(self):
        forms={'post':'p++','pre':'++p','decrement':'--p','add':'p+=1','subtract':'p-=1',
               'selected':'_Generic(0,int:p,default:p)++'}
        with tempfile.TemporaryDirectory() as tmp:
            source=''.join('unsigned '+name+'(void){struct Obj *p=current();'+effect+';return p->value;}' for name,effect in forms.items())
            tree=self.parse(Path(tmp),{'input.c':source})
            for root in forms:
                with self.subTest(root=root):
                    # A step without a proven offset leaves a derived pointer: its dereference blocks.
                    plan=self.blocked(tree,root,'dynamic_extent')
                    self.assertIn('dereference of a derived pointer (unproven offset) needs a checked span',{b['detail'] for b in plan['blockers']})

    def test_pointer_results_fields_and_helper_returns(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),{'input.c':'''struct Obj *move(void){struct Obj *p=current();return ++p;}
unsigned result(void){struct Obj *p=current();return (++p)->value;}
unsigned helper(void){return move()->value;}
unsigned field(void){current()->next++;return current()->next->value;}
'''})
            for root in ('result','helper'):
                with self.subTest(root=root):self.blocked(tree,root,'dynamic_extent')
            # A stepped pointer stored back into non-automatic memory still needs an escape model.
            with self.subTest(root='field'):self.blocked(tree,'field','pointer_arithmetic')

    def test_unevaluated_and_discarded_effects_do_not_poison_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),{'input.c':'''void clean(unsigned *p);unsigned extent(void);
unsigned size_pointer(void){struct Obj *p=current();(void)sizeof(p++);return p->value;}
unsigned size_local(void){return sizeof({static unsigned x;unsigned y __attribute__((cleanup(clean)));x++;});}
unsigned discarded(void){return __builtin_choose_expr(1,current()->value,({static unsigned x;x++;}));}
unsigned discarded_bound(void){return _Generic(0,int:current()->value,default:sizeof(unsigned[extent()]));}
unsigned fixed(void){unsigned a[4]={0};return a[0]+current()->value;}
unsigned integer(void){unsigned n=1;n++;return n+current()->value;}
'''})
            for root in ('size_pointer','size_local','discarded','discarded_bound','fixed','integer'):
                with self.subTest(root=root):
                    plan=Analyzer(tree,POLICY).analyze(root);self.assertFalse(plan['blockers'],plan['blockers']);capture_header([plan])
                    self.assertEqual({r['path'] for r in plan['entry_reads']},set() if root=='size_local' else {'current()->value'})

    def test_transitive_cross_file_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree=self.parse(Path(tmp),{'input.c':'''unsigned hidden(void);unsigned root(void){return hidden();}''',
                'helper.c':'''unsigned hidden(void){static unsigned value;return ++value;}'''})
            plan=self.blocked(tree,'root')
            self.assertTrue(any(b['call_path']==['root','hidden'] for b in plan['blockers']))


if __name__=='__main__':
    if len(sys.argv)==2:CLANG=sys.argv.pop()
    unittest.main()
