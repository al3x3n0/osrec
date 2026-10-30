"""Exercise typed reads, aliases, call closures and generated pointer-free capture."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,load_ast,capture_header
from automated_entry_state import validate_snapshot
CLANG='/opt/homebrew/opt/llvm@16/bin/clang'
FIXTURE='''
struct Obj { unsigned value; unsigned other; struct Obj *parent; };
extern struct Obj *current(void);
extern int external(int);
unsigned read_parent(void) { struct Obj *p=current(); return p->parent->value; }
unsigned callee(struct Obj *p) { return p->other; }
unsigned through_call(void) { struct Obj *alias=current(); return callee(alias); }
unsigned conditional(int select) { struct Obj *p=current(); if(select) return p->value; return p->other; }
unsigned initialized(void) { struct Obj *p=current(); p->value=4; return p->value; }
unsigned configuration(void) {
#ifdef PICK_OTHER
return current()->other;
#else
return current()->value;
#endif
}
unsigned indexed(unsigned n) { return ((unsigned *)current())[n]; }
unsigned unknown(void) { struct Obj *p; return p->value; }
unsigned unresolved_callback(unsigned (*fn)(void)) { return fn(); }
unsigned boundary(void) { return (unsigned)external(4); }
'''
POLICY={'current':{'kind':'object_provider','reason':'test current object','implementation':'stable object binding','snapshot_safe':True}}

class EntryStateTests(unittest.TestCase):
    def parse(self,stage,text=FIXTURE,flags=()):
        source=stage/'input.c';source.write_text(text)
        database=stage/'compile_commands.json';database.write_text(json.dumps([{
            'directory':str(stage),'file':str(source),'arguments':[CLANG,'-std=c11',*flags,'-c',str(source),'-o','input.o']}]))
        return load_ast(database,source)

    def test_real_types_aliases_and_contexts(self):
        with tempfile.TemporaryDirectory() as name:
            ast,identity=self.parse(Path(name))
            paths=lambda root:{row['path'] for row in Analyzer(ast,POLICY).analyze(root)['entry_reads']}
            self.assertEqual(paths('read_parent'),{'current()->parent','current()->parent->value'})
            self.assertEqual(paths('through_call'),{'current()->other'})
            self.assertEqual(paths('conditional'),{'current()->value','current()->other'})
            plan=Analyzer(ast,POLICY).analyze('initialized')
            self.assertEqual([row['path'] for row in plan['state_writes']],['current()->value'])
            self.assertEqual([row['path'] for row in plan['entry_reads']],['current()->value'])
            self.assertFalse(plan['minimality_proven']);self.assertIn(str((Path(name)/'input.c').resolve()),identity['dependencies'])

    def test_configured_branches(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for flags,field in (((),'value'),(('-DPICK_OTHER',),'other')):
                ast,_=self.parse(stage,flags=flags)
                plan=Analyzer(ast,POLICY).analyze('configuration')
                self.assertEqual({row['path'] for row in plan['entry_reads']},{'current()->'+field})

    def test_unknown_effects_block_hook_generation(self):
        with tempfile.TemporaryDirectory() as name:
            ast,_=self.parse(Path(name))
            for root in ('indexed','unknown','unresolved_callback','boundary'):
                with self.subTest(root=root):
                    plan=Analyzer(ast,POLICY).analyze(root)
                    self.assertTrue(plan['blockers'])
                    with self.assertRaises(ValueError):capture_header([plan])
            no_contract=Analyzer(ast,{'current':{k:v for k,v in POLICY['current'].items() if k!='snapshot_safe'}}).analyze('read_parent')
            with self.assertRaisesRegex(ValueError,'snapshot_safe'):capture_header([no_contract])

    def test_generated_hook_normalizes_aliases_nulls_and_edges(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);ast,_=self.parse(stage)
            plans=[Analyzer(ast,POLICY).analyze(root) for root in ('read_parent','through_call')]
            (stage/'capture.h').write_text(capture_header(plans))
            program=FIXTURE+'''
#include <assert.h>
#include "capture.h"
static struct Obj parent={123,456,0},object={7,8,&parent};
struct Obj *current(void) { return &object; }
int external(int x) { return x; }
int main(void) {
 struct osrec_entry_snapshot state;osrec_snapshot_init(&state);
 assert(osrec_snapshot_read_parent(&state));
 assert(state.object_count==2 && state.field_count==2);
 assert(state.fields[0].is_edge && state.fields[0].target_id==2 && !state.fields[0].size);
 assert(!state.fields[1].is_edge && state.fields[1].size==4 && state.fields[1].bytes[0]==123);
 object.parent=&object;osrec_snapshot_init(&state);
 assert(osrec_snapshot_read_parent(&state));assert(state.object_count==1 && state.fields[0].target_id==1);
 object.parent=0;osrec_snapshot_init(&state);
 assert(osrec_snapshot_read_parent(&state));assert(state.object_count==1 && state.field_count==1 && !state.fields[0].target_id);
 return 0;
}
'''
            source=stage/'run.c';source.write_text(program);binary=stage/'run'
            subprocess.run([CLANG,'-std=c11','-Wno-uninitialized','-I',str(ROOT/'include'),'-I',str(stage),
                str(source),str(ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True,text=True)
            subprocess.run([str(binary)],check=True,capture_output=True)

    def test_snapshot_validation_rejects_raw_pointer_payload(self):
        with tempfile.TemporaryDirectory() as name:
            ast,_=self.parse(Path(name));plan=Analyzer(ast,POLICY).analyze('read_parent')
            frame={'format':'osrec-entry-snapshot-v1','objects':[{'id':1,'type':'Obj'}],
                'roots':[{'name':'current()','object_id':1}],
                'fields':[{'object_id':1,'name':'parent','kind':'edge','target_id':0}]}
            validate_snapshot(frame,plan)
            frame['fields'][0]['data']='12345678'
            with self.assertRaisesRegex(ValueError,'address bytes'):validate_snapshot(frame,plan)

    def test_statement_expression_pointer_results_and_shadowed_locals(self):
        source=FIXTURE+'''
unsigned statement_result(int pick) {
 struct Obj *p=({struct Obj *q=current(); struct Obj *r=pick?q->parent:q; r;});
 return p->value;
}
unsigned shadowed_result(void) {
 struct Obj *p=current()->parent;
 struct Obj *q=({struct Obj *p=current(); ({p;});});
 return q->value+p->other;
}
unsigned comma_result(void) {
 struct Obj *p=(current()->other++,current()); return p->value;
}
unsigned assignment_result(void) {
 struct Obj *p; struct Obj *q=({p=current();}); return q->other;
}
void void_statement(void) { ({current()->value=current()->other;}); }
'''
        with tempfile.TemporaryDirectory() as name:
            tree,_=self.parse(Path(name),source)
            expected={
                'statement_result':{'current()->parent','current()->parent->value','current()->value'},
                'shadowed_result':{'current()->parent','current()->parent->other','current()->value'},
                'comma_result':{'current()->other','current()->value'},
                'assignment_result':{'current()->other'},
                'void_statement':{'current()->other'}}
            for root,paths in expected.items():
                with self.subTest(root=root):
                    plan=Analyzer(tree,POLICY).analyze(root)
                    self.assertFalse(plan['blockers'],plan['blockers'])
                    self.assertEqual({r['path'] for r in plan['entry_reads']},paths)
                    self.assertIn('osrec_snapshot_'+root,capture_header([plan]))
            for root,field in (('comma_result','other'),('void_statement','value')):
                plan=Analyzer(tree,POLICY).analyze(root)
                self.assertEqual({r['path'] for r in plan['state_writes']},{'current()->'+field})

    def test_statement_expression_callback_targets(self):
        source=FIXTURE+'''
unsigned other_value(struct Obj *p){return p->other;}
unsigned value(struct Obj *p){return p->value;}
unsigned statement_callback(int pick) {
 unsigned (*fn)(struct Obj *)=({unsigned (*local)(struct Obj *)=pick?value:other_value; local;});
 return fn(current());
}
'''
        with tempfile.TemporaryDirectory() as name:
            tree,_=self.parse(Path(name),source)
            plan=Analyzer(tree,POLICY).analyze('statement_callback')
            self.assertFalse(plan['blockers'],plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'current()->value','current()->other'})
            self.assertEqual({c['callee'] for c in plan['call_sites'] if c['resolution'].startswith('finite')},{'value','other_value'})

    def test_statement_expression_unknowns_and_nested_effects_stay_blocked(self):
        source=FIXTURE+'''
unsigned null_statement(void){unsigned *p=({(unsigned *)0;});return *p;}
unsigned local_statement(void){unsigned *p=({unsigned local=3; &local;});return *p;}
unsigned asm_statement(void){return ({unsigned value; __asm__ volatile("" : "=r"(value));value;});}
unsigned goto_statement(int pick){void *target=&&out;goto *target;out:return current()->value;}
unsigned vararg_statement(int n,...){__builtin_va_list ap;__builtin_va_start(ap,n);
 unsigned result=({__builtin_va_arg(ap,unsigned);});__builtin_va_end(ap);return result;}
'''
        with tempfile.TemporaryDirectory() as name:
            tree,_=self.parse(Path(name),source)
            expected={'null_statement':'unresolved_pointer_origin','local_statement':'pointer_arithmetic',
                'asm_statement':'architecture_or_ordering','goto_statement':'unsupported_construct',
                'vararg_statement':'unsupported_construct'}
            for root,kind in expected.items():
                with self.subTest(root=root):
                    plan=Analyzer(tree,POLICY).analyze(root)
                    self.assertIn(kind,{b['kind'] for b in plan['blockers']})
                    if root=='local_statement':self.assertTrue(any('scope/lifetime' in b['detail'] for b in plan['blockers']))
                    with self.assertRaises(ValueError):capture_header([plan])

    def test_direct_jumps_retain_skipped_repeated_and_nested_effects(self):
        source=FIXTURE+'''
unsigned forward(int pick){struct Obj *p=current();if(pick)goto out;p->other++;out:return p->value;}
unsigned backward(int pick){struct Obj *p=current();again:p->value++;p=current()->parent;if(pick--)goto again;return p->other;}
unsigned nested_jump(int pick){({if(pick)goto out;current()->other;});out:return current()->value;}
unsigned after_return(void){goto out;return current()->other;out:return current()->value;}
unsigned jump_helper(struct Obj *p,int pick){if(pick)goto out;p->other++;out:return p->value;}
unsigned call_jump(int pick){return jump_helper(current(),pick);}
'''
        with tempfile.TemporaryDirectory() as name:
            tree,_=self.parse(Path(name),source)
            for root in ('forward','nested_jump','after_return','call_jump'):
                with self.subTest(root=root):
                    plan=Analyzer(tree,POLICY).analyze(root)
                    self.assertFalse(plan['blockers'],plan['blockers'])
                    self.assertEqual({r['path'] for r in plan['entry_reads']},{'current()->value','current()->other'})
                    capture_header([plan])
            plan=Analyzer(tree,POLICY).analyze('backward')
            self.assertFalse(plan['blockers'],plan['blockers'])
            self.assertTrue({'current()->value','current()->parent->value','current()->parent->other'} <= {r['path'] for r in plan['entry_reads']})
            self.assertEqual({r['path'] for r in plan['state_writes']},{'current()->value','current()->parent->value'})
            stage=Path(name)
            (stage/'capture.h').write_text(capture_header([Analyzer(tree,POLICY).analyze('forward')]))
            runner=stage/'run.c';runner.write_text(source+'''
#include <assert.h>
#include "capture.h"
static struct Obj object;
struct Obj *current(void){return &object;} int external(int x){return x;}
int main(void){for(int pick=0;pick<2;pick++){
 object.value=7;object.other=8;struct osrec_entry_snapshot s;osrec_snapshot_init(&s);
 assert(osrec_snapshot_forward(&s));assert(s.object_count==1 && s.field_count==2);
 assert(forward(pick)==7);assert(object.other==(pick?8:9));
 for(unsigned i=0;i<s.field_count;i++)assert(s.fields[i].bytes[0]==7 || s.fields[i].bytes[0]==8);
}return 0;}
''')
            binary=stage/'run'
            subprocess.run([CLANG,'-std=c11','-I',str(ROOT/'include'),'-I',str(stage),str(runner),
                str(ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)
            # Even damaged ASTs must not silently accept unavailable targets.
            from entry_state import walk
            jump=next(n for n in walk(tree) if n.get('kind')=='GotoStmt')
            jump['targetLabelDeclId']='missing'
            plan=Analyzer(tree,POLICY).analyze('forward')
            self.assertIn('unsupported_construct',{b['kind'] for b in plan['blockers']})

    def test_jump_implicit_effects_and_computed_targets_stay_blocked(self):
        source=FIXTURE+'''
void cleanup_value(unsigned *p){current()->value=*p;}
unsigned cleanup_jump(void){{unsigned v __attribute__((cleanup(cleanup_value)))=7;goto out;}out:return 0;}
unsigned static_jump(void){static unsigned v;goto out;out:return v++;}
unsigned extern_jump(void){extern unsigned hidden;goto out;out:return hidden;}
unsigned vla_jump(void){unsigned v[current()->value++];goto out;out:return 0;}
unsigned sizeof_vla_jump(void){unsigned n=sizeof(unsigned[current()->value++]);goto out;out:return n;}
unsigned computed_jump(void){void *target=&&out;goto *target;out:return current()->value;}
unsigned address_label(void){void *target=&&out;out:return target!=0;}
unsigned global_array[4];
unsigned enter_loop(void){goto inside;for(unsigned i=0;i<4;i++){inside:global_array[i]=1;}return 0;}
'''
        with tempfile.TemporaryDirectory() as name:
            tree,_=self.parse(Path(name),source)
            for root in ('cleanup_jump','static_jump','extern_jump','vla_jump','sizeof_vla_jump','computed_jump','address_label','enter_loop'):
                with self.subTest(root=root):
                    plan=Analyzer(tree,POLICY).analyze(root)
                    self.assertTrue(plan['blockers'])
                    if root!='enter_loop':self.assertIn('unsupported_construct',{b['kind'] for b in plan['blockers']})
                    else:self.assertFalse(plan['memory_ranges'])
                    with self.assertRaises(ValueError):capture_header([plan])

    def test_wrapped_unknown_origins_do_not_match_real_null_names(self):
        source=FIXTURE+'''
unsigned null;
unsigned null_global(void){return null;}
unsigned wrapped_null(void){unsigned *p=0;return *p;}
unsigned wrapped_unknown(unsigned pick){unsigned *p; if(pick)p=(unsigned *)current();return *p;}
'''
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);tree,_=self.parse(stage,source)
            for root in ('wrapped_null','wrapped_unknown'):
                plan=Analyzer(tree,POLICY).analyze(root)
                self.assertTrue(plan['blockers'])
                self.assertFalse(any('*(null)' in r['path'] or 'unresolved:' in r['path'] for r in plan['entry_reads']))
            plan=Analyzer(tree,POLICY).analyze('null_global')
            self.assertFalse(plan['blockers']);self.assertEqual(plan['entry_reads'][0]['path'],'global:null')
            source='struct Obj {unsigned null;};struct Obj *null(void);unsigned named(void){return null()->null;}'
            tree,_=self.parse(stage,source)
            policy={'null':POLICY['current']}
            plan=Analyzer(tree,policy).analyze('named')
            self.assertFalse(plan['blockers']);self.assertEqual(plan['entry_reads'][0]['path'],'null()->null')
            self.assertIn('osrec_snapshot_named',capture_header([plan]))

    def test_statement_expression_implicit_effects_and_aggregate_results_stay_blocked(self):
        source=FIXTURE+'''
void cleanup_value(unsigned *p){current()->value=*p;}
unsigned cleanup_statement(void){return ({unsigned v __attribute__((cleanup(cleanup_value)))=7;v;});}
unsigned static_statement(void){return ({static unsigned v;v++;});}
unsigned extern_statement(void){return ({extern unsigned hidden;hidden;});}
unsigned vla_statement(void){return ({unsigned v[current()->value++];1;});}
unsigned sizeof_vla_statement(void){return ({sizeof(unsigned[current()->value++]);});}
unsigned record_statement(void){struct Obj v=({struct Obj tmp={0};tmp;});return v.value;}
typedef struct {unsigned value;} Anonymous;
unsigned anonymous_statement(void){Anonymous v=({Anonymous tmp={0};tmp;});return v.value;}
'''
        with tempfile.TemporaryDirectory() as name:
            tree,_=self.parse(Path(name),source)
            for root in ('cleanup_statement','static_statement','extern_statement','vla_statement','sizeof_vla_statement','record_statement','anonymous_statement'):
                with self.subTest(root=root):
                    plan=Analyzer(tree,POLICY).analyze(root)
                    self.assertIn('unsupported_construct',{b['kind'] for b in plan['blockers']})
                    with self.assertRaises(ValueError):capture_header([plan])

    def test_statement_expression_native_capture(self):
        source=FIXTURE+'\nunsigned statement_parent(void){return ({struct Obj *p=current();p->parent;})->value;}\n'
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);tree,_=self.parse(stage,source)
            plan=Analyzer(tree,POLICY).analyze('statement_parent')
            self.assertFalse(plan['blockers']);(stage/'capture.h').write_text(capture_header([plan]))
            runner=stage/'run.c';runner.write_text(source+'''
#include <assert.h>
#include "capture.h"
static struct Obj parent={123,456,0},object={7,8,&parent};
struct Obj *current(void){return &object;} int external(int x){return x;}
int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);
 assert(statement_parent()==123);assert(osrec_snapshot_statement_parent(&s));
 assert(s.object_count==2 && s.field_count==2);
 assert(s.fields[0].is_edge && s.fields[0].target_id==2);
 parent.value=999;assert(!s.fields[1].is_edge && s.fields[1].bytes[0]==123);return 0;}
''')
            binary=stage/'run'
            subprocess.run([CLANG,'-std=c11','-I',str(ROOT/'include'),str(runner),
                str(ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)

if __name__=='__main__':
    if len(sys.argv)==2:CLANG=sys.argv.pop()
    unittest.main()
