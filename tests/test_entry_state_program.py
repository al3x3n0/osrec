"""Configured multi-file analysis must preserve linkage, types and pointer paths."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,capture_header,walk,load_ast
from entry_state_program import canonical_type,load_program,merge_translation_units
CLANG='/opt/homebrew/opt/llvm@16/bin/clang'
POLICY={'current':{'kind':'object_provider','reason':'current object','implementation':'test binding','snapshot_safe':True}}
HEADER='struct Obj { unsigned first,second; struct Obj *parent; };\nstruct Obj *current(void);\n'

class ProgramTests(unittest.TestCase):
    def sources(self,stage,texts):
        files=[];entries=[]
        for name,text in texts.items():
            source=stage/name;source.write_text(text);files.append(source)
            entries.append({'directory':str(stage),'file':str(source),'arguments':[CLANG,'-std=c11','-c',str(source),'-o',name+'.o']})
        database=stage/'compile_commands.json';database.write_text(json.dumps(entries))
        return database,files

    def test_declarations_compare_by_type_not_spelling(self):
        typedefs={'linux':{'size_t':'unsigned long','fl_owner_t':'void *'}}
        self.assertEqual(canonical_type('bool (struct ctx *, unsigned int)','models',typedefs),canonical_type('_Bool (struct ctx *, unsigned int)','syscalls',typedefs))
        self.assertEqual(canonical_type('int (size_t, struct size_t *)','linux',typedefs),'int (unsigned long, struct size_t *)')
        self.assertNotEqual(canonical_type('int (size_t)','linux',typedefs),canonical_type('int (unsigned int)','other',typedefs))
        self.assertEqual(canonical_type('bool (int)','u',{'u':{'bool':'unsigned char'}}),'unsigned char (int)')

    def test_direct_jump_labels_are_namespaced_across_files(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);database,files=self.sources(stage,{
                'root.c':HEADER+'unsigned other(struct Obj *,int);unsigned query(int x){struct Obj *p=current();if(x)goto out;p->first++;out:return other(p,x);}',
                'helper.c':HEADER+'unsigned other(struct Obj *p,int x){if(x)goto out;p->second++;out:return p->first;}'})
            tree,_=load_program(database,files[0],all_sources=True)
            labels={n['declId'] for n in walk(tree) if n.get('kind')=='LabelStmt'}
            targets={n['targetLabelDeclId'] for n in walk(tree) if n.get('kind')=='GotoStmt'}
            self.assertEqual(labels,targets);self.assertEqual(len(labels),2)
            self.assertTrue(all(label.startswith(('tu0:','tu1:')) for label in labels))
            plan=Analyzer(tree,POLICY,prune_written=True).analyze('query')
            self.assertFalse(plan['blockers'],plan['blockers']);self.assertFalse(plan['dominated_reads'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'current()->first','current()->second'})
            self.assertEqual({r['path'] for r in plan['state_writes']},{'current()->first','current()->second'})
            capture_header([plan])

    def test_external_pointer_arguments_return_alias_and_capture(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);database,files=self.sources(stage,{
                'root.c':HEADER+'struct Obj *parent_of(struct Obj *); unsigned value_of(struct Obj *);\nunsigned query(void){ return value_of(parent_of(current())); }',
                'helper.c':HEADER+'struct Obj *parent_of(struct Obj *p){struct Obj *q=p->parent;return q;}\nunsigned value_of(struct Obj *p){return p->second;}'})
            tree,program=load_program(database,files[0],all_sources=True)
            plan=Analyzer(tree,POLICY).analyze('query')
            self.assertFalse(plan['blockers']);self.assertEqual(program['translation_units'],2)
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'current()->parent','current()->parent->second'})
            self.assertTrue(all('translation_unit' in r['location'] for r in plan['entry_reads']))
            (stage/'capture.h').write_text(capture_header([plan]))
            runner=stage/'runner.c';runner.write_text(HEADER+'''
#include "capture.h"
static struct Obj parent={7,123,0},object={4,5,&parent};
struct Obj *current(void){return &object;}
int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);
 if(!osrec_snapshot_query(&s) || s.object_count!=2 || s.field_count!=2) return 1;
 return s.fields[1].bytes[0]!=123;}
''')
            binary=stage/'run';subprocess.run([CLANG,'-std=c11','-I',str(ROOT/'include'),str(runner),str(ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([binary],check=True)
            output=stage/'plan.json'
            subprocess.run([sys.executable,str(ROOT/'tools/entry_state.py'),'--compile-commands',str(database),
                '--source',str(files[0]),'--root','query','--all-sources','--out',str(output)],check=True,capture_output=True)
            report=json.loads(output.read_text());self.assertEqual(len(report['source_identities']),2)

    def test_static_functions_and_globals_are_isolated(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);database,files=self.sources(stage,{
                'root.c':HEADER+'unsigned other(struct Obj *);\nstatic unsigned local(struct Obj *p){return p->first;}\nunsigned query(void){return local(current())+other(current());}',
                'helper.c':HEADER+'static unsigned local(struct Obj *p){return p->second;}\nunsigned other(struct Obj *p){return local(p);}'})
            tree,_=load_program(database,files[0],all_sources=True)
            plan=Analyzer(tree,POLICY).analyze('query')
            self.assertFalse(plan['blockers']);self.assertEqual({r['path'] for r in plan['entry_reads']},{'current()->first','current()->second'})
            calls={r['callee'] for r in plan['call_sites']}
            self.assertIn('tu0:local',calls);self.assertIn('tu1:local',calls)
            field_ids=[n['id'] for n in walk(tree) if n.get('kind')=='FieldDecl']
            self.assertEqual(len(field_ids),len(set(field_ids)))

    def test_static_globals_and_nonconverging_aliases(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);database,files=self.sources(stage,{
                'root.c':HEADER+'unsigned other(void); static unsigned state; unsigned query(void){return state+other();}\nunsigned chain(unsigned count){struct Obj *p=current();while(count--) p=p->parent;return p->first;}',
                'helper.c':'static unsigned state; unsigned other(void){return state;}'})
            tree,_=load_program(database,files[0],all_sources=True)
            plan=Analyzer(tree,POLICY).analyze('query')
            self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'global:tu0:state','global:tu1:state'})
            plan=Analyzer(tree,POLICY).analyze('chain')
            self.assertTrue(any(b['kind']=='alias_limit' for b in plan['blockers']))
            with self.assertRaises(ValueError):capture_header([plan])

    def test_header_inline_bodies_and_provider_models_remain_separate(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            header='struct Obj { unsigned first,second; struct Obj *parent; };\nstatic inline struct Obj *current(void){ return 0; }\nstatic inline unsigned local(struct Obj *p){return p->first;}\n'
            database,files=self.sources(stage,{
                'root.c':header+'unsigned other(struct Obj *); unsigned query(void){return local(current())+other(current());}',
                'helper.c':header+'unsigned other(struct Obj *p){return local(p);}'})
            tree,_=load_program(database,files[0],all_sources=True)
            plan=Analyzer(tree,POLICY).analyze('query')
            self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'current()->first'})
            self.assertEqual([p['function'] for p in plan['object_providers']],['current'])
            self.assertIn('current()',capture_header([plan]))

    def test_finite_callbacks_cross_file_and_unknown_targets_block(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);database,files=self.sources(stage,{
                'root.c':HEADER+'''unsigned first(struct Obj *); unsigned second(struct Obj *);
unsigned invoke(unsigned (*fn)(struct Obj *),struct Obj *p);
unsigned query(int choose){unsigned (*fn)(struct Obj *)=first; if(choose) fn=second;return invoke(fn,current());}
unsigned nullable(int choose){unsigned (*fn)(struct Obj *)=choose ? first : 0;return fn(current());}
unsigned unknown(unsigned (*fn)(struct Obj *)){return invoke(fn,current());}
unsigned loop(unsigned count){unsigned (*fn)(struct Obj *)=first;unsigned value=0;while(count--){value+=fn(current());fn=second;}return value;}
''',
                'helper.c':HEADER+'''unsigned first(struct Obj *p){return p->first;}
unsigned second(struct Obj *p){return p->second;}
unsigned invoke(unsigned (*fn)(struct Obj *),struct Obj *p){return (*fn)(p);}
'''})
            tree,_=load_program(database,files[0],all_sources=True)
            plan=Analyzer(tree,POLICY).analyze('query')
            self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'current()->first','current()->second'})
            self.assertEqual({r['callee'] for r in plan['call_sites'] if r['resolution'].startswith('finite')},{'first','second'})
            loop=Analyzer(tree,POLICY).analyze('loop')
            self.assertFalse(loop['blockers'])
            self.assertEqual({r['path'] for r in loop['entry_reads'] if r['path'].startswith('current()')},{'current()->first','current()->second'})
            for root in ('nullable','unknown'):
                blocked=Analyzer(tree,POLICY).analyze(root)
                self.assertTrue(any(b['kind']=='indirect_call' for b in blocked['blockers']))

    def test_conflicts_and_limits_fail_closed(self):
        scenarios=[(HEADER+'unsigned helper(struct Obj *p){return p->first;}','multiple configured'),
            ('struct Obj { unsigned first; }; unsigned helper(struct Obj *p){return p->first;}','incompatible configured record'),
            (HEADER+'int helper(struct Obj *p){return p->first;}','incompatible configured function')]
        for helper,message in scenarios:
            with self.subTest(message=message),tempfile.TemporaryDirectory() as name:
                stage=Path(name);root=HEADER+'unsigned helper(struct Obj *); unsigned query(void){return helper(current());}'
                if message.startswith('multiple'):root+='unsigned helper(struct Obj *p){return p->first;}'
                database,files=self.sources(stage,{'root.c':root,'helper.c':helper})
                with self.assertRaisesRegex(ValueError,message):load_program(database,files[0],all_sources=True)
                with self.assertRaisesRegex(ValueError,'limit exceeded'):load_program(database,files[0],all_sources=True,max_units=1)

    def test_mixed_compiler_targets_are_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);database,files=self.sources(stage,{
                'root.c':HEADER+'unsigned query(void){return current()->first;}',
                'helper.c':HEADER+'unsigned helper(struct Obj *p){return p->second;}'})
            entries=json.loads(database.read_text())
            entries[1]['arguments'].insert(1,'--target=arm-none-eabi')
            database.write_text(json.dumps(entries))
            with self.assertRaisesRegex(ValueError,'different compiler targets'):load_program(database,files[0],all_sources=True)

    def test_merge_output_is_independent_of_parsed_inputs(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);database,files=self.sources(stage,{
                'root.c':HEADER+'static unsigned state; static unsigned read_value(struct Obj *p){return p->first+state;}\nunsigned query(struct Obj *p){return read_value(p);}'})
            units=[load_ast(database,files[0])];original=copy.deepcopy(units)
            tree,program=merge_translation_units(units,roots=['query'])
            self.assertEqual(units,original)
            expected=copy.deepcopy((tree,program))
            field=next(n for n in walk(tree) if n.get('kind')=='FieldDecl')
            field['type']['qualType']='changed only in output'
            function=next(n for n in tree['inner'] if n.get('kind')=='FunctionDecl')
            function['inner'].clear()
            tree['inner'].clear()
            self.assertEqual(units,original)
            self.assertEqual(merge_translation_units(units,roots=['query']),expected)

    def test_reused_parsed_tree_has_distinct_ids_in_each_translation_unit(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);database,files=self.sources(stage,{
                'root.c':'static unsigned state; static unsigned read_value(void){return state;}'})
            parsed,identity=load_ast(database,files[0]);original=copy.deepcopy(parsed)
            other=dict(identity,source=str(stage/'other.c'))
            tree,_=merge_translation_units([(parsed,identity),(parsed,other)])
            self.assertEqual(parsed,original)
            functions=[n for n in tree['inner'] if n.get('kind')=='FunctionDecl']
            self.assertEqual({n['name'] for n in functions},{'tu0:read_value','tu1:read_value'})
            declarations={n['name']:n for n in tree['inner'] if n.get('kind')=='VarDecl'}
            for prefix,function in zip(('tu0:','tu1:'),functions):
                reference=next(n['referencedDecl'] for n in walk(function) if n.get('kind')=='DeclRefExpr')
                self.assertEqual(reference['name'],prefix+'state')
                self.assertEqual(reference['id'],declarations[prefix+'state']['id'])
                self.assertTrue(function['id'].startswith(prefix))
            self.assertNotEqual(declarations['tu0:state']['id'],declarations['tu1:state']['id'])

    def test_missing_body_stays_blocked_and_selected_closure_works(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);database,files=self.sources(stage,{
                'root.c':HEADER+'unsigned helper(struct Obj *); unsigned query(void){return helper(current());}',
                'helper.c':HEADER+'unsigned helper(struct Obj *p){return p->first;}'})
            tree,_=load_program(database,files[0])
            self.assertTrue(Analyzer(tree,POLICY).analyze('query')['blockers'])
            tree,_=load_program(database,files[0],closure_sources=[files[1]])
            self.assertFalse(Analyzer(tree,POLICY).analyze('query')['blockers'])

if __name__=='__main__':
    if len(sys.argv)==2:CLANG=sys.argv.pop()
    unittest.main()
