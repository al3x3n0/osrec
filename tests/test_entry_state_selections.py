"""Configured compile-time selections preserve lvalues, aliases and effects."""
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_entry_state as basic
import test_entry_state_loops as replay
import test_entry_state_multidimensional as matrix
from entry_state import Analyzer,capture_header,walk
from entry_state_program import load_program
from entry_capture import import_session
from export_entry_state import export,RequestError

POLICY=basic.POLICY
ISOLATED={'current':{**POLICY['current'],'stable_identity':True,'exclusive_state':True,'preserves_entry_state':True}}
RETAIN=None

class SelectionTests(unittest.TestCase):
    def parse(self,stage,text):return basic.EntryStateTests().parse(stage,basic.FIXTURE+text)[0]

    def test_pointer_results_and_unevaluated_alias_assignments(self):
        source='''struct Obj *unknown_object(void);
unsigned selected(void){struct Obj *p=_Generic(0,int:__builtin_choose_expr(-3,current(),unknown_object()),default:(struct Obj *)0);return p->value;}
unsigned default_selected(void){return _Generic(0.0,int:unknown_object(),default:current())->other;}
unsigned boolean_selected(void){return __builtin_choose_expr((_Bool)0,unknown_object(),current())->value;}
unsigned no_alias_poison(void){struct Obj *p=current();(void)_Generic((p=(struct Obj *)0),struct Obj *:0,default:0);(void)__builtin_choose_expr(1,0,(p=(struct Obj *)0,0));return p->value;}
struct Obj *chosen_return(void){return __builtin_choose_expr(1,current(),({return (struct Obj *)0;current();}));}
unsigned through_return(void){return chosen_return()->value;}
unsigned discarded_storage(void){return __builtin_choose_expr(1,current()->value,({static unsigned x;x++;}));}
unsigned discarded_vla(void){return __builtin_choose_expr(1,current()->value,sizeof(unsigned[external(0)]));}
'''
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),source)
            for root,field in (('selected','value'),('default_selected','other'),('boolean_selected','value'),('no_alias_poison','value'),('through_return','value'),('discarded_storage','value'),('discarded_vla','value')):
                with self.subTest(root=root):
                    plan=Analyzer(tree,POLICY).analyze(root)
                    self.assertFalse(plan['blockers'],plan['blockers']);self.assertEqual({r['path'] for r in plan['entry_reads']},{'current()->'+field})
                    self.assertNotIn('unknown_object',{c['callee'] for c in plan['call_sites']});capture_header([plan])

    def test_selected_lvalue_loads_writes_and_callback_targets(self):
        source='''unsigned chosen_load(void){return _Generic(0,int:current()->value,default:current()->other);}
unsigned chosen_store(void){__builtin_choose_expr(0,current()->other,current()->value)=7;return 0;}
unsigned chosen_compound(void){_Generic(0,int:current()->value,default:current()->other)+=3;return 0;}
unsigned first(struct Obj *p){return p->value;} unsigned second(struct Obj *p){return p->other;}
unsigned callback(void){return _Generic(0,int:first,default:second)(current());}
'''
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),source)
            for root in ('chosen_load','chosen_store','chosen_compound','callback'):
                plan=Analyzer(tree,POLICY).analyze(root)
                self.assertFalse(plan['blockers'],plan['blockers'])
                expected=set() if root=='chosen_store' else {'current()->value'}
                self.assertEqual({r['path'] for r in plan['entry_reads']},expected)
                self.assertEqual({r['path'] for r in plan['state_writes']},{'current()->value'} if root in ('chosen_store','chosen_compound') else set())
                capture_header([plan])
            self.assertIn('first',{c['callee'] for c in Analyzer(tree,POLICY).analyze('callback')['call_sites']})

    def test_selected_constant_indices_and_effects(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),'''int unknown_index(void);
struct Indexed{unsigned values[8];};struct Indexed *indexed_object(void);
unsigned constant(void){return indexed_object()->values[_Generic(unknown_index(),int:3U,default:99U)];}
unsigned masked(unsigned i){return indexed_object()->values[i & __builtin_choose_expr(0,99U,7U)];}
unsigned effect(void){return _Generic(external(0),int:current()->value++,default:external(1));}
unsigned bad_index(void){return indexed_object()->values[__builtin_choose_expr(1,unknown_index(),3U)];}
''')
            policy={**POLICY,'indexed_object':POLICY['current']}
            for root,indices in (('constant',range(3,4)),('masked',range(8))):
                plan=Analyzer(tree,policy).analyze(root);self.assertFalse(plan['blockers'],plan['blockers'])
                self.assertEqual({r['path'] for r in plan['entry_reads']},{'indexed_object()->values['+str(i)+']' for i in indices})
                self.assertNotIn('unknown_index',{c['callee'] for c in plan['call_sites']});capture_header([plan])
            plan=Analyzer(tree,POLICY).analyze('effect');self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['state_writes']},{'current()->value'})
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'current()->value'})
            self.assertNotIn('external',{c['callee'] for c in plan['call_sites']})
            self.assertTrue(Analyzer(tree,policy).analyze('bad_index')['blockers'])

    def test_selected_unknown_effects_and_missing_metadata_stay_blocked(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),'''unsigned unknown_effect(void){return __builtin_choose_expr(1,external(1),current()->value);}
unsigned null_result(void){return _Generic(0,int:(struct Obj *)0,default:current())->value;}
unsigned assembly(void){return __builtin_choose_expr(1,({__asm__ volatile("");1U;}),current()->value);}
unsigned good(void){return _Generic(0,int:current()->value,default:current()->other);}
unsigned choose(void){return __builtin_choose_expr(1,current()->value,current()->other);}
unsigned persistent(void){static unsigned x;return _Generic(0,int:x,default:0);}
unsigned vla_size(void){return __builtin_choose_expr(1,sizeof(unsigned[current()->value++]),0);}
''')
            for root in ('unknown_effect','null_result','assembly','persistent','vla_size'):
                plan=Analyzer(tree,POLICY).analyze(root);self.assertTrue(plan['blockers'])
                with self.assertRaises(ValueError):capture_header([plan])
            ambiguous=copy.deepcopy(tree)
            body=next(n for n in walk(ambiguous) if n.get('kind')=='FunctionDecl' and n.get('name')=='good')
            node=next(n for n in walk(body) if n.get('kind')=='GenericSelectionExpr')
            for association in node['inner']:
                if association.get('associationKind'):association['selected']=True
            plan=Analyzer(ambiguous,POLICY).analyze('good')
            self.assertIn('unsupported_construct',{b['kind'] for b in plan['blockers']})
            for kind,root in (('GenericSelectionExpr','good'),('ChooseExpr','choose')):
                damaged=copy.deepcopy(tree)
                body=next(n for n in walk(damaged) if n.get('kind')=='FunctionDecl' and n.get('name')==root)
                node=next(n for n in walk(body) if n.get('kind')==kind)
                if kind=='GenericSelectionExpr':
                    for association in node['inner']:association.pop('selected',None)
                else:node['inner'][0].pop('value',None)
                plan=Analyzer(damaged,POLICY).analyze(root)
                self.assertIn('unsupported_construct',{b['kind'] for b in plan['blockers']})
                with self.assertRaises(ValueError):capture_header([plan])

    def test_store_omissions_and_selected_early_exit_preservation(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name),'''unsigned overwrite(void){struct Obj *p=current();p->value=4;return _Generic(external(0),int:p->value,default:p->other);}
unsigned early_exit(unsigned x){__builtin_choose_expr(1,({if(x)return 0;0;}),0);current()->value=4;return 0;}
''')
            plan=Analyzer(tree,ISOLATED,prune_written=True,preserve_write_state=True).analyze('overwrite')
            self.assertFalse(plan['blockers']);self.assertFalse(plan['entry_reads'])
            self.assertEqual({r['path'] for r in plan['dominated_reads']},{'current()->value'})
            plan=Analyzer(tree,ISOLATED,prune_written=True,preserve_write_state=True).analyze('early_exit')
            self.assertFalse(plan['blockers']);self.assertFalse(plan['write_state_preservation']['guaranteed_exit_stores'])
            self.assertEqual({r['path'] for r in plan['preserved_entry_fields']},{'current()->value'})

    def test_translation_unit_aliases_and_static_callbacks(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);entries=[];files=[]
            header='struct Obj{unsigned value,other;struct Obj *parent;};struct Obj *current(void);'
            sources={'root.c':header+'struct Obj *get(void);unsigned other(struct Obj *);static unsigned local(struct Obj *p){return p->value;}unsigned query(void){return _Generic(0,int:local,default:other)(get());}',
                'helper.c':header+'struct Obj *get(void){return __builtin_choose_expr(1,current(),(struct Obj *)0);}unsigned other(struct Obj *p){return p->other;}'}
            for filename,text in sources.items():
                path=stage/filename;path.write_text(text);files.append(path)
                entries.append({'directory':str(stage),'file':str(path),'arguments':[basic.CLANG,'-std=c11','-c',str(path)]})
            db=stage/'compile_commands.json';db.write_text(json.dumps(entries))
            tree,_=load_program(db,files[0],all_sources=True);plan=Analyzer(tree,POLICY).analyze('query')
            self.assertFalse(plan['blockers'],plan['blockers']);self.assertEqual({r['path'] for r in plan['entry_reads']},{'current()->value'})
            self.assertIn('tu0:local',{c['callee'] for c in plan['call_sites']});capture_header([plan])

    def test_native_capture_and_relocated_selected_lvalue_replay(self):
        paint=matrix.PAINT.replace('state->values[r][c]=','__builtin_choose_expr(1,state->values[r][c],0)=')
        total='int unknown(void);\n'+matrix.TOTAL.replace('result+=state->values[r][c];','result+=_Generic(unknown(),int:state->values[r][c],default:0);')
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for mode in ('independent','continuous'):
                with patch.object(replay,'MODEL',matrix.MODEL):
                    plan,spec,capture,plans=replay.project(stage/(mode+'-inputs'),mode,paint,total,matrix.MAIN)
                self.assertEqual(len(plans[0]['preserved_entry_fields']),8);self.assertEqual(len(plans[1]['entry_reads']),8)
                self.assertNotIn('unknown',{c['callee'] for c in plans[1]['call_sites']})
                imported=stage/(mode+'-request');import_session(plan,spec,capture,imported);request=imported/'request.json'
                for bank in (0x40200000,0x40400000):
                    out=stage/(mode+hex(bank));report=export(replay.args_for(request,out,bank));o=report['target_observations']
                    self.assertEqual([c['raw_bits'] for c in o['actual_calls']],[0,36,0,333,0,84,0,84])
                    self.assertEqual(o['states_verified'],8)
                    if RETAIN is not None:shutil.copytree(out,RETAIN/mode/hex(bank))
                bodies=imported/'support-bodies.c';source=bodies.read_text()
                bodies.write_text(source.replace('=value+r*4+c;','=value+r*4+c+1;'))
                with self.assertRaises(RequestError) as caught:export(replay.args_for(request,stage/(mode+'-wrong-store')))
                self.assertIn('target replay diverged',str(caught.exception))
                if RETAIN is not None:(RETAIN/mode/'fault.txt').write_text(str(caught.exception))

if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:replay.LLVM=Path(sys.argv[1]);replay.QEMU=sys.argv[2];basic.CLANG=str(replay.LLVM/'clang');sys.argv=sys.argv[:1]
    unittest.main()
