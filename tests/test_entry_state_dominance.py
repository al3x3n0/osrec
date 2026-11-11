"""Only must-stores with explicit identity/isolation contracts can omit fields."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,load_ast,capture_header
CLANG='/opt/homebrew/opt/llvm@16/bin/clang'
POLICY={'current':{'kind':'object_provider','reason':'exclusive fixture object','implementation':'stable fixture binding','snapshot_safe':True,
    'stable_identity':True,'exclusive_state':True,'preserves_entry_state':True}}
SOURCE='''
struct Obj { unsigned value,other; unsigned array[4]; struct Obj *parent; };
struct Obj *current(void); void external(void);
unsigned overwrite(void){struct Obj *p=current();p->value=4;return p->value;}
unsigned copy_entry(void){struct Obj *p=current();p->value=p->other;return p->value;}
unsigned partial(void){struct Obj *p=current();*((unsigned char *)&p->value)=4;return p->value;}
unsigned conditional(unsigned x){struct Obj *p=current();if(x)p->value=4;return p->value;}
unsigned both(unsigned x){struct Obj *p=current();if(x)p->value=4;else p->value=5;return p->value;}
unsigned early(unsigned x){struct Obj *p=current();if(x)return p->other;p->value=4;return p->value;}
unsigned read_first(void){struct Obj *p=current();unsigned x=p->value;p->value=4;return p->value+x;}
unsigned alias(void){struct Obj *p=current();struct Obj *q=p;p->value=4;return q->value;}
unsigned ambiguous(unsigned x){struct Obj *p=current();struct Obj *q=x ? p : p->parent;q->value=4;return p->value;}
unsigned loop(unsigned x){struct Obj *p=current();while(x--)p->value=4;return p->value;}
unsigned loop_load(unsigned x){struct Obj *p=current();p->value=4;while(x--)p->other=p->value;return p->value;}
unsigned helper(struct Obj *p){return p->value;}
unsigned through_helper(void){struct Obj *p=current();p->value=4;return helper(p);}
unsigned external_barrier(void){struct Obj *p=current();p->value=4;external();return p->value;}
unsigned change_pointer(void){struct Obj *p=current();p->value=4;p=p->parent;return p->value;}
unsigned compound(void){struct Obj *p=current();p->value+=4;return p->value;}
unsigned unsequenced(void){struct Obj *p=current();p->value=4;return p->value+(p->other=1);}
unsigned indexed(void){struct Obj *p=current();p->array[2]=4;return p->array[2];}
unsigned range(unsigned x){struct Obj *p=current();p->array[x%4U]=4;return p->array[2];}
unsigned statement_early(unsigned x){struct Obj *p=current();({if(x)return 0;0;});p->value=4;return 0;}
unsigned statement_load(void){struct Obj *p=current();p->value=4;return ({p->value;});}
unsigned jump_skip(unsigned x){struct Obj *p=current();if(x)goto out;p->value=4;out:return p->value;}
unsigned jump_after_return(void){struct Obj *p=current();goto out;return 0;out:p->value=4;return p->value;}
unsigned jump_backward(unsigned x){struct Obj *p=current();if(x)goto load;store:p->value=4;load:if(x--)goto store;return p->value;}
unsigned jump_write_only(unsigned x){struct Obj *p=current();if(x)goto out;p->value=4;out:return 0;}
unsigned jump_expression(unsigned x){struct Obj *p=current();({if(x)goto out;0;});p->value=4;out:return p->value;}
'''
class DominanceTests(unittest.TestCase):
    def parse(self,stage):
        source=stage/'input.c';source.write_text(SOURCE)
        database=stage/'compile_commands.json';database.write_text(json.dumps([{'directory':str(stage),'file':str(source),
            'arguments':[CLANG,'-std=c11','-c',str(source),'-o','input.o']}]))
        return load_ast(database,source)[0]

    def test_jumps_disable_read_and_exit_store_omissions(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name))
            for root in ('jump_skip','jump_after_return','jump_backward','jump_expression','jump_write_only'):
                with self.subTest(root=root):
                    plan=Analyzer(tree,POLICY,prune_written=True,preserve_write_state=True).analyze(root)
                    self.assertFalse(plan['blockers'],plan['blockers'])
                    self.assertFalse(plan['dominated_reads'])
                    self.assertTrue(plan['write_state_preservation']['unsupported_control_flow'])
                    self.assertFalse(plan['write_state_preservation']['guaranteed_exit_stores'])
                    rows=plan['preserved_entry_fields'] if root=='jump_write_only' else plan['entry_reads']
                    self.assertEqual({r['path'] for r in rows},{'current()->value'})
                    capture_header([plan])

    def test_statement_expressions_do_not_prove_exit_overwrites(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name))
            plan=Analyzer(tree,POLICY,prune_written=True,preserve_write_state=True).analyze('statement_early')
            self.assertFalse(plan['blockers'])
            self.assertTrue(plan['write_state_preservation']['unsupported_control_flow'])
            self.assertFalse(plan['write_state_preservation']['guaranteed_exit_stores'])
            self.assertEqual({r['path'] for r in plan['preserved_entry_fields']},{'current()->value'})
            plan=Analyzer(tree,POLICY,prune_written=True).analyze('statement_load')
            self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'current()->value'})
            self.assertFalse(plan['dominated_reads'])

    def test_straight_branches_aliases_and_early_returns(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name))
            for root in ('overwrite','both','alias','indexed'):
                with self.subTest(root=root):
                    plan=Analyzer(tree,POLICY,prune_written=True).analyze(root)
                    self.assertFalse(plan['blockers']);self.assertFalse(plan['entry_reads'])
                    self.assertTrue(plan['dominated_reads']);self.assertFalse(plan['minimality_proven'])
            early=Analyzer(tree,POLICY,prune_written=True).analyze('early')
            self.assertEqual({r['path'] for r in early['entry_reads']},{'current()->other'})
            self.assertEqual({r['path'] for r in early['dominated_reads']},{'current()->value'})
            copied=Analyzer(tree,POLICY,prune_written=True).analyze('copy_entry')
            self.assertEqual({r['path'] for r in copied['entry_reads']},{'current()->other'})
            self.assertEqual({r['path'] for r in copied['dominated_reads']},{'current()->value'})
            both=Analyzer(tree,POLICY,prune_written=True).analyze('both')
            self.assertEqual(len(both['dominated_reads'][0]['covering_stores']),2)
            first=Analyzer(tree,POLICY,prune_written=True).analyze('read_first')
            self.assertEqual(len(first['entry_reads']),1);self.assertEqual(len(first['dominated_reads']),1)

    def test_uncertainty_retains_entry_reads(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name))
            for root in ('conditional','ambiguous','loop','loop_load','through_helper','external_barrier','change_pointer','compound','unsequenced','range','partial'):
                with self.subTest(root=root):
                    plan=Analyzer(tree,POLICY,prune_written=True).analyze(root)
                    expected=('current()->parent->value' if root=='change_pointer' else
                              'current()->array[2]' if root=='range' else 'current()->value')
                    self.assertIn(expected,{r['path'] for r in plan['entry_reads']})
                    if root=='change_pointer':
                        # The final read follows the reassigned pointer, not the overwritten original object.
                        self.assertEqual({r['path'] for r in plan['entry_reads']},
                                         {'current()->parent','current()->parent->value'})
            for contract in ('stable_identity','exclusive_state','preserves_entry_state'):
                policy={'current':{k:v for k,v in POLICY['current'].items() if k!=contract}}
                plan=Analyzer(tree,policy,prune_written=True).analyze('overwrite')
                self.assertTrue(plan['entry_reads']);self.assertFalse(plan['dominated_reads'])
            self.assertTrue(Analyzer(tree,POLICY).analyze('overwrite')['entry_reads'])

    def test_generated_capture_omits_only_overwritten_value(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);tree=self.parse(stage)
            plan=Analyzer(tree,POLICY,prune_written=True).analyze('overwrite')
            from reconstruct_entry_state import reconstruction_header
            frame={'format':'osrec-entry-snapshot-v1','objects':[{'id':1,'type':'Obj'}],'roots':[{'name':'current()','object_id':1}],'fields':[]}
            with self.assertRaisesRegex(ValueError,'write-effect'):reconstruction_header([frame],[plan])
            (stage/'capture.h').write_text(capture_header([plan]))
            source=stage/'run.c';source.write_text(SOURCE+'''
#include "capture.h"
static struct Obj object;
struct Obj *current(void){return &object;}
void external(void){}
int main(void){
 for(unsigned i=0;i<10;++i){object.value=100+i;struct osrec_entry_snapshot s;osrec_snapshot_init(&s);
  if(!osrec_snapshot_overwrite(&s) || s.object_count!=1 || s.field_count!=0) return 1;
  if(overwrite()!=4 || object.value!=4) return 2;
 }
 return 0;
}
''')
            output=stage/'plan.json';boundary=stage/'boundaries.json'
            boundary.write_text(json.dumps({'format':'osrec-entry-state-boundaries-v1','boundaries':POLICY}))
            subprocess.run([sys.executable,str(ROOT/'tools/entry_state.py'),'--compile-commands',str(stage/'compile_commands.json'),
                '--source',str(stage/'input.c'),'--root','overwrite','--boundaries',str(boundary),
                '--prune-written-fields','--out',str(output)],check=True,capture_output=True)
            self.assertFalse(json.loads(output.read_text())['plans'][0]['entry_reads'])
            binary=stage/'run';subprocess.run([CLANG,'-std=c11','-I',str(ROOT/'include'),'-I',str(stage),str(source),
                str(ROOT/'runtime/entry_snapshot.c'),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([binary],check=True)

if __name__=='__main__':
    if len(sys.argv)==2:CLANG=sys.argv.pop()
    unittest.main()
