"""Typed argument objects: configured discovery, native capture and target replay."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,load_ast,capture_header
from entry_state_program import load_program
from automated_entry_state import validate_snapshot,effect_plan
from reconstruct_entry_state import reconstruction_header
from freestanding_elf import prepare_target
from freestanding_armv7 import audit,run
from run_freestanding_armv7 import observe,require_success

CLANG='/opt/homebrew/opt/llvm@16/bin/clang'
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
MODEL='typedef struct Node { unsigned value; unsigned values[4]; struct Node *next; } Node;\n'
FUNCTION='''unsigned query(Node *left, unsigned index, Node *right) {
 unsigned value=left ? left->values[index & 3U] : 0;
 if(right && right->next) value+=right->next->value;
 return value;
}
'''
CONTRACT={'kind':'object_argument','reason':'caller holds fixture objects stable',
          'implementation':'entry argument binding under caller-owned lifetime','snapshot_safe':True}
CONTRACTS={'query':{'left':CONTRACT,'right':CONTRACT}}


class ArgumentTests(unittest.TestCase):
    def parse(self,stage,text=MODEL+FUNCTION):
        source=stage/'input.c';source.write_text(text)
        database=stage/'compile_commands.json'
        database.write_text(json.dumps([{'directory':str(stage),'file':str(source),
            'arguments':[CLANG,'-std=c11','-c',str(source),'-o','input.o']}]))
        return load_ast(database,source)[0],database,source

    def plan(self,tree):return Analyzer(tree,argument_objects=CONTRACTS).analyze('query')

    def test_discovery_and_cli_contract_provenance(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);tree,database,source=self.parse(stage);plan=self.plan(tree)
            self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},
                {f'osrec_argument_left()->values[{i}]' for i in range(4)}|
                {'osrec_argument_right()->next','osrec_argument_right()->next->value'})
            unbound=Analyzer(tree).analyze('query')
            with self.assertRaises(ValueError):capture_header([unbound])
            policy=stage/'boundaries.json'
            policy.write_text(json.dumps({'format':'osrec-entry-state-boundaries-v1',
                'boundaries':{},'argument_objects':CONTRACTS}))
            output=stage/'plan.json';header=stage/'capture.h'
            run([sys.executable,ROOT/'tools/entry_state.py','--compile-commands',database,
                '--source',source,'--root','query','--boundaries',policy,'--out',output,'--capture-header',header])
            report=json.loads(output.read_text())
            self.assertEqual(report['plans'][0]['object_providers'],plan['object_providers'])
            self.assertEqual(report['snapshot_generation'],'generated')
            self.assertEqual(header.read_text(),capture_header([plan]))

    def test_contracts_and_unsupported_argument_types_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);tree,_,_=self.parse(stage)
            for key,value in [('snapshot_safe',False),('reason',''),('implementation',''),('kind','object_provider')]:
                contracts=copy.deepcopy(CONTRACTS);contracts['query']['left'][key]=value
                with self.subTest(key=key),self.assertRaises(ValueError):
                    Analyzer(tree,argument_objects=contracts).analyze('query')
            with self.assertRaisesRegex(ValueError,'unknown root argument'):
                Analyzer(tree,argument_objects={'query':{'missing':CONTRACT}}).analyze('query')
            for typ in ('Node **','volatile Node *','unsigned (*)(void)','const void *','void *','unsigned int'):
                parameter='unsigned (*left)(void)' if '(' in typ else typ+' left'
                tree,_,_=self.parse(stage,MODEL+'unsigned query('+parameter+'){return 0;}')
                with self.subTest(typ=typ),self.assertRaises(ValueError):
                    Analyzer(tree,argument_objects={'query':{'left':CONTRACT}}).analyze('query')

    def capture(self,stage,plan):
        (stage/'capture.h').write_text(capture_header([plan]))
        source=stage/'capture.c'
        source.write_text(MODEL+FUNCTION+r'''
#include <stdio.h>
#include "capture.h"
static void emit(struct osrec_entry_snapshot *s,unsigned invocation,unsigned index,unsigned expected) {
 printf("{\"format\":\"osrec-entry-snapshot-v1\",\"syscall\":%u,\"expected\":%u,",invocation,expected);
 printf("\"arguments\":[{\"name\":\"index\",\"bytes\":4,\"data\":\"");
 for(unsigned i=0;i<4;++i) printf("%02x",(index>>(8*i))&255U);
 printf("\"}],\"objects\":[");
 for(unsigned i=0;i<s->object_count;++i) printf("%s{\"id\":%u,\"type\":\"%s\"}",i?",":"",s->objects[i].id,s->objects[i].type);
 printf("],\"roots\":[");
 for(unsigned i=0;i<s->root_count;++i) printf("%s{\"name\":\"%s\",\"object_id\":%u}",i?",":"",s->roots[i].name,s->roots[i].object_id);
 printf("],\"fields\":[");
 for(unsigned i=0;i<s->field_count;++i) {
  struct osrec_snapshot_field *f=&s->fields[i];
  printf("%s{\"object_id\":%u,\"name\":\"%s\",",i?",":"",f->object_id,f->name);
  if(f->is_edge) printf("\"kind\":\"edge\",\"target_id\":%u}",f->target_id);
  else {
   printf("\"kind\":\"scalar\",\"bytes\":%u,\"data\":\"",f->size);
   for(unsigned j=0;j<f->size;++j) printf("%02x",f->bytes[j]);
   printf("\"}");
  }
 }
 printf("]}");
}
int main(void) {
 Node a={17,{100,101,102,103},0},b={29,{200,201,202,203},0};
 Node *left[5]={&a,&a,0,&a,0},*right[5]={&b,&a,&b,0,0};
 unsigned indexes[5]={0,0xffffffffU,7,6,0};
 puts("[");
 for(unsigned i=0;i<5;++i) {
  a.next=&a;b.next=&a;
  struct osrec_entry_snapshot s;osrec_snapshot_init(&s);
  if(!osrec_snapshot_query(&s,left[i],right[i])) return 1;
  emit(&s,i,indexes[i],query(left[i],indexes[i],right[i]));
  puts(i==4 ? "" : ",");
 }
 puts("]");return 0;
}
''')
        binary=stage/'capture'
        run([CLANG,'-std=c11','-Wall','-Wextra','-Werror','-I',ROOT/'include',source,
             ROOT/'runtime/entry_snapshot.c','-o',binary])
        frames=json.loads(run([binary]).stdout)
        for frame in frames:validate_snapshot(frame,plan)
        return frames

    def test_native_capture_and_host_reconstruction_aliases_nulls(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);tree,_,_=self.parse(stage);plan=self.plan(tree);frames=self.capture(stage,plan)
            self.assertEqual([f['expected'] for f in frames],[117,120,17,102,0])
            self.assertEqual([len(f['objects']) for f in frames],[2,1,2,1,0])
            self.assertEqual(frames[1]['roots'][0]['object_id'],frames[1]['roots'][1]['object_id'])
            header=reconstruction_header(frames,[plan]*5,scalar_arguments=True)
            body=MODEL+header+FUNCTION+'''int main(void) {
 for(unsigned i=0;i<5;++i) {
  unsigned expected[5]={117,120,17,102,0};
  if(!osrec_restore(i) || !osrec_state_matches(i)) return 1;
  if(query(osrec_bound_osrec_argument_left,osrec_argument(i,1),osrec_bound_osrec_argument_right)!=expected[i]) return 2;
  if(i==1 && (osrec_bound_osrec_argument_left!=osrec_bound_osrec_argument_right || osrec_bound_osrec_argument_left->next!=osrec_bound_osrec_argument_left)) return 3;
 }
 return 0;
}'''
            source=stage/'replay.c';source.write_text(body);binary=stage/'replay'
            run([CLANG,'-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary]);run([binary])

    def test_invalid_bindings_and_pointer_bytes_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);tree,_,_=self.parse(stage);plan=self.plan(tree);frame=self.capture(stage,plan)[0]
            for change in ('index','name','type','safe','kind','missing','extra'):
                schema=copy.deepcopy(plan);p=schema['object_providers'][0]
                if change=='index':p['argument_index']=1
                if change=='name':p['argument']='absent'
                if change=='type':p['return_type']='Other *'
                if change=='safe':p['contract']['snapshot_safe']=False
                if change=='kind':p['binding_kind']='unknown'
                if change=='missing':del p['binding_kind']
                if change=='extra':schema['object_providers'].append(copy.deepcopy(p))
                with self.subTest(change=change),self.assertRaises(ValueError):reconstruction_header([frame],[schema],scalar_arguments=True)
            bad=copy.deepcopy(frame)
            next(row for row in bad['fields'] if row['kind']=='edge')['data']='0000000000000000'
            with self.assertRaises(ValueError):validate_snapshot(bad,plan)
            bad=copy.deepcopy(frame);bad['arguments'].insert(0,{'name':'left','bytes':8,'data':'0000000000000000'})
            with self.assertRaises(ValueError):reconstruction_header([bad],[plan],scalar_arguments=True)

    def test_cross_translation_unit_argument_closure(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            root=stage/'root.c';root.write_text(MODEL+'unsigned helper(Node *); unsigned query(Node *left){return helper(left);}')
            helper=stage/'helper.c';helper.write_text(MODEL+'unsigned helper(Node *p){return p->next->value;}')
            database=stage/'compile_commands.json';database.write_text(json.dumps([
                {'directory':str(stage),'file':str(s),'arguments':[CLANG,'-std=c11','-c',str(s)]} for s in (root,helper)]))
            tree,_=load_program(database,root,all_sources=True)
            plan=Analyzer(tree,argument_objects={'query':{'left':CONTRACT}}).analyze('query')
            self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},
                {'osrec_argument_left()->next','osrec_argument_left()->next->value'})
            self.assertIn('Node * osrec_argument_left',capture_header([plan]))

    def test_provider_and_argument_can_alias(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            tree,_,_=self.parse(stage,MODEL+'Node *current(void); unsigned query(Node *left){return left->value+current()->value;}')
            boundary={'current':{'kind':'object_provider','reason':'stable fixture current object',
                'implementation':'fixture current binding','snapshot_safe':True}}
            plan=Analyzer(tree,boundary,argument_objects={'query':{'left':CONTRACT}}).analyze('query')
            (stage/'capture.h').write_text(capture_header([plan]))
            source=stage/'mixed.c';source.write_text(MODEL+'Node *current(void);\n'+'''
#include "capture.h"
static Node node={17,{0,0,0,0},0};
Node *current(void){return &node;}
int main(void){struct osrec_entry_snapshot s;osrec_snapshot_init(&s);
 if(!osrec_snapshot_query(&s,&node)) return 1;
 if(s.object_count!=1 || s.root_count!=2 || s.field_count!=1) return 2;
 return s.roots[0].object_id!=s.roots[1].object_id;
}
''')
            binary=stage/'mixed';run([CLANG,'-std=c11','-Wall','-Wextra','-Werror','-I',ROOT/'include',source,
                ROOT/'runtime/entry_snapshot.c','-o',binary]);run([binary])
            conflict=MODEL+'Node *osrec_argument_left(void){return 0;} unsigned query(Node *left){return left->value;}'
            tree,_,_=self.parse(stage,conflict)
            with self.assertRaisesRegex(ValueError,'reserved argument binding name conflicts'):
                Analyzer(tree,argument_objects={'query':{'left':CONTRACT}}).analyze('query')

    def test_pointer_only_and_write_effect_reconstruction(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);tree,_,_=self.parse(stage,MODEL+'unsigned query(Node *left){left->value+=3;return left->value;}')
            plan=Analyzer(tree,argument_objects={'query':{'left':CONTRACT}}).analyze('query')
            field={'object_id':1,'name':'value','kind':'scalar','bytes':4,'data':'11000000'}
            frame={'format':'osrec-entry-snapshot-v1','objects':[{'id':1,'type':'Node'}],
                   'roots':[{'name':'osrec_argument_left()','object_id':1}],'fields':[field]}
            post=copy.deepcopy(frame);post['fields'][0]['data']='14000000'
            # Captured pointer arguments never enter the scalar argument array.
            header=reconstruction_header([frame],[plan],post_states=[post])
            source=stage/'effects.c';source.write_text(MODEL+header+'''int main(void){
 if(!osrec_restore(0) || osrec_state_matches(0)) return 1;
 osrec_bound_osrec_argument_left->value+=3;
 return !osrec_state_matches(0);
}''')
            binary=stage/'effects';run([CLANG,'-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary]);run([binary])
            self.assertIn('Node * osrec_argument_left',capture_header([effect_plan(plan)]))

    def test_aarch64_elf_raw_replay_after_capture_removal(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);tree,_,_=self.parse(stage);plan=self.plan(tree);frames=self.capture(stage,plan)
            sources=stage/'sources';sources.mkdir()
            (sources/'entry_reconstruction.h').write_text(reconstruction_header(frames,[plan]*5,scalar_arguments=True))
            (sources/'entry_model.h').write_text(MODEL)
            adapter=FUNCTION+'''uint32_t osrec_invoke(uint32_t number) {
 return query(osrec_bound_osrec_argument_left,osrec_argument(number,1),osrec_bound_osrec_argument_right);
}
'''
            (sources/'entry_adapter.h').write_text(adapter)
            (sources/'entry_checkpoint.h').write_text('#define OSREC_CHECKPOINT_CALLS 5\nstruct checkpoint_call {uint32_t number,raw;};\nstatic const struct checkpoint_call checkpoint_calls[5]={'+
                ','.join('{'+str(i)+','+str(f['expected'])+'}' for i,f in enumerate(frames))+'};\n')
            args=SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000)
            flags=prepare_target(args,sources);image=stage/'arguments.elf';binary=stage/'arguments.bin'
            command=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
                '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),'-I',sources,
                sources/'start.S',ROOT/'integrations/rtl_aarch64/entry_state_replay.c','-o',image]
            run(command);audit(image,LLVM);run([LLVM/'llvm-objcopy','-O','binary',image,binary])
            (stage/'capture').unlink();(stage/'capture.c').unlink();(stage/'input.c').unlink()
            result,raw=observe(image,QEMU);require_success(result)
            other,raw_binary=observe(binary,QEMU,descriptor=image);require_success(other)
            self.assertEqual(raw,raw_binary)
            self.assertEqual([c['raw_bits'] for c in result['actual_calls']],[117,120,17,102,0])
            self.assertEqual(result['states_restored'],5)
            # Mutation changes a captured but unselected array element.
            (sources/'entry_adapter.h').write_text(adapter.replace('return query(',
                'if(number==0) osrec_bound_osrec_argument_left->values[3]^=1; return query('))
            run(command);failed,_=observe(image,QEMU)
            self.assertEqual((failed['status'],failed['error']),(3,20))


if __name__=='__main__':
    if len(sys.argv)==4:CLANG=sys.argv[1];LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
