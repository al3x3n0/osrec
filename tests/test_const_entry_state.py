"""Const object views retain typed bindings while replay owns mutable storage."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,load_ast,capture_header
from reconstruct_entry_state import reconstruction_header
from automated_entry_state import validate_snapshot
from freestanding_armv7 import run,audit
from freestanding_elf import prepare_target
from run_freestanding_armv7 import observe,require_success

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
MODEL='typedef struct Node {unsigned value; const struct Node *next;} Node;\n'
BODY='''unsigned query(const Node *read, Node *other) {
 return (read ? read->value+(read->next ? read->next->value : 0) : 0)+(other ? other->value : 0);
}
'''
CONTRACT={'kind':'object_argument','snapshot_safe':True,'reason':'stable fixture objects','implementation':'caller-held lifetime'}
POLICY={'query':{'read':CONTRACT,'other':CONTRACT}}


class ConstTests(unittest.TestCase):
    def parse(self,stage,text=MODEL+BODY,contracts=POLICY):
        source=stage/'input.c';source.write_text(text);database=stage/'compile_commands.json'
        database.write_text(json.dumps([{'directory':str(stage),'file':str(source),
            'arguments':[str(LLVM/'clang'),'-std=c11','-c',str(source)]}]))
        tree,_=load_ast(database,source)
        return Analyzer(tree,argument_objects=contracts).analyze('query')

    def frames(self):
        def value(oid,v):return {'object_id':oid,'name':'value','kind':'scalar','bytes':4,'data':v.to_bytes(4,'little').hex()}
        def edge(oid,target):return {'object_id':oid,'name':'next','kind':'edge','target_id':target}
        common={'format':'osrec-entry-snapshot-v1'}
        return [
            dict(common,objects=[{'id':1,'type':'Node'}],roots=[{'name':'osrec_argument_read()','object_id':1},
                {'name':'osrec_argument_other()','object_id':1}],fields=[value(1,17),edge(1,1)]),
            dict(common,objects=[{'id':1,'type':'Node'},{'id':2,'type':'Node'}],roots=[{'name':'osrec_argument_read()','object_id':1},
                {'name':'osrec_argument_other()','object_id':2}],fields=[value(1,17),edge(1,2),value(2,29)]),
            dict(common,objects=[{'id':1,'type':'Node'}],roots=[{'name':'osrec_argument_read()','object_id':0},
                {'name':'osrec_argument_other()','object_id':1}],fields=[value(1,29)])]

    def test_native_capture_and_host_restore_const_aliases_cycles_null(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);plan=self.parse(stage);self.assertFalse(plan['blockers'])
            self.assertEqual(plan['arguments'][0]['type'],'const Node *')
            (stage/'capture.h').write_text(capture_header([plan]))
            source=stage/'capture.c';source.write_text(MODEL+BODY+'''
#include <string.h>
#include "capture.h"
int main(void){
 Node n={17,0};n.next=&n;
 struct osrec_entry_snapshot s;osrec_snapshot_init(&s);
 if(!osrec_snapshot_query(&s,&n,&n) || s.object_count!=1 || s.field_count!=2 || s.root_count!=2) return 1;
 if(strcmp(s.objects[0].type,"Node") || s.roots[0].object_id!=s.roots[1].object_id || query(&n,&n)!=51) return 2;
 return 0;
}''')
            binary=stage/'capture';run([LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror','-I',ROOT/'include',source,
                ROOT/'runtime/entry_snapshot.c','-o',binary]);run([binary])
            frames=self.frames()
            for frame in frames:validate_snapshot(frame,plan)
            header=reconstruction_header(frames,[plan]*3)
            self.assertIn('static const Node * osrec_bound_osrec_argument_read;',header)
            source.write_text(MODEL+header+BODY+'''int main(void){
 unsigned expected[3]={51,75,29};
 for(unsigned i=0;i<3;++i){
  if(!osrec_restore(i) || !osrec_state_matches(i)) return 1;
  if(query(osrec_bound_osrec_argument_read,osrec_bound_osrec_argument_other)!=expected[i]) return 2;
  if(i==0 && (osrec_bound_osrec_argument_read!=osrec_bound_osrec_argument_other || osrec_bound_osrec_argument_read->next!=osrec_bound_osrec_argument_read)) return 3;
 }
 return 0;
}''')
            run([LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary]);run([binary])
            # The public binding still prevents writes through the const view.
            source.write_text(MODEL+header+'int main(void){osrec_bound_osrec_argument_read->value=1;return !osrec_restore(0) || !osrec_state_matches(0);}')
            result=subprocess.run([str(LLVM/'clang'),'-std=c11','-fsyntax-only',str(source)],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0);self.assertIn('const',result.stderr)
            # Top-level const on the argument pointer must not freeze replay's
            # binding slot when it switches frames.
            plan=self.parse(stage,MODEL+'unsigned query(const Node *const read){return read->value;}',{'query':{'read':CONTRACT}})
            frame={'format':'osrec-entry-snapshot-v1','objects':[{'id':1,'type':'Node'}],
                'roots':[{'name':'osrec_argument_read()','object_id':1}],
                'fields':[{'object_id':1,'name':'value','kind':'scalar','bytes':4,'data':'11000000'}]}
            header=reconstruction_header([frame],[plan])
            source.write_text(MODEL+header+'int main(void){return !osrec_restore(0) || !osrec_state_matches(0) || osrec_bound_osrec_argument_read->value!=17;}')
            run([LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary]);run([binary])

    def test_const_writes_declared_const_storage_and_volatile_reject(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);contracts={'query':{'read':CONTRACT}}
            texts=[
                MODEL+'unsigned query(const Node *read){((Node *)read)->value=1;return read->value;}',
                MODEL+'typedef const Node ReadNode; unsigned query(ReadNode *read){((Node*)read)->value=1;return read->value;}',
                'typedef struct Node {unsigned *value;} Node; unsigned query(const Node *read){*read->value=1;return 0;}',
                'typedef struct Node {const unsigned value;} Node; unsigned query(const Node *read){return read->value;}',
                'typedef struct Node {const unsigned values[2];} Node; unsigned query(const Node *read){return read->values[1];}',
                'typedef struct Node {struct Node *const next;} Node; unsigned query(const Node *read){return read->next!=0;}',
                'typedef struct Node {volatile unsigned value;} Node; unsigned query(const Node *read){return read->value;}']
            for text in texts:
                plan=self.parse(stage,text,contracts)
                with self.subTest(text=text),self.assertRaises(ValueError):capture_header([plan])
            with self.assertRaisesRegex(ValueError,'volatile argument'):
                self.parse(stage,MODEL+'typedef volatile Node Device; unsigned query(Device *read){return 0;}',contracts)
            with self.assertRaisesRegex(ValueError,'not a plain object'):
                self.parse(stage,MODEL+'typedef Node *Handle; unsigned query(Handle *read){return 0;}',contracts)
            plan=self.parse(stage);frame=self.frames()[0];bad=copy.deepcopy(plan)
            bad['state_writes']=[copy.deepcopy(next(r for r in bad['entry_reads'] if r['path']=='osrec_argument_read()->value'))]
            with self.assertRaisesRegex(ValueError,'readonly footprint'):reconstruction_header([frame],[bad])
            bad=copy.deepcopy(plan);bad['object_providers'][0]['return_type']='Node *'
            with self.assertRaises(ValueError):reconstruction_header([frame],[bad])
            # Removing pointee const does not permit changing the pointee's type.
            header=reconstruction_header([self.frames()[1]],[plan])
            source=stage/'wrong.c';source.write_text('struct Other {unsigned value;}; typedef struct Node {unsigned value;const struct Other *next;} Node;\n'+header+
                'int main(void){return !osrec_restore(0) || !osrec_state_matches(0);}')
            result=subprocess.run([str(LLVM/'clang'),'-std=c11','-fsyntax-only',str(source)],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0);self.assertIn('captured pointer target type differs',result.stderr)
            # Even an omitted const member makes bytewise object clearing unsafe.
            plan=self.parse(stage,MODEL+'unsigned query(const Node *read){return read->value;}',{'query':{'read':CONTRACT}})
            frame=self.frames()[0];frame['roots']=frame['roots'][:1];frame['fields']=frame['fields'][:1]
            header=reconstruction_header([frame],[plan])
            source.write_text('typedef struct Node {unsigned value;const unsigned hidden;} Node;\n'+header+
                'int main(void){return !osrec_restore(0) || !osrec_state_matches(0);}')
            result=subprocess.run([str(LLVM/'clang'),'-std=c11','-fsyntax-only',str(source)],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0);self.assertIn('const-qualified data member',result.stderr)

    def test_const_graph_replays_in_aarch64_elf_and_raw(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);plan=self.parse(stage);sources=stage/'sources';sources.mkdir()
            (sources/'entry_model.h').write_text(MODEL)
            (sources/'entry_reconstruction.h').write_text(reconstruction_header(self.frames(),[plan]*3))
            (sources/'entry_adapter.h').write_text(BODY+'uint32_t osrec_invoke(uint32_t number){(void)number;return query(osrec_bound_osrec_argument_read,osrec_bound_osrec_argument_other);}\n')
            (sources/'entry_checkpoint.h').write_text('#define OSREC_CHECKPOINT_CALLS 3\nstruct checkpoint_call {uint32_t number,raw;};\nstatic const struct checkpoint_call checkpoint_calls[3]={{1,51},{1,75},{1,29}};\n')
            args=SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000)
            flags=prepare_target(args,sources);image=stage/'const.elf';binary=stage/'const.bin'
            run([LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
                '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),'-I',sources,
                sources/'start.S',ROOT/'integrations/rtl_aarch64/entry_state_replay.c','-o',image])
            audit(image,LLVM);run([LLVM/'llvm-objcopy','-O','binary',image,binary])
            result,raw=observe(image,QEMU);require_success(result)
            other,raw_binary=observe(binary,QEMU,descriptor=image);require_success(other)
            self.assertEqual(raw,raw_binary)
            self.assertEqual([c['raw_bits'] for c in result['actual_calls']],[51,75,29])


if __name__=='__main__':
    if len(sys.argv)==3:LLVM=Path(sys.argv[1]);QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
