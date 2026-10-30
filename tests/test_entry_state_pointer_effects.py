"""Fixed-lifetime pointer rebinding: identity checks and host-free AArch64 replay."""
import copy
import json
import shutil
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,load_ast,capture_header
from reconstruct_entry_state import reconstruction_header
from freestanding_elf import prepare_target
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
CLANG='/opt/homebrew/opt/llvm@16/bin/clang'
NATIVE_CC=shutil.which('cc') or CLANG
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
MODEL='typedef struct Obj { unsigned value; struct Obj *next; } Obj;\nObj *current(void); Obj *alternate(void);\n'
BODY='''unsigned rebind(unsigned step){
 unsigned raw=current()->value+alternate()->value;
 if(current()->next) raw+=current()->next->value;
 /* Keep the alternate edge in the captured footprint. */
 if(alternate()->next) raw+=0;
 if(step==1) current()->next=0;
 else if(step==2) current()->next=current();
 else current()->next=alternate();
 return raw;
}
'''
POLICY={name:{'kind':'object_provider','reason':'fixture objects remain live throughout replay',
    'implementation':'fixed object binding','snapshot_safe':True} for name in ('current','alternate')}

class PointerEffectTests(unittest.TestCase):
    def fixture(self,stage,body=BODY,objects='static Obj a={99,0},b={99,0};',setup='a.next=&a;b.next=&a;',post_effects=False,preserve_write_state=False,policy=None):
        source=stage/'input.c';source.write_text(MODEL+body)
        database=stage/'compile_commands.json';database.write_text(json.dumps([{'directory':str(stage),'file':str(source),
            'arguments':[CLANG,'-std=c11','-c',str(source),'-o','input.o']}]))
        plan=Analyzer(load_ast(database,source)[0],POLICY if policy is None else policy,
            prune_written=preserve_write_state,preserve_write_state=preserve_write_state).analyze('rebind')
        self.assertFalse(plan['blockers'],plan['blockers'])
        from automated_entry_state import effect_plan
        hooks=[plan]+([{**effect_plan(plan),'root':'effects_rebind'}] if post_effects else [])
        (stage/'capture.h').write_text(capture_header(hooks))
        capture=stage/'capture.c';capture.write_text(MODEL+body+r'''
#include <stdio.h>
#include "capture.h"
static Obj a={99,0},b={99,0};
Obj *current(void){return &a;} Obj *alternate(void){return &b;}
static struct osrec_entry_snapshot ids,states[8];
static void print_state(struct osrec_entry_snapshot *s,unsigned step){
 printf("{\"format\":\"osrec-entry-snapshot-v1\",\"objects\":[");
 for(unsigned i=0;i<s->object_count;++i){
  struct osrec_snapshot_object *o=&s->objects[i];
  printf("%s{\"id\":%u,\"session_id\":%u,\"type\":\"%s\"}",i?",":"",o->id,
   osrec_snapshot_identity(&ids,o->address,o->type),o->type);
 }
 printf("],\"roots\":[");
 for(unsigned i=0;i<s->root_count;++i)
  printf("%s{\"name\":\"%s\",\"object_id\":%u}",i?",":"",s->roots[i].name,s->roots[i].object_id);
 printf("],\"arguments\":[{\"name\":\"step\",\"bytes\":4,\"data\":\"%02x000000\"}],\"fields\":[",step);
 for(unsigned i=0;i<s->field_count;++i){
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
int main(void){
 a.next=&a;b.next=&a;osrec_snapshot_init(&ids);
 for(unsigned i=0;i<4;++i){
  osrec_snapshot_init(&states[i*2]);if(!osrec_snapshot_rebind(&states[i*2])) return 1;
  rebind(i);
  osrec_snapshot_init(&states[i*2+1]);if(!osrec_snapshot_rebind(&states[i*2+1])) return 2;
 }
 puts("[");
 for(unsigned i=0;i<8;++i){if(i) puts(",");print_state(&states[i],i/2);}
 puts("]");return 0;
}
'''.replace('static Obj a={99,0},b={99,0};',objects).replace('a.next=&a;b.next=&a;',setup)
   .replace('osrec_snapshot_rebind(&states[i*2+1])',
            ('osrec_snapshot_effects_rebind' if post_effects else 'osrec_snapshot_rebind')+'(&states[i*2+1])'))
        executable=stage/'capture'
        run([NATIVE_CC,'-std=c11','-I',ROOT/'include','-I',stage,capture,ROOT/'runtime/entry_snapshot.c','-o',executable])
        states=json.loads(run([executable]).stdout)
        executable.unlink();capture.unlink()
        return states[::2],states[1::2],[plan]*4

    def header(self,entries,posts,plans):
        return reconstruction_header(entries,plans,post_states=posts,scalar_arguments=True,continuous=True)

    def test_identity_lifetime_and_write_footprint_rejections(self):
        with tempfile.TemporaryDirectory() as directory:
            entries,posts,plans=self.fixture(Path(directory))
            self.header(entries,posts,plans)
            for change in ('new','reuse','unwritten','binding','missing','nested','pointer_pointer'):
                with self.subTest(change=change):
                    e,p,s=copy.deepcopy((entries,posts,plans))
                    edge=lambda state,owner:next(f for f in state['fields'] if f['kind']=='edge' and f['object_id']==owner)
                    if change=='new':p[0]['objects'].append({'id':3,'session_id':30,'type':'Obj'});edge(p[0],1)['target_id']=3
                    elif change=='reuse':p[0]['objects'][1]['session_id']=30
                    elif change=='unwritten':edge(p[0],2)['target_id']=2
                    elif change=='binding':p[0]['roots'][0]['object_id']=2
                    elif change=='missing':e[0]['objects'][0].pop('session_id')
                    elif change=='nested':s[0]['state_writes'][0]['path']='current()->next->next'
                    else:s[0]['state_writes'][0]['type']='Obj **'
                    with self.assertRaises(ValueError):self.header(e,p,s)
            with self.assertRaisesRegex(ValueError,'pointer writes require continuous'):
                reconstruction_header(entries,plans,post_states=posts,scalar_arguments=True)
            # A reviewed model with incompatible target storage must fail to compile.
            wrong=copy.deepcopy(plans)
            for plan in wrong:
                for provider in plan['object_providers']:
                    if provider['function']=='alternate':provider['return_type']='Other *'
            source=Path(directory)/'wrong-type.c'
            source.write_text('typedef struct Obj {unsigned value;struct Obj *next;} Obj;\n'
                'typedef struct Other {unsigned value;Obj *next;} Other;\n'+self.header(entries,posts,wrong))
            import subprocess
            compiled=subprocess.run([NATIVE_CC,'-std=c11','-fsyntax-only',str(source)],capture_output=True,text=True)
            self.assertNotEqual(compiled.returncode,0)
            self.assertIn('captured pointer target type differs',compiled.stderr)

    def test_aarch64_elf_raw_and_equal_value_wrong_pointer(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory);entries,posts,plans=self.fixture(stage)
            sources=stage/'sources';sources.mkdir()
            (sources/'entry_model.h').write_text('#include <stdint.h>\n'+MODEL)
            (sources/'entry_reconstruction.h').write_text(self.header(entries,posts,plans))
            adapter=sources/'entry_adapter.h'
            bindings='Obj *current(void){return osrec_bound_current;}\nObj *alternate(void){return osrec_bound_alternate;}\n'
            invoke='uint32_t osrec_invoke(uint32_t number){(void)number;static unsigned i;return rebind(osrec_argument(i++,0));}\n'
            adapter.write_text(BODY+bindings+invoke)
            (sources/'entry_checkpoint.h').write_text('#define OSREC_CHECKPOINT_CALLS 4\nstruct checkpoint_call {uint32_t number,raw;};\nstatic const struct checkpoint_call checkpoint_calls[4]={{1,297},{1,297},{1,198},{1,297}};\n')
            flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000),sources)
            image=stage/'pointers.elf';binary=stage/'pointers.bin'
            command=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
                '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),'-I',sources,
                sources/'start.S',ROOT/'integrations/rtl_aarch64/entry_state_replay.c','-o',image]
            run(command);audit(image,LLVM);run([LLVM/'llvm-objcopy','-O','binary',image,binary])
            result,raw=observe(image,QEMU);require_success(result)
            raw_result,binary_raw=observe(binary,QEMU,descriptor=image);require_success(raw_result)
            self.assertEqual(raw,binary_raw)
            self.assertEqual(result['states_restored'],1)
            self.assertEqual(result['states_verified'],4)
            self.assertEqual(result['entry_states_checked'],4)
            # Both objects contain 99; return values alone cannot distinguish them.
            adapter.write_text(BODY.replace('else current()->next=alternate();','else current()->next=current();')+bindings+invoke)
            run(command);audit(image,LLVM)
            failed,_=observe(image,QEMU)
            self.assertEqual(failed['actual_calls'][0]['raw_bits'],297)
            self.assertEqual(failed['error'],20)
            with self.assertRaises(ValueError):require_success(failed)

if __name__=='__main__':
    if len(sys.argv)==4:CLANG=sys.argv[1];LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
