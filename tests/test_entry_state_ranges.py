"""Capture proven inline-array ranges and reconstruct them on AArch64."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,load_ast,capture_header
from automated_entry_state import validate_snapshot
from reconstruct_entry_state import reconstruction_header
from freestanding_elf import prepare_target
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
CLANG='/opt/homebrew/opt/llvm@16/bin/clang'
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
MODEL='typedef struct State { unsigned index; unsigned values[8]; unsigned char bytes[20]; } State;\nState *current(void);\n'
FUNCTIONS='unsigned lookup(void){return current()->values[current()->index % 8U];}\nunsigned byte_lookup(void){return current()->bytes[current()->index & 15U];}\n'
BAD='''
unsigned unchecked(void){return current()->values[current()->index];}
unsigned negative(void){return current()->values[-1];}
unsigned outside(void){return current()->values[8];}
unsigned casted(void){return ((unsigned char *)current()->values)[current()->index & 3U];}
unsigned signed_modulo(int i){return current()->values[i % 8];}
unsigned pointer(unsigned *p){return p[0];}
unsigned constant(void){return current()->values[7];}
unsigned truncation(void){return current()->values[(unsigned char)257];}
'''
POLICY={'current':{'kind':'object_provider','reason':'fixture stable object','implementation':'State binding','snapshot_safe':True}}

class RangeTests(unittest.TestCase):
    def parse(self,stage):
        source=stage/'input.c';source.write_text(MODEL+FUNCTIONS+BAD)
        database=stage/'compile_commands.json';database.write_text(json.dumps([{'directory':str(stage),'file':str(source),
            'arguments':[CLANG,'-std=c11','-Wno-array-bounds','-c',str(source),'-o','input.o']}]))
        return load_ast(database,source)[0]

    def test_bounds_and_unresolved_ranges(self):
        with tempfile.TemporaryDirectory() as name:
            tree=self.parse(Path(name))
            plan=Analyzer(tree,POLICY).analyze('lookup')
            self.assertFalse(plan['blockers'])
            self.assertEqual({r['path'] for r in plan['entry_reads']},{'current()->index'}|{f'current()->values[{i}]' for i in range(8)})
            self.assertEqual(plan['memory_ranges'][0]['index_bounds'],[0,7])
            for root in ('unchecked','negative','outside','casted','signed_modulo','pointer','truncation'):
                with self.subTest(root=root):
                    blocked=Analyzer(tree,POLICY).analyze(root)
                    self.assertTrue(blocked['blockers'])
                    with self.assertRaises(ValueError):capture_header([blocked])
            constant=Analyzer(tree,POLICY).analyze('constant')
            self.assertEqual({r['path'] for r in constant['entry_reads']},{'current()->values[7]'})
            limited=Analyzer(tree,POLICY,max_range_elements=4).analyze('lookup')
            self.assertTrue(any(b['kind']=='range_limit' for b in limited['blockers']))

    def capture(self,stage,plans):
        (stage/'capture.h').write_text(capture_header(plans))
        source=stage/'capture.c';source.write_text(MODEL+FUNCTIONS+'''
#include <stdio.h>
#include "capture.h"
static State state;
State *current(void){return &state;}
int main(void) {
 unsigned indices[5]={0,7,100,31,0xffffffffU};
 for(unsigned i=0;i<8;++i) state.values[i]=0x90000000U+i;
 for(unsigned i=0;i<20;++i) state.bytes[i]=(unsigned char)(200+i);
 puts("[");
 for(unsigned invocation=0;invocation<5;++invocation) {
  state.index=indices[invocation];unsigned number=invocation<3 ? 1 : 2;
  struct osrec_entry_snapshot s;osrec_snapshot_init(&s);
  if(!(number==1 ? osrec_snapshot_lookup(&s) : osrec_snapshot_byte_lookup(&s))) return 1;
  unsigned raw=number==1 ? lookup() : byte_lookup();
  printf("{\\"format\\":\\"osrec-entry-snapshot-v1\\",\\"syscall\\":%u,\\"invocation\\":%u,\\"expected\\":%u,",number,invocation,raw);
  printf("\\"objects\\":[{\\"id\\":1,\\"type\\":\\"State\\"}],\\"roots\\":[{\\"name\\":\\"current()\\",\\"object_id\\":1}],\\"fields\\":[");
  for(unsigned j=0;j<s.field_count;++j) {
   struct osrec_snapshot_field *f=&s.fields[j];
   printf("{\\"object_id\\":%u,\\"name\\":\\"%s\\",\\"kind\\":\\"scalar\\",\\"bytes\\":%u,\\"data\\":\\"",f->object_id,f->name,f->size);
   for(unsigned k=0;k<f->size;++k) printf("%02x",f->bytes[k]);
   printf("\\"}%s",j+1==s.field_count ? "" : ",");
  }
  printf("]}%s\\n",invocation==4 ? "" : ",");
 }
 puts("]");return 0;
}
''')
        binary=stage/'capture';run([CLANG,'-std=c11','-I',ROOT/'include','-I',stage,source,ROOT/'runtime/entry_snapshot.c','-o',binary])
        return json.loads(run([binary]).stdout)

    def test_native_capture_to_aarch64_elf_and_raw(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);tree=self.parse(stage)
            plans=[Analyzer(tree,POLICY).analyze(root) for root in ('lookup','byte_lookup')]
            frames=self.capture(stage,plans);selected=[plans[f['syscall']-1] for f in frames]
            for frame,plan in zip(frames,selected):validate_snapshot(frame,plan)
            # These fixtures have no host pointers in serialized fields.
            self.assertEqual([len(f['fields']) for f in frames],[9,9,9,17,17])
            sources=stage/'sources';sources.mkdir()
            (sources/'entry_reconstruction.h').write_text(reconstruction_header(frames,selected))
            (sources/'entry_model.h').write_text('#include <stdint.h>\n'+MODEL)
            (sources/'entry_adapter.h').write_text(FUNCTIONS+'State *current(void){return osrec_bound_current;}\nuint32_t osrec_invoke(uint32_t number){return number==1 ? lookup() : byte_lookup();}\n')
            header='#define OSREC_CHECKPOINT_CALLS 5\nstruct checkpoint_call {uint32_t number,raw;};\nstatic const struct checkpoint_call checkpoint_calls[5]={'
            header+=','.join('{'+str(f['syscall'])+',UINT32_C('+str(f['expected'])+')}' for f in frames)+'};\n'
            (sources/'entry_checkpoint.h').write_text(header)
            args=SimpleNamespace(arch='aarch64',entry_address=0x40400000,result_address=0x40380000)
            flags=prepare_target(args,sources)
            image=stage/'ranges.elf';binary=stage/'ranges.bin'
            command=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
                '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),'-I',sources,
                sources/'start.S',ROOT/'integrations/rtl_aarch64/entry_state_replay.c','-o',image]
            compiled=subprocess.run(list(map(str,command)),capture_output=True,text=True,timeout=60)
            self.assertEqual(compiled.returncode,0,compiled.stderr)
            audit(image,LLVM);run([LLVM/'llvm-objcopy','-O','binary',image,binary])
            # Remove construction-time capture before target execution.
            (stage/'capture').unlink();(stage/'capture.c').unlink()
            result,raw=observe(image,QEMU);require_success(result)
            raw_result,binary_raw=observe(binary,QEMU,descriptor=image);require_success(raw_result)
            self.assertEqual(raw,binary_raw)
            self.assertEqual([c['raw_bits'] for c in result['actual_calls']],[0x90000000,0x90000007,0x90000004,215,215])
            self.assertEqual(result['states_restored'],5);self.assertEqual(result['unchanged_states'],5)
            # A write to a captured element that did not supply the return value
            # must still fail readonly replay validation.
            adapter=sources/'entry_adapter.h'
            adapter.write_text(FUNCTIONS+'State *current(void){return osrec_bound_current;}\nuint32_t osrec_invoke(uint32_t number){uint32_t raw=number==1 ? lookup() : byte_lookup();current()->values[6]^=1;return raw;}\n')
            compiled=subprocess.run(list(map(str,command)),capture_output=True,text=True,timeout=60)
            self.assertEqual(compiled.returncode,0,compiled.stderr)
            failed,_=observe(image,QEMU)
            self.assertEqual(failed['status'],3);self.assertEqual(failed['error'],20)
            with self.assertRaises(ValueError):require_success(failed)

if __name__=='__main__':
    if len(sys.argv)==4:CLANG=sys.argv[1];LLVM=Path(sys.argv[2]);QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
