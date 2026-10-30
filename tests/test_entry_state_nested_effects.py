"""Nested scalar effects use entry-resolved owners and stable pointer paths."""
import copy
import json
import hashlib
import shutil
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

import test_entry_state_pointer_effects as fixture
from reconstruct_entry_state import reconstruction_header
from freestanding_elf import prepare_target,describe,target_metadata
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success

ROOT=fixture.ROOT
BODY='''unsigned rebind(unsigned step){
 unsigned guard=current()->value+alternate()->value;
 if(current()->next && current()->next->next)
   current()->next->next->value+=step+1;
 return guard;
}
'''
OBJECTS='static Obj a={99,0},b={99,0},c={41,0};'
SETUP='a.next=&b;b.next=&c;'
RETAIN=None

class NestedEffectTests(unittest.TestCase):
    def capture(self,stage,body=BODY,setup=SETUP):
        return fixture.PointerEffectTests().fixture(stage,body,OBJECTS,setup)

    def header(self,entries,posts,plans,continuous=True):
        return reconstruction_header(entries,plans,post_states=posts,scalar_arguments=True,continuous=continuous)

    def test_nested_owners_aliases_cycles_null_and_independent_replay(self):
        for setup in (SETUP,'a.next=&b;b.next=&a;','a.next=&a;b.next=&a;',
                      'a.next=&b;b.next=0;','a.next=0;b.next=0;'):
            with self.subTest(setup=setup),tempfile.TemporaryDirectory() as directory:
                e,p,s=self.capture(Path(directory),setup=setup)
                self.assertIn('current()->next->next->value',{w['path'] for w in s[0]['state_writes']})
                for continuous in (True,False):
                    header=self.header(e,p,s,continuous=continuous)
                    harness=Path(directory)/'replay.c'
                    harness.write_text('#include <stdint.h>\n'+fixture.MODEL+header+BODY+
                        'Obj *current(void){return osrec_bound_current;}\n'
                        'Obj *alternate(void){return osrec_bound_alternate;}\n'
                        'int main(void){for(unsigned i=0;i<4;++i){'+
                        ('if(!i && !osrec_restore(i))return 1;if(!osrec_entry_matches(i))return 2;' if continuous
                         else 'if(!osrec_restore(i))return 1;')+
                        'rebind(osrec_argument(i,0));if(!osrec_state_matches(i))return 3;}return 0;}\n')
                    executable=Path(directory)/'replay'
                    run([fixture.NATIVE_CC,'-std=c11',harness,'-o',executable]);run([executable])

    def test_unwritten_fields_and_writable_prefixes_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory);e,p,s=self.capture(stage)
            for owner in (1,2):
                changed=copy.deepcopy(p[:1])
                next(f for f in changed[0]['fields'] if f['object_id']==owner and f['name']=='value')['data']='00000000'
                with self.subTest(owner=owner),self.assertRaisesRegex(ValueError,'unwritten field'):
                    self.header(e[:1],changed,s[:1])
            # A direct write through another root aliases the second traversal
            # edge. Even writing the same pointer value makes that path unsafe.
            for extra in ('current()->next=current()->next;',
                          'alternate()->next=alternate()->next;'):
                body=BODY.replace('return guard;',extra+'return guard;')
                a,b,plans=self.capture(stage,body)
                with self.subTest(extra=extra),self.assertRaisesRegex(ValueError,'writable pointer edge'):
                    self.header(a,b,plans)
            # Nested pointer effects remain outside the supported scalar case.
            body=BODY.replace('return guard;','current()->next->next=current();return guard;')
            a,b,plans=self.capture(stage,body)
            with self.assertRaises(ValueError):self.header(a,b,plans)

    def test_write_only_nested_scalar_requires_independent_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory);body=BODY.replace('value+=step+1','value=step+1')
            e,p,s=fixture.PointerEffectTests().fixture(stage,body,OBJECTS,SETUP,post_effects=True)
            header=self.header(e,p,s,continuous=False)
            self.assertNotIn('current()->next->next->value',{r['path'] for r in s[0]['entry_reads']})
            with self.assertRaisesRegex(ValueError,'complete field footprint'):self.header(e,p,s)
            source=stage/'replay.c';source.write_text('#include <stdint.h>\n'+fixture.MODEL+header+body+
                'Obj *current(void){return osrec_bound_current;}\nObj *alternate(void){return osrec_bound_alternate;}\n'
                'int main(void){for(unsigned i=0;i<4;++i){if(!osrec_restore(i))return 1;'
                'rebind(osrec_argument(i,0));if(!osrec_state_matches(i))return 2;}return 0;}\n')
            executable=stage/'replay';run([fixture.NATIVE_CC,'-std=c11',source,'-o',executable]);run([executable])

    def test_aarch64_relocated_elf_raw_and_wrong_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory);e,p,plans=self.capture(stage)
            sources=stage/'sources';sources.mkdir()
            (sources/'entry_model.h').write_text('#include <stdint.h>\n'+fixture.MODEL)
            (sources/'entry_reconstruction.h').write_text(self.header(e,p,plans))
            bindings='Obj *current(void){return osrec_bound_current;}\nObj *alternate(void){return osrec_bound_alternate;}\n'
            invoke='uint32_t osrec_invoke(uint32_t number){(void)number;static unsigned i;return rebind(osrec_argument(i++,0));}\n'
            adapter=sources/'entry_adapter.h';adapter.write_text(BODY+bindings+invoke)
            (sources/'entry_checkpoint.h').write_text('#define OSREC_CHECKPOINT_CALLS 4\nstruct checkpoint_call {uint32_t number,raw;};\nstatic const struct checkpoint_call checkpoint_calls[4]={{1,198},{1,198},{1,198},{1,198}};\n')
            for address in (0x40200000,0x40400000):
                flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=address,result_address=address-0x80000),sources)
                image=stage/'nested.elf';binary=stage/'nested.bin'
                command=[fixture.LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                    '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
                    '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),'-I',sources,
                    sources/'start.S',ROOT/'integrations/rtl_aarch64/entry_state_replay.c','-o',image]
                run(command);audit(image,fixture.LLVM);run([fixture.LLVM/'llvm-objcopy','-O','binary',image,binary])
                result,raw=observe(image,fixture.QEMU);require_success(result)
                raw_result,binary_raw=observe(binary,fixture.QEMU,descriptor=image);require_success(raw_result)
                self.assertEqual(raw,binary_raw)
                self.assertEqual((result['states_restored'],result['entry_states_checked'],result['states_verified']),(1,4,4))
                if RETAIN is not None:
                    destination=RETAIN/hex(address);destination.mkdir(parents=True)
                    shutil.copytree(sources,destination/'sources')
                    for artifact in (image,binary):shutil.copy2(artifact,destination/artifact.name)
                    (destination/'target-result.bin').write_bytes(raw)
                    evidence=dict(format='osrec-nested-scalar-effects-fixture-v1',
                        scope='native C fixture; no live kernel capture',entry_states=e,post_states=p,plans=plans,
                        target=target_metadata(describe(image),8),target_observations=result,elf_raw_match=True,
                        elf_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
                        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
                    (destination/'manifest.json').write_text(json.dumps(evidence,indent=2)+'\n')
            for body in (BODY.replace('current()->next->next->value+=step+1;','current()->next->value+=step+1;'),
                         BODY.replace('current()->next->next->value+=step+1;','(void)step;')):
                adapter.write_text(body+bindings+invoke);run(command);audit(image,fixture.LLVM)
                failed,_=observe(image,fixture.QEMU)
                self.assertEqual(failed['actual_calls'][0]['raw_bits'],198)
                self.assertEqual(failed['error'],20)
                with self.assertRaises(ValueError):require_success(failed)

if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve()
        del sys.argv[index:index+2]
        RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==4:
        fixture.CLANG=sys.argv[1];fixture.LLVM=Path(sys.argv[2]);fixture.QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
