"""Incoming nested scalar state through captured, stable entry pointer edges."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest

import test_entry_state_pointer_effects as fixture
import test_entry_state_argument_dominance as argument_fixture
from entry_state import entry_accesses,capture_header
from reconstruct_entry_state import reconstruction_header
from freestanding_elf import prepare_target,describe,target_metadata
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success

ROOT=fixture.ROOT;RETAIN=None
PATH='current()->next->next->value'
BODY='''unsigned rebind(unsigned step){
 unsigned guard=current()->value+alternate()->value;
 if(current()->next && current()->next->next && (step&1U))
   current()->next->next->value=step+1;
 return guard;
}
'''
OBJECTS='static Obj a={99,0},b={99,0},c={41,0};'
SETUP='a.next=&b;b.next=&c;'
POLICY={name:{**policy,'stable_identity':True,'exclusive_state':True,'preserves_entry_state':True}
        for name,policy in fixture.POLICY.items()}

class NestedPreservationTests(unittest.TestCase):
    def capture(self,stage,body=BODY,setup=SETUP,policy=POLICY,preserve=True):
        return fixture.PointerEffectTests().fixture(stage,body,OBJECTS,setup,post_effects=True,
            preserve_write_state=preserve,policy=policy)

    def header(self,e,p,s,continuous=False):
        return reconstruction_header(e,s,post_states=p,scalar_arguments=True,continuous=continuous)

    def test_argument_projection_and_contract_flags(self):
        body='''unsigned overwrite(Obj *left,unsigned input){
 if(left && left->next && left->next->next && (input&1U))left->next->next->value=input;
 return 0;}
'''
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);helper=argument_fixture.ArgumentDominanceTests();tree,_,_=helper.parse(stage,body)
            plan=helper.plan(tree,preserve_write_state=True)
            self.assertEqual([r['path'] for r in plan['preserved_entry_fields']],['osrec_argument_left()->next->next->value'])
            for flag in ('stable_identity','exclusive_state','preserves_entry_state'):
                weak={**argument_fixture.CONTRACT,flag:False}
                self.assertFalse(helper.plan(tree,contract=weak,preserve_write_state=True)['preserved_entry_fields'])
            (stage/'capture.h').write_text(capture_header([plan]))
            source=stage/'argument.c';source.write_text(argument_fixture.MODEL+body+'\n#include "capture.h"\n'+
                'int main(void){Obj a={0},b={0},c={0};a.next=&b;b.next=&c;c.value=41;'
                'struct osrec_entry_snapshot s;osrec_snapshot_init(&s);'
                'if(!osrec_snapshot_overwrite(&s,&a)||s.object_count!=3||s.field_count!=3)return 1;'
                'if(overwrite(&a,0)||c.value!=41)return 2;'
                'if(overwrite(&a,7)||c.value!=7)return 3;return 0;}\n')
            binary=stage/'argument';run([fixture.NATIVE_CC,'-std=c11','-I',ROOT/'include','-I',stage,
                source,ROOT/'runtime/entry_snapshot.c','-o',binary]);run([binary])

    def test_native_topologies_and_default_mode(self):
        for setup in (SETUP,'a.next=&b;b.next=&a;','a.next=&a;b.next=&a;',
                      'a.next=&b;b.next=0;','a.next=0;b.next=0;'):
            with self.subTest(setup=setup),tempfile.TemporaryDirectory() as name:
                stage=Path(name);e,p,s=self.capture(stage,setup=setup)
                self.assertEqual([r['path'] for r in s[0]['preserved_entry_fields']],[PATH])
                self.assertNotIn(PATH,{r['path'] for r in s[0]['entry_reads']})
                for continuous in (False,True):
                    source=stage/'host.c';source.write_text('#include <stdint.h>\n'+fixture.MODEL+self.header(e,p,s,continuous)+BODY+
                        'Obj *current(void){return osrec_bound_current;}\nObj *alternate(void){return osrec_bound_alternate;}\n'
                        'int main(void){for(unsigned i=0;i<4;++i){'+
                        ('if(!i&&!osrec_restore(i))return 1;if(!osrec_entry_matches(i))return 2;' if continuous else 'if(!osrec_restore(i))return 1;')+
                        'rebind(osrec_argument(i,0));if(!osrec_state_matches(i))return 3;}return 0;}\n')
                    binary=stage/'host';run([fixture.NATIVE_CC,'-std=c11',source,'-o',binary]);run([binary])
        with tempfile.TemporaryDirectory() as name:
            e,p,s=self.capture(Path(name),preserve=False)
            self.assertNotIn('preserved_entry_fields',s[0]);self.header(e,p,s)
            with self.assertRaisesRegex(ValueError,'complete field footprint'):self.header(e,p,s,True)

    def test_projection_contracts_and_writable_edge_aliases(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);e,p,s=self.capture(stage)
            for change in ('missing_edge','scalar_edge','volatile_edge','wrong_path','pointer_value','write_prefix','weak_contract'):
                plan=copy.deepcopy(s[0]);row=plan['preserved_entry_fields'][0]
                if change=='missing_edge':plan['entry_reads']=[r for r in plan['entry_reads'] if r['path']!='current()->next->next']
                elif change=='scalar_edge':
                    for r in plan['entry_reads']:
                        if r['path']=='current()->next':r['pointer_edge']=False
                elif change=='volatile_edge':
                    for r in plan['entry_reads']:
                        if r['path']=='current()->next':r['volatile']=True
                elif change=='wrong_path':row['path']='current()->next->missing->value'
                elif change=='pointer_value':row['pointer_edge']=True
                elif change=='write_prefix':plan['state_writes'].append({**row,'path':'current()->next','pointer_edge':True,'type':'Obj *'})
                else:plan['object_providers'][0]['contract']['exclusive_state']=False
                with self.subTest(change=change),self.assertRaises(ValueError):entry_accesses(plan)
            entries=copy.deepcopy(e)
            entries[0]['fields']=[f for f in entries[0]['fields'] if not(f['name']=='value' and f['object_id']==3)]
            with self.assertRaisesRegex(ValueError,'planned field missing'):self.header(entries,p,s)
            # The second path aliases the actual traversal edge, even though
            # the source spelling differs and the pointer value is unchanged.
            body=BODY.replace('return guard;','alternate()->next=alternate()->next;return guard;')
            a,b,plans=self.capture(stage,body)
            self.assertEqual([r['path'] for r in plans[0]['preserved_entry_fields']],[PATH])
            with self.assertRaisesRegex(ValueError,'writable pointer edge'):self.header(a,b,plans,True)

    def test_aarch64_images_and_preservation_faults(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);e,p,plans=self.capture(stage)
            sources=stage/'sources';sources.mkdir()
            (sources/'entry_model.h').write_text('#include <stdint.h>\n'+fixture.MODEL)
            bindings='Obj *current(void){return osrec_bound_current;}\nObj *alternate(void){return osrec_bound_alternate;}\n'
            invoke='uint32_t osrec_invoke(uint32_t number){(void)number;static unsigned i;return rebind(osrec_argument(i++,0));}\n'
            adapter=sources/'entry_adapter.h';adapter.write_text(BODY+bindings+invoke)
            (sources/'entry_checkpoint.h').write_text('#define OSREC_CHECKPOINT_CALLS 4\nstruct checkpoint_call{uint32_t number,raw;};\nstatic const struct checkpoint_call checkpoint_calls[4]={{1,198},{1,198},{1,198},{1,198}};\n')
            for continuous in (False,True):
                (sources/'entry_reconstruction.h').write_text(self.header(e,p,plans,continuous))
                for address in (0x40200000,0x40400000):
                    flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=address,result_address=address-0x80000),sources)
                    image=stage/'nested-preservation.elf';binary=stage/'nested-preservation.bin'
                    command=[fixture.LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                        '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
                        '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),'-I',sources,
                        sources/'start.S',ROOT/'integrations/rtl_aarch64/entry_state_replay.c','-o',image]
                    run(command);audit(image,fixture.LLVM);run([fixture.LLVM/'llvm-objcopy','-O','binary',image,binary])
                    result,raw=observe(image,fixture.QEMU);require_success(result)
                    other,binary_raw=observe(binary,fixture.QEMU,descriptor=image);require_success(other);self.assertEqual(raw,binary_raw)
                    self.assertEqual((result['states_restored'],result['states_verified'],result['entry_states_checked']),
                        (1 if continuous else 4,4,4 if continuous else 0))
                    if RETAIN is not None:
                        destination=RETAIN/('continuous' if continuous else 'independent')/hex(address);destination.mkdir(parents=True)
                        shutil.copytree(sources,destination/'sources')
                        for artifact in (image,binary):shutil.copy2(artifact,destination/artifact.name)
                        (destination/'target-result.bin').write_bytes(raw)
                        evidence=dict(format='osrec-nested-preservation-fixture-v1',scope='native C fixture; no live kernel preservation policy',
                            entry_states=e,post_states=p,plans=plans,target=target_metadata(describe(image),8),target_observations=result,
                            elf_raw_match=True,elf_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
                        (destination/'manifest.json').write_text(json.dumps(evidence,indent=2)+'\n')
            faults=[]
            for mutation,body,error in (
                ('zero skipped input',BODY.replace('return guard;','if(!(step&1U))current()->next->next->value=0;return guard;'),20),
                ('omit selected write',BODY.replace('current()->next->next->value=step+1;','(void)step;'),21),
                ('write wrong owner',BODY.replace('current()->next->next->value=step+1;','current()->next->value=step+1;'),21)):
                adapter.write_text(body+bindings+invoke);run(command);audit(image,fixture.LLVM)
                failed,_=observe(image,fixture.QEMU)
                self.assertEqual((failed['status'],failed['error']),(3,error));self.assertEqual(failed['actual_calls'][error-20]['raw_bits'],198)
                faults.append({'mutation':mutation,'observations':failed})
            if RETAIN is not None:(RETAIN/'fault-verification.json').write_text(json.dumps(faults,indent=2)+'\n')

if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==4:fixture.CLANG=sys.argv[1];fixture.LLVM=Path(sys.argv[2]);fixture.QEMU=sys.argv[3];sys.argv=sys.argv[:1]
    unittest.main()
