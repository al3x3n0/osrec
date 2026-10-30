"""Conditional and short-circuit proofs preserve every possible continuation."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest

import test_entry_state_argument_dominance as fixture
from reconstruct_entry_state import reconstruction_header
from freestanding_armv7 import run,audit
from freestanding_elf import prepare_target,describe,target_metadata
from run_freestanding_armv7 import observe,require_success

ROOT=fixture.ROOT;RETAIN=None
BODY='''unsigned overwrite(Obj *left,unsigned input){
 if(!left)return 0;
 return ((input&1U)&&(left->other&1U)) ?
  (left->value=input^left->other,left->value) :
  (left->value=(input^left->other)+1U,left->value);
}
'''
EXPECTED=[46,0xfffffff0,0x80000081,0xfffffffe,1,0]

class ConditionalDominanceTests(unittest.TestCase):
    def test_path_merges_and_conditional_reads(self):
        # Expected counts refer to incoming/omitted occurrences of value.
        cases={
            'both_arms':('return input?(left->value=4,left->value):(left->value=5,left->value);',0,2),
            'both_merge':('return(input?(left->value=4):(left->value=5),left->value);',0,1),
            'one_merge':('return(input?(left->value=4):0,left->value);',1,0),
            'one_local':('return input?(left->value=4,left->value):left->value;',1,1),
            'condition_read':('return left->value?(left->value=4,left->value):(left->value=5,left->value);',1,2),
            'condition_store':('return(left->value=input)?left->value:left->value;',0,2),
            'nested':('return input?(input&2U?(left->value=4,left->value):(left->value=5,left->value)):(left->value=6,left->value);',0,3),
            'and_merge':('return(input&&(left->value=4),left->value);',1,0),
            'or_merge':('return(input||(left->value=4),left->value);',1,0),
            'and_local':('return input&&(left->value=4,left->value);',0,1),
            'or_local':('return input||(left->value=4,left->value);',0,1),
            'and_left_store':('return(left->value=4)&&left->value;',0,1),
            'or_left_store':('return(left->value=0)||left->value;',0,1),
            'and_incoming':('return((left->value=4)&&input,left->value);',0,1),
            'barrier_arm':('return input?(left->value=4,barrier_effect(),left->value):(left->value=5,left->value);',1,1),
            'outer_sum':('return input+(input?(left->value=4,left->value):(left->value=5,left->value));',2,0),
            'call_argument':('return sink(input?(left->value=4,left->value):(left->value=5,left->value));',2,0),
            'effectful_target':('target()->other=input?(left->value=4,left->value):(left->value=5,left->value);return 0;',2,0),
            'assignment_index':('left->array[left->value&3U]=input?(left->value=4,left->value):(left->value=5,left->value);return 0;',1,2),
            'gnu_omitted_middle':('return input?:(left->value=4,left->value);',1,0),
            'loop':('while(input--){return input?(left->value=4,left->value):(left->value=5,left->value);}return 0;',2,0),
        }
        boundaries={
            'barrier_effect':{'kind':'ordering_model','reason':'fixture interference boundary','implementation':'reviewed barrier'},
            'sink':{'kind':'scalar_transcript','reason':'fixture scalar boundary','implementation':'ordered scalar result'},
            'target':{'kind':'object_provider','reason':'target evaluation can change state','implementation':'effectful provider','snapshot_safe':False}}
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);helper=fixture.ArgumentDominanceTests()
            text='void barrier_effect(void);unsigned sink(unsigned);Obj *target(void);\n'+''.join(
                'unsigned '+root+'(Obj *left,unsigned input){'+body+'}\n' for root,(body,_,_) in cases.items())
            tree,_,_=helper.parse(stage,text)
            for root,(_,incoming,omitted) in cases.items():
                with self.subTest(root=root):
                    p=helper.plan(tree,root,boundaries=boundaries);self.assertFalse(p['blockers'])
                    selected=lambda rows:[r for r in rows if r['path']=='osrec_argument_left()->value']
                    self.assertEqual(len(selected(p['entry_reads'])),incoming)
                    self.assertEqual(len(selected(p['dominated_reads'])),omitted)
                    self.assertFalse(p['minimality_proven']);self.assertFalse(p['completeness_proven'])
                    if root=='both_merge':self.assertEqual(len(p['dominated_reads'][0]['covering_stores']),2)
            # Repeated joins with an inherited store must not duplicate its
            # evidence exponentially, including the older structured-if path.
            body='left->value=4;'+('(void)(input&&input);'*40)+('if(input){(void)input;}else{(void)input;}'*40)+'return left->value;'
            tree,_,_=helper.parse(stage,'unsigned overwrite(Obj *left,unsigned input){'+body+'}')
            p=helper.plan(tree);self.assertFalse(p['blockers']);self.assertFalse(p['entry_reads'])
            self.assertEqual(len(p['dominated_reads']),1)
            self.assertEqual(len(p['dominated_reads'][0]['covering_stores']),1)

    def test_native_branch_capture_and_host_replay(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);p,_,rows=fixture.ArgumentDominanceTests().capture(stage,BODY)
            self.assertEqual(len(p['dominated_reads']),2)
            self.assertEqual([r['raw'] for r in rows],EXPECTED)
            self.assertEqual([sum(f['bytes'] for f in r['entry']['fields']) for r in rows],[4]*5+[0])
            header=reconstruction_header([r['entry'] for r in rows],[p]*6,post_states=[r['post'] for r in rows],scalar_arguments=True)
            source=stage/'host.c';source.write_text('#include <stdint.h>\n'+fixture.MODEL+header+BODY+
                'int main(void){unsigned expected[6]={'+','.join(str(v)+'U' for v in EXPECTED)+'};'
                'for(unsigned i=0;i<6;++i){if(!osrec_restore(i))return 1;'
                'if(i<5&&osrec_bound_osrec_argument_left->value)return 2;'
                'if(overwrite(osrec_bound_osrec_argument_left,osrec_argument(i,1))!=expected[i])return 3;'
                'if(!osrec_state_matches(i))return 4;}return 0;}\n')
            binary=stage/'host';run([fixture.LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary]);run([binary])

    def test_skipped_write_still_requires_matching_post_state(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            body='''unsigned overwrite(Obj *left,unsigned input){if(!left)return 0;
 return (input&1U)?(left->value=input^left->other,left->value):0;}
'''
            p,_,rows=fixture.ArgumentDominanceTests().capture(stage,body)
            self.assertEqual(len(p['dominated_reads']),1)
            header=reconstruction_header([r['entry'] for r in rows],[p]*6,post_states=[r['post'] for r in rows],scalar_arguments=True)
            # Calls 2 and 4 skip the write with a nonzero native entry value.
            # Its incoming value was never read, yet the post oracle includes
            # the may-written field and must reject the zero-filled replay.
            source=stage/'preservation.c';source.write_text('#include <stdint.h>\n'+fixture.MODEL+header+body+
                'int main(void){unsigned expected_match[6]={1,1,0,1,0,1};unsigned expected_return[6]={'+
                ','.join(str(r['raw'])+'U' for r in rows)+'};'
                'for(unsigned i=0;i<6;++i){if(!osrec_restore(i))return 1;'
                'if(overwrite(osrec_bound_osrec_argument_left,osrec_argument(i,1))!=expected_return[i])return 2;'
                'if((unsigned)osrec_state_matches(i)!=expected_match[i])return 3;}return 0;}\n')
            binary=stage/'preservation';run([fixture.LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary]);run([binary])

    def test_aarch64_branch_replay_and_faults(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);p,full,rows=fixture.ArgumentDominanceTests().capture(stage,BODY)
            sources=stage/'sources';sources.mkdir()
            (sources/'entry_model.h').write_text('#include <stdint.h>\n'+fixture.MODEL)
            (sources/'entry_reconstruction.h').write_text(reconstruction_header([r['entry'] for r in rows],[p]*6,post_states=[r['post'] for r in rows],scalar_arguments=True))
            adapter=sources/'entry_adapter.h';invoke='uint32_t osrec_invoke(uint32_t number){(void)number;static unsigned i;return overwrite(osrec_bound_osrec_argument_left,osrec_argument(i++,1));}\n'
            adapter.write_text(BODY+invoke)
            (sources/'entry_checkpoint.h').write_text('#define OSREC_CHECKPOINT_CALLS 6\nstruct checkpoint_call{uint32_t number,raw;};\nstatic const struct checkpoint_call checkpoint_calls[6]={'+','.join('{1,UINT32_C('+str(r['raw'])+')}' for r in rows)+'};\n')
            for address in (0x40200000,0x40400000):
                flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=address,result_address=address-0x80000),sources)
                image=stage/'conditional.elf';binary=stage/'conditional.bin'
                command=[fixture.LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                    '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
                    '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),'-I',sources,
                    sources/'start.S',ROOT/'integrations/rtl_aarch64/entry_state_replay.c','-o',image]
                run(command);audit(image,fixture.LLVM);run([fixture.LLVM/'llvm-objcopy','-O','binary',image,binary])
                result,raw=observe(image,fixture.QEMU);require_success(result)
                other,binary_raw=observe(binary,fixture.QEMU,descriptor=image);require_success(other);self.assertEqual(raw,binary_raw)
                self.assertEqual((result['states_restored'],result['states_verified']),(6,6))
                if RETAIN is not None:
                    destination=RETAIN/hex(address);destination.mkdir(parents=True)
                    shutil.copytree(sources,destination/'sources')
                    for artifact in (image,binary):shutil.copy2(artifact,destination/artifact.name)
                    (destination/'target-result.bin').write_bytes(raw)
                    evidence=dict(format='osrec-conditional-dominance-fixture-v1',scope='native C conditional/short-circuit fixture; no live kernel pruning',
                        plan=p,full_plan=full,calls=rows,target=target_metadata(describe(image),8),target_observations=result,
                        elf_raw_match=True,elf_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
                    (destination/'manifest.json').write_text(json.dumps(evidence,indent=2)+'\n')
            no_write='''unsigned overwrite(Obj *left,unsigned input){if(!left)return 0;
 return ((input&1U)&&(left->other&1U)) ? (input^left->other) : ((input^left->other)+1U);}
'''
            mutations=[(no_write,20),
                (BODY.replace('(left->value=(input^left->other)+1U,left->value)','((input^left->other)+1U)'),20),
                (BODY.replace('((input&1U)&&(left->other&1U))','!((input&1U)&&(left->other&1U))'),10)]
            for body,error in mutations:
                self.assertNotEqual(body,BODY);adapter.write_text(body+invoke);run(command);audit(image,fixture.LLVM)
                failed,_=observe(image,fixture.QEMU);self.assertEqual((failed['status'],failed['error']),(3,error))
                if error==20:self.assertEqual(failed['actual_calls'][0]['raw_bits'],46)

if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:fixture.LLVM=Path(sys.argv[1]);fixture.QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
