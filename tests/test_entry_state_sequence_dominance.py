"""Comma sequencing earns local store proofs; assignment operands do not."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest

import test_entry_state_argument_dominance as fixture
from entry_state import Analyzer
from reconstruct_entry_state import reconstruction_header
from freestanding_armv7 import run,audit
from freestanding_elf import prepare_target,describe,target_metadata
from run_freestanding_armv7 import observe,require_success

ROOT=fixture.ROOT;RETAIN=None
BODY='''unsigned overwrite(Obj *left,unsigned input){
 if(!left)return 0;
 return (left->value=input^left->other,left->value);
}
'''

class SequenceDominanceTests(unittest.TestCase):
    def test_sequenced_and_unsequenced_expressions(self):
        cases={
            'comma':'return (left->value=4,left->value);',
            'nested':'return (0,(left->value=4,left->value));',
            'statement':'(left->value=4,left->value);return left->value;',
            'cast':'return (unsigned)(left->value=4,left->value);',
            'void_cast':'(void)(left->value=4,left->value);return left->value;',
            'conditional':'return (input?(left->value=4):0,left->value);',
            'short_circuit':'return (input&&(left->value=4),left->value);',
            'compound':'return (left->value+=4,left->value);',
            'intervening':'return (left->value=4,left->other=3,left->value);',
            'barrier':'return (left->value=4,barrier_effect(),left->value);',
            'outer_sum':'return input+(left->value=4,left->value);',
            'call_argument':'return sink((left->value=4,left->value),left->other);',
            'effectful_target':'left->value=4;target()->other=left->value;return 0;',
            'effectful_target_comma':'target()->other=(left->value=4,left->value);return 0;',
        }
        boundaries={
            'barrier_effect':{'kind':'ordering_model','reason':'fixture interference barrier','implementation':'reviewed boundary'},
            'sink':{'kind':'scalar_transcript','reason':'fixture scalar call boundary','implementation':'ordered scalar result'},
            'target':{'kind':'object_provider','reason':'provider evaluation may mutate state','implementation':'explicit effectful target boundary','snapshot_safe':False}}
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);helper=fixture.ArgumentDominanceTests()
            text='void barrier_effect(void);unsigned sink(unsigned,unsigned);Obj *target(void);\n'+''.join(
                'unsigned '+root+'(Obj *left,unsigned input){'+body+'}\n' for root,body in cases.items())
            tree,_,_=helper.parse(stage,text)
            for root in cases:
                with self.subTest(root=root):
                    p=helper.plan(tree,root,boundaries=boundaries);self.assertFalse(p['blockers'])
                    if root in ('comma','nested','statement','cast','void_cast'):
                        self.assertFalse(p['entry_reads']);self.assertTrue(p['dominated_reads'])
                    else:
                        self.assertTrue(p['entry_reads']);self.assertFalse(p['dominated_reads'])
                    self.assertFalse(p['minimality_proven']);self.assertFalse(p['completeness_proven'])
            # The left index may be evaluated before the right-hand store.
            # Only the load inside the right-hand comma expression is covered.
            text='unsigned overwrite(Obj *left,unsigned input){(void)input;left->array[left->value&3U]=(left->value=4,left->value);return 0;}'
            tree,_,_=helper.parse(stage,text);p=helper.plan(tree)
            self.assertEqual(len(p['entry_reads']),1);self.assertEqual(len(p['dominated_reads']),1)
            self.assertEqual(p['entry_reads'][0]['path'],p['dominated_reads'][0]['path'])
            # The same comma rule works with contracted callable providers.
            tree,_,_=helper.parse(stage,'Obj *current(void);unsigned query(void){return(current()->value=4,current()->value);}')
            policy={**fixture.CONTRACT,'kind':'object_provider'}
            p=Analyzer(tree,{'current':policy},prune_written=True).analyze('query')
            self.assertFalse(p['blockers']);self.assertFalse(p['entry_reads']);self.assertTrue(p['dominated_reads'])

    def test_native_reduced_capture_and_host_replay(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);p,_,rows=fixture.ArgumentDominanceTests().capture(stage,BODY)
            header=reconstruction_header([r['entry'] for r in rows],[p]*6,post_states=[r['post'] for r in rows],scalar_arguments=True)
            self.assertEqual([sum(f['bytes'] for f in r['entry']['fields']) for r in rows],[4]*5+[0])
            expected=[45,0xffffffef,0x80000080,0xfffffffe,0,0]
            self.assertEqual([r['raw'] for r in rows],expected)
            source=stage/'host.c';source.write_text('#include <stdint.h>\n'+fixture.MODEL+header+BODY+
                'int main(void){unsigned expected[6]={'+','.join(str(v)+'U' for v in expected)+'};'
                'for(unsigned i=0;i<6;++i){if(!osrec_restore(i))return 1;'
                'if(i<5 && osrec_bound_osrec_argument_left->value)return 2;'
                'if(overwrite(osrec_bound_osrec_argument_left,osrec_argument(i,1))!=expected[i])return 3;'
                'if(!osrec_state_matches(i))return 4;}return 0;}\n')
            binary=stage/'host';run([fixture.LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary]);run([binary])

    def test_aarch64_relocated_images_and_missing_write(self):
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
                image=stage/'sequence.elf';binary=stage/'sequence.bin'
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
                    evidence=dict(format='osrec-sequence-dominance-fixture-v1',scope='native C comma-operator fixture; no live kernel pruning',
                        plan=p,full_plan=full,calls=rows,target=target_metadata(describe(image),8),target_observations=result,
                        elf_raw_match=True,elf_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
                    (destination/'manifest.json').write_text(json.dumps(evidence,indent=2)+'\n')
            faulty=BODY.replace('return (left->value=input^left->other,left->value);','return input^left->other;')
            self.assertNotEqual(faulty,BODY);adapter.write_text(faulty+invoke);run(command);audit(image,fixture.LLVM)
            failed,_=observe(image,fixture.QEMU);self.assertEqual(failed['actual_calls'][0]['raw_bits'],45)
            self.assertEqual((failed['status'],failed['error']),(3,20))

if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:fixture.LLVM=Path(sys.argv[1]);fixture.QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
