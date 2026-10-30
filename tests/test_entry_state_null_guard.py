"""Exclude only proven null argument exits from scalar overwrite coverage."""
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
from freestanding_elf import prepare_target,describe,target_metadata
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success

ROOT=fixture.ROOT;RETAIN=None
BODY=fixture.BODY

class NullGuardTests(unittest.TestCase):
    def test_guard_shapes_and_conservative_limits(self):
        cases={
            'negative':('if(!left)return 0;left->value=input;return left->value;',True),
            'parentheses':('if((!(left))){return input;}left->value=input;return left->value;',True),
            'positive_else':('if(left){left->value=input;return left->value;}else return 0;',True),
            'nested':('if(input){if(!left)return 0;}left->value=input;return left->value;',True),
            'nonnull_skip':('if(!left)return 0;if(input)return 0;left->value=input;return left->value;',False),
            'conditional_write':('if(!left)return 0;if(input)left->value=input;return 0;',False),
            'positive_fallthrough':('if(left){left->value=input;return left->value;}return 0;',False),
            'double_negative':('if(!!left){left->value=input;return left->value;}else return 0;',False),
            'comparison':('if(left==0)return 0;left->value=input;return left->value;',False),
            'explicit_cast':('if((_Bool)left){left->value=input;return left->value;}else return 0;',False),
            'alias':('Obj *p=left;if(!p)return 0;left->value=input;return left->value;',False),
            'address':('if(input)(void)&left;if(!left)return 0;left->value=input;return left->value;',False),
            'reassigned':('left=left;if(!left)return 0;left->value=input;return left->value;',False),
            'effectful_return':('if(!left)return side_effect();left->value=input;return left->value;',False),
            'multi_statement':('if(!left){(void)input;return 0;}left->value=input;return left->value;',False),
        }
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);helper=fixture.ArgumentDominanceTests()
            source='unsigned side_effect(void);\n'+''.join('unsigned '+root+'(Obj *left,unsigned input){'+body+'}\n' for root,(body,_) in cases.items())
            tree,_,_=helper.parse(stage,source)
            boundaries={'side_effect':{'kind':'ordering_model','reason':'fixture interference','implementation':'reviewed effect boundary'}}
            for root,(_,proven) in cases.items():
                with self.subTest(root=root):
                    plan=helper.plan(tree,root,boundaries=boundaries,preserve_write_state=True)
                    self.assertFalse(plan['blockers'],plan['blockers'])
                    self.assertEqual(bool(plan['preserved_entry_fields']),not proven)
                    if proven:
                        stores=plan['write_state_preservation']['guaranteed_exit_stores']
                        self.assertEqual(stores[0]['excluded_null_exits'],1)
                        self.assertEqual(len(plan['write_state_preservation']['null_guard_exit_proofs']),1)
            # A null left argument says nothing about the right object's
            # incoming state, even when two entry bindings can alias.
            tree,_,_=helper.parse(stage,'unsigned overwrite(Obj *left,unsigned input,Obj *right){if(!left)return 0;right->value=input;return right->value;}')
            plan=Analyzer(tree,prune_written=True,preserve_write_state=True,
                argument_objects={'overwrite':{'left':fixture.CONTRACT,'right':fixture.CONTRACT}}).analyze('overwrite')
            self.assertEqual([r['path'] for r in plan['preserved_entry_fields']],['osrec_argument_right()->value'])

    def test_native_capture_omission_and_default_policy(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);helper=fixture.ArgumentDominanceTests()
            plan,full,rows=helper.capture(stage,preserve_write_state=True)
            self.assertFalse(plan['preserved_entry_fields'])
            self.assertEqual([sum(f['bytes'] for f in r['entry']['fields']) for r in rows],[4]*5+[0])
            self.assertEqual([sum(f['bytes'] for f in r['full_entry']['fields']) for r in rows],[8]*5+[0])
            self.assertEqual(plan['write_state_preservation']['guaranteed_exit_stores'][0]['excluded_null_exits'],1)
            tree,_,_=helper.parse(stage)
            self.assertNotIn('write_state_preservation',helper.plan(tree))
            self.assertNotIn('dominated_reads',helper.plan(tree,prune=False))
            source=stage/'host.c';source.write_text('#include <stdint.h>\n'+fixture.MODEL+
                reconstruction_header([r['entry'] for r in rows],[plan]*6,post_states=[r['post'] for r in rows],scalar_arguments=True)+BODY+
                'int main(void){for(unsigned i=0;i<6;++i){if(!osrec_restore(i))return 1;'
                'overwrite(osrec_bound_osrec_argument_left,osrec_argument(i,1));if(!osrec_state_matches(i))return 2;}return 0;}\n')
            binary=stage/'host';run([fixture.LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary]);run([binary])

    def test_aarch64_images_and_omitted_write_fault(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);plan,full,rows=fixture.ArgumentDominanceTests().capture(stage,preserve_write_state=True)
            sources=stage/'sources';sources.mkdir()
            (sources/'entry_model.h').write_text('#include <stdint.h>\n'+fixture.MODEL)
            (sources/'entry_reconstruction.h').write_text(reconstruction_header([r['entry'] for r in rows],[plan]*6,post_states=[r['post'] for r in rows],scalar_arguments=True))
            invoke='uint32_t osrec_invoke(uint32_t number){(void)number;static unsigned i;return overwrite(osrec_bound_osrec_argument_left,osrec_argument(i++,1));}\n'
            adapter=sources/'entry_adapter.h';adapter.write_text(BODY+invoke)
            (sources/'entry_checkpoint.h').write_text('#define OSREC_CHECKPOINT_CALLS 6\nstruct checkpoint_call{uint32_t number,raw;};\nstatic const struct checkpoint_call checkpoint_calls[6]={'+','.join('{1,UINT32_C('+str(r['raw'])+')}' for r in rows)+'};\n')
            for address in (0x40200000,0x40400000):
                flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=address,result_address=address-0x80000),sources)
                image=stage/'null-guard.elf';binary=stage/'null-guard.bin'
                command=[fixture.LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                    '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
                    '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),'-I',sources,
                    sources/'start.S',ROOT/'integrations/rtl_aarch64/entry_state_replay.c','-o',image]
                run(command);audit(image,fixture.LLVM);run([fixture.LLVM/'llvm-objcopy','-O','binary',image,binary])
                result,raw=observe(image,fixture.QEMU);require_success(result)
                other,binary_raw=observe(binary,fixture.QEMU,descriptor=image);require_success(other);self.assertEqual(raw,binary_raw)
                self.assertEqual((result['states_restored'],result['states_verified']),(6,6))
                if RETAIN is not None:
                    destination=RETAIN/hex(address);destination.mkdir(parents=True);shutil.copytree(sources,destination/'sources')
                    for artifact in (image,binary):shutil.copy2(artifact,destination/artifact.name)
                    (destination/'target-result.bin').write_bytes(raw)
                    evidence=dict(format='osrec-null-guard-fixture-v1',scope='native C fixture; no live policy changes',
                        plan=plan,full_plan=full,calls=rows,target=target_metadata(describe(image),8),target_observations=result,
                        elf_raw_match=True,elf_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
                    (destination/'manifest.json').write_text(json.dumps(evidence,indent=2)+'\n')
            faulty=BODY.replace('left->value=input^left->other;\n return left->value;','return input^left->other;')
            self.assertNotEqual(faulty,BODY);adapter.write_text(faulty+invoke);run(command);audit(image,fixture.LLVM)
            failed,_=observe(image,fixture.QEMU);self.assertEqual((failed['status'],failed['error']),(3,20))
            self.assertEqual(failed['actual_calls'][0]['raw_bits'],45)
            if RETAIN is not None:(RETAIN/'fault-verification.json').write_text(json.dumps(failed,indent=2)+'\n')

if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:fixture.LLVM=Path(sys.argv[1]);fixture.QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
