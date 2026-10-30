"""Retain incoming may-written scalar values when exit overwrite is unproven."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

import test_entry_state_argument_dominance as fixture
from entry_state import Analyzer,entry_accesses,capture_header
from reconstruct_entry_state import reconstruction_header
from freestanding_armv7 import run,audit
from freestanding_elf import prepare_target,describe,target_metadata
from run_freestanding_armv7 import observe,require_success

ROOT=fixture.ROOT;RETAIN=None
BODY='''unsigned overwrite(Obj *left,unsigned input){if(!left)return 0;
 return (input&1U)?(left->value=input^left->other,left->value):0;}
'''
EXPECTED=[0,0xffffffef,0,0xfffffffe,0,0]

class WritePreservationTests(unittest.TestCase):
    def test_exit_coverage_and_conservative_regions(self):
        cases={
            'full':'left->value=input;return left->value;',
            'both':'if(input)left->value=4;else left->value=5;return left->value;',
            'early':'if(input)return 0;left->value=4;return left->value;',
            'write_only':'if(input)left->value=4;return 0;',
            'loop':'for(;input;){left->value=4;break;}return 0;',
            'two_stores':'left->value=4;left->other=5;return 0;',
            'barrier':'left->value=4;barrier_effect();return 0;',
            'helper':'write_helper(left);return 0;',
            'range':'left->array[input&3U]=4;return 0;',
        }
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);helper=fixture.ArgumentDominanceTests()
            source='void barrier_effect(void);void write_helper(Obj *p){p->value=4;}\n'+''.join(
                'unsigned '+root+'(Obj *left,unsigned input){'+body+'}\n' for root,body in cases.items())
            tree,_,_=helper.parse(stage,source)
            boundaries={'barrier_effect':{'kind':'ordering_model','reason':'fixture interference','implementation':'reviewed barrier'}}
            for root in cases:
                with self.subTest(root=root):
                    p=helper.plan(tree,root,boundaries=boundaries,preserve_write_state=True);self.assertFalse(p['blockers'])
                    fields={f['path'] for f in p['preserved_entry_fields']}
                    expected=set() if root in ('full','both') else ({'osrec_argument_left()->array['+str(i)+']' for i in range(4)} if root=='range' else {'osrec_argument_left()->value'})
                    self.assertEqual(fields,expected);entry_accesses(p);capture_header([p])
                    self.assertFalse(p['minimality_proven']);self.assertFalse(p['completeness_proven'])
                    if root=='loop':self.assertTrue(p['write_state_preservation']['unsupported_control_flow'])
                    if root=='both':self.assertEqual(len(p['write_state_preservation']['guaranteed_exit_stores'][0]['locations']),2)
            tree,_,_=helper.parse(stage,'void overwrite(Obj *left,unsigned input){left->value=input;}')
            p=helper.plan(tree,preserve_write_state=True);self.assertFalse(p['preserved_entry_fields'])
            self.assertEqual(p['write_state_preservation']['guaranteed_exit_stores'][0]['path'],'osrec_argument_left()->value')
            with self.assertRaisesRegex(ValueError,'requires prune_written'):
                Analyzer(tree,argument_objects={'overwrite':{'left':fixture.CONTRACT}},preserve_write_state=True)
            self.assertNotIn('preserved_entry_fields',helper.plan(tree))

    def test_native_inputs_and_projection_rejections(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);p,_,rows=fixture.ArgumentDominanceTests().capture(stage,BODY,preserve_write_state=True)
            self.assertEqual([r['raw'] for r in rows],EXPECTED)
            self.assertEqual({r['path'] for r in p['entry_reads']},{'osrec_argument_left()->other'})
            self.assertEqual([r['path'] for r in p['preserved_entry_fields']],['osrec_argument_left()->value'])
            self.assertEqual([sum(f['bytes'] for f in r['entry']['fields']) for r in rows],[8]*5+[0])
            header=reconstruction_header([r['entry'] for r in rows],[p]*6,post_states=[r['post'] for r in rows],scalar_arguments=True)
            source=stage/'host.c';source.write_text('#include <stdint.h>\n'+fixture.MODEL+header+BODY+
                'int main(void){unsigned initial[6]={0,0xffffffffU,0x80000000U,0x12345678U,99,0};'
                'unsigned expected[6]={'+','.join(str(v)+'U' for v in EXPECTED)+'};'
                'for(unsigned i=0;i<6;++i){if(!osrec_restore(i))return 1;'
                'if(i<5&&osrec_bound_osrec_argument_left->value!=initial[i])return 2;'
                'if(overwrite(osrec_bound_osrec_argument_left,osrec_argument(i,1))!=expected[i])return 3;'
                'if(!osrec_state_matches(i))return 4;}return 0;}\n')
            binary=stage/'host';run([fixture.LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary]);run([binary])
            for change in ('path','type','reason','pointer','duplicate','metadata','contract'):
                plan=copy.deepcopy(p);row=plan['preserved_entry_fields'][0]
                if change=='path':row['path']='osrec_argument_left()->other'
                elif change=='type':row['type']='unsigned short'
                elif change=='reason':row['preservation_reason']='invented preservation input'
                elif change=='pointer':row['pointer_edge']=True
                elif change=='duplicate':plan['preserved_entry_fields'].append(copy.deepcopy(row))
                elif change=='metadata':plan.pop('write_state_preservation')
                else:plan['object_providers'][0]['contract'].pop('exclusive_state')
                with self.subTest(change=change),self.assertRaises(ValueError):entry_accesses(plan)
            entries=[copy.deepcopy(r['entry']) for r in rows];entries[2]['fields']=[f for f in entries[2]['fields'] if f['name']!='value']
            with self.assertRaisesRegex(ValueError,'planned field missing'):
                reconstruction_header(entries,[p]*6,post_states=[r['post'] for r in rows],scalar_arguments=True)
            rejected=subprocess.run([sys.executable,ROOT/'tools/entry_state.py','--compile-commands',stage/'compile_commands.json',
                '--source',stage/'input.c','--root','overwrite','--preserve-write-state','--out',stage/'bad.json'],capture_output=True,text=True)
            self.assertEqual(rejected.returncode,2);self.assertFalse((stage/'bad.json').exists())

    def test_aarch64_preserved_skip_paths_and_faults(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);p,full,rows=fixture.ArgumentDominanceTests().capture(stage,BODY,preserve_write_state=True)
            sources=stage/'sources';sources.mkdir()
            (sources/'entry_model.h').write_text('#include <stdint.h>\n'+fixture.MODEL)
            (sources/'entry_reconstruction.h').write_text(reconstruction_header([r['entry'] for r in rows],[p]*6,post_states=[r['post'] for r in rows],scalar_arguments=True))
            adapter=sources/'entry_adapter.h';invoke='uint32_t osrec_invoke(uint32_t number){(void)number;static unsigned i;return overwrite(osrec_bound_osrec_argument_left,osrec_argument(i++,1));}\n'
            adapter.write_text(BODY+invoke)
            (sources/'entry_checkpoint.h').write_text('#define OSREC_CHECKPOINT_CALLS 6\nstruct checkpoint_call{uint32_t number,raw;};\nstatic const struct checkpoint_call checkpoint_calls[6]={'+','.join('{1,UINT32_C('+str(r['raw'])+')}' for r in rows)+'};\n')
            for address in (0x40200000,0x40400000):
                flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=address,result_address=address-0x80000),sources)
                image=stage/'preservation.elf';binary=stage/'preservation.bin'
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
                    evidence=dict(format='osrec-write-preservation-fixture-v1',scope='native C skipped-write fixture; no live kernel preservation profile',
                        plan=p,full_plan=full,calls=rows,target=target_metadata(describe(image),8),target_observations=result,
                        elf_raw_match=True,elf_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
                    (destination/'manifest.json').write_text(json.dumps(evidence,indent=2)+'\n')
            # Destroying preserved state on the skip path keeps the return
            # correct but must fail at the nonzero incoming value of call 2.
            faulty=BODY.replace(':0;',':(left->value=0,0);')
            adapter.write_text(faulty+invoke);run(command);audit(image,fixture.LLVM)
            failed,_=observe(image,fixture.QEMU);self.assertEqual((failed['status'],failed['error']),(3,22))
            self.assertEqual(failed['completed_calls'],2);self.assertEqual(failed['actual_calls'][2]['raw_bits'],0)
            # Corrupt a captured preservation input without changing outputs.
            adapter.write_text(BODY+invoke)
            entries=[copy.deepcopy(r['entry']) for r in rows]
            next(f for f in entries[2]['fields'] if f['name']=='value')['data']='01000080'
            (sources/'entry_reconstruction.h').write_text(reconstruction_header(entries,[p]*6,post_states=[r['post'] for r in rows],scalar_arguments=True))
            run(command);audit(image,fixture.LLVM);failed,_=observe(image,fixture.QEMU)
            self.assertEqual((failed['status'],failed['error'],failed['completed_calls']),(3,22,2))

if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2];RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:fixture.LLVM=Path(sys.argv[1]);fixture.QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
