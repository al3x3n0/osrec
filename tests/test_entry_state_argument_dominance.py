"""Contracted argument-field omissions, native capture and target effect checks."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import Analyzer,load_ast,capture_header
from automated_entry_state import effect_plan
from reconstruct_entry_state import reconstruction_header
from freestanding_armv7 import run,audit
from freestanding_elf import prepare_target,describe,target_metadata
from run_freestanding_armv7 import observe,require_success

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64';RETAIN=None
MODEL='typedef struct Obj {unsigned value,other;unsigned array[4];struct Obj *next;} Obj;\n'
BODY='''unsigned overwrite(Obj *left,unsigned input){
 if(!left)return 0;
 left->value=input^left->other;
 return left->value;
}
'''
CONTRACT={'kind':'object_argument','reason':'caller owns an isolated stable fixture object',
    'implementation':'argument binding with no concurrent writers for the complete call','snapshot_safe':True,
    'stable_identity':True,'exclusive_state':True,'preserves_entry_state':True}

class ArgumentDominanceTests(unittest.TestCase):
    def parse(self,stage,body=BODY):
        source=stage/'input.c';source.write_text(MODEL+body)
        database=stage/'compile_commands.json';database.write_text(json.dumps([{'directory':str(stage),'file':str(source),
            'arguments':[str(LLVM/'clang'),'-std=c11','-c',str(source)]}]))
        return load_ast(database,source)[0],database,source

    def plan(self,tree,root='overwrite',contract=CONTRACT,prune=True,boundaries=None,preserve_write_state=False):
        return Analyzer(tree,boundaries=boundaries,prune_written=prune,
            argument_objects={root:{'left':contract}},preserve_write_state=preserve_write_state).analyze(root)

    def test_proof_contracts_control_flow_aliases_and_barriers(self):
        cases={
            'direct':'left->value=4;return left->value;',
            'both':'if(input)left->value=4;else left->value=5;return left->value;',
            'alias':'Obj *alias=left;alias->value=4;return left->value;',
            'early':'if(input)return left->other;left->value=4;return left->value;',
            'indexed':'left->array[2]=4;return left->array[2];',
            'conditional':'if(input)left->value=4;return left->value;',
            'compound':'left->value+=4;return left->value;',
            'loop':'while(input--)left->value=4;return left->value;',
            'intervening':'left->value=4;left->other=5;return left->value;',
            'barrier':'left->value=4;barrier_effect();return left->value;',
            'unsequenced':'left->value=4;return left->value+(left->other=1);',
            'partial':'*((unsigned char *)&left->value)=4;return left->value;',
            'nested':'left->next->value=4;return left->next->value;',
            'rebind':'left->value=4;left=left->next;return left->value;',
            'range':'left->array[input&3U]=4;return left->array[2];',
            'ambiguous':'Obj *p=input?left:left->next;p->value=4;return left->value;',
            'through_helper':'left->value=4;return read_helper(left);',
        }
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            text='void barrier_effect(void);\nunsigned read_helper(Obj *p){return p->value;}\n'+''.join('unsigned '+root+'(Obj *left,unsigned input){'+body+'}\n' for root,body in cases.items())
            tree,_,_=self.parse(stage,text)
            policy={'barrier_effect':{'kind':'ordering_model','reason':'fixture ordering boundary','implementation':'reviewed external barrier'}}
            for root in cases:
                with self.subTest(root=root):
                    p=self.plan(tree,root,boundaries=policy)
                    if root=='rebind':
                        self.assertIn('alias_limit',{b['kind'] for b in p['blockers']})
                        self.assertFalse(p.get('dominated_reads',[]));continue
                    self.assertFalse(p['blockers'])
                    omitted={r['path'] for r in p['dominated_reads']}
                    if root in ('direct','both','alias','early','indexed'):
                        self.assertTrue(omitted)
                    else:self.assertFalse(omitted)
                    self.assertFalse(p['minimality_proven']);self.assertFalse(p['completeness_proven'])
            for flag in ('stable_identity','exclusive_state','preserves_entry_state'):
                for value in (None,False,1,'true'):
                    contract=copy.deepcopy(CONTRACT)
                    if value is None:contract.pop(flag)
                    else:contract[flag]=value
                    p=self.plan(tree,'direct',contract)
                    self.assertTrue(p['entry_reads']);self.assertFalse(p['dominated_reads'])
            self.assertTrue(self.plan(tree,'direct',prune=False)['entry_reads'])
            # An incoming read is retained even when a later occurrence is covered.
            tree,_,_=self.parse(stage,'unsigned overwrite(Obj *left,unsigned input){unsigned v=left->value;left->value=input;return v+left->value;}')
            p=self.plan(tree);self.assertEqual(len(p['entry_reads']),1);self.assertEqual(len(p['dominated_reads']),1)

    def capture(self,stage,body=BODY,preserve_write_state=False):
        tree,database,source=self.parse(stage,body);plan=self.plan(tree,preserve_write_state=preserve_write_state);full=self.plan(tree,prune=False)
        self.assertEqual({r['path'] for r in plan['entry_reads']},{'osrec_argument_left()->other'})
        self.assertEqual({r['path'] for r in plan['dominated_reads']},{'osrec_argument_left()->value'})
        policy=stage/'policy.json';policy.write_text(json.dumps({'format':'osrec-entry-state-boundaries-v1','boundaries':{},
            'argument_objects':{'overwrite':{'left':CONTRACT}}}))
        output=stage/'cli-plan.json'
        run([sys.executable,ROOT/'tools/entry_state.py','--compile-commands',database,'--source',source,
            '--root','overwrite','--boundaries',policy,'--prune-written-fields',
            *(['--preserve-write-state'] if preserve_write_state else []),'--out',output])
        self.assertEqual(json.loads(output.read_text())['plans'][0],plan)
        hooks=capture_header([plan,{**full,'root':'full_overwrite'},{**effect_plan(plan),'root':'effects_overwrite'}])
        (stage/'capture.h').write_text(hooks)
        native=stage/'native.c';native.write_text(MODEL+body+r'''
#include <stdio.h>
#include "capture.h"
static void emit(struct osrec_entry_snapshot *s,unsigned invocation,unsigned input){
 printf("{\"format\":\"osrec-entry-snapshot-v1\",\"syscall\":1,\"invocation\":%u,\"objects\":[",invocation);
 for(unsigned i=0;i<s->object_count;++i)printf("%s{\"id\":%u,\"type\":\"%s\"}",i?",":"",s->objects[i].id,s->objects[i].type);
 printf("],\"roots\":[");
 for(unsigned i=0;i<s->root_count;++i)printf("%s{\"name\":\"%s\",\"object_id\":%u}",i?",":"",s->roots[i].name,s->roots[i].object_id);
 printf("],\"arguments\":[{\"name\":\"input\",\"bytes\":4,\"data\":\"");
 for(unsigned j=0;j<4;++j)printf("%02x",(input>>(8*j))&255U);
 printf("\"}],\"fields\":[");
 for(unsigned i=0;i<s->field_count;++i){struct osrec_snapshot_field *f=&s->fields[i];
  if(f->is_edge)return;
  printf("%s{\"object_id\":%u,\"name\":\"%s\",\"kind\":\"scalar\",\"bytes\":%u,\"data\":\"",i?",":"",f->object_id,f->name,f->size);
  for(unsigned j=0;j<f->size;++j)printf("%02x",f->bytes[j]);printf("\"}");}
 printf("]}");
}
int main(void){
 unsigned initial[6]={0,0xffffffffU,0x80000000U,0x12345678U,99,0};
 unsigned other[6]={7,16,128,0xffffffffU,0,0};
 unsigned input[6]={42,0xffffffffU,0x80000000U,1,0,123};
 puts("[");
 for(unsigned i=0;i<6;++i){Obj object={initial[i],other[i],{0},0};Obj *left=i==5?0:&object;
  struct osrec_entry_snapshot before,full,after;osrec_snapshot_init(&before);osrec_snapshot_init(&full);osrec_snapshot_init(&after);
  if(!osrec_snapshot_overwrite(&before,left)||!osrec_snapshot_full_overwrite(&full,left))return 1;
  unsigned raw=overwrite(left,input[i]);if(!osrec_snapshot_effects_overwrite(&after,left))return 2;
  printf("%s{\"entry\":",i?",":"");emit(&before,i,input[i]);printf(",\"full_entry\":");emit(&full,i,input[i]);
  printf(",\"post\":");emit(&after,i,input[i]);printf(",\"raw\":%u}",raw);
 }puts("]");return 0;
}
''')
        binary=stage/'native';run([LLVM/'clang','-std=c11','-I',ROOT/'include','-I',stage,native,ROOT/'runtime/entry_snapshot.c','-o',binary])
        rows=json.loads(run([binary]).stdout)
        return plan,full,rows

    def test_native_reduced_snapshots_and_host_replay(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);plan,full,rows=self.capture(stage)
            entries=[r['entry'] for r in rows];posts=[r['post'] for r in rows]
            self.assertEqual([r['raw'] for r in rows],[45,0xffffffef,0x80000080,0xfffffffe,0,0])
            self.assertEqual([sum(f['bytes'] for f in r['fields']) for r in entries],[4]*5+[0])
            self.assertEqual([sum(f['bytes'] for f in r['full_entry']['fields']) for r in rows],[8]*5+[0])
            header=reconstruction_header(entries,[plan]*6,post_states=posts,scalar_arguments=True)
            for i,row in enumerate(rows):
                source=stage/'host.c';source.write_text('#include <stdint.h>\n'+MODEL+header+BODY+
                    'int main(void){if(!osrec_restore('+str(i)+'))return 1;'+
                    ('if(osrec_bound_osrec_argument_left->value!=0)return 2;' if i<5 else '')+
                    'if(overwrite(osrec_bound_osrec_argument_left,osrec_argument('+str(i)+',1))!='+str(row['raw'])+'U)return 3;'
                    'return !osrec_state_matches('+str(i)+');}\n')
                binary=stage/'host';run([LLVM/'clang','-std=c11','-Wall','-Wextra','-Werror',source,'-o',binary]);run([binary])
            with self.assertRaisesRegex(ValueError,'write-effect'):reconstruction_header(entries,[plan]*6,scalar_arguments=True)
            # Omitted fields never become a complete continuous entry footprint.
            e=copy.deepcopy(entries);p=copy.deepcopy(posts)
            for state in e+p:
                for obj in state['objects']:obj['session_id']=1
            with self.assertRaisesRegex(ValueError,'complete field footprint'):
                reconstruction_header(e[:1],[plan],post_states=p[:1],scalar_arguments=True,continuous=True)

    def test_aarch64_relocation_and_omitted_write_fault(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);plan,full,rows=self.capture(stage);sources=stage/'sources';sources.mkdir()
            entries=[r['entry'] for r in rows];posts=[r['post'] for r in rows]
            (sources/'entry_model.h').write_text('#include <stdint.h>\n'+MODEL)
            (sources/'entry_reconstruction.h').write_text(reconstruction_header(entries,[plan]*6,post_states=posts,scalar_arguments=True))
            adapter=sources/'entry_adapter.h';invoke='uint32_t osrec_invoke(uint32_t number){(void)number;static unsigned i;return overwrite(osrec_bound_osrec_argument_left,osrec_argument(i++,1));}\n'
            adapter.write_text(BODY+invoke)
            (sources/'entry_checkpoint.h').write_text('#define OSREC_CHECKPOINT_CALLS 6\nstruct checkpoint_call{uint32_t number,raw;};\nstatic const struct checkpoint_call checkpoint_calls[6]={'+','.join('{1,UINT32_C('+str(r['raw'])+')}' for r in rows)+'};\n')
            for address in (0x40200000,0x40400000):
                flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=address,result_address=address-0x80000),sources)
                image=stage/'arguments.elf';binary=stage/'arguments.bin'
                command=[LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                    '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
                    '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),'-I',sources,
                    sources/'start.S',ROOT/'integrations/rtl_aarch64/entry_state_replay.c','-o',image]
                run(command);audit(image,LLVM);run([LLVM/'llvm-objcopy','-O','binary',image,binary])
                result,raw=observe(image,QEMU);require_success(result)
                other,raw_binary=observe(binary,QEMU,descriptor=image);require_success(other);self.assertEqual(raw,raw_binary)
                self.assertEqual((result['states_restored'],result['states_verified']),(6,6))
                if RETAIN is not None:
                    destination=RETAIN/hex(address);destination.mkdir(parents=True)
                    shutil.copytree(sources,destination/'sources')
                    for artifact in (image,binary):shutil.copy2(artifact,destination/artifact.name)
                    (destination/'target-result.bin').write_bytes(raw)
                    evidence=dict(format='osrec-argument-dominance-fixture-v1',scope='native C fixture; no live kernel pruning',
                        plan=plan,full_plan=full,calls=rows,target=target_metadata(describe(image),8),target_observations=result,
                        elf_raw_match=True,elf_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
                    (destination/'manifest.json').write_text(json.dumps(evidence,indent=2)+'\n')
            # Compute the correct return without writing: post-state must fail.
            faulty=BODY.replace('left->value=input^left->other;\n return left->value;','return input^left->other;')
            self.assertNotEqual(faulty,BODY);adapter.write_text(faulty+invoke);run(command);audit(image,LLVM)
            failed,_=observe(image,QEMU);self.assertEqual(failed['actual_calls'][0]['raw_bits'],45)
            self.assertEqual((failed['status'],failed['error']),(3,20))

if __name__=='__main__':
    if '--out' in sys.argv:
        index=sys.argv.index('--out');RETAIN=Path(sys.argv[index+1]).resolve();del sys.argv[index:index+2]
        RETAIN.mkdir(parents=True,exist_ok=False)
    if len(sys.argv)==3:LLVM=Path(sys.argv[1]);QEMU=sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main()
