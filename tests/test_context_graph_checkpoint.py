"""Bounded kernel object graphs survive fresh images; bad references reject atomically."""
import json
import re
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from export_syscall_slices import export
from run_c_application_checkpoint_chain import run_pipeline,verify_chain
from verify_syscall_slices import verify_matrix
from application_pause import verify_joint
from slice_checkpoint_codec import generate
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64'
FIXTURE=ROOT/'tests/fixtures/context-graph-port'


class ContextGraphTests(unittest.TestCase):
    def test_graph_chain_relocation_and_atomic_rejections(self):
        with tempfile.TemporaryDirectory(prefix='osrec-context-graph-') as name:
            stage=Path(name)
            args=SimpleNamespace(arch='aarch64',capture=FIXTURE,kernel_root=stage/'unused',out=stage/'kernel',port=FIXTURE/'port.json',llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000)
            kernel=export(args);codec=kernel['checkpoint_codec']
            self.assertEqual(kernel['state_layout']['OSREC_SLICE_STATE_BYTES'],96)
            self.assertEqual(codec['record_bytes'],160)
            self.assertEqual(len(verify_matrix(args.out,stage/'kernel-qemu',qemu=QEMU,llvm_bin=LLVM)['executions']),4)
            chain=SimpleNamespace(slices=args.out,source=[FIXTURE/'application.c'],spec=FIXTURE/'spec.json',pause_ordinals=[1,2,4,5],out=stage/'chain',llvm_bin=LLVM,qemu=QEMU)
            report=run_pipeline(chain)
            self.assertEqual([r['observations']['completed_calls'] for r in report['stages']],[1,2,4,2,2])
            fields={f['path']:f for f in codec['fields']}
            states=json.loads((FIXTURE/'capture.json').read_text())['states']
            for i,ordinal in enumerate(chain.pause_ordinals):
                joint=verify_joint(chain.out/('stage-'+str(i))/'checkpoint',kernel)
                record=joint['record'];expected={'head':states[ordinal]['head'],'tail':states[ordinal]['tail'],'calls':ordinal}
                for j,node in enumerate(states[ordinal]['nodes']):
                    expected.update({'nodes['+str(j)+'].'+key:value for key,value in node.items()})
                for path,value in expected.items():
                    f=fields[path];size=f.get('wire_bytes',f['bytes'])
                    self.assertEqual(int.from_bytes(record[64+f['wire_offset']:64+f['wire_offset']+size],'little'),value,path)
            for row in report['stages']:
                self.assertEqual(row['qemu_executions'],4)
                self.assertFalse(row['observations']['guest_host_services'])
                if row['input_ordinal']:
                    self.assertNotEqual(row['observations']['producer_state_address'],row['observations']['current_state_address'])
            self.assertEqual(verify_chain(chain.out)['status'],'verified')

            # Reuse the ordinal-2 cyclic graph consumer. A test-only callback
            # counter proves malformed IDs reject before port validation runs.
            image=chain.out/'stage-2/image';sources=image/'sources';driver=sources/'slice_driver.c';original=driver.read_text()
            kernel_sources=image/'kernel-sources';probe=stage/'codec-probe';shutil.copytree(kernel_sources,probe)
            policy=json.loads((probe/'checkpoint-policy.json').read_text())
            check=r'''
if(!run){
unsigned char before[OSREC_SLICE_STATE_BYTES],bad[sizeof(kernel_record)];
struct osrec_slice_session saved=session;
for(size_t j=0;j<sizeof(before);++j)before[j]=osrec_checkpoint_state[j];
for(unsigned trial=0;trial<5;++trial){
for(size_t j=0;j<sizeof(bad);++j)bad[j]=kernel_record[j];
if(trial==0)bad[64+HEAD]=4;
if(trial==1)bad[64+HEAD]=0;
if(trial==2)bad[64+HEAD]=3;
if(trial==3)bad[64+NEXT]=255;
if(trial==4)bad[64+GEN]^=1;
uint64_t h=UINT64_C(14695981039346656037);for(size_t j=0;j<sizeof(bad);++j)if(j<56 || j>=64)h=(h^bad[j])*UINT64_C(1099511628211);for(unsigned j=0;j<8;++j)bad[56+j]=(unsigned char)(h>>(8*j));
unsigned count=callback_checks;
if(osrec_slice_checkpoint_load(&session,&osrec_kernel_checkpoint_codec,bad,sizeof(bad))!=OSREC_SLICE_BAD_INPUT)fail(40+trial);
if(callback_checks-count!=((trial==0 || trial==3 || (trial==1 && NONNULL))?0u:1u))fail(46);
for(size_t j=0;j<sizeof(saved);++j)if(((unsigned char *)&session)[j]!=((unsigned char *)&saved)[j])fail(47);
for(size_t j=0;j<sizeof(before);++j)if(before[j]!=osrec_checkpoint_state[j])fail(48);
++osrec_result[19];}}
'''.replace('HEAD',str(fields['head']['wire_offset'])).replace('NEXT',str(fields['nodes[0].next']['wire_offset'])).replace('GEN',str(fields['nodes[0].generation']['wire_offset']))
            after=r'''
if(!run){
struct osrec_kernel_context *ctx=(void *)osrec_checkpoint_state;
if(ctx->head!=&ctx->nodes[0] || ctx->tail!=&ctx->nodes[1] || ctx->nodes[0].next!=&ctx->nodes[1] || ctx->nodes[1].next!=&ctx->nodes[0] || ctx->nodes[2].next)fail(60);
struct osrec_kernel_context foreign;Node *saved=ctx->head;
unsigned char bad[sizeof(kernel_record)];
for(unsigned trial=0;trial<2;++trial){
ctx->head=trial ? (Node *)((unsigned char *)&ctx->nodes[0]+1) : &foreign.nodes[0];
for(size_t j=0;j<sizeof(bad);++j)bad[j]=0xa5;
unsigned count=callback_checks;
if(osrec_slice_checkpoint_save(&session,&osrec_kernel_checkpoint_codec,bad,sizeof(bad))!=OSREC_SLICE_BAD_INPUT || callback_checks!=count || session.next!=2 || session.active || session.poisoned)fail(61);
for(size_t j=0;j<sizeof(bad);++j)if(bad[j]!=0xa5)fail(62);
ctx->head=saved;++osrec_result[19];}}
'''
            compiler=[LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align','-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-I'+str(sources),'-I'+str(probe)]
            for nonnull in (False,True):
                policy['fields']['head']['nullable']=not nonnull
                contract=stage/'policy.json';contract.write_text(json.dumps(policy))
                generated=generate(probe,LLVM/'clang',contract,codec['identity'])
                codec_source=probe/'slice_codec.c';codec_source.write_text(codec_source.read_text().replace('osrec_kernel_checkpoint_check','test_port_check'))
                raw=bytearray((chain.out/'stage-1/checkpoint/kernel.bin').read_bytes());raw[16:48]=bytes.fromhex(generated['schema_sha256'])
                h=14695981039346656037
                for j,b in enumerate(raw):
                    if j<56 or j>=64:h=((h^b)*1099511628211)&((1<<64)-1)
                struct.pack_into('<Q',raw,56,h)
                text=re.sub(r'(kernel_record\[160\]=)\{[^}]*\}',lambda m:m[1]+'{'+','.join(map(str,raw))+'}',original)
                text=text.replace('#include "slice_layout.h"','#include "slice_layout.h"\n#include "slice_context.h"')
                text=text.replace('void replay_main(void){','static unsigned callback_checks;\nextern uint32_t osrec_kernel_checkpoint_check(const void *,uint64_t);\nuint32_t test_port_check(const void *s,uint64_t n){++callback_checks;return osrec_kernel_checkpoint_check(s,n);}\nvoid replay_main(void){')
                marker='if(osrec_slice_checkpoint_load(&session,'
                text=text.replace(marker,check.replace('NONNULL',str(int(nonnull)))+'\n'+marker,1)
                text=text.replace('osrec_import_restore(&osrec_saved_frame);',after+'\nosrec_import_restore(&osrec_saved_frame);',1)
                driver.write_text(text);elf=stage/('probe-'+str(nonnull)+'.elf')
                run([*compiler,'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',driver,sources/'application_checkpoint.c',codec_source,image/'slices.a','-o',elf]);audit(elf,LLVM)
                observed,_=observe(elf,QEMU);require_success(observed)
                self.assertEqual(observed['checkpoint_rejections'],7)
            driver.write_text(original)

            # Complete classification, bounded target names and target C types
            # are construction requirements, before any image can be published.
            original_policy=json.loads((kernel_sources/'checkpoint-policy.json').read_text())
            for mutation in ('missing','range','duplicate','syntax','type','transient','element','raw-pointer','nullable'):
                p=json.loads(json.dumps(original_policy));head=p['fields']['head']
                if mutation=='missing':del p['fields']['nodes']['element']['members']['next']
                if mutation=='range':head['targets']=['nodes[3]']
                if mutation=='duplicate':head['targets']=['nodes[0]','nodes[0]']
                if mutation=='syntax':head['targets']=['nodes[0]+1']
                if mutation=='type':head['targets']=['calls']
                if mutation=='transient':p['fields']['calls']['policy']='transient';head['targets']=['calls']
                if mutation=='element':p['fields']['nodes']['element']['type']='Node[3]'
                if mutation=='raw-pointer':head['policy']='persist'
                if mutation=='nullable':head['nullable']=1
                contract.write_text(json.dumps(p))
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):generate(probe,LLVM/'clang',contract,{})


if __name__=='__main__':unittest.main()
