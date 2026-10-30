"""Owned buffer cursors relocate; invalid offsets reject before port callbacks."""
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
FIXTURE=ROOT/'tests/fixtures/context-buffer-port'


class ContextBufferTests(unittest.TestCase):
    def test_cursor_chain_offsets_relocation_and_rejections(self):
        with tempfile.TemporaryDirectory(prefix='osrec-context-buffers-') as name:
            stage=Path(name)
            args=SimpleNamespace(arch='aarch64',capture=FIXTURE,kernel_root=stage/'unused',out=stage/'kernel',port=FIXTURE/'port.json',llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000)
            kernel=export(args);codec=kernel['checkpoint_codec'];fields={f['path']:f for f in codec['fields']}
            self.assertEqual(kernel['state_layout']['OSREC_SLICE_STATE_BYTES'],96)
            self.assertEqual(codec['record_bytes'],184)
            self.assertEqual([f['name'] for f in kernel['context_plan']['array_initializers']],['buffers'])
            self.assertEqual(kernel['context_plan']['local_state'],[dict(name='osrec_local_BufferStep_calls_0',source='kernel.c',function='BufferStep',declaration='calls',type='uint64_t')])
            self.assertEqual(kernel['context_plan']['private_state'],[dict(name='osrec_private_'+str(i)+'_visits',source=source,declaration='visits',type='uint64_t') for i,source in enumerate(('kernel.c','provider.c'))])
            self.assertEqual(kernel['context_plan']['private_functions'],[dict(name='osrec_private_'+str(i)+'_Tick',source=source,declaration='Tick',symbol='osrec_kernel_osrec_private_'+str(i)+'_Tick') for i,source in enumerate(('kernel.c','provider.c'))])
            self.assertEqual(kernel['context_plan']['function_dependencies']['BufferStep'],['ProviderTick','osrec_private_0_Tick'])
            self.assertEqual(kernel['context_plan']['function_dependencies']['ProviderTick'],['osrec_private_1_Tick'])
            self.assertEqual(len(verify_matrix(args.out,stage/'kernel-qemu',qemu=QEMU,llvm_bin=LLVM)['executions']),4)
            chain=SimpleNamespace(slices=args.out,source=[FIXTURE/'application.c'],spec=FIXTURE/'spec.json',pause_ordinals=[1,2,4,5],out=stage/'chain',llvm_bin=LLVM,qemu=QEMU)
            report=run_pipeline(chain);states=json.loads((FIXTURE/'capture.json').read_text())['states']
            self.assertEqual([r['observations']['completed_calls'] for r in report['stages']],[1,2,4,2,2])
            for i,ordinal in enumerate(chain.pause_ordinals):
                record=verify_joint(chain.out/('stage-'+str(i))/'checkpoint',kernel)['record']
                self.assertEqual(struct.unpack_from('<Q',record,64+fields['osrec_local_BufferStep_calls_0']['wire_offset'])[0],ordinal)
                for i,factor in enumerate((1,3)):self.assertEqual(struct.unpack_from('<Q',record,64+fields['osrec_private_'+str(i)+'_visits']['wire_offset'])[0],factor*ordinal)
                for path in ('cursor','alias','end'):
                    self.assertEqual(struct.unpack_from('<QQ',record,64+fields[path]['wire_offset']),tuple(states[ordinal][path]))
                for b in range(2):
                    self.assertEqual(struct.unpack_from('<IIII',record,64+fields['buffers['+str(b)+'].words']['wire_offset']),tuple(states[ordinal]['words'][b]))
            for row in report['stages']:
                self.assertEqual(row['qemu_executions'],4);self.assertFalse(row['observations']['guest_host_services'])
                if row['input_ordinal']:self.assertNotEqual(row['observations']['producer_state_address'],row['observations']['current_state_address'])
            self.assertEqual(verify_chain(chain.out)['status'],'verified')

            # Instrument only the test codec callback. Shared runtime, kernel
            # bodies and application remain the archived implementation.
            image=chain.out/'stage-1/image';sources=image/'sources';driver=sources/'slice_driver.c';original=driver.read_text()
            probe=stage/'codec-probe';shutil.copytree(image/'kernel-sources',probe)
            original_policy=json.loads((probe/'checkpoint-policy.json').read_text());contract=stage/'policy.json'
            check=r'''
if(!run){
unsigned char before[OSREC_SLICE_STATE_BYTES],bad[sizeof(kernel_record)];struct osrec_slice_session saved=session;
for(size_t j=0;j<sizeof(before);++j)before[j]=osrec_checkpoint_state[j];
for(unsigned trial=0;trial<9;++trial){
for(size_t j=0;j<sizeof(bad);++j)bad[j]=kernel_record[j];
if(trial==0)bad[64+CURSOR]=3;
if(trial==1)bad[64+CURSOR+8]=2;
if(trial==2)bad[64+CURSOR+8]=20;
if(trial==3)bad[64+CURSOR]=0;
if(trial==4)bad[64+ALIAS+8]=16;
if(trial==5)bad[64+CURSOR]=WRONG_ID;
if(trial==6)bad[64+WORDS+4]^=1;
if(trial==7)for(unsigned j=0;j<8;++j)bad[64+CURSOR+8+j]=255;
if(trial==8)for(unsigned j=0;j<16;++j)bad[64+CURSOR+j]=0;
uint64_t h=UINT64_C(14695981039346656037);for(size_t j=0;j<sizeof(bad);++j)if(j<56 || j>=64)h=(h^bad[j])*UINT64_C(1099511628211);for(unsigned j=0;j<8;++j)bad[56+j]=(unsigned char)(h>>(8*j));
unsigned count=callback_checks;
if(osrec_slice_checkpoint_load(&session,&osrec_kernel_checkpoint_codec,bad,sizeof(bad))!=OSREC_SLICE_BAD_INPUT)fail(40+trial);
if(callback_checks-count!=((trial==5 || trial==6 || (trial==8 && !NONNULL))?1u:0u))fail(50);
for(size_t j=0;j<sizeof(saved);++j)if(((unsigned char *)&session)[j]!=((unsigned char *)&saved)[j])fail(51);
for(size_t j=0;j<sizeof(before);++j)if(before[j]!=osrec_checkpoint_state[j])fail(52);
++osrec_result[19];}}
'''
            after=r'''
if(!run){
struct osrec_kernel_context *ctx=(void *)osrec_checkpoint_state;
if(ctx->cursor!=&ctx->buffers[0].words[1] || ctx->alias!=ctx->cursor || ctx->end!=&ctx->buffers[0].words[4])fail(60);
unsigned char record[sizeof(kernel_record)];
if(osrec_slice_checkpoint_save(&session,&osrec_kernel_checkpoint_codec,record,sizeof(record)))fail(61);
for(size_t j=0;j<sizeof(record);++j)if(record[j]!=kernel_record[j])fail(62);
struct osrec_kernel_context foreign;uint32_t *cursor=ctx->cursor,*alias=ctx->alias;
for(unsigned trial=0;trial<5;++trial){
if(trial==0)ctx->cursor=&foreign.buffers[0].words[1];
if(trial==1)ctx->cursor=(uint32_t *)((unsigned char *)&ctx->buffers[0].words[0]+2);
if(trial==2)ctx->cursor=(uint32_t *)((unsigned char *)&ctx->buffers[0].words[0]+20);
if(trial==3)ctx->alias=&ctx->buffers[0].words[4];
if(trial==4)ctx->cursor=NULL;
for(size_t j=0;j<sizeof(record);++j)record[j]=0xa5;
unsigned count=callback_checks;
if(osrec_slice_checkpoint_save(&session,&osrec_kernel_checkpoint_codec,record,sizeof(record))!=OSREC_SLICE_BAD_INPUT || session.next!=1 || session.active || session.poisoned)fail(63);
if(callback_checks-count!=((trial==4 && !NONNULL)?1u:0u))fail(64);
for(size_t j=0;j<sizeof(record);++j)if(record[j]!=0xa5)fail(65);
ctx->cursor=cursor;ctx->alias=alias;++osrec_result[19];}}
'''
            for key,path in (('CURSOR','cursor'),('ALIAS','alias'),('WORDS','buffers[0].words')):check=check.replace(key,str(fields[path]['wire_offset']))
            compiler=[LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align','-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-I'+str(sources),'-I'+str(probe)]
            for nonnull,reorder in ((False,False),(True,False),(False,True)):
                policy=json.loads(json.dumps(original_policy));policy['fields']['cursor']['nullable']=not nonnull
                if reorder:policy['fields']['cursor']['targets'].reverse()
                contract.write_text(json.dumps(policy));generated=generate(probe,LLVM/'clang',contract,codec['identity'])
                codec_source=probe/'slice_codec.c';codec_source.write_text(codec_source.read_text().replace('osrec_kernel_checkpoint_check','test_port_check'))
                raw=bytearray((chain.out/'stage-0/checkpoint/kernel.bin').read_bytes());raw[16:48]=bytes.fromhex(generated['schema_sha256'])
                if reorder:struct.pack_into('<Q',raw,64+fields['cursor']['wire_offset'],2)
                h=14695981039346656037
                for j,b in enumerate(raw):
                    if j<56 or j>=64:h=((h^b)*1099511628211)&((1<<64)-1)
                struct.pack_into('<Q',raw,56,h)
                text,replacements=re.subn(r'(kernel_record\['+str(codec['record_bytes'])+r'\]=)\{[^}]*\}',lambda m:m[1]+'{'+','.join(map(str,raw))+'}',original)
                self.assertEqual(replacements,1)
                text=text.replace('#include "slice_layout.h"','#include "slice_layout.h"\n#include "slice_context.h"')
                text=text.replace('void replay_main(void){','static unsigned callback_checks;\nextern uint32_t osrec_kernel_checkpoint_check(const void *,uint64_t);\nuint32_t test_port_check(const void *s,uint64_t n){++callback_checks;return osrec_kernel_checkpoint_check(s,n);}\nvoid replay_main(void){')
                text=text.replace('if(osrec_slice_checkpoint_load(&session,',check.replace('NONNULL',str(int(nonnull))).replace('WRONG_ID',str(1 if reorder else 2))+'\nif(osrec_slice_checkpoint_load(&session,',1)
                text=text.replace('osrec_import_restore(&osrec_saved_frame);',after.replace('NONNULL',str(int(nonnull)))+'\nosrec_import_restore(&osrec_saved_frame);',1)
                driver.write_text(text);elf=stage/('probe-'+str(nonnull)+'-'+str(reorder)+'.elf')
                run([*compiler,'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',driver,sources/'application_checkpoint.c',codec_source,image/'slices.a','-o',elf]);audit(elf,LLVM)
                observed,_=observe(elf,QEMU);require_success(observed);self.assertEqual(observed['checkpoint_rejections'],14)
            driver.write_text(original)

            for mutation in ('scalar','aggregate','transient','wrong-element-type','flag','missing','range','duplicate'):
                p=json.loads(json.dumps(original_policy));cursor=p['fields']['cursor']
                if mutation=='scalar':cursor['targets']=['osrec_local_BufferStep_calls_0']
                if mutation=='aggregate':cursor['targets']=['buffers[0]']
                if mutation=='transient':p['fields']['buffers']['element']['members']['words']['policy']='transient'
                if mutation=='wrong-element-type':cursor['targets']=['buffers[0].guard'];p['fields']['buffers']['element']['members']['guard']['type']='uint64_t[1]';(probe/'buffer_types.h').write_text((probe/'buffer_types.h').read_text().replace('uint64_t guard;','uint64_t guard[1];'))
                if mutation=='flag':cursor['allow_one_past']=1
                if mutation=='missing':del p['fields']['end']
                if mutation=='range':cursor['targets']=['buffers[2].words']
                if mutation=='duplicate':cursor['targets']=['buffers[0].words']*2
                contract.write_text(json.dumps(p))
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):generate(probe,LLVM/'clang',contract,{})
                shutil.copyfile(image/'kernel-sources/buffer_types.h',probe/'buffer_types.h')
            # Removing the separating guard makes allowed ends ambiguous with
            # the following buffer's first element; reject this construction.
            p=json.loads(json.dumps(original_policy));del p['fields']['buffers']['element']['members']['guard']
            (probe/'buffer_types.h').write_text((probe/'buffer_types.h').read_text().replace('uint64_t guard;',''))
            contract.write_text(json.dumps(p))
            with self.assertRaisesRegex(ValueError,'ambiguous ranges'):generate(probe,LLVM/'clang',contract,{})


if __name__=='__main__':unittest.main()
