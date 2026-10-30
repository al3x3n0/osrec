"""Fresh-QEMU joint snapshots preserve file state, live CPU frames and user RAM."""
import json,shutil,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from test_callable_slices import options,LLVM,QEMU
from export_syscall_slices import export
from build_c_file_application_fixture import build
from import_application_checkpoint import import_checkpoint
from export_application_replay import export as compose
from application_pause import freeze,verify_joint,record_check,decode_frame
from verify_syscall_slices import verify_matrix
from slice_checkpoint_codec import generate
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success

class ApplicationCheckpointTests(unittest.TestCase):
    def test_standalone_pauses_relocation_and_rejections(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);a=options(stage);kernel=export(a)
            codec=kernel['checkpoint_codec'];self.assertEqual(codec['record_bytes'],272)
            fields={f['path']:f for f in codec['fields']}
            for f in ('witness','entry_path','jump','arguments'):self.assertEqual(fields[f]['policy'],'transient');self.assertNotIn('wire_offset',fields[f])
            self.assertEqual(fields['process.vmSpace']['policy'],'self_reference')
            build(a.out,stage/'fixture',LLVM,prefix_calls=5);app=stage/'fixture/compiled';routes=stage/'routes'
            document=json.loads((app/'checkpoint.json').read_text())
            vectors=[[0x1020304050607080+i,0x8877665544332200+i] for i in range(32)]
            document['frame'].update(v=vectors,fpcr=0x400000,fpsr=0x10)
            (app/'checkpoint.json').write_text(json.dumps(document))
            import_checkpoint(app/'application.elf',app/'checkpoint.json',routes)
            base=dict(slices=a.out,llvm_bin=LLVM,qemu=QEMU,arch='aarch64',result_address=0x40380000,window_calls=0)
            for pause in (1,5,31):
                with self.subTest(pause=pause):
                    p=stage/('producer-'+str(pause));producer=compose(SimpleNamespace(**base,application=routes,out=p,entry_address=0x40400000,checkpoint_mode='save',pause_ordinal=pause))
                    self.assertEqual(producer['target_observations']['completed_calls'],pause)
                    self.assertEqual(len(verify_matrix(p,stage/('producer-matrix-'+str(pause)),qemu=QEMU,llvm_bin=LLVM)['executions']),4)
                    joint=stage/('joint-'+str(pause));freeze(p,joint);verified=verify_joint(joint,kernel)
                    self.assertEqual(record_check(verified['record'],codec),pause)
                    frame=decode_frame((p/'pause-records/frame.bin').read_bytes())
                    self.assertEqual(frame['v'],vectors);self.assertEqual(frame['fpcr'],0x400000);self.assertEqual(frame['fpsr'],0x10)
                    self.assertEqual(json.loads((joint/'application/checkpoint.json').read_text())['frame'],frame)
                    history=json.loads((joint/'application/route-plan.json').read_text())
                    self.assertEqual(len(history['completed_sites']),pause)
                    self.assertEqual([s['svc_pc'] for s in history['completed_sites']],[s['pc'] for s in document['calls'][:pause]])
                    if pause>=5:
                        self.assertNotIn(history['completed_sites'][0]['svc_pc'],{s['svc_pc'] for s in history['sites']})
                    for i,s in enumerate(history['loads']):
                        if s['flags']&1:self.assertEqual((joint/'application'/s['file']).read_bytes(),(p/'application'/s['file']).read_bytes())
                    c=stage/('consumer-'+str(pause));consumer=compose(SimpleNamespace(**base,application=joint/'application',out=c,entry_address=0x40600000,checkpoint_mode='load',checkpoint=joint))
                    v=consumer['target_observations'];self.assertEqual(v['completed_calls'],2*(32-pause));self.assertEqual(v['kernel_checkpoint_checks'],2)
                    self.assertNotEqual(v['producer_state_address'],v['current_state_address']);self.assertFalse(v['guest_host_services'])
                    self.assertEqual(len(verify_matrix(c,stage/('consumer-matrix-'+str(pause)),qemu=QEMU,llvm_bin=LLVM)['executions']),4)
            image=stage/'consumer-5';sources=image/'sources';driver=sources/'slice_driver.c';original=driver.read_text()
            compiler=[LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align','-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-I'+str(sources),'-I'+str(image/'kernel-sources')]
            def execute(text):
                driver.write_text(text);elf=stage/'mutated.elf'
                run([*compiler,'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',driver,sources/'application_checkpoint.c',image/'slices.a','-o',elf]);audit(elf,LLVM)
                return observe(elf,QEMU)[0]
            # Corrupt records with valid checksums as well as invalid checksums.
            # Every rejected load must preserve both the context and ordinal.
            check='''
if(!run){
unsigned char before[OSREC_SLICE_STATE_BYTES],bad[sizeof(kernel_record)];
for(size_t j=0;j<sizeof(before);++j)before[j]=osrec_checkpoint_state[j];
for(unsigned trial=0;trial<6;++trial){
for(size_t j=0;j<sizeof(bad);++j)bad[j]=kernel_record[j];
if(trial==0)bad[0]^=1;
if(trial==1)bad[16]^=1;
if(trial==2)bad[48]=6;
if(trial==3)bad[64+CURSOR]^=1;
if(trial==4)bad[64+VERIFIED]^=1;
if(trial==5)bad[56]^=1;
if(trial<5){uint64_t h=UINT64_C(14695981039346656037);for(size_t j=0;j<sizeof(bad);++j)if(j<56 || j>=64)h=(h^bad[j])*UINT64_C(1099511628211);for(unsigned j=0;j<8;++j)bad[56+j]=(unsigned char)(h>>(8*j));}
if(osrec_slice_checkpoint_load(&session,&osrec_kernel_checkpoint_codec,bad,sizeof(bad))!=OSREC_SLICE_BAD_INPUT)fail(40+trial);
if(session.next || session.active || session.poisoned)fail(47);
for(size_t j=0;j<sizeof(before);++j)if(before[j]!=osrec_checkpoint_state[j])fail(48);
++osrec_result[19];}
session.active=1;if(osrec_slice_checkpoint_load(&session,&osrec_kernel_checkpoint_codec,kernel_record,sizeof(kernel_record))!=OSREC_SLICE_BUSY)fail(49);
if(osrec_slice_checkpoint_save(&session,&osrec_kernel_checkpoint_codec,bad,sizeof(bad))!=OSREC_SLICE_BUSY)fail(50);session.active=0;
session.poisoned=1;if(osrec_slice_checkpoint_load(&session,&osrec_kernel_checkpoint_codec,kernel_record,sizeof(kernel_record))!=OSREC_SLICE_POISONED)fail(51);session.poisoned=0;
if(osrec_slice_checkpoint_load(&session,&osrec_kernel_checkpoint_codec,osrec_checkpoint_state,sizeof(kernel_record))!=OSREC_SLICE_BAD_INPUT)fail(52);
if(osrec_slice_checkpoint_load(&session,&osrec_kernel_checkpoint_codec,kernel_record,sizeof(kernel_record)-1)!=OSREC_SLICE_BAD_INPUT)fail(53);
++osrec_result[19];}
'''.replace('CURSOR',str(fields['cursor']['wire_offset'])).replace('VERIFIED',str(fields['verified']['wire_offset']))
            marker='if(osrec_slice_checkpoint_load(&session,'
            v=execute(original.replace(marker,check+'\n'+marker,1));require_success(v);self.assertEqual(v['checkpoint_rejections'],7)
            prefix_pc=document['calls'][0]['pc']
            retired='''
if(!run){
struct osrec_aarch64_frame saved=osrec_saved_frame;
unsigned char before[OSREC_SLICE_STATE_BYTES];for(size_t j=0;j<sizeof(before);++j)before[j]=osrec_checkpoint_state[j];
osrec_saved_frame.pc=PREFIX_PC;
if(osrec_aarch64_gateway_run(&gateway)!=OSREC_SLICE_DIVERGED || gateway.entries || gateway.cursor || session.next!=5 || !session.poisoned || session.active || gateway.active)fail(60);
for(size_t j=0;j<sizeof(before);++j)if(before[j]!=osrec_checkpoint_state[j])fail(61);
if(osrec_import_check_initial())fail(62);
if(osrec_slice_session_restore(&session) || osrec_slice_checkpoint_load(&session,&osrec_kernel_checkpoint_codec,kernel_record,sizeof(kernel_record)))fail(63);
osrec_saved_frame=saved;++osrec_result[19];}
'''.replace('PREFIX_PC',str(prefix_pc))
            v=execute(original.replace('if(osrec_aarch64_gateway_run(&gateway)',retired+'\nif(osrec_aarch64_gateway_run(&gateway)',1));require_success(v);self.assertEqual(v['checkpoint_rejections'],1)
            for old,new in [(marker,'session.next=5;\nif(0 && osrec_slice_checkpoint_load(&session,'),('if(session.next!=32)','session.adapter->restore(session.state);\nif(session.next!=32)')]:
                self.assertIn(old,original);v=execute(original.replace(old,new,1));self.assertEqual(v['status'],3)
            driver.write_text(original)
            # Host identities fail before generating a consumer.
            joint=stage/'joint-5';bad=stage/'bad-joint';shutil.copytree(joint,bad)
            raw=bytearray((bad/'kernel.bin').read_bytes());raw[64]^=1;(bad/'kernel.bin').write_bytes(raw)
            with self.assertRaisesRegex(ValueError,'identity mismatch'):verify_joint(bad,kernel)
            wrong=json.loads(json.dumps(kernel));wrong['checkpoint_codec']['schema_sha256']='00'*32
            with self.assertRaisesRegex(ValueError,'identity mismatch'):verify_joint(joint,wrong)
            with self.assertRaisesRegex(ValueError,'schema'):record_check((joint/'kernel.bin').read_bytes(),wrong['checkpoint_codec'])
            for pause in (0,32,-1,True):
                with self.assertRaises(ValueError):compose(SimpleNamespace(**base,application=routes,out=stage/'invalid',entry_address=0x40400000,checkpoint_mode='save',pause_ordinal=pause))

    def test_schema_requires_complete_review_and_plain_persistent_leaves(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);a=options(stage);kernel=export(a);sources=a.out/'sources'
            original=json.loads((sources/'slice_checkpoint_policy.json').read_text());contract=stage/'policy.json'
            for mutate in ('missing','pointer','nested'):
                p=json.loads(json.dumps(original))
                if mutate=='missing':del p['fields']['cursor']
                if mutate=='pointer':p['fields']['witness']['policy']='persist'
                if mutate=='nested':p['fields']['space']['members']={}
                contract.write_text(json.dumps(p))
                with self.assertRaises(ValueError):generate(sources,LLVM/'clang',contract,{})
            changed=(sources/'slice_context.h').read_text().replace('uint32_t cursor;','uint64_t cursor;');(sources/'slice_context.h').write_text(changed)
            contract.write_text(json.dumps(original))
            with self.assertRaisesRegex(ValueError,'type changed'):generate(sources,LLVM/'clang',contract,{})

if __name__=='__main__':unittest.main()
