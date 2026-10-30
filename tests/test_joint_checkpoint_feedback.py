"""Output-dependent syscall execution preserves live user-stack and kernel state."""
import json,shutil,struct,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import test_discovered_joint_execution as base
from discover_kernel_state import write
from entry_state import digest
from export_syscall_slices import export
from run_c_application_checkpoint_chain import run_pipeline,verify_chain
from application_pause import verify_joint
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
LLVM=base.LLVM;QEMU=base.QEMU;RETAIN=None
MASK=(1<<64)-1;SEED=0x6a09e667f3bcc908;OFFSET=0xcbf29ce484222325


def feedback_project(out):
    base.project(out)
    capture=json.loads((base.FIXTURE/'capture.json').read_text())
    carry=SEED;checksum=OFFSET;value=capture['initial_value'];history=[dict(value=value,carry=carry,checksum=checksum,step=0)]
    for i,call in enumerate(capture['calls']):
        call['number']=0x100000051+((carry>>1)&1)
        call['delta']^=carry&63
        call['user_value']=carry;call['user_marker']=(carry>>8)&255
        value=(value+call['delta']+call['user_marker'])&MASK
        call['raw_bits']=value
        carry=(value^((i+1)<<32)^(carry<<1))&MASK
        checksum=((checksum^value^(i+1))*0x100000001b3)&MASK
        history.append(dict(value=value,carry=carry,checksum=checksum,step=i+1))
    write(out/'capture.json',capture);write(out/'feedback-history.json',history)
    prep=(out/'prepare.py').read_text().replace("value+call['delta']+3*(len(values)-1)+1","value+call['delta']+call['user_marker']")
    old="('values',values)";new="('values',values),('inputs',[c['user_value'] for c in capture['calls']]),('markers',[c['user_marker'] for c in capture['calls']])"
    assert prep.count(old)==2;prep=prep.replace(old,new);(out/'prepare.py').write_text(prep)
    adapter=(out/'adapter.c').read_text().replace('output->value!=in->ordinal+1 || output->marker!=3*in->ordinal+1',
        'output->value!=fixture_inputs[in->ordinal] || output->marker!=fixture_markers[in->ordinal]')
    (out/'adapter.c').write_text(adapter)
    proof=(out/'proof.c').read_text().replace('((Output *)memory[s])->value=i+1;((Output *)memory[s])->marker=3*i+1;',
        '((Output *)memory[s])->value=fixture_inputs[i];((Output *)memory[s])->marker=fixture_markers[i];')
    (out/'proof.c').write_text(proof)
    shutil.copyfile(ROOT/'examples/joint-feedback/application.c',out/'application.c')
    spec=json.loads((out/'spec.json').read_text())
    for row in spec['assertions']:
        if row['symbol']=='app_returns':row['data']=struct.pack('<6Q',*[c['raw_bits'] for c in capture['calls']]).hex()
        if row['symbol']=='app_output':row['data']=struct.pack('<2Q',value,6).hex()
    spec['assertions'].append(dict(symbol='app_feedback',data=struct.pack('<3Q',carry,checksum,6).hex()))
    write(out/'spec.json',spec)
    port=json.loads((out/'port.json').read_text());port['bundle']['inputs']={n:digest((out/n).read_bytes()) for n in port['bundle']['inputs']};write(out/'port.json',port)
    return history,capture


def symbols(elf):
    return {row.split()[0]:int(row.split()[2],16) for row in run([LLVM/'llvm-nm','--defined-only','--format=posix',elf]).stdout.splitlines() if len(row.split())>=3}


def memory_at(checkpoint,address,size):
    for snapshot in checkpoint['snapshots']:
        data=bytes.fromhex(snapshot['data']);offset=address-snapshot['address']
        if 0<=offset and offset+size<=len(data):return data[offset:offset+size]
    raise ValueError('address outside saved user memory')


class FeedbackTests(unittest.TestCase):
    def test_dependent_syscalls_live_stack_and_joint_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp).resolve();p=stage/'port';history,capture=feedback_project(p)
            args=SimpleNamespace(arch='aarch64',capture=p,kernel_root=p,out=stage/'library',port=p/'port.json',llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000)
            kernel=export(args);self.assertTrue(kernel['discovered_state_contract']['checkpoint_coverage_verified'])
            chain=SimpleNamespace(slices=args.out,source=[p/'application.c'],spec=p/'spec.json',pause_ordinals=[2,4],out=stage/'chain',llvm_bin=LLVM,qemu=QEMU)
            result=run_pipeline(chain);self.assertEqual(result['logical_calls'],6);verify_chain(chain.out)
            names=symbols(chain.out/'compiled/application.elf');observations=[]
            for i,ordinal in enumerate([2,4]):
                cp=chain.out/('stage-'+str(i))/'checkpoint';verify_joint(cp,kernel)
                document=json.loads((cp/'application/checkpoint.json').read_text())
                pointer=struct.unpack('<Q',memory_at(document,names['app_continuation_address'],8))[0]
                local=struct.unpack('<3Q',memory_at(document,pointer,24));expected=history[ordinal]
                self.assertEqual(local,(expected['carry'],expected['checksum'],ordinal))
                self.assertGreaterEqual(pointer,document['frame']['sp'])
                self.assertLessEqual(pointer+24,names['osrec_application_stack_top'])
                call=capture['calls'][ordinal];frame=document['frame']['x']
                self.assertEqual((frame[30],frame[19]),(call['number'],call['delta']))
                self.assertEqual(struct.unpack('<2Q',memory_at(document,names['app_output'],16)),(call['user_value'],call['user_marker']))
                observations.append(dict(pause_ordinal=ordinal,stack_address=pointer,carry=local[0],checksum=local[1],step=local[2],next_number=frame[30],next_delta=frame[19]))
            # User feedback changes the route and arguments, rather than following
            # the old alternating route/constant-argument fixture.
            original=json.loads((base.FIXTURE/'capture.json').read_text())['calls']
            self.assertNotEqual([c['number'] for c in capture['calls']],[c['number'] for c in original])
            self.assertTrue(all(c['delta']!=o['delta'] for c,o in zip(capture['calls'],original)))
            image=chain.out/'finish/image';src=image/'sources';driver=src/'slice_driver.c';original_driver=driver.read_text()
            adapter=image/'kernel-sources/adapter.c';original_adapter=adapter.read_text();faults=[]
            command=[LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align','-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                '-I',src,'-I',image/'kernel-sources','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(src/'image.ld'),src/'start.S',driver,src/'application_checkpoint.c']
            for kind in ('corrupt-user-stack','wrong-kernel-return'):
                extra=[]
                if kind=='corrupt-user-stack':
                    marker='if(osrec_import_check_initial())fail(3);'
                    self.assertIn(marker,original_driver)
                    driver.write_text(original_driver.replace(marker,marker+'*(volatile uint64_t *)(uintptr_t)'+str(observations[-1]['stack_address']+8)+'^=1;'))
                else:
                    marker='    return OSREC_SLICE_OK;';self.assertIn(marker,original_adapter)
                    adapter.write_text(original_adapter.replace(marker,'    out->raw^=2;\n'+marker));extra=[adapter]
                try:
                    elf=stage/(kind+'.elf');run([*command,*extra,image/'slices.a','-o',elf]);audit(elf,LLVM)
                    observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],3)
                    faults.append(dict(mutation=kind,observations=observed))
                finally:driver.write_text(original_driver);adapter.write_text(original_adapter)
            write(stage/'stack-observations.json',observations);write(stage/'faults.json',faults);verify_chain(chain.out)
            if RETAIN is not None:shutil.copytree(stage,RETAIN/'feedback')

if __name__=='__main__':
    if '--out' in sys.argv:
        i=sys.argv.index('--out');RETAIN=Path(sys.argv[i+1]).resolve();del sys.argv[i:i+2];RETAIN.mkdir(parents=True,exist_ok=False)
    unittest.main()
