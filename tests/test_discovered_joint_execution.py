"""Discovered typed state feeds live user/kernel execution and joint checkpoints."""
import copy,json,shutil,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from entry_state import digest
from discover_kernel_state import survey_unit,write
from discover_call_closure import DefinitionIndex,discover,analysis_sources
from export_syscall_slices import export
from run_c_application_checkpoint_chain import run_pipeline,verify_chain
from application_pause import verify_joint
from discovered_slice_contract import prepare,check_checkpoint_coverage
from contextify_slice import transform
from freestanding_armv7 import run,audit
from freestanding_elf import prepare_target
from run_freestanding_armv7 import observe
LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU='qemu-system-aarch64';RETAIN=None
FIXTURE=ROOT/'tests/fixtures/portable-slice-port'
CONTRACT=dict(kind='object_argument',snapshot_safe=True,reason='complete caller-owned output record',implementation='live EL0 memory resolved at each invocation')
PROVIDER=dict(kind='object_provider',snapshot_safe=True,reason='stable private kernel ledger',implementation='Current returns the same static ledger; context transform relocates it')

def project(out):
    shutil.copytree(FIXTURE,out)
    model=(out/'port_types.h').read_text().replace('uint64_t Provider(uint64_t,void *);','typedef struct Output {uint64_t value,marker;} Output;\nLedger *Current(void);\nuint64_t Provider(uint64_t,Output *);').replace('void *','Output *')
    (out/'port_types.h').write_text(model)
    (out/'kernel.c').write_text((out/'kernel.c').read_text().replace('void *','Output *'))
    text=(out/'provider.c').read_text();a=text.index('uint64_t Provider(')
    text=text[:a]+'''Ledger *Current(void){return alias;}
uint64_t Provider(uint64_t delta,Output *output){
 Ledger *state=Current();state->value+=delta;
 if(output->value)state->value+=output->marker;
 ++state->calls;output->value=state->value;output->marker=state->calls;
 return state->value;
}
'''
    (out/'provider.c').write_text(text)
    # Every next input is produced by user instructions, not a post-state copy.
    capture=json.loads((out/'capture.json').read_text());value=capture['initial_value'];values=[value]
    for i,call in enumerate(capture['calls']):
        value=(value+call['delta']+(3*i+1))&((1<<64)-1);call['raw_bits']=value;values.append(value)
    write(out/'capture.json',capture)
    adapter=(out/'adapter.c').read_text().replace('#include "capture.h"','#include "capture.h"\n#include "discovery_bindings.h"')
    a=adapter.index('    const struct osrec_user_region *region=');b=adapter.index('    uintptr_t arguments',a)
    adapter=adapter[:a]+'''    Output *output=in->number==fixture_numbers[0] ? osrec_discovered_Add_output(in) : osrec_discovered_Adjust_output(in);
    if(!output || output->value!=in->ordinal+1 || output->marker!=3*in->ordinal+1)return OSREC_SLICE_BAD_INPUT;
    unsigned char *buffer=(unsigned char *)output;
'''+adapter[b:]
    a=adapter.index('    for(unsigned i=0;i<16;++i)if(buffer[i]');b=adapter.index('    return OSREC_SLICE_OK;',a)
    adapter=adapter[:a]+'''    if(output->value!=fixture_values[in->ordinal+1] || output->marker!=in->ordinal+1)return OSREC_SLICE_DIVERGED;
'''+adapter[b:];(out/'adapter.c').write_text(adapter)
    # Session proof produces the same user-side modifications before every call.
    proof=(out/'proof.c').read_text();proof=proof.replace('    struct osrec_slice_invocation in=invocation(s,i);',
        '    ((Output *)memory[s])->value=i+1;((Output *)memory[s])->marker=3*i+1;\n    struct osrec_slice_invocation in=invocation(s,i);')
    a=proof.index('    for(unsigned j=0;j<16;++j)if(memory[s][j]');b=proof.index('    ++osrec_result[12]',a)
    proof=proof[:a]+'''    if(((Output *)memory[s])->value!=fixture_values[i+1] || ((Output *)memory[s])->marker!=i+1)fail(3);
'''+proof[b:];proof=proof.replace('static unsigned char memory[2][16]','static _Alignas(8) unsigned char memory[2][16]');(out/'proof.c').write_text(proof)
    prep=(out/'prepare.py').read_text().replace("value = (value+call['delta'])", "value = (value+call['delta']+3*(len(values)-1)+1)")
    prep=prep.replace("'checkpoint-policy.json'):","'checkpoint-policy.json','discovery-contract.json','discovery-Add.json','discovery-Adjust.json'):")
    prep=prep.replace("return dict(identity=","return dict(discovery_contract='discovery-contract.json',identity=")
    (out/'prepare.py').write_text(prep)
    app=(out/'application.c').read_text();a=app.index('        uint64_t raw=');app=app[:a]+'''        ((uint64_t *)app_output)[0]=i+1;((uint64_t *)app_output)[1]=3*i+1;
'''+app[a:]
    a=app.index('        for(unsigned j=0;j<16;++j)');b=app.index('\n    }',a)
    app=app[:a]+'''        app_failed|=((uint64_t *)app_output)[0]!=raw || ((uint64_t *)app_output)[1]!=i+1;
'''+app[b:];(out/'application.c').write_text(app)
    spec=json.loads((out/'spec.json').read_text())
    import struct
    for row in spec['assertions']:
        if row['symbol']=='app_returns':row['data']=struct.pack('<6Q',*values[1:]).hex()
        if row['symbol']=='app_output':row['data']=struct.pack('<2Q',values[-1],6).hex()
    write(out/'spec.json',spec)
    # Survey exact configured C objects, then discover the two real fixture roots.
    entries=[dict(directory=str(out),file=str(out/n),arguments=[str(LLVM/'clang'),'--target=aarch64-none-elf','-std=c11','-I',str(out),'-c',str(out/n)]) for n in ('provider.c','kernel.c')]
    db=out/'compile_commands.json';write(db,entries);units=[];objects=[]
    for i,e in enumerate(entries):
        src=Path(e['file']);obj=src.with_suffix('.o');dep=src.with_suffix('.d')
        run([*e['arguments'],'-MD','-MF',dep,'-o',obj]);unit=survey_unit(db,src,100);path=out/('unit-'+str(i)+'.json');write(path,unit)
        units.append(dict(source=str(src),status='analyzed',report=path.name,report_sha256=digest(path.read_bytes())))
        objects.append(dict(source=str(src),source_sha256=digest(src.read_bytes()),language='c',object=str(obj),object_sha256=digest(obj.read_bytes()),dependency_file_sha256=digest(dep.read_bytes())))
    write(out/'report.json',dict(format='osrec-kernel-state-discovery-v1',compilation_database_sha256=digest(db.read_bytes()),units=units));write(out/'objects.json',objects)
    index=DefinitionIndex.from_survey(out,db);roots={}
    for root in ('Add','Adjust'):
        r=discover(db,out/'kernel.c',root,index,max_units=4,analysis_options=dict(boundaries={'Current':PROVIDER},argument_objects={root:{'output':CONTRACT}}))
        if r['status']!='candidate':raise ValueError(r)
        r['analysis_sources_sha256']=analysis_sources()
        report=out/('discovery-'+root+'.json');write(report,r)
        roots[root]=dict(report=report.name,report_sha256=digest(report.read_bytes()),providers={'Current':dict(context_path='ledger',reason='Current returns alias=&ledger',implementation='reviewed provider body; context transform relocates ledger and alias')},arguments={'output':dict(kind='user_memory',object_id=1,permissions=3)})
    contract=dict(format='osrec-discovered-slice-contract-v1',source_copies={str(out/n):n for n in ('provider.c','kernel.c','port_types.h')},roots=roots)
    write(out/'discovery-contract.json',contract)
    port=json.loads((out/'port.json').read_text());names=list(port['bundle']['inputs'])+['discovery-contract.json','discovery-Add.json','discovery-Adjust.json']
    port['bundle']['inputs']={n:digest((out/n).read_bytes()) for n in names};write(out/'port.json',port)
    return port,contract

class DiscoveredJointTests(unittest.TestCase):
    def prepared(self,stage):
        port,contract=project(stage/'port');p=stage/'port'
        context=transform(p,['provider.c','kernel.c'],['port_types.h'],LLVM/'clang',include_dirs=[ROOT/'include'])
        return p,port,contract,context

    def test_contract_rejects_uncovered_roots_sources_and_user_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            p,port,contract,context=self.prepared(Path(tmp).resolve())
            original=copy.deepcopy(contract)
            cases=['root','source','provider','argument','permissions','route']
            for kind in cases:
                changed=copy.deepcopy(original);recipe=copy.deepcopy(port);cx=copy.deepcopy(context)
                if kind=='root':del changed['roots']['Add']
                elif kind=='source':cx['input_sha256']['provider.c']='0'*64
                elif kind=='provider':changed['roots']['Add']['providers']['Current']['context_path']='absent'
                elif kind=='argument':changed['roots']['Add']['arguments']={}
                elif kind=='permissions':changed['roots']['Add']['arguments']['output']['permissions']=1
                elif kind=='route':recipe['roots'][0]['arguments'][1]='unsigned'
                write(p/'discovery-contract.json',changed)
                with self.subTest(kind=kind),self.assertRaises(ValueError):prepare(p,p/'discovery-contract.json',recipe,cx)
            write(p/'discovery-contract.json',original)
            result=prepare(p,p/'discovery-contract.json',port,context)
            for codec in ({},{'fields':[{'path':'ledger.calls','policy':'persist'},{'path':'ledger.value','policy':'transient'}]}):
                with self.assertRaises(ValueError):check_checkpoint_coverage(result,codec)

    def test_stale_analysis_and_report_hashes_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p,port,contract,context=self.prepared(Path(tmp).resolve());report=p/'discovery-Add.json';original=report.read_bytes()
            report.write_bytes(original+b' ')
            with self.assertRaisesRegex(ValueError,'report identity'):prepare(p,p/'discovery-contract.json',port,context)
            stale=json.loads(original);stale['analysis_sources_sha256']['entry_state.py']='0'*64;write(report,stale)
            contract['roots']['Add']['report_sha256']=digest(report.read_bytes());write(p/'discovery-contract.json',contract)
            with self.assertRaisesRegex(ValueError,'current candidate'):prepare(p,p/'discovery-contract.json',port,context)

    def test_generated_binding_rejects_invalid_alias_alignment_and_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            p,port,contract,context=self.prepared(Path(tmp).resolve());prepare(p,p/'discovery-contract.json',port,context)
            source=p/'binding.c';source.write_text('''#include "slice_context.h"
#include "discovery_bindings.h"
int main(void){Output output={0,0};struct osrec_user_region r={0x1000,(unsigned char *)&output,sizeof(output),3,1};
 struct osrec_slice_invocation in={0,0,{0,0x1000,0,0,0,0},{&r,1}};
 if(osrec_discovered_Add_output(&in)!=&output)return 1;
 in.args[1]++;if(osrec_discovered_Add_output(&in))return 2;
 in.args[1]=0x1010;if(osrec_discovered_Add_output(&in))return 3;
 in.args[1]=0x1000;r.object_id=2;if(osrec_discovered_Add_output(&in))return 4;
 r.object_id=1;r.permissions=1;if(osrec_discovered_Add_output(&in))return 5;
 r.permissions=3;r.bytes=8;if(osrec_discovered_Add_output(&in))return 6;
 if(osrec_discovered_Add_output(0))return 7;return 0;}
''')
            source.write_text(source.read_text().replace('int main(void)','static int check(void)')+'''
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static void stop(void){for(;;)__asm__ volatile("wfe");}
void replay_fault(void){osrec_result[2]=3;osrec_result[3]=99;stop();}
void replay_main(void){osrec_result[0]=0x4f535243;osrec_result[1]=18;unsigned result=check();osrec_result[3]=result;osrec_result[2]=result?3:2;stop();}
''')
            flags=prepare_target(SimpleNamespace(arch='aarch64',entry_address=0x40200000,result_address=0x40180000),p)
            binary=p/'binding.elf';run([LLVM/'clang',*flags,'-std=c11','-O1','-ffreestanding','-Wall','-Wextra','-Werror','-I',p,'-I',ROOT/'include','-nostdlib','-static','-fuse-ld=lld','-Wl,-T,'+str(p/'image.ld'),p/'start.S',source,ROOT/'runtime/syscall_slice.c',ROOT/'runtime/slice_bytes.c','-o',binary])
            observed,_=observe(binary,QEMU);self.assertEqual(observed['status'],2);self.assertEqual(observed['error'],0)

    def test_live_user_kernel_continuity_and_joint_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp).resolve();port,contract=project(stage/'port');p=stage/'port'
            args=SimpleNamespace(arch='aarch64',capture=p,kernel_root=p,out=stage/'library',port=p/'port.json',llvm_bin=LLVM,qemu=QEMU,entry_address=0x40200000,result_address=0x40180000)
            kernel=export(args);bridge=kernel['discovered_state_contract'];self.assertTrue(bridge['checkpoint_coverage_verified']);self.assertTrue(bridge['target_binding_syntax_verified'])
            self.assertEqual(bridge['kernel_fields'],['ledger.calls','ledger.value'])
            chain=SimpleNamespace(slices=args.out,source=[p/'application.c'],spec=p/'spec.json',pause_ordinals=[2,4],out=stage/'chain',llvm_bin=LLVM,qemu=QEMU)
            result=run_pipeline(chain);self.assertEqual(result['logical_calls'],6);verify_chain(chain.out)
            for i,ordinal in enumerate([2,4]):
                joint=verify_joint(chain.out/('stage-'+str(i))/'checkpoint',kernel)
                self.assertEqual(joint['pause_ordinal'],ordinal)
            # Run fresh resumed images with incorrect cross-boundary behavior.
            image=chain.out/'finish/image';sources=image/'sources';driver=sources/'slice_driver.c';original=driver.read_text()
            adapter=image/'kernel-sources/adapter.c';adapter_original=adapter.read_text();faults=[]
            command=[LLVM/'clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align','-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                '-I',sources,'-I',image/'kernel-sources','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',driver,sources/'application_checkpoint.c']
            for kind in ('reset-kernel','detached-user-buffer'):
                extra=[]
                if kind=='reset-kernel':
                    changed=original.replace('osrec_import_restore(&osrec_saved_frame);','session.adapter->restore(session.state);osrec_import_restore(&osrec_saved_frame);')
                    self.assertNotEqual(changed,original);driver.write_text(changed)
                else:
                    changed=adapter_original.replace('    unsigned char *buffer=(unsigned char *)output;','    Output detached=*output;output=&detached;\n    unsigned char *buffer=(unsigned char *)output;')
                    self.assertNotEqual(changed,adapter_original);adapter.write_text(changed);extra=[adapter]
                try:
                    elf=stage/(kind+'.elf');run([*command,*extra,image/'slices.a','-o',elf]);audit(elf,LLVM)
                    observed,_=observe(elf,QEMU);self.assertEqual(observed['status'],3)
                    faults.append(dict(mutation=kind,observations=observed))
                finally:driver.write_text(original);adapter.write_text(adapter_original)
            write(stage/'faults.json',faults);verify_chain(chain.out)
            if RETAIN is not None:shutil.copytree(stage,RETAIN/'live-joint')

if __name__=='__main__':
    if '--out' in sys.argv:
        i=sys.argv.index('--out');RETAIN=Path(sys.argv[i+1]).resolve();del sys.argv[i:i+2];RETAIN.mkdir(parents=True,exist_ok=False)
    unittest.main()
