"""Generated scalar entry restoration and captured write-effect replay for SysUmask."""
import json
import shutil
import tempfile
from klee_liteos import ROOT,digest
from live_umask_replay import MODEL_HEADER,decode_umask,prepare_source
from reconstruct_entry_state import load_reconstruction
from freestanding_elf import prepare_target,target_metadata
from freestanding_armv7 import audit,run
from run_freestanding_armv7 import observe,require_success

ADAPTER='''
static void complete(uint32_t status,uint32_t error) __attribute__((noreturn));
static uint32_t depth,locks,unlocks,accesses,invocation;
extern uint32_t SysUmask(uint32_t mask);
void OsrecSchedulerLock(uint32_t *saved){
 if(depth) complete(3,60);*saved=UINT32_C(0x13579bdf);depth=1;++locks;
}
void OsrecSchedulerUnlock(uint32_t saved){
 if(depth!=1 || saved!=UINT32_C(0x13579bdf)) complete(3,61);depth=0;++unlocks;
}
struct osrec_process *OsCurrProcessGet(void){
 if(depth!=1) complete(3,62);++accesses;return osrec_bound_OsCurrProcessGet;
}
uint32_t osrec_invoke(uint32_t number){
 if(number!=60 || invocation>=6) complete(3,63);
 uint32_t raw=SysUmask(osrec_argument(invocation,0));
 if(depth || locks!=invocation+1 || unlocks!=invocation+1 || accesses!=2*(invocation+1)) complete(3,70+invocation);
 ++invocation;return raw;
}
'''

def export(args):
    if args.arch!='aarch64':raise ValueError('generated umask effects currently require AArch64')
    if args.out.exists():raise ValueError('choose a new output directory')
    if any(args.out.is_relative_to(root.resolve()) for root in (args.kernel_root,args.capture,ROOT/'build/ohos')):
        raise ValueError('image output must be outside source and capture directories')
    metadata=json.loads((args.capture/'umask-replay.manifest.json').read_text())['metadata']
    if metadata['format']!='osrec-live-umask-replay-v1':raise ValueError('unsupported umask capture')
    user=(args.capture/'umask-user-observations.bin').read_bytes();kernel=(args.capture/'umask-kernel-observations.bin').read_bytes()
    if digest(user)!=metadata['user_observations_sha256'] or digest(kernel)!=metadata['kernel_observations_sha256']:
        raise ValueError('umask observation hash differs')
    calls=decode_umask(user,kernel);generated,identity=prepare_source(args.kernel_root)
    if identity!=metadata['source_identity'] or calls!=metadata['calls']:raise ValueError('umask source/call identity differs')
    continuous=getattr(args,'continuous',False)
    header,frames,hashes=load_reconstruction(args.capture,{60:'SysUmask'},[60]*6,effects=True,continuous=continuous)
    for frame,call in zip(frames,calls):
        if int.from_bytes(bytes.fromhex(frame['arguments'][0]['data']),'little')!=call['mask_bits']:
            raise ValueError('normalized mask argument differs from user capture')
    checkpoint='#define OSREC_CHECKPOINT_CALLS 6\nstruct checkpoint_call {uint32_t number,raw;};\nstatic const struct checkpoint_call checkpoint_calls[6]={'
    checkpoint+=','.join('{60,UINT32_C('+str(call['raw'])+')}' for call in calls)+'};\n'
    with tempfile.TemporaryDirectory(prefix='osrec-umask-effects-') as name:
        from pathlib import Path
        stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(args,sources)
        (sources/'entry_reconstruction.h').write_text(header)
        (sources/'entry_model.h').write_text('#include "umask_model.h"\ntypedef struct osrec_process LosProcessCB;\n_Static_assert(sizeof(uint32_t)==4,"scalar argument ABI");\n')
        (sources/'umask_model.h').write_text(MODEL_HEADER);(sources/'umask.c').write_text(generated)
        (sources/'entry_adapter.h').write_text(ADAPTER);(sources/'entry_checkpoint.h').write_text(checkpoint)
        shutil.copy2(ROOT/'integrations/rtl_aarch64/entry_state_replay.c',sources/'entry_state_replay.c')
        image=stage/'umask.elf';binary=stage/'umask.bin'
        run([args.llvm_bin/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
            '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
            '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'umask.c','-o',image])
        inspection=audit(image,args.llvm_bin);run([args.llvm_bin/'llvm-objcopy','-O','binary',image,binary])
        observed,raw=observe(image,args.qemu);require_success(observed)
        raw_observed,raw_result=observe(binary,args.qemu,descriptor=image);require_success(raw_observed)
        if raw!=raw_result:raise ValueError('ELF and raw write-effect results differ')
        if observed['actual_calls']!=[{'number':60,'raw_bits':c['raw']} for c in calls] or not observed['write_effects']:
            raise ValueError('write-effect target observations differ')
        report={'format':'osrec-freestanding-umask-effects-v1','source_identity':identity,
            'target':target_metadata(inspection,8),'entry_state_reconstruction':'generated normalized snapshots and captured scalar post-state',
            'session_identity_contract':json.loads((args.capture/'report.json').read_text()).get('automated_session_identity') if continuous else None,
            'live_capture_report_sha256':digest((args.capture/'report.json').read_bytes()),
            'automated_capture_hashes':hashes,'entry_reconstruction_sha256':digest(header.encode()),
            'checkpoint_sha256':digest(checkpoint.encode()),'image_audit':inspection,
            'runtime_host_interaction':False,'system_libraries':[],'guest_io':False,
            'modeled_dependencies':['OsCurrProcessGet','SCHEDULER_LOCK','SCHEDULER_UNLOCK'],
            'state_continuity_reproduced':continuous,'entry_states_restored_independently':not continuous,
            'kernel_image_sha256':metadata['kernel_image_sha256'],
            'live_capture_manifest_sha256':digest((args.capture/'umask-replay.manifest.json').read_bytes()),
            'elf_sha256':digest(image.read_bytes()),'binary_sha256':digest(binary.read_bytes()),
            'target_observations':observed,'raw_image_execution_match':True,'target_result_sha256':digest(raw),
            'source_hashes':{p.name:digest(p.read_bytes()) for p in sorted(sources.iterdir())},
            'compiler':run([args.llvm_bin/'clang','--version']).stdout.splitlines()[0],
            'qemu':run([args.qemu,'--version']).stdout.splitlines()[0],
            'rtl_validated':False,'cycle_timing_equivalence_verified':False}
        publish=stage/'published';publish.mkdir();shutil.copytree(sources,publish/'sources')
        shutil.copy2(image,publish/'umask.elf');shutil.copy2(binary,publish/'umask.bin')
        (publish/'target-result.bin').write_bytes(raw)
        (publish/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
        (publish/'entry-state-snapshots.json').write_text(json.dumps({'format':'osrec-live-entry-state-v1','snapshots':frames},indent=2)+'\n')
        for file in ('entry-state-effects.json','entry-state-plan.json'):shutil.copy2(args.capture/file,publish/file)
        args.out.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(publish,args.out)
    print(json.dumps({'image':str(args.out/'umask.elf'),'completed_calls':observed['completed_calls'],
        'states_verified':observed['states_verified'],'states_restored':observed['states_restored'],'continuous_replay':continuous,'write_effects':True,'runtime_host_interaction':False},indent=2))
