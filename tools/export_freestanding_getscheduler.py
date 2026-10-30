#!/usr/bin/env python3
"""Export captured getscheduler queries to a self-contained AArch64 ELF."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
from klee_liteos import ROOT,digest
from freestanding_armv7 import audit,run
from freestanding_elf import prepare_target,add_target_arguments,target_metadata
from live_getscheduler_replay import prepare_source,decode_getscheduler,decode_task_getscheduler,verify_task_config
from run_freestanding_armv7 import observe,require_success

def export(args):
    if args.out.exists():raise ValueError('choose a new output directory')
    if any(args.out.is_relative_to(root.resolve()) for root in (args.kernel_root,args.capture,ROOT/'build/ohos')):
        raise ValueError('image output must be outside source and capture directories')
    if getattr(args,'arch','aarch64')!='aarch64':raise ValueError('getscheduler image currently requires AArch64')
    metadata=json.loads((args.capture/'getscheduler-checkpoint.manifest.json').read_text())
    task=metadata['format']=='osrec-live-getscheduler-checkpoint-v2'
    if metadata['format'] not in ('osrec-live-getscheduler-checkpoint-v1','osrec-live-getscheduler-checkpoint-v2') or (task and metadata.get('profile')!='task'):raise ValueError('unknown getscheduler capture profile')
    generated,identity=prepare_source(args.kernel_root,task)
    if json.dumps(metadata['source_identity'],sort_keys=True)!=json.dumps(identity,sort_keys=True):
        raise ValueError('getscheduler capture format/source identity differs')
    user=(args.capture/'getscheduler-user-observations.bin').read_bytes()
    kernel=(args.capture/'getscheduler-dependencies.bin').read_bytes()
    if digest(user)!=metadata['user_observations_sha256'] or digest(kernel)!=metadata['dependency_transcript_sha256']:
        raise ValueError('getscheduler observation hash differs')
    if digest((args.capture/'liteos.bin').read_bytes())!=metadata['kernel_image_sha256']:raise ValueError('getscheduler kernel image hash differs')
    checkpoint=(decode_task_getscheduler if task else decode_getscheduler)(user,kernel)
    if task:
        config=(args.capture/'auto-entry-config.h').read_text()
        verify_task_config(config)
    if json.dumps(metadata['checkpoint'],sort_keys=True)!=json.dumps(checkpoint,sort_keys=True):raise ValueError('getscheduler checkpoint differs from captured entry state')
    calls=checkpoint['calls'];events=checkpoint['dependency_transcript']
    call_rows=','.join('{'+','.join(f'UINT32_C({call[key]})' for key in ('id_bits','flag_bits','raw_bits'))+'}' for call in calls)
    event_rows=','.join('{'+','.join(f'UINT32_C({event[key]})' for key in ('invocation','kind','id_bits','result_bits','policy_bits','policy_written'))+'}' for event in events)
    header='#include <stdint.h>\n#define CHECKPOINT_EVENTS '+str(len(events))+'U\n'
    header+='struct checkpoint_call { uint32_t id,flag,raw; };\n'
    header+='struct checkpoint_event { uint32_t invocation,kind,id,raw,policy,written; };\n'
    header+='static const struct checkpoint_call checkpoint_calls[4]={'+call_rows+'};\n'
    header+='static const struct checkpoint_event checkpoint_events[CHECKPOINT_EVENTS]={'+event_rows+'};\n'
    with tempfile.TemporaryDirectory(prefix='osrec-getscheduler-image-') as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir()
        target_flags=prepare_target(args,sources)
        shutil.copy2(ROOT/('integrations/rtl_aarch64/getscheduler_task_replay.c' if task else 'integrations/rtl_aarch64/getscheduler_replay.c'),sources/'getscheduler_replay.c')
        shutil.copy2(ROOT/('integrations/liteos_a/getscheduler_task_model.h' if task else 'integrations/liteos_a/getscheduler_model.h'),sources/'getscheduler_model.h')
        (sources/'getscheduler_syscalls.c').write_text(generated);(sources/'getscheduler_checkpoint.h').write_text(header)
        image=stage/'getscheduler.elf';binary=stage/'getscheduler.bin'
        run([args.llvm_bin/'clang',*target_flags,'-std=c11','-O1','-ffreestanding','-fno-builtin',
            '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
            '-Wall','-Wextra','-Werror','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined',
            '-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'getscheduler_replay.c',sources/'getscheduler_syscalls.c','-o',image])
        inspection=audit(image,args.llvm_bin)
        run([args.llvm_bin/'llvm-objcopy','-O','binary',image,binary])
        observed,raw=observe(image,args.qemu);require_success(observed)
        binary_observed,binary_raw=observe(binary,args.qemu,descriptor=image);require_success(binary_observed)
        if raw!=binary_raw:raise ValueError('ELF and raw getscheduler results differ')
        if observed['abi_version']!=(10 if task else 9) or [call['raw_bits'] for call in observed['actual_calls']]!=[call['raw_bits'] for call in calls]:
            raise ValueError('getscheduler result differs from capture')
        report={'format':'osrec-freestanding-getscheduler-image-v2' if task else 'osrec-freestanding-getscheduler-image-v1','source_identity':identity,
            'target':target_metadata(inspection,10 if task else 9),'checkpoint':checkpoint,'checkpoint_sha256':digest(header.encode()),
            'image_audit':inspection,'runtime_host_interaction':False,'system_libraries':[],'guest_io':False,
            'modeled_dependencies':(['task bounds/lookup','scheduler lock/unlock','OsUserTaskOperatePermissionsCheck','typed schedParamGet callback; policy projection'] if task else ['LOS_GetCurrProcessID','LOS_GetProcessScheduler']),
            'kernel_image_sha256':metadata['kernel_image_sha256'],
            'live_capture_manifest_sha256':digest((args.capture/'getscheduler-checkpoint.manifest.json').read_bytes()),
            'elf_sha256':digest(image.read_bytes()),'binary_sha256':digest(binary.read_bytes()),
            'target_observations':observed,'raw_image_execution_match':True,'target_result_sha256':digest(raw),
            'source_hashes':{p.name:digest(p.read_bytes()) for p in sorted(sources.iterdir())},
            'compiler':run([args.llvm_bin/'clang','--version']).stdout.splitlines()[0],
            'qemu':run([args.qemu,'--version']).stdout.splitlines()[0],
            'rtl_validated':False,'cycle_timing_equivalence_verified':False,'scheduler_irq_reproduction':False,'dependency_internals_replayed':False,'task_mode_supported':task,'process_mode_supported':not task}
        publish=stage/'published';publish.mkdir()
        shutil.copy2(image,publish/'getscheduler.elf');shutil.copy2(binary,publish/'getscheduler.bin');shutil.copytree(sources,publish/'sources')
        (publish/'target-result.bin').write_bytes(raw)
        (publish/'checkpoint.json').write_text(json.dumps(checkpoint,indent=2)+'\n')
        (publish/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
        args.out.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(publish,args.out)
    print(json.dumps({'image':str(args.out/'getscheduler.elf'),'completed_calls':observed['completed_calls'],
        'raw_returns':[call['raw'] for call in observed['actual_calls']],'runtime_host_interaction':False},indent=2))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',required=True,type=Path)
    parser.add_argument('--kernel-root',type=Path,default=ROOT/'build/kernel_liteos_a')
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--out',required=True,type=Path);parser.add_argument('--qemu',default='qemu-system-aarch64')
    add_target_arguments(parser);args=parser.parse_args()
    for name in ('capture','kernel_root','llvm_bin','out'):setattr(args,name,getattr(args,name).resolve())
    export(args)
if __name__=='__main__':main()
