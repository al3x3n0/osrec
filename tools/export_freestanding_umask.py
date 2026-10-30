#!/usr/bin/env python3
"""Build and check a freestanding ARMv7 umask image from a verified live capture."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile

from klee_liteos import ROOT,digest
from live_umask_replay import MODEL_HEADER,decode_umask,prepare_source
from freestanding_elf import prepare_target,add_target_arguments,target_metadata
from run_freestanding_armv7 import observe,require_success

from freestanding_armv7 import TARGET, audit, run


def export(args):
    if getattr(args,'continuous',False) and not getattr(args,'automated_entry_state',False):raise ValueError('--continuous requires --automated-entry-state')
    if getattr(args,'automated_entry_state',False):
        from export_automated_umask import export as export_effects
        return export_effects(args)
    if args.out.exists():raise ValueError('choose a new output directory')
    if any(args.out.is_relative_to(root.resolve()) for root in (args.kernel_root, args.capture, ROOT/'build/ohos')):
        raise ValueError('image output must be outside source and capture directories')
    user=(args.capture/'umask-user-observations.bin').read_bytes()
    kernel=(args.capture/'umask-kernel-observations.bin').read_bytes()
    manifest=json.loads((args.capture/'umask-replay.manifest.json').read_text())
    metadata=manifest['metadata']
    if metadata['format']!='osrec-live-umask-replay-v1':raise ValueError('unsupported capture metadata')
    if digest(user)!=metadata['user_observations_sha256'] or digest(kernel)!=metadata['kernel_observations_sha256']:
        raise ValueError('captured umask observation hashes differ')
    calls=decode_umask(user,kernel);generated,identity=prepare_source(args.kernel_root)
    if identity!=metadata['source_identity'] or calls!=metadata['calls']:
        raise ValueError('capture source identity or call sequence differs')
    checkpoint={'format':'osrec-target-umask-checkpoint-v1','initial_mask':calls[0]['mask_before'],
                'calls':[{key:call[key] for key in ('mask_bits','mask_before','raw','mask_after')} for call in calls]}
    rows=',\n'.join('{'+','.join(f'UINT32_C({call[key]})' for key in
                              ('mask_bits','mask_before','raw','mask_after'))+'}' for call in calls)
    header='#include <stdint.h>\nstatic const uint32_t checkpoint_initial_mask=UINT32_C('+str(checkpoint['initial_mask'])+');\n'
    header+='struct checkpoint_call { uint32_t argument,before,raw,after; };\nstatic const struct checkpoint_call checkpoint_calls[6]={'+rows+'};\n'
    with tempfile.TemporaryDirectory(prefix='osrec-umask-image-') as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir()
        for filename in ('start.S','image.ld','umask_replay.c'):shutil.copy2(TARGET/filename,sources/filename)
        (sources/'umask.c').write_text(generated);(sources/'umask_model.h').write_text(MODEL_HEADER)
        (sources/'checkpoint.h').write_text(header)
        image=stage/'umask.elf'
        target_flags=prepare_target(args,sources)
        command=[args.llvm_bin/'clang',*target_flags,
                 '-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                 '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror',
                 '-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),
                 sources/'start.S',sources/'umask_replay.c',sources/'umask.c','-o',image]
        run(command);inspection=audit(image,args.llvm_bin)
        binary=stage/'umask.bin';run([args.llvm_bin/'llvm-objcopy','-O','binary',image,binary])
        observed,raw=observe(image,args.qemu);require_success(observed)
        raw_observed,raw_result=observe(binary,args.qemu,descriptor=image);require_success(raw_observed)
        if raw_result!=raw:raise ValueError('ELF and raw image memory results differ')
        expected=[{'raw':call['raw'],'mask_after':call['mask_after']} for call in calls]
        if observed['initial_mask']!=checkpoint['initial_mask'] or observed['actual_calls']!=expected:
            raise ValueError('target memory observations differ from live capture')
        report={'format':'osrec-freestanding-umask-image-v1','source_identity':identity,
                'target':target_metadata(inspection,1),
                'checkpoint':checkpoint,'checkpoint_sha256':digest(header.encode()),'image_audit':inspection,
                'runtime_host_interaction':False,'system_libraries':[],'guest_io':False,
                'modeled_dependencies':['OsCurrProcessGet','SCHEDULER_LOCK','SCHEDULER_UNLOCK'],
                'kernel_image_sha256':metadata['kernel_image_sha256'],
                'live_capture_manifest_sha256':digest((args.capture/'umask-replay.manifest.json').read_bytes()),
                'elf_sha256':digest(image.read_bytes()),'binary_sha256':digest(binary.read_bytes()),
                'target_observations':observed,'raw_image_execution_match':True,'target_result_sha256':digest(raw),
                'source_hashes':{path.name:digest(path.read_bytes()) for path in sorted(sources.iterdir())},
                'compiler':run([args.llvm_bin/'clang','--version']).stdout.splitlines()[0],
                'qemu':run([args.qemu,'--version']).stdout.splitlines()[0],
                'rtl_validated':False,'cycle_timing_equivalence_verified':False}
        args.out.parent.mkdir(parents=True,exist_ok=True)
        # Stage the complete directory before publishing a validated image.
        publish=stage/'published';publish.mkdir()
        shutil.copy2(image,publish/'umask.elf');shutil.copy2(binary,publish/'umask.bin')
        shutil.copytree(sources,publish/'sources')
        (publish/'target-result.bin').write_bytes(raw)
        (publish/'checkpoint.json').write_text(json.dumps(checkpoint,indent=2)+'\n')
        (publish/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
        shutil.copytree(publish,args.out)
    print(json.dumps({'image':str(args.out/'umask.elf'),'raw_image':str(args.out/'umask.bin'),
                      'runtime_host_interaction':False,'completed_calls':observed['completed_calls']},indent=2))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',required=True,type=Path)
    parser.add_argument('--continuous',action='store_true',help='restore only the first state and verify captured state transitions')
    parser.add_argument('--automated-entry-state',action='store_true',help='restore normalized entry state and verify captured scalar effects')
    parser.add_argument('--kernel-root',type=Path,default=ROOT/'build/kernel_liteos_a')
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    add_target_arguments(parser)
    parser.add_argument('--qemu');parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    if args.qemu is None:args.qemu='qemu-system-aarch64' if args.arch=='aarch64' else 'qemu-system-arm'
    for key in ('capture','kernel_root','llvm_bin','out'):setattr(args,key,getattr(args,key).resolve())
    export(args)


if __name__=='__main__':main()
