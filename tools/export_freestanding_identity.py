#!/usr/bin/env python3
"""Package captured UID/GID/process-group queries as a host-independent ARMv7 image."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile

from klee_liteos import ROOT,digest
from freestanding_armv7 import TARGET,audit,run
from live_identity_replay import BOUNDARIES,decode_identity,prepare_source
from freestanding_elf import prepare_target,add_target_arguments,target_metadata
from run_freestanding_armv7 import observe,require_success


def export(args):
    if args.out.exists():raise ValueError('choose a new output directory')
    if any(args.out.is_relative_to(root.resolve()) for root in (args.kernel_root,args.capture,ROOT/'build/ohos')):
        raise ValueError('image output must be outside source and capture directories')
    user=(args.capture/'identity-observations.bin').read_bytes()
    transcript=(args.capture/'identity-dependencies.bin').read_bytes()
    manifest_path=args.capture/'identity-replay.manifest.json'
    metadata=json.loads(manifest_path.read_text())['metadata']
    if metadata['format']!='osrec-live-identity-replay-v1':raise ValueError('unsupported capture metadata')
    if digest(user)!=metadata['live_observations_sha256'] or digest(transcript)!=metadata['dependency_transcript_sha256']:
        raise ValueError('captured identity hashes differ')
    calls,events=decode_identity(user,transcript);generated,identity=prepare_source(args.kernel_root)
    if identity!=metadata['source_identity'] or calls!=metadata['calls'] or events!=metadata['dependency_transcript']:
        raise ValueError('capture source, calls or dependency transcript differs')
    checkpoint={'format':'osrec-target-identity-checkpoint-v1','calls':calls,'dependency_transcript':events}
    call_rows=',\n'.join('{'+','.join(f'UINT32_C({value})' for value in
                          (call['number'],call['argument_bits'],call['raw']&0xffffffff))+'}' for call in calls)
    event_rows=',\n'.join('{'+','.join(f'UINT32_C({event[key]})' for key in
                           ('invocation','kind','argument_bits','result_bits'))+'}' for event in events)
    header='#include <stdint.h>\n#define CHECKPOINT_EVENTS '+str(len(events))+'U\n'
    header+='struct checkpoint_call { uint32_t number,argument,raw; };\n'
    header+='struct checkpoint_event { uint32_t invocation,kind,argument,raw; };\n'
    header+='static const struct checkpoint_call checkpoint_calls[7]={'+call_rows+'};\n'
    header+='static const struct checkpoint_event checkpoint_events[CHECKPOINT_EVENTS]={'+event_rows+'};\n'
    with tempfile.TemporaryDirectory(prefix='osrec-identity-image-') as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir()
        for filename in ('start.S','image.ld','identity_replay.c'):shutil.copy2(TARGET/filename,sources/filename)
        (sources/'identity.c').write_text(generated);(sources/'checkpoint.h').write_text(header)
        image=stage/'identity.elf'
        target_flags=prepare_target(args,sources)
        command=[args.llvm_bin/'clang',*target_flags,
                 '-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
                 '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror',
                 '-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),
                 sources/'start.S',sources/'identity_replay.c',sources/'identity.c','-o',image]
        run(command);inspection=audit(image,args.llvm_bin)
        binary=stage/'identity.bin';run([args.llvm_bin/'llvm-objcopy','-O','binary',image,binary])
        observed,raw=observe(image,args.qemu);require_success(observed)
        raw_observed,raw_result=observe(binary,args.qemu,descriptor=image);require_success(raw_observed)
        if raw_result!=raw:raise ValueError('ELF and raw image memory results differ')
        if observed['abi_version']!=2 or [call['raw'] for call in observed['actual_calls']]!=[call['raw'] for call in calls]:
            raise ValueError('target identity observations differ from live capture')
        if observed['dependency_count']!=len(events):raise ValueError('target dependency count differs')
        report={'format':'osrec-freestanding-identity-image-v1','source_identity':identity,
                'target':target_metadata(inspection,2),
                'checkpoint':checkpoint,'checkpoint_sha256':digest(header.encode()),'image_audit':inspection,
                'runtime_host_interaction':False,'system_libraries':[],'guest_io':False,
                'modeled_dependencies':list(BOUNDARIES.values()),'kernel_image_sha256':metadata['kernel_image_sha256'],
                'live_capture_manifest_sha256':digest(manifest_path.read_bytes()),
                'elf_sha256':digest(image.read_bytes()),'binary_sha256':digest(binary.read_bytes()),
                'target_observations':observed,'raw_image_execution_match':True,'target_result_sha256':digest(raw),
                'source_hashes':{path.name:digest(path.read_bytes()) for path in sorted(sources.iterdir())},
                'compiler':run([args.llvm_bin/'clang','--version']).stdout.splitlines()[0],
                'qemu':run([args.qemu,'--version']).stdout.splitlines()[0],
                'rtl_validated':False,'cycle_timing_equivalence_verified':False}
        args.out.parent.mkdir(parents=True,exist_ok=True)
        publish=stage/'published';publish.mkdir()
        shutil.copy2(image,publish/'identity.elf');shutil.copy2(binary,publish/'identity.bin')
        shutil.copytree(sources,publish/'sources');(publish/'target-result.bin').write_bytes(raw)
        (publish/'checkpoint.json').write_text(json.dumps(checkpoint,indent=2)+'\n')
        (publish/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
        shutil.copytree(publish,args.out)
    print(json.dumps({'image':str(args.out/'identity.elf'),'raw_image':str(args.out/'identity.bin'),
                      'runtime_host_interaction':False,'completed_calls':observed['completed_calls'],
                      'dependencies_consumed':observed['dependencies_consumed']},indent=2))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',required=True,type=Path)
    parser.add_argument('--kernel-root',type=Path,default=ROOT/'build/kernel_liteos_a')
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    add_target_arguments(parser)
    parser.add_argument('--qemu');parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    if args.qemu is None:args.qemu='qemu-system-aarch64' if args.arch=='aarch64' else 'qemu-system-arm'
    for key in ('capture','kernel_root','llvm_bin','out'):setattr(args,key,getattr(args,key).resolve())
    export(args)


if __name__=='__main__':main()
