#!/usr/bin/env python3
"""Export captured geteuid32/getegid32 queries to a self-contained AArch64 ELF."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
from klee_liteos import ROOT,digest
from freestanding_armv7 import audit,run
from freestanding_elf import prepare_target,add_target_arguments,target_metadata
from live_credentials_replay import prepare_source,decode_credentials
from run_freestanding_armv7 import observe,require_success

def export(args):
    if args.out.exists():raise ValueError('choose a new output directory')
    if any(args.out.is_relative_to(root.resolve()) for root in (args.kernel_root,args.capture,ROOT/'build/ohos')):
        raise ValueError('image output must be outside source and capture directories')
    if getattr(args,'arch','aarch64')!='aarch64':raise ValueError('credentials image currently requires AArch64')
    generated,identity=prepare_source(args.kernel_root)
    metadata=json.loads((args.capture/'credentials-checkpoint.manifest.json').read_text())
    if metadata['format']!='osrec-live-credentials-checkpoint-v1' or metadata['source_identity']!=identity:
        raise ValueError('credentials capture format/source identity differs')
    user=(args.capture/'credentials-user-observations.bin').read_bytes()
    kernel=(args.capture/'credentials-kernel-observations.bin').read_bytes()
    if digest(user)!=metadata['user_observations_sha256'] or digest(kernel)!=metadata['kernel_observations_sha256']:
        raise ValueError('credentials observation hash differs')
    checkpoint=decode_credentials(user,kernel)
    if metadata['checkpoint']!=checkpoint:raise ValueError('credentials checkpoint differs from captured entry state')
    automatic=getattr(args,'automated_entry_state',False)
    reconstruction=None
    if automatic:
        from reconstruct_entry_state import load_reconstruction
        reconstruction,frames,hashes=load_reconstruction(args.capture,{201:'SysGetEffUserID',202:'SysGetEffGID'},(201,202,201,202))
    user=checkpoint['objects'][0]
    rows=','.join('{UINT32_C('+str(call['number'])+'),UINT32_C('+str(call['raw_bits'])+')}' for call in checkpoint['calls'])
    header='#include <stdint.h>\n'+('' if automatic else ''.join(f'static const uint32_t checkpoint_{name}=UINT32_C({value});\n' for name,value in
        (('pid',checkpoint['current_process_id']),('euid',user['effective_uid']),('egid',user['effective_gid']))))
    header+='struct checkpoint_call { uint32_t number,raw; };\nstatic const struct checkpoint_call checkpoint_calls[4]={'+rows+'};\n'
    with tempfile.TemporaryDirectory(prefix='osrec-credentials-image-') as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir()
        target_flags=prepare_target(args,sources)
        shutil.copy2(ROOT/'integrations/rtl_aarch64'/('credentials_snapshot_replay.c' if automatic else 'credentials_replay.c'),sources/'credentials_replay.c')
        if automatic:(sources/'entry_reconstruction.h').write_text(reconstruction)
        shutil.copy2(ROOT/'integrations/liteos_a/credentials_model.h',sources/'credentials_model.h')
        (sources/'credentials_syscalls.c').write_text(generated);(sources/'credentials_checkpoint.h').write_text(header)
        image=stage/'credentials.elf';binary=stage/'credentials.bin'
        run([args.llvm_bin/'clang',*target_flags,'-std=c11','-O1','-ffreestanding','-fno-builtin',
            '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
            '-Wall','-Wextra','-Werror','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined',
            '-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'credentials_replay.c',sources/'credentials_syscalls.c','-o',image])
        inspection=audit(image,args.llvm_bin)
        run([args.llvm_bin/'llvm-objcopy','-O','binary',image,binary])
        observed,raw=observe(image,args.qemu);require_success(observed)
        binary_observed,binary_raw=observe(binary,args.qemu,descriptor=image);require_success(binary_observed)
        if raw!=binary_raw:raise ValueError('ELF and raw credentials results differ')
        expected=[{'number':call['number'],'raw_bits':call['raw_bits']} for call in checkpoint['calls']]
        if observed['actual_calls']!=expected or (observed['current_pid'],observed['effective_uid'],observed['effective_gid'])!=(0 if automatic else checkpoint['current_process_id'],user['effective_uid'],user['effective_gid']):
            raise ValueError('credential result differs from capture')
        report={'format':'osrec-freestanding-credentials-image-v1','source_identity':identity,
            'entry_state_reconstruction':'generated normalized snapshots' if automatic else 'legacy semantic checkpoint',
            'current_pid_restored':not automatic,
            'automated_capture_hashes':hashes if automatic else None,
            'entry_reconstruction_sha256':digest(reconstruction.encode()) if automatic else None,
            'target':target_metadata(inspection,6),'checkpoint':checkpoint,'checkpoint_sha256':digest(header.encode()),
            'image_audit':inspection,'runtime_host_interaction':False,'system_libraries':[],'guest_io':False,
            'modeled_dependencies':['OsCurrUserGet','effective UID/GID fields','SCHEDULER_LOCK','SCHEDULER_UNLOCK'],
            'kernel_image_sha256':metadata['kernel_image_sha256'],
            'live_capture_manifest_sha256':digest((args.capture/'credentials-checkpoint.manifest.json').read_bytes()),
            'elf_sha256':digest(image.read_bytes()),'binary_sha256':digest(binary.read_bytes()),
            'target_observations':observed,'raw_image_execution_match':True,'target_result_sha256':digest(raw),
            'source_hashes':{p.name:digest(p.read_bytes()) for p in sorted(sources.iterdir())},
            'compiler':run([args.llvm_bin/'clang','--version']).stdout.splitlines()[0],
            'qemu':run([args.qemu,'--version']).stdout.splitlines()[0],
            'rtl_validated':False,'cycle_timing_equivalence_verified':False,'scheduler_irq_reproduction':False}
        publish=stage/'published';publish.mkdir()
        shutil.copy2(image,publish/'credentials.elf');shutil.copy2(binary,publish/'credentials.bin');shutil.copytree(sources,publish/'sources')
        (publish/'target-result.bin').write_bytes(raw)
        if automatic:
            (publish/'entry-state-snapshots.json').write_text(json.dumps({'format':'osrec-live-entry-state-v1','snapshots':frames},indent=2)+'\n')
            shutil.copy2(args.capture/'entry-state-plan.json',publish/'entry-state-plan.json')
        (publish/'checkpoint.json').write_text(json.dumps(checkpoint,indent=2)+'\n')
        (publish/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
        args.out.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(publish,args.out)
    print(json.dumps({'image':str(args.out/'credentials.elf'),'completed_calls':observed['completed_calls'],
        'effective_uid':observed['effective_uid'],'effective_gid':observed['effective_gid'],'runtime_host_interaction':False},indent=2))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',required=True,type=Path)
    parser.add_argument('--automated-entry-state',action='store_true',help='restore discovered credential snapshots')
    parser.add_argument('--kernel-root',type=Path,default=ROOT/'build/kernel_liteos_a')
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--out',required=True,type=Path);parser.add_argument('--qemu',default='qemu-system-aarch64')
    add_target_arguments(parser);args=parser.parse_args()
    for name in ('capture','kernel_root','llvm_bin','out'):setattr(args,name,getattr(args,name).resolve())
    export(args)
if __name__=='__main__':main()
