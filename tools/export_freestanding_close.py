#!/usr/bin/env python3
"""Export native OHOS descriptor-close lifecycle as a self-contained AArch64 replay image."""
import argparse
import json
import re
from pathlib import Path
import shutil
import tempfile
from klee_liteos import ROOT,digest
from close_capture import prepare_source,decode
from freestanding_armv7 import audit,run
from freestanding_elf import prepare_target,add_target_arguments,target_metadata
from run_freestanding_armv7 import observe,require_success


def load_capture(directory,identity):
    metadata=json.loads((directory/'close-checkpoint.manifest.json').read_text())
    if metadata.get('format')!='osrec-live-close-checkpoint-v1' or metadata.get('source_identity')!=identity:
        raise ValueError('close capture format/source identity differs')
    blobs=[]
    for name in ('user','kernel','dependencies'):
        data=(directory/('close-'+name+'.bin')).read_bytes()
        if digest(data)!=metadata[name+'_sha256']:raise ValueError('close capture hash differs')
        blobs.append(data)
    checkpoint=decode(*blobs)
    if json.dumps(checkpoint,sort_keys=True)!=json.dumps(metadata['checkpoint'],sort_keys=True):raise ValueError('close decoded checkpoint differs')
    if type(metadata.get('entry_errno_fixture')) is not int or metadata['entry_errno_fixture']!=0:
        raise ValueError('close entry errno fixture differs')
    config=(directory/'auto-entry-config.h').read_text()
    definitions=re.findall(r'(?m)^[ \t]*#[ \t]*define[ \t]+OSREC_CLOSE_CAPTURE\b[^\n]*',config)
    if [d.strip() for d in definitions]!=['#define OSREC_CLOSE_CAPTURE 1'] or re.search(r'(?m)^[ \t]*#[ \t]*undef[ \t]+OSREC_CLOSE_CAPTURE\b',config):raise ValueError('close native config differs')
    if metadata.get('injected_first_close_failure') is not True:raise ValueError('close injection provenance differs')
    image=directory/'liteos.bin'
    if image.exists() and digest(image.read_bytes())!=metadata['kernel_image_sha256']:raise ValueError('close kernel image hash differs')
    return checkpoint,metadata


def header(checkpoint):
    result='#include <stdint.h>\n#define CLOSE_SYSTEM_FD UINT32_C(%d)\n' % checkpoint['initial_system_fd']
    result+='struct close_call {uint32_t number,fd,raw,error,before[3],after[3];};\n'
    result+='struct close_event {uint32_t invocation,kind,argument,argument2,raw,error,before_map,before_allocated,before_cloexec,after_map,after_allocated,after_cloexec;};\n'
    literal=lambda values:','.join('UINT32_C('+str(v)+')' for v in values)
    rows=[]
    for c in checkpoint['calls']:
        rows.append('{'+literal([c[k] for k in ('number','fd_bits','raw_bits','errno')])+',{'+literal(c['before'])+'},{'+literal(c['after'])+'}}')
    result+='static const struct close_call close_calls[5]={'+','.join(rows)+'};\n'
    return result+'static const struct close_event close_events[15]={'+','.join('{'+literal(list(e.values()))+'}' for e in checkpoint['dependency_transcript'])+'};\n'


def export(args):
    if args.out.exists():raise ValueError('choose a new output directory')
    if getattr(args,'arch','aarch64')!='aarch64':raise ValueError('close replay currently requires AArch64')
    if any(args.out.resolve().is_relative_to(root.resolve()) for root in (args.capture,args.kernel_root,ROOT/'build/ohos')):
        raise ValueError('close output must be outside source and capture directories')
    generated,identity=prepare_source(args.kernel_root);checkpoint,metadata=load_capture(args.capture,identity)
    with tempfile.TemporaryDirectory(prefix='osrec-close-image-') as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(args,sources)
        shutil.copyfile(ROOT/'integrations/liteos_a/close_model.h',sources/'close_model.h')
        shutil.copyfile(ROOT/'integrations/rtl_aarch64/close_replay.c',sources/'close_replay.c')
        (sources/'close_syscalls.c').write_text(generated);(sources/'close_checkpoint.h').write_text(header(checkpoint))
        elf=stage/'close.elf';binary=stage/'close.bin'
        run([args.llvm_bin/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
            '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
            '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',
            sources/'close_replay.c',sources/'close_syscalls.c','-o',elf])
        inspected=audit(elf,args.llvm_bin);run([args.llvm_bin/'llvm-objcopy','-O','binary',elf,binary])
        observed,raw=observe(elf,args.qemu);require_success(observed)
        binary_observed,binary_raw=observe(binary,args.qemu,descriptor=elf);require_success(binary_observed)
        if raw!=binary_raw:raise ValueError('close ELF/raw results differ')
        publish=stage/'published';publish.mkdir()
        shutil.copyfile(elf,publish/elf.name);shutil.copyfile(binary,publish/binary.name);shutil.copytree(sources,publish/'sources')
        (publish/'checkpoint.json').write_text(json.dumps(checkpoint,indent=2)+'\n');(publish/'target-result.bin').write_bytes(raw)
        report={'format':'osrec-freestanding-close-image-v1','source_identity':identity,'target':target_metadata(inspected,15),
            'image_audit':inspected,'kernel_image_sha256':metadata['kernel_image_sha256'],
            'capture_manifest_sha256':digest((args.capture/'close-checkpoint.manifest.json').read_bytes()),
            'elf_sha256':digest(elf.read_bytes()),'binary_sha256':digest(binary.read_bytes()),
            'source_hashes':{p.name:digest(p.read_bytes()) for p in sorted(sources.iterdir())},
            'target_observations':observed,'raw_image_execution_match':True,'runtime_host_interaction':False,
            'state_scope':checkpoint['state_scope'],'modeled_dependencies':['DisassociateProcessFd','close','AssociateSystemFd','FreeProcessFd','errno'],
            'provider_internals_replayed':False,'injected_first_close_failure':True}
        (publish/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
        args.out.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(publish,args.out)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',type=Path,required=True);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--kernel-root',type=Path,default=ROOT/'build/kernel_liteos_a')
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    add_target_arguments(parser);parser.add_argument('--qemu',default='qemu-system-aarch64')
    args=parser.parse_args()
    for key in ('capture','out','kernel_root','llvm_bin'):setattr(args,key,getattr(args,key).resolve())
    report=export(args);print(json.dumps(report['target_observations'],indent=2))


if __name__=='__main__':main()
