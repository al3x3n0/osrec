#!/usr/bin/env python3
"""Export native OHOS identity queries as a self-contained AArch64 replay image."""
import argparse
import json
import re
from pathlib import Path
import shutil
import tempfile
from klee_liteos import ROOT,digest
from uname_capture import prepare_source,decode
from freestanding_armv7 import audit,run
from freestanding_elf import prepare_target,add_target_arguments,target_metadata
from run_freestanding_armv7 import observe,require_success


def load_capture(directory,identity):
    metadata=json.loads((directory/'uname-checkpoint.manifest.json').read_text())
    if metadata.get('format')!='osrec-live-uname-checkpoint-v1' or metadata.get('source_identity')!=identity:
        raise ValueError('uname capture format/source identity differs')
    blobs=[]
    for name in ('user','kernel','dependencies'):
        data=(directory/('uname-'+name+'.bin')).read_bytes()
        if digest(data)!=metadata[name+'_sha256']:raise ValueError('uname capture hash differs')
        blobs.append(data)
    checkpoint=decode(*blobs)
    if json.dumps(checkpoint,sort_keys=True)!=json.dumps(metadata['checkpoint'],sort_keys=True):raise ValueError('uname decoded checkpoint differs')
    if type(metadata.get('entry_errno_fixture')) is not int or metadata['entry_errno_fixture']!=0:
        raise ValueError('uname entry errno fixture differs')
    config=(directory/'auto-entry-config.h').read_text()
    definitions=re.findall(r'(?m)^[ \t]*#[ \t]*define[ \t]+OSREC_UNAME_CAPTURE\b[^\n]*',config)
    if [d.strip() for d in definitions]!=['#define OSREC_UNAME_CAPTURE 1'] or re.search(r'(?m)^[ \t]*#[ \t]*undef[ \t]+OSREC_UNAME_CAPTURE\b',config):raise ValueError('uname native config differs')
    fault=checkpoint.get('fault_profile')=='boundaries'
    declared=metadata.get('injected_boundary_faults',False)
    if type(declared) is not bool or declared!=fault:raise ValueError('uname injection provenance differs')
    fault_defs=re.findall(r'(?m)^[ \t]*#[ \t]*(?:define|undef)[ \t]+OSREC_UNAME_FAULTS\b[^\n]*',config)
    if [d.strip() for d in fault_defs]!=(['#define OSREC_UNAME_FAULTS 1'] if fault else []):raise ValueError('uname fault capture config differs')
    image=directory/'liteos.bin'
    if image.exists() and digest(image.read_bytes())!=metadata['kernel_image_sha256']:raise ValueError('uname kernel image hash differs')
    return checkpoint,metadata


def header(checkpoint):
    count=len(checkpoint['calls']);fault=count==8
    result=('#define UNAME_ABI %d\n#define UNAME_CALL_COUNT %d\n#define UNAME_EVENT_COUNT %d\n#define UNAME_PROVIDERS %d\n#define UNAME_OUTPUTS %d\n#define UNAME_COPIED %d\n' % (14 if fault else 13,count,len(checkpoint['dependency_transcript']),5 if fault else 2,4 if fault else 2,3120 if fault else 1560))
    result+='#include <stdint.h>\nstruct uname_call {uint32_t number,pointer_kind,raw,error;unsigned char before[390],after[390];};\n'
    result+='struct uname_event {uint32_t invocation,kind,argument,raw,size,mode;unsigned char memory[390];};\n'
    literal=lambda values:','.join(str(v) for v in values)
    rows=[]
    for c in checkpoint['calls']:
        rows.append('{'+literal([c[k] for k in ('number','pointer_kind','raw_bits','errno')])+',{'+literal(bytes.fromhex(c['before']))+'},{'+literal(bytes.fromhex(c['after']))+'}}')
    result+='static const struct uname_call uname_calls[UNAME_CALL_COUNT]={'+','.join(rows)+'};\n'
    rows=[]
    for e in checkpoint['dependency_transcript']:
        rows.append('{'+literal([e[k] for k in ('invocation','kind','argument','raw','size','mode')])+',{'+literal(bytes.fromhex(e['memory']))+'}}')
    return result+'static const struct uname_event uname_events[UNAME_EVENT_COUNT]={'+','.join(rows)+'};\n'


def export(args):
    if args.out.exists():raise ValueError('choose a new output directory')
    if getattr(args,'arch','aarch64')!='aarch64':raise ValueError('uname replay currently requires AArch64')
    if any(args.out.resolve().is_relative_to(root.resolve()) for root in (args.capture,args.kernel_root,ROOT/'build/ohos')):
        raise ValueError('uname output must be outside source and capture directories')
    generated,identity=prepare_source(args.kernel_root);checkpoint,metadata=load_capture(args.capture,identity)
    with tempfile.TemporaryDirectory(prefix='osrec-uname-image-') as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(args,sources)
        shutil.copyfile(ROOT/'integrations/liteos_a/uname_model.h',sources/'uname_model.h')
        shutil.copyfile(ROOT/'integrations/rtl_aarch64/uname_replay.c',sources/'uname_replay.c')
        (sources/'uname_syscalls.c').write_text(generated);(sources/'uname_checkpoint.h').write_text(header(checkpoint))
        elf=stage/'uname.elf';binary=stage/'uname.bin'
        run([args.llvm_bin/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
            '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
            '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',
            sources/'uname_replay.c',sources/'uname_syscalls.c','-o',elf])
        inspected=audit(elf,args.llvm_bin);run([args.llvm_bin/'llvm-objcopy','-O','binary',elf,binary])
        observed,raw=observe(elf,args.qemu);require_success(observed)
        binary_observed,binary_raw=observe(binary,args.qemu,descriptor=elf);require_success(binary_observed)
        if raw!=binary_raw:raise ValueError('uname ELF/raw results differ')
        publish=stage/'published';publish.mkdir()
        shutil.copyfile(elf,publish/elf.name);shutil.copyfile(binary,publish/binary.name);shutil.copytree(sources,publish/'sources')
        (publish/'checkpoint.json').write_text(json.dumps(checkpoint,indent=2)+'\n');(publish/'target-result.bin').write_bytes(raw)
        report={'format':'osrec-freestanding-uname-image-v1','source_identity':identity,'target':target_metadata(inspected,14 if len(checkpoint['calls'])==8 else 13),
            'image_audit':inspected,'kernel_image_sha256':metadata['kernel_image_sha256'],
            'capture_manifest_sha256':digest((args.capture/'uname-checkpoint.manifest.json').read_bytes()),
            'elf_sha256':digest(elf.read_bytes()),'binary_sha256':digest(binary.read_bytes()),
            'source_hashes':{p.name:digest(p.read_bytes()) for p in sorted(sources.iterdir())},
            'target_observations':observed,'raw_image_execution_match':True,'runtime_host_interaction':False,
            'identity_abi':checkpoint['identity_abi'],'modeled_dependencies':['uname','LOS_ArchCopyFromUser','LOS_ArchCopyToUser'],
            'provider_internals_replayed':False,'injected_boundary_faults':checkpoint.get('fault_profile')=='boundaries'}
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
