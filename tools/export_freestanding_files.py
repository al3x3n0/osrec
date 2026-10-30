#!/usr/bin/env python3
"""Export a native OHOS shared-state file-operation session as a self-contained AArch64 replay image."""
import argparse
import json
import re
from pathlib import Path
import shutil
import tempfile
from klee_liteos import ROOT,digest
from files_capture import prepare_source,decode
from freestanding_armv7 import audit,run
from freestanding_elf import prepare_target,add_target_arguments,target_metadata
from run_freestanding_armv7 import observe,require_success


def load_capture(directory,identity):
    metadata=json.loads((directory/'files-checkpoint.manifest.json').read_text())
    if metadata.get('format')!='osrec-live-files-checkpoint-v1' or metadata.get('source_identity')!=identity:
        raise ValueError('files capture format/source identity differs')
    blobs=[]
    for name in ('user','kernel','dependencies','abi'):
        data=(directory/('files-'+name+'.bin')).read_bytes()
        if digest(data)!=metadata[name+'_sha256']:raise ValueError('files capture hash differs')
        blobs.append(data)
    checkpoint=decode(*blobs)
    if json.dumps(checkpoint,sort_keys=True)!=json.dumps(metadata['checkpoint'],sort_keys=True):raise ValueError('files decoded checkpoint differs')
    if type(metadata.get('entry_errno_fixture')) is not int or metadata['entry_errno_fixture']!=0:
        raise ValueError('files entry errno fixture differs')
    config=(directory/'auto-entry-config.h').read_text()
    definitions=re.findall(r'(?m)^[ \t]*#[ \t]*define[ \t]+OSREC_FILE_CAPTURE\b[^\n]*',config)
    if [d.strip() for d in definitions]!=['#define OSREC_FILE_CAPTURE 1'] or re.search(r'(?m)^[ \t]*#[ \t]*undef[ \t]+OSREC_FILE_CAPTURE\b',config):raise ValueError('files native config differs')
    image=directory/'liteos.bin'
    if image.exists() and digest(image.read_bytes())!=metadata['kernel_image_sha256']:raise ValueError('files kernel image hash differs')
    return checkpoint,metadata


def return_hash():
    from file_profile import CASES
    value=2166136261
    for _,_,raw,_ in CASES:value=((value^(raw&0xffffffff))*16777619)&0xffffffff
    return value


def header(checkpoint):
    literal=lambda values:','.join('UINT32_C('+str(v)+')' for v in values)
    abi=checkpoint['abi'];events=checkpoint['dependency_transcript'];calls=checkpoint['calls']
    constants={'CALL_COUNT':len(calls),'EVENT_COUNT':len(events),'RETURN_HASH':return_hash(),
        'SYSTEM_A':checkpoint['system_fds'][0],'SYSTEM_B':checkpoint['system_fds'][1],
        'SYSTEM_LIMIT':abi[4],'STAT_SIZE':abi[0],'KSTAT_SIZE':abi[1],'SIZE_OFFSET':abi[2]}
    result='#ifndef OSREC_FILES_CHECKPOINT_H\n#define OSREC_FILES_CHECKPOINT_H\n#include <stdint.h>\n'
    for key,value in constants.items():result+='#define FILE_'+key+' UINT32_C('+str(value)+')\n'
    result+='struct files_call {uint32_t number,args[5],raw,error,before[15],after[15];unsigned char buffer_before[192],buffer_after[192];uint32_t event_start,event_end;};\n'
    result+='struct files_event {uint32_t invocation,kind,a,b,c,raw,error,length,before[15],after[15];unsigned char data[192];};\n#ifdef OSREC_FILES_REPLAY\n'
    rows=[]
    for c in calls:
        rows.append('{'+literal([c['number']])+',{'+literal(c['args'])+'},'+literal([c['raw_bits'],c['errno']])+',{'+literal(c['before'])+'},{'+literal(c['after'])+'},{'+literal(bytes.fromhex(c['buffer_before']))+'},{'+literal(bytes.fromhex(c['buffer_after']))+'},'+literal([c['event_start'],c['event_end']])+'}')
    result+='static const struct files_call files_calls[FILE_CALL_COUNT]={'+','.join(rows)+'};\n'
    rows=[]
    for e in events:
        data=bytes.fromhex(e['data'])
        rows.append('{'+literal([e[k] for k in ('invocation','kind','a','b','c','raw','error')])+','+literal([len(data)])+',{'+literal(e['before'])+'},{'+literal(e['after'])+'},{'+(literal(data) if data else '0')+'}}')
    return result+'static const struct files_event files_events[FILE_EVENT_COUNT]={'+','.join(rows)+'};\n#endif\n#endif\n'


def export(args):
    if args.out.exists():raise ValueError('choose a new output directory')
    if getattr(args,'arch','aarch64')!='aarch64':raise ValueError('files replay currently requires AArch64')
    if any(args.out.resolve().is_relative_to(root.resolve()) for root in (args.capture,args.kernel_root,ROOT/'build/ohos')):
        raise ValueError('files output must be outside source and capture directories')
    generated,identity=prepare_source(args.kernel_root);checkpoint,metadata=load_capture(args.capture,identity)
    with tempfile.TemporaryDirectory(prefix='osrec-files-image-') as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(args,sources)
        shutil.copyfile(ROOT/'integrations/liteos_a/files_model.h',sources/'files_model.h')
        shutil.copyfile(ROOT/'integrations/rtl_aarch64/files_replay.c',sources/'files_replay.c')
        (sources/'files_syscalls.c').write_text(generated);(sources/'files_checkpoint.h').write_text(header(checkpoint))
        elf=stage/'files.elf';binary=stage/'files.bin'
        run([args.llvm_bin/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
            '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
            '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',
            sources/'files_replay.c',sources/'files_syscalls.c','-o',elf])
        inspected=audit(elf,args.llvm_bin);run([args.llvm_bin/'llvm-objcopy','-O','binary',elf,binary])
        observed,raw=observe(elf,args.qemu);require_success(observed)
        binary_observed,binary_raw=observe(binary,args.qemu,descriptor=elf);require_success(binary_observed)
        if raw!=binary_raw:raise ValueError('files ELF/raw results differ')
        publish=stage/'published';publish.mkdir()
        shutil.copyfile(elf,publish/elf.name);shutil.copyfile(binary,publish/binary.name);shutil.copytree(sources,publish/'sources')
        (publish/'checkpoint.json').write_text(json.dumps(checkpoint,indent=2)+'\n');(publish/'target-result.bin').write_bytes(raw)
        report={'format':'osrec-freestanding-files-image-v1','source_identity':identity,'target':target_metadata(inspected,17),
            'image_audit':inspected,'kernel_image_sha256':metadata['kernel_image_sha256'],
            'capture_manifest_sha256':digest((args.capture/'files-checkpoint.manifest.json').read_bytes()),
            'elf_sha256':digest(elf.read_bytes()),'binary_sha256':digest(binary.read_bytes()),
            'source_hashes':{p.name:digest(p.read_bytes()) for p in sorted(sources.iterdir())},
            'target_observations':observed,'raw_image_execution_match':True,'runtime_host_interaction':False,
            'state_scope':checkpoint['scope'],'modeled_dependencies':['path allocation','descriptor tables','file references and positions','RAM file I/O','native stat bytes','VM checks and user copies'],
            'provider_internals_replayed':False,'injected_errors':False}
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
