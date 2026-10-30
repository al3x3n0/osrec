#!/usr/bin/env python3
"""Export four source-pinned SysRead calls and their object graph/transcript to ARM RAM."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile

from klee_liteos import ROOT,digest
from freestanding_armv7 import TARGET,audit,run
from syscall_checkpoint import identity,load,validate_capture,setup,event_initializer
from freestanding_elf import prepare_target,add_target_arguments,target_metadata
from run_freestanding_armv7 import observe,require_success


def driver(document,objects):
    files=sorted(obj['id'] for obj in objects.values() if obj['type']=='file')
    events=sum(len(row) for row in document['transcript'])
    lines=['#include "syscall_checkpoint.h"','extern volatile uint32_t osrec_result[32];',
           '__attribute__((noreturn)) void replay_complete(uint32_t status,uint32_t error);',
           'void replay_main(void) {','for(unsigned i=0;i<32;++i) osrec_result[i]=0;',
           'osrec_result[0]=UINT32_C(0x4f535243); osrec_result[1]=4; osrec_result[2]=1;',
           f'osrec_result[5]=4; osrec_result[9]={len(files)}; osrec_result[30]={events};']
    lines += [line.replace('return 1;','replay_complete(3,1);') for line in setup(document['entry'],objects)]
    for index,(call,transcript,expected) in enumerate(zip(document['calls'],document['transcript'],document['expected'])):
        ref=call['buffer'];values=','.join(event_initializer(event) for event in transcript) or '{0}'
        lines += ['{',f'struct session_call call={{{call["fd"]},{call["count"]},{{UINT64_C({ref["object"]}),UINT64_C({ref["offset"]})}}}};',
                  f'const struct session_event transcript[{max(1,len(transcript))}]={{{values}}};',
                  f'struct session_result actual=osrec_session_run(process,&table,call,NULL,transcript,{len(transcript)});',
                  f'if(actual.failed) replay_complete(3,{10+index});',
                  f'osrec_result[{10+4*index}]=(uint32_t)actual.raw; osrec_result[{11+4*index}]=(uint32_t)actual.result;',
                  f'osrec_result[{12+4*index}]=actual.error; osrec_result[{13+4*index}]=actual.recognized;',
                  'osrec_result[6]+=actual.event_count; osrec_result[7]=process->kernel_errno; osrec_result[8]=process->user_errno;']
        for i,identifier in enumerate(files):lines.append(f'osrec_result[{26+i}]=object_{identifier}.position;')
        lines += ['osrec_result[28]=osrec_result[29]=0;',
                  'for(unsigned i=0;i<8;++i) osrec_result[28+i/4]|=(uint32_t)process->memory[i]<<((i%4)*8);']
        checks=[f'actual.raw!={expected["raw"]}',f'actual.result!={expected["return"]}',
                f'actual.error!={expected["errno"]}U',f'actual.recognized!={expected["recognized"]}U',
                f'process->kernel_errno!={expected["kernel_errno"]}U']
        checks += [f'process->memory[{i}]!={value}' for i,value in enumerate(bytes.fromhex(expected['memory']))]
        checks += [f'object_{identifier}.position!=UINT32_C({position})' for identifier,position in expected['file_positions'].items()]
        lines += ['if('+' || '.join(checks)+f') replay_complete(3,{20+index});',f'osrec_result[4]={index+1};','}']
    lines += ['if(osrec_result[6]!=osrec_result[30]) replay_complete(3,2);','replay_complete(2,0);','}']
    return '\n'.join(lines)+'\n'


def export(args):
    if args.out.exists():raise ValueError('choose a new output directory')
    if any(args.out.is_relative_to(root.resolve()) for root in (args.kernel_root,args.capture.parent,ROOT/'build/ohos')):
        raise ValueError('image output must be outside source and capture directories')
    document=load(args.capture);record,generated,model_sources=identity(args.kernel_root)
    objects=validate_capture(document,record)
    if len(document['calls'])!=4:raise ValueError('read image requires four calls')
    if identity(ROOT/'build/ohos/kernel/liteos_a')[0]['kernel']!=record['kernel']:
        raise ValueError('live SysRead source differs')
    with tempfile.TemporaryDirectory(prefix='osrec-read-image-') as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir();(sources/'osrec').mkdir()
        for filename in ('start.S','image.ld','read_result.c','memory.c'):shutil.copy2(TARGET/filename,sources/filename)
        for path,data in model_sources.items():
            if path.name=='syscall_checkpoint_io.c':continue
            destination=sources/('osrec/checkpoint.h' if path==ROOT/'include/osrec/checkpoint.h' else path.name)
            destination.write_bytes(data)
        (sources/'kernel_sysread.c').write_text(generated);(sources/'read_main.c').write_text(driver(document,objects))
        image=stage/'read.elf'
        target_flags=prepare_target(args,sources)
        command=[args.llvm_bin/'clang',*target_flags,
                 '-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables',
                 '-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static','-fuse-ld=lld',
                 '-I',sources,'-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),
                 *[sources/file for file in ('start.S','read_result.c','memory.c','read_main.c','kernel_sysread.c','checkpoint.c','syscall_checkpoint.c')],'-o',image]
        run(command);inspection=audit(image,args.llvm_bin)
        binary=stage/'read.bin';run([args.llvm_bin/'llvm-objcopy','-O','binary',image,binary])
        observed,raw=observe(image,args.qemu);require_success(observed)
        raw_observed,raw_result=observe(binary,args.qemu,descriptor=image);require_success(raw_observed)
        if raw_result!=raw:raise ValueError('ELF and raw read results differ')
        expected=[{key:value[key] for key in ('raw','return','errno','recognized')} for value in document['expected']]
        final=document['expected'][-1];positions=[final['file_positions'][str(identifier)] for identifier in sorted(int(i) for i in final['file_positions'])]
        if (observed['abi_version']!=4 or observed['actual_calls']!=expected or observed['memory']!=final['memory']
                or observed['file_positions']!=positions or observed['kernel_errno']!=final['kernel_errno'] or observed['user_errno']!=final['errno']):
            raise ValueError('target read observations differ from capture')
        report={'format':'osrec-freestanding-read-image-v1','source_identity':record,'checkpoint':document,
                'capture_sha256':digest(args.capture.read_bytes()),'image_audit':inspection,
                'target':target_metadata(inspection,4),
                'runtime_host_interaction':False,'system_libraries':[],'guest_io':False,
                'modeled_dependencies':['address range','descriptor mapping','read payload/errno/file cursor','user errno adapter'],
                'elf_sha256':digest(image.read_bytes()),'binary_sha256':digest(binary.read_bytes()),
                'target_observations':observed,'target_result_sha256':digest(raw),'raw_image_execution_match':True,
                'source_hashes':{str(path.relative_to(sources)):digest(path.read_bytes()) for path in sorted(sources.rglob('*')) if path.is_file()},
                'compiler':run([args.llvm_bin/'clang','--version']).stdout.splitlines()[0],
                'qemu':run([args.qemu,'--version']).stdout.splitlines()[0],
                'rtl_validated':False,'cycle_timing_equivalence_verified':False}
        args.out.parent.mkdir(parents=True,exist_ok=True);publish=stage/'published';publish.mkdir()
        shutil.copy2(image,publish/'read.elf');shutil.copy2(binary,publish/'read.bin');shutil.copytree(sources,publish/'sources')
        (publish/'target-result.bin').write_bytes(raw);(publish/'checkpoint.json').write_text(json.dumps(document,indent=2)+'\n')
        (publish/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');shutil.copytree(publish,args.out)
    print(json.dumps({'image':str(args.out/'read.elf'),'raw_image':str(args.out/'read.bin'),
                      'runtime_host_interaction':False,'completed_calls':observed['completed_calls'],'memory':observed['memory']},indent=2))


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
