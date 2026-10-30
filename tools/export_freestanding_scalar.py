#!/usr/bin/env python3
"""Build a freestanding image for captured scheduler-limit and PID queries."""
import argparse
import json
from pathlib import Path
import re
import shutil
import struct
import tempfile

from klee_liteos import ROOT,digest
from freestanding_armv7 import TARGET,audit,run
from freestanding_elf import prepare_target,add_target_arguments,target_metadata
from run_freestanding_armv7 import observe,require_success

ROOTS=(('SysSchedGetPriorityMax','sched-priority-source-lock.json','priority',159),
       ('SysSchedGetPriorityMin','sched-priority-min-source-lock.json','priority-min',160),
       ('SysGetPID','getpid-source-lock.json','pid',20))


def prepare_sources(kernel_root):
    revision=run(['git','-C',kernel_root,'rev-parse','HEAD']).stdout.strip()
    sources={};identities={}
    for function,filename,prefix,number in ROOTS:
        lock=json.loads((ROOT/'integrations/liteos_a'/filename).read_text())
        if revision!=lock['revision']:raise ValueError('scalar kernel revision differs')
        for root in (kernel_root,ROOT/'build/ohos/kernel/liteos_a'):
            if digest((root/lock['source']).read_bytes())!=lock['source_sha256']:raise ValueError('scalar syscall source changed')
            for relative,expected in lock['headers'].items():
                if digest((root/relative).read_bytes())!=expected:raise ValueError('scalar dependency/constant header changed')
        source=(kernel_root/lock['source']).read_text()
        signature='unsigned int SysGetPID\\(void\\)' if number==20 else f'int {function}\\(int policy\\)'
        match=re.search(signature+r'\s*\{.*?\n\}',source,re.S)
        if not match or digest(match[0].encode())!=lock['function_sha256']:raise ValueError('scalar body changed')
        license_text=source[:source.index('*/')+2]
        prelude='\nextern unsigned int LOS_GetCurrProcessID(void);\n' if number==20 else '\n'+''.join(
            f'#define {name} {value}'+('U' if name=='LOS_SCHED_RR' else '')+'\n' for name,value in lock['constants'].items())
        generated=license_text+prelude+match[0]+'\n';sources[prefix+'.c']=generated
        identities[function]={'source':lock,'license':license_text,'generated_source_sha256':digest(generated.encode())}
    return sources,identities


def load_capture(directory,identities):
    calls=[];manifests={};kernel_hash=None;pid=None
    for function,filename,prefix,number in ROOTS:
        path=directory/(prefix+'-replay.manifest.json');document=json.loads(path.read_text())['metadata']
        expected_format='osrec-live-pid-replay-v1' if number==20 else 'osrec-live-priority-replay-v1'
        if document['format']!=expected_format or document['root']!=function:raise ValueError('scalar capture format/root differs')
        if document['source_identity']['source']!=identities[function]['source']:raise ValueError('scalar capture source lock differs')
        if document['source_identity']['license']!=identities[function]['license']:raise ValueError('scalar source license differs')
        if kernel_hash is None:kernel_hash=document['kernel_image_sha256']
        elif kernel_hash!=document['kernel_image_sha256']:raise ValueError('scalar captures come from different kernel images')
        data=(directory/(prefix+'-observations.bin')).read_bytes()
        if digest(data)!=document['live_observations_sha256']:raise ValueError('scalar observation hash differs')
        decoded=[]
        if number==20:
            if len(data)!=8:raise ValueError('PID observation size differs')
            pid,mode=struct.unpack('<2I',data)
            if mode!=16 or not pid or document['checkpoint']['current_process_id']!=pid:raise ValueError('PID checkpoint/mode differs')
            decoded=[{'raw':pid,'user_mode':mode}];calls.append({'number':20,'argument_bits':0,'raw':pid})
        else:
            if len(data)!=36:raise ValueError('priority observation size differs')
            for i,expected in enumerate((2,1,0xffffffff)):
                policy,raw,mode=struct.unpack_from('<3I',data,i*12)
                if policy!=expected or mode!=16:raise ValueError('priority policy/mode differs')
                signed=raw if raw<0x80000000 else raw-0x100000000
                decoded.append({'policy_bits':policy,'raw':signed,'user_mode':mode})
                calls.append({'number':number,'argument_bits':policy,'raw':signed})
        if decoded!=document['calls']:raise ValueError('scalar decoded calls differ from manifest')
        manifests[prefix]=digest(path.read_bytes())
    return {'format':'osrec-target-scalar-checkpoint-v1','current_process_id':pid,'calls':calls},manifests,kernel_hash


def export(args):
    if args.out.exists():raise ValueError('choose a new output directory')
    if any(args.out.is_relative_to(root.resolve()) for root in (args.kernel_root,args.capture,ROOT/'build/ohos')):
        raise ValueError('image output must be outside source and capture directories')
    generated,identities=prepare_sources(args.kernel_root)
    checkpoint,capture_hashes,kernel_hash=load_capture(args.capture,identities)
    rows=',\n'.join('{'+','.join(f'UINT32_C({value})' for value in
          (call['number'],call['argument_bits'],call['raw']&0xffffffff))+'}' for call in checkpoint['calls'])
    header='#include <stdint.h>\nstatic const uint32_t checkpoint_pid=UINT32_C('+str(checkpoint['current_process_id'])+');\n'
    header+='struct checkpoint_call { uint32_t number,argument,raw; };\nstatic const struct checkpoint_call checkpoint_calls[7]={'+rows+'};\n'
    with tempfile.TemporaryDirectory(prefix='osrec-scalar-image-') as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir()
        for filename in ('start.S','image.ld','scalar_replay.c'):shutil.copy2(TARGET/filename,sources/filename)
        for filename,content in generated.items():(sources/filename).write_text(content)
        (sources/'checkpoint.h').write_text(header);image=stage/'scalar.elf'
        target_flags=prepare_target(args,sources)
        command=[args.llvm_bin/'clang',*target_flags,
                 '-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables',
                 '-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static','-fuse-ld=lld',
                 '-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'scalar_replay.c',
                 *[sources/name for name in generated],'-o',image]
        run(command);inspection=audit(image,args.llvm_bin)
        binary=stage/'scalar.bin';run([args.llvm_bin/'llvm-objcopy','-O','binary',image,binary])
        observed,raw=observe(image,args.qemu);require_success(observed)
        raw_observed,raw_result=observe(binary,args.qemu,descriptor=image);require_success(raw_observed)
        if raw_result!=raw:raise ValueError('ELF and raw image results differ')
        expected=[{'number':call['number'],'raw':call['raw']} for call in checkpoint['calls']]
        if observed['abi_version']!=3 or observed['initial_pid']!=checkpoint['current_process_id'] or observed['actual_calls']!=expected:
            raise ValueError('scalar target observations differ from live capture')
        report={'format':'osrec-freestanding-scalar-image-v1','source_identities':identities,
                'target':target_metadata(inspection,3),
                'checkpoint':checkpoint,'checkpoint_sha256':digest(header.encode()),'image_audit':inspection,
                'runtime_host_interaction':False,'system_libraries':[],'guest_io':False,
                'modeled_dependencies':['LOS_GetCurrProcessID'],'kernel_image_sha256':kernel_hash,
                'live_capture_manifest_hashes':capture_hashes,'elf_sha256':digest(image.read_bytes()),
                'binary_sha256':digest(binary.read_bytes()),'target_observations':observed,'raw_image_execution_match':True,
                'target_result_sha256':digest(raw),'source_hashes':{path.name:digest(path.read_bytes()) for path in sorted(sources.iterdir())},
                'compiler':run([args.llvm_bin/'clang','--version']).stdout.splitlines()[0],
                'qemu':run([args.qemu,'--version']).stdout.splitlines()[0],
                'rtl_validated':False,'cycle_timing_equivalence_verified':False}
        args.out.parent.mkdir(parents=True,exist_ok=True);publish=stage/'published';publish.mkdir()
        shutil.copy2(image,publish/'scalar.elf');shutil.copy2(binary,publish/'scalar.bin');shutil.copytree(sources,publish/'sources')
        (publish/'target-result.bin').write_bytes(raw);(publish/'checkpoint.json').write_text(json.dumps(checkpoint,indent=2)+'\n')
        (publish/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');shutil.copytree(publish,args.out)
    print(json.dumps({'image':str(args.out/'scalar.elf'),'raw_image':str(args.out/'scalar.bin'),
                      'runtime_host_interaction':False,'completed_calls':observed['completed_calls']},indent=2))


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
