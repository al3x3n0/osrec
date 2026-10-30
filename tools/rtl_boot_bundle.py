#!/usr/bin/env python3
"""Package a replay bank bundle and verified EL3 boot payload for model loading."""
import argparse
import json
from pathlib import Path
import shutil

import aarch64_boot
import rtl_load_bundle
from freestanding_elf import describe
from image_memory import require_coverage


def manifest(directory):
    directory=Path(directory);replay=directory/'replay'
    rtl_load_bundle.verify(replay)
    replay_plan=json.loads((replay/'load-plan.json').read_text())
    boot=aarch64_boot.verify(describe(replay/'image.elf'),directory/'boot')
    require_coverage([boot['reserved_range']],replay_plan['ram_regions'])
    loads=[{**bank,'file':'replay/'+bank['file']} for bank in replay_plan['banks']]
    loads.append({**boot['payload'],'file':'boot/boot.bin'})
    return {'format':'osrec-rtl-el3-boot-bundle-v1','isa':'AArch64','endianness':'little',
        'entry':boot['entry'],'replay_entry':replay_plan['entry'],'result':replay_plan['result'],
        'ram_regions':replay_plan['ram_regions'],'loads':loads,
        'replay_plan_sha256':rtl_load_bundle.file_hash(replay/'load-plan.json'),
        'boot_plan_sha256':rtl_load_bundle.file_hash(directory/'boot/boot-plan.json'),
        'entry_requirements':{'initial_exception_level':3,'el2_implemented':True,'el3_implemented':True,
            'aarch64':True,'el3_mmu_enabled':False,'el3_caches_enabled':False},
        'boot_reserved_range':boot['reserved_range'],
        'load_instructions':'copy all load file bytes to their physical addresses, start at entry in the listed EL3 reset state, retain accessible RAM for the complete run',
        'checkpoint_instructions':'observe at replay_entry before its first instruction; check replay banks, boot payload and listed EL1 CPU controls',
        'artifact_bytes_verified':True,'model_initial_memory_verified':False,
        'runtime_host_interaction':False,'rtl_execution_verified':False}


def verify(directory):
    directory=Path(directory);actual=json.loads((directory/'load-plan.json').read_text())
    expected=manifest(directory)
    if json.dumps(actual,sort_keys=True)!=json.dumps(expected,sort_keys=True):
        raise ValueError('combined boot bundle differs from derived loading plan')
    return expected


def prepare(replay,out,llvm=Path('/opt/homebrew/opt/llvm@16/bin'),address=aarch64_boot.BOOT_ADDRESS):
    replay=Path(replay);out=Path(out);rtl_load_bundle.verify(replay)
    plan=json.loads((replay/'load-plan.json').read_text());layout=describe(replay/'image.elf')
    aarch64_boot.validate(layout,address)
    require_coverage([{'address':address,'bytes':aarch64_boot.BOOT_BYTES}],plan['ram_regions'])
    out.mkdir(parents=True,exist_ok=False)
    try:
        target=out/'replay';target.mkdir()
        files=['load-plan.json','image.elf']+[bank['file'] for bank in plan['banks']]
        if plan['loading_mode']=='raw':files.append('image.bin')
        for name in files:shutil.copyfile(replay/name,target/name)
        aarch64_boot.build(layout,out/'boot',llvm,address)
        document=manifest(out);(out/'load-plan.json').write_text(json.dumps(document,indent=2)+'\n')
        return verify(out)
    except Exception:
        shutil.rmtree(out);raise


def check_loaded(directory,ram,dumps,cpu_state=None):
    directory=Path(directory);plan=verify(directory)
    replay=rtl_load_bundle.check_loaded(directory/'replay',ram,dumps,cpu_state)
    boot=aarch64_boot.check_loaded(describe(directory/'replay/image.elf'),directory/'boot',ram,dumps)
    return {'format':'osrec-rtl-loaded-el3-boot-bundle-verification-v1','status':'verified',
        'load_plan_sha256':rtl_load_bundle.file_hash(directory/'load-plan.json'),
        'entry':plan['entry'],'replay_entry':plan['replay_entry'],
        'replay_memory_verification':replay,'boot_memory_verification':boot,
        'model_initial_memory_verified':True,'cpu_entry_state_verified':replay['cpu_entry_state_verified'],
        'snapshot_phase_verified':False,'snapshot_backend':'caller-supplied physical dumps',
        'scope':'all planned load bytes and optional listed EL1 CPU fields in supplied snapshots; capture phase and execution are unverified',
        'runtime_host_interaction':False,'rtl_execution_verified':False}


def main():
    from check_image_memory import ram_region,memory_dump
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest='command',required=True)
    create=commands.add_parser('prepare');create.add_argument('--replay-bundle',type=Path,required=True)
    create.add_argument('--out',type=Path,required=True);create.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    create.add_argument('--boot-address',type=lambda s:int(s,0),default=aarch64_boot.BOOT_ADDRESS)
    inspect=commands.add_parser('verify');inspect.add_argument('directory',type=Path)
    loaded=commands.add_parser('check-loaded');loaded.add_argument('directory',type=Path)
    loaded.add_argument('--ram',type=ram_region,action='append',required=True)
    loaded.add_argument('--memory-dump',type=memory_dump,action='append',required=True)
    loaded.add_argument('--cpu-state',type=Path)
    loaded.add_argument('--out',type=Path)
    args=parser.parse_args()
    if args.command=='prepare':report=prepare(args.replay_bundle,args.out,args.llvm_bin,args.boot_address)
    elif args.command=='verify':report=verify(args.directory)
    else:
        report=check_loaded(args.directory,args.ram,args.memory_dump,args.cpu_state)
        if args.out:
            with args.out.open('x') as stream:stream.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
