#!/usr/bin/env python3
"""Prepare and verify portable physical RAM initialization files for a replay image."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

from check_image_memory import check,ram_region,memory_dump
from freestanding_elf import describe
from image_memory import initialization_spans,merged_ranges,verify_loaded_memory,compare_physical_memory,require_coverage


def file_hash(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        while block:=stream.read(65536):digest.update(block)
    return digest.hexdigest()


def plan(image,ram,binary=None):
    report=check(image,ram,binary)
    required=report['memory_contract']['required_ranges']
    if binary is not None:required=required+[{**report['raw_payload'],'purpose':'raw loader payload'}]
    banks=[{'address':a,'bytes':b-a,'file':f'bank-{i:03d}.bin'} for i,(a,b) in enumerate(merged_ranges(required))]
    return describe(image),report['memory_contract'],banks


def manifest(directory,ram,raw_mode):
    image=directory/'image.elf';binary=directory/'image.bin' if raw_mode else None
    layout,contract,banks=plan(image,ram,binary)
    for bank in banks:
        if (directory/bank['file']).stat().st_size!=bank['bytes']:
            raise ValueError('initialization bank extent differs from the derived loading plan')
    verified=verify_loaded_memory(image,layout,
        [{'address':b['address'],'file':directory/b['file']} for b in banks],ram,binary)
    sources=[{'file':'image.elf','sha256':file_hash(image)}]
    if binary is not None:sources.append({'file':'image.bin','sha256':file_hash(binary)})
    return {'format':'osrec-rtl-load-bundle-v1','loading_mode':'raw' if raw_mode else 'elf',
        'isa':layout['isa'],'endianness':'little','entry':layout['entry'],
        'result':{'address':layout['result_address'],'bytes':layout['result_bytes']},
        'ram_regions':ram,'memory_contract':contract,'source_files':sources,
        'banks':[{**bank,'sha256':record['sha256']} for bank,record in zip(banks,verified['dump_files'])],
        'load_instructions':'copy every bank file byte to its physical address before starting the CPU at entry; retain accessible RAM for the complete run',
        'entry_requirements':{'mmu_enabled':False,'privileged_start':True,
            'initial_exception_level':1 if layout['isa']=='AArch64' else None},
        'bank_files_verified':True,'verified_initialization_bytes':verified['verified_bytes'],
        'evidence_scope':'generated initialization files; actual model memory and CPU state are not observed',
        'model_initial_memory_verified':False,'runtime_host_interaction':False,
        'dynamic_access_coverage_proven':False,'rtl_execution_verified':False}


def verification_report(document):
    return {'format':'osrec-rtl-load-bundle-verification-v1','status':'verified',
        'isa':document['isa'],'entry':document['entry'],'banks':len(document['banks']),
        'bank_bytes':sum(b['bytes'] for b in document['banks']),
        'bank_files_verified':True,'model_initial_memory_verified':False,
        'rtl_execution_verified':False,'runtime_host_interaction':False}


def verify(directory):
    directory=Path(directory)
    # Use fixed local filenames, never paths supplied by an unverified manifest.
    document=json.loads((directory/'load-plan.json').read_text())
    if not isinstance(document,dict) or document.get('loading_mode') not in ('elf','raw'):
        raise ValueError('invalid RTL load bundle manifest')
    expected=manifest(directory,document.get('ram_regions'),document['loading_mode']=='raw')
    # Canonical JSON also distinguishes bool from integer fields.
    if json.dumps(document,sort_keys=True)!=json.dumps(expected,sort_keys=True):
        raise ValueError('RTL load bundle manifest or hashes differ from derived image contents')
    return verification_report(expected)


def check_loaded(directory,ram,dumps,cpu_state=None):
    """Compare caller-supplied pre-execution physical dumps with every bank byte."""
    directory=Path(directory);verify(directory)
    document=json.loads((directory/'load-plan.json').read_text())
    require_coverage(document['memory_contract']['required_ranges'],ram)
    spans=[{**bank,'file':directory/bank['file'],'offset':0,
        'purpose':f"bundle bank {bank['file']}"} for bank in document['banks']]
    require_coverage(spans,ram)
    comparison=compare_physical_memory(spans,dumps,ram)
    report={'format':'osrec-rtl-loaded-bundle-verification-v1','status':'verified',
        'isa':document['isa'],'entry':document['entry'],'ram_regions':ram,
        'load_plan_sha256':file_hash(directory/'load-plan.json'),
        'source_files':document['source_files'],'bank_files_verified':True,
        'initial_memory_verified':True,'model_initial_memory_verified':True,
        'initial_memory_verification':comparison,
        'snapshot_phase':'after loading all bank files, before the first instruction',
        'snapshot_phase_verified':False,'snapshot_backend':'caller-supplied physical dumps',
        'scope':'exact bank bytes in supplied physical dumps; CPU state and execution are not verified',
        'cpu_entry_state_verified':False,'dynamic_access_coverage_proven':False,
        'rtl_execution_verified':False,'runtime_host_interaction':False}
    if cpu_state is not None:
        from aarch64_entry_state import check_entry_state
        path=Path(cpu_state);state=json.loads(path.read_text())
        checked=check_entry_state(describe(directory/'image.elf'),state)
        report.update({'format':'osrec-rtl-loaded-bundle-verification-v2',
            'cpu_entry_state_verified':True,'cpu_entry_verification':checked,
            'cpu_state_file':{'file':str(path),'sha256':file_hash(path)},
            'scope':'exact bank bytes and listed CPU entry fields in supplied snapshots; execution is not verified'})
    return report


def prepare(image,ram,out,binary=None):
    image=Path(image);out=Path(out);binary=Path(binary) if binary is not None else None
    # Validate before creating any output; never overwrite a previous bundle.
    plan(image,ram,binary)
    out.mkdir(parents=True,exist_ok=False)
    try:
        shutil.copyfile(image,out/'image.elf')
        if binary is not None:shutil.copyfile(binary,out/'image.bin')
        copied=out/'image.elf';raw=out/'image.bin' if binary is not None else None
        layout,_,banks=plan(copied,ram,raw)
        spans=initialization_spans(copied,layout,raw)
        for bank in banks:
            with (out/bank['file']).open('xb') as stream:
                # New sparse extents read as zero, including loader tails and
                # any legacy startup padding. No large RAM-sized allocation.
                stream.truncate(bank['bytes'])
                for span in spans:
                    start=max(bank['address'],span['address'])
                    end=min(bank['address']+bank['bytes'],span['address']+span['bytes'])
                    if start>=end or span['file'] is None:continue
                    stream.seek(start-bank['address'])
                    with span['file'].open('rb') as source:
                        source.seek(span['offset']+start-span['address']);remaining=end-start
                        while remaining:
                            block=source.read(min(remaining,65536))
                            if not block:raise ValueError('source truncated while writing bank')
                            stream.write(block);remaining-=len(block)
        document=manifest(out,ram,binary is not None)
        (out/'load-plan.json').write_text(json.dumps(document,indent=2)+'\n')
        return verification_report(document)
    except Exception:
        shutil.rmtree(out)
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    create=commands.add_parser('prepare',help='create a new portable initialization bundle')
    create.add_argument('--image',type=Path,required=True)
    create.add_argument('--binary',type=Path)
    create.add_argument('--ram',type=ram_region,action='append',required=True)
    create.add_argument('--out',type=Path,required=True)
    validate=commands.add_parser('verify',help='recheck source hashes, plan and addressed bank bytes')
    validate.add_argument('directory',type=Path)
    loaded=commands.add_parser('check-loaded',help='verify physical testbench dumps against every bundle bank byte')
    loaded.add_argument('directory',type=Path)
    loaded.add_argument('--ram',type=ram_region,action='append',required=True,help='actual model RAM BASE:BYTES')
    loaded.add_argument('--memory-dump',type=memory_dump,action='append',required=True,help='BASE:FILE physical bytes after loading, before execution')
    loaded.add_argument('--out',type=Path,help='new verification report file')
    loaded.add_argument('--cpu-state',type=Path,help='optional osrec-aarch64-entry-state-v1/v2 JSON from the same pre-execution phase')
    args=parser.parse_args()
    if args.command=='prepare':report=prepare(args.image,args.ram,args.out,args.binary)
    elif args.command=='verify':report=verify(args.directory)
    else:
        report=check_loaded(args.directory,args.ram,args.memory_dump,args.cpu_state)
        if args.out:
            args.out.parent.mkdir(parents=True,exist_ok=True)
            with args.out.open('x') as stream:stream.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
