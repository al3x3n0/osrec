#!/usr/bin/env python3
"""Validate MMU-off replay RAM coverage and optional pre-execution loader dumps."""
import argparse
import json
from pathlib import Path
from klee_liteos import digest
from freestanding_elf import describe
from image_memory import memory_contract,require_coverage,validate_raw,verify_loaded_memory

def ram_region(value):
    try:
        parts=value.split(':')
        if len(parts)!=2:raise ValueError()
        address,size=(int(part,0) for part in parts)
        if address<0 or size<=0 or address+size>1<<64:raise ValueError()
        return {'address':address,'bytes':size}
    except ValueError as error:raise argparse.ArgumentTypeError('RAM must be BASE:BYTES, with a nonnegative base and positive bounded size') from error

def memory_dump(value):
    try:
        base,file=value.split(':',1)
        address=int(base,0)
        if address<0 or address>=1<<64 or not file:raise ValueError()
        return {'address':address,'file':Path(file)}
    except ValueError as error:raise argparse.ArgumentTypeError('memory dump must be BASE:FILE with a nonnegative bounded base') from error

def check(image,ram,binary=None,dumps=None):
    layout=describe(image);contract=memory_contract(layout)
    require_coverage(contract['required_ranges'],ram)
    payload=None
    if binary is not None:
        payload=validate_raw(binary,image,layout)
        require_coverage([{**payload,'purpose':'raw loader payload'}],ram)
    initialized=verify_loaded_memory(image,layout,dumps,ram,binary) if dumps is not None else None
    return {'format':'osrec-image-memory-preflight-v2' if dumps is not None else 'osrec-image-memory-preflight-v1','status':'verified','elf_sha256':digest(image.read_bytes()),
        'entry':layout['entry'],'isa':layout['isa'],'ram_regions':ram,'memory_contract':contract,
        'binary_sha256':digest(binary.read_bytes()) if binary else None,'raw_payload':payload,
        'result_address':layout['result_address'],'result_bytes':layout['result_bytes'],
        'scope':'declared ELF, startup clearing, stack, result and optional raw loading ranges; dynamic accesses are not proven',
        'initial_memory_verified':initialized is not None,'initial_memory_verification':initialized,
        'runtime_host_interaction':False,'rtl_validated':False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True,type=Path)
    parser.add_argument('--binary',type=Path,help='also verify raw payload bytes and its complete loading range')
    parser.add_argument('--ram',required=True,action='append',type=ram_region,help='physical BASE:BYTES; repeat for multiple RAM regions')
    parser.add_argument('--memory-dump',action='append',type=memory_dump,help='BASE:FILE bytes captured after loading and zero-fill, before first instruction; repeat for multiple banks')
    parser.add_argument('--out',type=Path,help='save a preflight report; requires a new output file')
    args=parser.parse_args()
    report=check(args.image,args.ram,args.binary,args.memory_dump)
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True)
        with args.out.open('x') as stream:stream.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
