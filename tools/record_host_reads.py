#!/usr/bin/env python3
"""Record real host-file read observations in the portable boundary transport."""
import argparse
import os
from pathlib import Path
import sys

from syscall_checkpoint import identity, load, keys, publish, validate_entry
from read_observations import backend_calls, context_hash, encode


def record(args):
    case=load(args.entry)
    keys(case,("format","entry","calls"),"read entry manifest")
    if case["format"]!="osrec-syscall-session-entry-v1": raise ValueError("unsupported read entry manifest")
    objects=validate_entry(case["entry"],case["calls"])
    record_identity,_,_=identity(args.kernel_root)
    paths={}
    for binding in args.file:
        identifier,path=binding.split("=",1)
        identifier=int(identifier)
        if identifier in paths: raise ValueError("duplicate file binding")
        paths[identifier]=Path(path).resolve()
    files={obj["id"]:obj for obj in objects.values() if obj["type"]=="file"}
    if set(paths)!=set(files): raise ValueError("provide one --file OBJECT_ID=PATH per file object")
    helpers = set(Path(__file__).resolve().parent.glob("*.py"))
    if args.out.resolve() in {*paths.values(),args.entry.resolve(),*helpers} or args.out.resolve().is_relative_to(args.kernel_root.resolve()):
        raise ValueError("capture output cannot overwrite an input")
    descriptors={}
    reads=[]
    try:
        for identifier,path in paths.items():
            fd=os.open(path,os.O_RDONLY)
            descriptors[identifier]=fd
            os.lseek(fd,files[identifier]["fields"]["position"],os.SEEK_SET)
        for index,call,file_id,backend_fd in backend_calls(case["entry"],case["calls"],objects):
            if not file_id: outcome={"result":-1,"errno":9,"payload":""}
            else:
                try:
                    data=os.read(descriptors[file_id],call["count"])
                    outcome={"result":len(data),"errno":0,"payload":data.hex()}
                except OSError as error:
                    outcome={"result":-1,"errno":error.errno,"payload":""}
            reads.append((index,call,backend_fd,outcome))
    finally:
        for fd in descriptors.values(): os.close(fd)
    publish(args.out,encode(context_hash(case["entry"],case["calls"],record_identity),reads))
    print(f"recorded {len(reads)} actual host read outcomes")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-root",required=True,type=Path)
    parser.add_argument("--entry",required=True,type=Path)
    parser.add_argument("--file",action="append",default=[])
    parser.add_argument("--out",required=True,type=Path)
    args=parser.parse_args()
    try: record(args)
    except (OSError,ValueError,KeyError,TypeError) as error:
        print(f"host read capture rejected: {error}",file=sys.stderr); return 1
    return 0


if __name__=="__main__": sys.exit(main())
