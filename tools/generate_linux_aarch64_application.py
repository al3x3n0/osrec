#!/usr/bin/env python3
"""Generate the Linux C syscall witness from its reviewed recipe and port ABI."""
import argparse
import json
from pathlib import Path
from capture_linux_aarch64 import profile_integration,reviewed_adapter

def generate(profile):
    integration=profile_integration(profile)
    return reviewed_adapter().application_source(profile,json.loads((integration/'port-template.json').read_text()))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    source=generate(args.profile)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(source)
    print(args.out)

if __name__=='__main__':main()
