#!/usr/bin/env python3
"""Publish a pinned portable Linux slice bundle from a verified native capture."""
import argparse
import json
import shutil
import struct
from pathlib import Path
from capture_linux_aarch64 import INTEGRATION,reviewed_adapter,digest,profile_integration

def build_bundle(capture,out):
    capture=Path(capture).resolve();out=Path(out).resolve()
    if out.exists():raise FileExistsError(out)
    if out.is_relative_to(capture):raise ValueError('port output overlaps native capture')
    review=reviewed_adapter();observed,_=review.validate_capture(capture);profile=review.profile_for(observed);integration=profile_integration(profile)
    if (integration/'application.c').read_bytes()!=(capture/'sources/application.c').read_bytes():raise ValueError('application differs from captured native source')
    out.mkdir(parents=True)
    for name in ('prepare.py','model.h','models.c','adapter.c','checkpoint-policy.json','proof.c','application.c',*(['entry-glue.S'] if (integration/'entry-glue.S').is_file() else [])):shutil.copyfile((INTEGRATION if name=='prepare.py' else integration)/name,out/name)
    # Keep complete native evidence, excluding transient files. Kernel Image is
    # identified by hash and supplied separately when making a new capture.
    native=out/'native';native.mkdir()
    for name in ('capture.json','capture.manifest.json','kernel.config','init','root.ext2','qemu.log','source-identity.json'):shutil.copyfile(capture/name,native/name)
    shutil.copytree(capture/'sources',native/'sources');shutil.copytree(capture/'upstream',native/'upstream')
    if (out/'application.c').read_bytes()!=(native/'sources/application.c').read_bytes():raise ValueError('application differs from captured native source')
    count=len(observed['calls'])
    spec=dict(call_sites=['prefix']*8+['default']*(count-8),frame=dict(tpidr_el0=0x123456789,tpidrro_el0=0xabcde0012,v=[[0x1020304050607000+i,0xaabbccddeeff0000+i] for i in range(32)],fpcr=0x400000,fpsr=16),objects=[dict(symbol='app_words',bytes=32,id=1)],assertions=[dict(symbol='app_returns',data=struct.pack('<'+str(count)+'Q',*[c['raw_bits'] for c in observed['calls']]).hex()),dict(symbol='app_count',data=struct.pack('<Q',count).hex()),dict(symbol='app_words',data=struct.pack('<8I',*observed['calls'][-1]['words']).hex())])
    if profile in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        spec['objects'].append(dict(symbol='stat_words',bytes=128,id=2))
        spec['assertions'].append(dict(symbol='stat_digest',data=struct.pack('<Q',observed['calls'][-1]['stat_digest']).hex()))
        spec['assertions'].append(dict(symbol='stat_words',data=struct.pack('<32I',*observed['calls'][-1]['stat_words']).hex()))
    (out/'spec.json').write_text(json.dumps(spec,indent=2)+'\n')
    port=json.loads((integration/'port-template.json').read_text())
    port['bundle']=dict(format='osrec-kernel-slice-bundle-v1',adapter='prepare.py',proofs=dict(session=dict(source='proof.c',result_abi=26)),inputs={str(p.relative_to(out)):digest(p.read_bytes()) for p in sorted(out.rglob('*')) if p.is_file()})
    (out/'port.json').write_text(json.dumps(port,indent=2)+'\n')
    return out/'port.json'

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--capture',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    print(build_bundle(args.capture,args.out))

if __name__=='__main__':main()
