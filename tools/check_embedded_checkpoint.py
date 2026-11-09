#!/usr/bin/env python3
"""Validate a checkpoint with only its ELF mounted into a native arm64 container.

The source package, oracle, build sources and shared libraries are deliberately
absent. A writable output directory is provided only for optional observations.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
from export_native_checkpoint import verify_elf,verify_standalone
from kernel_source_verify import Elf
from source_image import compare


def payload_file_offset(executable):
    elf=Elf(executable)
    address=next(s['value'] for s in elf.symbols if s['name']=='osrec_checkpoint_payload')
    for section in elf.sections:
        if section['addr']<=address<section['addr']+section['size'] and section['type']!=8:
            return section['offset']+address-section['addr']
    raise ValueError('linked checkpoint payload is missing')


def check(image,oracle,out,docker_image='alpine:3'):
    image,oracle,out=map(lambda p:Path(p).resolve(),(image,oracle,out))
    binary=image/'user-checkpoint';manifest=json.loads((image/'manifest.json').read_text())
    elf=verify_standalone(binary) if binary.with_name(binary.name+'.map').exists() else verify_elf(binary)
    architecture=subprocess.run(['docker','info','--format','{{.Architecture}}'],capture_output=True,text=True,check=True).stdout.strip()
    if architecture not in ('aarch64','arm64'):raise ValueError('native validation requires an arm64 Docker daemon')
    out.mkdir(parents=True,exist_ok=False)
    def run(executable,args,stem,success,output=False):
        command=['docker','run','--rm','--network','none','--read-only',
                 '--mount','type=bind,src='+str(executable)+',dst=/checkpoint,readonly']
        if output:command+=['--mount','type=bind,src='+str(out)+',dst=/out']
        command+=['--workdir','/','--entrypoint','/checkpoint',docker_image,*args]
        result=subprocess.run(command,capture_output=True,text=True,timeout=180)
        (out/(stem+'.stdout')).write_text(result.stdout);(out/(stem+'.stderr')).write_text(result.stderr)
        if (result.returncode==0)!=success:raise ValueError(stem+' returned '+str(result.returncode)+': '+result.stdout+result.stderr)
        return result
    described=json.loads(run(binary,['--describe'],'describe',True).stdout)
    if described['identity']!=manifest['identity']:raise ValueError('embedded provenance identity differs')
    default=json.loads(run(binary,[],'default',True).stdout)
    if not default['verified']:raise ValueError('default standalone execution failed')
    positive=json.loads(run(binary,['--trace','/out/calls.json'],'checkpoint',True,output=True).stdout)
    comparison=compare(oracle/'calls.json',out/'calls.json')
    if not positive['verified'] or not comparison['matches']:raise ValueError('standalone execution differs from oracle')
    expected=json.loads((oracle/'calls.json').read_text())
    actual=json.loads((out/'calls.json').read_text())
    if actual['end']['pc']!=expected['end']['pc'] or actual['end']['stop_code']!=1:raise ValueError('wrong completion boundary')
    if actual['counters_consumed']!=manifest['counter_reads'] or actual['mmio_consumed']!=manifest['mmio_accesses']:
        raise ValueError('hardware transcript was not completely consumed')
    base=payload_file_offset(binary)
    # Corrupt only linked acceptance data, preserving the executed checkpoint.
    wrong=out/'wrong-expectation';shutil.copyfile(binary,wrong);wrong.chmod(0o755)
    with wrong.open('r+b') as file:
        file.seek(base+manifest['asset_offsets']['expected'][0]+64);value=file.read(1)
        file.seek(-1,1);file.write(bytes([value[0]^1]))
    rejected=json.loads(run(wrong,[],'wrong-expectation',False).stdout)
    if rejected['verified']:raise ValueError('corrupt embedded expectation was accepted')
    # UART output writes must be checked, not just consumed or ignored.
    records=list(struct.iter_unpack('<5Q',(oracle/'mmio.bin').read_bytes()))
    index=next(i for i,row in enumerate(records) if row[3])
    wrong_io=out/'wrong-mmio';shutil.copyfile(binary,wrong_io);wrong_io.chmod(0o755)
    with wrong_io.open('r+b') as file:
        file.seek(base+manifest['asset_offsets']['mmio'][0]+index*40+32);value=file.read(1)
        file.seek(-1,1);file.write(bytes([value[0]^1]))
    rejected_io=json.loads(run(wrong_io,[],'wrong-mmio',False).stdout)
    if rejected_io['verified'] or rejected_io['mmio_accesses']>=manifest['mmio_accesses']:
        raise ValueError('corrupt UART expectation was not rejected at the access')
    # Keep reports small; disposable mutant executables are not deliverables.
    wrong.unlink();wrong_io.unlink()
    report=dict(elf,identity=manifest['identity'],native_architecture=architecture,
                oracle_comparison=comparison,completion=positive,default_completion=default,
                isolation='read-only root, no network; default run mounts only the executable; trace run adds only an output directory',
                negative_checks=['corrupt embedded expected result rejected','corrupt MMIO output expectation rejected'])
    (out/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
    return dict(events=positive['events'],verified=positive['verified'],executable_bytes=elf['executable_size'],identity=manifest['identity'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('image','oracle','out'):p.add_argument('--'+name,required=True)
    p.add_argument('--docker-image',default='alpine:3')
    a=p.parse_args();print(json.dumps(check(a.image,a.oracle,a.out,a.docker_image)))
