#!/usr/bin/env python3
"""Run both native checkpoint link variants and require complete oracle agreement."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
from source_image import compare


def check(package,oracle,binaries,out,live=None):
    package,oracle,binaries,out=map(lambda p:Path(p).resolve(),(package,oracle,binaries,out))
    out.mkdir(parents=True,exist_ok=False)
    expected=json.loads((oracle/'calls.json').read_text())
    counters=(oracle/'counters.bin').stat().st_size//24
    mmio=(oracle/'mmio.bin').stat().st_size//40
    results={}
    if live:
        results['live_vs_qemu']=compare(live,oracle/'calls.json')
        if not results['live_vs_qemu']['matches']:raise ValueError('QEMU oracle differs from live recording')
    for executable in ('user-checkpoint','user-checkpoint-shared'):
        record=out/(executable+'.json')
        run=subprocess.run([str(binaries/executable),str(package),str(oracle/'counters.bin'),str(record),str(oracle/'mmio.bin')],
                           capture_output=True,text=True,timeout=180)
        (out/(executable+'.log')).write_text(run.stdout+run.stderr)
        if run.returncode:raise ValueError(executable+' failed: '+run.stdout+run.stderr)
        comparison=compare(oracle/'calls.json',record)
        actual=json.loads(record.read_text())
        if not comparison['matches'] or actual['end']['pc']!=expected['end']['pc'] or actual['end']['stop_code']!=1:
            raise ValueError(executable+' diverged: '+str(comparison))
        if actual['counters_consumed']!=counters or actual['mmio_consumed']!=mmio:
            raise ValueError(executable+' did not consume the complete hardware transcript')
        results[executable]=comparison
    uart=bytes(v&255 for pc,a,s,w,v in struct.iter_unpack('<5Q',(oracle/'mmio.bin').read_bytes()) if w and a&4095==0)
    if uart!=(oracle/'console.txt').read_bytes() or b'OSREC_VM_PASS' not in uart:
        raise ValueError('recorded UART writes do not reproduce the complete PASS output')
    results.update(package=str(package),oracle=str(oracle),counter_reads=counters,mmio_accesses=mmio,
                   console=uart.decode(),native_end=expected['end']['pc'],
                   execution='native captured application and kernel, branch-to-BRK gateways, recorded architecture inputs')
    (out/'validation.json').write_text(json.dumps(results,indent=2)+'\n')
    return {key:results[key] for key in ('counter_reads','mmio_accesses','native_end')}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','oracle','binaries','out'):p.add_argument('--'+name,required=True)
    p.add_argument('--live')
    a=p.parse_args();print(json.dumps(check(a.package,a.oracle,a.binaries,a.out,a.live)))
