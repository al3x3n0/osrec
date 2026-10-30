#!/usr/bin/env python3
"""Verify a portable AArch64 replay or EL3 boot bundle on QEMU and save evidence."""
import argparse
import json
from pathlib import Path
import subprocess

import rtl_boot_bundle
import rtl_load_bundle
from run_freestanding_armv7 import observe,require_success


def verify(directory,out,qemu='qemu-system-aarch64',memory_dumps=()):
    directory=Path(directory).resolve();out=Path(out).resolve()
    document=json.loads((directory/'load-plan.json').read_text())
    boot=document.get('format')=='osrec-rtl-el3-boot-bundle-v1'
    if boot:plan=rtl_boot_bundle.verify(directory);replay=directory/'replay'
    else:
        rtl_load_bundle.verify(directory);plan=document;replay=directory
    if plan['isa']!='AArch64':raise ValueError('QEMU bundle verification requires AArch64')
    if out.exists():raise FileExistsError(out)
    version=subprocess.check_output([qemu,'--version'],text=True).splitlines()[0]
    identity=rtl_load_bundle.file_hash(directory/'load-plan.json')
    try:
        execution,raw=observe(replay/'image.elf',qemu,initial_memory_dir=out,check_cpu_entry=True,
            boot_bundle=directory if boot else None,load_bundle=None if boot else directory,memory_dumps=memory_dumps)
        require_success(execution)
        preflight=json.loads((out/'memory-preflight.json').read_text())
        cpu=preflight['cpu_entry_verification']
        if not preflight['snapshot_phase_verified'] or not cpu['snapshot_phase_verified']:
            raise ValueError('QEMU checkpoint phase was not established')
        dumps=[{'address':d['address'],'file':Path(d['file'])} for d in preflight['initial_memory_verification']['dump_files']]
        if boot:
            dumps.append({'address':plan['entry'],'file':out/'boot-replay-entry.bin'})
            checked=rtl_boot_bundle.check_loaded(directory,plan['ram_regions'],dumps,out/'cpu-entry-state.json')
            for phase in ('before_boot','at_replay_entry'):
                if not preflight['boot_memory_verification'][phase]['snapshot_phase_verified']:
                    raise ValueError('QEMU boot memory phase was not established')
        else:checked=rtl_load_bundle.check_loaded(directory,plan['ram_regions'],dumps,out/'cpu-entry-state.json')
        if rtl_load_bundle.file_hash(directory/'load-plan.json')!=identity:
            raise ValueError('bundle load plan changed during verification')
        (out/'target-result.bin').write_bytes(raw)
        (out/'execution-report.json').write_text(json.dumps(execution,indent=2)+'\n')
        (out/'independent-loaded-verification.json').write_text(json.dumps(checked,indent=2)+'\n')
        evidence=['memory-preflight.json','cpu-entry-state.json','target-result.bin',
            'execution-report.json','independent-loaded-verification.json']
        if boot:evidence+=['boot-reset-state.json','boot-reset.bin','boot-replay-entry.bin']
        evidence += [str(Path(d['file']).relative_to(out)) for d in memory_dumps]
        report={'format':'osrec-qemu-bundle-verification-v1','status':'verified',
            'verification_target':'QEMU functional execution','qemu_version':version,
            'bundle_format':plan['format'],'load_plan_sha256':identity,
            'boot_entry':plan['entry'] if boot else None,'replay_entry':plan['replay_entry'] if boot else plan['entry'],
            'replay_bank_bytes_verified':preflight['initial_memory_verification']['verified_bytes'],
            'boot_payload_bytes_verified':preflight['boot_memory_verification']['at_replay_entry']['initial_memory_verification']['verified_bytes'] if boot else 0,
            'cpu_entry_state_verified':True,'checkpoint_phase_verified':True,
            'functional_result_verified':True,'abi_version':execution['abi_version'],
            'terminal_memory_observations':[{'address':d['address'],'bytes':d['bytes'],'file':str(Path(d['file']).relative_to(out))} for d in memory_dumps],
            'completed_calls':execution['completed_calls'],'runtime_host_interaction':False,
            'scope':'QEMU model, listed entry controls, exact planned load bytes and embedded replay expectations',
            'evidence_files':[{'file':f,'sha256':rtl_load_bundle.file_hash(out/f)} for f in evidence]}
        (out/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
        return report
    except Exception as error:
        if out.is_dir() and not isinstance(error,FileExistsError):
            (out/'verification.json').write_text(json.dumps({'format':'osrec-qemu-bundle-verification-v1',
                'status':'failed','load_plan_sha256':identity,'qemu_version':version,'error':str(error)},indent=2)+'\n')
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--qemu',default='qemu-system-aarch64');args=parser.parse_args()
    print(json.dumps(verify(args.directory,args.out,args.qemu),indent=2))


if __name__=='__main__':main()
