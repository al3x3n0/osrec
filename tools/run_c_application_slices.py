#!/usr/bin/env python3
"""Compile C, derive ELF routes, compose persistent syscall windows and verify QEMU."""
import argparse
import json
from pathlib import Path
from compile_c_application import compile_application
from import_application_checkpoint import import_checkpoint,digest
from export_application_replay import export
from verify_syscall_slices import verify_matrix

def run_pipeline(args):
    out=args.out.resolve();library=args.slices.resolve()
    if out.exists():raise FileExistsError(out)
    if out.is_relative_to(library):raise ValueError('workflow output overlaps the kernel library')
    manifest=(library/'manifest.json').read_bytes();kernel=json.loads(manifest)
    calls=args.calls if args.calls is not None else kernel['target_observations']['call_count']
    sources=[dict(file=str(p.resolve()),sha256=digest(p.read_bytes())) for p in args.source]
    spec=json.loads(args.spec.read_text()) if args.spec else {}
    out.mkdir(parents=True);port=out/'port.json';port.write_text(json.dumps(kernel['port'],indent=2)+'\n')
    compile_application(args.source,port,out/'application',args.llvm_bin,spec,calls)
    import_checkpoint(out/'application/application.elf',out/'application/checkpoint.json',out/'routes',reserved=[(0x43f00000,65536)])
    args.application=out/'routes';args.out=out/'image';args.arch='aarch64'
    image=export(args)
    matrix=verify_matrix(out/'image',out/'qemu-verified',qemu=args.qemu,llvm_bin=args.llvm_bin)
    if (library/'manifest.json').read_bytes()!=manifest:raise ValueError('kernel library changed during workflow')
    report=dict(format='osrec-c-application-slices-workflow-v1',status='verified',kernel_manifest_sha256=digest(manifest),input_sources=sources,spec_sha256=digest(args.spec.read_bytes()) if args.spec else None,compiled_elf_sha256=digest((out/'application/application.elf').read_bytes()),route_manifest_sha256=digest((out/'routes/route-plan.json').read_bytes()),image_manifest_sha256=digest((out/'image/manifest.json').read_bytes()),verification_sha256=digest((out/'qemu-verified/verification-matrix.json').read_bytes()),pipeline_sha256=digest(Path(__file__).read_bytes()),stages=dict(application='application',routes='routes',image='image',qemu='qemu-verified'),window_call_limit=args.window_calls,target_observations=image['target_observations'],qemu_executions=len(matrix['executions']),runtime_host_interaction=False)
    (out/'workflow.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slices',type=Path,required=True);parser.add_argument('--source',type=Path,action='append',required=True);parser.add_argument('--spec',type=Path);parser.add_argument('--calls',type=int);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--window-calls',type=int,default=1);parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));parser.add_argument('--qemu',default='qemu-system-aarch64')
    parser.add_argument('--entry-address',type=lambda v:int(v,0),default=0x40400000);parser.add_argument('--result-address',type=lambda v:int(v,0),default=0x40380000)
    args=parser.parse_args();print(json.dumps(run_pipeline(args),indent=2))
if __name__=='__main__':main()
