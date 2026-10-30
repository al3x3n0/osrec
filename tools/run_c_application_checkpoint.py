#!/usr/bin/env python3
"""Compile C and verify a standalone mid-sequence kernel/application checkpoint."""
import argparse,json
from pathlib import Path
from types import SimpleNamespace
from compile_c_application import compile_application
from import_application_checkpoint import import_checkpoint,digest
from export_application_replay import export
from application_pause import freeze
from verify_syscall_slices import verify_matrix


def run_pipeline(args):
    out=args.out.resolve();library=args.slices.resolve()
    if out.exists():raise FileExistsError(out)
    if out.is_relative_to(library):raise ValueError('output overlaps kernel package')
    parent=(library/'manifest.json').read_bytes();kernel=json.loads(parent)
    count=kernel['target_observations']['call_count']
    if not kernel.get('checkpoint_codec') or type(args.pause_ordinal) is not int or not 0<args.pause_ordinal<count:raise ValueError('checkpoint-capable kernel and an intermediate pause ordinal required')
    out.mkdir(parents=True);port=out/'port.json';port.write_text(json.dumps(kernel['port'],indent=2)+'\n')
    compile_application(args.source,port,out/'compiled',args.llvm_bin,json.loads(args.spec.read_text()) if args.spec else {},count)
    import_checkpoint(out/'compiled/application.elf',out/'compiled/checkpoint.json',out/'routes',reserved=[(0x43f00000,65536)])
    base=dict(slices=library,llvm_bin=args.llvm_bin,qemu=args.qemu,arch='aarch64',result_address=0x40380000,window_calls=0,pause_ordinal=args.pause_ordinal)
    producer=export(SimpleNamespace(**base,application=out/'routes',out=out/'producer',entry_address=0x40400000,checkpoint_mode='save'))
    producer_matrix=verify_matrix(out/'producer',out/'producer-qemu',qemu=args.qemu,llvm_bin=args.llvm_bin)
    joint=freeze(out/'producer',out/'checkpoint')
    consumer=export(SimpleNamespace(**base,application=out/'checkpoint/application',out=out/'consumer',entry_address=0x40600000,checkpoint_mode='load',checkpoint=out/'checkpoint'))
    consumer_matrix=verify_matrix(out/'consumer',out/'consumer-qemu',qemu=args.qemu,llvm_bin=args.llvm_bin)
    if (library/'manifest.json').read_bytes()!=parent:raise ValueError('kernel package changed during checkpoint construction')
    result=dict(format='osrec-c-joint-checkpoint-workflow-v1',status='verified',pause_ordinal=args.pause_ordinal,total_calls=count,suffix_calls=count-args.pause_ordinal,producer=producer['target_observations'],consumer=consumer['target_observations'],qemu_producer_executions=len(producer_matrix['executions']),qemu_consumer_executions=len(consumer_matrix['executions']),kernel_manifest_sha256=digest(parent),checkpoint_manifest_sha256=digest((out/'checkpoint/manifest.json').read_bytes()),construction_sha256=digest(Path(__file__).read_bytes()),input_sources=[dict(file=str(p.resolve()),sha256=digest(p.read_bytes())) for p in args.source],input_spec_sha256=digest(args.spec.read_bytes()) if args.spec else None,stages=dict(compiled='compiled',routes='routes',producer='producer',checkpoint='checkpoint',consumer='consumer',producer_verification='producer-qemu',consumer_verification='consumer-qemu'),runtime_host_interaction=False)
    result['stage_manifest_hashes']={name:digest((out/path/file).read_bytes()) for name,path,file in [('compiled','compiled','manifest.json'),('routes','routes','route-plan.json'),('producer','producer','manifest.json'),('consumer','consumer','manifest.json'),('producer-qemu','producer-qemu','verification-matrix.json'),('consumer-qemu','consumer-qemu','verification-matrix.json')]}
    (out/'workflow.json').write_text(json.dumps(result,indent=2)+'\n');return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slices',type=Path,required=True);parser.add_argument('--source',type=Path,action='append',required=True);parser.add_argument('--spec',type=Path);parser.add_argument('--pause-ordinal',type=int,required=True);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));parser.add_argument('--qemu',default='qemu-system-aarch64')
    print(json.dumps(run_pipeline(parser.parse_args()),indent=2))
if __name__=='__main__':main()
