#!/usr/bin/env python3
"""Compile C and advance joint checkpoints through fresh self-contained QEMU images."""
import argparse,json
from pathlib import Path
from compile_c_application import compile_application
from import_application_checkpoint import import_checkpoint,digest
from application_checkpoint_chain import checked_ordinals,run_stages,publish_report,verify_chain


def run_pipeline(args):
    out=args.out.resolve();library=args.slices.resolve()
    if out.exists():raise FileExistsError(out)
    if out.is_relative_to(library):raise ValueError('chain output overlaps kernel package')
    parent=(library/'manifest.json').read_bytes();kernel=json.loads(parent);total=kernel['target_observations']['call_count']
    points=checked_ordinals(args.pause_ordinals,total)
    if not kernel.get('checkpoint_codec'):raise ValueError('checkpoint-capable kernel required')
    out.mkdir(parents=True);port=out/'port.json';port.write_text(json.dumps(kernel['port'],indent=2)+'\n')
    compile_application(args.source,port,out/'compiled',args.llvm_bin,json.loads(args.spec.read_text()) if args.spec else {},total)
    import_checkpoint(out/'compiled/application.elf',out/'compiled/checkpoint.json',out/'routes',reserved=[(0x43f00000,65536)])
    rows=run_stages(args,out,library,parent,kernel,points)
    report=dict(format='osrec-c-joint-checkpoint-chain-v1',status='verified',pause_ordinals=points,total_calls=total,logical_calls=sum(r['logical_calls'] for r in rows),stages=rows,kernel_manifest_sha256=digest(parent),construction_sha256=digest(Path(__file__).read_bytes()),input_sources=[dict(file=str(p.resolve()),sha256=digest(p.read_bytes())) for p in args.source],input_spec_sha256=digest(args.spec.read_bytes()) if args.spec else None,runtime_host_interaction=False)
    return publish_report(out,report,['compiled/manifest.json','routes/route-plan.json','port.json'])


def ordinals(text):
    try:return [int(p,0) for p in text.split(',')]
    except ValueError:raise argparse.ArgumentTypeError('supply comma-separated absolute pause ordinals') from None


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slices',type=Path);parser.add_argument('--source',type=Path,action='append');parser.add_argument('--spec',type=Path);parser.add_argument('--pause-ordinals',type=ordinals);parser.add_argument('--out',type=Path);parser.add_argument('--verify',type=Path)
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));parser.add_argument('--qemu',default='qemu-system-aarch64')
    args=parser.parse_args()
    if args.verify:result=verify_chain(args.verify)
    else:
        if not args.slices or not args.source or not args.pause_ordinals or not args.out:parser.error('--slices, --source, --pause-ordinals and --out are required')
        result=run_pipeline(args)
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
