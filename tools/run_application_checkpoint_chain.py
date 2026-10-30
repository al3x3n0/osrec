#!/usr/bin/env python3
"""Import a user ELF or resume a joint checkpoint through fresh QEMU images."""
import argparse
import json
import shutil
from pathlib import Path
from application_checkpoint_chain import checked_ordinals,run_stages,publish_report,verify_chain
from application_pause import verify_joint
from import_application_checkpoint import import_checkpoint,plan,digest,verify_package


def run_pipeline(args):
    out=args.out.resolve();library=args.slices.resolve()
    if out.exists():raise FileExistsError(out)
    if out.is_relative_to(library):raise ValueError('chain output overlaps kernel package')
    parent=(library/'manifest.json').read_bytes();kernel=json.loads(parent);total=kernel['target_observations']['call_count']
    if not kernel.get('checkpoint_codec'):raise ValueError('checkpoint-capable kernel required')
    resume=getattr(args,'resume_checkpoint',None);elf=getattr(args,'elf',None);checkpoint=getattr(args,'checkpoint',None)
    points=getattr(args,'pause_ordinals',None) or [];start=0
    if resume:
        if elf or checkpoint:raise ValueError('choose an ELF/checkpoint or an existing joint checkpoint')
        if getattr(args,'ram',None) or getattr(args,'reserved',None):raise ValueError('resumed memory is supplied by the joint checkpoint')
        resume=resume.resolve()
        if out.is_relative_to(resume):raise ValueError('chain output overlaps input checkpoint')
        joint=verify_joint(resume,kernel);start=joint['pause_ordinal']
        route=verify_package(resume/'application')
        checked_ordinals(points,total,start,allow_empty=True)
        if points and len(route.get('completed_sites',[]))!=start:raise ValueError('checkpoint chaining requires complete syscall PC history')
    else:
        if not elf or not checkpoint:raise ValueError('supply both application ELF and neutral checkpoint metadata')
        elf=elf.resolve();checkpoint=checkpoint.resolve()
        raw=elf.read_bytes();metadata=checkpoint.read_bytes()
        ram=getattr(args,'ram',None) or [(0x40000000,64*1024*1024)]
        reserved=[(0x43f00000,65536),*(getattr(args,'reserved',None) or [])]
        # Validate the supplied checkpoint before creating outputs or executing target code.
        imported=plan(raw,json.loads(metadata),ram,reserved)
        if len(imported['sites'])!=total or imported['sites'][0]['ordinal']!=0:raise ValueError('application route count/ordinal differs from kernel sequence; nonzero ordinals require joint kernel state')
        checked_ordinals(points,total)
    out.mkdir(parents=True)
    if resume:
        shutil.copytree(resume,out/'initial-checkpoint')
        verify_joint(out/'initial-checkpoint',kernel)
        shutil.copytree(out/'initial-checkpoint/application',out/'routes')
        initial_identity=digest((out/'initial-checkpoint/manifest.json').read_bytes())
        files=['initial-checkpoint/manifest.json','routes/route-plan.json']
    else:
        inputs=out/'inputs';inputs.mkdir();(inputs/'application.elf').write_bytes(raw);(inputs/'checkpoint.json').write_bytes(metadata)
        import_checkpoint(inputs/'application.elf',inputs/'checkpoint.json',out/'routes',ram=ram,reserved=reserved)
        initial_identity=None;files=['inputs/application.elf','inputs/checkpoint.json','routes/route-plan.json']
    rows=run_stages(args,out,library,parent,kernel,points,out/'initial-checkpoint' if resume else None)
    report=dict(format='osrec-application-joint-checkpoint-chain-v1',status='verified',input_mode='joint-checkpoint' if resume else 'elf',first_ordinal=start,initial_checkpoint_manifest_sha256=initial_identity,pause_ordinals=points,total_calls=total,logical_calls=total-start,stages=rows,kernel_manifest_sha256=digest(parent),construction_sha256=digest(Path(__file__).read_bytes()),runtime_host_interaction=False)
    return publish_report(out,report,files)


def ordinals(text):
    try:return [int(p,0) for p in text.split(',')]
    except ValueError:raise argparse.ArgumentTypeError('supply comma-separated absolute pause ordinals') from None


def main():
    from import_application_checkpoint import memory_range
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slices',type=Path);parser.add_argument('--out',type=Path);parser.add_argument('--verify',type=Path)
    inputs=parser.add_mutually_exclusive_group();inputs.add_argument('--elf',type=Path);inputs.add_argument('--resume-checkpoint',type=Path)
    parser.add_argument('--checkpoint',type=Path);parser.add_argument('--pause-ordinals',type=ordinals)
    parser.add_argument('--ram',type=memory_range,action='append');parser.add_argument('--reserved',type=memory_range,action='append')
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));parser.add_argument('--qemu',default='qemu-system-aarch64')
    args=parser.parse_args()
    if args.verify:result=verify_chain(args.verify)
    else:
        if not args.slices or not args.out or not (args.resume_checkpoint or (args.elf and args.checkpoint and args.pause_ordinals)):
            parser.error('supply --slices, --out and either --elf/--checkpoint/--pause-ordinals or --resume-checkpoint')
        if args.resume_checkpoint and (args.checkpoint or args.ram or args.reserved):parser.error('resumed memory is supplied by the joint checkpoint')
        result=run_pipeline(args)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
