#!/usr/bin/env python3
"""Recover configured LiteOS compile commands using a syscall-module make dry run."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
from klee_liteos import ROOT

def make_configuration(tree,llvm_bin):
    kernel=tree/'kernel/liteos_a'
    return ['HIDE=','LITEOSTOPDIR='+str(kernel),'PRODUCT_PATH='+str(tree/'vendor/ohemu/qemu_small_system_demo'),
        'DEVICE_PATH='+str(tree/'device/qemu/arm_virt/liteos_a'),
        'LITEOS_COMPILER_PATH='+str(llvm_bin)+'/', 'CROSS_COMPILE=llvm-',
        'SYSROOT_PATH='+str(tree/'sysroot'),'OUTDIR='+str(tree/'out'),
        'OSREC_ARM_BUILTINS='+str(tree.parent/'liteos-arm-builtins/lib/generic/libclang_rt.builtins-arm.a')]


def compile_record(tree,source,llvm_bin,module=None):
    """Recover one configured command without compiling or changing the source."""
    tree=tree.resolve();source=source.resolve();kernel=tree/'kernel/liteos_a'
    if not source.is_file() or not source.is_relative_to(tree):raise ValueError('source must be inside the managed tree')
    relative=source.relative_to(tree)
    target=tree/'out/obj'/relative.with_suffix('.o')
    module=Path(module).resolve() if module is not None else source.parent
    while not (module/'Makefile').is_file() and module!=tree:module=module.parent
    if not (module/'Makefile').is_file():raise ValueError('source has no module Makefile')
    command=['make','-n','-C',module,'-W',source,target,*make_configuration(tree,llvm_bin)]
    result=subprocess.run(list(map(str,command)),capture_output=True,text=True,timeout=60)
    if result.returncode:raise ValueError('compile-command discovery failed: '+result.stderr)
    records=[]
    for line in result.stdout.splitlines():
        if 'clang ' not in line or ' -c ' not in line:continue
        arguments=shlex.split(line)
        operand=Path(arguments[arguments.index('-c')+1])
        if not operand.is_absolute():operand=module/operand
        if operand.resolve()!=source:continue
        records.append({'directory':str(module),'file':str(source),'arguments':arguments})
    if len(records)!=1:raise ValueError('make dry run did not yield exactly one source compilation command')
    return records[0]


def prepare(args):
    kernel=args.tree/'kernel/liteos_a';source=kernel/args.source
    if not source.is_file() or not source.resolve().is_relative_to(kernel.resolve()):raise ValueError('source must be inside the managed kernel')
    records=[compile_record(args.tree,source,args.llvm_bin)]
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(records,indent=2)+'\n')
    print(json.dumps({'compile_commands':str(args.out),'source':str(source)},indent=2))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree',type=Path,default=ROOT/'build/ohos')
    parser.add_argument('--source',type=Path,default=Path('syscall/process_syscall.c'))
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    args.tree=args.tree.resolve();args.out=args.out.resolve();prepare(args)
if __name__=='__main__':main()
