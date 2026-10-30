#!/usr/bin/env python3
"""Run ARM user/SVC SysRead capture in QEMU and export/compare native replay."""
import argparse
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
from syscall_checkpoint import identity, load, keys, validate_entry, setup, publish
from read_observations import context_hash, backend_calls, decode
from klee_liteos import ROOT, digest


def run(command, **kwargs):
    return subprocess.run(list(map(str,command)),check=True,capture_output=True,text=True,timeout=60,**kwargs)


def demo(args):
    case=load(args.entry)
    keys(case,('format','entry','calls'),'guest entry')
    if case['format']!='osrec-syscall-session-entry-v1': raise ValueError('unsupported guest entry')
    objects=validate_entry(case['entry'],case['calls'])
    record,kernel,_=identity(args.kernel_root)
    files=[obj for obj in objects.values() if obj['type']=='file']
    fields=objects[case['entry']['roots']['current_process']['object']]['fields']
    if len(files)!=1 or fields['fd3']['object']!=files[0]['id'] or fields['fd4']!=fields['fd3']:
        raise ValueError('QEMU demo requires fd3/fd4 aliasing one file')
    if not args.input.is_file(): raise ValueError('input must be a regular file')
    if args.out.is_relative_to(args.kernel_root): raise ValueError('output cannot modify the pinned kernel checkout')
    if args.out.exists() and any(args.out.iterdir()): raise ValueError('choose an empty output directory')
    context=context_hash(case['entry'],case['calls'],record)
    source_dir=ROOT/'integrations/qemu_arm'
    config=['#define GUEST_CALLS '+str(len(case['calls'])),
            '#define GUEST_BACKEND_READS '+str(len(list(backend_calls(case['entry'],case['calls'],objects)))),
            '#define GUEST_CONTEXT '+json.dumps(context),'static const struct session_call guest_calls[] = {']
    for call in case['calls']:
        ref=call['buffer']; config.append(f"{{{call['fd']},{call['count']},{{UINT64_C({ref['object']}),UINT64_C({ref['offset']})}}}},")
    config.append('};')
    loader='\n'.join(setup(case['entry'],objects)).replace('return 1;','unexpected_exception();')
    loader=loader.replace('struct session_process *process =','struct session_process *guest_process =').replace('process->memory_size','guest_process->memory_size')
    config.append('#define GUEST_SETUP '+loader.replace('\n',' \\\n'))
    with tempfile.TemporaryDirectory(prefix='osrec-qemu-') as temporary:
        stage=Path(temporary); sources=stage/'sources'; sources.mkdir()
        (sources/'osrec').mkdir()
        for name in ['checkpoint.h','recorder.h','io_capture.h']:
            shutil.copy2(ROOT/'include/osrec'/name,sources/'osrec'/name)
        for name in ['checkpoint.c','recorder.c','io_capture.c']:
            shutil.copy2(ROOT/'runtime'/name,sources/name)
        shutil.copy2(ROOT/'integrations/liteos_a/syscall_checkpoint.h',sources/'syscall_checkpoint.h')
        for path in source_dir.iterdir():
            if path.is_file(): shutil.copy2(path,sources/path.name)
        (sources/'guest_config.h').write_text('\n'.join(config)+'\n')
        (sources/'kernel_sysread.c').write_text(kernel)
        image=stage/'guest.elf'
        command=[args.clang,'--target=arm-none-eabi','-mcpu=cortex-a7','-marm','-mfloat-abi=soft',
                 '-std=c11','-O1','-g','-ffreestanding','-fno-builtin','-fno-stack-protector',
                 '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror',
                 '-nostdlib','-fuse-ld=lld','-I',sources,'-Wl,-T,'+str(sources/'guest.ld'),
                 *[sources/name for name in ['start.S','guest.c','kernel_sysread.c','checkpoint.c','recorder.c','io_capture.c']],
                 '-o',image]
        run(command)
        args.out.mkdir(parents=True,exist_ok=True)
        shutil.copy2(image,args.out/'guest.elf'); shutil.copytree(sources,args.out/'guest.sources')
        # Only this temporary fixture is exposed to the fixed-path semihost guest.
        shutil.copyfile(args.input,stage/'input.bin')
        qemu_command=[args.qemu,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a7',
                      '-accel','tcg','-smp','1','-m','64M','-display','none','-monitor','none','-serial','none',
                      '-semihosting-config','enable=on,target=native','-kernel',image]
        guest=run(qemu_command,cwd=stage)
        if 'QEMU capture verified:' not in guest.stdout+guest.stderr: raise ValueError('guest did not report successful completion')
        raw=(stage/'reads.osrec').read_bytes()
        decode(raw,context,case['entry'],case['calls'],objects)
        observed=(stage/'observations.bin').read_bytes()
        if len(observed)!=32*len(case['calls']): raise ValueError('incomplete guest observations')
        args.out.mkdir(parents=True,exist_ok=True)
        capture=args.out/'capture.json'; binary=args.out/'replay'
        publish(args.out/'reads.osrec',raw); publish(args.out/'entry.json',json.dumps(case,indent=2).encode()+b'\n')
        publish(args.out/'guest-observations.bin',observed)
        publish(args.out/'qemu.log',(guest.stdout+guest.stderr).encode())
        tool=ROOT/'tools/syscall_checkpoint.py'
        run([sys.executable,tool,'capture','--kernel-root',args.kernel_root,'--compiler',args.compiler,
             '--case',args.out/'entry.json','--reads',args.out/'reads.osrec','--source-kind','qemu','--out',capture])
        document=load(capture)
        for index,expected in enumerate(document['expected']):
            words=struct.unpack_from('<6I',observed,index*32)
            raw_return=words[0] if words[0]<0x80000000 else words[0]-0x100000000
            user_return=words[1] if words[1]<0x80000000 else words[1]-0x100000000
            actual={'raw':raw_return,'return':user_return,'errno':words[2],'recognized':words[3],
                    'kernel_errno':words[4],'file_positions':{str(files[0]['id']):words[5]},
                    'memory':observed[index*32+24:index*32+32].hex()}
            if actual!=expected: raise ValueError(f'guest/native state differs at invocation {index}')
        run([sys.executable,tool,'export','--kernel-root',args.kernel_root,'--compiler',args.compiler,
             '--capture',capture,'--out',binary])
        # Remove the original staged data before running only the copied executable.
        (stage/'input.bin').unlink()
        isolated=stage/'isolated'; isolated.mkdir(); copied=isolated/'replay'; shutil.copy2(binary,copied)
        verification=run([copied],cwd=isolated,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}).stdout.strip()
        report={'format':'osrec-qemu-sysread-demo-v1','status':'verified',
                'scope':'freestanding ARMv7 user/SVC harness with pinned SysRead; not a full OHOS boot',
                'machine':'virt-9.2','cpu':'cortex-a7','acceleration':'tcg','guest_mmu':False,
                'scheduler_irq_execution':False,'read_backend':'QEMU semihosting file',
                'kernel_identity':record,'guest_image_sha256':digest(image.read_bytes()),
                'guest_source_hashes':{str(p.relative_to(sources)):digest(p.read_bytes()) for p in sorted(sources.rglob('*')) if p.is_file()},
                'read_stream_sha256':digest(raw),'guest_observations_sha256':digest(observed),
                'calls':len(case['calls']),'raw_returns':[o['raw'] for o in document['expected']],
                'guest_native_observations_match':True,'isolated_native_replay':verification,
                'qemu_version':run([args.qemu,'--version']).stdout.splitlines()[0],
                'cross_compiler_version':run([args.clang,'--version']).stdout.splitlines()[0],
                'qemu_command':[str(p) for p in qemu_command[:-1]]+['guest.elf']}
        publish(args.out/'report.json',json.dumps(report,indent=2).encode()+b'\n')
    print(json.dumps({'report':str(args.out/'report.json'),'replay':str(binary),
                      'raw_returns':report['raw_returns'],'verification':verification},indent=2))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-root',required=True,type=Path)
    parser.add_argument('--entry',type=Path,default=ROOT/'examples/sysread_session_entry.json')
    parser.add_argument('--input',required=True,type=Path)
    parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--clang',default='/opt/homebrew/opt/llvm@16/bin/clang')
    parser.add_argument('--qemu',default='qemu-system-arm')
    parser.add_argument('--compiler',default='cc')
    args=parser.parse_args()
    for field in ['kernel_root','entry','input','out']: setattr(args,field,getattr(args,field).resolve())
    try: demo(args)
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        if isinstance(error,subprocess.CalledProcessError): print(error.stderr,file=sys.stderr)
        print(f'QEMU demo failed: {error}',file=sys.stderr); return 1
    return 0
if __name__=='__main__': sys.exit(main())
