#!/usr/bin/env python3
"""Validate the generic QMP checkpoint transport with unmodified Linux SVC calls."""
import argparse,json,shutil,subprocess
from pathlib import Path
from capture_linux_aarch64 import kernel_identity,validate_profile_config
from minimal_ext2 import root_disk
from qemu_vm_checkpoint import capture,sha,write
ROOT=Path(__file__).resolve().parents[1]
def build(kernel,out,llvm_bin,qemu,timeout=120,workload=None,success_suffix='',pin_user_pages=False):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False);sources=out/'sources';sources.mkdir()
    identity,config=kernel_identity(kernel);validate_profile_config('file-io',config)
    shutil.copyfile(workload or ROOT/'examples/linux-vm-checkpoint/init.c',sources/'init.c');shutil.copyfile(ROOT/'integrations/linux_aarch64/native-start.S',sources/'start.S')
    command=[str(llvm_bin/'clang'),'--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align','-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-e,_start','-Wl,-z,max-page-size=4096',str(sources/'start.S'),str(sources/'init.c'),'-o',str(out/'init')]
    if pin_user_pages:
        command.append('-DOSREC_PIN_USER_PAGES')
    subprocess.run(command,check=True,capture_output=True,text=True,timeout=60)
    (out/'root.ext2').write_bytes(root_disk((out/'init').read_bytes()));(out/'kernel.config').write_bytes(config)
    carry=0x1234
    for b in b'cde':carry=(carry*33+b)&((1<<64)-1)
    final=b'abcde'+bytes([ord('X')+(carry&1),ord('0')+carry%10])+b'h'
    for b in final:carry=(carry*33+b)&((1<<64)-1)
    expected='OSREC_VM_PASS checksum='+format(carry,'016x')+' bytes='+final.hex()+' offset=8 closed=-9'+success_suffix
    recipe=dict(format='osrec-qemu-machine-checkpoint-v1',qemu=qemu,external_state='immutable-boot-assets-only',
        arguments=['-machine','virt-9.2','-cpu','cortex-a53','-accel','tcg','-smp','1','-m','512M','-nodefaults','-display','none','-monitor','none','-no-reboot','-kernel','{kernel}',
            '-drive','file={root},format=raw,if=none,id=root,readonly=on','-device','virtio-blk-device,drive=root','-append','console=ttyAMA0 root=/dev/vda rootfstype=ext4 ro rootwait init=/init panic=-1'],
        files=dict(kernel=dict(path=str(Path(kernel).resolve()),sha256=sha(kernel)),root=dict(path=str(out/'root.ext2'),sha256=sha(out/'root.ext2'))),
        protocol=dict(ready_prefix='OSREC_VM_READY ',success_prefix='OSREC_VM_PASS ',failure_prefix='OSREC_VM_FAIL ',continue_line='go\n',expected_success=expected,reject_on_resume=['OSREC_VM_BOOT','OSREC_VM_READY']))
    if pin_user_pages:
        recipe['guest_memory_preparation'] = 'mlockall(MCL_CURRENT | MCL_FUTURE)'
    write(out/'recipe.json',recipe);write(out/'kernel-identity.json',identity)
    result=capture(out/'recipe.json',out/'checkpoint',timeout);result['native_linux_identity']=identity;result['native_source_build_attested']=False;result['syscalls']='direct unmodified AArch64 svc #0: memfd_create, dup, prlimit64, read, write, lseek, close, uname and reboot' if workload is None else 'direct unmodified AArch64 svc #0, as listed in sources/init.c'
    if pin_user_pages:
        result['guest_memory_preparation'] = recipe['guest_memory_preparation']
    write(out/'report.json',result);return result
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kernel-image',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));p.add_argument('--qemu',default='qemu-system-aarch64');p.add_argument('--timeout',type=int,default=120)
    p.add_argument('--workload',type=Path,help='init.c variant (same file sequence and PASS line, plus SUCCESS_SUFFIX)');p.add_argument('--success-suffix',default='')
    p.add_argument('--pin-user-pages',action='store_true',help='populate and lock current and future workload mappings with guest mlockall before capture')
    a=p.parse_args()
    r=build(a.kernel_image,a.out,a.llvm_bin,a.qemu,a.timeout,a.workload,a.success_suffix,a.pin_user_pages);print(json.dumps(dict(status=r['status'],ready=r['ready'],baseline=r['baseline_result'],resumes=len(r['resumes']),checkpoint_bytes=r['vmstate_bytes']),indent=2))
