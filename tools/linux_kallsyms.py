#!/usr/bin/env python3
"""Dump a Linux kernel image's symbol table by booting it with a PID 1 that prints /proc/kallsyms.

The guest (examples/linux-vm-checkpoint/init-kallsyms.c) opens kallsyms on a
detached proc mount (fsopen/fsconfig/fsmount), so the root disk needs no /proc.
Without KASLR (CONFIG_RANDOMIZE_BASE unset) the addresses are those of every
boot of the same image. Symbols attribute traced instructions to functions; the
capture and replay themselves never use them.
"""
import argparse,bisect,hashlib,re,subprocess,tempfile
from pathlib import Path
from minimal_ext2 import root_disk

ROOT=Path(__file__).resolve().parents[1]
SYMBOL=re.compile(r'([0-9a-f]{16}) ([tTwW]) (\S+)(?:\s+\[\w+\])?')

def dump(kernel,out,llvm_bin,qemu,timeout=1800):
    with tempfile.TemporaryDirectory() as name:
        stage=Path(name)
        subprocess.run([str(llvm_bin/'clang'),'--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align','-std=c11','-O1','-ffreestanding','-fno-builtin',
            '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined',
            '-Wl,-e,_start','-Wl,-z,max-page-size=4096',str(ROOT/'integrations/linux_aarch64/native-start.S'),str(ROOT/'examples/linux-vm-checkpoint/init-kallsyms.c'),'-o',str(stage/'init')],
            check=True,capture_output=True,text=True,timeout=120)
        (stage/'root.ext2').write_bytes(root_disk((stage/'init').read_bytes()))
        subprocess.run([qemu,'-machine','virt-9.2','-cpu','cortex-a53','-accel','tcg','-smp','1','-m','512M','-nodefaults','-display','none','-monitor','none','-no-reboot',
            '-kernel',str(kernel),'-drive','file=%s,format=raw,if=none,id=root,readonly=on'%(stage/'root.ext2'),'-device','virtio-blk-device,drive=root',
            '-append','console=ttyAMA0 root=/dev/vda rootfstype=ext4 ro rootwait init=/init panic=-1','-serial','file:%s'%(stage/'console.txt')],check=True,timeout=timeout)
        text=(stage/'console.txt').read_text(errors='replace')
    begin,end=text.find('KALLSYMS_BEGIN\n'),text.find('KALLSYMS_END')
    if begin<0 or end<0:raise ValueError('guest did not print kallsyms: '+text[-300:])
    body=text[begin+len('KALLSYMS_BEGIN\n'):end]
    if not re.search(r' [tT] el0_svc$',body,re.M):raise ValueError('kallsyms has no text addresses (kptr_restrict?)')
    Path(out).write_text('# kernel sha256 %s\n'%hashlib.sha256(Path(kernel).read_bytes()).hexdigest()+body)
    return out

class Symbols:
    """Text symbols of a kallsyms dump; an address maps to the symbol at or below it."""
    def __init__(self,path):
        rows=sorted((int(m.group(1),16),m.group(3)) for m in map(SYMBOL.fullmatch,Path(path).read_text().splitlines()) if m)
        self.addresses=[a for a,_ in rows];self.names=[n for _,n in rows]
    def __call__(self,pc):
        i=bisect.bisect_right(self.addresses,pc)-1;return self.names[i] if i>=0 else '?'

def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--kernel',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));p.add_argument('--qemu',default='qemu-system-aarch64');a=p.parse_args()
    dump(a.kernel,a.out,a.llvm_bin,a.qemu);print(a.out)

if __name__=='__main__':main()
