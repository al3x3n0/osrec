#!/usr/bin/env python3
"""Capture a minimal process/credential/umask profile under a real ARM64 Linux.

Boots a supplied ARM64 Image with a generated readonly root disk, or with
`--root initramfs` a generated initramfs (ramfs rootfs), and a libc-free PID-1
init. No host Docker daemon, root mount, download or semihosting is needed.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
import re
import subprocess
from pathlib import Path
from compile_c_application import wrappers
from minimal_ext2 import root_disk
from minimal_initramfs import initramfs

ROOT=Path(__file__).resolve().parents[1]
INTEGRATION=ROOT/'integrations/linux_aarch64'
PROFILES=('minimal','credentials','fsgid','group-setters','getgroups','setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters','fd-dup','file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit')
BASE_CONFIG=('ARM64','BINFMT_ELF','EXT4_FS','VIRTIO_BLK','SERIAL_AMBA_PL011_CONSOLE','MULTIUSER')
# Initramfs boots need no block device or ext4; rootfs is ramfs without tmpfs.
INITRAMFS_BASE_CONFIG=('ARM64','BINFMT_ELF','BLK_DEV_INITRD','SERIAL_AMBA_PL011_CONSOLE','MULTIUSER')
ROOTS=('disk','initramfs')
GENERATED_PROFILES=frozenset(('fsuid','setresuid','uid-setters','credential-setters','fd-dup','file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'))

def profile_integration(profile):
    if profile not in PROFILES:raise ValueError('unsupported Linux profile')
    return INTEGRATION if profile=='minimal' else INTEGRATION/profile

def required_config(profile,root='disk'):
    """Native-constructor prerequisites inferred from the reviewed route set."""
    if root not in ROOTS:raise ValueError('unsupported capture root')
    port=json.loads((profile_integration(profile)/'port-template.json').read_text())
    routes={r['number'] for r in port['roots']}
    symbols=list(BASE_CONFIG if root=='disk' else INITRAMFS_BASE_CONFIG)
    # Group-copy and memory-file witnesses protect a following 4 KiB page.
    if routes & {158,159,63,64}:symbols.append('ARM64_4K_PAGES')
    # Without SHMEM, memfd files are tiny-shmem files backed by ramfs operations.
    if routes & {63,64}:symbols.extend(('MEMFD_CREATE','SHMEM') if root=='disk' else ('MEMFD_CREATE',))
    return tuple(symbols)

def missing_config(config,symbols):
    settings={}
    for line in config.decode('utf-8').splitlines():
        match=re.fullmatch(r'CONFIG_([A-Z0-9_]+)=(.*)',line)
        if match:settings.setdefault(match[1],[]).append(match[2])
        unset=re.fullmatch(r'# CONFIG_([A-Z0-9_]+) is not set',line)
        if unset:settings.setdefault(unset[1],[]).append('n')
    return [symbol for symbol in symbols if settings.get(symbol)!=['y']]

def validate_profile_config(profile,config,root='disk'):
    missing=missing_config(config,required_config(profile,root))
    if missing:raise ValueError('capture profile '+profile+' requires unique builtin settings: '+', '.join('CONFIG_'+s for s in missing))

def reviewed_adapter():
    spec=importlib.util.spec_from_file_location('osrec_linux_review',INTEGRATION/'prepare.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def digest(raw):return hashlib.sha256(raw).hexdigest()

def native_argument_header(port):
    """Bind native buffer normalization to the same ABI as the C witness."""
    text='/* Generated from the reviewed port argument kinds. Capture only. */\n'
    text+='static unsigned osrec_native_buffer_object(uint64_t syscall,unsigned argument)\n{\n    switch(syscall){\n'
    for route in port['roots']:
        # An iovec array is in the witness buffer too (its segment bases are offsets again when recorded).
        buffers=[j for j,kind in enumerate(route['arguments']) if kind in ('buffer','iovec')]
        if not buffers:continue
        text+='    case UINT64_C('+str(route['number'])+'):\n'
        for j in buffers:
            object_id=2 if route['function']=='linux_newfstat' and j==1 else 1
            text+='        if(argument=='+str(j)+')return '+str(object_id)+';\n'
        text+='        return 0;\n'
    return text+'    default:return 0;\n    }\n}\n'

def kernel_identity(image,config=None,root='disk'):
    raw=Path(image).read_bytes()
    if len(raw)<64 or raw[56:60]!=b'ARM\x64':raise ValueError('supply an uncompressed ARM64 Linux Image')
    banners=re.findall(rb'Linux version ([^ \x00\n]+)',raw)
    if not banners or len(set(banners))!=1:raise ValueError('kernel release is missing or ambiguous')
    release=banners[0].decode('ascii')
    if config is None:
        start=raw.find(b'IKCFG_ST');end=raw.find(b'IKCFG_ED',start+8)
        if start<0 or end<start:raise ValueError('kernel has no embedded configuration; supply --config')
        config=gzip.decompress(raw[start+8:end])
    else:config=Path(config).read_bytes()
    text=config.decode('utf-8')
    missing=missing_config(config,BASE_CONFIG if root=='disk' else INITRAMFS_BASE_CONFIG)
    if missing:raise ValueError('capture requires builtin '+', '.join('CONFIG_'+s for s in missing))
    if not re.search(r'^# Linux/arm64 '+re.escape(release.split('-')[0])+r' Kernel Configuration$',text,re.M):raise ValueError('kernel configuration release differs from Image')
    return dict(kernel_release=release,kernel_image_sha256=digest(raw),kernel_config_sha256=digest(config),architecture='aarch64'),config

def capture(args):
    out=Path(args.out).resolve()
    if out.exists():raise FileExistsError(out)
    root=getattr(args,'root','disk')
    identity,config=kernel_identity(args.kernel_image,getattr(args,'config',None),root)
    profile=getattr(args,'profile','minimal');integration=profile_integration(profile)
    validate_profile_config(profile,config,root)
    review=reviewed_adapter();review_identity,_=review.source_identity(integration)
    if profile in GENERATED_PROFILES and (integration/'application.c').read_text()!=review.application_source(profile,json.loads((integration/'port-template.json').read_text())):raise ValueError('Linux generated witness differs from reviewed recipe')
    producer_hashes={n:digest((ROOT/'tools'/n).read_bytes()) for n in ('capture_linux_aarch64.py','minimal_ext2.py' if root=='disk' else 'minimal_initramfs.py','compile_c_application.py')}
    out.mkdir(parents=True);stage=out/'sources';stage.mkdir()
    import shutil
    # The capture records the profile's excerpts by manifest (prepare.py's excerpt store), materialized on use.
    review.copy_excerpts(integration,out)
    (out/'source-identity.json').write_bytes((integration/'source-identity.json').read_bytes())
    port=json.loads((integration/'port-template.json').read_text())
    (stage/'linux-native-arguments.h').write_text(native_argument_header(port))
    header,assembly=wrappers(port,('default','prefix'))
    (stage/'osrec_application.h').write_text(header)
    (stage/'syscall.S').write_text(assembly)
    for name in ('application.c','native.c','native-start.S'):(stage/name).write_bytes(((integration if name=='application.c' else INTEGRATION)/name).read_bytes())
    elf=out/'init'
    command=[str(args.llvm_bin/'clang'),'--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only','-mstrict-align','-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-DOSREC_NATIVE_CAPTURE','-Wall','-Wextra','-Werror','-I'+str(stage),'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-e,_start','-Wl,-z,max-page-size=4096',*[str(stage/name) for name in ('native-start.S','syscall.S','native.c','application.c')],'-o',str(elf)]
    if profile in ('credentials','fsgid','group-setters','getgroups','setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):command.insert(1,'-DOSREC_LINUX_CREDENTIAL_PROFILE')
    if profile=='fsgid':command.insert(1,'-DOSREC_LINUX_FSGID_PROFILE')
    if profile=='group-setters':command.insert(1,'-DOSREC_LINUX_GROUP_SETTERS_PROFILE')
    if profile in ('getgroups','setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):command.insert(1,'-DOSREC_LINUX_GETGROUPS_PROFILE')
    if profile in ('setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):command.insert(1,'-DOSREC_LINUX_SETGROUPS_PROFILE')
    if profile in ('capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):command.insert(1,'-DOSREC_LINUX_CAPABILITIES_PROFILE')
    if profile in ('prctl','fsuid','setresuid','uid-setters','credential-setters'):command.insert(1,'-DOSREC_LINUX_PRCTL_PROFILE')
    if profile in ('fsuid','setresuid','uid-setters','credential-setters'):command.insert(1,'-DOSREC_LINUX_FSUID_PROFILE')
    if profile in ('setresuid','uid-setters','credential-setters'):command.insert(1,'-DOSREC_LINUX_SETRESUID_PROFILE')
    if profile in ('uid-setters','credential-setters'):command.insert(1,'-DOSREC_LINUX_UID_SETTERS_PROFILE')
    if profile=='file-setrlimit':command.insert(1,'-DOSREC_LINUX_FILE_SETRLIMIT_PROFILE')
    if profile in ('file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FILE_LIMITS_PROFILE')
    if profile in ('file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FILE_RLIMIT_PROFILE')
    if profile in ('file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FILE_CREDENTIALS_PROFILE')
    if profile in ('file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FILE_PRCTL_PROFILE')
    if profile in ('file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FILE_CAPGET_PROFILE')
    if profile in ('file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FILE_STATUS_PROFILE')
    if profile in ('file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FILE_GROUP_SETTERS_PROFILE')
    if profile in ('file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FILE_GROUPS_PROFILE')
    if profile in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FILE_FSUID_PROFILE')
    if profile in ('file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FILE_FSGID_PROFILE')
    if profile in ('file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FILE_CAPABILITIES_PROFILE')
    if profile in ('fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FCHOWN_CAPABLE_PROFILE')
    if profile in ('fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FCHOWN_PROFILE')
    if profile in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FCHMOD_PROFILE')
    if profile in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FSTAT_PROFILE')
    if profile in ('close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_CLOSE_RANGE_PROFILE')
    if profile in ('fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FD_CONTROL_PROFILE')
    if profile in ('file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FILE_POSITIONED_PROFILE')
    if profile in ('file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):command.insert(1,'-DOSREC_LINUX_FILE_IO_PROFILE');command.insert(1,'-DOSREC_LINUX_FD_DUP_PROFILE')
    if profile=='fd-dup':command.insert(1,'-DOSREC_LINUX_FD_DUP_PROFILE')
    if root=='initramfs':command.insert(1,'-DOSREC_LINUX_RAMFS_ROOT')
    if profile=='credential-setters':command.insert(1,'-DOSREC_LINUX_CREDENTIAL_SETTERS_PROFILE')
    if profile=='capget':command.insert(1,'-DOSREC_LINUX_CAPGET_PROFILE')
    if profile=='setgroups-denied':
        command.insert(1,'-DOSREC_LINUX_SETGROUPS_DENIED_PROFILE')
    if profile in ('setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        shutil.copyfile(review.upstream(integration)/'include/uapi/linux/capability.h',stage/'linux-capability.h')
    subprocess.run(command,check=True,capture_output=True,text=True,timeout=60)
    if root=='disk':disk=out/'root.ext2';disk.write_bytes(root_disk(elf.read_bytes()))
    else:disk=out/'root.cpio';disk.write_bytes(initramfs(elf.read_bytes()))
    (out/'kernel.config').write_bytes(config)
    accelerator=getattr(args,'accel','tcg')
    qemu=[args.qemu,'-machine','virt','-cpu','host' if accelerator=='hvf' else 'cortex-a53','-accel',accelerator,'-smp','1','-m','512M','-nographic','-monitor','none','-nic','none','-no-reboot','-kernel',str(Path(args.kernel_image).resolve())]
    if root=='disk':qemu+=['-drive','file='+str(disk)+',format=raw,if=none,id=root,readonly=on','-device','virtio-blk-device,drive=root','-append','console=ttyAMA0 root=/dev/vda rootfstype=ext4 ro rootwait init=/init panic=-1']
    else:qemu+=['-initrd',str(disk),'-append','console=ttyAMA0 rdinit=/init panic=-1']
    timed_out=False
    with (out/'qemu.log').open('wb') as log:
        process=subprocess.Popen(qemu,stdout=log,stderr=subprocess.STDOUT)
        try:process.wait(timeout=getattr(args,'timeout',180))
        except subprocess.TimeoutExpired:timed_out=True
        finally:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
    if timed_out:raise ValueError('native Linux capture timed out; see '+str(out/'qemu.log'))
    raw=(out/'qemu.log').read_bytes()
    text=raw.decode('utf-8','replace');matches=re.findall(r'^OSREC_LINUX_CAPTURE (\{[^\r\n]+\})\r?$',text,re.M)
    if process.returncode or len(matches)!=1 or 'OSREC_LINUX_CAPTURE_DONE' not in text:raise ValueError('native Linux capture did not complete; see '+str(out/'qemu.log'))
    observed=json.loads(matches[0]);observed['format']='osrec-linux-aarch64-capture-v1'
    if review.profile_for(observed)!=profile:raise ValueError('native Linux capture profile differs from selection')
    (out/'capture.json').write_text(json.dumps(observed,indent=2)+'\n')
    observation='syscall-observed projection; umask probes restore the observed mask'
    if profile in ('credentials','fsgid','group-setters','getgroups','setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):observation+='; private getresgid and nonmutating setfsgid(-1) probes observe group IDs; pool slots/generations are modeled bookkeeping'
    if profile in ('getgroups','setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):observation+='; private getgroups probes observe supplementary IDs; native caller witness ends at a protected guard page'
    if profile in ('setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):observation+='; input snapshots bind setter data; list reference counts are bounded model bookkeeping'
    if profile=='setgroups-denied':observation+='; native capget probes observe absent effective CAP_SETGID; capget is not a replay root'
    if profile in ('capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):observation+='; private capget and prctl probes observe effective/permitted/inheritable/bounding/ambient sets; all pool lifetimes are model bookkeeping'
    if profile=='prctl':observation+='; private PR_GET_SECUREBITS observes securebits; replay routes only reviewed commoncap prctl options'
    if profile in ('fsuid','setresuid','uid-setters','credential-setters'):observation+='; private setfsuid(-1) observes the filesystem user ID; original commoncap fixup changes filesystem effective bits unless suppressed by securebits'
    if profile in ('setresuid','uid-setters','credential-setters'):observation+='; private getresuid observes all user IDs after each call; native NPROC limit explicitly unlimited and checked by getrlimit; user/accounting links and ownership counts are bounded model bookkeeping'
    if profile=='fd-dup':observation+='; private F_GETFD/F_GETFL observe slots and flags; checked NOFILE limit 8; OFD identities/reference counts inferred by the reviewed construction and duplication contract'
    if profile in ('file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):observation+='; private seal/flag probes identify the memfd class; pread observes bounded file bytes, lseek(0,CUR) observes shared offset; closed-object snapshots are model bookkeeping; native caller has a protected guard page'
    if profile in ('file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):observation+='; positioned transfers and truncations observed with unchanged shared offsets; inode graph and superblock balance are model bookkeeping'
    if profile in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):observation+='; entry stat metadata and per-call blocks are native observations; the application discards successful stat timestamps before comparison, and a separate 128-byte guarded object records all other output bytes'
    if profile in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):observation+='; private fchown assigns the memfd to effective UID 1002 before credential drop; per-call fstat observes live mode; the initial ownership transfer belongs to capture construction'
    if profile in ('fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):observation+='; native ownership replay records UID/GID after every call; private setgroups seeds group zero, then getgroups and capget bind authorization inputs; runtime fchown is a replay root'
    if profile=='fchown-capable':observation+='; private capset grants effective CAP_CHOWN only; CAP_FOWNER remains absent; permitted CAP_SYS_BOOT is reserved for teardown'
    if profile in ('file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):observation+='; live capset controls ownership and chmod; private capget observes effective/permitted/inheritable sets after every call; initial prctl observes bounding and ambient; publication generations and inactive slots are model bookkeeping'
    if profile in ('file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):observation+='; private invalid-ID setfsgid(-1) probes observe live filesystem group after every call; original application setfsgid is a replay route'
    if profile in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):observation+='; private setfsuid(-1) probes observe live filesystem user after every call; PR_GET_SECUREBITS observes entry fixup policy; original setfsuid/commoncap fixup are replay paths'
    if profile in ('file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):observation+='; private getgroups observes live supplementary membership after every call; setgroups/getgroups and original list/copy helpers are replay paths; caller list capacity four; initial SETGID permitted but not effective'
    if profile in ('file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):observation+='; private getresgid observes real/effective/saved groups after every call; original scalar GID setters are replay paths'
    if profile in ('file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):observation+='; private F_GETFL observes live shared status flags per descriptor; F_SETFL and append callbacks are explicit reviewed models'
    if profile in ('file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):observation+='; temporary permitted SETPCAP at entry; private prctl observes bounding, ambient and securebits after every call; original commoncap prctl hook is the replay route, general sys_prctl excluded'
    if profile in ('file-credentials','file-rlimit','file-limits','file-setrlimit'):observation+='; private getresuid observes live user IDs; unlimited NPROC set and observed; bounded user/accounting links and lifetimes are model bookkeeping'
    if profile in ('file-rlimit','file-limits','file-setrlimit'):observation+='; private getrlimit observes retained pairs after every call; file-limits additionally observes all 16 resource pairs; original application queries use retained entry state'
    manifest=dict(format='osrec-linux-aarch64-capture-manifest-v1',identity=identity,reviewed_source_identity=review_identity,capture_sha256=digest((out/'capture.json').read_bytes()),init_sha256=digest(elf.read_bytes()),root_disk_sha256=digest(disk.read_bytes()),root_kind=root,root_file=disk.name,qemu_log_sha256=digest(raw),capture_construction_sha256=producer_hashes,root_builder_sha256=producer_hashes['minimal_ext2.py' if root=='disk' else 'minimal_initramfs.py'],source_sha256={str(p.relative_to(stage)):digest(p.read_bytes()) for p in stage.iterdir() if p.is_file()},qemu_command=qemu,qemu_exit_status=process.returncode,native_linux_boot=True,semihosting=False,state_observation=observation)
    (out/'capture.manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    review.validate_capture(out)
    print(json.dumps(dict(status='captured',kernel_release=identity['kernel_release'],calls=len(observed['calls']),out=str(out)),indent=2))
    return manifest

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-image',type=Path,required=True);parser.add_argument('--config',type=Path);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--profile',choices=PROFILES,default='minimal')
    parser.add_argument('--root',choices=ROOTS,default='disk',help='disk: readonly ext2 on virtio; initramfs: ramfs rootfs, no block device')
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));parser.add_argument('--qemu',default='qemu-system-aarch64');parser.add_argument('--timeout',type=int,default=300);parser.add_argument('--accel',choices=('tcg','hvf'),default='tcg')
    capture(parser.parse_args())

if __name__=='__main__':main()
