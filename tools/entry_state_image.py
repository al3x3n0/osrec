"""Shared construction and verification of reviewed AArch64 entry-state ports."""
from pathlib import Path
from freestanding_elf import prepare_target
from freestanding_armv7 import run,audit
from run_freestanding_armv7 import observe,require_success
from entry_state_result import MAX_CALLS,LEGACY_CALLS,HEADER_BYTES,RECORD_BYTES


def build_and_verify(args,sources,calls,continuous,write_effects,basename='entry-state',translation_units=()):
    if args.arch!='aarch64':raise ValueError('entry-state images currently require AArch64')
    if not 1<=len(calls)<=MAX_CALLS:raise ValueError('entry-state result supports 1 through '+str(MAX_CALLS)+' calls')
    sources=Path(sources);flags=prepare_target(args,sources)
    if len(calls)>LEGACY_CALLS:
        linker=sources/'image.ld';text=linker.read_text()
        text=text.replace('SIZEOF(.result) == 128','SIZEOF(.result) == '+str(HEADER_BYTES+RECORD_BYTES*len(calls)))
        linker.write_text(text.replace('result ABI must be 128 bytes','result ABI must match transcript extent'))
    image=sources.parent/(basename+'.elf');binary=sources.parent/(basename+'.bin')
    run([args.llvm_bin/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
        '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static',
        '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),
        sources/'start.S',sources/'entry_state_replay.c',*[sources/name for name in translation_units],'-o',image])
    inspection=audit(image,args.llvm_bin);run([args.llvm_bin/'llvm-objcopy','-O','binary',image,binary])
    observed,raw=observe(image,args.qemu);require_success(observed)
    other,binary_raw=observe(binary,args.qemu,descriptor=image);require_success(other)
    expected=[{k:c[k] for k in ('number','raw_bits')} for c in calls]
    if raw!=binary_raw or observed['actual_calls']!=expected:raise ValueError('entry-state ELF/raw replay differs')
    counters=(len(calls),1 if continuous else len(calls),len(calls),len(calls) if continuous else 0)
    if tuple(observed[k] for k in ('completed_calls','states_restored','states_verified','entry_states_checked'))!=counters:
        raise ValueError('entry-state replay verification counters differ')
    if observed['continuous_replay']!=continuous or bool(observed['write_effects'])!=write_effects:
        raise ValueError('entry-state replay mode differs')
    return inspection,observed,raw,image,binary
