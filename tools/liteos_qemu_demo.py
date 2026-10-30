#!/usr/bin/env python3
"""Build/boot the pinned LiteOS-A kernel and compare live SysRead capture with native replay."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from syscall_checkpoint import identity, load, validate_entry, publish
from read_observations import context_hash, decode
from klee_liteos import ROOT, digest
from live_priority_replay import export_live_priority
from live_pid_replay import export_live_pid
from live_identity_replay import export_live_identity
from live_umask_replay import export_live_umask
from live_task_replay import export_live_task
from live_credentials_replay import export_live_credentials
from live_getpriority_replay import export_live_getpriority

SOURCE=ROOT/'integrations/liteos_qemu'
TREE=ROOT/'build/ohos'

def argument_profile(args):
    if getattr(args,'parent_argument_session',False):return 'parent-exit-signal-session'
    if getattr(args,'argument_write_session',False):return 'exit-signal-session'
    if getattr(args,'argument_write_state',False):return 'exit-signal-write'
    return 'process-group-leader' if getattr(args,'const_argument_entry_state',False) else 'exit-code'


def run(command,**kwargs):
    return subprocess.run(list(map(str,command)),check=True,capture_output=True,text=True,timeout=60,**kwargs)


def write_changed(path,data):
    if not path.exists() or path.read_bytes()!=data:
        path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(data)


def dependencies(fetch):
    lock=load(SOURCE/'dependencies.json')
    for item in lock['repositories']:
        path=(TREE/item['path']).resolve()
        if not path.exists():
            if not fetch: raise ValueError(f"missing dependency {item['path']}; use --fetch")
            path.parent.mkdir(parents=True,exist_ok=True)
            command=['git','clone','--depth','1','--no-checkout']
            if item['path']=='../arm-compiler-rt': command+=['--filter=blob:none','--sparse']
            run([*command,item['repository'],path])
            run(['git','-C',path,'fetch','--depth','1','origin',item['revision']])
            run(['git','-C',path,'checkout','--detach',item['revision']])
            if item['path']=='../arm-compiler-rt':
                run(['git','-C',path,'sparse-checkout','set','compiler-rt','cmake','llvm/cmake'])
        if run(['git','-C',path,'rev-parse','HEAD']).stdout.strip()!=item['revision']:
            raise ValueError(f"dependency revision differs: {item['path']}")
    return lock


def prepare(args,record):
    lock=dependencies(args.fetch)
    for relative,patch in load(SOURCE/'build-files.json').items():
        repo=next((TREE/item['path'] for item in lock['repositories']
                   if relative.startswith(item['path']+'/')),None)
        if repo is None: raise ValueError('build adaptation has no locked repository')
        name=relative[len(str(repo.relative_to(TREE)))+1:]
        original=run(['git','-C',repo,'show','HEAD:'+name]).stdout
        if digest(original.encode())!=patch['before_sha256']: raise ValueError('build adaptation source mismatch')
        target=TREE/relative
        content=patch['content'].replace('@OSREC_INCLUDE@',str(ROOT/'include')).encode()
        # Permit only the reviewed original or our known build adaptation.
        # Existing tree from the initial bring-up has a concrete builtins path.
        current=target.read_text().replace(str(TREE.parent/'arm-builtins/lib/generic/libclang_rt.builtins-arm.a'),'$(OSREC_ARM_BUILTINS)')
        current=current.replace('$(LITEOSTOPDIR)/../../../arm-builtins/lib/generic/libclang_rt.builtins-arm.a','$(OSREC_ARM_BUILTINS)')
        if current not in (original,content.decode()) and digest(current.encode()) not in patch.get('previous_content_sha256',[]): raise ValueError(f'unreviewed changes in {relative}')
        write_changed(target,content)
    kernel=TREE/'kernel/liteos_a';board=TREE/'device/qemu/arm_virt/liteos_a/board'
    kernel_config=(SOURCE/'kernel.config').read_bytes()
    if getattr(args,'async_wait',False):kernel_config=kernel_config.replace(b'# LOSCFG_KERNEL_HOOK is not set',b'LOSCFG_KERNEL_HOOK=y')
    write_changed(kernel/'.config',kernel_config)
    write_changed(kernel/'kernel/user/src/los_user_init.c',(SOURCE/'user_init.c').read_bytes())
    write_changed(board/'live_capture.c',(SOURCE/'live_capture.c').read_bytes())
    write_changed(board/'parent_argument_adapter.h',(SOURCE/'parent_argument_adapter.h').read_bytes())
    write_changed(board/'wait_capture.h',(SOURCE/'wait_capture.h').read_bytes())
    for name in ['recorder.c','io_capture.c']: write_changed(board/('osrec_'+name),(ROOT/'runtime'/name).read_bytes())
    case=load(SOURCE/'entry.json');validate_entry(case['entry'],case['calls'])
    context=context_hash(case['entry'],case['calls'],record)
    payload=args.input.read_bytes() if args.input else b'ABCDE'
    if len(payload)>64: raise ValueError('demo fixture is bounded to 64 bytes')
    config='#define LIVE_CONTEXT '+json.dumps(context)+'\n#define LIVE_PAYLOAD {'+','.join(str(b) for b in payload+b'\0')+'}\n'
    write_changed(board/'live_config.h',config.encode())
    auto_config=b'#define OSREC_AUTOMATED_ENTRY_STATE 1\n' if args.automated_entry_state else b'/* Automated snapshot capture disabled. */\n'
    if getattr(args,'argument_entry_state',False):auto_config+=b'#define OSREC_ARGUMENT_ENTRY 1\n'
    if getattr(args,'const_argument_entry_state',False):auto_config+=b'#define OSREC_CONST_ARGUMENT_ENTRY 1\n'
    if getattr(args,'argument_write_state',False):auto_config+=b'#define OSREC_ARGUMENT_WRITE 1\n'
    if getattr(args,'argument_write_session',False):auto_config+=b'#define OSREC_ARGUMENT_SESSION 1\n'
    if getattr(args,'shared_argument_capture',False):auto_config+=b'#define OSREC_SHARED_ARGUMENT_CAPTURE 1\n'
    if getattr(args,'shared_mixed_capture',False):auto_config+=b'#define OSREC_SHARED_MIXED_CAPTURE 1\n'
    if getattr(args,'shared_session',None):
        auto_config+=('#define OSREC_SHARED_CONFIGURED_CAPTURE 1\n#define OSREC_CAPTURE_CALLS '+str(len(args.shared_session_data['calls']))+'\n').encode()
    if getattr(args,'parent_argument_session',False):auto_config+=b'#define OSREC_PARENT_ARGUMENT_SESSION 1\n'
    if getattr(args,'async_wait',False):auto_config+=b'#define OSREC_ASYNC_WAIT_CAPTURE 1\n'
    if getattr(args,'setgroups_allocation_failures',False):auto_config+=b'#define OSREC_SETGROUPS_FAILURES 1\n'
    if (getattr(args,'setgroups_copy_failures',False) or getattr(args,'setgroups_partial_copy_failures',False)):auto_config+=b'#define OSREC_SETGROUPS_COPY_FAILURES 1\n'
    if getattr(args,'setgroups_partial_copy_failures',False):auto_config+=b'#define OSREC_SETGROUPS_PARTIAL_COPY_FAILURES 1\n'
    if getattr(args,'getresuid',False):auto_config+=b'#define OSREC_GETRESUID_CAPTURE 1\n'
    if getattr(args,'getresgid',False):auto_config+=b'#define OSREC_GETRESGID_CAPTURE 1\n'
    if getattr(args,'getresuid',False) or getattr(args,'getresgid',False):auto_config+=b'#define OSREC_GENERATED_CREDENTIAL_FIELDS 1\n'
    from getresuid_capture import PROFILES
    selected_kind='getresgid' if getattr(args,'getresgid',False) else 'getresuid' if getattr(args,'getresuid',False) else None
    custom_ids=selected_kind is not None and getattr(args,'credential_ids',None) is not None and args.credential_ids!=list(PROFILES[selected_kind]['values'])
    if custom_ids:
        auto_config+=('#define OSREC_CREDENTIAL_REAL_ID '+str(args.credential_ids[0])+'U\n#define OSREC_CREDENTIAL_EFFECTIVE_ID '+str(args.credential_ids[1])+'U\n').encode()
    if custom_ids or getattr(args,'credential_output_offsets',[0,4,8])!=[0,4,8]:
        auto_config+=''.join('#define OSREC_CREDENTIAL_OUTPUT_'+str(i)+' '+str(v)+'\n' for i,v in enumerate(args.credential_output_offsets)).encode()
    if getattr(args,'getgroups',False):auto_config+=('#define OSREC_GETGROUPS_CAPTURE 1\n#define OSREC_GETGROUPS_OUTPUT_SIZE '+str(getattr(args,'getgroups_output_size',4))+'\n').encode()
    if getattr(args,'getgroups_copy_outcome','success')!='success':auto_config+=b'#define OSREC_GETGROUPS_COPY_FAILURES 1\n'
    if getattr(args,'getgroups_copy_bytes',None) is not None:auto_config+=('#define OSREC_GETGROUPS_COPY_BYTES '+str(args.getgroups_copy_bytes)+'\n').encode()
    if getattr(args,'getgroups_copy_outcome','success')=='half':auto_config+=b'#define OSREC_GETGROUPS_PARTIAL_COPY_FAILURES 1\n'
    if getattr(args,'getgroups_allocation_failure',False):auto_config+=b'#define OSREC_GETGROUPS_ALLOCATION_FAILURE 1\n'
    if getattr(args,'getgroups_null_output',False):auto_config+=b'#define OSREC_GETGROUPS_NULL_OUTPUT 1\n'
    if getattr(args,'getgroups_null_boundaries',False):auto_config+=b'#define OSREC_GETGROUPS_NULL_BOUNDARIES 1\n'
    if getattr(args,'getgroups_negative_sizes',False):auto_config+=b'#define OSREC_GETGROUPS_NEGATIVE_SIZES 1\n'
    if getattr(args,'getgroups',False):auto_config+=('#define OSREC_GETGROUPS_OUTPUT_OFFSET '+str(getattr(args,'getgroups_output_offset',0))+'\n').encode()
    if getattr(args,'getgroups',False):auto_config+=('#define OSREC_GETGROUPS_GROUP_COUNT '+str(getattr(args,'getgroups_group_count',3))+'\n').encode()
    if getattr(args,'getscheduler',False):auto_config+=b'#define OSREC_GETSCHEDULER_CAPTURE 1\n'
    if getattr(args,'clocks',False):auto_config+=b'#define OSREC_CLOCK_CAPTURE 1\n'
    if getattr(args,'file_operations',False):auto_config+=b'#define OSREC_FILE_CAPTURE 1\n'
    if getattr(args,'dup',False):auto_config+=b'#define OSREC_DUP_CAPTURE 1\n'
    if getattr(args,'close_lifecycle',False):auto_config+=b'#define OSREC_CLOSE_CAPTURE 1\n'
    if getattr(args,'uname_faults',False):auto_config+=b'#define OSREC_UNAME_FAULTS 1\n'
    if getattr(args,'uname',False):auto_config+=b'#define OSREC_UNAME_CAPTURE 1\n'
    if getattr(args,'resource_limits',False):auto_config+=b'#define OSREC_RLIMIT_CAPTURE 1\n'
    if getattr(args,'getscheduler_task',False):auto_config+=b'#define OSREC_GETSCHEDULER_TASK_CAPTURE 1\n'
    write_changed(board/'file_capture.h',(ROOT/'integrations/liteos_qemu/file_capture.h').read_bytes())
    from file_profile import workload
    write_changed(board/'file_workload.h',workload().encode())
    write_changed(board/'auto_entry_config.h',auto_config)
    write_changed(board/'osrec_entry_capture.c',b'#include "auto_entry_config.h"\n#ifdef OSREC_SHARED_ARGUMENT_CAPTURE\n'+
                  (ROOT/'runtime/entry_capture.c').read_bytes()+b'\n#endif\n')
    if args.automated_entry_state:
        from automated_entry_state import generate
        from credential_entry_state import QUERY_ROOTS
        kind='getresgid' if getattr(args,'getresgid',False) else 'getresuid' if getattr(args,'getresuid',False) else None
        queries=[QUERY_ROOTS[kind]] if kind else []
        plan,header=generate(TREE,args.llvm_bin,TREE.parent/'automated-entry-state',credential_queries=queries,
                             argument_entry=argument_profile(args) if getattr(args,'argument_entry_state',False) else False,
                             shared_mixed=getattr(args,'shared_mixed_capture',False) or bool(getattr(args,'shared_session',None)))
        write_changed(board/'auto_entry_capture.h',header.encode())
        write_changed(board/'osrec_entry_snapshot.c',(ROOT/'runtime/entry_snapshot.c').read_bytes())
        write_changed(board/'osrec_object_lifetime.c',(ROOT/'runtime/object_lifetime.c').read_bytes())
        if getattr(args,'shared_argument_capture',False):
            if getattr(args,'shared_session',None):
                from live_configured_capture import prepare as prepare_shared
                shared=prepare_shared(TREE.parent/'automated-entry-state',args.kernel_root,args.shared_session_data)
                write_changed(board/'shared_session_schedule.h',(TREE.parent/'automated-entry-state/shared-session-schedule.h').read_bytes())
            else:
                from live_shared_capture import prepare as prepare_shared
                shared=prepare_shared(TREE.parent/'automated-entry-state',args.kernel_root,mixed=getattr(args,'shared_mixed_capture',False))
            write_changed(board/'shared_entry_capture.h',shared.encode())
    wrappers=TREE/'host-tools';wrappers.mkdir(exist_ok=True)
    script='#!'+sys.executable+'\nimport sys\nsys.path.insert(0,'+repr(str(TREE.parent/'kconfiglib'))+')\nfrom genconfig import main\nmain()\n'
    write_changed(wrappers/'genconfig',script.encode());(wrappers/'genconfig').chmod(0o755)
    return lock,case,payload


def logged(command,path,**kwargs):
    # Long builds return immediately to the caller shell; log preserves diagnostics.
    with path.open('wb') as log:
        completed=subprocess.run(list(map(str,command)),stdout=log,stderr=subprocess.STDOUT,**kwargs)
    if completed.returncode: raise ValueError(f'build failed; see {path}')


def build(args):
    llvm=args.llvm_bin; builtins=TREE.parent/'liteos-arm-builtins'
    source=TREE.parent/'arm-compiler-rt/compiler-rt/lib/builtins'
    flags='-mcpu=cortex-a7 -mfloat-abi=softfp -mfpu=neon-vfpv4'
    logged(['cmake','-G','Ninja','-S',source,'-B',builtins,'-DCMAKE_SYSTEM_NAME=Generic',
        '-DCMAKE_C_COMPILER='+str(llvm/'clang'),'-DCMAKE_C_COMPILER_TARGET=arm-none-eabi',
        '-DCMAKE_ASM_COMPILER_TARGET=arm-none-eabi','-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY',
        '-DCMAKE_C_FLAGS='+flags,'-DCMAKE_ASM_FLAGS='+flags,
        '-DCOMPILER_RT_BAREMETAL_BUILD=ON','-DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON',
        '-DLLVM_CONFIG_PATH='+str(llvm/'llvm-config')],TREE/'builtins-configure.log')
    logged(['cmake','--build',builtins,'-j',str(args.jobs)],TREE/'builtins-build.log')
    env=os.environ.copy();env['PATH']=str(TREE/'host-tools')+os.pathsep+env.get('PATH','')
    logged(['make','-C',TREE/'kernel/liteos_a','-j'+str(args.jobs),'liteos',
        'PRODUCT_PATH='+str(TREE/'vendor/ohemu/qemu_small_system_demo'),
        'DEVICE_PATH='+str(TREE/'device/qemu/arm_virt/liteos_a'),
        'LITEOS_COMPILER_PATH='+str(llvm)+'/', 'CROSS_COMPILE=llvm-',
        'SYSROOT_PATH='+str(TREE/'sysroot'),'OUTDIR='+str(TREE/'out'),'KCONFIG_CONFIG=.config',
        'OSREC_ARM_BUILTINS='+str(builtins/'lib/generic/libclang_rt.builtins-arm.a')],TREE/'build.log',env=env)


def boot(args):
    command=[args.qemu,'-M','virt-9.2,gic-version=2,secure=on','-cpu','cortex-a7','-accel','tcg',
             '-smp','1','-m','1G','-display','none','-monitor','none','-serial','stdio','-bios',TREE/'out/liteos.bin']
    try:
        result=subprocess.run(list(map(str,command)),capture_output=True,timeout=20 if getattr(args,'file_operations',False) else 10)
        raw=result.stdout+result.stderr
    except subprocess.TimeoutExpired as error:
        raw=(error.stdout or b'')+(error.stderr or b'')
    # Kernel remains alive; timeout deliberately ends the observation interval.
    publish(args.out/'boot.log',raw)
    text=raw.decode(errors='replace')
    if 'cpu 0 entering scheduler' not in text or 'OSREC_LIVE_DONE' not in text or 'OSREC_LIVE_FAILED' in text:
        raise ValueError('kernel did not finish the live capture; inspect boot.log')
    values={}
    if getattr(args,'async_wait',False):
        for name in ('WAIT_EVENTS','WAIT_STATE','WAIT_USER'):
            matches=re.findall(r'^OSREC_'+name+r' ([0-9a-f]+)\r?$',text,re.M)
            if len(matches)!=1:raise ValueError('async wait capture missing or duplicated: '+name)
            values[name]=bytes.fromhex(matches[0])
    if getattr(args,'file_operations',False):
        from file_profile import COUNT
        rows=[]
        for name in [f'FILES_USER_{i}' for i in range(COUNT)]+['FILES_KERNEL','FILES_DEPS','FILES_ABI']:
            matches=re.findall(r'^OSREC_'+name+r' ([0-9a-f]+)\r?$',text,re.M)
            if len(matches)!=1:raise ValueError('file native capture missing or duplicated')
            blob=bytes.fromhex(matches[0])
            if name.startswith('FILES_USER'):rows.append(blob)
            else:values[name]=blob
        values['FILES_USER']=b''.join(rows)
    if getattr(args,'dup',False):
        for name in ('DUP_USER','DUP_KERNEL','DUP_DEPS'):
            matches=re.findall(r'^OSREC_'+name+r' ([0-9a-f]+)\r?$',text,re.M)
            if len(matches)!=1:raise ValueError('dup native capture missing or duplicated')
            values[name]=bytes.fromhex(matches[0])
    if getattr(args,'close_lifecycle',False):
        for name in ('CLOSE_USER','CLOSE_KERNEL','CLOSE_DEPS'):
            matches=re.findall(r'^OSREC_'+name+r' ([0-9a-f]+)\r?$',text,re.M)
            if len(matches)!=1:raise ValueError('close native capture missing or duplicated')
            values[name]=bytes.fromhex(matches[0])
    if getattr(args,'uname',False):
        for name in ('UNAME_USER','UNAME_KERNEL','UNAME_DEPS'):
            matches=re.findall(r'^OSREC_'+name+r' ([0-9a-f]+)\r?$',text,re.M)
            if len(matches)!=1:raise ValueError('uname native capture missing or duplicated')
            values[name]=bytes.fromhex(matches[0])
    if getattr(args,'resource_limits',False):
        for name in ('RLIMIT_USER','RLIMIT_KERNEL','RLIMIT_DEPS'):
            matches=re.findall(r'^OSREC_'+name+r' ([0-9a-f]+)\r?$',text,re.M)
            if len(matches)!=1:raise ValueError('resource limit capture incomplete or duplicated')
            values[name]=bytes.fromhex(matches[0])
    if getattr(args,'clocks',False):
        for name in ('CLOCK_USER','CLOCK_KERNEL','CLOCK_DEPS'):
            matches=re.findall(r'^OSREC_'+name+r' ([0-9a-f]+)\r?$',text,re.M)
            if len(matches)!=1:raise ValueError('clock capture incomplete or duplicated')
            values[name]=bytes.fromhex(matches[0])
    for name in ['READS','KERNEL','USER','PRIORITY','PRIORITY_MIN','PID','IDENTITY','IDENTITY_DEPS','UMASK_USER','UMASK_KERNEL','TASK_USER','TASK_KERNEL','CREDENTIALS_USER','CREDENTIALS_KERNEL','GETPRIORITY_USER','GETPRIORITY_DEPS','SETGROUPS_USER']:
        matches=re.findall(r'^OSREC_'+name+r' ([0-9a-f]+)\r?$',text,re.MULTILINE)
        if len(matches)!=1: raise ValueError('incomplete or duplicated kernel capture output')
        values[name]=bytes.fromhex(matches[0])
    if getattr(args,'getscheduler',False):
        for name in ('GETSCHEDULER_USER','GETSCHEDULER_DEPS'):
            matches=re.findall(r'^OSREC_'+name+r' ([0-9a-f]+)\r?$',text,re.M)
            if len(matches)!=1:raise ValueError('getscheduler capture incomplete or duplicated')
            values[name]=bytes.fromhex(matches[0])
    if args.automated_entry_state:
        from automated_entry_state import validate_snapshot,effect_plan
        # Analysis provenance is larger than the compact syscall-session format.
        plan=json.loads((TREE.parent/'automated-entry-state/plan.json').read_text())
        if plan.get('format')!='osrec-entry-state-plan-v1':raise ValueError('unsupported entry-state plan')
        roots={60:'SysUmask',64:'SysGetPPID',224:'SysGetTid',201:'SysGetEffUserID',202:'SysGetEffGID'}
        plans={p['root']:p for p in plan['plans']}
        frames=[json.loads(value) for value in re.findall(r'^OSREC_AUTO_ENTRY (.+)\r?$',text,re.MULTILINE)]
        if len(frames)!=14:raise ValueError('automatic entry snapshots are incomplete')
        for frame in frames:validate_snapshot(frame,plans[roots[frame['syscall']]])
        argument_effects=[]
        if getattr(args,'argument_entry_state',False):
            from live_argument_state import profile_settings,parse_capture
            profile=argument_profile(args)
            settings=profile_settings(profile)
            if settings.get('effects'):
                from live_argument_effects import parse_capture as parse_effect_capture
                argument_frames,argument_effects,argument_witness=parse_effect_capture(text,plans[settings['helper']],profile)
            else:
                argument_frames,argument_witness=parse_capture(text,plans[settings['helper']],profile)
                if re.search(r'^OSREC_ARGUMENT_EFFECT ',text,re.M):raise ValueError('unexpected argument write effects in readonly capture')
            frames+=argument_frames
            publish(args.out/'argument-entry-kernel.bin',argument_witness)
        elif re.search(r'^OSREC_ARGUMENT_(?:ENTRY|EFFECT|KERNEL) ',text,re.M):
            raise ValueError('unexpected argument-entry capture markers')
        effects=[json.loads(value) for value in re.findall(r'^OSREC_AUTO_EFFECT (.+)\r?$',text,re.MULTILINE)]
        if [(f['invocation'],f['syscall']) for f in effects]!=list(enumerate([60]*6)):raise ValueError('automatic effect snapshots are incomplete')
        for frame in effects:validate_snapshot(frame,effect_plan(plans['SysUmask']))
        effects+=argument_effects
        from entry_state_lifetimes import validate_lifetimes
        lifetime_reports=re.findall(r'^OSREC_LIFETIMES (.+)\r?$',text,re.MULTILINE)
        if len(lifetime_reports)!=1:raise ValueError('lifetime capture is incomplete or duplicated')
        lifetimes=json.loads(lifetime_reports[0]);validate_lifetimes(lifetimes,frames+effects)
        from setgroups_capture import validate_setgroups
        group_entries=[json.loads(value) for value in re.findall(r'^OSREC_GROUP_ENTRY (.+)\r?$',text,re.MULTILINE)]
        group_exits=[json.loads(value) for value in re.findall(r'^OSREC_GROUP_EFFECT (.+)\r?$',text,re.MULTILINE)]
        if len(group_entries)!=3 or len(group_exits)!=3 or len(values['SETGROUPS_USER'])!=36:raise ValueError('setgroups capture incomplete')
        for i in range(3):
            raw=group_entries[i]['raw']
            if raw not in (0,0xfffffff4,0xfffffff2) or (getattr(args,'setgroups_allocation_failures',False) and raw!=0xfffffff4):raise ValueError('unsupported setgroups result')
            if (getattr(args,'setgroups_copy_failures',False) or getattr(args,'setgroups_partial_copy_failures',False)) and raw!=(0xfffffff2 if i else 0):raise ValueError('copy failure injection result differs')
            if struct.unpack_from('<3I',values['SETGROUPS_USER'],i*12)!=(i,raw,16):raise ValueError('setgroups user observation differs')
        groups={'format':'osrec-live-setgroups-v5','capture_adapter':'reviewed SysSetGroups lists of 0..2 groups, allocation outcomes and controlled prefix copy failures',
            'fault_injected':bool(getattr(args,'setgroups_allocation_failures',False) or (getattr(args,'setgroups_copy_failures',False) or getattr(args,'setgroups_partial_copy_failures',False))),
            'partial_copy_fault_injected':bool(getattr(args,'setgroups_partial_copy_failures',False)),
            'copy_fault_injected':bool((getattr(args,'setgroups_copy_failures',False) or getattr(args,'setgroups_partial_copy_failures',False))),
            'dynamic_object_replay':False,'calls':[{'invocation':i,'arguments':group_entries[i]['arguments'],'raw':group_entries[i]['raw'],
                'entry':group_entries[i],'exit':group_exits[i],
                'events':lifetimes['events'][group_entries[i]['lifetime_cursor']:group_exits[i]['lifetime_cursor']]} for i in range(3)],
            'source_sha256':digest((TREE/'kernel/liteos_a/syscall/process_syscall.c').read_bytes()),
            'type_header_sha256':digest((TREE/'kernel/liteos_a/kernel/base/include/los_process_pri.h').read_bytes())}
        validate_setgroups(groups,lifetimes)
        publish(args.out/'setgroups-capture.json',json.dumps(groups,indent=2).encode()+b'\n')
        if getattr(args,'getgroups',False):
            from getgroups_capture import validate_getgroups,output_bytes
            entries=[json.loads(v) for v in re.findall(r'^OSREC_GETGROUP_ENTRY (.+)\r?$',text,re.M)]
            exits=[json.loads(v) for v in re.findall(r'^OSREC_GETGROUP_EFFECT (.+)\r?$',text,re.M)]
            if len(entries)!=3 or len(exits)!=3:raise ValueError('getgroups capture incomplete')
            null_profile='negative-sizes' if getattr(args,'getgroups_negative_sizes',False) else 'boundaries' if getattr(args,'getgroups_null_boundaries',False) else 'short' if getattr(args,'getgroups_null_output',False) else 'none'
            getgroups={'format':'osrec-live-getgroups-v10','group_count':getattr(args,'getgroups_group_count',3),'output_offset':getattr(args,'getgroups_output_offset',0),'output_size':getattr(args,'getgroups_output_size',4),'null_output_profile':null_profile,'null_output_case':null_profile!='none','output_region':{'id':201,'offset':0,'bytes':16},'allocation_fault_injected':bool(getattr(args,'getgroups_allocation_failure',False)),'copy_outcome':getattr(args,'getgroups_copy_outcome','success'),'capture_adapter':'reviewed count, short-buffer and null-output branches with captured 1..3-group credentials; shared 16-byte output witness sampled even when not passed',
                'source_sha256':groups['source_sha256'],'type_header_sha256':groups['type_header_sha256'],
                'calls':[{'invocation':i,'arguments':entries[i]['arguments'],'raw':entries[i]['raw'],'entry':entries[i],'exit':exits[i],
                    'events':lifetimes['events'][entries[i]['lifetime_cursor']:exits[i]['lifetime_cursor']]} for i in range(3)]}
            if getgroups['group_count']<3 and null_profile!='none':getgroups['format']='osrec-live-getgroups-v12'
            if getattr(args,'getgroups_copy_bytes',None) is not None:getgroups.update(format='osrec-live-getgroups-v11',copy_bytes=args.getgroups_copy_bytes)
            validate_getgroups(getgroups,lifetimes)
            user=re.findall(r'^OSREC_GETGROUPS_USER ([0-9a-f]+)\r?$',text,re.M)
            expected=b''.join(struct.pack('<3I',c['arguments']['size'] & 0xffffffff,c['raw'],16)+output_bytes(c['exit']) for c in getgroups['calls'])
            if len(user)!=1 or bytes.fromhex(user[0])!=expected:raise ValueError('getgroups independent user observation differs')
            publish(args.out/'getgroups-capture.json',json.dumps(getgroups,indent=2).encode()+b'\n')
        if getattr(args,'getresuid',False) or getattr(args,'getresgid',False):
            kind='getresgid' if args.getresgid else 'getresuid'
            from getresuid_capture import validate_credential_query,PROFILES
            from credential_entry_state import QUERY_ROOTS,GENERATION
            profile=PROFILES[kind];prefix=profile['prefix']
            entries=[json.loads(v) for v in re.findall(r'^OSREC_'+prefix+r'_ENTRY (.+)\r?$',text,re.M)]
            exits=[json.loads(v) for v in re.findall(r'^OSREC_'+prefix+r'_EFFECT (.+)\r?$',text,re.M)]
            if len(entries)!=4 or len(exits)!=4:raise ValueError(f'{kind} capture incomplete')
            bundle={'format':f'osrec-live-{kind}-v1','credential_fixture':{'real':args.credential_ids[0],'effective':args.credential_ids[1],'scope':'selected syscall only; native fields restored afterward'},'output_region':{'id':301,'offset':0,'bytes':16},'source_sha256':groups['source_sha256'],'type_header_sha256':groups['type_header_sha256'],
                'calls':[{'invocation':i,'arguments':entries[i]['arguments'],'raw':entries[i]['raw'],'entry':entries[i],'exit':exits[i],'events':lifetimes['events'][entries[i]['lifetime_cursor']:exits[i]['lifetime_cursor']]} for i in range(4)]}
            if args.credential_output_offsets!=[0,4,8]:bundle.update(format='osrec-live-'+kind+'-v2',output_offsets=args.credential_output_offsets)
            if args.credential_ids!=list(profile['values']):bundle.update(format='osrec-live-'+kind+'-v3',output_offsets=args.credential_output_offsets)
            bundle['entry_state_generation']=GENERATION
            query_plan=next(p for p in plan['capture_plans'] if p['root']=='credential_'+QUERY_ROOTS[kind])
            for frame in (*entries,*exits):validate_snapshot(frame,query_plan)
            validate_credential_query(bundle,lifetimes,kind)
            user=re.findall(r'^OSREC_'+prefix+r'_USER ([0-9a-f]+)\r?$',text,re.M)
            expected=b''.join(struct.pack('<3I',i,c['raw'],16)+bytes.fromhex(c['exit']['output_data']) for i,c in enumerate(bundle['calls']))
            if len(user)!=1 or bytes.fromhex(user[0])!=expected:raise ValueError(f'{kind} user observations differ')
            publish(args.out/f'{kind}-capture.json',json.dumps(bundle,indent=2).encode()+b'\n')
        publish(args.out/'entry-state-lifetimes.json',json.dumps(lifetimes,indent=2).encode()+b'\n')
        publish(args.out/'entry-state-effects.json',json.dumps({'format':'osrec-live-entry-effects-v1','snapshots':effects},indent=2).encode()+b'\n')
        publish(args.out/'entry-state-snapshots.json',json.dumps({'format':'osrec-live-entry-state-v1','snapshots':frames},indent=2).encode()+b'\n')
        shutil.copy2(TREE.parent/'automated-entry-state/plan.json',args.out/'entry-state-plan.json')
        shutil.copy2(TREE.parent/'automated-entry-state/capture.h',args.out/'entry-state-capture.h')
        if getattr(args,'shared_argument_capture',False):
            if getattr(args,'shared_session',None):
                from live_configured_capture import publish_capture
                publish_capture(args.out,TREE.parent/'automated-entry-state',text)
            else:
                from live_shared_capture import publish_capture
                publish_capture(args.out,TREE.parent/'automated-entry-state',text,argument_frames,argument_effects,argument_witness)
        elif re.search(r'^OSREC_SHARED_CAPTURE ',text,re.M):raise ValueError('unexpected shared capture marker')
    match=re.search(r'OSREC_LIVE_ENTRY pid=(\d+) user_fd=3 system_fd=(\d+) cursor=0 initial_errno=0',text)
    if not match or int(match[1])!=1: raise ValueError('capture owner is not user init PID 1')
    return values,command,int(match[2])


def demo(args):
    if args.out.exists() and any(args.out.iterdir()): raise ValueError('choose an empty output directory')
    if args.out.is_relative_to(TREE) or (args.input and args.out==args.input): raise ValueError('output cannot overwrite the build tree or input')
    record,_,_=identity(args.kernel_root)
    lock,case,payload=prepare(args,record)
    if identity(TREE/'kernel/liteos_a')[0]['kernel']!=record['kernel']:
        raise ValueError('live kernel SysRead source differs from the pinned replay source')
    build(args)
    args.out.mkdir(parents=True,exist_ok=True)
    values,command,system_fd=boot(args)
    if getattr(args,'async_wait',False):
        from live_wait_replay import export_live_wait
        export_live_wait(args,values,command)
    objects=validate_entry(case['entry'],case['calls'])
    decode(values['READS'],context_hash(case['entry'],case['calls'],record),case['entry'],case['calls'],objects)
    publish(args.out/'reads.osrec',values['READS'])
    publish(args.out/'entry.json',json.dumps(case,indent=2).encode()+b'\n')
    publish(args.out/'kernel-observations.bin',values['KERNEL']);publish(args.out/'user-observations.bin',values['USER'])
    if len(values['KERNEL'])!=64 or len(values['USER'])!=112: raise ValueError('wrong observation size')
    tool=ROOT/'tools/syscall_checkpoint.py';capture=args.out/'capture.json';binary=args.out/'replay'
    run([sys.executable,tool,'capture','--kernel-root',args.kernel_root,'--compiler',args.compiler,
        '--case',args.out/'entry.json','--reads',args.out/'reads.osrec','--source-kind','qemu','--out',capture])
    document=load(capture)
    for i,expected in enumerate(document['expected']):
        kernel=struct.unpack_from('<4I',values['KERNEL'],i*16)
        user=struct.unpack_from('<5I',values['USER'],i*28)
        signed=lambda n:n if n<0x80000000 else n-0x100000000
        actual={'raw':signed(user[0]),'return':signed(user[1]),'errno':user[2],'recognized':user[3],
                'kernel_errno':kernel[1],'file_positions':{'20':kernel[2]},
                'memory':values['USER'][i*28+20:i*28+28].hex()}
        if actual!=expected or kernel[0]!=user[0] or kernel[3]!=0x113 or user[4]!=0x10:
            raise ValueError(f'live kernel/user/native observation mismatch at call {i}')
    run([sys.executable,tool,'export','--kernel-root',args.kernel_root,'--compiler',args.compiler,
         '--capture',capture,'--out',binary])
    with tempfile.TemporaryDirectory(prefix='osrec-live-replay-') as isolated:
        copied=Path(isolated)/'replay';shutil.copy2(binary,copied)
        verified=run([copied],cwd=isolated,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}).stdout.strip()
    shutil.copy2(TREE/'out/liteos.bin',args.out/'liteos.bin');shutil.copy2(TREE/'out/liteos',args.out/'liteos.elf')
    shutil.copy2(TREE/'device/qemu/arm_virt/liteos_a/board/auto_entry_config.h',args.out/'auto-entry-config.h')
    priority=export_live_priority(args,values['PRIORITY'],digest((args.out/'liteos.bin').read_bytes()))
    minimum=export_live_priority(args,values['PRIORITY_MIN'],digest((args.out/'liteos.bin').read_bytes()),'SysSchedGetPriorityMin')
    pid=export_live_pid(args,values['PID'],digest((args.out/'liteos.bin').read_bytes()),1)
    identities=export_live_identity(args,values['IDENTITY'],values['IDENTITY_DEPS'],digest((args.out/'liteos.bin').read_bytes()))
    masks=export_live_umask(args,values['UMASK_USER'],values['UMASK_KERNEL'],digest((args.out/'liteos.bin').read_bytes()))
    tasks=export_live_task(args,values['TASK_USER'],values['TASK_KERNEL'],digest((args.out/'liteos.bin').read_bytes()))
    credentials=export_live_credentials(args,values['CREDENTIALS_USER'],values['CREDENTIALS_KERNEL'],digest((args.out/'liteos.bin').read_bytes()))
    process_priorities=export_live_getpriority(args,values['GETPRIORITY_USER'],values['GETPRIORITY_DEPS'],digest((args.out/'liteos.bin').read_bytes()))
    if getattr(args,'getscheduler',False):
        from live_getscheduler_replay import export_live_getscheduler
        export_live_getscheduler(args,values['GETSCHEDULER_USER'],values['GETSCHEDULER_DEPS'],digest((args.out/'liteos.bin').read_bytes()))
    if getattr(args,'clocks',False):
        from clock_capture import export_capture
        export_capture(args,values['CLOCK_USER'],values['CLOCK_KERNEL'],values['CLOCK_DEPS'],digest((args.out/'liteos.bin').read_bytes()))
    if getattr(args,'file_operations',False):
        from files_capture import export_capture
        export_capture(args,values['FILES_USER'],values['FILES_KERNEL'],values['FILES_DEPS'],values['FILES_ABI'],digest((args.out/'liteos.bin').read_bytes()))
    if getattr(args,'dup',False):
        from dup_capture import export_capture
        export_capture(args,values['DUP_USER'],values['DUP_KERNEL'],values['DUP_DEPS'],digest((args.out/'liteos.bin').read_bytes()))
    if getattr(args,'close_lifecycle',False):
        from close_capture import export_capture
        export_capture(args,values['CLOSE_USER'],values['CLOSE_KERNEL'],values['CLOSE_DEPS'],digest((args.out/'liteos.bin').read_bytes()))
    if getattr(args,'uname',False):
        from uname_capture import export_capture
        export_capture(args,values['UNAME_USER'],values['UNAME_KERNEL'],values['UNAME_DEPS'],digest((args.out/'liteos.bin').read_bytes()))
    if getattr(args,'resource_limits',False):
        from rlimit_capture import export_capture
        export_capture(args,values['RLIMIT_USER'],values['RLIMIT_KERNEL'],values['RLIMIT_DEPS'],digest((args.out/'liteos.bin').read_bytes()))
    report={'format':'osrec-live-liteos-qemu-demo-v1','status':'verified','actual_kernel_boot':True,
        'scope':'four SysRead calls through SVC/VFS/RAMFS, three SysSchedGetPriorityMax calls, three SysSchedGetPriorityMin calls, one SysGetPID call seven UID/GID/process-group queries and six SysUmask calls and four effective credential queries and six getpriority calls and three bounded SysSetGroups calls from PID 1 and four parent/task queries from its forked child',
        'priority_replay':priority,'priority_min_replay':minimum,'pid_replay':pid,'identity_replay':identities,'umask_replay':masks,'task_checkpoint':tasks,'credentials_checkpoint':credentials,'getpriority_checkpoint':process_priorities,
        'guest_mmu_enabled':True,'user_mode':16,'kernel_mode':19,'system_fd':system_fd,
        'normalized_backend_fd':17,'actual_kernel_source':record['kernel'],'dependencies':lock,
        'workload_input_sha256':digest(payload),'raw_returns':[o['raw'] for o in document['expected']],
        'live_native_observations_match':True,'isolated_native_replay':verified,
        'scheduler_irq_reproduction':False,'replay_dependencies':'declared process/fd/range/read/cursor models',
        'kernel_image_sha256':digest((args.out/'liteos.bin').read_bytes()),
        'kernel_elf_sha256':digest((args.out/'liteos.elf').read_bytes()),
        'automated_entry_state':args.automated_entry_state,
        'setgroups_fault_injected':bool(getattr(args,'setgroups_allocation_failures',False) or (getattr(args,'setgroups_copy_failures',False) or getattr(args,'setgroups_partial_copy_failures',False))),
        'setgroups_partial_copy_fault_injected':bool(getattr(args,'setgroups_partial_copy_failures',False)),
        'setgroups_copy_fault_injected':bool((getattr(args,'setgroups_copy_failures',False) or getattr(args,'setgroups_partial_copy_failures',False))),
        'auto_entry_config_sha256':digest((TREE/'device/qemu/arm_virt/liteos_a/board/auto_entry_config.h').read_bytes()),
        'kernel_config_sha256':digest((TREE/'kernel/liteos_a/.config').read_bytes()),
        'live_config_sha256':digest((TREE/'device/qemu/arm_virt/liteos_a/board/live_config.h').read_bytes()),
        'boot_log_sha256':digest((args.out/'boot.log').read_bytes()),
        'kernel_observations_sha256':digest(values['KERNEL']),'user_observations_sha256':digest(values['USER']),
        'read_stream_sha256':digest(values['READS']),'qemu_command':list(map(str,command)),
        'qemu_version':run([args.qemu,'--version']).stdout.splitlines()[0],
        'integration_source_hashes':{p.name:digest(p.read_bytes()) for p in sorted(SOURCE.iterdir()) if p.is_file()},
        'recorder_source_hashes':{str(p.relative_to(ROOT)):digest(p.read_bytes()) for p in [ROOT/'runtime/recorder.c',ROOT/'runtime/io_capture.c',ROOT/'include/osrec/recorder.h',ROOT/'include/osrec/io_capture.h',ROOT/'include/osrec/checkpoint.h']}}
    if args.automated_entry_state:
        report['automated_session_identity']={'format':'osrec-capture-scoped-object-ids-v1',
            'identity_source':'transient kernel lifetime table sampled with each snapshot; addresses never serialized',
            'stable_lifetimes_for_syscalls':[60],
            'lifetime_scope':'PID 1 current process during six SysUmask calls in configured workload',
            'allocation_reuse_tracking':True,'allocation_reuse_scope':[206,205] if getattr(args,'getgroups',False) else [206],
            'allocation_reuse_workload':'three SysSetGroups calls with bounded lists of 0..2 groups from PID 1; base addresses only'+('; three bounded SysGetGroups output calls' if getattr(args,'getgroups',False) else '')}
        report['automated_capture_hashes']={
            'runtime':digest((ROOT/'runtime/entry_snapshot.c').read_bytes()),
            'header':digest((ROOT/'include/osrec/entry_snapshot.h').read_bytes()),
            'lifetime_runtime':digest((ROOT/'runtime/object_lifetime.c').read_bytes()),
            'lifetime_header':digest((ROOT/'include/osrec/object_lifetime.h').read_bytes()),
            'plan':digest((args.out/'entry-state-plan.json').read_bytes()),
            'generated_hooks':digest((args.out/'entry-state-capture.h').read_bytes()),
            'snapshots':digest((args.out/'entry-state-snapshots.json').read_bytes()),
            'effects':digest((args.out/'entry-state-effects.json').read_bytes())}
        report['automated_capture_hashes']['lifetimes']=digest((args.out/'entry-state-lifetimes.json').read_bytes())
        if getattr(args,'argument_entry_state',False):
            from live_argument_state import profile_settings,prepare_source
            profile=argument_profile(args)
            settings=profile_settings(profile)
            _,helper_identity=prepare_source(args.kernel_root,profile)
            report['argument_entry_capture']={'file':'argument-entry-kernel.bin','function':settings['helper'],'profile':profile,'calls':6,
                'sha256':digest((args.out/'argument-entry-kernel.bin').read_bytes()),'source_identity':helper_identity,
                'scope':'explicit capture-adapter helper invocations on PID 1 current process under scheduler lock'}
            if settings.get('effects'):
                report['argument_entry_capture'].update(controlled_restore=True,
                    scope='controlled original helper writes on PID 1; exitCode restored before scheduler unlock')
                if settings.get('continuous'):
                    report['argument_entry_capture'].update(
                        scope='six original helper calls retaining writes in one locked batch; exitCode restored once after the batch',
                        session_contract={'format':'osrec-locked-argument-session-v1','route':settings['route'],'calls':6,
                            'single_lock_region':True,'restoration':'after_batch','entry_inherits_previous_post':True})
                    report['automated_session_identity']['stable_lifetimes_for_syscalls'].append(settings['route'])
                    report['automated_session_identity']['lifetime_scope']+='; current process held throughout one locked six-call helper session'
                    if settings.get('nested'):
                        from live_parent_argument import PARENT_CONTRACT
                        report['argument_entry_capture']['scope']='before workload child first getppid, capture adapter follows real parentProcess edge; six original helper writes on PID 1 parent; parent exitCode restored once after the locked batch'
                        report['argument_entry_capture']['parent_contract']=PARENT_CONTRACT
                        report['automated_session_identity']['lifetime_scope']+='; workload child, its distinct PID 1 parent and parentProcess edge held stable throughout the same locked batch'
        if getattr(args,'shared_argument_capture',False):
            if getattr(args,'shared_session',None):
                from live_configured_capture import metadata as shared_metadata
            else:
                from live_shared_capture import metadata as shared_metadata
            report['shared_argument_capture']=shared_metadata(args.out)
        report['setgroups_capture']={'file':'setgroups-capture.json',
            'sha256':digest((args.out/'setgroups-capture.json').read_bytes()),'calls':3,
            'original_syscall_executed':True,'dynamic_object_replay':False}
    if getattr(args,'getgroups',False):
        null_profile='negative-sizes' if getattr(args,'getgroups_negative_sizes',False) else 'boundaries' if getattr(args,'getgroups_null_boundaries',False) else 'short' if getattr(args,'getgroups_null_output',False) else 'none'
        report['getgroups_capture']={'group_count':getattr(args,'getgroups_group_count',3),'output_offset':getattr(args,'getgroups_output_offset',0),'output_size':getattr(args,'getgroups_output_size',4),'file':'getgroups-capture.json','sha256':digest((args.out/'getgroups-capture.json').read_bytes()),'calls':3,'original_syscall_executed':True,'copy_outcome':getattr(args,'getgroups_copy_outcome','success'),'allocation_fault_injected':bool(getattr(args,'getgroups_allocation_failure',False)),'null_output_case':null_profile!='none','null_output_profile':null_profile}
    if getattr(args,'getscheduler',False):
        report['getscheduler_capture']={'file':'getscheduler-checkpoint.manifest.json','sha256':digest((args.out/'getscheduler-checkpoint.manifest.json').read_bytes()),'calls':4,'original_syscall_executed':True,'dependency_internals_replayed':False,'flag':-1 if args.getscheduler_task else 0}
        report['scope']+=' and four '+('task' if args.getscheduler_task else 'process')+'-mode SysSchedGetScheduler calls before fork'
    if getattr(args,'clocks',False):
        report['clock_capture']={'file':'clock-checkpoint.manifest.json','sha256':digest((args.out/'clock-checkpoint.manifest.json').read_bytes()),
            'calls':10,'provider_events':8,'user_copy_events':6,'original_syscalls_executed':True,'provider_internals_replayed':False,'entry_errno_fixture':0}
        report['scope']+=' and ten clock_gettime/clock_getres SVC calls before fork with native provider and copy outcomes'
    if getattr(args,'file_operations',False):
        report['files_capture']={'file':'files-checkpoint.manifest.json','sha256':digest((args.out/'files-checkpoint.manifest.json').read_bytes()),'calls':32,'original_syscalls_executed':True}
        report['scope']+=' and a shared-state 32-call native file session'
    if getattr(args,'dup',False):
        report['dup_capture']={'file':'dup-checkpoint.manifest.json','sha256':digest((args.out/'dup-checkpoint.manifest.json').read_bytes()),'calls':5,'original_syscall_executed':True,'injected_first_allocation_failure':True}
        report['scope']+=' and five dup SVC calls before fork with three-slot descriptor effects and native reference counts, plus one scoped allocation failure'
    if getattr(args,'close_lifecycle',False):
        report['close_capture']={'file':'close-checkpoint.manifest.json','sha256':digest((args.out/'close-checkpoint.manifest.json').read_bytes()),'calls':5,'original_syscall_executed':True,'injected_first_close_failure':True}
        report['scope']+=' and five close SVC calls before fork with descriptor rollback/free effects and one scoped EIO failure'
    if getattr(args,'uname',False):
        report['uname_capture']={'file':'uname-checkpoint.manifest.json','sha256':digest((args.out/'uname-checkpoint.manifest.json').read_bytes()),'calls':8 if args.uname_faults else 4,'original_syscall_executed':True,'injected_boundary_faults':args.uname_faults}
        report['scope']+=' and uname SVC calls before fork with complete native input/provider/output bytes'
        if args.uname_faults:report['scope']+=' and scoped partial input, provider error, zero-write and partial output failures'
    if getattr(args,'resource_limits',False):
        report['rlimit_capture']={'file':'rlimit-checkpoint.manifest.json','sha256':digest((args.out/'rlimit-checkpoint.manifest.json').read_bytes()),
            'calls':6,'provider_events':6,'user_copy_events':4,'original_syscall_executed':True,'provider_internals_replayed':False}
        report['scope']+=' and six ugetrlimit SVC calls before fork with native provider and copy outcomes'
    if getattr(args,'async_wait',False):
        report['async_wait_capture']={'file':'wait-capture.json','sha256':digest((args.out/'wait-capture.json').read_bytes()),
            'calls':1,'events':10,'native_scheduler_executed':True,'native_timer_irq_observed':True,
            'replay_scheduler':'explicit sequential model','replay':'wait-replay'}
        report['scope']+=' and one real blocking SysNanoSleep with scheduler switches, timeout deadline and timer IRQ wakeup'
    if getattr(args,'getresuid',False):report['getresuid_capture']={'file':'getresuid-capture.json','sha256':digest((args.out/'getresuid-capture.json').read_bytes()),'calls':4,'original_syscall_executed':True,'scoped_credential_fixture':True,'generated_entry_fields':True}
    if getattr(args,'getresgid',False):report['getresgid_capture']={'file':'getresgid-capture.json','sha256':digest((args.out/'getresgid-capture.json').read_bytes()),'calls':4,'original_syscall_executed':True,'scoped_credential_fixture':True,'generated_entry_fields':True}
    if getattr(args,'getgroups_copy_bytes',None) is not None:report['getgroups_capture']['copy_bytes']=args.getgroups_copy_bytes
    publish(args.out/'report.json',json.dumps(report,indent=2).encode()+b'\n')
    print(json.dumps({'report':str(args.out/'report.json'),'replay':str(binary),'raw_returns':report['raw_returns'],'verification':verified},indent=2))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-root',type=Path,default=ROOT/'build/kernel_liteos_a')
    parser.add_argument('--input',type=Path)
    parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--qemu',default='qemu-system-arm');parser.add_argument('--compiler',default='cc')
    parser.add_argument('--getgroups-allocation-failure',action='store_true',help='inject a null temporary allocation into the final getgroups call')
    parser.add_argument('--getgroups-null-output',action='store_true',help='pass NULL to the short-buffer getgroups call; check EFAULT before EINVAL')
    parser.add_argument('--getgroups-null-boundaries',action='store_true',help='capture NULL count query and NULL size-4 rejection without allocation or copying')
    parser.add_argument('--getgroups-negative-sizes',action='store_true',help='capture -1 with a valid buffer and INT32_MIN with NULL; no allocation or copying')
    parser.add_argument('--getgroups-group-count',type=int,choices=(1,2,3),default=3,help='capture after the first or final successful setgroups call, with 1, 2 or 3 groups')
    parser.add_argument('--getgroups-output-offset',type=int,default=0,help='byte offset 0..4 into the actual 16-byte output object for the final nonnull call')
    parser.add_argument('--getgroups-output-size',type=int,default=4,help='declared capacity of the final nonnull output call, group_count..INT32_MAX (actual shared buffer remains 16 bytes)')
    parser.add_argument('--getgroups-copy-bytes',type=int,help='inject output-copy failure after a byte prefix, 0..4*group_count-1; excludes other copy outcomes')
    parser.add_argument('--getgroups-copy-outcome',choices=('success','none','half'),default='success',help='getgroups copy: full success, injected failure before writes, or failure after half the bytes')
    parser.add_argument('--getresuid',action='store_true',help='capture getresuid success and each NULL output position with a scoped distinct-ID fixture')
    parser.add_argument('--getscheduler-task',action='store_true',help='capture task-mode scheduler callback and permission outcomes; implies --getscheduler')
    parser.add_argument('--getscheduler',action='store_true',help='capture process-mode sched_getscheduler success, invalid PID and unused slot')
    parser.add_argument('--getresgid',action='store_true',help='capture getresgid success and each NULL output position with a scoped distinct-ID fixture')
    parser.add_argument('--credential-output-offsets',help='three comma-separated byte offsets 0..12 in the shared 16-byte UID/GID output witness; aliases and overlaps allowed')
    parser.add_argument('--credential-ids',help='scoped real,effective UID/GID fixture values, decimal or hexadecimal, each 0..UINT32_MAX')
    parser.add_argument('--getgroups',action='store_true',help='capture count, short-buffer and successful bounded SysGetGroups output calls')
    parser.add_argument('--automated-entry-state',action='store_true',help='discover entry fields with Clang and capture normalized objects using generated hooks')
    parser.add_argument('--argument-entry-state',action='store_true',help='capture explicit original process-helper calls with generated argument-object bindings; implies --automated-entry-state')
    parser.add_argument('--const-argument-entry-state',action='store_true',help='capture the original read-only process-group-leader helper; implies automated argument capture')
    parser.add_argument('--argument-write-state',action='store_true',help='capture original signal-set helper writes and restore the live process field under scheduler lock; implies automated argument capture')
    parser.add_argument('--argument-write-session',action='store_true',help='capture six original helper calls retaining writes in one locked batch, then restore the live field once')
    parser.add_argument('--shared-argument-capture',action='store_true',help='use generated shared wrappers in the locked signal-helper session and retain independent witnesses')
    parser.add_argument('--shared-mixed-capture',action='store_true',help='interleave an original read helper with the six shared writes in one locked session')
    parser.add_argument('--shared-session',type=Path,help='capture a supplied bounded sequence of reviewed process signal reads/writes under one scheduler lock')
    parser.add_argument('--parent-argument-session',action='store_true',help='capture adapter follows the real parentProcess edge; batch original helper writes on the parent and restore once')
    parser.add_argument('--clocks',action='store_true',help='capture OHOS clock_gettime/getres success and invalid clock/output cases')
    parser.add_argument('--file-operations',action='store_true',help='capture shared-state open/openat/write/read/llseek/dup2/stat/fstat64/close session')
    parser.add_argument('--dup',action='store_true',help='capture dup allocation failure, shared references, flags and invalid descriptors')
    parser.add_argument('--close-lifecycle',action='store_true',help='capture close rollback, success, repeated close and invalid descriptors with one scoped provider failure')
    parser.add_argument('--uname-faults',action='store_true',help='extend uname capture with scoped input/provider/output failures; implies --uname')
    parser.add_argument('--uname',action='store_true',help='capture uname input/output bytes, NULL and invalid-pointer cases')
    parser.add_argument('--resource-limits',action='store_true',help='capture getrlimit file/file-size, invalid-resource and invalid-output cases')
    parser.add_argument('--async-wait',action='store_true',help='capture one real nanosleep with scheduler/IRQ boundaries; use without other optional profiles')
    parser.add_argument('--setgroups-partial-copy-failures',action='store_true',help='copy half the input bytes then inject a scoped user-copy failure')
    parser.add_argument('--setgroups-copy-failures',action='store_true',help='inject nonnull user-copy failures before any destination bytes are written')
    parser.add_argument('--setgroups-allocation-failures',action='store_true',help='inject three scoped allocator failure outcomes into live SysSetGroups capture')
    parser.add_argument('--fetch',action='store_true',help='fetch missing repositories at locked revisions')
    parser.add_argument('--jobs',type=int,default=8)
    args=parser.parse_args()
    if args.shared_session:
        if args.shared_argument_capture or args.shared_mixed_capture:parser.error('select one shared capture profile')
        from live_configured_capture import validate_session
        args.shared_session_data=validate_session(json.loads(args.shared_session.read_text()))
        args.shared_argument_capture=True
    if args.shared_mixed_capture:
        if args.shared_argument_capture:parser.error('select one shared capture profile')
        args.shared_argument_capture=True
    if args.shared_argument_capture:
        if args.parent_argument_session or args.argument_write_session or args.argument_write_state or args.argument_entry_state or args.const_argument_entry_state:
            parser.error('--shared-argument-capture selects its own locked current-process session')
        args.argument_write_session=True
    if args.parent_argument_session:
        if args.argument_write_session or args.argument_write_state or args.argument_entry_state or args.const_argument_entry_state:
            parser.error('select one argument-entry helper profile')
        args.argument_write_session=True
    if args.argument_write_session:
        if args.argument_write_state or args.argument_entry_state or args.const_argument_entry_state:
            parser.error('select one argument-entry helper profile')
        args.argument_write_state=True
    if args.argument_write_state:
        if args.argument_entry_state or args.const_argument_entry_state:parser.error('select one argument-entry helper profile')
        args.argument_entry_state=True
    if args.const_argument_entry_state:
        if args.argument_entry_state:parser.error('select one argument-entry helper profile')
        args.argument_entry_state=True
    if args.argument_entry_state:
        args.automated_entry_state=True
        if any((args.async_wait,args.file_operations,args.dup,args.close_lifecycle,args.uname,args.uname_faults,
                args.resource_limits,args.clocks,args.getscheduler,args.getscheduler_task,args.getgroups,
                args.getresuid,args.getresgid,args.setgroups_allocation_failures,args.setgroups_copy_failures,
                args.setgroups_partial_copy_failures)):
            parser.error('--argument-entry-state currently requires the default live workload')
    if args.uname_faults:args.uname=True
    if args.file_operations and (args.dup or args.close_lifecycle or args.uname or args.resource_limits or args.clocks or args.getscheduler or args.getscheduler_task or args.getgroups or args.getresuid or args.getresgid or args.setgroups_allocation_failures or args.setgroups_copy_failures or args.setgroups_partial_copy_failures):parser.error('--file-operations excludes other specialized capture profiles')
    if args.dup and (args.close_lifecycle or args.uname or args.resource_limits or args.clocks or args.getscheduler or args.getscheduler_task or args.getgroups or args.getresuid or args.getresgid or args.setgroups_allocation_failures or args.setgroups_copy_failures or args.setgroups_partial_copy_failures):parser.error('--dup excludes other specialized capture profiles')
    if args.close_lifecycle and (args.uname or args.resource_limits or args.clocks or args.getscheduler or args.getscheduler_task or args.getgroups or args.getresuid or args.getresgid or args.setgroups_allocation_failures or args.setgroups_copy_failures or args.setgroups_partial_copy_failures):parser.error('--close-lifecycle excludes other specialized capture profiles')
    if args.clocks and (args.getscheduler or args.getscheduler_task or args.getgroups or args.getresuid or args.getresgid or args.setgroups_allocation_failures or args.setgroups_copy_failures or args.setgroups_partial_copy_failures):parser.error('--clocks excludes other specialized capture profiles')
    if args.uname and (args.resource_limits or args.clocks or args.getscheduler or args.getscheduler_task or args.getgroups or args.getresuid or args.getresgid or args.setgroups_allocation_failures or args.setgroups_copy_failures or args.setgroups_partial_copy_failures):parser.error('--uname excludes other specialized capture profiles')
    if args.resource_limits and (args.clocks or args.getscheduler or args.getscheduler_task or args.getgroups or args.getresuid or args.getresgid or args.setgroups_allocation_failures or args.setgroups_copy_failures or args.setgroups_partial_copy_failures):parser.error('--resource-limits excludes other specialized capture profiles')
    from getresuid_capture import PROFILES
    if args.async_wait and any((args.automated_entry_state,args.file_operations,args.dup,args.close_lifecycle,
            args.uname,args.resource_limits,args.clocks,args.getscheduler,args.getscheduler_task,args.getgroups,
            args.getresuid,args.getresgid,args.setgroups_allocation_failures,args.setgroups_copy_failures,
            args.setgroups_partial_copy_failures)):
        parser.error('--async-wait excludes other specialized capture profiles')
    if args.getscheduler_task:args.getscheduler=True
    if args.getscheduler and (args.getgroups or args.getresuid or args.getresgid or args.setgroups_allocation_failures or args.setgroups_copy_failures or args.setgroups_partial_copy_failures):parser.error('--getscheduler excludes output query profiles and setgroups fault injection')
    selected_kind='getresgid' if args.getresgid else 'getresuid' if args.getresuid else None
    if args.credential_ids is not None:
        if selected_kind is None:parser.error('--credential-ids requires --getresuid or --getresgid')
        parts=args.credential_ids.split(',')
        if len(parts)!=2 or any(not re.fullmatch(r'(?:0[xX][0-9a-fA-F]+|[0-9]+)',v) for v in parts):parser.error('--credential-ids requires two unsigned decimal or hexadecimal IDs')
        args.credential_ids=[int(v,16 if v.lower().startswith('0x') else 10) for v in parts]
        if any(v>0xffffffff for v in args.credential_ids):parser.error('--credential-ids values must be in 0..UINT32_MAX')
    elif selected_kind:args.credential_ids=list(PROFILES[selected_kind]['values'])

    if args.credential_output_offsets is not None:
        if not (args.getresuid or args.getresgid):parser.error('--credential-output-offsets requires --getresuid or --getresgid')
        parts=args.credential_output_offsets.split(',')
        if len(parts)!=3 or any(not re.fullmatch(r'[0-9]+',v) for v in parts):parser.error('--credential-output-offsets requires three decimal offsets 0..12')
        args.credential_output_offsets=[int(v) for v in parts]
        if any(v>12 for v in args.credential_output_offsets):parser.error('--credential-output-offsets must fit four-byte outputs in a 16-byte witness (0..12)')
    else:args.credential_output_offsets=[0,4,8]

    if args.getresuid and (not args.automated_entry_state or args.getresgid or args.getgroups or args.setgroups_allocation_failures or args.setgroups_copy_failures or args.setgroups_partial_copy_failures):parser.error('--getresuid requires automated capture and successful setgroups; excludes --getgroups and --getresgid')
    if args.getresgid and (not args.automated_entry_state or args.getgroups or args.getresuid or args.setgroups_allocation_failures or args.setgroups_copy_failures or args.setgroups_partial_copy_failures):parser.error('--getresgid requires automated capture and successful setgroups; excludes --getgroups and --getresuid')
    if args.getgroups_copy_bytes is not None:
        if not args.getgroups or args.getgroups_copy_outcome!='success' or not 0<=args.getgroups_copy_bytes<4*args.getgroups_group_count:parser.error('--getgroups-copy-bytes requires --getgroups, default copy outcome and a prefix in 0..4*group_count-1')
        args.getgroups_copy_outcome='partial' 
    if args.getgroups_group_count!=3 and not args.getgroups:parser.error('--getgroups-group-count 1 or 2 requires --getgroups')
    if not 0<=args.getgroups_output_offset<=4:parser.error('--getgroups-output-offset must be in 0..4')
    if args.getgroups_output_offset and (not args.getgroups or args.getgroups_negative_sizes or args.getgroups_null_output or args.getgroups_null_boundaries):parser.error('--getgroups-output-offset requires --getgroups and excludes null/negative profiles')
    if not args.getgroups_group_count<=args.getgroups_output_size<=2147483647:parser.error('--getgroups-output-size must be between the group count and INT32_MAX')
    if args.getgroups_output_size!=4 and (not args.getgroups or args.getgroups_negative_sizes or args.getgroups_null_output or args.getgroups_null_boundaries):parser.error('--getgroups-output-size requires --getgroups and excludes null/negative profiles')
    if args.getgroups_negative_sizes and (not args.getgroups or args.getgroups_null_output or args.getgroups_null_boundaries or args.getgroups_allocation_failure or args.getgroups_copy_outcome!='success'):parser.error('--getgroups-negative-sizes requires --getgroups and excludes other argument modes and failure injection')
    if args.getgroups_null_output and (not args.getgroups or args.getgroups_allocation_failure or args.getgroups_copy_outcome!='success'):parser.error('--getgroups-null-output requires --getgroups and excludes failure injection')
    if args.getgroups_null_boundaries and (not args.getgroups or args.getgroups_null_output or args.getgroups_allocation_failure or args.getgroups_copy_outcome!='success'):parser.error('--getgroups-null-boundaries requires --getgroups and excludes other null modes and failure injection')
    if args.getgroups_allocation_failure and (not args.getgroups or args.getgroups_copy_outcome!='success'):parser.error('--getgroups-allocation-failure requires --getgroups and excludes copy-failure injection')
    if args.getgroups_copy_outcome!='success' and not args.getgroups:parser.error('--getgroups-copy-outcome requires --getgroups')
    if args.getgroups and (not args.automated_entry_state or args.setgroups_allocation_failures or args.setgroups_copy_failures or args.setgroups_partial_copy_failures):parser.error('--getgroups requires automated entry state and successful preceding setgroups calls')
    if args.setgroups_partial_copy_failures and (not args.automated_entry_state or args.setgroups_allocation_failures or args.setgroups_copy_failures):parser.error('--setgroups-partial-copy-failures requires automated capture and excludes other fault injection')
    if args.setgroups_copy_failures and (not args.automated_entry_state or args.setgroups_allocation_failures):parser.error('--setgroups-copy-failures requires automated entry state and excludes allocator injection')
    if args.setgroups_allocation_failures and not args.automated_entry_state:parser.error('--setgroups-allocation-failures requires --automated-entry-state')
    for name in ['kernel_root','input','out','llvm_bin']:
        if getattr(args,name): setattr(args,name,getattr(args,name).resolve())
    try: demo(args)
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        if isinstance(error,subprocess.CalledProcessError): print(error.stderr,file=sys.stderr)
        print(f'live LiteOS-A demo failed: {error}',file=sys.stderr);return 1
    return 0
if __name__=='__main__':sys.exit(main())
