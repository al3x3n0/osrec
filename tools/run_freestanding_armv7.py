#!/usr/bin/env python3
"""Observe a freestanding ARM/AArch64 image's RAM result record with guest services disabled."""
import argparse
import json
from pathlib import Path
import shutil
import os
import select
import struct
import subprocess
import tempfile
import time

RESULT_ADDRESS=0x40000000
RESULT_BYTES=128


def observe(image, qemu=None, descriptor=None, initial_memory_dir=None, load_bundle=None, check_cpu_entry=False, boot_from_el3=False, boot_bundle=None, memory_dumps=()):
    packaged_boot=None
    if boot_bundle is not None:
        if load_bundle is not None or descriptor is not None:raise ValueError('boot bundle cannot be combined with a replay bundle or descriptor')
        from rtl_boot_bundle import verify as verify_boot_bundle
        boot_bundle=Path(boot_bundle).resolve();packaged_boot=verify_boot_bundle(boot_bundle)
        load_bundle=boot_bundle/'replay';boot_from_el3=True
    from freestanding_elf import describe
    is_elf=image.read_bytes()[:4]==b'\x7fELF'
    layout=describe(image if is_elf else descriptor) if is_elf or descriptor else {
        'isa':'ARMv7-A A32','entry':0x40010000,'result_address':RESULT_ADDRESS,'raw_image_load_address':0x40010000}
    if 'load_segments' in layout:
        from image_memory import memory_contract,require_coverage,validate_raw
        require_coverage(memory_contract(layout)['required_ranges'],[{'address':0x40000000,'bytes':64*1024*1024}])
        if not is_elf:
            payload=validate_raw(image,descriptor,layout)
            require_coverage([{**payload,'purpose':'raw loader payload'}],[{'address':0x40000000,'bytes':64*1024*1024}])
    aarch64=layout['isa']=='AArch64'
    from image_memory import require_coverage
    if sum(d['bytes'] for d in memory_dumps)>16*1024*1024:raise ValueError('terminal memory observations exceed bound')
    for d in memory_dumps:
        if type(d['address']) is not int or type(d['bytes']) is not int or d['bytes']<=0:raise ValueError('invalid terminal memory observation')
        require_coverage([d],[{'address':0x40000000,'bytes':64*1024*1024}])
    if check_cpu_entry and (not aarch64 or initial_memory_dir is None):
        raise ValueError('CPU entry checking requires AArch64 and an initial memory directory')
    if boot_from_el3:
        if not check_cpu_entry:raise ValueError('EL3 boot requires CPU entry checking')
        from aarch64_boot import validate
        validate(layout,packaged_boot['entry'] if packaged_boot else 0x43f00000)
    banks=None
    initial_binary=None if is_elf else image
    if load_bundle is not None:
        if not aarch64:raise ValueError('QEMU addressed-bank execution currently requires AArch64')
        from rtl_load_bundle import verify
        load_bundle=Path(load_bundle).resolve();verify(load_bundle)
        if not is_elf or image.read_bytes()!=(load_bundle/'image.elf').read_bytes():
            raise ValueError('bundle source ELF differs from observer image')
        bundle_plan=json.loads((load_bundle/'load-plan.json').read_text());banks=bundle_plan['banks']
        if bundle_plan['loading_mode']=='raw':initial_binary=load_bundle/'image.bin'
    if initial_memory_dir is not None:
        if 'load_segments' not in layout:raise ValueError('initial memory verification requires an ELF descriptor')
        initial_memory_dir=Path(initial_memory_dir).resolve()
        initial_memory_dir.mkdir(parents=True,exist_ok=False)
    boot_plan=None
    if boot_from_el3:
        from aarch64_boot import build,verify as verify_boot
        if packaged_boot is None:boot_plan=build(layout,initial_memory_dir/'boot')
        else:
            target=initial_memory_dir/'boot';target.mkdir()
            for filename in ('boot.bin','boot-plan.json'):
                shutil.copyfile(boot_bundle/'boot'/filename,target/filename)
            boot_plan=verify_boot(layout,target)
    if qemu is None:qemu='qemu-system-aarch64' if aarch64 else 'qemu-system-arm'
    result_address=layout['result_address']
    # Only the image is supplied to the machine. QMP is an external testbench
    # memory observer/control channel; guest code has no connection to it.
    with tempfile.TemporaryDirectory(prefix='osrec-arm-image-') as name:
        stage=Path(name); copied=stage/'image.elf'; shutil.copy2(image,copied)
        memory=stage/'result.bin'
        if banks is not None:
            loaders=[part for bank in banks for part in
                ['-device',f'loader,file={load_bundle/bank["file"]},addr={bank["address"]},force-raw=on']]
            loaders+=['-device',f'loader,addr={layout["entry"]},cpu-num=0']
        elif not aarch64:loaders=['-kernel',str(copied)]
        elif is_elf:loaders=['-device',f'loader,file={copied},cpu-num=0']
        else:
            loaders=['-device',f'loader,file={copied},addr={layout["raw_image_load_address"]},force-raw=on',
                     '-device',f'loader,addr={layout["entry"]},cpu-num=0']
        if boot_from_el3:
            loaders+=['-device',f'loader,file={initial_memory_dir/"boot/boot.bin"},addr={boot_plan["entry"]},force-raw=on',
                      '-device',f'loader,addr={boot_plan["entry"]},cpu-num=0']
        machine='virt-9.2,secure=on,virtualization=on' if boot_from_el3 else 'virt-9.2,secure=off,virtualization=off'
        phase='before first replay instruction, after self-contained EL3 boot' if boot_from_el3 else 'before first instruction'
        command=[qemu,'-M',machine,'-cpu','cortex-a53' if aarch64 else 'cortex-a7',
                 '-accel','tcg','-smp','1','-m','64M','-nodefaults','-display','none',
                 '-serial','none','-monitor','none','-semihosting-config','enable=off',
                 '-S','-qmp','stdio',*loaders]
        if check_cpu_entry:
            register_pipe=stage/'registers'
            for suffix in ('.in','.out'):os.mkfifo(str(register_pipe)+suffix,0o600)
            command+=['-chardev',f'pipe,path={register_pipe},id=entryregs','-gdb','chardev:entryregs']
        with (stage/'qemu.log').open('wb') as log:
            process=subprocess.Popen(command,cwd=stage,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log)
            try:
                buffered=b''
                def read_message():
                    nonlocal buffered
                    deadline=time.monotonic()+5
                    while b'\n' not in buffered:
                        remaining=deadline-time.monotonic()
                        if remaining<=0 or not select.select([process.stdout],[],[],remaining)[0]:
                            raise ValueError('observer response timed out')
                        chunk=os.read(process.stdout.fileno(),65536)
                        if not chunk:raise ValueError('observer channel closed')
                        buffered+=chunk
                    line,buffered=buffered.split(b'\n',1)
                    return json.loads(line)
                greeting=read_message()
                if 'QMP' not in greeting:raise ValueError('invalid QMP greeting')
                sequence=0
                def request(name,arguments=None):
                    nonlocal sequence
                    sequence+=1;message={'execute':name,'id':sequence}
                    if arguments is not None:message['arguments']=arguments
                    process.stdin.write(json.dumps(message).encode()+b'\n');process.stdin.flush()
                    while True:
                        response=read_message()
                        if response.get('id')==sequence:
                            if 'error' in response:raise ValueError('observer request failed: '+str(response['error']))
                            return response.get('return')
                request('qmp_capabilities')
                def observe_boot(label):
                    from aarch64_boot import check_loaded
                    payload=boot_plan['payload'];path=initial_memory_dir/f'boot-{label}.bin'
                    request('pmemsave',{'val':payload['address'],'size':payload['bytes'],'filename':str(path)})
                    checked=check_loaded(layout,initial_memory_dir/'boot',
                        [{'address':0x40000000,'bytes':64*1024*1024}],[{'address':payload['address'],'file':path}])
                    checked.update(snapshot_phase_verified=True,snapshot_backend='QEMU TCG, CPU stopped',
                        snapshot_phase='before boot execution' if label=='reset' else phase)
                    return checked
                boot_memory=None
                cpu_report=None
                if check_cpu_entry:
                    from aarch64_entry_state import capture_qemu_entry,check_entry_state
                    if request('query-status')['running']:raise ValueError('CPU ran before entry observation')
                    cpus=request('query-cpus-fast')
                    if len(cpus)!=1 or cpus[0]['cpu-index']!=0:raise ValueError('entry observer requires one identified CPU')
                    cpu_path=cpus[0]['qom-path']
                    implementation={f'el{level}_implemented':request('qom-get',{'path':cpu_path,'property':f'has_el{level}'}) for level in (2,3)}
                    if boot_from_el3:
                        from aarch64_entry_state import EntryBreakpointController
                        controller=EntryBreakpointController(register_pipe)
                        try:
                            reset=controller.snapshot(implementation)
                            if not all(implementation.values()) or reset['pstate']&31!=13 or reset['pc']!=boot_plan['entry']:
                                raise ValueError('boot requires identified EL3 reset state with EL2/EL3 present')
                            (initial_memory_dir/'boot-reset-state.json').write_text(json.dumps(reset,indent=2)+'\n')
                            boot_memory={'before_boot':observe_boot('reset')}
                            controller.arm(layout['entry']);controller.run_and_remove()
                        finally:controller.close()
                    state=capture_qemu_entry(register_pipe,implementation)
                    if request('query-status')['running']:raise ValueError('CPU resumed during entry observation')
                    if boot_from_el3:boot_memory['at_replay_entry']=observe_boot('replay-entry')
                    state_path=initial_memory_dir/'cpu-entry-state.json'
                    state_path.write_text(json.dumps(state,indent=2)+'\n')
                    cpu_report=check_entry_state(layout,state)
                    cpu_report['snapshot_phase_verified']=True
                    cpu_report['snapshot_backend']='QEMU TCG, read-only register observer '+phase
                    if boot_from_el3:
                        cpu_report['boot_transition']={'plan':boot_plan,'stop_method':'external testbench hardware entry breakpoint; removed before replay'}
                    cpu_report['implementation_observation']={'backend':'QEMU QOM has_el2/has_el3',
                        'cpu_index':0,'qom_path':cpu_path}
                    cpu_report['implementation_presence_observed']=True
                initial_report=None
                if initial_memory_dir is not None:
                    from image_memory import merged_ranges
                    from check_image_memory import check
                    required=memory_contract(layout)['required_ranges']
                    if initial_binary is not None:
                        initial_payload=validate_raw(initial_binary,image if is_elf else descriptor,layout)
                        required=required+[{**initial_payload,'purpose':'raw loader payload'}]
                    dumps=[]
                    for i,(address,end) in enumerate(merged_ranges(required)):
                        path=initial_memory_dir/f'bank-{i}.bin'
                        request('pmemsave',{'val':address,'size':end-address,'filename':str(path)})
                        dumps.append({'address':address,'file':path})
                    ram=[{'address':0x40000000,'bytes':64*1024*1024}]
                    if load_bundle is not None:
                        from rtl_load_bundle import check_loaded
                        initial_report=check_loaded(load_bundle,ram,dumps)
                        initial_report['snapshot_phase_verified']=True
                    else:initial_report=check(image if is_elf else descriptor,ram,initial_binary,dumps)
                    initial_report['snapshot_backend']='QEMU TCG, CPU stopped '+phase
                    initial_report['snapshot_phase']='after loading all replay banks, '+phase
                    if boot_memory is not None:
                        initial_report['boot_memory_verification']=boot_memory
                    if packaged_boot is not None:
                        from rtl_load_bundle import file_hash
                        initial_report['boot_bundle_source']={'file':str(boot_bundle/'load-plan.json'),
                            'sha256':file_hash(boot_bundle/'load-plan.json'),'entry':packaged_boot['entry']}
                    if cpu_report is not None:
                        from rtl_load_bundle import file_hash
                        initial_report.update({'cpu_entry_state_verified':True,'cpu_entry_verification':cpu_report,
                            'cpu_state_file':{'file':str(state_path),'sha256':file_hash(state_path)},
                            'scope':'loaded memory and listed CPU entry fields observed '+phase+'; execution is not verified by this preflight'})
                        if load_bundle is not None:initial_report['format']='osrec-rtl-loaded-bundle-verification-v2'
                    (initial_memory_dir/'memory-preflight.json').write_text(json.dumps(initial_report,indent=2)+'\n')
                request('cont')
                deadline=time.monotonic()+5
                while True:
                    time.sleep(0.02);request('stop')
                    request('pmemsave',{'val':result_address,'size':RESULT_BYTES,'filename':str(memory)})
                    raw=memory.read_bytes()
                    if len(raw)!=RESULT_BYTES:raise ValueError('incomplete target result record')
                    words=struct.unpack('<32I',raw)
                    if words[0]==0x4f535243 and words[1] in range(1,31) and words[2] in (2,3):break
                    if time.monotonic()>deadline:raise ValueError('image did not publish a terminal RAM result')
                    request('cont')
                if words[1]==30:
                    from entry_state_result import transcript_bytes
                    size=transcript_bytes(words,layout.get('result_bytes'))
                    request('pmemsave',{'val':result_address,'size':size,'filename':str(memory)})
                    raw=memory.read_bytes()
                    if len(raw)!=size or raw[:RESULT_BYTES]!=struct.pack('<32I',*words):
                        raise ValueError('incomplete or changed entry-state transcript')
                elif layout.get('result_bytes',RESULT_BYTES)!=RESULT_BYTES:
                    raise ValueError('legacy result ABI requires a 128-byte result symbol')
                if words[2]==2:
                    for d in memory_dumps:
                        request('pmemsave',{'val':d['address'],'size':d['bytes'],'filename':str(Path(d['file']).resolve())})
                report={'format':'osrec-memory-result-v1','isa':layout['isa'],'abi_version':words[1],'status':words[2],'error':words[3],
                        'completed_calls':words[4],'initial_mask':words[5],'final_mask':words[6],
                        'locks':words[7],'unlocks':words[8],'process_accesses':words[9],
                        'actual_calls':[{'raw':words[10+2*i],'mask_after':words[11+2*i]} for i in range(6)],
                        'result_address':result_address,'semihosting_enabled':False,
                        'guest_host_services':False,'verification_backend':'QEMU TCG; no RTL/cycle timing validation'}
                if words[1]==30:
                    from entry_state_result import decode_transcript
                    for key in ('initial_mask','final_mask','locks','unlocks','process_accesses'):
                        del report[key]
                    report.update(decode_transcript(raw))
                if words[1] in (28,29):
                    for key in ('initial_mask','final_mask','locks','unlocks','process_accesses','actual_calls'):
                        del report[key]
                    report.update(session='linux_irq',expected_events=words[5],irq_count=words[6],
                                  expected_irqs=words[7],callback_calls=words[8],wake_calls=words[9],
                                  selected_tid=words[10],task_state=words[11],sleeper_task_cleared=bool(words[12]),
                                  resumes=words[13],max_irq_depth=words[14],irq_depth=words[15],
                                  expires_ns=words[16]|(words[17]<<32),soft_expires_ns=words[18]|(words[19]<<32),
                                  expiry_now_ns=words[20]|(words[21]<<32),current_tid=words[22],
                                  native_irq=words[23],phase=words[24],timer_removed=words[25])
                    if words[1]==29:
                        report.update(task_on_rq=words[26],task_on_cpu=words[27],activation_calls=words[28],
                                      wake_attempts=words[29],denied_wakes=words[30],state_guard_checks=words[31])
                if words[1]==27:
                    for key in ('initial_mask','final_mask','locks','unlocks','process_accesses','actual_calls'):
                        del report[key]
                    report.update(session='async_task',irq_count=words[5],max_irq_depth=words[6],
                                  nested_completions=words[7],wakeups=words[8],trace_bytes=words[9],
                                  remaining=words[10]|(words[11]<<32),return_value=words[12]|(words[13]<<32),
                                  trace_verified=bool(words[14]))
                if initial_report is not None:
                    report['initial_memory_verified']=True
                    report['initial_memory_report']=str(initial_memory_dir/'memory-preflight.json')
                if cpu_report is not None:report['cpu_entry_state_verified']=True
                if words[1] in (2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22):
                    for key in ('initial_mask','final_mask','locks','unlocks','process_accesses'):
                        del report[key]
                    signed=lambda bits:bits if bits<0x80000000 else bits-0x100000000
                if words[1]==3:
                    report.update({'session':'scalar','initial_pid':words[5],'pid_dependency_calls':words[6],
                                   'call_count':words[7],'last_invocation':words[8],
                                   'actual_calls':[{'raw':words[10+2*i] if words[11+2*i]==20 else signed(words[10+2*i]),
                                                    'number':words[11+2*i]} for i in range(7)]})
                if words[1]==2:
                    report.update({'session':'identity','dependencies_consumed':words[5],
                                   'dependency_count':words[6],'call_count':words[7],
                                   'last_invocation':words[8],
                                   'actual_calls':[{'raw':signed(words[10+2*i]),
                                                    'dependencies_consumed':words[11+2*i]} for i in range(7)]})
                if words[1]==4:
                    if words[9]>2:raise ValueError('read result has invalid file count')
                    report.update({'session':'read','call_count':words[5],'events_consumed':words[6],
                                   'kernel_errno':words[7],'user_errno':words[8],
                                   'file_positions':list(words[26:26+words[9]]),
                                   'memory':struct.pack('<2I',words[28],words[29]).hex(),
                                   'expected_events':words[30],
                                   'actual_calls':[{'raw':signed(words[10+4*i]),'return':signed(words[11+4*i]),
                                                    'errno':words[12+4*i],'recognized':words[13+4*i]} for i in range(4)]})
                if words[1]==5:
                    report.update({'session':'task','current_pid':words[5],'parent_pid':words[6],
                        'task_id':words[7],'process_accesses':words[8],'task_accesses':words[9],
                        'call_count':words[10],'parent_queries':words[11],'task_queries':words[12],
                        'last_invocation':words[22],
                        'actual_calls':[{'number':words[14+2*i],'raw':words[15+2*i]} for i in range(4)]})
                if words[1]==6:
                    report.update({'session':'credentials','effective_uid':words[5],'effective_gid':words[6],
                        'locks':words[7],'unlocks':words[8],'credential_accesses':words[9],
                        'lock_depth':words[10],'call_count':words[11],'current_pid':words[12],
                        'last_invocation':words[22],
                        'actual_calls':[{'number':words[14+2*i],'raw_bits':words[15+2*i]} for i in range(4)]})
                if words[1]==8:
                    if not 1<=words[5]<=7:raise ValueError('entry-state result has invalid call count')
                    if words[26] not in (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24):raise ValueError('entry-state result has invalid dynamic replay flag')
                    if words[26] in (2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22) and words[5]!=3:raise ValueError('bounded input result has invalid call count')
                    report.update({'session':'entry_state','call_count':words[5],'states_restored':words[6],
                        'states_verified':words[7],'last_invocation':words[8],'write_effects':bool(words[9]),
                        'continuous_replay':bool(words[24]),'entry_states_checked':words[25],
                        'actual_calls':[{'number':words[10+2*i],'raw_bits':words[11+2*i]} for i in range(words[5])]})
                    if not words[9]:report['unchanged_states']=words[7]
                    if words[26] and words[26] not in (23,24):report.update({'dynamic_object_replay':True,'allocations':words[27],
                        'releases':words[28],'copies':words[29],'live_objects':words[30],'address_reuses':words[31]})
                    if words[26] in (2,3,4,5):report.update({'bounded_input_replay':True,'user_copies':words[23]})
                    if words[26] in (3,4,5):report.update({'allocation_outcome_replay':True,'allocation_attempts':words[21],'allocation_failures':words[22]})
                    if words[26] in (4,5):report.update({'user_copy_outcome_replay':True,'user_copy_failures':words[20]})
                    if words[26]==5:report['user_copy_bytes']=words[19]
                    if words[26] in (6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22):report.update({'bounded_output_replay':True,'user_copies':words[23],'user_copy_bytes':words[19],'allocation_attempts':words[21],'allocation_failures':words[22],'locks':words[17],'unlocks':words[18]})
                    if words[26] in (7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22):report.update({'output_copy_outcome_replay':True,'user_copy_failures':words[20]})
                    if words[26] in (8,9,12,13,14,15,16,17,18,19,20,21,22):report['getgroups_allocation_outcome_replay']=True
                    if words[26]==23:report.update({'getresuid_replay':True,'user_copy_attempts':words[27],'user_copy_bytes':words[28],'locks':words[29],'unlocks':words[30],'credential_accesses':words[31]})
                    if words[26]==24:report.update({'getresgid_replay':True,'user_copy_attempts':words[27],'user_copy_bytes':words[28],'locks':words[29],'unlocks':words[30],'credential_accesses':words[31]})
                    if words[26] in (17,18,19,20,21,22):report['getgroups_argument_group_count']=1+(words[26]-17)%2
                    if words[26] in (9,17,18):report['getgroups_null_output_replay']=True
                    if words[26] in (10,19,20):report['getgroups_null_boundaries_replay']=True
                    if words[26] in (11,21,22):report['getgroups_negative_sizes_replay']=True
                    if words[26]==12:report['getgroups_single_group_replay']=True
                    if words[26]==13:report['getgroups_two_group_replay']=True
                    if words[26] in (14,15,16):report.update({'getgroups_copy_prefix_replay':True,'getgroups_copy_prefix_group_count':words[26]-13})
                if words[1]==10:
                    report.update({'session':'getscheduler_task','dependencies_consumed':words[5],
                        'dependency_count':words[6],'call_count':words[7],'last_invocation':words[8],
                        'bounds_checks':words[9],'task_lookups':words[10],'permission_checks':words[11],
                        'policy_callbacks':words[12],'locks':words[13],'unlocks':words[24],
                        'lock_depth':words[25],'syscall_number':words[26],'task_limit':words[27],
                        'actual_calls':[{'raw':signed(words[14+2*i]),'raw_bits':words[14+2*i],
                                         'dependencies_consumed':words[15+2*i]} for i in range(4)]})
                if words[1]==11:
                    report.update({'session':'clocks','provider_calls':words[5],'user_copies':words[6],
                        'user_copy_bytes':words[7],'dependencies_consumed':words[8],'call_count':words[9],
                        'output_states_verified':words[30],'errno_reads':words[31],
                        'actual_calls':[{'number':263 if i<5 else 264,'raw':signed(words[10+i]),
                            'raw_bits':words[10+i],'errno':words[20+i]} for i in range(10)]})
                if words[1]==26:
                    names=('call_count','completed_sessions','verified_calls','isolation_checks','restart_checks','input_rejections','return_value_checks','application_memory_checks','scalar_width','context_functions','state_objects','slice_runtime_abi','recipe_checks','completion_checks')
                    report.update(dict(zip(names,words[5:19])));report['session']='kernel-port-slices'
                    for k in ('actual_calls','initial_mask','final_mask','locks','unlocks','process_accesses'):report.pop(k,None)
                if words[1] in (23,24,25):
                    names=('call_count','pause_ordinal','completed_sessions','kernel_checkpoint_checks','routed_calls','application_exits','checkpoint_bytes','producer_state_address','current_state_address','application_assertion_checks','saved_frame_checks','gateway_abi','stack_guard_checks','application_frame_abi','checkpoint_rejections','checkpoint_abi','initial_memory_checks')
                    report.update(dict(zip(names,words[5:22])));report['session']='standalone-pause' if words[1]==23 else 'standalone-resume'
                    if words[1]==25:
                        if words[3]==99:report.update(fault_esr=words[28],fault_pc=words[29])
                        report['session']='standalone-advance';report.update(dict(zip(('checkpoint_start_ordinal','checkpoint_loads','checkpoint_saves'),words[22:25])))
                    for k in ('actual_calls','initial_mask','final_mask','locks','unlocks','process_accesses'):report.pop(k,None)
                if words[1] in (21,22):
                    names=('call_count','completed_sessions','initial_memory_checks','application_assertion_checks','routed_calls','application_exits','load_segments','executable_segments','unique_patches','snapshots','assertions','gateway_abi','stack_guard_checks','application_frame_abi')
                    report.update(dict(zip(names,words[5:19])));report['session']='imported-application';report.pop('actual_calls',None)
                    if words[1]==22:
                        report.update(dict(zip(('window_count','window_pauses','resume_checks','state_progress_checks','completed_windows','window_call_limit'),words[19:25])))
                        report['session']='application-windows'
                if words[1] in (18,19,20):
                    names=('call_count','verified_calls','interleaved_calls','restarted_calls','input_rejections','isolation_checks','app_buffer_checks','return_hash_a','return_hash_b','expected_return_hash','dependencies_consumed','divergences_returned','poison_rejections','recovery_restores','completion_rejections','event_count','returning_calls','file_length_a','file_length_b','references_released','wide_app_addresses','captured_scalar_width','session_count','context_functions','state_objects','completed_sessions','slice_runtime_abi')
                    report.update(dict(zip(names,words[5:32])));report['session']='callable-slices';report.pop('actual_calls',None)
                    if words[1]==19:
                        report['session']='application-frames';report['preserved_frames']=report.pop('context_functions');report['register_abi_variants']=report.pop('state_objects');report['application_frame_abi']=report.pop('slice_runtime_abi')
                    if words[1]==20:
                        report['session']='cpu-gateway';report['hardware_frame_checks']=report.pop('context_functions');report['container_restore_checks']=report.pop('state_objects');report['gateway_abi']=report.pop('slice_runtime_abi');report['stack_guard_checks']=report.pop('wide_app_addresses');report['gateway_paths_verified']=report.pop('completion_rejections')
                if words[1]==17:
                    names=('dependencies_consumed','event_count','buffers_verified','states_verified','path_balance','return_hash','expected_return_hash','range_checks','errno_reads','user_copies','user_copy_bytes','read_providers','read_bytes','write_providers','write_bytes','file_length','file_word','references_a','references_b','vm_lock_depth','system_a','system_b','stat_size','kstat_size','extent','free_slots','call_count')
                    report.update(dict(zip(names,words[5:32])));report['session']='files';report.pop('actual_calls',None)
                if words[1]==16:
                    report.update({'session':'dup','lookup_calls':words[5],'allocation_attempts':words[6],
                        'reference_calls':words[7],'association_calls':words[8],'dependencies_consumed':words[9],
                        'final_references':words[20],'final_maps':list(words[21:24]),'final_allocated_bits':words[24],
                        'final_cloexec_bits':words[25],'system_fd_limit':words[26],'initial_system_fd':words[27],
                        'call_count':words[28],'syscall_number':words[29],'state_witnesses_verified':words[30],
                        'actual_calls':[{'raw':signed(words[10+i]),'raw_bits':words[10+i],'errno':words[15+i]} for i in range(5)]})
                if words[1]==15:
                    report.update({'session':'close','detach_calls':words[5],'provider_calls':words[6],
                        'restore_calls':words[7],'free_calls':words[8],'dependencies_consumed':words[9],
                        'final_map_bits':words[20],'final_allocated':words[21],'final_cloexec':words[22],
                        'final_system_live':words[23],'call_count':words[24],'syscall_number':words[25],
                        'initial_system_fd':words[26],'errno_reads':words[29],'state_witnesses_verified':words[30],
                        'actual_calls':[{'raw':signed(words[10+i]),'raw_bits':words[10+i],'errno':words[15+i]} for i in range(5)]})
                if words[1] in (13,14):
                    count=8 if words[1]==14 else 4
                    report.update({'session':'uname','provider_calls':words[5],'input_copies':words[6],
                        'output_copies':words[7],'user_copy_bytes':words[8],'dependencies_consumed':words[9],
                        'call_count':words[10+2*count],'syscall_number':words[11+2*count],'identity_size':words[12+2*count],
                        'output_states_verified':words[30],
                        'actual_calls':[{'raw':signed(words[10+i]),'raw_bits':words[10+i],'errno':words[10+count+i]} for i in range(count)]})
                if words[1]==12:
                    report.update({'session':'rlimit','provider_calls':words[5],'user_copies':words[6],
                        'user_copy_bytes':words[7],'dependencies_consumed':words[8],'call_count':words[22],
                        'syscall_number':words[23],'output_states_verified':words[30],
                        'actual_calls':[{'resource_bits':words[24+i],'raw':signed(words[10+i]),
                            'raw_bits':words[10+i],'errno':words[16+i]} for i in range(6)]})
                if words[1]==9:
                    report.update({'session':'getscheduler','dependencies_consumed':words[5],
                        'dependency_count':words[6],'call_count':words[7],'last_invocation':words[8],
                        'pid_queries':words[9],'scheduler_queries':words[10],'policy_writes':words[11],
                        'syscall_number':words[26],
                        'actual_calls':[{'raw':signed(words[14+2*i]),'raw_bits':words[14+2*i],
                                         'dependencies_consumed':words[15+2*i]} for i in range(4)]})
                if words[1]==7:
                    report.update({'session':'getpriority','dependencies_consumed':words[5],
                        'dependency_count':words[6],'call_count':words[7],'last_invocation':words[8],
                        'pid_queries':words[9],'priority_queries':words[10],'syscall_number':words[26],
                        'actual_calls':[{'raw':signed(words[14+2*i]),'raw_bits':words[14+2*i],
                                         'dependencies_consumed':words[15+2*i]} for i in range(6)]})
                return report,raw
            except Exception as error:
                log.flush()
                detail=(stage/'qemu.log').read_text(errors='replace')
                raise ValueError(f'freestanding execution failed: {error}; {detail}') from error
            finally:
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
                process.stdin.close();process.stdout.close()


def require_success(report):
    passed=report['status']==2 and report['error']==0
    if report.get('abi_version',1)==1:
        passed=passed and report['completed_calls']==6 and report['locks']==6 and report['unlocks']==6 and report['process_accesses']==12
    elif report['abi_version'] in (28,29):
        passed=passed and 13<=report['expected_events']<=4096 and report['completed_calls']==report['expected_events'] and 1<=report['expected_irqs']<=4096 and report['irq_count']==report['expected_irqs'] and report['callback_calls']==report['wake_calls']==report['resumes']==1 and report['selected_tid']==report['current_tid']==1 and report['task_state']==report['irq_depth']==0 and report['max_irq_depth']==1 and report['sleeper_task_cleared'] and report['phase']==5 and report['timer_removed']==1 and report['expires_ns']-report['soft_expires_ns']==50000 and report['expiry_now_ns']>=report['expires_ns']
        if report['abi_version']==29:
            passed=passed and report['task_on_rq']==report['task_on_cpu']==report['activation_calls']==report['denied_wakes']==1 and report['wake_attempts']==2 and report['state_guard_checks']==6
    elif report['abi_version']==27:
        passed=passed and report['completed_calls']==13 and report['irq_count']==2 and report['max_irq_depth']==2 and report['nested_completions']==1 and report['wakeups']==1 and report['trace_bytes']==1176 and report['trace_verified']
    elif report['abi_version'] in (8,30):
        count=report['call_count']
        from entry_state_result import MAX_CALLS
        valid_count=1<=count<=7 if report['abi_version']==8 else 7<count<=MAX_CALLS
        passed=passed and valid_count and report['completed_calls']==count and report['states_restored']==(1 if report['continuous_replay'] else count) and report['entry_states_checked']==(count if report['continuous_replay'] else 0) and report['states_verified']==count and report['last_invocation']==count-1
        if report.get('getresuid_replay') or report.get('getresgid_replay'):
            number=211 if report.get('getresgid_replay') else 209
            passed=passed and count==4 and report['actual_calls']==[{'number':number,'raw_bits':v} for v in (0,0xfffffff2,0xfffffff2,0xfffffff2)] and report['user_copy_attempts']==9 and report['user_copy_bytes']==24 and report['locks']==report['unlocks']==4 and report['credential_accesses']==12
        if report.get('dynamic_object_replay'):
            allocations=report['allocations']
            if report.get('getgroups_null_boundaries_replay') or report.get('getgroups_negative_sizes_replay'):
                group_count=report.get('getgroups_argument_group_count',3)
                middle=0xffffffea if report.get('getgroups_negative_sizes_replay') else group_count
                passed=passed and count==3 and report['actual_calls']==[{'number':205,'raw_bits':v} for v in (group_count,middle,0xfffffff2)]
                passed=passed and report['live_objects']==1 and report['locks']==report['unlocks']==3
                passed=passed and all(report[k]==0 for k in ('allocation_attempts','allocation_failures','allocations','releases','copies','user_copies','user_copy_bytes','user_copy_failures','address_reuses'))
            elif report.get('bounded_output_replay'):
                last=report['actual_calls'][-1]['raw_bits']
                failure=last==0xfffffff2
                allocation_failure=last==0xfffffff4
                group_count=report.get('getgroups_argument_group_count') or report.get('getgroups_copy_prefix_group_count') or (1 if report.get('getgroups_single_group_replay') else 2 if report.get('getgroups_two_group_replay') else 3)
                width=4*group_count
                allowed=(group_count,)+( (0xfffffff2,) if report.get('output_copy_outcome_replay') else () )+( (0xfffffff4,) if report.get('getgroups_allocation_outcome_replay') else () )
                middle=group_count if group_count==1 else 0xfffffff2 if report.get('getgroups_null_output_replay') else 0xffffffea
                if report.get('getgroups_null_output_replay'):passed=passed and last==group_count
                passed=passed and count==3 and report['actual_calls']==[{'number':205,'raw_bits':v} for v in (group_count,middle,last)] and last in allowed
                if report.get('output_copy_outcome_replay'):passed=passed and report['user_copy_failures']==int(failure)
                expected=int(not allocation_failure)
                copied=tuple(range(width)) if report.get('getgroups_copy_prefix_replay') else (0,) if allocation_failure else (0,width//2) if failure else (width,)
                if report.get('getgroups_copy_prefix_replay'):passed=passed and failure and not allocation_failure
                passed=passed and report['allocation_attempts']==1 and allocations==report['releases']==report['copies']==report['user_copies']==expected and report['allocation_failures']==int(allocation_failure) and report['user_copy_bytes'] in copied and report['live_objects']==1 and report['locks']==report['unlocks']==3
            elif report.get('allocation_outcome_replay'):
                successes=sum(c['raw_bits']==0 for c in report['actual_calls'])
                allowed=(0,0xfffffff4,0xfffffff2) if report.get('user_copy_outcome_replay') else (0,0xfffffff4)
                passed=passed and all(c['raw_bits'] in allowed for c in report['actual_calls']) and report['allocation_failures']==sum(c['raw_bits']==0xfffffff4 for c in report['actual_calls'])
                if report.get('user_copy_outcome_replay'):passed=passed and report['user_copy_failures']==sum(c['raw_bits']==0xfffffff2 for c in report['actual_calls'])
                if 'user_copy_bytes' in report:passed=passed and 0<=report['user_copy_bytes']<=8*report['user_copies']
                passed=passed and report['allocation_attempts']==allocations+report['allocation_failures'] and report['allocation_attempts']<=2*count
                passed=passed and allocations==successes+report['user_copies'] and report['releases']==allocations and successes<=report['copies']<=2*successes and report['live_objects']==1
            else:
                passed=passed and count<=allocations<=2*count and report['releases']==allocations and report['copies']==allocations and report['live_objects']==1
                if report.get('bounded_input_replay'):passed=passed and report['user_copies']==allocations-count
                else:passed=passed and allocations==count
    elif report['abi_version']==26:
        count=report['call_count']
        checks=dict(completed_calls=3*count,completed_sessions=3,verified_calls=3*count,isolation_checks=2*count,restart_checks=1,return_value_checks=3*count,application_memory_checks=3*count,slice_runtime_abi=1,recipe_checks=3*count,completion_checks=3)
        passed=passed and 0<count<=65536 and all(report.get(k)==v for k,v in checks.items()) and report['input_rejections']>0 and report['scalar_width'] in (32,64) and report['context_functions']>0 and report['state_objects']>0
    elif report['abi_version']==25:
        count=report['call_count'];start=report['checkpoint_start_ordinal'];pause=report['pause_ordinal'];calls=2*(pause-start)
        checks=dict(completed_calls=calls,routed_calls=calls,completed_sessions=2,kernel_checkpoint_checks=4,application_exits=2,application_assertion_checks=0,saved_frame_checks=2,gateway_abi=2,stack_guard_checks=2,application_frame_abi=1,checkpoint_abi=1,initial_memory_checks=2,checkpoint_loads=2,checkpoint_saves=2)
        passed=passed and 0<start<pause<count<=65536 and 64<report['checkpoint_bytes']<=65600 and report['producer_state_address']!=report['current_state_address'] and all(report.get(k)==v for k,v in checks.items())
    elif report['abi_version'] in (23,24):
        count=report['call_count'];pause=report['pause_ordinal'];resume=report['abi_version']==24;runs=2 if resume else 1;calls=runs*(count-pause) if resume else pause
        checks=dict(completed_calls=calls,routed_calls=calls,completed_sessions=runs,kernel_checkpoint_checks=runs,application_exits=runs,application_assertion_checks=2 if resume else 0,saved_frame_checks=runs,gateway_abi=2,stack_guard_checks=runs,application_frame_abi=1,checkpoint_abi=1,initial_memory_checks=runs)
        passed=passed and 0<pause<count<=65536 and 64<report['checkpoint_bytes']<=65600 and all(report.get(k)==v for k,v in checks.items())
        if resume:passed=passed and report['producer_state_address']!=report['current_state_address']
    elif report['abi_version'] in (21,22):
        count=report['call_count']
        checks={'completed_calls':2*count,'routed_calls':2*count,'completed_sessions':2,'initial_memory_checks':2,'application_assertion_checks':2,'application_exits':2,'gateway_abi':2,'stack_guard_checks':2,'application_frame_abi':1}
        if report['abi_version']==22:
            limit=report['window_call_limit'];windows=(count+limit-1)//limit if limit else 0
            checks.update(window_count=windows,window_pauses=2*(windows-1),resume_checks=2*(windows-1),state_progress_checks=2*windows,completed_windows=2*windows,stack_guard_checks=2*windows)
            passed=passed and 0<limit<=65536
        passed=passed and 0<count<=65536 and all(report.get(k)==v for k,v in checks.items()) and 0<report['executable_segments']<=report['load_segments']<=4096 and 1<report['unique_patches']<=count+1
    elif report['abi_version'] in (18,19,20):
        count=report['call_count'];expected=report['expected_return_hash'];events=report['event_count']
        checks={'completed_calls':3*count,'verified_calls':3*count,'interleaved_calls':2*count,'restarted_calls':count,'input_rejections':10 if report['abi_version']==20 else 20 if report['abi_version']==19 else 8,'isolation_checks':2*count,'app_buffer_checks':3*count,'return_hash_a':expected,'return_hash_b':expected,'dependencies_consumed':2*events,'divergences_returned':1,'poison_rejections':1,'recovery_restores':1,'completion_rejections':1,'returning_calls':3*count,'references_released':1,'wide_app_addresses':1,'session_count':2,'completed_sessions':3}
        if report['abi_version']==20:
            checks.pop('wide_app_addresses');checks.pop('completion_rejections');checks.update(gateway_paths_verified=15,hardware_frame_checks=3*count,container_restore_checks=3*count,stack_guard_checks=3*count)
            passed=passed and report['gateway_abi'] in (1,2)
        elif report['abi_version']==19:checks.update(preserved_frames=3*count,register_abi_variants=2,application_frame_abi=1)
        else:checks.update(slice_runtime_abi=1)
        passed=passed and 0<count<=65536 and 0<events<=1048576 and all(report.get(k)==v for k,v in checks.items()) and (report['abi_version'] in (19,20) or (report['context_functions']>0 and report['state_objects']>0)) and report['captured_scalar_width'] in (32,64)
    elif report['abi_version']==17:
        from file_profile import CASES
        expected=2166136261
        for _,_,raw,_ in CASES:expected=((expected^(raw&0xffffffff))*16777619)&0xffffffff
        checks={'completed_calls':32,'call_count':32,'dependencies_consumed':94,'event_count':94,'buffers_verified':32,'states_verified':32,'path_balance':0,'return_hash':expected,'expected_return_hash':expected,'range_checks':11,'errno_reads':7,'user_copies':7,'user_copy_bytes':240,'read_providers':3,'read_bytes':8,'write_providers':3,'write_bytes':6,'file_length':4,'file_word':0x59586261,'references_a':0,'references_b':0,'vm_lock_depth':0,'stat_size':152,'kstat_size':104,'extent':8,'free_slots':3}
        passed=passed and all(report.get(k)==v for k,v in checks.items()) and 3<=report['system_a']<65536 and 3<=report['system_b']<65536 and report['system_a']!=report['system_b']
    elif report['abi_version']==16:
        passed=passed and report['completed_calls']==report['call_count']==report['state_witnesses_verified']==5
        passed=passed and (report['lookup_calls'],report['allocation_attempts'],report['reference_calls'],report['association_calls'],report['dependencies_consumed'],report['final_references'],report['final_allocated_bits'],report['final_cloexec_bits'],report['syscall_number'])==(5,3,2,2,12,3,7,1,41)
        passed=passed and 8<=report['system_fd_limit']<=65536 and 3<=report['initial_system_fd']<report['system_fd_limit'] and report['final_maps']==[report['initial_system_fd']]*3
        passed=passed and report['actual_calls']==[{'raw':v,'raw_bits':v&0xffffffff,'errno':0} for v in (-24,5,6,-9,-9)]
    elif report['abi_version']==15:
        passed=passed and report['completed_calls']==report['call_count']==report['state_witnesses_verified']==5
        passed=passed and (report['detach_calls'],report['provider_calls'],report['restore_calls'],report['free_calls'],report['dependencies_consumed'],report['errno_reads'],report['syscall_number'])==(5,5,4,1,15,4,6)
        passed=passed and (report['final_map_bits'],report['final_allocated'],report['final_cloexec'],report['final_system_live'])==(0xffffffff,0,0,0) and 3<=report['initial_system_fd']<1024
        passed=passed and report['actual_calls']==[{'raw':v,'raw_bits':v&0xffffffff,'errno':-v} for v in (-5,0,-9,-9,-9)]
    elif report['abi_version']==14:
        passed=passed and report['completed_calls']==report['call_count']==report['output_states_verified']==8
        passed=passed and (report['provider_calls'],report['input_copies'],report['output_copies'],report['user_copy_bytes'],report['dependencies_consumed'],report['syscall_number'],report['identity_size'])==(5,8,4,3120,17,122,390)
        passed=passed and report['actual_calls']==[{'raw':v,'raw_bits':v&0xffffffff,'errno':0} for v in (0,0,-14,-14,-14,-5,-14,-14)]
    elif report['abi_version']==13:
        passed=passed and report['completed_calls']==report['call_count']==report['output_states_verified']==4
        passed=passed and (report['provider_calls'],report['input_copies'],report['output_copies'],report['user_copy_bytes'],report['dependencies_consumed'],report['syscall_number'],report['identity_size'])==(2,4,2,1560,8,122,390)
        passed=passed and report['actual_calls']==[{'raw':v,'raw_bits':v&0xffffffff,'errno':0} for v in (0,0,-14,-14)]
    elif report['abi_version']==12:
        passed=passed and report['completed_calls']==report['call_count']==report['output_states_verified']==6 and report['provider_calls']==6 and report['user_copies']==4 and report['user_copy_bytes']==32 and report['dependencies_consumed']==10 and report['syscall_number']==191
        passed=passed and [c['raw'] for c in report['actual_calls']]==[0,0,-22,-14,-14,-22] and [c['errno'] for c in report['actual_calls']]==[0]*6 and [c['resource_bits'] for c in report['actual_calls']]==[7,1,0xffffffff,7,7,0]
    elif report['abi_version']==11:
        expected=[0,0,-22,-22,-14]*2
        passed=passed and report['completed_calls']==report['call_count']==report['output_states_verified']==10 and report['provider_calls']==8 and report['user_copies']==6 and report['user_copy_bytes']==64 and report['dependencies_consumed']==14 and report['errno_reads']==2
        passed=passed and [c['raw'] for c in report['actual_calls']]==expected and [c['errno'] for c in report['actual_calls']]==[abs(v) for v in expected]
    elif report['abi_version']==10:
        passed=passed and report['completed_calls']==4 and report['call_count']==4 and report['last_invocation']==3 and report['dependencies_consumed']==report['dependency_count']==8 and report['bounds_checks']==4 and report['task_lookups']==report['permission_checks']==3 and report['policy_callbacks']==1 and report['locks']==report['unlocks']==3 and report['lock_depth']==0 and report['syscall_number']==157 and report['task_limit']==128
        calls=report['actual_calls']
        passed=passed and [c['dependencies_consumed'] for c in calls]==[3,4,6,8] and [c['raw_bits'] for c in calls[1:]]==[0xffffffea,0xffffffea,0xffffffff] and calls[0]['raw_bits'] in (0,1,2,3,6)
    elif report['abi_version']==9:
        passed=passed and report['completed_calls']==4 and report['call_count']==4 and report['last_invocation']==3 and report['dependencies_consumed']==report['dependency_count']==5 and report['pid_queries']==1 and report['scheduler_queries']==4 and report['policy_writes']==2 and report['syscall_number']==157
        calls=report['actual_calls']
        passed=passed and [c['dependencies_consumed'] for c in calls]==[2,3,4,5] and [c['raw_bits'] for c in calls[2:]]==[0xffffffea,0xfffffffd] and calls[0]['raw_bits']==calls[1]['raw_bits'] and calls[0]['raw_bits'] in (0,1,2,6)
    elif report['abi_version']==7:
        passed=passed and report['completed_calls']==6 and report['call_count']==6 and report['last_invocation']==5 and report['dependencies_consumed']==report['dependency_count'] and report['pid_queries']==4 and report['priority_queries']==6 and report['syscall_number']==96
    elif report['abi_version']==6:
        passed=passed and report['completed_calls']==4 and report['call_count']==4 and report['last_invocation']==3 and report['locks']==4 and report['unlocks']==4 and report['credential_accesses']==4 and report['lock_depth']==0
    elif report['abi_version']==5:
        passed=passed and report['completed_calls']==4 and report['call_count']==4 and report['last_invocation']==3 and report['process_accesses']==2 and report['task_accesses']==2 and report['parent_queries']==2 and report['task_queries']==2
    elif report['abi_version']==4:
        passed=passed and report['completed_calls']==4 and report['call_count']==4 and report['events_consumed']==report['expected_events']
    elif report['abi_version']==3:
        passed=passed and report['completed_calls']==7 and report['call_count']==7 and report['last_invocation']==6 and report['pid_dependency_calls']==1
    elif report['abi_version']==2:
        passed=passed and report['completed_calls']==7 and report['call_count']==7 and report['last_invocation']==6 and report['dependencies_consumed']==report['dependency_count']
    else:
        passed=False
    if not passed:
        raise ValueError('target replay diverged: '+json.dumps(report,sort_keys=True))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image',type=Path,nargs='?');parser.add_argument('--qemu')
    parser.add_argument('--load-bundle',type=Path,help='load addressed bank files from a verified AArch64 bundle')
    parser.add_argument('--boot-bundle',type=Path,help='load a combined EL3 boot/replay bundle without rebuilding; requires --check-entry-state')
    parser.add_argument('--descriptor',type=Path,help='ELF loading contract for a raw binary')
    parser.add_argument('--initial-memory-dir',type=Path,help='new directory for pre-execution physical dumps and loader verification report')
    parser.add_argument('--check-entry-state',action='store_true',help='also observe/check bounded AArch64 entry registers; requires --initial-memory-dir')
    parser.add_argument('--boot-from-el3',action='store_true',help='build/run a guest EL3 to EL1 shim with EL2/EL3 implemented; requires --check-entry-state')
    args=parser.parse_args()
    if sum(x is not None for x in (args.image,args.load_bundle,args.boot_bundle))!=1:parser.error('supply an image, --load-bundle or --boot-bundle')
    if (args.load_bundle or args.boot_bundle) and args.descriptor:parser.error('--descriptor is only for a raw image')
    image=args.image if args.image is not None else args.boot_bundle/'replay/image.elf' if args.boot_bundle else args.load_bundle/'image.elf'
    report,_=observe(image,args.qemu,args.descriptor,args.initial_memory_dir,args.load_bundle,args.check_entry_state,args.boot_from_el3,args.boot_bundle);require_success(report)
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
