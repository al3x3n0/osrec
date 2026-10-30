#!/usr/bin/env python3
"""Export a Linux IRQ/wait trace to a standalone AArch64 timer-interrupt replay."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import struct
import tempfile

from capture_linux_aarch64 import ROOT, digest
from capture_linux_irq import parse_output, block, parse_layout, parse_timer_layout, parse_base_layout, parse_offsets_layout, parse_timekeeper_layout
from linux_irq_trace import decode, pack
from freestanding_armv7 import audit, run
from freestanding_elf import prepare_target, target_metadata
from run_freestanding_armv7 import observe, require_success

INTEGRATION = ROOT/'integrations/linux_aarch64/irq-wait'


def load_capture(path):
    path = Path(path).resolve()
    manifest = json.loads((path/'capture.manifest.json').read_text())
    if manifest.get('format')!='osrec-linux-irq-capture-v1' or manifest.get('status')!='native_trace_captured':
        raise ValueError('not a native Linux IRQ capture')
    actual = {str(p.relative_to(path)) for p in path.rglob('*') if p.is_file() and p!=path/'capture.manifest.json'}
    if actual != set(manifest['artifact_sha256']):
        raise ValueError('Linux IRQ capture artifact set differs')
    for name, expected in manifest['artifact_sha256'].items():
        if digest((path/name).read_bytes()) != expected:
            raise ValueError('Linux IRQ capture artifact changed: '+name)
    result, trace, stats, formats = parse_output((path/'qemu.log').read_text(errors='replace'))
    if result!=manifest['result'] or result!=json.loads((path/'result.json').read_text()) or trace!=(path/'trace.txt').read_text() or stats!=(path/'trace-stats.txt').read_text() or formats!=json.loads((path/'event-formats.json').read_text()):
        raise ValueError('Linux IRQ parsed observations differ from native log')
    if manifest.get('task_state_capture',False)!=result.get('task_state_capture',False):
        raise ValueError('Linux task-state capture manifest mode differs')
    if result.get('task_state_capture'):
        log=(path/'qemu.log').read_text(errors='replace').replace('\r\n','\n')
        if (path/'probe-definitions.txt').read_text()!=block(log,'PROBES') or (path/'probe-profile.txt').read_text()!=block(log,'PROFILE'):
            raise ValueError('Linux task-state metadata differs from native log')
    if manifest.get('sleeper_state_capture',False)!=result.get('sleeper_state_capture',False):
        raise ValueError('Linux sleeper capture manifest mode differs')
    if manifest.get('timer_state_capture',False)!=result.get('timer_state_capture',False):
        raise ValueError('Linux timer capture manifest mode differs')
    if result.get('sleeper_state_capture'):
        layout=parse_layout(log)
        if json.loads((path/'btf-layout.json').read_text())!=layout or manifest.get('sleeper_layout')!=layout:
            raise ValueError('Linux sleeper BTF layout differs from native log')
    if manifest.get('timer_return_capture',False)!=result.get('timer_return_capture',False):
        raise ValueError('Linux timer return capture manifest mode differs')
    if result.get('timer_return_capture'):
        timer_layout=parse_timer_layout(log)
        if json.loads((path/'timer-layout.json').read_text())!=timer_layout or manifest.get('timer_return_layout')!=timer_layout:
            raise ValueError('Linux timer return BTF layout differs from native log')
    if manifest.get('base_state_capture',False)!=result.get('base_state_capture',False):
        raise ValueError('Linux base-state capture manifest mode differs')
    if result.get('base_state_capture'):
        base_layout=parse_base_layout(log,timer_layout)
        if json.loads((path/'base-layout.json').read_text())!=base_layout or manifest.get('base_state_layout')!=base_layout:
            raise ValueError('Linux base-state BTF layout differs from native log')
    if manifest.get('outer_state_capture',False)!=result.get('outer_state_capture',False):
        raise ValueError('Linux outer-state capture manifest mode differs')
    if manifest.get('clock_state_capture',False)!=result.get('clock_state_capture',False):
        raise ValueError('Linux clock-state capture manifest mode differs')
    offsets_layout=None
    flag=manifest.get('clock_offsets_capture',False)
    if type(flag) is not bool or flag!=result.get('clock_offsets_capture',False):
        raise ValueError('Linux clock-offsets capture manifest mode differs')
    if flag:
        offsets_layout=parse_offsets_layout(log,timer_layout,base_layout)
        if json.loads((path/'clock-offsets-layout.json').read_text())!=offsets_layout or manifest.get('clock_offsets_layout')!=offsets_layout:
            raise ValueError('Linux clock-offsets BTF layout differs from native log')
    flag=manifest.get('clock_entry_capture',False)
    if type(flag) is not bool or flag!=result.get('clock_entry_capture',False):
        raise ValueError('Linux clock-entry capture manifest mode differs')
    flag=manifest.get('timekeeper_layout_capture',False)
    if type(flag) is not bool or flag!=result.get('timekeeper_layout_capture',False):
        raise ValueError('Linux timekeeper layout capture manifest mode differs')
    if flag:
        provider_layout=parse_timekeeper_layout(log)
        if json.loads((path/'timekeeper-layout.json').read_text())!=provider_layout or manifest.get('timekeeper_layout')!=provider_layout:
            raise ValueError('Linux timekeeper BTF layout differs from native log')
        supported=b'CONFIG_KALLSYMS_ALL=y' in (path/'kernel.config').read_bytes().splitlines()
        if type(manifest.get('timekeeper_data_symbol_lookup_supported')) is not bool or manifest['timekeeper_data_symbol_lookup_supported']!=supported:
            raise ValueError('Linux timekeeper data-symbol capability differs from native config')
    return decode(trace,result,stats,offsets_layout), manifest


def source_identity():
    identity = json.loads((INTEGRATION/'source-identity.json').read_text())
    raw = (INTEGRATION/'hrtimer_wakeup.c').read_bytes()
    body = raw[raw.index(b'static enum'):].rstrip(b'\n')
    if digest(raw)!=identity['excerpt_sha256'] or digest(body)!=identity['function_sha256']:
        raise ValueError('reviewed Linux IRQ callback source changed')
    scheduler = json.loads((INTEGRATION/'scheduler-source-identity.json').read_text())
    if set(scheduler['files'])!={'sched_state.c','sched_wakeup.c','sched_queue.c'}:
        raise ValueError('reviewed Linux scheduler source set differs')
    for name, entry in scheduler['files'].items():
        if digest((INTEGRATION/name).read_bytes())!=entry['excerpt_sha256']:
            raise ValueError('reviewed Linux scheduler source changed: '+name)
    timer=json.loads((INTEGRATION/'timer-source-identity.json').read_text())
    if timer['file']!='timer_sleeper.c' or digest((INTEGRATION/timer['file']).read_bytes())!=timer['excerpt_sha256']:
        raise ValueError('reviewed Linux timer constructor source changed')
    timer_queue=json.loads((INTEGRATION/'timer-queue-source-identity.json').read_text())
    if timer_queue['file']!='timer_queue.c' or digest((INTEGRATION/timer_queue['file']).read_bytes())!=timer_queue['excerpt_sha256']:
        raise ValueError('reviewed Linux timer queue source changed')
    timer_run=json.loads((INTEGRATION/'timer-run-source-identity.json').read_text())
    if timer_run['file']!='timer_run.c' or digest((INTEGRATION/timer_run['file']).read_bytes())!=timer_run['excerpt_sha256']:
        raise ValueError('reviewed Linux timer run source changed')
    timer_driver=json.loads((INTEGRATION/'timer-driver-source-identity.json').read_text())
    if timer_driver['file']!='timer_driver.c' or digest((INTEGRATION/timer_driver['file']).read_bytes())!=timer_driver['excerpt_sha256']:
        raise ValueError('reviewed Linux timer driver source changed')
    timer_outer=json.loads((INTEGRATION/'timer-outer-source-identity.json').read_text())
    if timer_outer['file']!='timer_outer.c' or digest((INTEGRATION/timer_outer['file']).read_bytes())!=timer_outer['excerpt_sha256']:
        raise ValueError('reviewed Linux outer timer source changed')
    timer_clock=json.loads((INTEGRATION/'timer-clock-source-identity.json').read_text())
    if timer_clock['file']!='timer_clock.c' or digest((INTEGRATION/timer_clock['file']).read_bytes())!=timer_clock['excerpt_sha256']:
        raise ValueError('reviewed Linux timer clock source changed')
    timekeeper=json.loads((INTEGRATION/'timekeeper-source-identity.json').read_text())
    if timekeeper['file']!='timekeeper_update.c' or digest((INTEGRATION/timekeeper['file']).read_bytes())!=timekeeper['excerpt_sha256']:
        raise ValueError('reviewed Linux timer timekeeper source changed')
    return {**identity, 'scheduler':scheduler,'timer':timer,'timer_queue':timer_queue,'timer_run':timer_run,'timer_driver':timer_driver,'timer_outer':timer_outer,'timer_clock':timer_clock,'timekeeper':timekeeper}


def export(args):
    capture, native = load_capture(args.capture)
    identity = source_identity()
    timekeeper_source=bool(getattr(args,'timekeeper_source',False))
    if timekeeper_source:
        if not capture['clock_entry_capture']:
            raise ValueError('original timekeeper replay requires native clock-entry capture')
        selected=next(t for t in capture['native_clock_transitions'] if capture['native_clock_states'][t['irq_index']]['selected_expiry'])
        if selected['changed_fields']:
            raise ValueError('original timekeeper replay admits unchanged selected entry/return fields only')
    out = Path(args.out).resolve()
    if out.exists():
        raise FileExistsError(out)
    if out.is_relative_to(Path(args.capture).resolve()):
        raise ValueError('image output must be outside native capture')
    expected_trace = pack(capture['records'])
    header = '#include <stdint.h>\nstruct irq_record {uint32_t kind,pid;uint64_t a,b,c;};\n'
    header += f'static const unsigned checkpoint_timekeeper_source={int(timekeeper_source)};\n'
    header += f'static const unsigned checkpoint_count={capture["replay_event_count"]};\n'
    header += f'static const unsigned checkpoint_irqs={capture["irq_count"]};\n'
    header += f'static const unsigned checkpoint_native_irq={capture["native_irq"]};\n'
    header += 'static const struct irq_record checkpoint_events[]={'+','.join(
        '{'+','.join('UINT64_C('+str(row[k])+')' if k in ('a','b','c') else str(row[k])
                      for k in ('kind','pid','a','b','c'))+'}' for row in capture['records'])+'};\n'
    # These projected states are inferred recipe witnesses, not native memory snapshots.
    queue_rows=[(1,9,1,0,1,1,1,1),(2,9,1,0,1,0,0,6),
                (3,9,1,0,0,1,1,4),(4,9,1,1,0,1,1,6)]
    expected_queue=b''.join(struct.pack('<8I',*row) for row in queue_rows)
    task_state=bool(capture['task_state_capture'])
    sleep_state=capture['native_task_states'][0]['state'] if task_state else 1
    activation_state=capture['native_task_states'][2]['state'] if task_state else 1
    header+=f'static const unsigned checkpoint_sleeper_state={int(capture["sleeper_state_capture"])};\n'
    background_active=capture['native_base_states'][0]['selected_active_bit'] if capture['base_state_capture'] else 0
    header+=f'static const unsigned checkpoint_background_active={background_active};\n'
    clock_state=capture['clock_state_capture']
    clocks=capture['native_clock_states']
    selected_clock=next((r for r in clocks if r['selected_expiry']),None)
    header+=f'static const unsigned checkpoint_clock_entry={int(capture["clock_entry_capture"])};\n'
    header+=f'static const unsigned checkpoint_clock_offsets={int(capture["clock_offsets_capture"])};\n'
    header+=f'static const unsigned checkpoint_clock_state={int(clock_state)};\n'
    header+='struct clock_input {int64_t now;unsigned sequence;int64_t real,boot,tai;};\n'
    clock_inputs=clocks or [dict(now_ns=0,sequence=1,offs_real=11,offs_boot=22,offs_tai=33)]
    header+='static const struct clock_input checkpoint_clocks[]={'+','.join(
        '{'+','.join(('(-INT64_C(9223372036854775807)-1)' if r[k]==-(1<<63) else 'INT64_C('+str(r[k])+')') if k!='sequence' else str(r[k]) for k in ('now_ns','sequence','offs_real','offs_boot','offs_tai'))+'}' for r in clock_inputs)+'};\n'
    entry_inputs=capture['native_clock_entries'] or [dict(sequence=0,offs_real=0,offs_boot=0,offs_tai=0)]
    header+='static const struct clock_input checkpoint_clock_entries[]={'+','.join(
        '{0,'+','.join(('(-INT64_C(9223372036854775807)-1)' if r[k]==-(1<<63) else 'INT64_C('+str(r[k])+')') if k!='sequence' else str(r[k]) for k in ('sequence','offs_real','offs_boot','offs_tai'))+'}' for r in entry_inputs)+'};\n'
    header+=f'static const unsigned checkpoint_outer_state={int(capture["outer_state_capture"])};\n'
    header+=f'static const unsigned checkpoint_base_state={int(capture["base_state_capture"])};\n'
    header+=f'static const unsigned checkpoint_timer_return={int(capture["timer_return_capture"])};\n'
    header+=f'static const unsigned checkpoint_timer_state={int(capture["timer_state_capture"])};\n'
    header+=f'static const unsigned checkpoint_task_state={int(task_state)},checkpoint_sleep_state={sleep_state},checkpoint_activation_state={activation_state};\n'
    queue_rows=[tuple(activation_state if i==2 and row[0]>=3 else sleep_state if i==2 else value
                      for i,value in enumerate(row)) for row in queue_rows]
    expected_queue=b''.join(struct.pack('<8I',*row) for row in queue_rows)
    timer_rows=[(1,0,0,0,0,0,0,0),(2,1,1,0,0,0,1,0),
                (3,1,1,1,1,0,1,0),(4,1,1,1,1,0,1,1)]
    expected_timer=b''.join(struct.pack('<8I',*row) for row in timer_rows)
    timer_queue_rows=[(1,0,0,0,0,0,0,0),(2,1,1,1,1,0,0,0),(3,1,1,1,1,0,0,0),
                      (4,0,0,0,1,1,0,0),(5,0,0,0,1,1,0,1)]
    timer_queue_rows=[tuple(background_active if i==2 and row[0] in (1,4,5) else value for i,value in enumerate(row)) for row in timer_queue_rows]
    expected_timer_queue=b''.join(struct.pack('<8I',*row) for row in timer_queue_rows)
    callback_rows=[(1,0,1,1,0,0,0,0),(2,1,1,1,1,0,0,0),(3,1,0,0,1,1,0,0),
                   (4,1,0,0,1,1,0,1),(5,1,0,1,1,1,1,1),(6,1,0,1,2,1,1,1),(7,0,0,1,2,1,1,1)]
    expected_callback=b''.join(struct.pack('<8I',*row) for row in callback_rows)
    ordered_rows=[(1,background_active,2 if background_active else 0,0,0,background_active,0,0),
                  (2,1+background_active,1,2 if background_active else 0,1,background_active,1,0),
                  (3,background_active,2 if background_active else 0,0,0,background_active,1,1),
                  (4,background_active,2 if background_active else 0,0,0,background_active,1,1)]
    expected_ordered=b''.join(struct.pack('<8I',*row) for row in ordered_rows)
    driver_rows=[(1,0,1,1,1,0,0,0),(2,0,1,1,1,1,1,1),
                 (3,1,0,2 if background_active else 0,background_active,3,2+background_active,2),
                 (4,1,0,2 if background_active else 0,background_active,3+background_active,2+2*background_active,2+background_active)]
    expected_driver=b''.join(struct.pack('<8I',*row) for row in driver_rows)
    outer_rows=[(1,0,0,0,0,0,0,0),(2,0,0,0,0,0,0,0),(3,0,0,1,0,0,0,0),
                (4,1,0,1,0,0,0,0),(5,1,1,1,0,0,0,0),(6,1,1,1,0,0,0,0),(7,0,1,1,0,1,1,0)]
    expected_outer=b''.join(struct.pack('<8I',*row) for row in outer_rows)
    clock_sequence=selected_clock['sequence'] if selected_clock else 1
    clock_offsets=tuple(selected_clock[k] for k in ('offs_real','offs_boot','offs_tai')) if selected_clock else (11,22,33)
    clock_rows=[(1,1,clock_sequence,capture['expiry_now_ns'],*clock_offsets,-11,-22,-33),
                (2,1,clock_sequence,capture['expiry_now_ns'],*clock_offsets,*clock_offsets)]
    expected_clock=b''.join(struct.pack('<10q',*row) for row in clock_rows)
    timekeeper_rows=[(1,1,0,0,0,clock_sequence,clock_sequence,7,0,1),
                     (2,1,1,0,0,clock_sequence,clock_sequence,7,0,1),
                     (3,1,1,1,1,clock_sequence,clock_sequence,7,0,1),
                     (4,1,1,1,1,clock_sequence,clock_sequence,7,capture['expiry_now_ns'],1)] if timekeeper_source else []
    expected_timekeeper=b''.join(struct.pack('<10Q',*row) for row in timekeeper_rows)
    args.arch='aarch64' 
    with tempfile.TemporaryDirectory(prefix='osrec-linux-irq-') as name:
        stage = Path(name); sources=stage/'sources';sources.mkdir()
        flags=prepare_target(args,sources)
        shutil.copyfile(ROOT/'integrations/rtl_aarch64/async_start.S',sources/'start.S')
        shutil.copyfile(INTEGRATION/'replay.c',sources/'replay.c')
        shutil.copyfile(INTEGRATION/'hrtimer_wakeup.c',sources/'hrtimer_wakeup.c')
        shutil.copyfile(INTEGRATION/'sched_queue_model.c',sources/'sched_queue_model.c')
        for filename in ('timer_model.c','timer_sleeper.c','timer_queue.c','timer_queue_model.c','timer_run.c','timer_run_model.c','ordered_timer_queue.h','timer_driver.c','timer_driver_model.c','timer_outer.c','timer_outer_model.c','timer_clock.c','timer_clock_model.c','timekeeper_update.c','timekeeper_model.c'):
            shutil.copyfile(INTEGRATION/filename,sources/filename)
        for filename in identity['scheduler']['files']:
            shutil.copyfile(INTEGRATION/filename,sources/filename)
        (sources/'irq_checkpoint.h').write_text(header)
        elf,binary=stage/'linux-irq.elf',stage/'linux-irq.bin'
        run([args.llvm_bin/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin',
             '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
             '-Wall','-Wextra','-Werror','-nostdlib','-static','-fuse-ld=lld',
             '-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),'-I'+str(sources),
             sources/'start.S',sources/'replay.c','-o',elf])
        inspection=audit(elf,args.llvm_bin)
        symbols=[line.split() for line in run([args.llvm_bin/'llvm-nm','--defined-only','--format=posix',elf]).stdout.splitlines()]
        matches=[row for row in symbols if row[0]=='osrec_linux_irq_events']
        if len(matches)!=1 or int(matches[0][3],16)!=4096*32:
            raise ValueError('Linux IRQ image has no bounded event ledger')
        trace_address=int(matches[0][2],16)
        queue_symbols=[row for row in symbols if row[0]=='osrec_linux_irq_queue']
        if len(queue_symbols)!=1 or int(queue_symbols[0][3],16)!=len(expected_queue):
            raise ValueError('Linux IRQ image has no bounded scheduler witness ledger')
        queue_address=int(queue_symbols[0][2],16)
        timer_symbols=[row for row in symbols if row[0]=='osrec_linux_irq_timer']
        if len(timer_symbols)!=1 or int(timer_symbols[0][3],16)!=len(expected_timer):
            raise ValueError('Linux IRQ image has no bounded timer witness ledger')
        timer_address=int(timer_symbols[0][2],16)
        timer_queue_symbols=[row for row in symbols if row[0]=='osrec_linux_irq_timer_queue']
        if len(timer_queue_symbols)!=1 or int(timer_queue_symbols[0][3],16)!=len(expected_timer_queue):
            raise ValueError('Linux IRQ image has no bounded timer queue witness ledger')
        timer_queue_address=int(timer_queue_symbols[0][2],16)
        callback_symbols=[row for row in symbols if row[0]=='osrec_linux_irq_callback']
        if len(callback_symbols)!=1 or int(callback_symbols[0][3],16)!=len(expected_callback):
            raise ValueError('Linux IRQ image has no bounded callback witness ledger')
        callback_address=int(callback_symbols[0][2],16)
        ordered_symbols=[row for row in symbols if row[0]=='osrec_linux_irq_ordered']
        if len(ordered_symbols)!=1 or int(ordered_symbols[0][3],16)!=len(expected_ordered):
            raise ValueError('Linux IRQ image has no bounded ordered queue witness ledger')
        ordered_address=int(ordered_symbols[0][2],16)
        driver_symbols=[row for row in symbols if row[0]=='osrec_linux_irq_driver']
        if len(driver_symbols)!=1 or int(driver_symbols[0][3],16)!=len(expected_driver):
            raise ValueError('Linux IRQ image has no bounded timer driver witness ledger')
        driver_address=int(driver_symbols[0][2],16)
        outer_symbols=[row for row in symbols if row[0]=='osrec_linux_irq_outer']
        if len(outer_symbols)!=1 or int(outer_symbols[0][3],16)!=len(expected_outer):
            raise ValueError('Linux IRQ image has no bounded outer timer witness ledger')
        outer_address=int(outer_symbols[0][2],16)
        clock_symbols=[row for row in symbols if row[0]=='osrec_linux_irq_clock']
        if len(clock_symbols)!=1 or int(clock_symbols[0][3],16)!=len(expected_clock):
            raise ValueError('Linux IRQ image has no bounded timer clock witness ledger')
        clock_address=int(clock_symbols[0][2],16)
        timekeeper_address=0
        if timekeeper_source:
            timekeeper_symbols=[row for row in symbols if row[0]=='osrec_linux_irq_timekeeper']
            if len(timekeeper_symbols)!=1 or int(timekeeper_symbols[0][3],16)!=len(expected_timekeeper):
                raise ValueError('Linux IRQ image has no bounded timekeeper witness ledger')
            timekeeper_address=int(timekeeper_symbols[0][2],16)
        run([args.llvm_bin/'llvm-objcopy' ,'-O','binary',elf,binary])
        observations=[]
        for index,(image,descriptor) in enumerate(((elf,None),(binary,elf))):
            dumped=stage/f'target-events-{index}.bin'
            queue_dumped=stage/f'target-queue-{index}.bin'
            timer_dumped=stage/f'target-timer-{index}.bin'
            timer_queue_dumped=stage/f'target-timer-queue-{index}.bin'
            callback_dumped=stage/f'target-callback-{index}.bin'
            ordered_dumped=stage/f'target-ordered-{index}.bin'
            driver_dumped=stage/f'target-driver-{index}.bin'
            outer_dumped=stage/f'target-outer-{index}.bin'
            clock_dumped=stage/f'target-clock-{index}.bin'
            timekeeper_dumped=stage/f'target-timekeeper-{index}.bin'
            result,raw=observe(image,args.qemu,descriptor=descriptor,
                               memory_dumps=({'address':trace_address,'bytes':len(expected_trace),'file':str(dumped)},
                                             {'address':queue_address,'bytes':len(expected_queue),'file':str(queue_dumped)},
                                             {'address':timer_address,'bytes':len(expected_timer),'file':str(timer_dumped)},
                                             {'address':timer_queue_address,'bytes':len(expected_timer_queue),'file':str(timer_queue_dumped)},
                                             {'address':callback_address,'bytes':len(expected_callback),'file':str(callback_dumped)},
                                             {'address':ordered_address,'bytes':len(expected_ordered),'file':str(ordered_dumped)},
                                             {'address':driver_address,'bytes':len(expected_driver),'file':str(driver_dumped)},
                                             {'address':outer_address,'bytes':len(expected_outer),'file':str(outer_dumped)},
                                             {'address':clock_address,'bytes':len(expected_clock),'file':str(clock_dumped)})+(({'address':timekeeper_address,'bytes':len(expected_timekeeper),'file':str(timekeeper_dumped)},) if timekeeper_source else ()))
            require_success(result)
            if dumped.read_bytes()!=expected_trace:
                raise ValueError('independent Linux IRQ RAM event trace differs')
            if queue_dumped.read_bytes()!=expected_queue:
                raise ValueError('independent Linux IRQ scheduler witnesses differ')
            if timer_dumped.read_bytes()!=expected_timer:
                raise ValueError('independent Linux IRQ timer witnesses differ')
            if timer_queue_dumped.read_bytes()!=expected_timer_queue:
                raise ValueError('independent Linux IRQ timer queue witnesses differ')
            if callback_dumped.read_bytes()!=expected_callback:
                raise ValueError('independent Linux IRQ callback witnesses differ')
            if ordered_dumped.read_bytes()!=expected_ordered:
                raise ValueError('independent Linux IRQ ordered queue witnesses differ')
            if driver_dumped.read_bytes()!=expected_driver:
                raise ValueError('independent Linux IRQ timer driver witnesses differ')
            if outer_dumped.read_bytes()!=expected_outer:
                raise ValueError('independent Linux IRQ outer timer witnesses differ')
            if clock_dumped.read_bytes()!=expected_clock:
                raise ValueError('independent Linux IRQ timer clock witnesses differ')
            if timekeeper_source and timekeeper_dumped.read_bytes()!=expected_timekeeper:
                raise ValueError('independent Linux IRQ timekeeper witnesses differ')
            if any(result[key]!=capture[key] for key in ('expires_ns','soft_expires_ns','expiry_now_ns')) or result['native_irq']!=capture['native_irq']:
                raise ValueError('Linux IRQ image timing inputs or IRQ mapping differ')
            observations.append((result,raw))
        if observations[0][1]!=observations[1][1]:
            raise ValueError('Linux IRQ ELF/raw results differ')
        target=target_metadata(inspection,29)
        target.update(interrupts_enabled=True,interrupt_controller='QEMU virt GICv2',physical_timer_irq=30)
        report=dict(format='osrec-linux-irq-image-v1',status='verified',target=target,
                    image_audit=inspection,source_identity=identity,native_kernel=native['identity'],
                    native_capture_manifest_sha256=digest((Path(args.capture)/'capture.manifest.json').read_bytes()),
                    native_source_build_attested=False,hardware_irq_delivery=True,
                    kernel_scheduler_reproduction=False,
                    original_scheduler_functions=[f['name'] for entry in identity['scheduler']['files'].values() for f in entry['functions']],
                    scheduler_activation='original activation/deactivation wrappers; selected-task class queue and accounting boundaries modeled',
                    scheduler_witnesses=dict(format='osrec-linux-irq-queue-v1',rows=queue_rows,record_bytes=32,
                        fields=['kind','flags','state','on_rq','on_cpu','selected_nr_running','queued_tid','hook_step'],
                        address=queue_address,native_memory_snapshot=False),
                    independent_scheduler_witnesses_verified=True,
                    original_timer_functions=['hrtimer_wakeup']+[f['name'] for f in identity['timer']['functions']+identity['timer_queue']['functions']+identity['timer_run']['functions']+identity['timer_driver']['functions']+identity['timer_outer']['functions']+identity['timer_clock']['functions']+(identity['timekeeper']['functions'] if timekeeper_source else [])],
                    original_timekeeper_functions=[f['name'] for f in identity['timekeeper']['functions']] if timekeeper_source else [],
                    timekeeper_source_executed=timekeeper_source,
                    native_timekeeper_provider_state_captured=False,
                    timekeeper_source_scope='selected helper call only; observed unchanged entry/return fields; original source runs with modeled global sequence equal to input, captured time as monotonic base, zero ns increment, no leap and no retry; does not attest native internals',
                    timekeeper_witnesses=dict(format='osrec-linux-irq-timekeeper-v1',rows=timekeeper_rows,record_bytes=80,address=timekeeper_address,
                        fields=['kind','seq_reads','ns_reads','add_calls','retry_checks','provider_sequence','output_sequence','offset_match_mask','returned_now','logical_lock'],native_memory_snapshot=False) if timekeeper_source else None,
                    independent_timekeeper_witnesses_verified=timekeeper_source,
                    timer_witnesses=dict(format='osrec-linux-irq-timer-v1',rows=timer_rows,record_bytes=32,address=timer_address,
                        fields=['kind','clock_id','mode','callback_matches','linked_tid','is_hard','init_calls','start_calls'],native_memory_snapshot=False),
                    independent_timer_witnesses_verified=True,
                    timer_queue_witnesses=dict(format='osrec-linux-irq-timer-queue-v1',rows=timer_queue_rows,record_bytes=32,address=timer_queue_address,
                        fields=['kind','timer_state','active_mask','queued_id','add_calls','delete_calls','reprogram_calls','inactive_remove_probes'],native_memory_snapshot=False),
                    independent_timer_queue_witnesses_verified=True,
                    callback_witnesses=dict(format='osrec-linux-irq-callback-v1',rows=callback_rows,record_bytes=32,address=callback_address,
                        fields=['kind','running_timer_id','timer_state','lock_depth','sequence_barriers','unlocks','relocks','callback_calls'],native_memory_snapshot=False),
                    independent_callback_witnesses_verified=True,
                    ordered_queue_witnesses=dict(format='osrec-linux-irq-ordered-queue-v1',rows=ordered_rows,record_bytes=32,address=ordered_address,
                        fields=['kind','count','first_id','second_id','selected_queued','sentinel_queued','selected_adds','selected_deletes'],native_memory_snapshot=False),
                    independent_ordered_queue_witnesses_verified=True,
                    ordered_queue_boundary='two-slot stable ordered array; selected node and optional synthetic sentinel with UINT64_MAX ordering key; not Linux rbtree or native background timer state',
                    timer_driver_witnesses=dict(format='osrec-linux-irq-timer-driver-v1',rows=driver_rows,record_bytes=32,address=driver_address,
                        fields=['kind','callbacks','selected_queued','first_id','active_mask','getnext_calls','soft_checks','base_visits'],native_memory_snapshot=False),
                    independent_timer_driver_witnesses_verified=True,
                    timer_driver_boundary='original queue-dispatch body; one zero-offset monotonic base, ordered array and clock/accessor boundaries modeled; captured expiry clock input',
                    outer_timer_witnesses=dict(format='osrec-linux-irq-outer-timer-v1',rows=outer_rows,record_bytes=32,address=outer_address,
                        fields=['kind','logical_lock','clock_updates','tick_checks','softirq_raises','queue_dispatches','callbacks','softirq_activated'],native_memory_snapshot=False),
                    independent_outer_timer_witnesses_verified=True,
                    timer_clock_witnesses=dict(format='osrec-linux-irq-timer-clock-v1',rows=clock_rows,record_bytes=80,address=clock_address,
                        fields=['kind','clock_updates','sequence','now','real','boot','tai','soft_real','soft_boot','soft_tai'],native_memory_snapshot=False),
                    independent_timer_clock_witnesses_verified=True,
                    timer_clock_boundary=('original hrtimer_update_base and timekeeper helper; modeled provider yields native unchanged selected entry/return values; initial soft offsets remain synthetic omission guards' if timekeeper_source else 'original hrtimer_update_base propagation using native selected-IRQ timekeeper return, sequence and hard offsets; initial soft offsets remain synthetic omission guards; no timekeeper implementation' if clock_state else 'original hrtimer_update_base offset propagation; captured expiry time injected by modeled timekeeper; sequence 1 and offsets 11/22/33 are synthetic guards, not native state; monotonic offsets stay zero'),
                    native_clock_update_return_captured=clock_state,native_clock_offsets_captured=clock_state,
                    native_clock_observations=clocks,
                    native_clock_entry_fields_verified=capture['clock_entry_capture'],native_clock_entry_observations=capture['native_clock_entries'],
                    native_clock_input_sequence_captured=capture['clock_entry_capture'],native_clock_input_offsets_captured=capture['clock_entry_capture'],
                    clock_entry_transition_model=('original helper control flow under modeled provider state; does not attest native internal branch execution' if timekeeper_source else 'field-wise application of recorded outputs; preserves equal values; does not implement or attest the native helper conditional-update branch'),
                    native_clock_value_transitions=capture['native_clock_transitions'],
                    native_timekeeper_layout_discovered=capture['timekeeper_layout_capture'],
                    native_timekeeper_layout=native.get('timekeeper_layout'),
                    native_timekeeper_data_symbol_lookup_supported=native.get('timekeeper_data_symbol_lookup_supported',False),
                    native_timekeeper_symbol_type_binding_attested=False,
                    native_timekeeper_layout_scope='unique anonymous BTF shape only; no provider field values, symbol/type binding or native branch history; replay provider remains modeled',
                    native_clock_entry_scope='sequence and hard offsets at each helper entry, paired with returns; changed fields describe observed values, not native stores or internal branch execution',
                    native_propagated_offsets_verified=capture['clock_offsets_capture'],native_propagated_offset_observations=capture['native_propagated_offsets'],
                    native_clock_offsets_layout=native.get('clock_offsets_layout'),
                    native_clock_destinations_btf_cpu_base_mapping_verified=capture['native_clock_destinations_btf_cpu_base_mapping_verified'],
                    native_propagated_offset_scope='soft realtime/boottime/TAI offsets and output sequence at callback entry; native write instructions and initial soft fields remain unobserved',
                    native_clock_observation_scope='timekeeper return, output sequence and three hard offsets at each captured low-resolution runner call; soft offset writes and timekeeper internals remain unobserved'+('; input sequence and offsets observed by entry probe' if capture['clock_entry_capture'] else '; input sequence remains unobserved'),
                    context_clock_return_boundary=('non-expiry IRQ entry/return pairs are injected boundary observations; full outer/tick work on those IRQs is not reproduced' if capture['clock_entry_capture'] else 'non-expiry IRQ timekeeper returns are injected boundary observations; full outer/tick work on those IRQs is not reproduced'),
                    native_outer_fields_verified=capture['outer_state_capture'],native_outer_observations=capture['native_outer_states'],
                    native_outer_observation_scope='softirq deadline and activation at callback entry only; initial fields, timekeeper input, tick decision and lock memory remain modeled',
                    outer_timer_boundary='original low-resolution outer runner and clock-offset propagation; captured expiry time injected at timekeeper boundary; logical lock flags, current CPU, tick decision and softirq deadline modeled; transitions and softirq delivery unsupported',
                    additional_driver_guards='synthetic masked, pre-soft-deadline and post-callback passes; no additional native events',
                    additional_timer_guard='one synthetic inactive removal; not a captured native operation',
                    timer_boundary='original low-resolution outer runner, queue-dispatch, callback-run and enqueue/removal bodies; bounded ordered selected timer plus optional synthetic remainder sentinel, lock/sequence/lockdep boundaries, clock bases and debug machinery modeled',
                    additional_target_guards='six synthetic state-match cases and one repeated wakeup; not native captured events',
                    native_sleeper_links_verified=capture['sleeper_state_capture'],native_sleeper_links=capture['native_sleeper_links'],
                    native_sleeper_layout=native.get('sleeper_layout'),
                    native_timer_fields_verified=capture['timer_state_capture'],native_timer_observations=capture['native_timer_states'],
                    native_timer_observation_scope=('timer state and base running-pointer identity at callback entry, plus running pointer at sleep return' if capture['timer_return_capture'] else 'timer state and base running-pointer identity at callback entry only')+('; no native lock or sequence snapshot' if capture['base_state_capture'] else '; no native lock, sequence or active-mask snapshot'),
                    native_timer_return_verified=capture['timer_return_capture'],native_timer_return_observations=capture['native_timer_returns'],
                    native_timer_return_layout=native.get('timer_return_layout'),
                    native_base_fields_verified=capture['base_state_capture'],native_base_observations=capture['native_base_states'],
                    native_base_layout=native.get('base_state_layout'),
                    background_base_occupancy=background_active,
                    background_occupancy_scope='synthetic sentinel for nonempty remainder inferred from post-removal active bit, assumed stable across slice; sentinel key UINT64_MAX is not a native deadline; no native background objects, counts, ordering or deadlines replayed',
                    native_base_observation_scope='base index and selected active bit at callback/sleep return; other active-mask bits retained as native context only; no lock or sequence memory snapshot',
                    checkpoint=('typed reconstruction with direct task-field and sleeper-link observations' if capture['sleeper_state_capture'] else 'typed reconstruction with direct task-field observations; sleeper association inferred' if task_state else 'semantic typed sleeper/task reconstruction from admitted trace'),
                    native_task_fields_verified=task_state,native_task_observations=capture['native_task_states'],
                    runtime_host_interaction=False,independent_ram_events_verified=True,
                    raw_image_execution_match=True,rtl_validated=False,cycle_timing_equivalence_verified=False,
                    contract=capture,target_observations=observations[0][0],
                    elf_sha256=digest(elf.read_bytes()),binary_sha256=digest(binary.read_bytes()),
                    source_hashes={p.name:digest(p.read_bytes()) for p in sources.iterdir()},
                    compiler=run([args.llvm_bin/'clang','--version']).stdout.splitlines()[0],
                    qemu=run([args.qemu,'--version']).stdout.splitlines()[0])
        if timekeeper_source:(stage/'expected-timekeeper.bin').write_bytes(expected_timekeeper)
        (stage/'expected-clock.bin').write_bytes(expected_clock)
        (stage/'expected-outer.bin').write_bytes(expected_outer)
        (stage/'expected-driver.bin').write_bytes(expected_driver)
        (stage/'expected-ordered.bin').write_bytes(expected_ordered)
        (stage/'expected-callback.bin').write_bytes(expected_callback)
        (stage/'expected-timer-queue.bin').write_bytes(expected_timer_queue)
        (stage/'expected-timer.bin').write_bytes(expected_timer)
        (stage/'expected-queue.bin').write_bytes(expected_queue)
        (stage/'expected-events.bin').write_bytes(expected_trace)
        (stage/'target-result.bin').write_bytes(observations[0][1])
        (stage/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
        out.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(stage,out)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',type=Path,required=True)
    parser.add_argument('--timekeeper-source',action='store_true',help='execute original timekeeper helper for unchanged selected clock-entry observations, with explicit modeled provider state')
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--qemu',default='qemu-system-aarch64')
    parser.add_argument('--entry-address',type=lambda v:int(v,0),default=0x40200000)
    parser.add_argument('--result-address',type=lambda v:int(v,0),default=0x40180000)
    args=parser.parse_args()
    try:result=export(args)
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        if isinstance(error,subprocess.CalledProcessError):print(error.stderr)
        parser.exit(1,str(error)+'\n')
    print(json.dumps(result['target_observations'],indent=2))


if __name__=='__main__':main()
