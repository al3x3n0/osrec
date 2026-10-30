#!/usr/bin/env python3
"""Capture a real AArch64 Linux nanosleep with scheduler, timer and IRQ tracepoints."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess

from capture_linux_aarch64 import ROOT, kernel_identity, missing_config, digest
from minimal_ext2 import root_disk

SOURCE = ROOT/'integrations/linux_aarch64/irq-wait/native.c'
REQUIRED = ('TRACING', 'FTRACE', 'FTRACE_SYSCALLS', 'EVENT_TRACING', 'DEBUG_FS',
            'ARM_ARCH_TIMER', 'KALLSYMS')
TASK_PROBES = ('osrec_task_dequeue','osrec_task_wake','osrec_task_activate','osrec_task_preempt')
TASK_SYMBOLS=('dequeue_task_fair','wake_up_process','activate_task','wakeup_preempt')
TASK_FIELDS=' task=p:x64 pid=p->pid:s32 state=p->__state:u32 saved=p->saved_state:u32 on_rq=p->on_rq:u32 on_cpu=p->on_cpu:u32'
TASK_DEFINITIONS=''.join('p:osrec/'+name+' '+symbol+TASK_FIELDS+'\n' for name,symbol in zip(TASK_PROBES,TASK_SYMBOLS))
TASK_REQUIRED = ('KPROBES','KPROBE_EVENTS','PROBE_EVENTS_BTF_ARGS','DEBUG_INFO_BTF','BPF_SYSCALL')

TIMER_PROBES=('osrec_timer_callback',)
TIMER_DEFINITIONS=''.join('p:osrec/'+name+' '+symbol+' object=timer:x64 base=timer->base:x64 running=timer->base->running:x64 state=timer->state:u8\n' for name,symbol in zip(TIMER_PROBES,('hrtimer_wakeup',)))


SLEEPER_PROBES=('osrec_sleeper_entry','osrec_sleeper_callback','osrec_sleeper_callback_return','osrec_sleeper_return')


def parse_layout(text):
    rows=re.findall(r'^OSREC_LINUX_IRQ_LAYOUT (\{[^\n]+\})$',text.replace('\r\n','\n'),re.M)
    if len(rows)!=1:raise ValueError('missing or duplicated Linux sleeper BTF layout')
    layout=json.loads(rows[0])
    keys=('btf_bytes','type_id','size','task_offset','timer_offset')
    if layout.get('source')!='native-sysfs-btf' or any(type(layout.get(k)) is not int for k in keys):
        raise ValueError('Linux sleeper BTF layout field types differ')
    if not (24<=layout['btf_bytes']<=8*1024*1024 and 1<=layout['type_id']<=1000000 and
            16<=layout['size']<=4096 and 8<=layout['task_offset']<=layout['size']-8 and
            layout['task_offset']%8==0 and layout['timer_offset']==0):
        raise ValueError('unsupported Linux sleeper BTF layout')
    return layout


def sleeper_definitions(layout):
    offset=layout['task_offset']
    return ('p:osrec/osrec_sleeper_entry do_nanosleep object=t:x64 task=t->task:x64\n'
            f'p:osrec/osrec_sleeper_callback hrtimer_wakeup object=$arg1:x64 task=+{offset}($arg1):x64\n'
            f'r8:osrec/osrec_sleeper_callback_return hrtimer_wakeup object=$arg1:x64 task=+{offset}($arg1):x64 result=$retval:s32\n'
            f'r8:osrec/osrec_sleeper_return do_nanosleep object=$arg1:x64 task=+{offset}($arg1):x64 result=$retval:s32\n')


def parse_timer_layout(text):
    rows=re.findall(r'^OSREC_LINUX_IRQ_TIMER_LAYOUT (\{[^\n]+\})$',text.replace('\r\n','\n'),re.M)
    if len(rows)!=1:raise ValueError('missing or duplicated Linux timer return BTF layout')
    layout=json.loads(rows[0])
    keys=('timer_type_id','timer_size','base_type_id','base_size','base_offset','running_offset')
    if layout.get('source')!='native-sysfs-btf' or any(type(layout.get(k)) is not int for k in keys):
        raise ValueError('Linux timer return BTF layout field types differ')
    if (any(not 1<=layout[k]<=1000000 for k in ('timer_type_id','base_type_id')) or
        layout['timer_type_id']==layout['base_type_id'] or
        any(not 8<=layout[k]<=4096 for k in ('timer_size','base_size')) or
        any(layout[offset]<0 or layout[offset]%8 or layout[offset]+8>layout[size]
            for offset,size in (('base_offset','timer_size'),('running_offset','base_size')))):
        raise ValueError('unsupported Linux timer return BTF layout')
    return layout


def timer_return_definitions(layout):
    base,running=layout['base_offset'],layout['running_offset']
    return (f'r8:osrec/osrec_timer_return do_nanosleep object=$arg1:x64 base=+{base}($arg1):x64 '
            f'running=+{running}(+{base}($arg1)):x64 result=$retval:s32\n')


BASE_PROBES=('osrec_base_callback','osrec_base_return')
BASE_CALLBACK='p:osrec/osrec_base_callback hrtimer_wakeup object=timer:x64 base=timer->base:x64 cpu_base=timer->base->cpu_base:x64 index=timer->base->index:u32 active=timer->base->cpu_base->active_bases:u32\n'


def parse_base_layout(text,timer_layout):
    rows=re.findall(r'^OSREC_LINUX_IRQ_BASE_LAYOUT (\{[^\n]+\})$',text.replace('\r\n','\n'),re.M)
    if len(rows)!=1:raise ValueError('missing or duplicated Linux base-state BTF layout')
    layout=json.loads(rows[0]);keys=('base_type_id','cpu_type_id','cpu_size','cpu_base_offset','index_offset','active_offset')
    if layout.get('source')!='native-sysfs-btf' or any(type(layout.get(k)) is not int for k in keys):
        raise ValueError('Linux base-state BTF layout field types differ')
    if (layout['base_type_id']!=timer_layout['base_type_id'] or not 1<=layout['cpu_type_id']<=1000000 or
        layout['cpu_type_id'] in (timer_layout['timer_type_id'],timer_layout['base_type_id']) or
        not 8<=layout['cpu_size']<=4096 or
        any(layout[offset]<0 or layout[offset]%width or layout[offset]+width>size
            for offset,width,size in (('cpu_base_offset',8,timer_layout['base_size']),
                                      ('index_offset',4,timer_layout['base_size']),('active_offset',4,layout['cpu_size'])))):
        raise ValueError('unsupported Linux base-state BTF layout')
    return layout


def base_definitions(timer,base):
    t,c,i,a=timer['base_offset'],base['cpu_base_offset'],base['index_offset'],base['active_offset']
    return (BASE_CALLBACK+f'r8:osrec/osrec_base_return do_nanosleep object=$arg1:x64 base=+{t}($arg1):x64 '
            f'cpu_base=+{c}(+{t}($arg1)):x64 index=+{i}(+{t}($arg1)):u32 '
            f'active=+{a}(+{c}(+{t}($arg1))):u32 result=$retval:s32\n')

OUTER_PROBES=('osrec_outer_callback',)
OUTER_DEFINITIONS='p:osrec/osrec_outer_callback hrtimer_wakeup object=timer:x64 cpu_base=timer->base->cpu_base:x64 deadline=timer->base->cpu_base->softirq_expires_next:s64 activated=timer->base->cpu_base->softirq_activated\n'

CLOCK_PROBES=('osrec_clock_return',)
CLOCK_DEFINITIONS='r8:osrec/osrec_clock_return ktime_get_update_offsets_now seq=$arg1:x64 real=$arg2:x64 boot=$arg3:x64 tai=$arg4:x64 sequence=+0($arg1):u32 offs_real=+0($arg2):s64 offs_boot=+0($arg3):s64 offs_tai=+0($arg4):s64 now=$retval:s64\n'

ENTRY_PROBES=('osrec_clock_entry',)
ENTRY_DEFINITIONS='p:osrec/osrec_clock_entry ktime_get_update_offsets_now seq=$arg1:x64 real=$arg2:x64 boot=$arg3:x64 tai=$arg4:x64 sequence=+0($arg1):u32 offs_real=+0($arg2):s64 offs_boot=+0($arg3):s64 offs_tai=+0($arg4):s64\n'

TIMEKEEPER_FIELDS=(('provider_sequence','sequence_offset','u32'),
                   ('provider_clock_sequence','clock_sequence_offset','u32'),
                   ('mono_base','mono_base_offset','s64'),('provider_real','real_offset','s64'),
                   ('provider_boot','boot_offset','s64'),('provider_tai','tai_offset','s64'),
                   ('next_leap','leap_offset','s64'))


def parse_timekeeper_layout(text):
    rows=re.findall(r'^OSREC_LINUX_IRQ_TIMEKEEPER_LAYOUT (\{[^\n]+\})$',text.replace('\r\n','\n'),re.M)
    if len(rows)!=1:raise ValueError('missing or duplicated Linux timekeeper BTF layout')
    layout=json.loads(rows[0])
    ids=('core_type_id','timekeeper_type_id');sizes=('core_size','timekeeper_size')
    offsets=tuple(offset for _,offset,_ in TIMEKEEPER_FIELDS)
    if (set(layout)!=set(('source','symbol_type_binding_attested',*ids,*sizes,*offsets)) or
        layout['source']!='native-sysfs-btf-unique-anonymous-shape' or layout['symbol_type_binding_attested'] is not False or
        any(type(layout[k]) is not int for k in (*ids,*sizes,*offsets))):
        raise ValueError('Linux timekeeper BTF layout field types differ')
    if (any(not 1<=layout[k]<=1000000 for k in ids) or layout[ids[0]]==layout[ids[1]] or
        not 8<=layout['timekeeper_size']<layout['core_size']<=4096):
        raise ValueError('unsupported Linux timekeeper BTF layout')
    regions=[]
    for _,offset,kind in TIMEKEEPER_FIELDS:
        width=4 if kind=='u32' else 8;start=layout[offset]
        if (start<0 or start%width or start+width>layout['core_size'] or
            any(start<end and begin<start+width for begin,end in regions)):
            raise ValueError('unsupported Linux timekeeper BTF layout offsets')
        regions.append((start,start+width))
    return layout


OFFSETS_PROBES=('osrec_offsets_callback',)

def parse_offsets_layout(text,timer,base):
    rows=re.findall(r'^OSREC_LINUX_IRQ_OFFSETS_LAYOUT (\{[^\n]+\})$',text.replace('\r\n','\n'),re.M)
    if len(rows)!=1:raise ValueError('missing or duplicated Linux clock-offsets BTF layout')
    layout=json.loads(rows[0])
    keys=('cpu_type_id','cpu_size','base_type_id','base_size','array_offset','array_count','offset_offset','sequence_offset')
    if layout.get('source')!='native-sysfs-btf' or any(type(layout.get(k)) is not int for k in keys):
        raise ValueError('Linux clock-offsets BTF layout field types differ')
    if (any(layout[k]!=base[k] for k in ('cpu_type_id','cpu_size','base_type_id')) or layout['base_size']!=timer['base_size'] or
        layout['array_count']!=8 or layout['array_offset']<0 or layout['array_offset']%8 or
        layout['array_offset']+8*layout['base_size']>layout['cpu_size'] or
        layout['offset_offset']<0 or layout['offset_offset']%8 or layout['offset_offset']+8>layout['base_size'] or
        layout['sequence_offset']<0 or layout['sequence_offset']%4 or layout['sequence_offset']+4>layout['array_offset']):
        raise ValueError('unsupported Linux clock-offsets BTF layout')
    return layout

def offsets_definitions(timer,base,layout):
    def fetch(offset):return f'+{offset}(+{base["cpu_base_offset"]}(+{timer["base_offset"]}($arg1)))'
    return ('p:osrec/osrec_offsets_callback hrtimer_wakeup object=$arg1:x64 cpu_base=timer->base->cpu_base:x64 '+
            'sequence='+fetch(layout['sequence_offset'])+':u32 '+
            ' '.join('soft_'+name+'='+fetch(layout['array_offset']+index*layout['base_size']+layout['offset_offset'])+':s64'
                     for name,index in (('real',5),('boot',6),('tai',7)))+'\n')

EVENTS = ('syscalls/sys_enter_nanosleep', 'syscalls/sys_exit_nanosleep',
          'sched/sched_switch', 'sched/sched_waking', 'sched/sched_wakeup',
          'timer/hrtimer_init', 'timer/hrtimer_start', 'timer/hrtimer_expire_entry',
          'timer/hrtimer_expire_exit', 'timer/hrtimer_cancel',
          'irq/irq_handler_entry', 'irq/irq_handler_exit')


def block(text, kind):
    matches = re.findall(r'^OSREC_LINUX_IRQ_'+kind+r'_BEGIN\n(.*?)\nOSREC_LINUX_IRQ_'+kind+r'_END$', text, re.M|re.S)
    if len(matches) != 1:
        raise ValueError('missing or duplicated Linux IRQ '+kind)
    return matches[0]+'\n'


def parse_output(text):
    text = text.replace('\r\n', '\n')
    if 'OSREC_LINUX_IRQ_FAILED' in text or text.count('OSREC_LINUX_IRQ_DONE\n') != 1:
        raise ValueError('Linux IRQ workload did not complete')
    rows = re.findall(r'^OSREC_LINUX_IRQ_RESULT (\{[^\n]+\})$', text, re.M)
    if len(rows) != 1:
        raise ValueError('missing or duplicated Linux IRQ result')
    result = json.loads(rows[0])
    for mode in ('task_state_capture','sleeper_state_capture','timer_state_capture','timer_return_capture','base_state_capture','outer_state_capture','clock_state_capture','clock_offsets_capture','clock_entry_capture','timekeeper_layout_capture'):
        if mode in result and result[mode] is not True:raise ValueError('unsupported Linux IRQ capture mode value')
    if result.get('sleeper_state_capture') and not result.get('task_state_capture'):
        raise ValueError('Linux sleeper capture requires native task fields')
    if result.get('timer_state_capture') and not result.get('sleeper_state_capture'):
        raise ValueError('Linux timer capture requires sleeper observations')
    if result.get('timer_return_capture') and not result.get('timer_state_capture'):
        raise ValueError('Linux timer return capture requires callback timer observations')
    if result.get('base_state_capture') and not result.get('timer_return_capture'):
        raise ValueError('Linux base-state capture requires timer return observations')
    if result.get('outer_state_capture') and not result.get('base_state_capture'):
        raise ValueError('Linux outer-state capture requires base observations')
    if result.get('clock_state_capture') and not result.get('outer_state_capture'):
        raise ValueError('Linux clock-state capture requires outer observations')
    if result.get('clock_offsets_capture') and not result.get('clock_state_capture'):
        raise ValueError('Linux clock-offsets capture requires timekeeper observations')
    if result.get('clock_entry_capture') and not result.get('clock_offsets_capture'):
        raise ValueError('Linux clock-entry capture requires propagated offset observations')
    if result.get('timekeeper_layout_capture') and not result.get('clock_entry_capture'):
        raise ValueError('Linux timekeeper layout capture requires clock-entry observations')
    if bool(re.search(r'^OSREC_LINUX_IRQ_TIMEKEEPER_LAYOUT ',text,re.M))!=bool(result.get('timekeeper_layout_capture')):
        raise ValueError('Linux timekeeper layout marker differs from capture mode')
    if any(result.get(k) != v for k, v in dict(pid=1, tid=1, syscall=101, request_ns=20000000, timer_slack_ns=50000, raw=0).items()):
        raise ValueError('Linux IRQ workload arguments/result differ')
    if result['after_ns']-result['before_ns'] < result['request_ns']:
        raise ValueError('Linux wait returned before its requested interval')
    trace, stats = block(text, 'TRACE'), block(text, 'STATS')
    counters = {key.strip(): int(value) for key, value in re.findall(r'^([^:\n]+):\s*(\d+)\s*$', stats, re.M)}
    for key in ('overrun', 'commit overrun', 'dropped events'):
        if counters.get(key) != 0:
            raise ValueError('Linux IRQ trace loss or missing loss counter: '+key)
    formats = re.findall(r'^OSREC_LINUX_IRQ_FORMAT_BEGIN ([\w/]+)\n(.*?)\nOSREC_LINUX_IRQ_FORMAT_END \1$', text, re.M|re.S)
    expected_events=set(EVENTS) | ({'osrec/'+n for n in TASK_PROBES} if result.get('task_state_capture') is True else set())
    if result.get('sleeper_state_capture'):expected_events|={'osrec/'+n for n in SLEEPER_PROBES}
    if result.get('timer_state_capture'):expected_events|={'osrec/'+n for n in TIMER_PROBES}
    if result.get('timer_return_capture'):expected_events.add('osrec/osrec_timer_return')
    if result.get('base_state_capture'):expected_events|={'osrec/'+n for n in BASE_PROBES}
    if result.get('outer_state_capture'):expected_events|={'osrec/'+n for n in OUTER_PROBES}
    if result.get('clock_state_capture'):expected_events|={'osrec/'+n for n in CLOCK_PROBES}
    if result.get('clock_offsets_capture'):expected_events|={'osrec/'+n for n in OFFSETS_PROBES}
    if result.get('clock_entry_capture'):expected_events|={'osrec/'+n for n in ENTRY_PROBES}
    if len(formats) != len(expected_events) or {name for name, _ in formats} != expected_events:
        raise ValueError('Linux IRQ event formats are incomplete')
    if any(not re.search(r'^name: '+re.escape(name.split('/')[-1])+r'$', definition, re.M)
           or 'common_pid' not in definition for name, definition in formats):
        raise ValueError('Linux IRQ event format identity differs')
    if result.get('task_state_capture') is True:
        definitions=block(text,'PROBES');profile=block(text,'PROFILE')
        layout=parse_layout(text) if result.get('sleeper_state_capture') else None
        expected_definitions=TASK_DEFINITIONS+(sleeper_definitions(layout) if layout else '')+(TIMER_DEFINITIONS if result.get('timer_state_capture') else '')
        if result.get('timer_return_capture'):
            timer_layout=parse_timer_layout(text)
            if timer_layout['timer_size']>layout['task_offset']:raise ValueError('Linux timer return size differs from sleeper layout')
            expected_definitions+=timer_return_definitions(timer_layout)
        if result.get('base_state_capture'):expected_definitions+=base_definitions(timer_layout,parse_base_layout(text,timer_layout))
        if result.get('outer_state_capture'):expected_definitions+=OUTER_DEFINITIONS
        if result.get('timekeeper_layout_capture'):parse_timekeeper_layout(text)
        if result.get('clock_state_capture'):expected_definitions+=CLOCK_DEFINITIONS
        if result.get('clock_offsets_capture'):
            base_layout=parse_base_layout(text,timer_layout)
            expected_definitions+=offsets_definitions(timer_layout,base_layout,parse_offsets_layout(text,timer_layout,base_layout))
        if result.get('clock_entry_capture'):expected_definitions+=ENTRY_DEFINITIONS
        if definitions.strip()!=expected_definitions.strip():
            raise ValueError('Linux task-state probe definitions differ')
        for name in TASK_PROBES:
            if any(not re.search(r'field:(?:u32|s32) '+field+r';.*size:4;',dict(formats)['osrec/'+name]) for field in ('pid','state','saved','on_rq','on_cpu')):
                raise ValueError('Linux task-state probe field format differs')
        if layout:
            for name in SLEEPER_PROBES:
                if any(not re.search(r'field:u64 '+field+r';.*size:8;',dict(formats)['osrec/'+name]) for field in ('object','task')):
                    raise ValueError('Linux sleeper probe field format differs')
        if result.get('timer_state_capture'):
            for name in TIMER_PROBES:
                definition=dict(formats)['osrec/'+name]
                if any(not re.search(r'field:u64 '+field+r';.*size:8;',definition) for field in ('object','base','running')) or not re.search(r'field:u8 state;.*size:1;',definition):
                    raise ValueError('Linux timer probe field format differs')
        if result.get('timer_return_capture'):
            definition=dict(formats)['osrec/osrec_timer_return']
            if any(not re.search(r'field:u64 '+field+r';.*size:8;',definition) for field in ('object','base','running')) or not re.search(r'field:s32 result;.*size:4;',definition):
                raise ValueError('Linux timer return probe field format differs')
        if result.get('base_state_capture'):
            for name in BASE_PROBES:
                definition=dict(formats)['osrec/'+name]
                if any(not re.search(r'field:u64 '+field+r';.*size:8;',definition) for field in ('object','base','cpu_base')) or any(not re.search(r'field:u32 '+field+r';.*size:4;',definition) for field in ('index','active')):
                    raise ValueError('Linux base-state probe field format differs')
                if name.endswith('return') and not re.search(r'field:s32 result;.*size:4;',definition):raise ValueError('Linux base-state return format differs')
        if result.get('outer_state_capture'):
            definition=dict(formats)['osrec/osrec_outer_callback']
            if any(not re.search(r'field:u64 '+field+r';.*size:8;',definition) for field in ('object','cpu_base')) or not re.search(r'field:s64 deadline;.*size:8;',definition) or not re.search(r'field:u32 activated;.*size:4;',definition):
                raise ValueError('Linux outer-state probe field format differs')
        if result.get('clock_state_capture'):
            definition=dict(formats)['osrec/osrec_clock_return']
            if (any(not re.search(r'field:u64 '+field+r';.*size:8;.*signed:0;',definition) for field in ('seq','real','boot','tai')) or
                any(not re.search(r'field:s64 '+field+r';.*size:8;.*signed:1;',definition) for field in ('offs_real','offs_boot','offs_tai','now')) or
                not re.search(r'field:u32 sequence;.*size:4;.*signed:0;',definition)):
                raise ValueError('Linux clock-state probe field format differs')
        if result.get('clock_offsets_capture'):
            definition=dict(formats)['osrec/osrec_offsets_callback']
            if (any(not re.search(r'field:u64 '+field+r';.*size:8;.*signed:0;',definition) for field in ('object','cpu_base')) or
                any(not re.search(r'field:s64 soft_'+field+r';.*size:8;.*signed:1;',definition) for field in ('real','boot','tai')) or
                not re.search(r'field:u32 sequence;.*size:4;.*signed:0;',definition)):
                raise ValueError('Linux clock-offsets probe field format differs')
        if result.get('clock_entry_capture'):
            definition=dict(formats)['osrec/osrec_clock_entry']
            if (any(not re.search(r'field:u64 '+field+r';.*size:8;.*signed:0;',definition) for field in ('seq','real','boot','tai')) or
                any(not re.search(r'field:s64 '+field+r';.*size:8;.*signed:1;',definition) for field in ('offs_real','offs_boot','offs_tai')) or
                not re.search(r'field:u32 sequence;.*size:4;.*signed:0;',definition)):
                raise ValueError('Linux clock-entry probe field format differs')
        rows=re.findall(r'^\s*(?:osrec/)?(osrec_(?:task|sleeper|timer|base|outer|clock|offsets)_\w+)\s+(\d+)\s+(\d+)\s*$',profile,re.M)
        probes=TASK_PROBES+(SLEEPER_PROBES if layout else ())+(TIMER_PROBES if result.get('timer_state_capture') else ())+(('osrec_timer_return',) if result.get('timer_return_capture') else ())+(BASE_PROBES if result.get('base_state_capture') else ())+(OUTER_PROBES if result.get('outer_state_capture') else ())+(CLOCK_PROBES if result.get('clock_state_capture') else ())+(OFFSETS_PROBES if result.get('clock_offsets_capture') else ())+(ENTRY_PROBES if result.get('clock_entry_capture') else ())
        if len(rows)!=len(probes) or {n for n,_,_ in rows}!=set(probes) or any(int(misses) or not int(hits) for _,hits,misses in rows):
            raise ValueError('Linux task-state probe misses or incomplete profile')
    return result, trace, stats, dict(formats)


def capture(args):
    if getattr(args,'timekeeper_layout',False):args.clock_entry=True
    if getattr(args,'clock_entry',False):args.clock_offsets=True
    if getattr(args,'clock_offsets',False):args.clock_state=True
    if getattr(args,'clock_state',False):args.outer_state=True
    if getattr(args,'outer_state',False):args.base_state=True
    if getattr(args,'base_state',False):args.timer_return=True
    if getattr(args,'timer_return',False):args.timer_state=True
    if getattr(args,'timer_state',False):args.sleeper_state=True
    if getattr(args,'sleeper_state',False):args.task_state=True
    out = args.out.resolve()
    if out.exists():
        raise FileExistsError(out)
    identity, config = kernel_identity(args.kernel_image, getattr(args, 'config', None))
    missing = missing_config(config, REQUIRED + (TASK_REQUIRED + (('SYSFS',) if getattr(args,'sleeper_state',False) else ()) if getattr(args,'task_state',False) else ()))
    if missing:
        raise ValueError('Linux IRQ capture requires builtin '+', '.join(missing))
    if any(re.search(rb'^CONFIG_'+name+rb'=y$', config, re.M) for name in (b'HIGH_RES_TIMERS', b'PREEMPT_RT')):
        raise ValueError('initial Linux IRQ recipe requires low-resolution non-RT timer delivery')
    out.mkdir(parents=True)
    sources = out/'sources'; sources.mkdir()
    shutil.copyfile(SOURCE, sources/'native.c')
    if getattr(args,'sleeper_state',False):shutil.copyfile(SOURCE.parent/'btf_sleeper.h',sources/'btf_sleeper.h')
    if getattr(args,'timer_return',False):shutil.copyfile(SOURCE.parent/'btf_timer_return.h',sources/'btf_timer_return.h')
    if getattr(args,'base_state',False):shutil.copyfile(SOURCE.parent/'btf_base_state.h',sources/'btf_base_state.h')
    if getattr(args,'clock_offsets',False):shutil.copyfile(SOURCE.parent/'btf_clock_offsets.h',sources/'btf_clock_offsets.h')
    if getattr(args,'timekeeper_layout',False):shutil.copyfile(SOURCE.parent/'btf_timekeeper.h',sources/'btf_timekeeper.h')
    shutil.copyfile(ROOT/'integrations/linux_aarch64/native-start.S', sources/'start.S')
    init = out/'init'
    subprocess.run([str(args.llvm_bin/'clang'), '--target=aarch64-none-elf', '-mcpu=cortex-a53',
                    '-mgeneral-regs-only', '-mstrict-align', '-std=c11', '-O1', '-ffreestanding',
                    '-fno-builtin', '-fno-stack-protector', '-fno-unwind-tables',
                    '-fno-asynchronous-unwind-tables', '-Wall', '-Wextra', '-Werror',
                    *(['-DOSREC_TASK_STATE'] if getattr(args,'task_state',False) else []),
                    *(['-DOSREC_SLEEPER_STATE'] if getattr(args,'sleeper_state',False) else []),
                    *(['-DOSREC_TIMER_STATE'] if getattr(args,'timer_state',False) else []),
                    *(['-DOSREC_TIMER_RETURN'] if getattr(args,'timer_return',False) else []),
                    *(['-DOSREC_BASE_STATE'] if getattr(args,'base_state',False) else []),
                    *(['-DOSREC_OUTER_STATE'] if getattr(args,'outer_state',False) else []),
                    *(['-DOSREC_CLOCK_STATE'] if getattr(args,'clock_state',False) else []),
                    *(['-DOSREC_CLOCK_OFFSETS'] if getattr(args,'clock_offsets',False) else []),
                    *(['-DOSREC_CLOCK_ENTRY'] if getattr(args,'clock_entry',False) else []),
                    *(['-DOSREC_TIMEKEEPER_LAYOUT'] if getattr(args,'timekeeper_layout',False) else []),
                    '-nostdlib', '-static', '-fuse-ld=lld', '-Wl,--no-undefined',
                    '-Wl,-e,_start', '-Wl,-z,max-page-size=4096', str(sources/'start.S'),
                    str(sources/'native.c'), '-o', str(init)], check=True, capture_output=True, text=True)
    disk = out/'root.ext2'; disk.write_bytes(root_disk(init.read_bytes()))
    (out/'kernel.config').write_bytes(config)
    command = [args.qemu, '-machine', 'virt-9.2,gic-version=2', '-cpu', 'cortex-a53', '-accel', 'tcg', '-smp', '1',
               '-m', '512M', '-nographic', '-monitor', 'none', '-nic', 'none', '-no-reboot',
               '-kernel', str(args.kernel_image.resolve()), '-drive',
               'file='+str(disk)+',format=raw,if=none,id=root,readonly=on',
               '-device', 'virtio-blk-device,drive=root', '-append',
               'console=ttyAMA0 root=/dev/vda rootfstype=ext4 ro rootwait init=/init panic=-1']
    with (out/'qemu.log').open('wb') as log:
        completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout)
    if completed.returncode:
        raise ValueError('Linux IRQ guest failed; inspect '+str(out/'qemu.log'))
    result, trace, stats, formats = parse_output((out/'qemu.log').read_text(errors='replace'))
    if bool(result.get('task_state_capture'))!=bool(getattr(args,'task_state',False)):
        raise ValueError('Linux task-state capture mode differs')
    if bool(result.get('sleeper_state_capture'))!=bool(getattr(args,'sleeper_state',False)):
        raise ValueError('Linux sleeper capture manifest mode differs')
    if bool(result.get('timer_state_capture'))!=bool(getattr(args,'timer_state',False)):
        raise ValueError('Linux timer capture manifest mode differs')
    if bool(result.get('timer_return_capture'))!=bool(getattr(args,'timer_return',False)):
        raise ValueError('Linux timer return capture manifest mode differs')
    if bool(result.get('base_state_capture'))!=bool(getattr(args,'base_state',False)):
        raise ValueError('Linux base-state capture manifest mode differs')
    if bool(result.get('outer_state_capture'))!=bool(getattr(args,'outer_state',False)):
        raise ValueError('Linux outer-state capture manifest mode differs')
    if bool(result.get('clock_state_capture'))!=bool(getattr(args,'clock_state',False)):
        raise ValueError('Linux clock-state capture manifest mode differs')
    if bool(result.get('clock_offsets_capture'))!=bool(getattr(args,'clock_offsets',False)):
        raise ValueError('Linux clock-offsets capture manifest mode differs')
    if bool(result.get('clock_entry_capture'))!=bool(getattr(args,'clock_entry',False)):
        raise ValueError('Linux clock-entry capture manifest mode differs')
    if bool(result.get('timekeeper_layout_capture'))!=bool(getattr(args,'timekeeper_layout',False)):
        raise ValueError('Linux timekeeper layout capture manifest mode differs')
    if result.get('task_state_capture'):
        raw_log=(out/'qemu.log').read_text(errors='replace').replace('\r\n','\n')
        (out/'probe-definitions.txt').write_text(block(raw_log,'PROBES'))
        (out/'probe-profile.txt').write_text(block(raw_log,'PROFILE'))
    if result.get('sleeper_state_capture'):
        (out/'btf-layout.json').write_text(json.dumps(parse_layout(raw_log),indent=2)+'\n')
    if result.get('timer_return_capture'):
        (out/'timer-layout.json').write_text(json.dumps(parse_timer_layout(raw_log),indent=2)+'\n')
    if result.get('base_state_capture'):
        (out/'base-layout.json').write_text(json.dumps(parse_base_layout(raw_log,parse_timer_layout(raw_log)),indent=2)+'\n')
    if result.get('clock_offsets_capture'):
        (out/'clock-offsets-layout.json').write_text(json.dumps(parse_offsets_layout(raw_log,parse_timer_layout(raw_log),parse_base_layout(raw_log,parse_timer_layout(raw_log))),indent=2)+'\n')
    if result.get('timekeeper_layout_capture'):
        (out/'timekeeper-layout.json').write_text(json.dumps(parse_timekeeper_layout(raw_log),indent=2)+'\n')
    (out/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    (out/'trace.txt').write_text(trace)
    (out/'trace-stats.txt').write_text(stats)
    (out/'event-formats.json').write_text(json.dumps(formats, indent=2)+'\n')
    manifest = dict(format='osrec-linux-irq-capture-v1', status='native_trace_captured',
                    identity=identity, result=result, qemu_command=command,
                    native_linux_boot=True, native_source_build_attested=False,
                    task_state_capture=bool(result.get('task_state_capture')),
                    sleeper_state_capture=bool(result.get('sleeper_state_capture')),
                    timer_state_capture=bool(result.get('timer_state_capture')),
                    timer_return_capture=bool(result.get('timer_return_capture')),
                    timer_return_layout=parse_timer_layout(raw_log) if result.get('timer_return_capture') else None,
                    base_state_capture=bool(result.get('base_state_capture')),
                    base_state_layout=parse_base_layout(raw_log,parse_timer_layout(raw_log)) if result.get('base_state_capture') else None,
                    outer_state_capture=bool(result.get('outer_state_capture')),
                    clock_state_capture=bool(result.get('clock_state_capture')),
                    clock_offsets_capture=bool(result.get('clock_offsets_capture')),
                    clock_entry_capture=bool(result.get('clock_entry_capture')),
                    timekeeper_layout_capture=bool(result.get('timekeeper_layout_capture')),
                    timekeeper_layout=parse_timekeeper_layout(raw_log) if result.get('timekeeper_layout_capture') else None,
                    timekeeper_data_symbol_lookup_supported=bool(re.search(rb'^CONFIG_KALLSYMS_ALL=y$',config,re.M)),
                    clock_offsets_layout=json.loads((out/'clock-offsets-layout.json').read_text()) if result.get('clock_offsets_capture') else None,
                    sleeper_layout=parse_layout(raw_log) if result.get('sleeper_state_capture') else None, 
                    semihosting=False, artifact_sha256={str(p.relative_to(out)): digest(p.read_bytes())
                        for p in sorted(out.rglob('*')) if p.is_file()},
                    construction_sha256={str(p.relative_to(ROOT)): digest(p.read_bytes())
                        for p in (Path(__file__), SOURCE, ROOT/'tools/minimal_ext2.py',
                                  *([SOURCE.parent/'btf_sleeper.h'] if getattr(args,'sleeper_state',False) else []),
                                  *([SOURCE.parent/'btf_timer_return.h'] if getattr(args,'timer_return',False) else []),
                                  *([SOURCE.parent/'btf_base_state.h'] if getattr(args,'base_state',False) else []),
                                  *([SOURCE.parent/'btf_clock_offsets.h'] if getattr(args,'clock_offsets',False) else []),
                                  *([SOURCE.parent/'btf_timekeeper.h'] if getattr(args,'timekeeper_layout',False) else []))})
    (out/'capture.manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-image', type=Path, required=True)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--task-state',action='store_true',help='capture BTF-resolved native task fields using four entry probes')
    parser.add_argument('--sleeper-state',action='store_true',help='also capture BTF-resolved sleeper links; implies --task-state')
    parser.add_argument('--timer-state',action='store_true',help='also capture native timer state and base running pointer at callback entry; implies --sleeper-state')
    parser.add_argument('--timer-return',action='store_true',help='also capture base running pointer at sleep return using BTF offsets; implies --timer-state')
    parser.add_argument('--base-state',action='store_true',help='also observe clock-base index and active bit at callback/sleep return; implies --timer-return')
    parser.add_argument('--outer-state',action='store_true',help='also observe softirq deadline and activation at callback entry; implies --base-state')
    parser.add_argument('--clock-state',action='store_true',help='also capture native timekeeper return and offset outputs on each timer IRQ; implies --outer-state')
    parser.add_argument('--clock-offsets',action='store_true',help='also capture native propagated soft offsets at callback entry using BTF layout; implies --clock-state')
    parser.add_argument('--clock-entry',action='store_true',help='also capture timekeeper input sequence and hard offsets on every IRQ; implies --clock-offsets')
    parser.add_argument('--timekeeper-layout',action='store_true',help='discover a unique anonymous BTF layout candidate for tk_core; captures no provider memory; implies --clock-entry')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--llvm-bin', type=Path, default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--qemu', default='qemu-system-aarch64')
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    try:
        report = capture(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr)
        parser.exit(1, str(error)+'\n')
    print(json.dumps(dict(status=report['status'], **report['result']), indent=2))


if __name__ == '__main__':
    main()
