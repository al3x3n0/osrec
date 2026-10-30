"""Correlate one Linux nanosleep with its timer, IRQ and scheduler tracepoints."""
import re
import struct

KINDS = dict(enter=1, init=2, start=3, switch=4, irq_enter=5, cancel=6,
             expire=7, waking=8, wakeup=9, expire_exit=10, irq_exit=11, exit=12, task_state=13, sleeper_state=14, timer_state=15, timer_return=16, base_state=17, outer_state=18, clock_return=19, clock_offsets=20, propagated_offsets=21, clock_entry=22, clock_entry_offsets=23)
LINE = re.compile(r'^\s*(.+)-(\d+)\s+\[(\d+)\]\s+(\S+)\s+(\d+)\.(\d+):\s+(.*)$')


def fields(payload, pattern):
    match = re.fullmatch(pattern, payload)
    if not match:
        raise ValueError('unsupported Linux IRQ event payload: '+payload)
    return match.groups()


def decode(trace, result, stats, offsets_layout=None):
    if any(result.get(k) != v for k, v in dict(pid=1, tid=1, syscall=101, request_ns=20000000,
                                              timer_slack_ns=50000, raw=0).items()):
        raise ValueError('Linux IRQ request/result domain differs')
    counters = {k.strip(): int(v) for k, v in re.findall(r'^([^:\n]+):\s*(\d+)\s*$', stats, re.M)}
    if any(counters.get(k) != 0 for k in ('overrun', 'commit overrun', 'dropped events')):
        raise ValueError('Linux IRQ trace is incomplete or lost events')
    header = re.search(r'entries-in-buffer/entries-written: (\d+)/(\d+)\s+#P:(\d+)', trace)
    if not header or header[1] != header[2] or header[3] != '1':
        raise ValueError('Linux IRQ buffer is incomplete or not single-CPU')
    native, records = [], []
    current, irq_stack, timer, native_irq = 1, [], None, None
    entered = armed = blocked = expired = waking = awake = resumed = exited = cancelled = False
    callback_open = callback_closed = False
    last_stamp = 0
    deadline = soft = expiry_now = 0
    task_state_capture=result.get('task_state_capture') is True
    task_stage=0;task_pointer=None;task_states=[]
    sleeper_state_capture=result.get('sleeper_state_capture') is True
    if sleeper_state_capture and not task_state_capture:raise ValueError('Linux sleeper capture requires task observations')
    sleeper_stage=0;sleeper_pointer=None;sleeper_links=[]
    timer_state_capture=result.get('timer_state_capture') is True
    if timer_state_capture and not sleeper_state_capture:raise ValueError('Linux timer capture requires sleeper observations')
    timer_states=[];timer_base_pointer=None;timer_returns=[]
    timer_return_capture=result.get('timer_return_capture') is True
    if timer_return_capture and not timer_state_capture:raise ValueError('Linux timer return capture requires callback timer observations')
    base_state_capture=result.get('base_state_capture') is True
    if base_state_capture and not timer_return_capture:raise ValueError('Linux base-state capture requires timer return observations')
    base_states=[];cpu_base_pointer=None
    outer_state_capture=result.get('outer_state_capture') is True
    if outer_state_capture and not base_state_capture:raise ValueError('Linux outer-state capture requires base observations')
    outer_states=[]
    clock_state_capture=result.get('clock_state_capture') is True
    if clock_state_capture and not outer_state_capture:raise ValueError('Linux clock-state capture requires outer observations')
    clock_states=[];clock_pointers=None;irq_clock=None
    clock_offsets_capture=result.get('clock_offsets_capture') is True
    if clock_offsets_capture and (not clock_state_capture or offsets_layout is None):
        raise ValueError('Linux clock-offsets capture requires timekeeper observations and BTF layout')
    propagated_offsets=[]
    clock_entry_capture=result.get('clock_entry_capture') is True
    if clock_entry_capture and not clock_offsets_capture:raise ValueError('Linux clock-entry capture requires propagated offsets')
    clock_entries=[];irq_clock_entry=None
    timekeeper_layout_capture=result.get('timekeeper_layout_capture') is True
    if timekeeper_layout_capture and not clock_entry_capture:raise ValueError('Linux timekeeper layout capture requires clock-entry observations')



    for line in trace.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = LINE.fullmatch(line)
        if not match:
            raise ValueError('unparsed Linux IRQ trace line')
        comm, pid, cpu, flags, seconds, fraction, payload = match.groups()
        pid, cpu = int(pid), int(cpu)
        if cpu or pid != current or len(fraction)>9:
            raise ValueError('Linux IRQ CPU/current-task continuity differs')
        stamp = int(seconds)*1000000000+int(fraction.ljust(9, '0'))
        if stamp < last_stamp:
            raise ValueError('Linux IRQ timestamps moved backwards')
        last_stamp = stamp
        event_pid = current
        kind, a, b, c = 0, 0, 0, 0
        if payload.startswith('osrec_offsets_'):
            values=fields(payload,r'osrec_offsets_callback: \(hrtimer_wakeup\+0x0/0x[0-9a-f]+\) object=(0x[0-9a-f]+) cpu_base=(0x[0-9a-f]+) sequence=(\d+) soft_real=(-?\d+) soft_boot=(-?\d+) soft_tai=(-?\d+)')
            obj,cpu_base=int(values[0],16),int(values[1],16);sequence=int(values[2]);soft_offsets=tuple(int(v) for v in values[3:])
            if (not clock_offsets_capture or propagated_offsets or irq_clock is None or not callback_open or not irq_stack or pid==1 or
                sleeper_stage!=1 or outer_states or obj!=sleeper_pointer or cpu_base<0xffff000000000000 or cpu_base>0xffffffffffffffff or cpu_base%8 or cpu_base in (obj,task_pointer) or
                not clock_states[irq_clock]['selected_expiry'] or sequence!=clock_states[irq_clock]['sequence'] or
                soft_offsets!=tuple(clock_states[irq_clock][k] for k in ('offs_real','offs_boot','offs_tai'))):
                raise ValueError('Linux native propagated offsets, identity or context differ')
            expected=(cpu_base+offsets_layout['sequence_offset'],)+tuple(cpu_base+offsets_layout['array_offset']+i*offsets_layout['base_size']+offsets_layout['offset_offset'] for i in (1,2,3))
            if clock_pointers!=expected:raise ValueError('Linux native clock destinations differ from BTF CPU-base mapping')
            cpu_base_pointer=cpu_base
            propagated_offsets.append(dict(cpu_base_wire_id=1,sequence=sequence,soft_real=soft_offsets[0],soft_boot=soft_offsets[1],soft_tai=soft_offsets[2]))
            kind=KINDS['propagated_offsets'];a,b,c=(v&((1<<64)-1) for v in soft_offsets)
        elif payload.startswith('osrec_clock_entry:'):
            values=fields(payload,r'osrec_clock_entry: \(ktime_get_update_offsets_now\+0x0/0x[0-9a-f]+\) seq=(0x[0-9a-f]+) real=(0x[0-9a-f]+) boot=(0x[0-9a-f]+) tai=(0x[0-9a-f]+) sequence=(\d+) offs_real=(-?\d+) offs_boot=(-?\d+) offs_tai=(-?\d+)')
            pointers=tuple(int(v,16) for v in values[:4]);sequence=int(values[4]);entry_offsets=tuple(int(v) for v in values[5:])
            if (not clock_entry_capture or not entered or not irq_stack or irq_clock is not None or irq_clock_entry is not None or not native or
                not native[-1]['payload'].startswith('irq_handler_entry:') or cancelled or expired or
                len(set(pointers))!=4 or any(p<0xffff000000000000 or p>0xffffffffffffffff or p%(4 if i==0 else 8) for i,p in enumerate(pointers)) or
                (clock_pointers is not None and pointers!=clock_pointers) or sequence>0xffffffff or
                any(not -(1<<63)<=v<(1<<63) for v in entry_offsets)):
                raise ValueError('Linux native clock-entry fields, identity or context differ')
            clock_pointers=pointers;irq_clock_entry=len(clock_entries)
            clock_entries.append(dict(timekeeper_wire_id=1,irq_index=irq_clock_entry,sequence=sequence,
                offs_real=entry_offsets[0],offs_boot=entry_offsets[1],offs_tai=entry_offsets[2],selected_expiry=False))
            kind=KINDS['clock_entry'];a,b,c=sequence,1,0
        elif payload.startswith('osrec_clock_'):
            values=fields(payload,r'osrec_clock_return: \(hrtimer_run_queues\+0x[0-9a-f]+/0x[0-9a-f]+ <- ktime_get_update_offsets_now\) seq=(0x[0-9a-f]+) real=(0x[0-9a-f]+) boot=(0x[0-9a-f]+) tai=(0x[0-9a-f]+) sequence=(\d+) offs_real=(-?\d+) offs_boot=(-?\d+) offs_tai=(-?\d+) now=(-?\d+)')
            pointers=tuple(int(v,16) for v in values[:4]);sequence=int(values[4]);offsets=tuple(int(v) for v in values[5:8]);now=int(values[8])
            if (not clock_state_capture or not irq_stack or irq_clock is not None or not native or
                not native[-1]['payload'].startswith('osrec_clock_entry:' if clock_entry_capture else 'irq_handler_entry:') or
                (clock_entry_capture and irq_clock_entry!=len(clock_states)) or cancelled or expired or
                len(set(pointers))!=4 or any(p<0xffff000000000000 or p>0xffffffffffffffff or p%(4 if i==0 else 8) for i,p in enumerate(pointers)) or
                (clock_pointers is not None and pointers!=clock_pointers) or sequence>0xffffffff or
                any(not -(1<<63)<=v<(1<<63) for v in offsets) or
                not result['before_ns']<=now<=min(result['after_ns'],stamp+999) or
                (clock_states and now<=clock_states[-1]['now_ns'])):
                raise ValueError('Linux native clock-state fields, identity or context differ')
            clock_pointers=pointers;irq_clock=len(clock_states)
            clock_states.append(dict(timekeeper_wire_id=1,irq_index=irq_clock,sequence=sequence,
                now_ns=now,offs_real=offsets[0],offs_boot=offsets[1],offs_tai=offsets[2],selected_expiry=False))
            kind=KINDS['clock_return'];a,b,c=now,sequence,1
        elif payload.startswith('osrec_outer_'):
            symbol,obj,cpu_base,softirq_deadline,activated=fields(payload,
                r'osrec_outer_callback: \((\w+)\+0x0/0x[0-9a-f]+\) object=(0x[0-9a-f]+) cpu_base=(0x[0-9a-f]+) deadline=(-?\d+) activated=(\d+)')
            obj,cpu_base,softirq_deadline,activated=int(obj,16),int(cpu_base,16),int(softirq_deadline),int(activated)
            if (not outer_state_capture or outer_states or symbol!='hrtimer_wakeup' or obj!=sleeper_pointer or
                cpu_base<0xffff000000000000 or cpu_base%8 or cpu_base in (obj,task_pointer) or
                (cpu_base_pointer is not None and cpu_base!=cpu_base_pointer) or
                (clock_offsets_capture and len(propagated_offsets)!=1) or softirq_deadline!=0x7fffffffffffffff or activated):
                raise ValueError('Linux native outer-state fields or identity differ')
            if not callback_open or waking or not irq_stack or pid==1 or sleeper_stage!=1 or base_states:
                raise ValueError('Linux native outer-state context differs')
            cpu_base_pointer=cpu_base;kind=KINDS['outer_state'];a,b,c=1,softirq_deadline,activated
            outer_states.append(dict(cpu_base_wire_id=a,softirq_expires_next=b,softirq_activated=c))
        elif payload.startswith('osrec_base_'):
            returning=payload.startswith('osrec_base_return:')
            pattern=(r'osrec_base_return: \([^\n]+ <- (\w+)\) object=(0x[0-9a-f]+) base=(0x[0-9a-f]+) cpu_base=(0x[0-9a-f]+) index=(\d+) active=(\d+) result=(-?\d+)' if returning else
                     r'osrec_base_callback: \((\w+)\+0x0/0x[0-9a-f]+\) object=(0x[0-9a-f]+) base=(0x[0-9a-f]+) cpu_base=(0x[0-9a-f]+) index=(\d+) active=(\d+)')
            values=fields(payload,pattern);symbol,obj,base,cpu_base,index,active=values[:6]
            obj,base,cpu_base,index,active=int(obj,16),int(base,16),int(cpu_base,16),int(index),int(active)
            if (not base_state_capture or len(base_states)!=(1 if returning else 0) or
                (outer_state_capture and len(outer_states)!=1) or
                symbol!=('do_nanosleep' if returning else 'hrtimer_wakeup') or (returning and int(values[6])) or
                obj!=sleeper_pointer or base<0xffff000000000000 or base%8 or base==obj or
                (timer_base_pointer is not None and base!=timer_base_pointer) or
                cpu_base<0xffff000000000000 or cpu_base%8 or cpu_base in (obj,base,task_pointer) or
                (cpu_base_pointer is not None and cpu_base!=cpu_base_pointer) or index!=0 or
                active>0xffffffff or (returning and (active&1)!=base_states[0]['selected_active_bit'])):
                raise ValueError('Linux native base-state fields or identity differ')
            valid=(resumed and callback_closed and not irq_stack and pid==1 and sleeper_stage==4 and len(timer_returns)==1 if returning else
                   callback_open and not waking and bool(irq_stack) and pid!=1 and sleeper_stage==1 and not timer_states)
            if not valid:raise ValueError('Linux native base-state context differs')
            timer_base_pointer=base;cpu_base_pointer=cpu_base
            kind=KINDS['base_state'];a,b,c=(2 if returning else 1),index,(active>>index)&1
            base_states.append(dict(stage=a,base_wire_id=1,cpu_base_wire_id=1,index=index,active_bases=active,selected_active_bit=c))
        elif payload.startswith('osrec_timer_return:'):
            symbol,object_token,base_token,running_token,ret=fields(payload,
                r'osrec_timer_return: \([^\n]+ <- (\w+)\) object=(0x[0-9a-f]+) base=(0x[0-9a-f]+) running=(0x[0-9a-f]+) result=(-?\d+)')
            if (not timer_return_capture or timer_returns or symbol!='do_nanosleep' or int(ret) or
                int(object_token,16)!=sleeper_pointer or int(base_token,16)!=timer_base_pointer or int(running_token,16)):
                raise ValueError('Linux native timer return identity or running pointer differs')
            if not resumed or not callback_closed or irq_stack or pid!=1 or sleeper_stage!=4 or exited:
                raise ValueError('Linux native timer return context differs')
            kind=KINDS['timer_return'];a,b,c=1,1,0
            timer_returns.append(dict(timer_wire_id=a,base_wire_id=b,running_timer_wire_id=c))
        elif payload.startswith('osrec_timer_'):
            symbol,object_token,base_token,running_token,state=fields(payload,
                r'osrec_timer_callback: \((\w+)\+0x0/0x[0-9a-f]+\) object=(0x[0-9a-f]+) base=(0x[0-9a-f]+) running=(0x[0-9a-f]+) state=(\d+)')
            pointer,base,running=int(object_token,16),int(base_token,16),int(running_token,16)
            if (not timer_state_capture or timer_states or symbol!='hrtimer_wakeup' or
                pointer!=sleeper_pointer or base<0xffff000000000000 or base%8 or base==pointer or
                (base_state_capture and (len(base_states)!=1 or base!=timer_base_pointer)) or
                running!=pointer or int(state)!=0):
                raise ValueError('Linux native timer-state fields or identity differ')
            if not callback_open or waking or not irq_stack or pid==1 or sleeper_stage!=1 or task_stage!=1:
                raise ValueError('Linux native timer-state context differs')
            timer_base_pointer=base
            kind=KINDS['timer_state'];a,b,c=1,int(state),1
            timer_states.append(dict(stage=1,timer_wire_id=1,base_wire_id=1,state=b,running_timer_wire_id=c))
        elif payload.startswith('osrec_sleeper_'):
            names=('osrec_sleeper_entry','osrec_sleeper_callback','osrec_sleeper_callback_return','osrec_sleeper_return')
            if not sleeper_state_capture or sleeper_stage>=4:raise ValueError('unreviewed Linux sleeper observation')
            returning=sleeper_stage>=2
            pattern=(r'(osrec_sleeper_\w+): \([^\n]+ <- (\w+)\) object=(0x[0-9a-f]+) task=(0x[0-9a-f]+) result=(-?\d+)' if returning else
                     r'(osrec_sleeper_\w+): \((\w+)\+0x0/0x[0-9a-f]+\) object=(0x[0-9a-f]+) task=(0x[0-9a-f]+)')
            values=fields(payload,pattern);event,symbol,object_token,link_token=values[:4]
            expected_symbol=('do_nanosleep','hrtimer_wakeup','hrtimer_wakeup','do_nanosleep')[sleeper_stage]
            if (event!=names[sleeper_stage] or symbol!=expected_symbol or (returning and int(values[4])) or
                (sleeper_stage==1 and timer_state_capture and len(timer_states)!=1)):
                raise ValueError('Linux sleeper probe sequence or return differs')
            pointer,link=int(object_token,16),int(link_token,16)
            if pointer<0xffff000000000000 or pointer%8 or (sleeper_pointer is not None and pointer!=sleeper_pointer):
                raise ValueError('Linux sleeper/timer object identity differs')
            sleeper_pointer=pointer
            if returning:
                if link:raise ValueError('Linux sleeper task link was not cleared')
            else:
                if link<0xffff000000000000 or (task_pointer is not None and link!=task_pointer):
                    raise ValueError('Linux sleeper task identity differs')
                task_pointer=link
            valid=(entered and timer is not None and not armed and pid==1 and not irq_stack if sleeper_stage==0 else
                   callback_open and not waking and task_stage==1 and bool(irq_stack) if sleeper_stage==1 else
                   callback_open and awake and task_stage==4 and bool(irq_stack) if sleeper_stage==2 else
                   resumed and callback_closed and pid==1 and not irq_stack and not exited)
            if not valid:raise ValueError('Linux sleeper observation context differs')
            sleeper_stage+=1;kind=KINDS['sleeper_state'];a,b,c=sleeper_stage,1,0 if returning else 1
            sleeper_links.append(dict(stage=sleeper_stage,timer_wire_id=1,task_wire_id=c))
        elif payload.startswith('osrec_task_'):
            event,symbol,token,target,state,saved,on_rq,on_cpu=fields(payload,
                r'(osrec_task_\w+): \((\w+)\+0x0/0x[0-9a-f]+\) task=(0x[0-9a-f]+) pid=(\d+) state=(\d+) saved=(\d+) on_rq=(\d+) on_cpu=(\d+)')
            names=('osrec_task_dequeue','osrec_task_wake','osrec_task_activate','osrec_task_preempt')
            symbols=('dequeue_task_fair','wake_up_process','activate_task','wakeup_preempt')
            expected=((8193,0,1),(8193,0,0),(512,0,0),(512,1,0))
            if not task_state_capture or task_stage>=4 or event!=names[task_stage] or symbol!=symbols[task_stage]:
                raise ValueError('Linux native task-state probe sequence differs')
            state,saved,on_rq,on_cpu=int(state),int(saved),int(on_rq),int(on_cpu)
            pointer=int(token,16)
            if int(target)!=1 or saved or (state,on_rq,on_cpu)!=expected[task_stage] or pointer<0xffff000000000000:
                raise ValueError('Linux native task-state fields differ')
            if task_pointer is not None and task_pointer!=pointer:
                raise ValueError('Linux native task pointer identity differs')
            task_pointer=pointer
            if task_stage==0:
                valid=armed and not blocked and not irq_stack and pid==1
            else:
                valid=callback_open and bool(irq_stack) and pid!=1 and not awake and (waking==(task_stage>=2))
            if not valid:raise ValueError('Linux native task-state probe context differs')
            task_stage+=1;kind=KINDS['task_state'];a,b,c=task_stage,state,on_rq|(on_cpu<<32)
            task_states.append(dict(stage=task_stage,state=state,saved_state=saved,on_rq=on_rq,on_cpu=on_cpu,tid=1))
        elif payload.startswith('sys_nanosleep('):
            pointer, rem = fields(payload, r'sys_nanosleep\(rqtp: ([0-9a-f]+), rmtp: ([0-9a-f]+)\)')
            if entered or pid!=1 or irq_stack or not int(pointer,16) or int(rem,16):
                raise ValueError('Linux nanosleep entry differs')
            entered=True;kind=KINDS['enter'];a,b,c=101,20000000,50000
        elif payload.startswith('sys_nanosleep ->'):
            ret, = fields(payload, r'sys_nanosleep -> (0x[0-9a-f]+)')
            if (base_state_capture and len(base_states)!=2) or (timer_return_capture and len(timer_returns)!=1) or (sleeper_state_capture and sleeper_stage!=4) or int(ret,16) or not resumed or not callback_closed or irq_stack or pid!=1 or exited:
                raise ValueError('Linux nanosleep return differs')
            exited=True;kind=KINDS['exit']
        elif payload.startswith('irq_handler_entry:'):
            irq, name = fields(payload, r'irq_handler_entry: irq=(\d+) name=(\S+)')
            if name!='arch_timer' or irq_stack:
                raise ValueError('unreviewed Linux IRQ handler or nested interrupt')
            if native_irq is not None and native_irq!=int(irq):
                raise ValueError('Linux arch timer IRQ identity changed')
            native_irq=int(irq)
            irq_clock=None;irq_clock_entry=None
            irq_stack.append(int(irq));kind=KINDS['irq_enter'];a,b=int(irq),1
        elif payload.startswith('irq_handler_exit:'):
            irq, handled = fields(payload, r'irq_handler_exit: irq=(\d+) ret=(\S+)')
            if not irq_stack or int(irq)!=irq_stack[-1] or handled!='handled' or callback_open:
                raise ValueError('Linux IRQ exit is unbalanced or unhandled')
            if clock_state_capture and irq_clock is None:raise ValueError('missing Linux native clock return in IRQ')
            irq_stack.pop();irq_clock=None;irq_clock_entry=None;kind=KINDS['irq_exit'];a,b=int(irq),1
        elif payload.startswith('hrtimer_init:'):
            identity, = fields(payload, r'hrtimer_init: hrtimer=([0-9a-f]+) clockid=CLOCK_MONOTONIC mode=REL')
            if timer is not None or not int(identity,16) or not entered or exited or pid!=1 or irq_stack:
                raise ValueError('unreviewed Linux timer initialization')
            timer=identity;kind=KINDS['init'];a,b,c=1,1,1
        elif payload.startswith('hrtimer_start:'):
            identity, hard, minimum = fields(payload, r'hrtimer_start: hrtimer=([0-9a-f]+) function=hrtimer_wakeup expires=(\d+) softexpires=(\d+) mode=REL')
            if identity!=timer or armed or not entered or pid!=1 or irq_stack or (sleeper_state_capture and sleeper_stage!=1):
                raise ValueError('Linux timer arming/ownership differs')
            deadline,soft=int(hard),int(minimum)
            if deadline-soft!=result['timer_slack_ns'] or soft<result['before_ns']+result['request_ns'] or deadline>result['after_ns']:
                raise ValueError('Linux timer deadline/slack differs')
            armed=True;kind=KINDS['start'];a,b,c=1,deadline,soft
        elif payload.startswith('sched_switch:'):
            previous,state,nxt = fields(payload, r'sched_switch: prev_comm=\S+ prev_pid=(\d+) prev_prio=\d+ prev_state=(\S+) ==> next_comm=\S+ next_pid=(\d+) next_prio=\d+')
            previous,nxt=int(previous),int(nxt)
            if previous!=current or previous==nxt or irq_stack or state not in ('S','R','I','D'):
                raise ValueError('Linux scheduler ownership/state differs')
            if previous==1:
                if not armed or blocked or state!='S' or (task_state_capture and task_stage!=1):raise ValueError('Linux selected task did not block once')
                blocked=True
            if nxt==1:
                if not awake or resumed:raise ValueError('Linux task resumed before timer wakeup')
                resumed=True
            current=nxt;kind=KINDS['switch'];a,b,c=previous,nxt,{'R':0,'S':1,'I':2,'D':3}[state]
        elif payload.startswith('hrtimer_cancel:'):
            identity, = fields(payload, r'hrtimer_cancel: hrtimer=([0-9a-f]+)')
            if identity!=timer or not armed or cancelled or expired or not irq_stack:
                raise ValueError('Linux timer removal differs')
            if clock_state_capture and irq_clock is None:raise ValueError('Linux timer removal precedes native clock return')
            cancelled=True;kind=KINDS['cancel'];a=1
        elif payload.startswith('hrtimer_expire_entry:'):
            identity, now = fields(payload, r'hrtimer_expire_entry: hrtimer=([0-9a-f]+) function=hrtimer_wakeup now=(\d+)')
            if identity!=timer or not blocked or not cancelled or expired or not irq_stack or pid==1:
                raise ValueError('Linux expiry does not belong to the blocked task timer IRQ')
            expiry_now=int(now)
            if clock_state_capture:
                if irq_clock is None or expiry_now!=clock_states[irq_clock]['now_ns']:
                    raise ValueError('Linux native timekeeper return differs from selected expiry time')
                clock_states[irq_clock]['selected_expiry']=True
                if clock_entry_capture:clock_entries[irq_clock]['selected_expiry']=True
            if expiry_now<deadline:raise ValueError('Linux timer expired before its deadline')
            expired=True;callback_open=True;kind=KINDS['expire'];a,b=1,expiry_now
        elif payload.startswith('sched_waking:') or payload.startswith('sched_wakeup:'):
            event_name,target,target_cpu = fields(payload, r'(sched_waking|sched_wakeup): comm=init pid=(\d+) prio=\d+ target_cpu=(\d+)')
            if int(target)!=1 or int(target_cpu) or not callback_open or not irq_stack or pid==1:
                raise ValueError('Linux task wakeup is outside its timer callback/CPU')
            if event_name=='sched_waking':
                if waking or awake or (task_state_capture and task_stage!=2):raise ValueError('duplicate Linux task waking')
                waking=True;kind=KINDS['waking']
            else:
                if not waking or awake or (task_state_capture and task_stage!=4):raise ValueError('Linux wakeup ordering differs')
                awake=True;kind=KINDS['wakeup']
            a=1
        elif payload.startswith('hrtimer_expire_exit:'):
            identity, = fields(payload, r'hrtimer_expire_exit: hrtimer=([0-9a-f]+)')
            if identity!=timer or not awake or not irq_stack or not callback_open or (sleeper_state_capture and sleeper_stage!=3):
                raise ValueError('Linux callback exit precedes task wakeup')
            callback_open=False;callback_closed=True
            kind=KINDS['expire_exit'];a=1
        else:
            raise ValueError('unreviewed Linux IRQ trace event: '+payload)
        if len(flags)<3 or ((flags[2] in 'hH') != bool(irq_stack or kind==KINDS['irq_exit'])):
            raise ValueError('Linux hardirq context flag differs from IRQ boundaries')
        native.append(dict(pid=pid,cpu=cpu,timestamp_ns=stamp,flags=flags,payload=payload))
        if entered:
            if exited and kind!=KINDS['exit']:
                raise ValueError('events after Linux nanosleep completion')
            records.append(dict(kind=kind,pid=event_pid,a=a,b=b,c=c))
            if kind==KINDS['clock_entry']:
                records.append(dict(kind=KINDS['clock_entry_offsets'],pid=event_pid,**dict(zip(('a','b','c'),(v&((1<<64)-1) for v in entry_offsets)))))
            if kind==KINDS['clock_return']:
                records.append(dict(kind=KINDS['clock_offsets'],pid=event_pid,**dict(zip(('a','b','c'),(v&((1<<64)-1) for v in offsets)))))
    if not (entered and armed and blocked and expired and waking and awake and resumed and exited and callback_closed) or irq_stack or callback_open:
        raise ValueError('incomplete Linux IRQ/wait dependency chain')
    if sleeper_state_capture and sleeper_stage!=4:raise ValueError('incomplete Linux sleeper observations')
    if timer_state_capture and len(timer_states)!=1:raise ValueError('incomplete Linux native timer-state capture')
    if timer_return_capture and len(timer_returns)!=1:raise ValueError('incomplete Linux native timer return capture')
    if base_state_capture and len(base_states)!=2:raise ValueError('incomplete Linux native base-state capture')
    if outer_state_capture and len(outer_states)!=1:raise ValueError('incomplete Linux native outer-state capture')
    if clock_offsets_capture and timer_base_pointer!=cpu_base_pointer+offsets_layout['array_offset']:
        raise ValueError('Linux selected base differs from BTF CPU-base array mapping')
    if clock_offsets_capture and len(propagated_offsets)!=1:raise ValueError('incomplete Linux native propagated-offset capture')
    if clock_pointers and any(p in (sleeper_pointer,task_pointer,timer_base_pointer,cpu_base_pointer) for p in clock_pointers):
        raise ValueError('Linux native clock destination aliases another observed object')
    if clock_state_capture and (len(clock_states)!=sum(r['kind']==5 for r in records) or sum(r['selected_expiry'] for r in clock_states)!=1):
        raise ValueError('incomplete Linux native clock-state capture')
    if clock_entry_capture and len(clock_entries)!=len(clock_states):raise ValueError('incomplete Linux native clock-entry capture')
    transitions=[dict(irq_index=i,changed_fields=[k for k in ('sequence','offs_real','offs_boot','offs_tai') if entry[k]!=clock_states[i][k]]) for i,entry in enumerate(clock_entries)]
    if task_state_capture and task_stage!=4:raise ValueError('incomplete Linux native task-state capture')
    if len(native)!=int(header[1]) or counters.get('entries')!=len(native) or not 1<=len(records)<=4096:
        raise ValueError('Linux IRQ trace event count differs from buffer statistics')
    return dict(format='osrec-linux-irq-contract-v1',task_state_capture=task_state_capture,native_task_states=task_states,
                sleeper_state_capture=sleeper_state_capture,native_sleeper_links=sleeper_links,
                timer_state_capture=timer_state_capture,native_timer_states=timer_states,
                timer_return_capture=timer_return_capture,native_timer_returns=timer_returns,
                base_state_capture=base_state_capture,native_base_states=base_states,
                outer_state_capture=outer_state_capture,native_outer_states=outer_states,
                clock_state_capture=clock_state_capture,native_clock_states=clock_states,
                clock_entry_capture=clock_entry_capture,native_clock_entries=clock_entries,native_clock_transitions=transitions,
                timekeeper_layout_capture=timekeeper_layout_capture,
                clock_offsets_capture=clock_offsets_capture,native_propagated_offsets=propagated_offsets,
                native_clock_destinations_btf_cpu_base_mapping_verified=clock_offsets_capture,
                native_event_count=len(native),
                replay_event_count=len(records),irq_count=sum(r['kind']==5 for r in records),
                records=records,timer_wire_id=1,selected_tid=1,native_irq=native_irq,expires_ns=deadline,
                soft_expires_ns=soft,expiry_now_ns=expiry_now,native_source_build_attested=False,
                object_identity=('sleeper/task link and callback timer address correlated by direct native probes' if sleeper_state_capture else 'timer token is an opaque ftrace correlation key; typed sleeper/task association inferred from admitted construction'),
                scheduler_reproduction='recorded switch choices with sequential task-state models')


def pack(records):
    return b''.join(struct.pack('<IIQQQ',*(row[k] for k in ('kind','pid','a','b','c'))) for row in records)
