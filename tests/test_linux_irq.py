"""Real Linux IRQ trace correlation and standalone hardware callback replay."""
import gzip
import json
from pathlib import Path
import re
import shutil
import sys
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import export_linux_irq as exporter
from capture_linux_irq import parse_output, capture as capture_native
import capture_linux_irq as capture_tool
from linux_irq_trace import decode
from run_freestanding_armv7 import observe,require_success
FIXTURE=ROOT/'tests/fixtures/linux-aarch64-irq-native'
TASK_FIXTURE=ROOT/'tests/fixtures/linux-aarch64-irq-task-state-native'
SLEEPER_FIXTURE=ROOT/'tests/fixtures/linux-aarch64-irq-sleeper-native'
TIMER_FIXTURE=ROOT/'tests/fixtures/linux-aarch64-irq-timer-state-native'
RETURN_FIXTURE=ROOT/'tests/fixtures/linux-aarch64-irq-timer-return-native'
BASE_FIXTURE=ROOT/'tests/fixtures/linux-aarch64-irq-base-state-native'
ENTRY_FIXTURE=ROOT/'tests/fixtures/linux-aarch64-irq-clock-entry-native'
OFFSETS_FIXTURE=ROOT/'tests/fixtures/linux-aarch64-irq-clock-offsets-native'
CLOCK_FIXTURE=ROOT/'tests/fixtures/linux-aarch64-irq-clock-state-native'
OUTER_FIXTURE=ROOT/'tests/fixtures/linux-aarch64-irq-outer-state-native'
TIMEKEEPER_LAYOUT_FIXTURE=ROOT/'tests/fixtures/linux-aarch64-irq-timekeeper-layout-native'
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
QEMU='qemu-system-aarch64'


def prepare(stage,fixture=FIXTURE):
    capture=stage/'native'
    shutil.copytree(fixture,capture,ignore=shutil.ignore_patterns('root.ext2.gz'))
    (capture/'root.ext2').write_bytes(gzip.decompress((fixture/'root.ext2.gz').read_bytes()))
    return SimpleNamespace(capture=capture,out=stage/'image',llvm_bin=LLVM,qemu=QEMU,
                           entry_address=0x40200000,result_address=0x40180000)


class LinuxIRQTests(unittest.TestCase):
    def test_real_capture_and_standalone_relocated_hardware_replay(self):
        for fixture,address in ((FIXTURE,0x40200000),(FIXTURE,0x40400000),(TASK_FIXTURE,0x40400000),(SLEEPER_FIXTURE,0x40400000),(TIMER_FIXTURE,0x40400000),(RETURN_FIXTURE,0x40400000),(BASE_FIXTURE,0x40400000),(OUTER_FIXTURE,0x40400000),(CLOCK_FIXTURE,0x40400000),(OFFSETS_FIXTURE,0x40400000),(ENTRY_FIXTURE,0x40400000)):
            with self.subTest(address=address,fixture=fixture.name),tempfile.TemporaryDirectory() as name:
                stage=Path(name);args=prepare(stage,fixture);args.entry_address=address;args.result_address=address-0x80000
                contract,native=exporter.load_capture(args.capture)
                self.assertGreaterEqual(contract['replay_event_count'],13)
                self.assertGreaterEqual(contract['irq_count'],1)
                self.assertGreaterEqual(contract['expiry_now_ns'],contract['expires_ns'])
                report=exporter.export(args)
                self.assertTrue(report['hardware_irq_delivery']);self.assertFalse(report['kernel_scheduler_reproduction'])
                self.assertFalse(report['runtime_host_interaction']);self.assertTrue(report['independent_ram_events_verified'])
                self.assertFalse(native['native_source_build_attested'])
                self.assertEqual(report['native_task_fields_verified'],fixture!=FIXTURE)
                self.assertEqual(sum(r['kind']==13 for r in contract['records']),4 if fixture!=FIXTURE else 0)
                if fixture!=FIXTURE:
                    token=int(re.search(r'task=(0x[0-9a-f]+)',(args.capture/'trace.txt').read_text())[1],16)
                    self.assertNotIn(token.to_bytes(8,'little'),(args.out/'linux-irq.elf').read_bytes())
                self.assertEqual(report['native_sleeper_links_verified'],fixture in (SLEEPER_FIXTURE,TIMER_FIXTURE,RETURN_FIXTURE,BASE_FIXTURE,OUTER_FIXTURE,CLOCK_FIXTURE,OFFSETS_FIXTURE,ENTRY_FIXTURE))
                if fixture in (SLEEPER_FIXTURE,TIMER_FIXTURE,RETURN_FIXTURE,BASE_FIXTURE,OUTER_FIXTURE,CLOCK_FIXTURE,OFFSETS_FIXTURE,ENTRY_FIXTURE):
                    self.assertEqual([r['task_wire_id'] for r in report['native_sleeper_links']],[1,1,0,0])
                    for token in re.findall(r'object=(0x[0-9a-f]+)',(args.capture/'trace.txt').read_text()):
                        self.assertNotIn(int(token,16).to_bytes(8,'little'),(args.out/'linux-irq.elf').read_bytes())
                self.assertEqual(report['native_timer_fields_verified'],fixture in (TIMER_FIXTURE,RETURN_FIXTURE,BASE_FIXTURE,OUTER_FIXTURE,CLOCK_FIXTURE,OFFSETS_FIXTURE,ENTRY_FIXTURE))
                if fixture in (TIMER_FIXTURE,RETURN_FIXTURE,BASE_FIXTURE,OUTER_FIXTURE,CLOCK_FIXTURE,OFFSETS_FIXTURE,ENTRY_FIXTURE):
                    self.assertEqual(report['native_timer_observations'],[dict(stage=1,timer_wire_id=1,base_wire_id=1,state=0,running_timer_wire_id=1)])
                    for token in re.findall(r'(?:base|running)=(0x[0-9a-f]+)',(args.capture/'trace.txt').read_text()):
                        if int(token,16):
                            self.assertFalse(int(token,16).to_bytes(8,'little') in (args.out/'linux-irq.elf').read_bytes(),
                                             'native base/running address embedded in replay ELF')
                self.assertEqual(report['native_timer_return_verified'],fixture in (RETURN_FIXTURE,BASE_FIXTURE,OUTER_FIXTURE,CLOCK_FIXTURE,OFFSETS_FIXTURE,ENTRY_FIXTURE))
                if fixture in (RETURN_FIXTURE,BASE_FIXTURE,OUTER_FIXTURE,CLOCK_FIXTURE,OFFSETS_FIXTURE,ENTRY_FIXTURE):
                    self.assertEqual(report['native_timer_return_observations'],[dict(timer_wire_id=1,base_wire_id=1,running_timer_wire_id=0)])
                self.assertEqual(report['native_base_fields_verified'],fixture in (BASE_FIXTURE,OUTER_FIXTURE,CLOCK_FIXTURE,OFFSETS_FIXTURE,ENTRY_FIXTURE))
                if fixture in (BASE_FIXTURE,OUTER_FIXTURE,CLOCK_FIXTURE,OFFSETS_FIXTURE,ENTRY_FIXTURE):
                    self.assertEqual(report['background_base_occupancy'],1)
                    self.assertEqual([r['selected_active_bit'] for r in report['native_base_observations']],[1,1])
                    for token in re.findall(r'cpu_base=(0x[0-9a-f]+)',(args.capture/'trace.txt').read_text()):
                        self.assertFalse(int(token,16).to_bytes(8,'little') in (args.out/'linux-irq.elf').read_bytes())
                self.assertEqual(report['native_outer_fields_verified'],fixture in (OUTER_FIXTURE,CLOCK_FIXTURE,OFFSETS_FIXTURE,ENTRY_FIXTURE))
                if fixture in (OUTER_FIXTURE,CLOCK_FIXTURE,OFFSETS_FIXTURE,ENTRY_FIXTURE):
                    self.assertEqual(report['native_outer_observations'],[dict(cpu_base_wire_id=1,softirq_expires_next=0x7fffffffffffffff,softirq_activated=0)])
                expected=(args.out/'expected-events.bin').read_bytes()
                self.assertEqual((args.out/'target-events-0.bin').read_bytes(),expected)
                self.assertEqual((args.out/'target-events-1.bin').read_bytes(),expected)
                self.assertTrue(report['independent_scheduler_witnesses_verified'])
                expected_queue=(args.out/'expected-queue.bin').read_bytes()
                self.assertEqual(len(expected_queue),128)
                for index in (0,1):self.assertEqual((args.out/f'target-queue-{index}.bin').read_bytes(),expected_queue)
                queue_address=report['scheduler_witnesses']['address']
                self.assertTrue(report['independent_timer_witnesses_verified'])
                self.assertEqual(set(report['original_timer_functions']),{'hrtimer_wakeup','hrtimer_init_sleeper',
                    '__hrtimer_init_sleeper','hrtimer_sleeper_start_expires','enqueue_hrtimer','__remove_hrtimer','__run_hrtimer','__hrtimer_run_queues','hrtimer_run_queues','hrtimer_update_base'})
                expected_timer=(args.out/'expected-timer.bin').read_bytes();self.assertEqual(len(expected_timer),128)
                for index in (0,1):self.assertEqual((args.out/f'target-timer-{index}.bin').read_bytes(),expected_timer)
                timer_address=report['timer_witnesses']['address']
                self.assertTrue(report['independent_timer_queue_witnesses_verified'])
                expected_timer_queue=(args.out/'expected-timer-queue.bin').read_bytes();self.assertEqual(len(expected_timer_queue),160)
                for index in (0,1):self.assertEqual((args.out/f'target-timer-queue-{index}.bin').read_bytes(),expected_timer_queue)
                timer_queue_address=report['timer_queue_witnesses']['address']
                self.assertTrue(report['independent_callback_witnesses_verified'])
                expected_callback=(args.out/'expected-callback.bin').read_bytes();self.assertEqual(len(expected_callback),224)
                for index in (0,1):self.assertEqual((args.out/f'target-callback-{index}.bin').read_bytes(),expected_callback)
                callback_address=report['callback_witnesses']['address']
                self.assertTrue(report['independent_ordered_queue_witnesses_verified'])
                expected_ordered=(args.out/'expected-ordered.bin').read_bytes();self.assertEqual(len(expected_ordered),128)
                for index in (0,1):self.assertEqual((args.out/f'target-ordered-{index}.bin').read_bytes(),expected_ordered)
                ordered_address=report['ordered_queue_witnesses']['address']
                self.assertTrue(report['independent_timer_driver_witnesses_verified'])
                expected_driver=(args.out/'expected-driver.bin').read_bytes();self.assertEqual(len(expected_driver),128)
                for index in (0,1):self.assertEqual((args.out/f'target-driver-{index}.bin').read_bytes(),expected_driver)
                driver_address=report['timer_driver_witnesses']['address']
                self.assertTrue(report['independent_outer_timer_witnesses_verified'])
                expected_outer=(args.out/'expected-outer.bin').read_bytes();self.assertEqual(len(expected_outer),224)
                for index in (0,1):self.assertEqual((args.out/f'target-outer-{index}.bin').read_bytes(),expected_outer)
                outer_address=report['outer_timer_witnesses']['address']
                self.assertTrue(report['independent_timer_clock_witnesses_verified'])
                self.assertEqual(report['native_clock_update_return_captured'],fixture in (CLOCK_FIXTURE,OFFSETS_FIXTURE,ENTRY_FIXTURE));self.assertEqual(report['native_clock_offsets_captured'],fixture in (CLOCK_FIXTURE,OFFSETS_FIXTURE,ENTRY_FIXTURE))
                if fixture in (CLOCK_FIXTURE,OFFSETS_FIXTURE,ENTRY_FIXTURE):
                    self.assertEqual(len(report['native_clock_observations']),contract['irq_count'])
                    self.assertEqual(sum(r['kind']==19 for r in contract['records']),contract['irq_count'])
                    selected=next(r for r in report['native_clock_observations'] if r['selected_expiry'])
                    self.assertEqual(selected['now_ns'],contract['expiry_now_ns'])
                    self.assertEqual(list(report['timer_clock_witnesses']['rows'][1][2:]),[selected['sequence'],selected['now_ns'],selected['offs_real'],selected['offs_boot'],selected['offs_tai'],selected['offs_real'],selected['offs_boot'],selected['offs_tai']])
                    for token in re.findall(r'(?:seq|real|boot|tai)=(0x[0-9a-f]+)',(args.capture/'trace.txt').read_text()):
                        self.assertNotIn(int(token,16).to_bytes(8,'little'),(args.out/'linux-irq.elf').read_bytes())
                self.assertEqual(report['native_propagated_offsets_verified'],fixture in (OFFSETS_FIXTURE,ENTRY_FIXTURE))
                if fixture in (OFFSETS_FIXTURE,ENTRY_FIXTURE):
                    self.assertTrue(report['native_clock_destinations_btf_cpu_base_mapping_verified'])
                    self.assertEqual(sum(r['kind']==21 for r in contract['records']),1)
                    self.assertEqual([r[k] for k in ('soft_real','soft_boot','soft_tai') for r in report['native_propagated_offset_observations']], [selected[k] for k in ('offs_real','offs_boot','offs_tai')])
                self.assertEqual(report['native_clock_entry_fields_verified'],fixture==ENTRY_FIXTURE)
                if fixture==ENTRY_FIXTURE:
                    self.assertEqual(sum(r['kind']==22 for r in contract['records']),contract['irq_count'])
                    self.assertEqual(len(report['native_clock_entry_observations']),contract['irq_count'])
                    self.assertTrue(all(not t['changed_fields'] for t in report['native_clock_value_transitions']))
                expected_clock=(args.out/'expected-clock.bin').read_bytes();self.assertEqual(len(expected_clock),160)
                for index in (0,1):self.assertEqual((args.out/f'target-clock-{index}.bin').read_bytes(),expected_clock)
                clock_address=report['timer_clock_witnesses']['address']
                standalone=stage/'standalone';standalone.mkdir()
                for n in ('linux-irq.elf','linux-irq.bin'):shutil.copyfile(args.out/n,standalone/n)
                shutil.rmtree(args.capture);shutil.rmtree(args.out)
                elf=standalone/'linux-irq.elf'
                a,raw=observe(elf,QEMU,memory_dumps=({'address':queue_address,'bytes':128,'file':str(standalone/'queue-elf.bin')},
                    {'address':timer_address,'bytes':128,'file':str(standalone/'timer-elf.bin')},
                    {'address':timer_queue_address,'bytes':160,'file':str(standalone/'timer-queue-elf.bin')},
                    {'address':callback_address,'bytes':224,'file':str(standalone/'callback-elf.bin')},
                    {'address':ordered_address,'bytes':128,'file':str(standalone/'ordered-elf.bin')},
                    {'address':driver_address,'bytes':128,'file':str(standalone/'driver-elf.bin')},
                    {'address':outer_address,'bytes':224,'file':str(standalone/'outer-elf.bin')},
                    {'address':clock_address,'bytes':160,'file':str(standalone/'clock-elf.bin')}))
                b,binary_raw=observe(standalone/'linux-irq.bin',QEMU,descriptor=elf,
                                     memory_dumps=({'address':queue_address,'bytes':128,'file':str(standalone/'queue-raw.bin')},
                                         {'address':timer_address,'bytes':128,'file':str(standalone/'timer-raw.bin')},
                                         {'address':timer_queue_address,'bytes':160,'file':str(standalone/'timer-queue-raw.bin')},
                                         {'address':callback_address,'bytes':224,'file':str(standalone/'callback-raw.bin')},
                                         {'address':ordered_address,'bytes':128,'file':str(standalone/'ordered-raw.bin')},
                                         {'address':driver_address,'bytes':128,'file':str(standalone/'driver-raw.bin')},
                                         {'address':outer_address,'bytes':224,'file':str(standalone/'outer-raw.bin')},
                    {'address':clock_address,'bytes':160,'file':str(standalone/'clock-raw.bin')}))
                for n in ('queue-elf.bin','queue-raw.bin'):self.assertEqual((standalone/n).read_bytes(),expected_queue)
                for n in ('timer-elf.bin','timer-raw.bin'):self.assertEqual((standalone/n).read_bytes(),expected_timer)
                for n in ('timer-queue-elf.bin','timer-queue-raw.bin'):self.assertEqual((standalone/n).read_bytes(),expected_timer_queue)
                for n in ('callback-elf.bin','callback-raw.bin'):self.assertEqual((standalone/n).read_bytes(),expected_callback)
                for n in ('ordered-elf.bin','ordered-raw.bin'):self.assertEqual((standalone/n).read_bytes(),expected_ordered)
                for n in ('driver-elf.bin','driver-raw.bin'):self.assertEqual((standalone/n).read_bytes(),expected_driver)
                for n in ('outer-elf.bin','outer-raw.bin'):self.assertEqual((standalone/n).read_bytes(),expected_outer)
                for n in ('clock-elf.bin','clock-raw.bin'):self.assertEqual((standalone/n).read_bytes(),expected_clock)
                require_success(a);require_success(b);self.assertEqual(raw,binary_raw)
                self.assertEqual(a['irq_count'],contract['irq_count']);self.assertEqual(a['callback_calls'],1)
                self.assertTrue(a['sleeper_task_cleared'])
                self.assertEqual(a['abi_version'],29)
                self.assertEqual(set(report['original_scheduler_functions']),
                                 {'__task_state_match','ttwu_state_match','ttwu_do_wakeup','wake_up_process',
                                  'enqueue_task','dequeue_task','activate_task','deactivate_task'})
                for key,expected_value in (('task_on_rq',1),('task_on_cpu',1),('activation_calls',1),
                                           ('wake_attempts',2),('denied_wakes',1),('state_guard_checks',6)):
                    self.assertEqual(a[key],expected_value)
                    with self.subTest(terminal_field=key),self.assertRaisesRegex(ValueError,'target replay diverged'):
                        require_success({**a,key:expected_value+1})

    def test_false_timer_task_irq_context_deadline_and_sequence_reject(self):
        trace=(FIXTURE/'trace.txt').read_text();result=json.loads((FIXTURE/'result.json').read_text());stats=(FIXTURE/'trace-stats.txt').read_text()
        mutations=[
            trace.replace('irq_handler_exit: irq=11','irq_handler_exit: irq=12',1),
            trace.replace('name=arch_timer','name=other_device',1),
            trace.replace('sched_waking: comm=init pid=1','sched_waking: comm=init pid=2',1),
            trace.replace('target_cpu=000','target_cpu=001',1),
            re.sub(r'(hrtimer_expire_entry: hrtimer=)[0-9a-f]+',r'\g<1>0000000000000001',trace,count=1),
            re.sub(r'(hrtimer_expire_entry: .* now=)\d+',r'\g<1>0',trace,count=1),
            trace.replace('function=hrtimer_wakeup','function=wrong_callback',1),
            trace.replace('prev_pid=1 prev_prio=120 prev_state=S','prev_pid=1 prev_prio=120 prev_state=R',1),
            trace.replace('sys_nanosleep -> 0x0','sys_nanosleep -> 0x1',1),
        ]
        waking=next(line for line in trace.splitlines() if 'sched_waking:' in line)
        mutations.append(trace.replace(waking,re.sub(r'\s+d.h..\s+', ' ..... ',waking)))
        for i,bad in enumerate(mutations):
            with self.subTest(i=i):
                self.assertNotEqual(bad,trace)
                with self.assertRaises(ValueError):decode(bad,result,stats)
        for key,value in (('raw',1),('request_ns',1),('timer_slack_ns',0)):
            with self.subTest(result=key),self.assertRaises(ValueError):decode(trace,{**result,key:value},stats)

    def test_loss_missing_formats_and_native_artifact_tampering_reject(self):
        text=(FIXTURE/'qemu.log').read_text()
        for bad in (text.replace('dropped events: 0','dropped events: 1'),
                    text.replace('commit overrun: 0','commit overrun: 1'),
                    text.replace('OSREC_LINUX_IRQ_FORMAT_BEGIN irq/irq_handler_exit','OSREC_LINUX_IRQ_FORMAT_BEGIN irq/unknown'),
                    text.replace('OSREC_LINUX_IRQ_DONE','OSREC_LINUX_IRQ_FAILED')):
            with self.assertRaises(ValueError):parse_output(bad)
        with tempfile.TemporaryDirectory() as name:
            args=prepare(Path(name));(args.capture/'trace.txt').write_text('changed')
            with self.assertRaisesRegex(ValueError,'artifact changed'):exporter.export(args)
            self.assertFalse(args.out.exists())
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);shutil.copyfile(exporter.INTEGRATION/'source-identity.json',root/'source-identity.json')
            (root/'hrtimer_wakeup.c').write_bytes((exporter.INTEGRATION/'hrtimer_wakeup.c').read_bytes()+b'\n')
            with patch.object(exporter,'INTEGRATION',root):
                with self.assertRaisesRegex(ValueError,'callback source changed'):exporter.source_identity()

    def test_native_task_fields_probe_provenance_and_configuration_reject(self):
        trace=(TASK_FIXTURE/'trace.txt').read_text();result=json.loads((TASK_FIXTURE/'result.json').read_text());stats=(TASK_FIXTURE/'trace-stats.txt').read_text()
        for bad in (trace.replace('state=8193','state=1',1),trace.replace('saved=0','saved=1',1),
                    trace.replace('on_rq=0 on_cpu=1','on_rq=1 on_cpu=1',1),
                    trace.replace('dequeue_task_fair+','wrong_function+',1),
                    re.sub(r'task=0x[0-9a-f]+','task=0xffff000000000001',trace,count=1)):
            with self.subTest(trace=bad[:32]),self.assertRaises(ValueError):decode(bad,result,stats)
        text=(TASK_FIXTURE/'qemu.log').read_text()
        bad_profile=re.sub(r'(osrec_task_dequeue +\d+ +)0',r'\g<1>1',text,count=1)
        self.assertNotEqual(bad_profile,text)
        for bad in (bad_profile,text.replace('pid=p->pid:s32','pid=p->tgid:s32',1),
                    text.replace('field:u32 state;','field:u64 state;',1)):
            self.assertNotEqual(bad,text)
            with self.assertRaises(ValueError):parse_output(bad)
        with tempfile.TemporaryDirectory() as name:
            config=(TASK_FIXTURE/'kernel.config').read_bytes().replace(b'CONFIG_PROBE_EVENTS_BTF_ARGS=y',b'# CONFIG_PROBE_EVENTS_BTF_ARGS is not set')
            args=SimpleNamespace(out=Path(name)/'capture',kernel_image=Path('unused'),task_state=True)
            with patch.object(capture_tool,'kernel_identity',return_value=({},config)):
                with self.assertRaisesRegex(ValueError,'PROBE_EVENTS_BTF_ARGS'):capture_native(args)
            self.assertFalse(args.out.exists())

    def test_native_state_transition_mutants_reject(self):
        changes=[('irq_checkpoint.h','checkpoint_sleep_state=8193','checkpoint_sleep_state=1',1),
                 ('replay.c','selected.__state=checkpoint_activation_state;',
                             'selected.__state=checkpoint_sleep_state;',1),
                 ('replay.c','emit_task_state(4);','/* omit native preempt observation */',1)]
        self._assert_mutants_rejected(changes,TASK_FIXTURE)

    def test_sleeper_identity_link_return_and_layout_corruption_reject(self):
        trace=(SLEEPER_FIXTURE/'trace.txt').read_text();result=json.loads((SLEEPER_FIXTURE/'result.json').read_text());stats=(SLEEPER_FIXTURE/'trace-stats.txt').read_text()
        callback=next(l for l in trace.splitlines() if 'osrec_sleeper_callback:' in l)
        returned=next(l for l in trace.splitlines() if 'osrec_sleeper_callback_return:' in l)
        for bad in (trace.replace(callback,re.sub(r'object=0x[0-9a-f]+','object=0xffff000000000008',callback)),
                    trace.replace(callback,re.sub(r'task=0x[0-9a-f]+','task=0xffff000000000008',callback)),
                    trace.replace(returned,returned.replace('task=0x0','task=0xffff000000000008')),
                    trace.replace(returned,returned.replace('result=0','result=1')),
                    trace.replace('osrec_sleeper_callback_return:','osrec_sleeper_return:',1)):
            with self.assertRaises(ValueError):decode(bad,result,stats)
        text=(SLEEPER_FIXTURE/'qemu.log').read_text()
        for bad in (text.replace('"timer_offset":0','"timer_offset":8',1),
                    text.replace('task=+64($arg1):x64','task=+56($arg1):x64',1),
                    text.replace('r8:osrec/osrec_sleeper_return','r9:osrec/osrec_sleeper_return',1)):
            self.assertNotEqual(bad,text)
            with self.assertRaises(ValueError):parse_output(bad)

    def test_sleeper_runtime_mutants_reject(self):
        changes=[('timer_run_model.c','emit_sleeper_state(2);','/* omit callback link observation */',1),
                 ('timer_run_model.c','emit_sleeper_state(3);','sleeper.task=&selected;emit_sleeper_state(3);',1),
                 ('replay.c','emit(14,stage,sleeper.timer.id,sleeper.task?sleeper.task->id:0);',
                             'emit(14,stage,2,sleeper.task?sleeper.task->id:0);',1)]
        self._assert_mutants_rejected(changes,SLEEPER_FIXTURE)

    def test_native_timer_fields_identity_context_and_probe_provenance_reject(self):
        trace=(TIMER_FIXTURE/'trace.txt').read_text();result=json.loads((TIMER_FIXTURE/'result.json').read_text());stats=(TIMER_FIXTURE/'trace-stats.txt').read_text()
        row=next(line for line in trace.splitlines() if 'osrec_timer_callback:' in line)
        mutations=[row.replace('state=0','state=1'),
                   re.sub(r'running=0x[0-9a-f]+','running=0x0',row),
                   re.sub(r'base=0x[0-9a-f]+','base=0xffff000000000001',row),
                   re.sub(r'base=0x[0-9a-f]+','base='+re.search(r'object=(0x[0-9a-f]+)',row)[1],row),
                   re.sub(r'object=0x[0-9a-f]+','object=0xffff000000000008',row),
                   row.replace('hrtimer_wakeup+','other_callback+')]
        for changed in mutations:
            with self.subTest(changed=changed),self.assertRaises(ValueError):decode(trace.replace(row,changed),result,stats)
        with self.assertRaises(ValueError):decode(trace,{**result,'timer_state_capture':False},stats)
        sleeper=next(line for line in trace.splitlines() if 'osrec_sleeper_callback:' in line)
        with self.assertRaises(ValueError):decode(trace.replace(row,'SWAP').replace(sleeper,row).replace('SWAP',sleeper),result,stats)
        text=(TIMER_FIXTURE/'qemu.log').read_text()
        for bad in (text.replace('state=timer->state:u8','state=timer->is_rel:u8',1),
                    text.replace('field:u8 state;','field:u32 state;',1),
                    text.replace('"timer_state_capture":true','"timer_state_capture":false',1),
                    re.sub(r'(osrec_timer_callback +[0-9]+ +)0',r'\g<1>1',text,count=1)):
            self.assertNotEqual(bad,text)
            with self.assertRaises(ValueError):parse_output(bad)
        with tempfile.TemporaryDirectory() as name:
            args=prepare(Path(name),TIMER_FIXTURE)
            manifest=json.loads((args.capture/'capture.manifest.json').read_text());manifest['timer_state_capture']=False
            (args.capture/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'timer capture manifest mode'):exporter.export(args)
            self.assertFalse(args.out.exists())

    def test_native_timer_observation_runtime_mutants_reject(self):
        emit='emit(15,1,timer->state,timer_base.running==timer?timer->id:0);'
        changes=[('timer_run_model.c',emit,'/* omit native timer observation */',1),
                 ('timer_run_model.c',emit,'emit(15,1,1,timer_base.running==timer?timer->id:0);',1),
                 ('timer_run_model.c',emit,'emit(15,1,timer->state,0);',1)]
        self._assert_mutants_rejected(changes,TIMER_FIXTURE)

    def test_native_timer_return_identity_order_and_layout_reject(self):
        trace=(RETURN_FIXTURE/'trace.txt').read_text();result=json.loads((RETURN_FIXTURE/'result.json').read_text());stats=(RETURN_FIXTURE/'trace-stats.txt').read_text()
        row=next(line for line in trace.splitlines() if 'osrec_timer_return:' in line)
        object_token=re.search(r'object=(0x[0-9a-f]+)',row)[1]
        for changed in (row.replace('running=0x0','running='+object_token),
                        re.sub(r'base=0x[0-9a-f]+','base=0xffff000000000008',row),
                        re.sub(r'object=0x[0-9a-f]+','object=0xffff000000000008',row),
                        row.replace('result=0','result=1'),row.replace('<- do_nanosleep','<- hrtimer_wakeup')):
            self.assertNotEqual(changed,row)
            with self.assertRaises(ValueError):decode(trace.replace(row,changed),result,stats)
        sleeper=next(line for line in trace.splitlines() if 'osrec_sleeper_return:' in line)
        with self.assertRaises(ValueError):decode(trace.replace(row,'SWAP').replace(sleeper,row).replace('SWAP',sleeper),result,stats)
        text=(RETURN_FIXTURE/'qemu.log').read_text()
        for bad in (text.replace('"base_offset":48','"base_offset":49',1),
                    text.replace('"running_offset":24','"running_offset":64',1),
                    text.replace('"timer_size":64','"timer_size":72',1),
                    text.replace('running=+24(+48($arg1))','running=+16(+48($arg1))',1),
                    text.replace('r8:osrec/osrec_timer_return','r9:osrec/osrec_timer_return',1)):
            self.assertNotEqual(bad,text)
            with self.assertRaises(ValueError):parse_output(bad)
        with tempfile.TemporaryDirectory() as name:
            args=prepare(Path(name),RETURN_FIXTURE)
            manifest=json.loads((args.capture/'capture.manifest.json').read_text());manifest['timer_return_layout']['base_offset']=40
            (args.capture/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'timer return BTF layout'):exporter.export(args)
            self.assertFalse(args.out.exists())

    def test_native_timer_return_runtime_mutants_reject(self):
        emit='emit(16,sleeper.timer.id,1,timer_base.running?timer_base.running->id:0);'
        changes=[('timer_run_model.c',emit,'/* omit timer return observation */',1),
                 ('timer_run_model.c',emit,'emit(16,sleeper.timer.id,1,1);',1),
                 ('timer_run_model.c',emit,'emit(16,2,1,timer_base.running?timer_base.running->id:0);',1)]
        self._assert_mutants_rejected(changes,RETURN_FIXTURE)

    def test_bounded_timer_return_btf_reader(self):
        strings=b'\0task_struct\0hrtimer\0hrtimer_sleeper\0timer\0task\0hrtimer_clock_base\0base\0running\0'
        def name(n):return strings.index(n.encode()+b'\0')
        def record(n,kind,count,size):return struct.pack('<3I',name(n) if n else 0,kind<<24|count,size)
        def blob(base_bits=384,running_bits=192,base_type=6,running_type=7,timer_size=64,base_size=64,base_flag=0):
            types=record('task_struct',4,0,64)
            types+=record('hrtimer',4,1,timer_size)+struct.pack('<3I',name('base'),base_type,base_bits)
            types+=record('',2,0,1)
            types+=record('hrtimer_sleeper',4,2,72)+struct.pack('<6I',name('timer'),2,0,name('task'),3,512)
            types+=record('hrtimer_clock_base',4|(base_flag<<7),1,base_size)+struct.pack('<3I',name('running'),running_type,running_bits)
            types+=record('',2,0,5)+record('',2,0,2)
            return struct.pack('<HBB5I',0xeb9f,1,0,24,0,len(types),len(types),len(strings))+types+strings
        with tempfile.TemporaryDirectory() as name_dir:
            stage=Path(name_dir);driver=stage/'driver.c';executable=stage/'driver'
            driver.write_text('#include <stdio.h>\n#include "btf_timer_return.h"\n'
                'int main(int argc,char **argv){unsigned char data[16384];struct timer_return_layout layout;'
                'if(argc!=2)return 3;FILE *file=fopen(argv[1],"rb");if(!file)return 3;'
                'size_t n=fread(data,1,sizeof(data),file);fclose(file);'
                'if(!btf_timer_return_layout(data,n,&layout))return 2;'
                'return layout.timer_type_id==2 && layout.base_type_id==5 && layout.timer_size==64 && '
                'layout.base_size==64 && layout.base_offset==48 && layout.running_offset==24?0:4;}')
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(exporter.INTEGRATION),str(driver),'-o',str(executable)],check=True,capture_output=True)
            valid=blob();cases=[(valid,0),(blob(base_flag=1),0),(valid[:23],2),(valid[:-1],2),
                (blob(base_bits=385),2),(blob(running_bits=193),2),(blob(base_bits=512),2),
                (blob(running_bits=512),2),(blob(base_type=3),2),(blob(running_type=6),2),
                (blob(base_type=5),2),(blob(base_type=99),2),(blob(timer_size=48),2),
                (blob(base_size=24),2),(blob(base_flag=1,running_bits=(8<<24)|192),2)]
            for i,(payload,expected) in enumerate(cases):
                fixture=stage/f'btf-{i}.bin';fixture.write_bytes(payload)
                with self.subTest(i=i):self.assertEqual(subprocess.run([str(executable),str(fixture)]).returncode,expected)

    def test_base_fields_identity_sequence_and_layout_reject(self):
        trace=(BASE_FIXTURE/'trace.txt').read_text();result=json.loads((BASE_FIXTURE/'result.json').read_text());stats=(BASE_FIXTURE/'trace-stats.txt').read_text()
        row=next(l for l in trace.splitlines() if 'osrec_base_return:' in l)
        for changed in (row.replace('index=0','index=1'),row.replace('active=1','active=0'),
                        row.replace('active=1','active=4294967296'),row.replace('result=0','result=1'),
                        re.sub(r'cpu_base=0x[0-9a-f]+','cpu_base=0xffff000000000008',row),
                        re.sub(r'base=0x[0-9a-f]+','base=0xffff000000000008',row,count=1)):
            self.assertNotEqual(changed,row)
            with self.assertRaises(ValueError):decode(trace.replace(row,changed),result,stats)
        callback=next(l for l in trace.splitlines() if 'osrec_base_callback:' in l)
        timer=next(l for l in trace.splitlines() if 'osrec_timer_callback:' in l)
        with self.assertRaises(ValueError):decode(trace.replace(callback,'SWAP').replace(timer,callback).replace('SWAP',timer),result,stats)
        text=(BASE_FIXTURE/'qemu.log').read_text()
        for bad in (text.replace('"index_offset":8','"index_offset":9',1),
                    text.replace('"active_offset":8','"active_offset":576',1),
                    text.replace('index=timer->base->index:u32','index=timer->base->clockid:u32',1),
                    text.replace('r8:osrec/osrec_base_return','r9:osrec/osrec_base_return',1),
                    re.sub(r'(osrec_base_return +[0-9]+ +)0',r'\g<1>1',text,count=1)):
            self.assertNotEqual(bad,text)
            with self.assertRaises(ValueError):parse_output(bad)
        with tempfile.TemporaryDirectory() as name:
            args=prepare(Path(name),BASE_FIXTURE);manifest=json.loads((args.capture/'capture.manifest.json').read_text())
            manifest['base_state_layout']['index_offset']=12;(args.capture/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'base-state BTF layout'):exporter.export(args)
            self.assertFalse(args.out.exists())

    def test_base_active_mask_projection_and_empty_remainder(self):
        trace=(BASE_FIXTURE/'trace.txt').read_text();result=json.loads((BASE_FIXTURE/'result.json').read_text());stats=(BASE_FIXTURE/'trace-stats.txt').read_text()
        # Other base bits are retained as context, not replayed as selected occupancy.
        changed=re.sub(r'(osrec_base_(?:callback|return):[^\n]* active=)1',r'\g<1>2',trace)
        contract=decode(changed,result,stats)
        self.assertEqual([r['active_bases'] for r in contract['native_base_states']],[2,2])
        self.assertEqual([r['c'] for r in contract['records'] if r['kind']==17],[0,0])
        with tempfile.TemporaryDirectory() as name:
            args=prepare(Path(name),BASE_FIXTURE);_,native=exporter.load_capture(args.capture)
            # Synthetic boundary-contract case, not a newly captured native history.
            with patch.object(exporter,'load_capture',return_value=(contract,native)):report=exporter.export(args)
            self.assertEqual(report['background_base_occupancy'],0)
            for ledger in ('events','queue','timer','timer-queue','callback','ordered','driver','outer','clock'):
                expected=(args.out/f'expected-{ledger}.bin').read_bytes()
                for i in (0,1):self.assertEqual((args.out/f'target-{ledger}-{i}.bin').read_bytes(),expected)

    def test_base_occupancy_and_observation_runtime_mutants_reject(self):
        emit='emit(17,stage,timer_base.index,(timer_base.cpu_base->active_bases>>timer_base.index)&1);'
        changes=[('timer_run_model.c',emit,'emit(17,stage,timer_base.index,0);',1),
                 ('timer_run_model.c',emit,'emit(17,stage,1,(timer_base.cpu_base->active_bases>>timer_base.index)&1);',1),
                 ('timer_run_model.c','if(checkpoint_base_state)emit_base_state(1);','/* omit base callback snapshot */',1),
                 ('replay.c','emit_base_state(2);','/* omit base return snapshot */',1),
                 ('timer_queue_model.c','return nonempty;','return (void)nonempty,0;',1),
                 ('irq_checkpoint.h','checkpoint_background_active=1','checkpoint_background_active=0',1)]
        self._assert_mutants_rejected(changes,BASE_FIXTURE)

    def test_bounded_base_state_btf_reader(self):
        strings=b'\0task_struct\0hrtimer\0hrtimer_sleeper\0timer\0task\0hrtimer_clock_base\0base\0running\0hrtimer_cpu_base\0cpu_base\0index\0active_bases\0'
        def off(n):return strings.index(n.encode()+b'\0')
        def record(n,kind,count,size):return struct.pack('<3I',off(n) if n else 0,kind<<24|count,size)
        def member(n,t,b):return struct.pack('<3I',off(n),t,b)
        def blob(cpu_bits=0,index_bits=64,active_bits=64,cpu_pointee=8,scalar_size=4,scalar_bits=32,
                 alias=9,index_type=11,active_type=9,cpu_size=576,flag=0,duplicate=False):
            types=record('task_struct',4,0,64)+record('hrtimer',4,1,64)+member('base',6,384)+record('',2,0,1)
            types+=record('hrtimer_sleeper',4,2,72)+member('timer',2,0)+member('task',3,512)
            types+=record('hrtimer_clock_base',4|(flag<<7),3,64)+member('running',7,192)+member('cpu_base',10,cpu_bits)+member('index',index_type,index_bits)
            types+=record('',2,0,5)+record('',2,0,2)
            types+=record('hrtimer_cpu_base',4,1,cpu_size)+member('active_bases',active_type,active_bits)
            types+=record('',1,0,scalar_size)+struct.pack('<I',scalar_bits)+record('',2,0,cpu_pointee)+record('',8,0,alias)
            if duplicate:types+=record('hrtimer_cpu_base',4,0,576)
            return struct.pack('<HBB5I',0xeb9f,1,0,24,0,len(types),len(types),len(strings))+types+strings
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);driver=stage/'driver.c';executable=stage/'driver'
            driver.write_text('#include <stdio.h>\n#include "btf_base_state.h"\n'
                'int main(int argc,char **argv){unsigned char data[16384];struct base_state_layout layout;'
                'if(argc!=2)return 3;FILE *file=fopen(argv[1],"rb");if(!file)return 3;'
                'size_t n=fread(data,1,sizeof(data),file);fclose(file);'
                'if(!btf_base_state_layout(data,n,&layout))return 2;'
                'return layout.base_type_id==5 && layout.cpu_type_id==8 && layout.cpu_size==576 && '
                '!layout.cpu_base_offset && layout.index_offset==8 && layout.active_offset==8?0:4;}')
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(exporter.INTEGRATION),str(driver),'-o',str(executable)],check=True,capture_output=True)
            valid=blob();cases=[(valid,0),(blob(flag=1),0),(valid[:23],2),(valid[:-1],2),
                (blob(cpu_bits=1),2),(blob(index_bits=65),2),(blob(active_bits=65),2),
                (blob(cpu_bits=512),2),(blob(active_bits=576*8),2),(blob(cpu_pointee=5),2),
                (blob(index_type=10),2),(blob(active_type=10),2),(blob(scalar_size=8),2),
                (blob(scalar_bits=16),2),(blob(alias=11),2),(blob(cpu_size=8),2),
                (blob(flag=1,index_bits=(4<<24)|64),2),(blob(duplicate=True),2)]
            for i,(payload,expected) in enumerate(cases):
                fixture=stage/f'btf-{i}.bin';fixture.write_bytes(payload)
                with self.subTest(i=i):self.assertEqual(subprocess.run([str(executable),str(fixture)]).returncode,expected)

    def test_ordered_queue_model_insert_remove_ties_and_invalid_operations(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);driver=stage/'driver.c';executable=stage/'driver'
            driver.write_text('#include <stdlib.h>\n'
                'static void check(int value){if(!value)exit(2); }\n'
                '#include "ordered_timer_queue.h"\n'
                'int main(int argc,char **argv){if(argc!=2)return 3;int c=atoi(argv[1]);'
                'struct timerqueue_head q={0};struct timerqueue_node a={100,1,0},b={200,2,0},d={300,3,0};'
                'if(c==0){check(ordered_insert(&q,&b)==1);check(ordered_insert(&q,&a)==1);'
                'check(ordered_remove(&q,&a)==1 && ordered_first(&q)==&b);check(ordered_remove(&q,&b)==0);return 0;}'
                'if(c==2)b.expires=100;'
                'check(ordered_insert(&q,&a)==1);'
                'if(c==3)ordered_insert(&q,&a);'
                'if(c==6){d.id=1;ordered_insert(&q,&d);}'
                'if(c==7){d.id=0;ordered_insert(&q,&d);}'
                'check(ordered_insert(&q,&b)==0);'
                'if(c==1){check(ordered_remove(&q,&a)==1 && ordered_first(&q)==&b);check(ordered_remove(&q,&b)==0);return 0;}'
                'if(c==2){check(ordered_first(&q)==&a);check(ordered_remove(&q,&b)==1 && ordered_first(&q)==&a);'
                'check(ordered_remove(&q,&a)==0);return 0;}'
                'if(c==4){d.queued=1;ordered_remove(&q,&d);}'
                'if(c==5)ordered_insert(&q,&d);'
                'if(c==8)q.count=3;'
                'if(c==9){q.nodes[0]=&b;q.nodes[1]=&a;}'
                'if(c==10)a.queued=0;'
                'if(c==11)q.nodes[1]=&a;'
                'if(c==12){q.count=1;}'
                'if(c==13){ordered_remove(&q,&a);ordered_remove(&q,&a);}'
                'if(c==14){ordered_remove(&q,&b);check(!b.queued);b.expires=50;'
                'check(ordered_insert(&q,&b)==1 && ordered_first(&q)==&b);return 0;}'
                'ordered_validate(&q);return 4;}')
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(exporter.INTEGRATION),str(driver),'-o',str(executable)],check=True,capture_output=True)
            for case in range(15):
                with self.subTest(case=case):
                    self.assertEqual(subprocess.run([str(executable),str(case)]).returncode,0 if case in (0,1,2,14) else 2)

    def test_ordered_queue_mutants_reject(self):
        changes=[('timer_queue_model.c','.expires=UINT64_MAX','.expires=0',1),
                 ('ordered_timer_queue.h','head->nodes[at]->expires<=node->expires','head->nodes[at]->expires>=node->expires',1),
                 ('ordered_timer_queue.h','node->queued=1;','/* omit membership mark */',1),
                 ('ordered_timer_queue.h','node->queued=0;','/* omit membership clear */',1),
                 ('ordered_timer_queue.h','--head->count;','/* omit count decrement */',1),
                 ('ordered_timer_queue.h','head->nodes[head->count]=NULL;','/* omit tail clear */',1),
                 ('ordered_timer_queue.h','return head->count!=0;','return 0;',1),
                 ('timer_queue_model.c','ordered_snapshot(4);','/* omit ordered exit witness */',1)]
        self._assert_mutants_rejected(changes,BASE_FIXTURE)

    def test_original_queue_driver_runtime_mutants_reject(self):
        changes=[('timer_driver.c','cpu_base->active_bases & active_mask','cpu_base->active_bases | active_mask',1),
                 ('timer_driver.c','basenow < hrtimer_get_softexpires_tv64(timer)','basenow > hrtimer_get_softexpires_tv64(timer)',1),
                 ('timer_driver.c','break;','(void)timer;',1),
                 ('timer_driver.c','__run_hrtimer(cpu_base, base, timer, &basenow, flags);','(void)__run_hrtimer;(void)flags;',1),
                 ('timer_driver.c','active_mask == HRTIMER_ACTIVE_SOFT','active_mask != HRTIMER_ACTIVE_SOFT',1),
                 ('timer_driver_model.c','return ordered_first(head);','return NULL;',1),
                 ('timer_driver_model.c','return now;','return now+1;',1),
                 ('timer_queue_model.c','.soft=UINT64_C(0x7fffffffffffffff)','.soft=0',1),
                 ('timer_run_model.c','run_queue_pass(now,0,1);','run_queue_pass(now,HRTIMER_ACTIVE_HARD,1);',1)]
        self._assert_mutants_rejected(changes,BASE_FIXTURE)

    def test_original_queue_driver_soft_deadline_masks_and_offsets(self):
        driver_code=r'''#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
static void check(int value){if(!value)exit(2);}
#include "ordered_timer_queue.h"
typedef int64_t ktime_t;
struct hrtimer {struct timerqueue_node node;ktime_t soft,hard;};
struct hrtimer_clock_base {struct timerqueue_head active;ktime_t offset;};
struct hrtimer_cpu_base {unsigned active_bases;};
static struct hrtimer_clock_base test_base;
static unsigned callbacks,sync_calls;
#define container_of(ptr,type,member) ((type *)((char *)(ptr)-offsetof(type,member)))
#define HRTIMER_ACTIVE_SOFT 0xf0u
#define for_each_active_base(base,cpu,active) for(base=((void)(cpu),(active)?&test_base:NULL);base;base=NULL)
static ktime_t ktime_add(ktime_t a,ktime_t b){return a+b;}
static struct timerqueue_node *timerqueue_getnext(struct timerqueue_head *head){return ordered_first(head);}
static ktime_t hrtimer_get_softexpires_tv64(struct hrtimer *timer){return timer->soft;}
static void __run_hrtimer(struct hrtimer_cpu_base *cpu,struct hrtimer_clock_base *base,
                          struct hrtimer *timer,ktime_t *now,unsigned long flags)
{check(flags==1 && *now>=timer->soft);++callbacks;
 if(!ordered_remove(&base->active,&timer->node))cpu->active_bases=0;}
static void hrtimer_sync_wait_running(struct hrtimer_cpu_base *cpu,unsigned long flags)
{(void)cpu;check(flags==1);++sync_calls;}
#include "timer_driver.c"
int main(int argc,char **argv)
{
 if(argc!=2)return 3;int c=atoi(argv[1]);
 struct hrtimer a={{1000,1,0},1000,1050},b={{2000,2,0},2000,2050};
 struct hrtimer_cpu_base cpu={c==8?16u:1u};unsigned mask=c==8?HRTIMER_ACTIVE_SOFT:15u;
 ktime_t now=1000;check(ordered_insert(&test_base.active,&a.node)==1);
 if(c==0){mask=0;now=3000;}
 if(c==1)now=999;
 if(c==3)now=1049;
 if(c==4)cpu.active_bases=0;
 if(c==5){test_base.offset=5;now=995;}
 if(c==6){test_base.offset=-5;now=1004;}
 if(c==7 || c==9)check(ordered_insert(&test_base.active,&b.node)==0);
 if(c==9)now=2000;
 __hrtimer_run_queues(&cpu,now,1,mask);
 unsigned expected=(c==0 || c==1 || c==4 || c==6)?0:c==9?2:1;
 check(callbacks==expected && sync_calls==(c==8?1u:0u));
 check(test_base.active.count==((c==7 || c==9)?2u:1u)-expected);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);driver=stage/'driver.c';source=stage/'timer_driver.c';exe=stage/'driver'
            original=(exporter.INTEGRATION/'timer_driver.c').read_text();driver.write_text(driver_code);source.write_text(original)
            def compile_driver():
                subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(exporter.INTEGRATION),str(driver),'-o',str(exe)],check=True,capture_output=True)
            compile_driver()
            for case in range(10):
                with self.subTest(case=case):self.assertEqual(subprocess.run([str(exe),str(case)]).returncode,0)
            source.write_text(original.replace('basenow < hrtimer_get_softexpires_tv64(timer)','basenow <= hrtimer_get_softexpires_tv64(timer)'))
            compile_driver();self.assertNotEqual(subprocess.run([str(exe),'2']).returncode,0)
            source.write_text(original);driver.write_text(driver_code.replace('return timer->soft;','return timer->hard;'))
            compile_driver();self.assertNotEqual(subprocess.run([str(exe),'2']).returncode,0)

    def test_original_outer_timer_runtime_mutants_reject(self):
        changes=[('timer_outer.c','if (hrtimer_hres_active(cpu_base))','if (!hrtimer_hres_active(cpu_base))',1),
                 ('timer_outer.c','tick_check_oneshot_change(!hrtimer_is_hres_enabled())','tick_check_oneshot_change(hrtimer_is_hres_enabled())',1),
                 ('timer_outer.c','raw_spin_lock_irqsave(&cpu_base->lock, flags);','flags=1;(void)outer_lock;',1),
                 ('timer_outer.c','__hrtimer_run_queues(cpu_base, now, flags, HRTIMER_ACTIVE_HARD);','(void)__hrtimer_run_queues;',1),
                 ('timer_outer.c','raw_spin_unlock_irqrestore(&cpu_base->lock, flags);','(void)outer_unlock;',1),
                 ('timer_clock_model.c','return (ktime_t)observed_now;','return (ktime_t)observed_now+1;',1),
                 ('timer_outer_model.c','return now<next;','return now>=next;',1),
                 ('timer_outer_model.c','outer_snapshot(2);return 0;','outer_snapshot(2);return 1;',1),
                 ('timer_outer_model.c','++outer_ticks;outer_snapshot(3);return 0;','++outer_ticks;outer_snapshot(3);return 1;',1),
                 ('timer_outer_model.c','record_queue_pass(3);','/* omit dispatch witness */',1)]
        self._assert_mutants_rejected(changes,BASE_FIXTURE)

    def test_original_outer_timer_mode_and_softirq_branches(self):
        driver_code=r'''#include <stdint.h>
#include <stdlib.h>
static void check(int value){if(!value)exit(2);}
typedef int64_t ktime_t;
#define KTIME_MAX INT64_MAX
#define HRTIMER_ACTIVE_HARD 15u
enum {HRTIMER_SOFTIRQ};
struct hrtimer_cpu_base {unsigned lock;ktime_t softirq_expires_next;unsigned softirq_activated;};
static struct hrtimer_cpu_base hrtimer_bases;
static unsigned hres,enabled,oneshot,ticks,switches,locks,unlocks,updates,raises,dispatches;
static ktime_t clock_input=100;
#define this_cpu_ptr(ptr) (ptr)
static int hrtimer_hres_active(struct hrtimer_cpu_base *cpu){check(cpu==&hrtimer_bases);return hres;}
static int hrtimer_is_hres_enabled(void){return enabled;}
static int tick_check_oneshot_change(int allow){check(allow==!enabled);++ticks;return oneshot;}
static void hrtimer_switch_to_hres(void){++switches;}
static unsigned long save(unsigned *lock){check(!*lock);*lock=1;++locks;return 0x1234;}
#define raw_spin_lock_irqsave(lock,flags) ((flags)=save(lock))
static void raw_spin_unlock_irqrestore(unsigned *lock,unsigned long flags)
{check(*lock==1 && flags==0x1234);*lock=0;++unlocks;}
static ktime_t hrtimer_update_base(struct hrtimer_cpu_base *cpu)
{check(cpu==&hrtimer_bases && cpu->lock==1);++updates;return clock_input;}
static int ktime_before(ktime_t a,ktime_t b){return a<b;}
static void raise_softirq_irqoff(unsigned selector)
{check(selector==HRTIMER_SOFTIRQ && hrtimer_bases.lock==1 && hrtimer_bases.softirq_activated==1 &&
       hrtimer_bases.softirq_expires_next==KTIME_MAX);++raises;}
static void __hrtimer_run_queues(struct hrtimer_cpu_base *cpu,ktime_t now,unsigned long flags,unsigned mask)
{check(cpu==&hrtimer_bases && cpu->lock==1 && now==clock_input && flags==0x1234 && mask==HRTIMER_ACTIVE_HARD);++dispatches;}
#include "timer_outer.c"
int main(int argc,char **argv)
{
 if(argc!=2)return 3;int c=atoi(argv[1]);hrtimer_bases.softirq_expires_next=101;
 if(c==1)hres=1;
 if(c==2)oneshot=1;
 if(c==3)hrtimer_bases.softirq_expires_next=100;
 if(c==4)hrtimer_bases.softirq_expires_next=99;
 if(c==5)enabled=1;
 if(c==6)hrtimer_bases.softirq_activated=1;
 if(c==7){clock_input=KTIME_MAX-1;hrtimer_bases.softirq_expires_next=KTIME_MAX;}
 hrtimer_run_queues();
 unsigned early=c==1 || c==2,soft=c==3 || c==4;
 check(!hrtimer_bases.lock && ticks==(c==1?0u:1u) && switches==(c==2?1u:0u));
 check(locks==!early && unlocks==!early && updates==!early && dispatches==!early);
 check(raises==soft && hrtimer_bases.softirq_activated==(soft || c==6));
 if(soft)check(hrtimer_bases.softirq_expires_next==KTIME_MAX);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);driver=stage/'driver.c';source=stage/'timer_outer.c';exe=stage/'driver'
            original=(exporter.INTEGRATION/'timer_outer.c').read_text();driver.write_text(driver_code);source.write_text(original)
            def compile_driver():subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(driver),'-o',str(exe)],check=True,capture_output=True)
            compile_driver()
            for case in range(8):
                with self.subTest(case=case):self.assertEqual(subprocess.run([str(exe),str(case)]).returncode,0)
            source.write_text(original.replace('!ktime_before(now, cpu_base->softirq_expires_next)','ktime_before(now, cpu_base->softirq_expires_next)'))
            compile_driver();self.assertNotEqual(subprocess.run([str(exe),'0']).returncode,0)
            source.write_text(original.replace('raise_softirq_irqoff(HRTIMER_SOFTIRQ);','(void)raise_softirq_irqoff;'))
            compile_driver();self.assertNotEqual(subprocess.run([str(exe),'3']).returncode,0)

    def test_original_clock_offset_propagation_and_signed_inputs(self):
        driver_code=r'''#include <stdint.h>
#include <stdlib.h>
typedef int64_t ktime_t;
enum {HRTIMER_BASE_MONOTONIC,HRTIMER_BASE_REALTIME,HRTIMER_BASE_BOOTTIME,HRTIMER_BASE_TAI,
      HRTIMER_BASE_MONOTONIC_SOFT,HRTIMER_BASE_REALTIME_SOFT,HRTIMER_BASE_BOOTTIME_SOFT,HRTIMER_BASE_TAI_SOFT};
struct hrtimer_cpu_base {unsigned clock_was_set_seq;struct {ktime_t offset;} clock_base[8];};
static struct hrtimer_cpu_base cpu;
static ktime_t values[4];
static unsigned calls;
static void check(int value){if(!value)exit(2);}
static ktime_t ktime_get_update_offsets_now(unsigned *seq,ktime_t *real,ktime_t *boot,ktime_t *tai)
{
 check(seq==&cpu.clock_was_set_seq && real==&cpu.clock_base[1].offset &&
       boot==&cpu.clock_base[2].offset && tai==&cpu.clock_base[3].offset);
 check(*seq==7 && !calls);++calls;*seq=9;
 *real=values[1];*boot=values[2];*tai=values[3];return values[0];
}
#include "timer_clock.c"
int main(int argc,char **argv)
{
 check(argc==2);unsigned c=(unsigned)strtoul(argv[1],0,10);
 static const ktime_t cases[][4]={{100,11,22,33},{0,0,0,0},{-1,-11,-22,-33},
  {INT64_MAX,INT64_MIN,INT64_MAX,0},{INT64_MIN,INT64_MAX,0,INT64_MIN},
  {123,INT64_C(4294967297),-INT64_C(4294967297),INT64_C(8589934593)}};
 check(c<sizeof(cases)/sizeof(cases[0]));
 for(unsigned i=0;i<4;++i)values[i]=cases[c][i];
 for(unsigned i=0;i<8;++i)cpu.clock_base[i].offset=-77;
 cpu.clock_was_set_seq=7;
 check(hrtimer_update_base(&cpu)==values[0] && calls==1 && cpu.clock_was_set_seq==9);
 check(cpu.clock_base[0].offset==-77 && cpu.clock_base[4].offset==-77);
 for(unsigned i=1;i<4;++i)check(cpu.clock_base[i].offset==values[i] && cpu.clock_base[i+4].offset==values[i]);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);driver=stage/'driver.c';source=stage/'timer_clock.c';exe=stage/'driver'
            original=(exporter.INTEGRATION/'timer_clock.c').read_text();driver.write_text(driver_code);source.write_text(original)
            def compile_driver():subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(driver),'-o',str(exe)],check=True,capture_output=True)
            compile_driver()
            for case in range(6):
                with self.subTest(case=case):self.assertEqual(subprocess.run([str(exe),str(case)]).returncode,0)
            for old,new in (('HRTIMER_BASE_REALTIME_SOFT].offset = *offs_real','HRTIMER_BASE_REALTIME_SOFT].offset = *offs_boot'),
                            ('return now;','return now+1;')):
                source.write_text(original.replace(old,new));compile_driver()
                self.assertNotEqual(subprocess.run([str(exe),'0']).returncode,0)

    def test_original_clock_runtime_mutants_reject(self):
        changes=[]
        for base,value in (('REALTIME','real'),('BOOTTIME','boot'),('TAI','tai')):
            changes.append(('timer_clock.c',f'base->clock_base[HRTIMER_BASE_{base}_SOFT].offset = *offs_{value};',
                            f'/* omit {base} propagation */',1))
        changes += [('timer_clock.c','return now;','return now+1;',1),
                    ('timer_clock.c','offs_real, offs_boot, offs_tai','offs_boot, offs_real, offs_tai',1),
                    ('timer_clock_model.c','*seq=checkpoint_clock_state?input->sequence:1;','*seq=2;',1),
                    ('timer_clock_model.c','*tai=checkpoint_clock_state?input->tai:33;','*tai=34;',1),
                    ('timer_clock_model.c','clock_snapshot(2,now);','/* omit clock witness */',1)]
        self._assert_mutants_rejected(changes,OUTER_FIXTURE)

    def test_bounded_clock_offsets_btf_reader(self):
        strings=b'\0task_struct\0hrtimer\0hrtimer_sleeper\0timer\0task\0hrtimer_clock_base\0base\0running\0hrtimer_cpu_base\0cpu_base\0index\0active_bases\0offset\0clock_base\0clock_was_set_seq\0ktime_t\0'
        def off(n):return strings.index(n.encode()+b'\0')
        def record(n,kind,count,size):return struct.pack('<3I',off(n) if n else 0,kind<<24|count,size)
        def member(n,t,b):return struct.pack('<3I',off(n),t,b)
        def blob(array_count=8,array_bits=512,array_type=12,element=5,index_type=9,offset_bits=448,sequence_bits=96,
                 offset_size=8,offset_width=64,offset_encoding=1,offset_type=13,alias=11,sequence_type=9,
                 cpu_size=576,base_size=64,duplicate=False):
            types=record('task_struct',4,0,64)+record('hrtimer',4,1,64)+member('base',6,384)+record('',2,0,1)
            types+=record('hrtimer_sleeper',4,2,72)+member('timer',2,0)+member('task',3,512)
            types+=record('hrtimer_clock_base',132,4,base_size)+member('running',7,192)+member('cpu_base',10,0)+member('index',9,64)+member('offset',offset_type,offset_bits)
            types+=record('',2,0,5)+record('',2,0,2)
            types+=record('hrtimer_cpu_base',132,4 if duplicate else 3,cpu_size)+member('active_bases',9,64)+member('clock_was_set_seq',sequence_type,sequence_bits)+member('clock_base',array_type,array_bits)
            if duplicate:types+=member('clock_base',array_type,array_bits)
            types+=record('',1,0,4)+struct.pack('<I',32)+record('',2,0,8)
            types+=record('',1,0,offset_size)+struct.pack('<I',offset_encoding<<24|offset_width)
            types+=record('',3,0,0)+struct.pack('<3I',element,index_type,array_count)+record('ktime_t',8,0,alias)
            return struct.pack('<HBB5I',0xeb9f,1,0,24,0,len(types),len(types),len(strings))+types+strings
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);driver=stage/'driver.c';exe=stage/'driver'
            driver.write_text('#include <stdio.h>\n#include "btf_clock_offsets.h"\n'
                'int main(int argc,char **argv){unsigned char data[16384];struct clock_offsets_layout o;'
                'if(argc!=2)return 3;FILE *f=fopen(argv[1],"rb");if(!f)return 3;size_t n=fread(data,1,sizeof(data),f);fclose(f);'
                'if(!btf_clock_offsets_layout(data,n,&o))return 2;'
                'return o.cpu_type_id==8 && o.base_type_id==5 && o.cpu_size==576 && o.base_size==64 && '
                'o.array_offset==64 && o.array_count==8 && o.offset_offset==56 && o.sequence_offset==12?0:4;}')
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(exporter.INTEGRATION),str(driver),'-o',str(exe)],check=True,capture_output=True)
            valid=blob();cases=[(valid,0),(blob(offset_type=11),0),(valid[:23],2),(valid[:-1],2),
                (blob(array_count=7),2),(blob(array_count=9),2),(blob(array_bits=513),2),(blob(array_bits=576),2),
                (blob(array_type=10),2),(blob(element=2),2),(blob(index_type=10),2),(blob(offset_bits=449),2),
                (blob(offset_bits=(8<<24)|448),2),(blob(offset_bits=512),2),(blob(sequence_bits=97),2),
                (blob(sequence_bits=512),2),(blob(offset_size=4),2),(blob(offset_width=32),2),
                (blob(offset_encoding=0),2),(blob(alias=13),2),(blob(sequence_type=11),2),
                (blob(cpu_size=568),2),(blob(base_size=72),2),(blob(duplicate=True),2)]
            for i,(payload,expected) in enumerate(cases):
                fixture=stage/f'btf-{i}.bin';fixture.write_bytes(payload)
                with self.subTest(case=i):self.assertEqual(subprocess.run([str(exe),str(fixture)]).returncode,expected)

    def test_native_propagated_offsets_and_btf_destination_mapping(self):
        text=(OFFSETS_FIXTURE/'qemu.log').read_text();result,trace,stats,_=parse_output(text)
        timer=capture_tool.parse_timer_layout(text);base=capture_tool.parse_base_layout(text,timer)
        layout=capture_tool.parse_offsets_layout(text,timer,base)
        def decode_offsets(t):return decode(t,result,stats,layout)
        contract=decode_offsets(trace);self.assertTrue(contract['native_clock_destinations_btf_cpu_base_mapping_verified'])
        row=next(l for l in trace.splitlines() if 'osrec_offsets_callback:' in l)
        for changed in (row.replace('hrtimer_wakeup+','unrelated+'),re.sub(r' object=0x[0-9a-f]+',' object=0xffff000000000008',row),
                        re.sub(r' cpu_base=0x[0-9a-f]+',' cpu_base=0xffff000000000008',row),
                        re.sub(r' sequence=\d+',' sequence=4294967296',row),
                        re.sub(r' soft_real=-?\d+',' soft_real=-1',row),
                        re.sub(r' soft_boot=-?\d+',' soft_boot=1',row),
                        re.sub(r' soft_tai=-?\d+',' soft_tai=9223372036854775808',row),'',row+'\n'+row):
            with self.subTest(change=changed),self.assertRaises(ValueError):decode_offsets(trace.replace(row,changed))
        lines=trace.splitlines();i=lines.index(row);lines[i],lines[i+1]=lines[i+1],lines[i]
        with self.assertRaises(ValueError):decode_offsets('\n'.join(lines))
        with self.assertRaises(ValueError):decode(trace,result,stats)
        with self.assertRaisesRegex(ValueError,'BTF CPU-base mapping'):decode(trace,result,stats,{**layout,'array_offset':layout['array_offset']-8})
        for bad in (text.replace('"array_count":8','"array_count":7',1),
                    text.replace('"offset_offset":56','"offset_offset":55',1),
                    text.replace('"sequence_offset":12','"sequence_offset":16',1),
                    text.replace('field:s64 soft_real;','field:u64 soft_real;'),
                    re.sub(r'(osrec_offsets_callback +[0-9]+ +)0',r'\g<1>1',text,count=1),
                    text.replace('"clock_offsets_capture":true','"clock_offsets_capture":false',1)):
            with self.subTest(metadata=bad[:100]),self.assertRaises(ValueError):parse_output(bad)
        for value in (False,1):
            with tempfile.TemporaryDirectory() as name:
                args=prepare(Path(name),OFFSETS_FIXTURE);m=json.loads((args.capture/'capture.manifest.json').read_text());m['clock_offsets_capture']=value
                (args.capture/'capture.manifest.json').write_text(json.dumps(m))
                with self.assertRaisesRegex(ValueError,'clock-offsets capture manifest mode'):exporter.export(args)
                self.assertFalse(args.out.exists())

    def test_propagated_signed_offsets_projection(self):
        text=(OFFSETS_FIXTURE/'qemu.log').read_text();result,trace,stats,_=parse_output(text)
        timer=capture_tool.parse_timer_layout(text);base=capture_tool.parse_base_layout(text,timer)
        layout=capture_tool.parse_offsets_layout(text,timer,base)
        # Synthetic signed values exercise normalization, not a new native history.
        values=(-9223372036854775808,-4294967297,9223372036854775807)
        for name,value in zip(('real','boot','tai'),values):
            trace=re.sub(r' (offs_|soft_)'+name+r'=-?\d+',lambda m:' '+m[1]+name+'='+str(value),trace)
        contract=decode(trace,result,stats,layout)
        self.assertEqual([contract['native_propagated_offsets'][0][k] for k in ('soft_real','soft_boot','soft_tai')],list(values))
        with tempfile.TemporaryDirectory() as name:
            args=prepare(Path(name),OFFSETS_FIXTURE);_,native=exporter.load_capture(args.capture)
            with patch.object(exporter,'load_capture',return_value=(contract,native)):report=exporter.export(args)
            self.assertTrue(report['native_propagated_offsets_verified'])
            self.assertEqual(list(report['timer_clock_witnesses']['rows'][1][4:]),list(values)*2)
            row=next(r for r in contract['records'] if r['kind']==21)
            self.assertEqual(tuple(row[k] for k in ('a','b','c')),tuple(v&((1<<64)-1) for v in values))
            for ledger in ('events','queue','timer','timer-queue','callback','ordered','driver','outer','clock'):
                expected=(args.out/f'expected-{ledger}.bin').read_bytes()
                for index in (0,1):self.assertEqual((args.out/f'target-{ledger}-{index}.bin').read_bytes(),expected)

    def test_native_propagated_offset_runtime_mutants_reject(self):
        emitted='emit(21,(uint64_t)timer_cpu.clock_base[5].offset,(uint64_t)timer_cpu.clock_base[6].offset,(uint64_t)timer_cpu.clock_base[7].offset);'
        changes=[('timer_clock_model.c',emitted,'/* omit propagated offsets */',1),
                 ('timer_clock_model.c',emitted,emitted.replace('[5].offset','[5].offset+1'),1),
                 ('timer_run_model.c','if(checkpoint_clock_offsets)emit_propagated_offsets();','(void)emit_propagated_offsets;',1),
                 ('timer_clock_model.c','++native_propagated_offset_count;','/* omit propagated-offset count */',1)]
        self._assert_mutants_rejected(changes,OFFSETS_FIXTURE)

    def test_bounded_timekeeper_btf_layout_candidate(self):
        def blob(case='valid'):
            strings=bytearray(b'\0');types=[]
            def name(n):
                value=n.encode()+b'\0'
                if value not in strings:strings.extend(value)
                return strings.index(value)
            def rec(n,k,count,size,body=b''):
                types.append(struct.pack('<3I',name(n) if n else 0,k<<24|count,size)+body)
                return len(types)
            def members(*rows):return b''.join(struct.pack('<3I',name(n),t,b) for n,t,b in rows)
            rec('task_struct',4,0,64)
            rec('hrtimer',4,1,64,members(('base',6,384)))
            rec('',2,0,1)
            rec('hrtimer_sleeper',4,2,72,members(('timer',2,0),('task',3,512)))
            rec('hrtimer_clock_base',4,4,64,members(('running',7,192),('cpu_base',10,0),('index',9,64),('offset',13,448)))
            rec('',2,0,5);rec('',2,0,2)
            rec('hrtimer_cpu_base',4,3,576,members(('active_bases',9,64),('clock_was_set_seq',9,96),('clock_base',12,512)))
            rec('',1,0,4,struct.pack('<I',32));rec('',2,0,8)
            rec('',1,0,8,struct.pack('<I',1<<24|64))
            rec('',3,0,0,struct.pack('<3I',5,9,8))
            rec('ktime_t',8,0,13 if case=='alias_cycle' else 11)
            rec('tk_read_base' if case!='missing_mono' else 'missing',4,1,8,
                members(('base',9 if case=='base_width' else 13,1 if case=='base_align' else 0)))
            tk=[('tkr_mono',2 if case=='mono_type' else 14,0),
                ('clock_was_set_seq',13 if case=='sequence_width' else 9,64),
                ('offs_real',13,192 if case=='overlap' else 128),('offs_boot',13,192),('offs_tai',13,256),
                ('next_leap_ktime',13,(8<<24)|320 if case=='leap_bitfield' else 384 if case=='leap_extent' else 321 if case=='leap_align' else 320)]
            if case=='duplicate_member':tk.append(tk[-1])
            rec('timekeeper',132,len(tk),47 if case=='tk_extent' else 48,members(*tk))
            rec('seqcount',4,1,4,members(('sequence',13 if case=='seqcount_width' else 9,0)))
            rec('seqcount_t',8,0,17 if case=='seqcount_cycle' else 16)
            rec('seqcount_raw_spinlock',4,1,4,members(('seqcount',9 if case=='seqcount_type' else 17,0)))
            rec('seqcount_raw_spinlock_t',8,0,18)
            core=[('seq',19,32 if case=='core_seq_align' else 0),('timekeeper',15,0 if case=='core_overlap' else 65 if case=='core_align' else 128 if case=='shifted_core' else 64)]
            rec('named_core' if case=='named_core' else '',4,2,55 if case=='core_extent' else 64 if case=='shifted_core' else 56,members(*core))
            if case=='ambiguous':rec('',4,2,56,members(*core))
            if case=='duplicate_tk':rec('timekeeper',4,len(tk),48,members(*tk))
            if case=='duplicate_mono':rec('tk_read_base',4,1,8,members(('base',13,0)))
            raw=b''.join(types)
            result=struct.pack('<HBB5I',0xeb9f,1,0,24,0,len(raw),len(raw),len(strings))+raw+strings
            if case=='truncated':result=result[:-1]
            if case=='header':result=result[:4]+struct.pack('<I',0xffffffff)+result[8:]
            if case=='record':result=result[:24]+result[24:28]+struct.pack('<I',31<<24)+result[32:]
            return result
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);driver=stage/'driver.c';exe=stage/'driver'
            driver.write_text('#include <stdio.h>\n#include "btf_timekeeper.h"\n'
                'int main(int argc,char **argv){unsigned char data[16384];struct timekeeper_layout o;'
                'if(argc<2 || argc>3)return 3;unsigned d=argc==3?8:0;FILE *f=fopen(argv[1],"rb");if(!f)return 3;size_t n=fread(data,1,sizeof(data),f);fclose(f);'
                'if(!btf_timekeeper_layout(data,n,&o))return 2;'
                'return o.core_type_id==20 && o.core_size==56+d && o.timekeeper_type_id==15 && o.timekeeper_size==48 && '
                'o.sequence_offset==0 && o.clock_sequence_offset==16+d && o.mono_base_offset==8+d && '
                'o.real_offset==24+d && o.boot_offset==32+d && o.tai_offset==40+d && o.leap_offset==48+d?0:4;}')
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(exporter.INTEGRATION),str(driver),'-o',str(exe)],check=True,capture_output=True)
            cases=('valid','shifted_core','alias_cycle','missing_mono','base_width','base_align','mono_type','sequence_width','overlap',
                'leap_bitfield','leap_extent','leap_align','duplicate_member','tk_extent','seqcount_width','seqcount_cycle',
                'seqcount_type','core_seq_align','core_overlap','core_align','core_extent','named_core','ambiguous',
                'duplicate_tk','duplicate_mono','truncated','header','record')
            for case in cases:
                data=stage/(case+'.btf');data.write_bytes(blob(case))
                with self.subTest(case=case):self.assertEqual(subprocess.run([str(exe),str(data),*(['shift'] if case=='shifted_core' else [])]).returncode,0 if case in ('valid','shifted_core') else 2)

    def test_timekeeper_layout_protocol_and_manifest_rejections(self):
        text=(TIMEKEEPER_LAYOUT_FIXTURE/'qemu.log').read_text()
        result,trace,stats,_=parse_output(text);layout=capture_tool.parse_timekeeper_layout(text)
        self.assertTrue(result['timekeeper_layout_capture']);self.assertFalse(layout['symbol_type_binding_attested'])
        self.assertEqual((layout['core_size'],layout['timekeeper_size']),(288,280))
        marker=next(line for line in text.splitlines() if line.startswith('OSREC_LINUX_IRQ_TIMEKEEPER_LAYOUT '))
        bad_layouts=[{**layout,'core_size':True},{**layout,'source':'native-sysfs-btf'},
                    {**layout,'symbol_type_binding_attested':True},{**layout,'extra':0},
                    {**layout,'core_size':280},{**layout,'timekeeper_type_id':layout['core_type_id']},
                    {**layout,'sequence_offset':-4},{**layout,'real_offset':153},
                    {**layout,'boot_offset':layout['real_offset']},{**layout,'leap_offset':288}]
        bad_texts=[text.replace(marker,marker+'\n'+marker),text.replace(marker,''),
                   text.replace('"timekeeper_layout_capture":true,',''),
                   text.replace('"timekeeper_layout_capture":true','"timekeeper_layout_capture":false'),
                   text.replace('"clock_entry_capture":true,','')]
        bad_texts += [text.replace(marker,'OSREC_LINUX_IRQ_TIMEKEEPER_LAYOUT '+json.dumps(x)) for x in bad_layouts]
        for bad in bad_texts:
            with self.subTest(metadata=bad[:100]),self.assertRaises(ValueError):parse_output(bad)
        for key,value,error in (('timekeeper_layout_capture',False,'capture manifest mode'),
                                ('timekeeper_layout_capture',1,'capture manifest mode'),
                                ('timekeeper_data_symbol_lookup_supported',True,'data-symbol capability'),
                                ('timekeeper_data_symbol_lookup_supported',0,'data-symbol capability'),
                                ('timekeeper_layout',{**layout,'sequence_offset':4},'BTF layout differs')):
            with self.subTest(key=key,value=value),tempfile.TemporaryDirectory() as name:
                args=prepare(Path(name),TIMEKEEPER_LAYOUT_FIXTURE)
                p=args.capture/'capture.manifest.json';m=json.loads(p.read_text());m[key]=value;p.write_text(json.dumps(m))
                with self.assertRaisesRegex(ValueError,error):exporter.export(args)
                self.assertFalse(args.out.exists())
        timer=capture_tool.parse_timer_layout(text);base=capture_tool.parse_base_layout(text,timer)
        offsets=capture_tool.parse_offsets_layout(text,timer,base)
        with self.assertRaisesRegex(ValueError,'requires clock-entry'):decode(trace,{**result,'clock_entry_capture':False},stats,offsets)

    def test_timekeeper_layout_native_export_profiles(self):
        for source,address in ((False,0x40200000),(True,0x40400000)):
            with self.subTest(source=source,address=address),tempfile.TemporaryDirectory() as name:
                args=prepare(Path(name),TIMEKEEPER_LAYOUT_FIXTURE);args.timekeeper_source=source
                args.entry_address=address;args.result_address=address-0x80000
                report=exporter.export(args)
                self.assertTrue(report['native_timekeeper_layout_discovered'])
                self.assertFalse(report['native_timekeeper_symbol_type_binding_attested'])
                self.assertFalse(report['native_timekeeper_data_symbol_lookup_supported'])
                self.assertFalse(report['native_timekeeper_provider_state_captured'])
                self.assertEqual(report['timekeeper_source_executed'],source)
                self.assertEqual(report['native_timekeeper_layout'],capture_tool.parse_timekeeper_layout((args.capture/'qemu.log').read_text()))
                self.assertEqual((report['contract']['native_event_count'],report['contract']['replay_event_count'],report['contract']['irq_count']),(29,31,1))
                for kind in ('events','queue','timer','timer-queue','callback','ordered','driver','outer','clock',*(('timekeeper',) if source else ())):
                    expected=(args.out/f'expected-{kind}.bin').read_bytes()
                    for i in (0,1):self.assertEqual((args.out/f'target-{kind}-{i}.bin').read_bytes(),expected)

    def test_original_timekeeper_export_relocation_and_admission(self):
        witnesses={'queue':'scheduler_witnesses','timer':'timer_witnesses','timer-queue':'timer_queue_witnesses',
            'callback':'callback_witnesses','ordered':'ordered_queue_witnesses','driver':'timer_driver_witnesses',
            'outer':'outer_timer_witnesses','clock':'timer_clock_witnesses','timekeeper':'timekeeper_witnesses'}
        for address in (0x40200000,0x40400000):
            with self.subTest(address=address),tempfile.TemporaryDirectory() as name:
                stage=Path(name);args=prepare(stage,ENTRY_FIXTURE);args.timekeeper_source=True
                args.entry_address=address;args.result_address=address-0x80000
                report=exporter.export(args)
                self.assertTrue(report['timekeeper_source_executed']);self.assertTrue(report['independent_timekeeper_witnesses_verified'])
                self.assertFalse(report['native_timekeeper_provider_state_captured'])
                self.assertEqual(report['original_timekeeper_functions'],['ktime_get_update_offsets_now'])
                self.assertEqual(len(report['original_timer_functions']),11)
                self.assertEqual(report['timekeeper_witnesses']['rows'][-1][-2:],(report['contract']['expiry_now_ns'],1))
                expected={n:(args.out/f'expected-{n}.bin').read_bytes() for n in ('events',*witnesses)}
                for n,data in expected.items():
                    for i in (0,1):self.assertEqual((args.out/f'target-{n}-{i}.bin').read_bytes(),data)
                standalone=stage/'standalone';standalone.mkdir()
                for n in ('linux-irq.elf','linux-irq.bin'):shutil.copyfile(args.out/n,standalone/n)
                shutil.rmtree(args.capture);shutil.rmtree(args.out)
                results=[]
                for i,n in enumerate(('linux-irq.elf','linux-irq.bin')):
                    dumps=tuple(dict(address=report[key]['address'],bytes=len(expected[kind]),file=str(standalone/f'{kind}-{i}.bin')) for kind,key in witnesses.items())
                    result,raw=observe(standalone/n,QEMU,descriptor=standalone/'linux-irq.elf' if i else None,memory_dumps=dumps)
                    require_success(result);results.append(raw)
                    for kind in witnesses:self.assertEqual((standalone/f'{kind}-{i}.bin').read_bytes(),expected[kind])
                self.assertEqual(*results)
        with tempfile.TemporaryDirectory() as name:
            args=prepare(Path(name),OFFSETS_FIXTURE);args.timekeeper_source=True
            with self.assertRaisesRegex(ValueError,'requires native clock-entry'):exporter.export(args)
            self.assertFalse(args.out.exists())
        text=(ENTRY_FIXTURE/'qemu.log').read_text();result,trace,stats,_=parse_output(text)
        timer=capture_tool.parse_timer_layout(text);base=capture_tool.parse_base_layout(text,timer);layout=capture_tool.parse_offsets_layout(text,timer,base)
        trace=re.sub(r'(osrec_clock_entry:[^\n]* sequence=)\d+',r'\g<1>0',trace)
        contract=decode(trace,result,stats,layout)
        with tempfile.TemporaryDirectory() as name:
            args=prepare(Path(name),ENTRY_FIXTURE);args.timekeeper_source=True;_,native=exporter.load_capture(args.capture)
            with patch.object(exporter,'load_capture',return_value=(contract,native)):
                with self.assertRaisesRegex(ValueError,'unchanged selected entry/return'):exporter.export(args)
            self.assertFalse(args.out.exists())

    def test_original_timekeeper_conditional_leap_and_retry_paths(self):
        code=r'''#include <stdint.h>
#include <stdlib.h>
typedef int64_t ktime_t;
typedef uint64_t u64;
struct tk_read_base {ktime_t base;};
struct timekeeper {struct tk_read_base tkr_mono;unsigned clock_was_set_seq;ktime_t offs_real,offs_boot,offs_tai,next_leap_ktime;};
static struct {unsigned seq;struct timekeeper timekeeper;} tk_core;
static unsigned reads,ns_reads,adds,retries,sets,retry_enabled;
static u64 increment=7;
static void check(int v){if(!v)exit(2);}
static unsigned read_seqcount_begin(unsigned *seq){check(seq==&tk_core.seq);return ++reads;}
static u64 timekeeping_get_ns(struct tk_read_base *mono){check(mono==&tk_core.timekeeper.tkr_mono);++ns_reads;return increment;}
static ktime_t ktime_add_ns(ktime_t base,u64 ns){++adds;return base+(ktime_t)ns;}
static ktime_t ktime_set(int sec,unsigned long ns){check(sec==1 && !ns);++sets;return INT64_C(1000000000);}
static ktime_t ktime_sub(ktime_t a,ktime_t b){return a-b;}
static int read_seqcount_retry(unsigned *seq,unsigned start)
{
 check(seq==&tk_core.seq && start==reads);++retries;
 if(retry_enabled && retries==1){tk_core.timekeeper.tkr_mono.base=200;tk_core.timekeeper.clock_was_set_seq=10;
  tk_core.timekeeper.offs_real=INT64_C(4000000000);tk_core.timekeeper.offs_boot=6;tk_core.timekeeper.offs_tai=INT64_C(5000000000);return 1;}
 return 0;
}
#define unlikely(v) (v)
#include "timekeeper_update.c"
int main(int argc,char **argv)
{
 check(argc==2);unsigned c=(unsigned)strtoul(argv[1],0,10);check(c<=10);
 tk_core.timekeeper=(struct timekeeper){.tkr_mono={100},.clock_was_set_seq=9,.offs_real=INT64_C(2000000000),.offs_boot=5,.offs_tai=INT64_C(3000000000),.next_leap_ktime=INT64_MAX};
 unsigned seq=(c==1 || c==3 || c==7)?8:9;ktime_t real=-11,boot=-22,tai=-33;
 if(c==2)tk_core.timekeeper.next_leap_ktime=107;
 if(c==3)tk_core.timekeeper.next_leap_ktime=106;
 if(c==4)tk_core.timekeeper.next_leap_ktime=108;
 if(c==5 || c==6)retry_enabled=1;
 if(c==6)tk_core.timekeeper.next_leap_ktime=150;
 if(c==7)increment=0;
 if(c==8)tk_core.timekeeper.tkr_mono.base=-100;
 if(c==9)tk_core.timekeeper.next_leap_ktime=INT64_MIN;
 if(c==10){seq=UINT32_MAX;tk_core.timekeeper.clock_was_set_seq=0;}
 ktime_t now=ktime_get_update_offsets_now(&seq,&real,&boot,&tai);
 unsigned passes=retry_enabled?2:1,updated=c==1 || c==3 || c==5 || c==6 || c==7 || c==10;
 unsigned leap=c==2 || c==3 || c==6 || c==9;
 check(reads==passes && ns_reads==passes && adds==passes && retries==passes && sets==leap);
 check(now==(c==8?-93:c==7?100:retry_enabled?207:107));
 check(seq==(c==10?0:retry_enabled?10:9));
 check(boot==(updated?retry_enabled?6:5:-22) && tai==(updated?retry_enabled?INT64_C(5000000000):INT64_C(3000000000):-33));
 check(real==(leap?(retry_enabled?INT64_C(3000000000):INT64_C(1000000000)):updated?(retry_enabled?INT64_C(4000000000):INT64_C(2000000000)):-11));
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);driver=stage/'driver.c';source=stage/'timekeeper_update.c';exe=stage/'driver'
            original=(exporter.INTEGRATION/'timekeeper_update.c').read_text();driver.write_text(code);source.write_text(original)
            def compile_driver():subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(driver),'-o',str(exe)],check=True,capture_output=True)
            compile_driver()
            for case in range(11):
                with self.subTest(case=case):self.assertEqual(subprocess.run([str(exe),str(case)]).returncode,0)
            for old,new,case in (('*cwsseq != tk->clock_was_set_seq','*cwsseq == tk->clock_was_set_seq',0),
                                 ('base >= tk->next_leap_ktime','base > tk->next_leap_ktime',2),
                                 ('read_seqcount_retry(&tk_core.seq, seq)','((void)read_seqcount_retry,(void)seq,0)',5),
                                 ('return base;','return base+1;',0),
                                 ('*offs_boot = tk->offs_boot;','*offs_boot = tk->offs_tai;',1)):
                source.write_text(original.replace(old,new));compile_driver()
                with self.subTest(mutant=old):self.assertNotEqual(subprocess.run([str(exe),str(case)]).returncode,0)

    def test_original_timekeeper_runtime_mutants_reject(self):
        changes=[('timekeeper_update.c','*cwsseq != tk->clock_was_set_seq','*cwsseq == tk->clock_was_set_seq',1),
                 ('timekeeper_update.c','nsecs = timekeeping_get_ns(&tk->tkr_mono);','nsecs = 0;(void)timekeeping_get_ns;',1),
                 ('timekeeper_update.c','base = ktime_add_ns(base, nsecs);','(void)ktime_add_ns;(void)nsecs;',1),
                 ('timekeeper_update.c','seq = read_seqcount_begin(&tk_core.seq);','seq=0;(void)read_seqcount_begin;',1),
                 ('timekeeper_update.c','read_seqcount_retry(&tk_core.seq, seq)','((void)read_seqcount_retry,(void)seq,0)',1),
                 ('timekeeper_update.c','return base;','return base+1;',1),
                 ('timekeeper_model.c','.next_leap_ktime=INT64_MAX','.next_leap_ktime=0',1),
                 ('timekeeper_model.c','timekeeper_snapshot(4,now);','/* omit returned witness */',1),
                 ('timekeeper_model.c','.clock_was_set_seq=entry->sequence,','.clock_was_set_seq=entry->sequence+1,',1),
                 ('timekeeper_model.c','timekeeper_snapshot(3,0);return 0;','timekeeper_snapshot(3,0);return 1;',1)]
        self._assert_mutants_rejected(changes,ENTRY_FIXTURE,timekeeper_source=True)

    def test_external_timekeeper_ledger_corruption_rejects(self):
        real_observe=exporter.observe
        for image_index in (0,1):
            with self.subTest(image=image_index),tempfile.TemporaryDirectory() as name:
                args=prepare(Path(name),ENTRY_FIXTURE);args.timekeeper_source=True;calls=0
                def altered_observe(*positional,**kwargs):
                    nonlocal calls
                    result=real_observe(*positional,**kwargs)
                    if calls==image_index:
                        target=Path(kwargs['memory_dumps'][-1]['file']);self.assertIn('target-timekeeper',target.name)
                        data=bytearray(target.read_bytes());data[0]^=1;target.write_bytes(data)
                    calls+=1;return result
                with patch.object(exporter,'observe',altered_observe):
                    with self.assertRaisesRegex(ValueError,'timekeeper witnesses differ'):exporter.export(args)
                self.assertFalse(args.out.exists())

    def test_native_clock_entry_pairing_identity_and_provenance(self):
        text=(ENTRY_FIXTURE/'qemu.log').read_text();result,trace,stats,_=parse_output(text)
        timer=capture_tool.parse_timer_layout(text);base=capture_tool.parse_base_layout(text,timer)
        layout=capture_tool.parse_offsets_layout(text,timer,base)
        def decode_entry(t):return decode(t,result,stats,layout)
        contract=decode_entry(trace);rows=[l for l in trace.splitlines() if 'osrec_clock_entry:' in l];row=rows[-1]
        self.assertEqual(len(rows),contract['irq_count'])
        self.assertEqual(contract['replay_event_count'],contract['native_event_count']+2*len(rows))
        self.assertTrue(all(not t['changed_fields'] for t in contract['native_clock_transitions']))
        for changed in (row.replace('ktime_get_update_offsets_now+','unrelated+'),
                        re.sub(r' seq=0x[0-9a-f]+',' seq=0x0',row),
                        re.sub(r' real=0x[0-9a-f]+',' real=0xffff000000000001',row),
                        re.sub(r' boot=0x[0-9a-f]+',' boot='+re.search(r' real=(0x[0-9a-f]+)',row)[1],row),
                        re.sub(r' tai=0x[0-9a-f]+',' tai=0xffff000000000008',row),
                        re.sub(r' sequence=\d+',' sequence=4294967296',row),
                        re.sub(r' offs_real=-?\d+',' offs_real=9223372036854775808',row),
                        re.sub(r' offs_tai=-?\d+',' offs_tai=-9223372036854775809',row),'',row+'\n'+row):
            with self.subTest(change=changed),self.assertRaises(ValueError):decode_entry(trace.replace(row,changed))
        lines=trace.splitlines();i=lines.index(row);lines[i],lines[i+1]=lines[i+1],lines[i]
        with self.assertRaises(ValueError):decode_entry('\n'.join(lines))
        for old,new in (('p:osrec/osrec_clock_entry','r8:osrec/osrec_clock_entry'),
                        ('"clock_entry_capture":true','"clock_entry_capture":1'),
                        ('"clock_offsets_capture":true,','')):
            with self.subTest(provenance=old),self.assertRaises(ValueError):parse_output(text.replace(old,new,1))
        bad=re.sub(r'(osrec_clock_entry +[0-9]+ +)0',r'\g<1>1',text,count=1)
        with self.assertRaises(ValueError):parse_output(bad)
        bad=re.sub(r'(OSREC_LINUX_IRQ_FORMAT_BEGIN osrec/osrec_clock_entry\n.*?)field:s64 offs_real;',r'\g<1>field:u64 offs_real;',text,flags=re.S)
        self.assertNotEqual(bad,text)
        with self.assertRaises(ValueError):parse_output(bad)
        for value in (False,1):
            with tempfile.TemporaryDirectory() as name:
                args=prepare(Path(name),ENTRY_FIXTURE);m=json.loads((args.capture/'capture.manifest.json').read_text());m['clock_entry_capture']=value
                (args.capture/'capture.manifest.json').write_text(json.dumps(m))
                with self.assertRaisesRegex(ValueError,'clock-entry capture manifest mode'):exporter.export(args)
                self.assertFalse(args.out.exists())

    def test_clock_entry_changed_and_signed_value_projection(self):
        text=(ENTRY_FIXTURE/'qemu.log').read_text();result,trace,stats,_=parse_output(text)
        timer=capture_tool.parse_timer_layout(text);base=capture_tool.parse_base_layout(text,timer)
        layout=capture_tool.parse_offsets_layout(text,timer,base)
        for case in range(3):
            # Synthetic boundary inputs/outputs, not newly observed native transitions.
            lines=[]
            for row in trace.splitlines():
                if 'osrec_clock_entry:' in row:
                    row=re.sub(r' sequence=\d+',' sequence='+str(4294967295 if case==2 else 0),row)
                    if case:
                        for field,value in zip(('real','boot','tai'),(-9223372036854775808,-4294967297,9223372036854775807)):
                            row=re.sub(r' offs_'+field+r'=-?\d+',' offs_'+field+'='+str(value),row)
                elif case==2 and ('osrec_clock_return:' in row or 'osrec_offsets_callback:' in row):
                    row=re.sub(r' sequence=\d+',' sequence=0',row)
                    for field,value in zip(('real','boot','tai'),(9223372036854775807,-9223372036854775808,-4294967297)):
                        row=re.sub(r' (offs_|soft_)'+field+r'=-?\d+',lambda m:' '+m[1]+field+'='+str(value),row)
                lines.append(row)
            contract=decode('\n'.join(lines),result,stats,layout)
            expected=['sequence'] if not case else ['sequence','offs_real','offs_boot','offs_tai']
            self.assertTrue(all(t['changed_fields']==expected for t in contract['native_clock_transitions']))
            with self.subTest(case=case),tempfile.TemporaryDirectory() as name:
                args=prepare(Path(name),ENTRY_FIXTURE);_,native=exporter.load_capture(args.capture)
                with patch.object(exporter,'load_capture',return_value=(contract,native)):report=exporter.export(args)
                self.assertTrue(report['native_clock_entry_fields_verified'])
                for ledger in ('events','queue','timer','timer-queue','callback','ordered','driver','outer','clock'):
                    expected_bytes=(args.out/f'expected-{ledger}.bin').read_bytes()
                    for index in (0,1):self.assertEqual((args.out/f'target-{ledger}-{index}.bin').read_bytes(),expected_bytes)

    def test_native_clock_entry_runtime_mutants_reject(self):
        changes=[('timer_clock_model.c','timer_cpu.clock_was_set_seq=entry->sequence;','timer_cpu.clock_was_set_seq=entry->sequence+1;',1),
                 ('timer_clock_model.c','timer_cpu.clock_base[1].offset=entry->real;','timer_cpu.clock_base[1].offset=entry->real+1;',1),
                 ('timer_clock_model.c','emit(22,input->sequence,1,0);','emit(22,input->sequence+1,1,0);',1),
                 ('timer_clock_model.c','emit(23,(uint64_t)input->real,(uint64_t)input->boot,(uint64_t)input->tai);','emit(23,(uint64_t)input->real+1,(uint64_t)input->boot,(uint64_t)input->tai);',1),
                 ('timer_clock_model.c','if(checkpoint_clock_entry)emit_clock_entry(&checkpoint_clock_entries[delivered]);','/* omit contextual entry */',1),
                 ('timer_clock_model.c','++native_clock_entry_count;','/* omit entry count */',1),
                 ('timer_clock_model.c','struct clock_input actual={0,*seq,*real,*boot,*tai};emit_clock_entry(&actual);','struct clock_input actual={0,*seq,*real,*boot,*tai};(void)actual;',1)]
        self._assert_mutants_rejected(changes,ENTRY_FIXTURE)

    def test_clock_entry_changed_output_runtime_mutants_reject(self):
        text=(ENTRY_FIXTURE/'qemu.log').read_text();result,trace,stats,_=parse_output(text)
        timer=capture_tool.parse_timer_layout(text);base=capture_tool.parse_base_layout(text,timer)
        layout=capture_tool.parse_offsets_layout(text,timer,base);lines=[]
        for row in trace.splitlines():
            if 'osrec_clock_entry:' in row:
                row=re.sub(r' sequence=\d+',' sequence=0',row)
                for field,value in (('real',0),('boot',-1),('tai',0)):
                    row=re.sub(r' offs_'+field+r'=-?\d+',' offs_'+field+'='+str(value),row)
            lines.append(row)
        contract=decode('\n'.join(lines),result,stats,layout)
        with tempfile.TemporaryDirectory() as name:_,native=exporter.load_capture(prepare(Path(name),ENTRY_FIXTURE).capture)
        changes=[('timer_clock_model.c','*seq=checkpoint_clock_state?input->sequence:1;','(void)seq;',1),
                 ('timer_clock_model.c','*real=checkpoint_clock_state?input->real:11;','(void)real;',1),
                 ('timer_clock_model.c','*boot=checkpoint_clock_state?input->boot:22;','(void)boot;',1),
                 ('timer_clock_model.c','*tai=checkpoint_clock_state?input->tai:33;','(void)tai;',1)]
        with patch.object(exporter,'load_capture',return_value=(contract,native)):self._assert_mutants_rejected(changes,ENTRY_FIXTURE)

    def test_native_clock_state_identity_order_and_outputs(self):
        text=(CLOCK_FIXTURE/'qemu.log').read_text();result,trace,stats,_=parse_output(text)
        contract=decode(trace,result,stats);rows=[l for l in trace.splitlines() if 'osrec_clock_return:' in l];row=rows[-1]
        self.assertEqual(len(rows),contract['irq_count'])
        self.assertEqual(contract['replay_event_count'],contract['native_event_count']+len(rows))
        selected=next(r for r in contract['native_clock_states'] if r['selected_expiry'])
        self.assertEqual(selected['now_ns'],contract['expiry_now_ns'])
        for changed in (re.sub(r' now=\d+',' now='+str(selected['now_ns']+1),row),
                        re.sub(r' now=\d+',' now=0',row),re.sub(r' sequence=\d+',' sequence=4294967296',row),
                        re.sub(r' offs_real=-?\d+',' offs_real=9223372036854775808',row),
                        re.sub(r' offs_tai=-?\d+',' offs_tai=-9223372036854775809',row),
                        re.sub(r' seq=0x[0-9a-f]+',' seq=0x0',row),
                        re.sub(r' real=0x[0-9a-f]+',' real=0xffff000000000001',row),
                        re.sub(r' boot=0x[0-9a-f]+',' boot='+re.search(r' real=(0x[0-9a-f]+)',row)[1],row),
                        re.sub(r' tai=0x[0-9a-f]+',' tai=0xffff000000000008',row),
                        row.replace('hrtimer_run_queues+','unrelated_runner+'),'',row+'\n'+row):
            with self.subTest(change=changed),self.assertRaises(ValueError):decode(trace.replace(row,changed),result,stats)
        lines=trace.splitlines();i=lines.index(row);lines[i],lines[i+1]=lines[i+1],lines[i]
        with self.assertRaises(ValueError):decode('\n'.join(lines),result,stats)
        for bad in (text.replace('now=$retval:s64','now=$retval:u64',1),
                    text.replace('field:s64 now;','field:u64 now;'),
                    re.sub(r'(osrec_clock_return +[0-9]+ +)0',r'\g<1>1',text,count=1),
                    text.replace('"clock_state_capture":true','"clock_state_capture":1',1),
                    text.replace('"outer_state_capture":true,','',1)):
            with self.subTest(provenance=bad[:100]),self.assertRaises(ValueError):parse_output(bad)
        with tempfile.TemporaryDirectory() as name:
            args=prepare(Path(name),CLOCK_FIXTURE);manifest=json.loads((args.capture/'capture.manifest.json').read_text())
            manifest['clock_state_capture']=False;(args.capture/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'clock-state capture manifest mode'):exporter.export(args)
            self.assertFalse(args.out.exists())

    def test_native_clock_signed_boundary_projection(self):
        text=(CLOCK_FIXTURE/'qemu.log').read_text();result,trace,stats,_=parse_output(text)
        # Synthetic signed-boundary inputs; these are not a fresh native observation.
        values=(-9223372036854775808,-4294967297,9223372036854775807)
        for field,value in zip(('real','boot','tai'),values):
            trace=re.sub(r' offs_'+field+r'=-?\d+',' offs_'+field+'='+str(value),trace)
        contract=decode(trace,result,stats)
        with tempfile.TemporaryDirectory() as name:
            args=prepare(Path(name),CLOCK_FIXTURE);_,native=exporter.load_capture(args.capture)
            with patch.object(exporter,'load_capture',return_value=(contract,native)):report=exporter.export(args)
            self.assertEqual(list(report['timer_clock_witnesses']['rows'][1][4:]),list(values)*2)
            offsets=[r for r in contract['records'] if r['kind']==20]
            self.assertEqual(tuple(offsets[0][k] for k in ('a','b','c')),tuple(v&((1<<64)-1) for v in values))
            for ledger in ('events','queue','timer','timer-queue','callback','ordered','driver','outer','clock'):
                expected=(args.out/f'expected-{ledger}.bin').read_bytes()
                for index in (0,1):self.assertEqual((args.out/f'target-{ledger}-{index}.bin').read_bytes(),expected)

    def test_native_clock_return_runtime_mutants_reject(self):
        changes=[('timer_clock_model.c','emit(19,(uint64_t)input->now,input->sequence,1);',
                  'emit(19,(uint64_t)input->now+1,input->sequence,1);',1),
                 ('timer_clock_model.c','emit(20,(uint64_t)input->real,(uint64_t)input->boot,(uint64_t)input->tai);',
                  'emit(20,(uint64_t)input->boot,(uint64_t)input->real,(uint64_t)input->tai);',1),
                 ('timer_clock_model.c','*seq=checkpoint_clock_state?input->sequence:1;','*seq=0;',1),
                 ('timer_clock_model.c','*real=checkpoint_clock_state?input->real:11;','*real=11;',1),
                 ('timer_clock_model.c','++native_clock_return_count;','/* omit observed-return count */',1),
                 ('timer_clock.c','base->clock_base[HRTIMER_BASE_BOOTTIME_SOFT].offset = *offs_boot;',
                  '/* omit native boottime propagation */',1),
                 ('timer_clock_model.c','emit_clock_return(&checkpoint_clocks[delivered]);','(void)emit_clock_return;',1),
                 ('timer_clock_model.c','check(input->now==(ktime_t)observed_now);','input=&checkpoint_clocks[0];check(input->now==(ktime_t)observed_now);',1)]
        self._assert_mutants_rejected(changes,CLOCK_FIXTURE)

    def test_native_outer_fields_identity_order_and_distinct_deadlines(self):
        trace=(OUTER_FIXTURE/'trace.txt').read_text();result=json.loads((OUTER_FIXTURE/'result.json').read_text());stats=(OUTER_FIXTURE/'trace-stats.txt').read_text()
        contract=decode(trace,result,stats)
        hard,soft=re.search(r'hrtimer_start:.* expires=(\d+) softexpires=(\d+)',trace).groups()
        self.assertEqual((contract['expires_ns'],contract['soft_expires_ns']),(int(hard),int(soft)))
        self.assertNotEqual(contract['expires_ns'],contract['native_outer_states'][0]['softirq_expires_next'])
        row=next(l for l in trace.splitlines() if 'osrec_outer_callback:' in l)
        for changed in (row.replace('deadline=9223372036854775807','deadline=0'),
                        row.replace('deadline=9223372036854775807','deadline=-1'),
                        row.replace('activated=0','activated=1'),
                        re.sub(r'cpu_base=0x[0-9a-f]+','cpu_base=0xffff000000000008',row),
                        re.sub(r'object=0x[0-9a-f]+','object=0xffff000000000008',row),
                        row.replace('hrtimer_wakeup+','other_function+')):
            self.assertNotEqual(row,changed)
            with self.assertRaises(ValueError):decode(trace.replace(row,changed),result,stats)
        base=next(l for l in trace.splitlines() if 'osrec_base_callback:' in l)
        with self.assertRaises(ValueError):decode(trace.replace(row,'SWAP').replace(base,row).replace('SWAP',base),result,stats)
        text=(OUTER_FIXTURE/'qemu.log').read_text()
        for bad in (text.replace('deadline=timer->base->cpu_base->softirq_expires_next:s64','deadline=timer->base->cpu_base->expires_next:s64',1),
                    text.replace('field:s64 deadline;','field:u64 deadline;',1),
                    text.replace('field:u32 activated;','field:u8 activated;',1),
                    re.sub(r'(osrec_outer_callback +[0-9]+ +)0',r'\g<1>1',text,count=1),
                    text.replace('"outer_state_capture":true','"outer_state_capture":false',1)):
            self.assertNotEqual(bad,text)
            with self.assertRaises(ValueError):parse_output(bad)
        with tempfile.TemporaryDirectory() as name:
            args=prepare(Path(name),OUTER_FIXTURE);manifest=json.loads((args.capture/'capture.manifest.json').read_text())
            manifest['outer_state_capture']=False;(args.capture/'capture.manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'outer-state capture manifest mode'):exporter.export(args)
            self.assertFalse(args.out.exists())

    def test_native_outer_snapshot_runtime_mutants_reject(self):
        emit='emit(18,1,(uint64_t)timer_cpu.softirq_expires_next,timer_cpu.softirq_activated);'
        changes=[('timer_outer_model.c',emit,'/* omit native outer snapshot */',1),
                 ('timer_outer_model.c',emit,'emit(18,1,0,timer_cpu.softirq_activated);',1),
                 ('timer_outer_model.c',emit,'emit(18,1,(uint64_t)timer_cpu.softirq_expires_next,1);',1)]
        self._assert_mutants_rejected(changes,OUTER_FIXTURE)

    def test_bounded_native_btf_layout_reader(self):
        strings=b'\0task_struct\0hrtimer\0hrtimer_sleeper\0timer\0task\0'
        def string_offset(value):return strings.index(value.encode()+b'\0')
        def record(n,kind,count,size):return struct.pack('<3I',string_offset(n),kind<<24|count,size)
        def btf(task_bits=512,timer_bits=0,size=72,pointee=1):
            types=record('task_struct',4,0,64)+record('hrtimer',4,0,64)+struct.pack('<3I',0,2<<24,pointee)
            types+=record('hrtimer_sleeper',4,2,size)+struct.pack('<6I',string_offset('timer'),2,timer_bits,string_offset('task'),3,task_bits)
            return struct.pack('<HBB5I',0xeb9f,1,0,24,0,len(types),len(types),len(strings))+types+strings
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);driver=stage/'driver.c';executable=stage/'driver'
            driver.write_text('#include <stdio.h>\n#include "btf_sleeper.h"\n'
                'int main(int argc,char **argv){unsigned char data[16384];struct sleeper_layout layout;'
                'if(argc!=2)return 3;FILE *file=fopen(argv[1],"rb");if(!file)return 3;'
                'size_t n=fread(data,1,sizeof(data),file);fclose(file);'
                'if(!btf_sleeper_layout(data,n,&layout))return 2;'
                'return layout.size==72 && layout.task_offset==64 && !layout.timer_offset?0:4;}')
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(exporter.INTEGRATION),str(driver),'-o',str(executable)],check=True,capture_output=True)
            valid=btf();cases=[(valid,0),(valid[:23],2),(b'xx'+valid[2:],2),(btf(task_bits=513),2),
                (btf(timer_bits=8),2),(btf(size=64),2),(btf(pointee=2),2),(valid[:-1],2),
                (valid[:16]+struct.pack('<I',0)+valid[20:],2),
                (valid[:12]+struct.pack('<I',0xffffffff)+valid[16:],2)]
            for i,(payload,expected) in enumerate(cases):
                fixture=stage/f'btf-{i}.bin';fixture.write_bytes(payload)
                with self.subTest(i=i):self.assertEqual(subprocess.run([str(executable),str(fixture)]).returncode,expected)

    def test_scheduler_source_pins_reject_modified_helpers(self):
        for filename in ('sched_state.c','sched_wakeup.c','sched_queue.c'):
            with self.subTest(filename=filename),tempfile.TemporaryDirectory() as name:
                root=Path(name)/'integration';shutil.copytree(exporter.INTEGRATION,root)
                target=root/filename;target.write_bytes(target.read_bytes()+b'\n')
                with patch.object(exporter,'INTEGRATION',root):
                    with self.assertRaisesRegex(ValueError,'scheduler source changed'):
                        exporter.source_identity()

    def test_timer_source_pins_reject_modified_definitions(self):
        for filename in ('timer_sleeper.c','timer_queue.c','timer_run.c','timer_driver.c','timer_outer.c','timer_clock.c','timekeeper_update.c'):
            with self.subTest(filename=filename),tempfile.TemporaryDirectory() as name:
                root=Path(name)/'integration';shutil.copytree(exporter.INTEGRATION,root)
                target=root/filename;target.write_bytes(target.read_bytes()+b'\n')
                with patch.object(exporter,'INTEGRATION',root):
                    with self.assertRaisesRegex(ValueError,'timer .*source changed'):exporter.source_identity()

    def test_original_timer_queue_and_inactive_removal_mutants_reject(self):
        changes=[('timer_queue.c','base->cpu_base->active_bases |= 1 << base->index;',
                                'base->cpu_base->active_bases &= 1 << base->index;',1),
                 ('timer_queue.c','WRITE_ONCE(timer->state, HRTIMER_STATE_ENQUEUED);',
                                  'WRITE_ONCE(timer->state, HRTIMER_STATE_INACTIVE);',1),
                 ('timer_queue.c','return timerqueue_add(&base->active, &timer->node);',
                                  'return (timerqueue_add(&base->active, &timer->node),0);',1),
                 ('timer_queue.c','WRITE_ONCE(timer->state, newstate);',
                                  'WRITE_ONCE(timer->state, HRTIMER_STATE_ENQUEUED);(void)newstate;',1),
                 ('timer_queue.c','cpu_base->active_bases &= ~(1 << base->index);',
                                  'cpu_base->active_bases |= 1 << base->index;',1),
                 ('timer_queue.c','if (!(state & HRTIMER_STATE_ENQUEUED))',
                                  'if (!(state & HRTIMER_STATE_ENQUEUED) && state != HRTIMER_STATE_INACTIVE)',1),
                 ('timer_queue.c','!timerqueue_del(&base->active, &timer->node)',
                                  '!((void)timerqueue_del,0)',1),
                 ('timer_run.c','__remove_hrtimer(timer, base, HRTIMER_STATE_INACTIVE, 0);',
                                '__remove_hrtimer(timer, base, HRTIMER_STATE_INACTIVE, 1);',1)]
        self._assert_mutants_rejected(changes,SLEEPER_FIXTURE)

    def test_original_callback_run_order_and_restart_mutants_reject(self):
        changes=[('timer_run.c','base->running = timer;','base->running = NULL;',1),
                 ('timer_run.c','__remove_hrtimer(timer, base, HRTIMER_STATE_INACTIVE, 0);','(void)__remove_hrtimer;',1),
                 ('timer_run.c','base->running = timer;\n\traw_write_seqcount_barrier(&base->seq);','base->running = timer;',1),
                 ('timer_run.c','raw_spin_unlock_irqrestore(&cpu_base->lock, flags);',
                                '(void)raw_spin_unlock_irqrestore;(void)flags;',1),
                 ('timer_run.c','expires_in_hardirq = lockdep_hrtimer_enter(timer);',
                                'expires_in_hardirq = true;(void)lockdep_hrtimer_enter;',1),
                 ('timer_run.c','restart = fn(timer);','restart = HRTIMER_NORESTART;(void)fn;',1),
                 ('timer_run.c','lockdep_hrtimer_exit(expires_in_hardirq);',
                                '(void)lockdep_hrtimer_exit;(void)expires_in_hardirq;',1),
                 ('timer_run.c','restart != HRTIMER_NORESTART','restart == HRTIMER_NORESTART',1),
                 ('timer_run.c','raw_write_seqcount_barrier(&base->seq);\n\n\tWARN_ON_ONCE',
                                '/* omit second barrier */\n\tWARN_ON_ONCE',1),
                 ('timer_run.c','base->running = NULL;','/* omit running clear */',1)]
        self._assert_mutants_rejected(changes,SLEEPER_FIXTURE)

    def test_original_timer_constructor_and_start_mutants_reject(self):
        changes=[('timer_sleeper.c','sl->timer.function = hrtimer_wakeup;','sl->timer.function = NULL;',1),
                 ('timer_sleeper.c','sl->task = current;','sl->task = NULL;',1),
                 ('timer_sleeper.c','debug_init(&sl->timer, clock_id, mode);','(void)debug_init;',1),
                 ('timer_sleeper.c','__hrtimer_init(&sl->timer, clock_id, mode);','(void)__hrtimer_init;(void)clock_id;(void)mode;',1),
                 ('timer_sleeper.c','hrtimer_start_expires(&sl->timer, mode);','(void)hrtimer_start_expires;(void)sl;(void)mode;',1),
                 ('timer_sleeper.c','hrtimer_start_expires(&sl->timer, mode);',
                                    'hrtimer_start_expires(&sl->timer, HRTIMER_MODE_ABS);(void)mode;',1),
                 ('timer_sleeper.c','__hrtimer_init(&sl->timer, clock_id, mode);',
                                    '__hrtimer_init(&sl->timer, clock_id, HRTIMER_MODE_ABS);',1)]
        self._assert_mutants_rejected(changes,SLEEPER_FIXTURE)

    def test_external_boundary_witness_corruption_rejects_before_publication(self):
        real_observe=exporter.observe
        for ledger_index,kind in ((1,'scheduler'),(2,'timer'),(3,'timer queue'),(4,'callback'),(5,'ordered queue'),(6,'timer driver'),(7,'outer timer'),(8,'timer clock')):
            for image_index in (0,1):
                with self.subTest(image=image_index,kind=kind),tempfile.TemporaryDirectory() as name:
                    args=prepare(Path(name));calls=0
                    def altered_observe(*positional,**kwargs):
                        nonlocal calls
                        result=real_observe(*positional,**kwargs)
                        if calls==image_index:
                            target=Path(kwargs['memory_dumps'][ledger_index]['file']);data=bytearray(target.read_bytes());data[0]^=1;target.write_bytes(data)
                        calls+=1
                        return result
                    with patch.object(exporter,'observe',altered_observe):
                        with self.assertRaisesRegex(ValueError,kind+' witnesses differ'):exporter.export(args)
                    self.assertFalse(args.out.exists())

    def test_original_callback_and_physical_irq_mutants_fail_before_publication(self):
        changes=[('hrtimer_wakeup.c','\tt->task = NULL;','\t/* omit link clear */',1),
                 ('hrtimer_wakeup.c','wake_up_process(task);','(void)wake_up_process;',1),
                 ('hrtimer_wakeup.c','return HRTIMER_NORESTART;','return HRTIMER_RESTART;',1),
                 ('replay.c','"r"(UINT64_C(1))','"r"(UINT64_C(0))',3),
                 ('sched_state.c','READ_ONCE(p->__state) & state','READ_ONCE(p->__state) | state',1),
                 ('sched_state.c','return -1;','return 1;',1),
                 ('sched_state.c','p->saved_state = TASK_RUNNING;','p->saved_state = TASK_INTERRUPTIBLE;',1),
                 ('sched_wakeup.c','try_to_wake_up(p, TASK_NORMAL, 0)','try_to_wake_up(p, TASK_UNINTERRUPTIBLE, 0)',1),
                 ('sched_wakeup.c','WRITE_ONCE(p->__state, TASK_RUNNING);','WRITE_ONCE(p->__state, TASK_INTERRUPTIBLE);',1),
                 ('sched_queue.c','WRITE_ONCE(p->on_rq, TASK_ON_RQ_QUEUED);','WRITE_ONCE(p->on_rq, 0);',1),
                 ('sched_queue.c','p->sched_class->enqueue_task(rq, p, flags);','/* omitted class enqueue */',1),
                 ('sched_queue.c','p->sched_class->dequeue_task(rq, p, flags);','/* omitted class dequeue */',1),
                 ('sched_queue.c','sched_info_enqueue(rq, p);','(void)sched_info_enqueue;',1),
                 ('sched_queue.c','psi_enqueue(p, (flags & ENQUEUE_WAKEUP) && !(flags & ENQUEUE_MIGRATED));',
                                  'psi_enqueue(p, 0);',1),
                 ('sched_queue.c','(flags & DEQUEUE_SLEEP) ? 0 : TASK_ON_RQ_MIGRATING',
                                  '(flags & DEQUEUE_SLEEP) ? TASK_ON_RQ_QUEUED : TASK_ON_RQ_MIGRATING',1),
                 ('sched_queue.c','enqueue_task(rq, p, flags);\n\n\tWRITE_ONCE(p->on_rq, TASK_ON_RQ_QUEUED);',
                                  'WRITE_ONCE(p->on_rq, TASK_ON_RQ_QUEUED);\n\tenqueue_task(rq, p, flags);',1),
                 ('sched_queue_model.c','queue_flags=ENQUEUE_WAKEUP|ENQUEUE_NOCLOCK;',
                                        'queue_flags=ENQUEUE_RESTORE|ENQUEUE_NOCLOCK;',1)]
        self._assert_mutants_rejected(changes)

    def _assert_mutants_rejected(self,changes,fixture=FIXTURE,timekeeper_source=False):
        real_run=exporter.run
        for filename,old,new,error in changes:
            with self.subTest(change=old),tempfile.TemporaryDirectory() as name:
                args=prepare(Path(name),fixture);args.timekeeper_source=timekeeper_source
                def altered_run(command):
                    if Path(command[0]).name=='clang':
                        cfile=next(Path(p) for p in command if str(p).endswith('/replay.c'))
                        target=cfile.parent/filename;s=target.read_text();self.assertEqual(s.count(old),1);target.write_text(s.replace(old,new))
                    try:return real_run(command)
                    except subprocess.CalledProcessError as error:self.fail('runtime mutant did not compile: '+error.stderr)
                with patch.object(exporter,'run',altered_run):
                    with self.assertRaisesRegex(ValueError,'target replay diverged: .*"error": '+str(error)):
                        exporter.export(args)
                self.assertFalse(args.out.exists())


if __name__=='__main__':
    if len(sys.argv)==3:
        LLVM,QEMU=Path(sys.argv[1]),sys.argv[2];sys.argv=sys.argv[:1]
    unittest.main(verbosity=2)
