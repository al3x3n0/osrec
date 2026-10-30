"""Validate one native LiteOS-A nanosleep and export its bounded scheduler replay."""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT/'integrations/liteos_a/wait-source-lock.json'
TEMPLATE = ROOT/'integrations/liteos_a/wait_replay.c.in'
ORDER = ('ValidTimeSpec', 'OsNS2Tick', 'HPFDelay', 'HPFWaitTimeGet',
         'SchedTimeoutTaskWake', 'DoNanoSleep', 'nanosleep', 'SysNanoSleep')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def definition(text, name):
    match = re.search(r'^[^\n;{}]*\b'+name+r'\([^;{}]*\)\s*\{', text, re.M)
    if not match:
        raise ValueError('missing wait definition: '+name)
    depth, end = 1, match.end()
    while depth and end < len(text):
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    if depth:
        raise ValueError('incomplete wait definition')
    return text[match.start():end]


def prepare_source(kernel_root):
    lock = json.loads(LOCK.read_text())
    revision = subprocess.check_output(['git', '-C', str(kernel_root), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != lock['revision']:
        raise ValueError('wait kernel revision differs')
    for path, expected in {**lock['sources'], **lock['headers']}.items():
        if digest((kernel_root/path).read_bytes()) != expected:
            raise ValueError('wait source/header changed: '+path)
    bodies, licenses = [], []
    for name in ORDER:
        entry = lock['definitions'][name]
        text = (kernel_root/entry['source']).read_text()
        body = definition(text, name)
        if digest(body.encode()) != entry['sha256']:
            raise ValueError('wait original definition changed: '+name)
        license_text = text[:text.index('*/')+2]
        if license_text not in licenses:
            licenses.append(license_text)
        bodies.append(body)
    return '\n'.join(licenses+bodies), lock


def decode_wait(state, events, user):
    if len(state) != 128 or len(user) != 8 or len(events) != 400:
        raise ValueError('unsupported live wait capture geometry')
    s = list(struct.unpack('<32I', state))
    rows = [list(row) for row in struct.iter_unpack('<10I', events)]
    if (s[0], s[2], s[4:11], s[16:20], s[28], s[31]) != (
            1, 1, [4, 2, 32, 0, 20000000, 16, 1000], [0, 10, 0, 0], 50000000, 2):
        raise ValueError('live wait recipe/state differs')
    if struct.unpack('<2I', user) != (0, 16) or not s[1] or s[3] != 0x1004 or s[15] != s[3]:
        raise ValueError('live wait user/kernel result or task state differs')
    if [r[1] for r in rows] != [1, 2, 3, 9, 4, 6, 5, 3, 7, 8]:
        raise ValueError('unsupported live wait scheduling/IRQ order')
    if any(r[0] != i or (r[8]&31) != 19 for i, r in enumerate(rows)):
        raise ValueError('live wait sequence or kernel mode differs')
    selected, background = s[1], rows[2][7]
    if background != 0 or rows[2][4] != 0x2000 or selected == background or rows[2][6] != selected or rows[7][6:8] != [background, selected]:
        raise ValueError('live wait task ownership differs')
    if rows[4][6] != 29 or rows[6][6] != 29 or [r[5] for r in rows] != [0, 0, 0, 0, 1, 1, 1, 0, 0, 0]:
        raise ValueError('live wait timer IRQ parentage differs')
    current = [selected]*3+[background]*5+[selected]*2
    if [r[2] for r in rows] != current:
        raise ValueError('live wait running task differs')
    wide = lambda lo: s[lo] | (s[lo+1] << 32)
    cycles = rows[1][6] | (rows[1][7] << 32)
    deadline = rows[3][6] | (rows[3][7] << 32)
    wake_time = rows[5][6] | (rows[5][7] << 32)
    if cycles != 1000000 or deadline != cycles+wide(24) or deadline != wide(26) or deadline != wide(20):
        raise ValueError('live wait delay/deadline differs')
    if wake_time != wide(29) or not deadline <= wake_time <= wide(22):
        raise ValueError('live wait resumed before timeout')
    if wide(24) < wide(13):
        raise ValueError('live wait scheduler clock moved backwards')
    expected_status = [s[3], s[3], s[3]|32, (s[3]&~4)|32,
                       (s[3]&~4)|32, (s[3]&~4)|2, (s[3]&~4)|2,
                       s[3]&~(4|2), s[3], s[3]]
    if [r[9] for r in rows] != expected_status:
        raise ValueError('live wait task status transitions differ')
    for i in (0, 1, 3, 5, 7, 8, 9):
        if rows[i][3] != selected or rows[i][4] != expected_status[i]:
            raise ValueError('live wait selected subject state differs')
    if any(rows[i][6:8] != [0, 0] for i in (0, 8, 9)):
        raise ValueError('live wait return or entry event differs')
    for i in (4, 6):
        if rows[i][3:5] != [0, 0] or rows[i][7]:
            raise ValueError('live wait IRQ payload differs')
    checkpoint = dict(task=dict(id=selected, status=s[3], wait_time=wide(11), start_time=wide(13), policy=s[31]),
                      request=dict(seconds=s[7], nanoseconds=s[8], bytes=s[9]),
                      tick_hz=s[10], clock_hz=s[28])
    clocks = dict(deadline_base_start=wide(24), enqueue_clock=wake_time, resume_start=wide(22))
    return dict(format='osrec-live-wait-v1', state=s, events=rows, checkpoint=checkpoint,
                scheduler_clock_inputs=clocks,
                user_result=0, user_mode=16, selected_task=selected,
                background_task=background, delay_cycles=cycles, deadline=deadline,
                wake_time=wake_time, timer_irq=29, event_count=10)


def generate(capture, original):
    array = 'static const UINT32 checkpoint[32]={'+','.join(map(str, capture['state']))+'};\n'
    array += 'static UINT32 events[10][10]={'+','.join(
        '{'+','.join(map(str, row))+'}' for row in capture['events'])+'};\n'
    return TEMPLATE.read_text().replace('/* @CAPTURE@ */', array).replace('/* @ORIGINAL@ */', original)


def export_live_wait(args, values, command):
    captured = decode_wait(values['WAIT_STATE'], values['WAIT_EVENTS'], values['WAIT_USER'])
    original, lock = prepare_source(args.kernel_root)
    # Verify that the live build used the same unmodified syscall/scheduler bodies.
    _, live_lock = prepare_source(ROOT/'build/ohos/kernel/liteos_a')
    if live_lock != lock:
        raise ValueError('live wait source identity differs')
    source = generate(captured, original)
    with tempfile.TemporaryDirectory(prefix='osrec-live-wait-') as name:
        stage = Path(name)
        cfile, binary = stage/'wait-replay.c', stage/'wait-replay'
        cfile.write_text(source)
        subprocess.run([args.compiler, '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                        str(cfile), '-o', str(binary)], check=True, capture_output=True, text=True)
        result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
        if result.stdout.strip() != 'live wait replay verified: 10 events':
            raise ValueError('standalone wait replay did not verify')
        for path in (cfile, binary):
            (args.out/path.name).write_bytes(path.read_bytes())
        (args.out/'wait-replay').chmod(0o755)
    for key in ('WAIT_STATE', 'WAIT_EVENTS', 'WAIT_USER'):
        (args.out/(key.lower().replace('_', '-')+'.bin')).write_bytes(values[key])
    captured.update(source_identity=lock, native_scheduler_executed=True,
                    native_timer_irq_observed=True, replay_scheduler='explicit sequential model',
                    original_definitions=list(ORDER), kernel_image_sha256=digest((ROOT/'build/ohos/out/liteos.bin').read_bytes()),
                    generated_source_sha256=digest(source.encode()), replay_requires_live_kernel=False,
                    replay_host_runtime=True, replay_external_inputs='embedded',
                    syscall=dict(number=162, function='SysNanoSleep', remaining_pointer='NULL'),
                    capture_adapter_sha256=digest((ROOT/'integrations/liteos_qemu/wait_capture.h').read_bytes()),
                    replay_template_sha256=digest(TEMPLATE.read_bytes()),
                    source_lock_sha256=digest(LOCK.read_bytes()),
                    replay_binary_sha256=digest((args.out/'wait-replay').read_bytes()),
                    qemu_command=list(map(str, command)), boot_log_sha256=digest((args.out/'boot.log').read_bytes()),
                    capture_sha256={key: digest(values[key]) for key in ('WAIT_STATE', 'WAIT_EVENTS', 'WAIT_USER')})
    (args.out/'wait-capture.json').write_text(json.dumps(captured, indent=2)+'\n')
    return captured
