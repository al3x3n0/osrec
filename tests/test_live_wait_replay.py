"""Replay a real blocking LiteOS-A wait and reject false scheduling histories."""
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import live_wait_replay as replay
KERNEL = ROOT/'build/kernel_liteos_a'
FIXTURE = ROOT/'tests/fixtures/live-liteos-wait'
CC = 'cc'


class LiveWaitTests(unittest.TestCase):
    def raw(self):
        return [(FIXTURE/name).read_bytes() for name in ('wait-state.bin', 'wait-events.bin', 'wait-user.bin')]

    def compile(self, stage, source):
        cfile, binary = stage/'wait.c', stage/'wait'
        cfile.write_text(source)
        subprocess.run([CC, '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', str(cfile), '-o', str(binary)],
                       check=True, capture_output=True, text=True)
        cfile.unlink()
        return subprocess.run([str(binary)], capture_output=True, text=True)

    def test_real_native_checkpoint_and_standalone_original_computation(self):
        proof = json.loads((FIXTURE/'provenance.json').read_text())
        for name, expected in proof['files_sha256'].items():
            self.assertEqual(replay.digest((FIXTURE/name).read_bytes()), expected)
        captured = replay.decode_wait(*self.raw())
        original, lock = replay.prepare_source(KERNEL)
        metadata = json.loads((FIXTURE/'wait-capture.json').read_text())
        self.assertEqual(metadata['source_identity'], lock)
        self.assertEqual(metadata['source_lock_sha256'], replay.digest(replay.LOCK.read_bytes()))
        self.assertEqual(metadata['replay_template_sha256'], replay.digest(replay.TEMPLATE.read_bytes()))
        self.assertEqual(metadata['capture_adapter_sha256'], replay.digest((ROOT/'integrations/liteos_qemu/wait_capture.h').read_bytes()))
        self.assertEqual(len(lock['definitions']), 8)
        self.assertEqual(captured['checkpoint']['clock_hz'], 50000000)
        self.assertEqual(captured['event_count'], 10)
        self.assertGreaterEqual(captured['wake_time'], captured['deadline'])
        with tempfile.TemporaryDirectory() as name:
            result = self.compile(Path(name), replay.generate(captured, original))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'live wait replay verified: 10 events')

    def test_false_context_order_state_clock_and_results_reject(self):
        state, events, user = self.raw()
        for row, field, value in ((2, 6, 99), (2, 4, 0), (4, 6, 30), (5, 5, 0), (5, 6, 0),
                                   (7, 7, 99), (3, 7, 1), (6, 9, 0), (0, 8, 16), (9, 6, 1)):
            with self.subTest(row=row, field=field):
                bad = bytearray(events)
                struct.pack_into('<I', bad, row*40+field*4, value)
                with self.assertRaises(ValueError):
                    replay.decode_wait(state, bad, user)
        for field, value in ((0, 2), (1, 0), (3, 4), (9, 8), (16, 1), (18, 1), (19, 1), (26, 0), (28, 1), (31, 1)):
            with self.subTest(state_field=field):
                bad = bytearray(state); struct.pack_into('<I', bad, field*4, value)
                with self.assertRaises(ValueError):
                    replay.decode_wait(bad, events, user)
        for payload in (events[:-1], events+events[:40]):
            with self.assertRaises(ValueError):replay.decode_wait(state, payload, user)
        with self.assertRaises(ValueError):replay.decode_wait(state, events, struct.pack('<2I', 1, 16))

    def test_original_delay_deadline_timeout_and_enqueue_mutants_fail(self):
        captured = replay.decode_wait(*self.raw())
        original, _ = replay.prepare_source(KERNEL)
        source = replay.generate(captured, original)
        changes = [
            ('runTask->taskStatus |= OS_TASK_STATUS_DELAY;', 'runTask->taskStatus |= OS_TASK_STATUS_READY;'),
            ('taskCB->waitTime += taskCB->startTime;', 'taskCB->waitTime += 0;'),
            ('if (!(tempStatus & OS_TASK_STATUS_SUSPENDED)) {',
             'if (tempStatus & OS_TASK_STATUS_SUSPENDED) {'),
            ('t->taskStatus|=OS_TASK_STATUS_READY;', 't->taskStatus|=OS_TASK_STATUS_RUNNING;'),
        ]
        for old, new in changes:
            with self.subTest(change=old), tempfile.TemporaryDirectory() as name:
                self.assertEqual(source.count(old), 1)
                result = self.compile(Path(name), source.replace(old, new))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('live wait replay diverged', result.stderr)

    def test_source_and_abi_tampering_reject(self):
        lock = json.loads(replay.LOCK.read_text())
        for target in ('syscall/time_syscall.c', 'kernel/base/sched/los_sched.c', 'syscall/syscall_lookup.h'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                for path in {**lock['sources'], **lock['headers']}:
                    (root/path).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(KERNEL/path, root/path)
                (root/target).write_bytes((root/target).read_bytes()+b'\n/* changed */\n')
                with patch.object(replay.subprocess, 'check_output', return_value=lock['revision']+'\n'):
                    with self.assertRaisesRegex(ValueError, 'source/header changed'):
                        replay.prepare_source(root)

    def test_optional_capture_flags_reject_before_build(self):
        result = subprocess.run([sys.executable, str(ROOT/'tools/liteos_qemu_demo.py'),
                                 '--async-wait', '--clocks', '--out', '/private/tmp/osrec-unused-wait'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('--async-wait excludes', result.stderr)


if __name__ == '__main__':
    if len(sys.argv) == 3:
        KERNEL, CC = Path(sys.argv[1]), sys.argv[2]
        sys.argv = sys.argv[:1]
    unittest.main(verbosity=2)
