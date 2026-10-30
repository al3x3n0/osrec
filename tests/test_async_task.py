"""Execute timer-driven completion, nested hardware IRQs and rejected replays."""
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import export_async_task as exporter
from export_task_capsule import records
from run_freestanding_armv7 import observe, require_success

DEMO = ROOT/'build/live-syscall-checks/record_task_demo'
LLVM = Path('/opt/homebrew/opt/llvm@16/bin')
QEMU = 'qemu-system-aarch64'


def change_event(raw, event, field, value):
    rows = records(raw)
    kind, site, payload = rows[event+3]
    values = list(struct.unpack('<8Q', payload))
    values[field] = value
    rows[event+3] = kind, site, struct.pack('<8Q', *values)
    return b'OSRC\x01\0\0\0'+b''.join(struct.pack('<III', k, s, len(p))+p for k, s, p in rows)


class AsyncTaskTests(unittest.TestCase):
    def capture(self, stage, values=(0, 7, 5, 2), single=True):
        trace = stage/'capture.osrec'
        subprocess.run([str(DEMO), str(trace), *map(str, values),
                        *(['--single-cpu'] if single else [])],
                       check=True, capture_output=True)
        return SimpleNamespace(capture=trace, out=stage/'image', llvm_bin=LLVM,
                               qemu=QEMU, entry_address=0x40200000,
                               result_address=0x40180000)

    def test_actual_nested_irqs_saturation_and_standalone_images(self):
        for values in ((0, 7, 5, 2), (4, 10, 4, 2),
                       ((1<<64)-3, (1<<64)-1, 9, 1)):
            with self.subTest(values=values), tempfile.TemporaryDirectory() as name:
                args = self.capture(Path(name), values)
                args.entry_address = 0x40400000
                args.result_address = 0x40380000
                report = exporter.export(args)
                self.assertEqual(report['target_observations']['irq_count'], 2)
                self.assertEqual(report['target_observations']['max_irq_depth'], 2)
                self.assertTrue(report['target_observations']['trace_verified'])
                self.assertTrue(report['hardware_irq_delivery'])
                self.assertFalse(report['kernel_scheduler_reproduction'])
                self.assertFalse(report['runtime_host_interaction'])
                args.capture.unlink()
                shutil.rmtree(args.out/'sources')
                (args.out/'manifest.json').unlink()
                (args.out/'capture.osrec').unlink()
                elf = args.out/'async-task.elf'
                a, raw = observe(elf, QEMU)
                b, binary_raw = observe(args.out/'async-task.bin', QEMU, descriptor=elf)
                require_success(a); require_success(b)
                self.assertEqual(raw, binary_raw)
                self.assertEqual(a['return_value'], values[1])
                self.assertEqual(a['remaining'], min((1<<64)-1, sum((values[0], values[2], values[3])))-values[1])

    def test_migration_bad_source_and_irq_order_reject_before_publication(self):
        for case in ('migration', 'source', 'parent', 'generation'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as name:
                args = self.capture(Path(name), single=case!='migration')
                raw = args.capture.read_bytes()
                if case == 'source':
                    raw = raw[:20]+b'x'+raw[21:]
                elif case == 'parent':
                    raw = change_event(raw, 4, 3, 102)
                elif case == 'generation':
                    raw = change_event(raw, 9, 7, 2)
                args.capture.write_bytes(raw)
                with self.assertRaises(ValueError):
                    exporter.export(args)
                self.assertFalse(args.out.exists())

    def test_false_intermediate_effect_fails_inside_target(self):
        with tempfile.TemporaryDirectory() as name:
            args = self.capture(Path(name))
            args.capture.write_bytes(change_event(args.capture.read_bytes(), 6, 7, 3))
            with self.assertRaisesRegex(ValueError, 'target replay diverged'):
                exporter.export(args)
            self.assertFalse(args.out.exists())

    def test_missing_preemption_and_handler_effect_reject_in_target(self):
        changes = [
            ('        unmask();', '        mask();'),
            ('complete_irq(&completion,checkpoint_nested);', '(void)checkpoint_nested;'),
        ]
        real_run = exporter.run
        for error, (old, new) in zip((2, 1), changes):
            with self.subTest(change=old), tempfile.TemporaryDirectory() as name:
                args = self.capture(Path(name))

                def altered_run(command):
                    if Path(command[0]).name == 'clang':
                        source = next(Path(p) for p in command if str(p).endswith('/replay.c'))
                        text = source.read_text()
                        self.assertEqual(text.count(old), 1)
                        source.write_text(text.replace(old, new))
                    return real_run(command)

                with patch.object(exporter, 'run', altered_run):
                    with self.assertRaisesRegex(ValueError, 'target replay diverged: .*"error": '+str(error)):
                        exporter.export(args)
                self.assertFalse(args.out.exists())


if __name__ == '__main__':
    if len(sys.argv) == 4:
        DEMO, LLVM, QEMU = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
        sys.argv = sys.argv[:1]
    unittest.main(verbosity=2)
