"""Validate task contexts and execute generated continuation capsules."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("task_exporter", ROOT / "tools" / "export_task_capsule.py")
exporter = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = exporter
spec.loader.exec_module(exporter)
DEMO, CC = sys.argv[1:3]
sys.argv = sys.argv[:1]


def encode(records):
    return b"OSRC\x01\x00\x00\x00" + b"".join(
        struct.pack("<III", kind, site, len(payload)) + payload
        for kind, site, payload in records)


def mutate(data, event, field, value):
    records = exporter.records(data)
    kind, site, payload = records[event + 3]
    fields = list(struct.unpack("<8Q", payload))
    fields[field] = value
    records[event + 3] = (kind, site, struct.pack("<8Q", *fields))
    return encode(records)


class TaskCapsuleTests(unittest.TestCase):
    def record(self, folder, values=(0, 7, 5, 2)):
        path = folder / "task.osrec"
        subprocess.run([DEMO, str(path), *map(str, values)], check=True, capture_output=True)
        return path.read_bytes()

    def replay(self, folder, data):
        source = folder / "task.c"
        source.write_text(exporter.export(data, exporter.REGION.read_bytes()))
        binary = folder / "task"
        subprocess.run([CC, "-std=c11", "-Wall", "-Wextra", "-Werror", str(source),
                        "-o", str(binary)], check=True, capture_output=True)
        return subprocess.run([str(binary)], capture_output=True, text=True)

    def test_replay_and_contexts(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for args in [(0, 7, 5, 2), (4, 10, 4, 2), (0, 3, 1, 2),
                         (0, 2**64 - 1, 2**64 - 2, 1),
                         (2**64 - 3, 2**64 - 1, 9, 1)]:
                with self.subTest(args=args):
                    data = self.record(folder, args)
                    capture = exporter.decode(data, exporter.REGION.read_bytes())
                    self.assertEqual(len(capture.events), 13)
                    self.assertEqual(capture.events[4].parent, capture.events[2].context)
                    self.assertEqual(capture.events[-1].cpu, 1)
                    self.assertEqual(capture.events[-1].task, capture.selected_task)
                    result = self.replay(folder, data)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), "task replay verified")

    def test_invalid_contexts(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.record(Path(directory))
            source = exporter.REGION.read_bytes()
            outer = exporter.IRQ_BASE
            mutations = {
                "sequence gap": (5, 0, 99),
                "invalid CPU": (5, 1, 4),
                "incorrect nested parent": (4, 3, 102),
                "duplicate IRQ identity": (4, 2, outer),
                "wrong exit order": (7, 2, outer),
                "event outside current task": (1, 4, 999),
                "wrong wake generation": (9, 7, 2),
                "switch to task already on other CPU": (1, 7, 103),
                "wrong source task on resume": (11, 6, 999),
                "unknown event kind": (6, 5, 99),
                "unknown completion object": (6, 6, 2),
            }
            for name, args in mutations.items():
                with self.subTest(name=name), self.assertRaises(ValueError):
                    exporter.decode(mutate(data, *args), source)
            records = exporter.records(data)
            for invalid in [encode(records[:-1]), encode(records + [records[-1]]),
                            encode(records[:8] + records[9:]), data + b"extra",
                            b"invalid", b"x" * 4097]:
                with self.assertRaises(ValueError):
                    exporter.decode(invalid, source)
            with self.assertRaisesRegex(ValueError, "fingerprint"):
                exporter.decode(data, source + b"\n")

    def test_all_truncated_prefixes(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.record(Path(directory))
            for size in range(len(data)):
                with self.assertRaises(ValueError):
                    exporter.decode(data[:size], exporter.REGION.read_bytes())

    def test_recomputes_handler_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            data = self.record(folder)
            # The transcript remains structurally valid; replay computes the
            # handler's actual output and detects the wrong recorded expectation.
            for changed in [mutate(data, 6, 7, 99), mutate(data, 3, 7, 4)]:
                result = self.replay(folder, changed)
                self.assertEqual(result.returncode, 1)
                self.assertIn("diverged", result.stderr)

    def test_refuses_unsupported_scenarios(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "invalid.osrec"
            for args in [(10, 7, 5, 2), (0, 7, 1, 2), (0, 7, 0, 7),
                         (0, "-1", 5, 2), (0, 2**64, 5, 2)]:
                result = subprocess.run([DEMO, str(trace), *map(str, args)], capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(trace.exists())


if __name__ == "__main__":
    unittest.main()
