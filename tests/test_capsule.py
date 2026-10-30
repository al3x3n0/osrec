"""Exercise capture -> export -> compile -> replay and invalid capture refusal."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("exporter", ROOT / "tools" / "export_capsule.py")
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)
DEMO, CC = sys.argv[1:3]
sys.argv = sys.argv[:1]


class CapsuleTests(unittest.TestCase):
    def test_invalid_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "invalid.osrec"
            for invalid in ["", "-1", " -1", "+1", "1x", str(2**64)]:
                result = subprocess.run([DEMO, str(trace), invalid, "500", "30", "400"],
                                        capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(trace.exists())

    def record(self, folder, values):
        trace = folder / "capture.osrec"
        subprocess.run([DEMO, str(trace), *map(str, values)], check=True, capture_output=True)
        return trace.read_bytes()

    def test_replay_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for values in [(100, 500, 30, 400), (10, 500, 30, 400),
                           (100, 500, 30, 501), (0, 0, 0, 0),
                           (2**64 - 1, 2**64 - 1, 2**64 - 1, 2**64 - 1)]:
                with self.subTest(values=values):
                    data = self.record(folder, values)
                    source = folder / "capsule.c"
                    source.write_text(exporter.export(data, exporter.REGION.read_bytes()))
                    binary = folder / "capsule"
                    subprocess.run([CC, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                    str(source), "-o", str(binary)], check=True, capture_output=True)
                    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
                    self.assertEqual(result.stdout.strip(), "replay verified")

    def test_refuses_invalid_traces(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.record(Path(directory), (100, 500, 30, 400))
            source = exporter.REGION.read_bytes()
            bad_site = bytearray(data)
            bad_site[88] = 99  # INPUT site field
            bad_output = bytearray(data)
            bad_output[148] ^= 1  # wrong OUTPUT payload length
            for invalid in [data[:n] for n in range(len(data))] + [
                    b"BAD!" + data[4:], data + b"extra", bytes(bad_site), bytes(bad_output)]:
                with self.assertRaises(ValueError):
                    exporter.decode(invalid, source)
            with self.assertRaisesRegex(ValueError, "fingerprint"):
                exporter.decode(data, source + b"\n")

    def test_detects_output_divergence(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            data = bytearray(self.record(folder, (100, 500, 30, 400)))
            data[156] ^= 1  # corrupt expected remaining credits
            source = folder / "capsule.c"
            source.write_text(exporter.export(bytes(data), exporter.REGION.read_bytes()))
            binary = folder / "capsule"
            subprocess.run([CC, "-std=c11", str(source), "-o", str(binary)], check=True, capture_output=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("diverged", result.stderr)


if __name__ == "__main__":
    unittest.main()
