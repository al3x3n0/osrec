"""Check symbolic publication, isolated execution and failed-equivalence rejection."""
import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

LLVM_BIN, PLUGIN, KLEE, INCLUDE = [Path(value).resolve() for value in sys.argv[1:5]]
sys.argv = sys.argv[:1]
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from export_el0 import proof


class ExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.stage = Path(cls.temporary.name)
        cls.module = cls.stage / "callback.bc"
        subprocess.run([str(LLVM_BIN / "clang"), "-O0", "-g", "-fno-builtin", "-emit-llvm", "-c",
                        str(ROOT / "examples/el0_callback_slice.c"), "-o", str(cls.module)],
                       check=True, capture_output=True)
        cls.artifact = cls.stage / "scenario"
        cls.command = [sys.executable, str(ROOT / "tools/export_el0.py"), str(cls.module),
                       "--root", "callback_scenario", "--arguments", "[100,1]",
                       "--llvm-bin", str(LLVM_BIN), "--plugin", str(PLUGIN),
                       "--klee", str(KLEE), "--klee-include", str(INCLUDE), "--out", str(cls.artifact)]
        result = subprocess.run(cls.command, text=True, capture_output=True)
        if result.returncode:
            raise AssertionError(result.stderr)
        cls.description = json.loads(subprocess.check_output([str(cls.artifact), "--describe"], text=True))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_isolated_binary_and_complete_symbolic_check(self):
        metadata = self.description
        self.assertEqual(metadata["checkpoint"], [100, 1])
        self.assertEqual(metadata["expected_return_bits"], 107)
        self.assertGreater(metadata["extraction"]["removed"], 0)
        self.assertEqual(metadata["symbolic_equivalence"]["partial_paths"], 0)
        self.assertGreater(metadata["symbolic_equivalence"]["completed_paths"], 0)
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "scenario"
            shutil.copy2(self.artifact, copied)
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
            result = subprocess.run([str(copied)], cwd=directory, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "scenario verified: return=107")
            self.assertEqual(json.loads(subprocess.check_output([str(copied), "--describe"], cwd=directory,
                                                               env=env, text=True)), metadata)
            self.assertEqual(list(Path(directory).iterdir()), [copied])

    def test_checkpoint_rejection_preserves_existing_binary(self):
        original = self.artifact.read_bytes()
        for values in ("[100]", "[true,1]", "[-1,1]", "[4294967296,1]"):
            with self.subTest(values=values):
                command = self.command.copy()
                command[command.index("--arguments") + 1] = values
                result = subprocess.run(command, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.artifact.read_bytes(), original)

    def test_unsupported_state_and_undefinedness_contracts(self):
        cases = {
            "global": "unsigned shared; unsigned root(unsigned v) { shared = v; return v; }",
            "signed": "int root(int v) { return v + 7; }",
            "indirect": "unsigned (*callback)(unsigned); unsigned root(unsigned v) { return callback(v); }",
            "pointer": "unsigned root(unsigned *v) { return *v; }",
            "uninitialized": "unsigned root(unsigned v) { unsigned x; return v ? x : 1; }",
        }
        for name, source in cases.items():
            with self.subTest(name=name):
                path = self.stage / f"{name}.c"
                path.write_text(source)
                module = self.stage / f"{name}.bc"
                subprocess.run([str(LLVM_BIN / "clang"), "-O0", "-fno-builtin", "-emit-llvm", "-c",
                                str(path), "-o", str(module)], check=True, capture_output=True)
                command = self.command.copy()
                command[2] = str(module)
                command[command.index("--root") + 1] = "root"
                command[command.index("--arguments") + 1] = "[1]"
                command[command.index("--out") + 1] = str(self.stage / f"rejected-{name}")
                result = subprocess.run(command, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.stage / f"rejected-{name}").exists())

    def test_changed_return_is_caught_by_klee(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            outputs = []
            for name, offset in (("reference", 7), ("extracted", 8)):
                source = stage / f"{name}.c"
                source.write_text(f"unsigned osrec_{name}_entry(unsigned value) {{ return value + {offset}U; }}")
                module = stage / f"{name}.bc"
                subprocess.run([str(LLVM_BIN / "clang"), "-O0", "-fno-builtin", "-emit-llvm", "-c",
                                str(source), "-o", str(module)], check=True, capture_output=True)
                outputs.append(module)
            args = SimpleNamespace(llvm_bin=LLVM_BIN, klee=KLEE, klee_include=INCLUDE)
            with self.assertRaisesRegex(ValueError, "symbolic equivalence"):
                proof(args, stage, outputs[0], outputs[1], 1)
            self.assertTrue(list((stage / "klee-proof").glob("*.equivalence.err")))

    def test_minmax_and_hash_bound_source_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            source = stage / "maximum.c"
            source.write_text("unsigned root(unsigned a, unsigned b) { return a > b ? a : b; }")
            module = stage / "maximum.bc"
            subprocess.run([str(LLVM_BIN / "clang"), "-O1", "-g", "-fno-builtin", "-emit-llvm", "-c",
                            str(source), "-o", str(module)], check=True, capture_output=True)
            identity = {"format": "osrec-el0-source-identity-v1",
                        "module_sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
                        "source": {"function": "root"}, "license": "test fixture",
                        "type_contract": "two unsigned 32-bit scalar arguments"}
            identity_path = stage / "identity.json"
            identity_path.write_text(json.dumps(identity))
            artifact = stage / "maximum"
            command = self.command.copy()
            command[2] = str(module)
            command[command.index("--root") + 1] = "root"
            command[command.index("--out") + 1] = str(artifact)
            command += ["--source-identity", str(identity_path)]
            result = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            metadata = json.loads(subprocess.check_output([str(artifact), "--describe"], text=True))
            self.assertEqual(metadata["source_identity"], identity)
            self.assertEqual(metadata["expected_return_bits"], 100)
            original = artifact.read_bytes()
            identity["module_sha256"] = "0" * 64
            identity_path.write_text(json.dumps(identity))
            result = subprocess.run(command, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exact input module", result.stderr)
            self.assertEqual(artifact.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
