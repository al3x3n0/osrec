"""Integration checks for typed capture, graph reconstruction and isolated export."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

RECORDER, COMPILER = sys.argv[1:3]
sys.argv = sys.argv[:1]
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from export_object_checkpoint import REGION, decode


class CheckpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.stage = Path(cls.temporary.name)
        cls.capture = cls.stage / "checkpoint.json"
        subprocess.run([RECORDER, str(cls.capture)], check=True, capture_output=True)
        cls.document = json.loads(cls.capture.read_bytes())
        cls.artifact = cls.stage / "scenario"
        cls.command = [sys.executable, str(ROOT / "tools/export_object_checkpoint.py"),
                       str(cls.capture), "--compiler", COMPILER, "--out", str(cls.artifact)]
        result = subprocess.run(cls.command, text=True, capture_output=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_entry_state_and_observed_effects_are_distinct(self):
        document, indexed = decode(self.capture.read_bytes(), REGION.read_bytes())
        self.assertEqual(indexed[1]["fields"]["credits"], 5)
        self.assertEqual(indexed[2]["fields"]["credits"], 3)
        self.assertEqual(indexed[3]["data"], "a5" * 8)
        self.assertEqual(document["expected"]["credits"], {"1": 0, "2": 1})
        self.assertEqual(document["expected"]["return"], 7)
        task = indexed[4]["fields"]
        self.assertEqual(task["wait"], task["alias"])
        self.assertEqual(task["cursor"], {"object": 3, "offset": 2})
        self.assertEqual(task["view"], {"object": 3, "offset": 4})
        self.assertEqual(indexed[1]["fields"]["next"]["object"], 2)
        self.assertEqual(indexed[2]["fields"]["next"]["object"], 1)

    def test_executable_runs_without_capture_or_sidecars(self):
        with tempfile.TemporaryDirectory() as directory:
            isolated = Path(directory) / "scenario"
            shutil.copy2(self.artifact, isolated)
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
            result = subprocess.run([str(isolated)], cwd=directory, env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "object replay verified: return=7")
            described = json.loads(subprocess.check_output([str(isolated), "--describe"], cwd=directory, env=env, text=True))
            self.assertEqual(described["checkpoint"], self.document)
            self.assertFalse(described["symbolic_equivalence_verified"])
            self.assertEqual(list(Path(directory).iterdir()), [isolated])

    def test_relocated_object_ids_and_order(self):
        changed = copy.deepcopy(self.document)
        remap = {1: 901, 2: 113, 3: 77, 4: 49}
        for entry in changed["objects"]:
            entry["id"] = remap[entry["id"]]
            for value in entry.get("fields", {}).values():
                if isinstance(value, dict):
                    value["object"] = remap[value["object"]]
        changed["roots"]["current_task"]["object"] = remap[4]
        for key in ("credits", "buffers"):
            changed["expected"][key] = {str(remap[int(identifier)]): value for identifier, value in changed["expected"][key].items()}
        changed["objects"].reverse()
        capture = self.stage / "reordered.json"
        capture.write_text(json.dumps(changed))
        command = self.command.copy()
        command[2] = str(capture)
        command[-1] = str(self.stage / "reordered")
        result = subprocess.run(command, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("return=7", subprocess.check_output([command[-1]], text=True))

    def test_malformed_graphs_are_rejected(self):
        def mutate(name, change):
            document = copy.deepcopy(self.document)
            change(document)
            with self.subTest(name=name), self.assertRaises(ValueError):
                decode(json.dumps(document).encode(), REGION.read_bytes())
        mutate("duplicate ID", lambda d: d["objects"][1].update(id=1))
        mutate("dangling", lambda d: d["objects"][3]["fields"]["wait"].update(object=99))
        mutate("wrong type", lambda d: d["objects"][3]["fields"]["wait"].update(object=3))
        mutate("struct interior", lambda d: d["objects"][3]["fields"]["wait"].update(offset=1))
        mutate("buffer extent", lambda d: d["objects"][3]["fields"]["cursor"].update(offset=6))
        mutate("one past buffer", lambda d: d["objects"][3]["fields"]["view"].update(offset=8))
        mutate("null root", lambda d: d["roots"]["current_task"].update(object=0))
        mutate("boolean scalar", lambda d: d["objects"][0]["fields"].update(credits=True))
        mutate("overflow scalar", lambda d: d["objects"][0]["fields"].update(credits=1 << 32))
        mutate("extra field", lambda d: d["objects"][0]["fields"].update(hidden=1))
        mutate("stale source", lambda d: d.update(source_sha256="0" * 64))
        mutate("unreachable", lambda d: d["objects"].append({"id": 9, "type": "bytes", "data": "00"}))
        mutate("broken alias", lambda d: d["objects"][3]["fields"]["alias"].update(object=2))
        mutate("broken cycle", lambda d: d["objects"][1]["fields"]["next"].update(object=2))
        with self.assertRaises(ValueError):
            decode(self.capture.read_bytes().replace(b'"demand":7', b'"demand":7,"demand":8'), REGION.read_bytes())

    def test_wrong_expectation_does_not_replace_executable(self):
        changed = copy.deepcopy(self.document)
        changed["expected"]["return"] = 8
        capture = self.stage / "wrong.json"
        capture.write_text(json.dumps(changed))
        command = self.command.copy()
        command[2] = str(capture)
        original = self.artifact.read_bytes()
        result = subprocess.run(command, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.artifact.read_bytes(), original)

    def test_zero_and_large_initial_states(self):
        for first, second, demand in ((0, 0, 0), (0, 5, 3), (5, 0, 9), (0xffffffff, 1, 0xffffffff)):
            with self.subTest(first=first, second=second, demand=demand):
                capture = self.stage / "variant.json"
                subprocess.run([RECORDER, str(capture), str(first), str(second), str(demand)], check=True, capture_output=True)
                command = self.command.copy()
                command[2] = str(capture)
                command[-1] = str(self.stage / "variant")
                result = subprocess.run(command, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
