"""End-to-end checkpoints, continued syscall state, ordered replay and rejection."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

KERNEL, COMPILER = sys.argv[1:3]
sys.argv = sys.argv[:1]
ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT/"tools/syscall_checkpoint.py"


class SessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.stage = Path(cls.temporary.name)
        cls.capture = cls.stage/"capture.json"
        cls.case = json.loads((ROOT/"examples/sysread_session_case.json").read_bytes())
        cls.command = [sys.executable,str(TOOL),"capture","--kernel-root",KERNEL,"--compiler",COMPILER,
                       "--case",str(ROOT/"examples/sysread_session_case.json"),"--out",str(cls.capture)]
        result = subprocess.run(cls.command,text=True,capture_output=True)
        if result.returncode: raise AssertionError(result.stderr)
        cls.document = json.loads(cls.capture.read_bytes())
        cls.artifact = cls.stage/"nested/scenarios/session"
        cls.export_command = [sys.executable,str(TOOL),"export","--kernel-root",KERNEL,"--compiler",COMPILER,
                              "--capture",str(cls.capture),"--out",str(cls.artifact)]
        result = subprocess.run(cls.export_command,text=True,capture_output=True)
        if result.returncode: raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def test_state_persists_across_aliased_descriptors(self):
        observations = self.document["expected"]
        self.assertEqual([step["return"] for step in observations],[2,1,-1,0])
        self.assertEqual([step["errno"] for step in observations],[0,0,4,4])
        self.assertEqual([step["file_positions"]["20"] for step in observations],[12,13,13,13])
        self.assertEqual(observations[-1]["memory"],"0011414243556677")
        self.assertEqual([[event["kind"] for event in step] for step in self.document["transcript"]],[[1,2,3],[1,2,3],[1,2,3,4],[]])
        self.assertNotIn("environment",self.document)
        self.assertEqual(self.document["entry"]["objects"][0]["data"],"0011223344556677")

    def test_isolated_executable_and_embedded_source_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            copied=Path(directory)/"scenario"; shutil.copy2(self.artifact,copied)
            env={"PATH":"/usr/bin:/bin","LC_ALL":"C"}
            output=subprocess.check_output([str(copied)],cwd=directory,env=env,text=True)
            self.assertEqual(output.strip(),"syscall session verified: 4 calls")
            described=json.loads(subprocess.check_output([str(copied),"--describe"],cwd=directory,env=env,text=True))
            self.assertEqual(described["capture"],self.document)
            self.assertEqual(described["executed_kernel_code"],["SysRead"])
            self.assertIn("Redistributions in binary form",described["kernel_license"])
            self.assertFalse(described["scheduler_irq_execution"])
            self.assertFalse(described["symbolic_equivalence_verified"])
            self.assertEqual(list(Path(directory).iterdir()),[copied])

    def test_corrupt_state_transcript_and_expectations_preserve_binary(self):
        modifications = {
            "initial memory":lambda d:d["entry"]["objects"][0].update(data="ff11223344556677"),
            "file cursor":lambda d:d["entry"]["objects"][1]["fields"].update(position=11),
            "user errno":lambda d:d["entry"]["objects"][2]["fields"].update(user_errno=7),
            "descriptor alias":lambda d:d["entry"]["objects"][2]["fields"]["fd4"].update(object=0),
            "event order":lambda d:d["transcript"][0].reverse(),
            "missing event":lambda d:d["transcript"][0].pop(),
            "extra event":lambda d:d["transcript"][1].append(copy.deepcopy(d["transcript"][1][0])),
            "wrong arguments":lambda d:d["calls"][0].update(count=3),
            "wrong observation":lambda d:d["expected"][0].update(raw=3),
            "payload":lambda d:d["transcript"][0][-1].update(payload="5842"),
            "stale model":lambda d:d["identity"]["models"].update({"runtime/checkpoint.c":"0"*64}),
            "invalid pointer":lambda d:d["calls"][0]["buffer"].update(offset=9),
        }
        original=self.artifact.read_bytes()
        for name,change in modifications.items():
            with self.subTest(name=name):
                damaged=copy.deepcopy(self.document); change(damaged)
                path=self.stage/"bad.json"; path.write_text(json.dumps(damaged))
                command=self.export_command.copy(); command[command.index("--capture")+1]=str(path)
                result=subprocess.run(command,text=True,capture_output=True)
                self.assertNotEqual(result.returncode,0,result.stdout)
                self.assertEqual(self.artifact.read_bytes(),original)

    def test_two_files_wraparound_faults_backend_error_and_zero_length(self):
        case=copy.deepcopy(self.case)
        case["entry"]["objects"][1]["fields"]["position"]=0xffffffff
        case["entry"]["objects"].append({"id":21,"type":"file","fields":{"backend_fd":18,"position":100}})
        process=case["entry"]["objects"][2]["fields"]
        process["fd4"]["object"]=21; process["user_errno"]=9; process["kernel_errno"]=5
        requests=[(3,2,10,0),(4,1,10,4),(3,1,0,0),(3,2,10,7),(3,1,10,8),(1,1,10,0),(4,1,10,0),(0,0,0,0)]
        case["calls"]=[{"syscall":"SysRead","fd":fd,"count":count,"buffer":{"object":obj,"offset":offset}} for fd,count,obj,offset in requests]
        case["environment"]=[{"result":2,"errno":0,"payload":"4142"},{"result":1,"errno":0,"payload":"43"}]
        case["environment"] += [{"result":0,"errno":0,"payload":""} for _ in range(4)]
        case["environment"] += [{"result":-1,"errno":5,"payload":""},{"result":0,"errno":0,"payload":""}]
        path=self.stage/"matrix-case.json"; path.write_text(json.dumps(case))
        captured=self.stage/"matrix-capture.json"
        command=self.command.copy(); command[command.index("--case")+1]=str(path); command[-1]=str(captured)
        result=subprocess.run(command,text=True,capture_output=True); self.assertEqual(result.returncode,0,result.stderr)
        document=json.loads(captured.read_bytes())
        self.assertEqual([o["raw"] for o in document["expected"]],[2,1,-14,-14,-14,-9,-5,0])
        self.assertEqual(document["expected"][0]["file_positions"],{"20":1,"21":100})
        self.assertEqual(document["expected"][1]["file_positions"],{"20":1,"21":101})
        self.assertEqual([o["errno"] for o in document["expected"]],[9,9,14,14,14,9,5,5])
        command=self.export_command.copy(); command[command.index("--capture")+1]=str(captured); command[-1]=str(self.stage/"matrix")
        result=subprocess.run(command,text=True,capture_output=True); self.assertEqual(result.returncode,0,result.stderr)

    def test_zero_byte_backend_and_null_descriptor_state(self):
        case=copy.deepcopy(self.case)
        case["calls"]=case["calls"][:2]; case["environment"]=case["environment"][:2]
        case["environment"][0]={"result":0,"errno":0,"payload":""}
        case["entry"]["objects"][2]["fields"]["fd4"]={"object":0,"offset":0}
        path=self.stage/"eof-case.json"; path.write_text(json.dumps(case)); captured=self.stage/"eof-capture.json"
        command=self.command.copy(); command[command.index("--case")+1]=str(path); command[-1]=str(captured)
        result=subprocess.run(command,text=True,capture_output=True); self.assertEqual(result.returncode,0,result.stderr)
        document=json.loads(captured.read_bytes())
        self.assertEqual([o["raw"] for o in document["expected"]],[0,-9])
        self.assertEqual(document["expected"][0]["file_positions"]["20"],10)
        command=self.export_command.copy(); command[command.index("--capture")+1]=str(captured); command[-1]=str(self.stage/"eof")
        result=subprocess.run(command,text=True,capture_output=True); self.assertEqual(result.returncode,0,result.stderr)


if __name__ == "__main__": unittest.main()
