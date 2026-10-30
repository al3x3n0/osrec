"""Check omission candidates and conservative fallbacks in real LLVM IR."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

OPT, PLUGIN = sys.argv[1:3]
sys.argv = sys.argv[:1]
IR = """
target datalayout = "e-p:64:64-i64:64-n32:64-S128"
target triple = "aarch64-unknown-linux-gnu"
declare i64 @clock()
declare void @escape(ptr)
declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64, i1)
declare i64 @llvm.readcyclecounter()

define i64 @helper(ptr %input) {
  %value = load i64, ptr %input, align 8
  ret i64 %value
}
define i64 @root(ptr %input) {
  %slot = alloca i64, align 8
  store i64 11, ptr %slot, align 8
  %local = load i64, ptr %slot, align 8
  %other = call i64 @helper(ptr %input)
  %result = add i64 %local, %other
  ret i64 %result
}
define i64 @partial() {
  %slot = alloca i64, align 8
  store i32 11, ptr %slot, align 8
  %value = load i64, ptr %slot, align 8
  ret i64 %value
}
define i64 @volatile_read() {
  %slot = alloca i64, align 8
  store i64 11, ptr %slot, align 8
  %value = load volatile i64, ptr %slot, align 8
  ret i64 %value
}
define i64 @atomic_read() {
  %slot = alloca i64, align 8
  store atomic i64 11, ptr %slot monotonic, align 8
  %value = load atomic i64, ptr %slot monotonic, align 8
  ret i64 %value
}
define i64 @escaped() {
  %slot = alloca i64, align 8
  store i64 11, ptr %slot, align 8
  call void @escape(ptr %slot)
  %value = load i64, ptr %slot, align 8
  ret i64 %value
}
define i64 @branch(i1 %condition) {
  %slot = alloca i64, align 8
  br i1 %condition, label %write, label %read
write:
  store i64 11, ptr %slot, align 8
  br label %read
read:
  %value = load i64, ptr %slot, align 8
  ret i64 %value
}
define i64 @shared(ptr %input) {
  store i64 11, ptr %input, align 8
  %value = load i64, ptr %input, align 8
  ret i64 %value
}
define i64 @indirect(ptr %callback) {
  %slot = alloca i64, align 8
  store i64 11, ptr %slot, align 8
  call void %callback()
  %value = load i64, ptr %slot, align 8
  ret i64 %value
}
define i64 @assembly() {
  %slot = alloca i64, align 8
  store i64 11, ptr %slot, align 8
  call void asm sideeffect "", "~{memory}"()
  %value = load i64, ptr %slot, align 8
  ret i64 %value
}
define i64 @external() {
  %time = call i64 @clock()
  ret i64 %time
}
define void @copy(ptr %out, ptr %in) {
  call void @llvm.memcpy.p0.p0.i64(ptr %out, ptr %in, i64 8, i1 false)
  ret void
}
define i64 @cycle() {
  %value = call i64 @llvm.readcyclecounter()
  ret i64 %value
}
define void @osrec_hook(ptr %input) {
  %value = load volatile i64, ptr %input, align 8
  ret void
}
define void @exclusion(ptr %input) {
  call void @osrec_hook(ptr %input)
  ret void
}
"""


class PlannerTests(unittest.TestCase):
    def plan(self, root):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.ll"
            source.write_text(IR)
            result = subprocess.run([OPT, "-load-pass-plugin", PLUGIN,
                                     f"-passes=osrec-plan<{root}>", "-disable-output",
                                     str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stderr)

    def test_direct_closure_and_local_candidate(self):
        plan = self.plan("root")
        self.assertEqual(plan["functions"], ["helper", "root"])
        self.assertEqual(plan["static_load_sites"], 2)
        self.assertEqual(plan["local_load_omit_candidates"], 1)
        loads = [site for site in plan["sites"] if site["opcode"] == "load"]
        self.assertEqual(loads[0]["decision"], "record_observation")
        self.assertEqual(loads[1]["decision"], "omit_candidate")
        self.assertTrue(plan["analysis_only"])
        self.assertFalse(plan["omissions_applied"])
        self.assertFalse(plan["kernel_replay_ready"])
        # The source path is part of the exact IR identity, so temporary file
        # locations can change the module hash while site mappings remain stable.
        other = self.plan("root")
        self.assertEqual(plan["sites"], other["sites"])
        self.assertEqual(len(plan["module_ir_sha256"]), 64)

    def test_keeps_uncertain_loads(self):
        for root in ["partial", "volatile_read", "atomic_read", "escaped",
                     "branch", "shared", "indirect", "assembly"]:
            with self.subTest(root=root):
                plan = self.plan(root)
                self.assertEqual(plan["local_load_omit_candidates"], 0)
                self.assertTrue(any(site["decision"] == "record_observation"
                                    for site in plan["sites"]))

    def test_reports_unmodeled_effects(self):
        for root in ["indirect", "assembly", "escaped", "external", "copy", "cycle", "atomic_read"]:
            with self.subTest(root=root):
                self.assertTrue(self.plan(root)["blockers"])
        self.assertEqual(self.plan("external")["external_calls"], ["clock"])

    def test_recorder_exclusion_and_unknown_root(self):
        plan = self.plan("exclusion")
        self.assertEqual(plan["functions"], ["exclusion"])
        self.assertEqual(plan["sites"], [])
        for root in ["not_present", "clock", "osrec_hook"]:
            self.assertTrue(self.plan(root)["blockers"])
            self.assertEqual(self.plan(root)["functions"], [])


if __name__ == "__main__":
    unittest.main()
