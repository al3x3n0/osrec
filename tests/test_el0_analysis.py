"""Exercise EL0 discovery on actual LLVM IR, including conservative obstacles."""
import json
from pathlib import Path
import subprocess
import re
import sys
import tempfile
import unittest

OPT, PLUGIN = sys.argv[1:3]
LLVM_MAJOR = int(re.search(r"LLVM version (\d+)", subprocess.run(
    [OPT, "--version"], capture_output=True, text=True, check=True).stdout)[1])
sys.argv = sys.argv[:1]
ANALYZER = Path(__file__).resolve().parents[1] / "tools/analyze_el0.py"
IR = '''
target datalayout = "e-p:64:64-i64:64-n32:64-S128"
target triple = "aarch64-unknown-linux-gnu"
@shared = global i64 0
@percpu = thread_local global i64 0
@alias = alias i64 (i64), ptr @leaf
@immutable_callback = constant ptr @leaf
@mutable_callback = global ptr @leaf
@replaceable_callback = weak constant ptr @leaf
@externally_initialized_callback = externally_initialized constant ptr @leaf
@callback_table = constant [2 x ptr] [ptr @leaf, ptr @asm_leaf]
declare i64 @device()
declare i64 @llvm.readcyclecounter()
declare i32 @llvm.umax.i32(i32, i32)
define i32 @maximum(i32 %a, i32 %b) {
  %v = call i32 @llvm.umax.i32(i32 %a, i32 %b)
  ret i32 %v
}
declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64, i1)
declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)
define void @copy(ptr %out, ptr %in, i64 %size) {
  call void @llvm.memcpy.p0.p0.i64(ptr %out, ptr %in, i64 %size, i1 false)
  call void @llvm.memset.p0.i64(ptr %out, i8 0, i64 %size, i1 false)
  ret void
}
define void @volatile_copy(ptr %out, ptr %in) {
  call void @llvm.memcpy.p0.p0.i64(ptr %out, ptr %in, i64 8, i1 true)
  ret void
}
define i64 @leaf(i64 %value) {
  %r = add i64 %value, 7
  ret i64 %r
}
define i64 @pure(i64 %value) {
  %r = call i64 @leaf(i64 %value)
  ret i64 %r
}
define i64 @via_alias(i64 %value) {
  %r = call i64 @alias(i64 %value)
  ret i64 %r
}
define i64 @state(ptr %output) {
  %v = load i64, ptr @shared
  store i64 %v, ptr %output
  ret i64 %v
}
define ptr @global_address() {
  ret ptr @shared
}
define i64 @needs_device() {
  %v = call i64 @device()
  %r = call i64 @leaf(i64 %v)
  ret i64 %r
}
define i64 @asm_leaf() {
  %v = call i64 asm sideeffect "mrs $0, sctlr_el1", "=r"()
  ret i64 %v
}
define i64 @outer() {
  %v = call i64 @asm_leaf()
  %r = call i64 @leaf(i64 %v)
  ret i64 %r
}
define i64 @indirect(ptr %callback) {
  %v = call i64 %callback()
  ret i64 %v
}
define i64 @volatile_read(ptr %input) {
  %v = load volatile i64, ptr %input
  ret i64 %v
}
define i64 @atomic_read(ptr %input) {
  %v = load atomic i64, ptr %input monotonic, align 8
  ret i64 %v
}
define void @fenced() {
  fence seq_cst
  ret void
}
define i64 @tls() {
  %v = load i64, ptr @percpu
  ret i64 %v
}
define i64 @fixed_address() {
  %v = load i64, ptr inttoptr (i64 4096 to ptr)
  ret i64 %v
}
define i64 @converted(i64 %address) {
  %p = inttoptr i64 %address to ptr
  %v = load i64, ptr %p
  ret i64 %v
}
define i64 @address_space(ptr addrspace(1) %input) {
  %v = load i64, ptr addrspace(1) %input
  ret i64 %v
}
define i64 @counter() {
  %v = call i64 @llvm.readcyclecounter()
  ret i64 %v
}
define i64 @recursive(i64 %n) {
  %stop = icmp eq i64 %n, 0
  br i1 %stop, label %done, label %again
again:
  %next = sub i64 %n, 1
  %v = call i64 @recursive(i64 %next)
  ret i64 %v
done:
  ret i64 1
}
define i64 @osrec_unreviewed() {
  %v = call i64 @device()
  ret i64 %v
}
define i64 @dead_branch(i1 %choose) {
  br i1 %choose, label %a, label %b
a:
  %v = call i64 @device()
  ret i64 %v
b:
  ret i64 7
}
define i64 @selected_callback(i1 %choose, i64 %value) {
  %callback = select i1 %choose, ptr @leaf, ptr @pure
  %v = call i64 %callback(i64 %value)
  ret i64 %v
}
define i64 @partial_callback(i1 %choose, ptr %unknown, i64 %value) {
  %callback = select i1 %choose, ptr @leaf, ptr %unknown
  %v = call i64 %callback(i64 %value)
  ret i64 %v
}
define i64 @constant_callback(i64 %value) {
  %callback = load ptr, ptr @immutable_callback
  %v = call i64 %callback(i64 %value)
  ret i64 %v
}
define i64 @registered_callback(i64 %value) {
  %callback = load ptr, ptr @mutable_callback
  %v = call i64 %callback(i64 %value)
  ret i64 %v
}
define i64 @replaceable(i64 %value) {
  %callback = load ptr, ptr @replaceable_callback
  %v = call i64 %callback(i64 %value)
  ret i64 %v
}
define i64 @externally_initialized(i64 %value) {
  %callback = load ptr, ptr @externally_initialized_callback
  %v = call i64 %callback(i64 %value)
  ret i64 %v
}
define i64 @constant_table_callback() {
  %address = getelementptr [2 x ptr], ptr @callback_table, i64 0, i64 1
  %callback = load ptr, ptr %address
  %v = call i64 %callback()
  ret i64 %v
}
define i64 @stack_callback(i64 %value) {
  %slot = alloca ptr
  store ptr @leaf, ptr %slot
  %callback = load ptr, ptr %slot
  %v = call i64 %callback(i64 %value)
  ret i64 %v
}
define i64 @phi_callback(i1 %choose) {
  br i1 %choose, label %a, label %b
a:
  br label %join
b:
  br label %join
join:
  %callback = phi ptr [@asm_leaf, %a], [@device, %b]
  %v = call i64 %callback()
  ret i64 %v
}
define i64 @dead_private_work(i64 %input) {
  %unused = alloca i64
  %garbage = mul i64 %input, 99
  store i64 %garbage, ptr %unused
  %result = add i64 %input, 7
  ret i64 %result
}
define i64 @memory_slice(i64 %input) {
  %live = alloca i64
  %dead = alloca i64
  store i64 %input, ptr %live
  store i64 91, ptr %dead
  %result = load i64, ptr %live
  ret i64 %result
}
define i64 @partial_memory_slice() {
  %slot = alloca i64
  store i64 18, ptr %slot
  store i32 7, ptr %slot
  %result = load i64, ptr %slot
  ret i64 %result
}
define i64 @branched_memory_slice(i1 %choose) {
  %slot = alloca i64
  br i1 %choose, label %a, label %b
a:
  store i64 11, ptr %slot
  br label %join
b:
  store i64 12, ptr %slot
  br label %join
join:
  %result = load i64, ptr %slot
  ret i64 %result
}
define i64 @unused_external_effect(ptr %output) {
  store i64 42, ptr %output
  %unused = call i64 @device()
  %other_unused = call i64 asm sideeffect "mrs $0, sctlr_el1", "=r"()
  ret i64 7
}
declare void @read_private(ptr captures(none))
define i64 @call_reads_private() {
  %slot = alloca i64
  store i64 99, ptr %slot
  call void @read_private(ptr %slot)
  ret i64 7
}
define i64 @call_cannot_read_private() {
  %slot = alloca i64
  store i64 99, ptr %slot
  %result = call i64 @device()
  ret i64 %result
}
define i64 @dynamic_table_callback(i64 %index) {
  %address = getelementptr [2 x ptr], ptr @callback_table, i64 0, i64 %index
  %callback = load ptr, ptr %address
  %v = call i64 %callback()
  ret i64 %v
}
define i64 @volatile_callback(i64 %value) {
  %callback = load volatile ptr, ptr @immutable_callback
  %v = call i64 %callback(i64 %value)
  ret i64 %v
}
define i64 @cyclic_callback(i1 %again) {
entry:
  br label %loop
loop:
  %callback = phi ptr [@device, %entry], [%callback, %loop]
  %v = call i64 %callback()
  br i1 %again, label %loop, label %done
done:
  ret i64 %v
}
'''

if LLVM_MAJOR == 16:
    IR = IR.replace("captures(none)", "nocapture")


class El0Tests(unittest.TestCase):
    def invoke(self, root, boundaries=None, ir=IR, success=True, slice_return=False):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.ll"
            source.write_text(ir)
            command = [sys.executable, str(ANALYZER), str(source), "--root", root,
                       "--opt", OPT, "--plugin", PLUGIN]
            if slice_return:
                command += ["--slice-return"]
            if boundaries is not None:
                boundary_file = Path(directory) / "boundaries.json"
                boundary_file.write_text(json.dumps({"format": "osrec-el0-boundaries-v1",
                                                       "boundaries": boundaries}))
                command += ["--boundaries", str(boundary_file)]
            result = subprocess.run(command, capture_output=True, text=True)
            if not success:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("rejected", result.stderr)
                return
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)

    def boundary(self, name):
        return {name: {"reason": "external scenario input", "implementation": "proposed model"}}

    def test_computation_closure_and_alias(self):
        for root in ("pure", "via_alias"):
            report = self.invoke(root)
            selected = report["selected_slice"]
            self.assertEqual(selected["classification"], "computation_candidate")
            self.assertEqual(selected["included_functions"], sorted([root, "leaf"]))
            self.assertEqual(selected["call_paths"]["leaf"], [root, "leaf"])
            self.assertFalse(report["native_execution_verified"])
            self.assertFalse(report["replay_equivalence_verified"])
            self.assertFalse(report["asynchronous_roots_included"])

    def test_memory_contracts(self):
        selected = self.invoke("state")["selected_slice"]
        self.assertEqual(selected["classification"], "candidate_with_state")
        memory = [r for r in selected["state_requirements"] if r["kind"] == "memory_contract"]
        self.assertEqual([m["origin"] for m in memory], ["global", "argument"])
        self.assertEqual(memory[0]["global"], "shared")
        self.assertTrue(memory[1]["write"])
        selected = self.invoke("global_address")["selected_slice"]
        self.assertEqual(selected["classification"], "candidate_with_state")
        self.assertEqual(selected["state_requirements"][0]["kind"], "global_binding")
        self.assertEqual(selected["state_requirements"][0]["global"], "shared")

    def test_dependency_path_and_model_proposal(self):
        report = self.invoke("needs_device")
        selected = report["selected_slice"]
        self.assertEqual(selected["classification"], "requires_review")
        self.assertEqual(selected["blockers"][0]["call_path"], ["needs_device", "device"])
        self.assertEqual(next(c for c in report["candidate_slices"] if c["root"] == "leaf")
                         ["classification"], "computation_candidate")
        report = self.invoke("needs_device", self.boundary("device"))
        self.assertEqual(report["selected_slice"]["classification"], "candidate_with_models")
        self.assertEqual(report["selected_slice"]["blockers"], [])
        self.assertEqual(len(report["boundary_manifest_sha256"]), 64)
        self.assertFalse(report["replay_equivalence_verified"])

    def test_cut_defined_privileged_dependency(self):
        selected = self.invoke("outer")["selected_slice"]
        self.assertEqual(selected["blockers"][0]["call_path"], ["outer", "asm_leaf"])
        selected = self.invoke("outer", self.boundary("asm_leaf"))["selected_slice"]
        self.assertNotIn("asm_leaf", selected["included_functions"])
        self.assertEqual(selected["classification"], "candidate_with_models")
        self.assertEqual(selected["model_boundaries"][0]["callee"], "asm_leaf")

    def test_opaque_and_environment_operations(self):
        cases = {"asm_leaf": "inline_assembly", "indirect": "indirect_call",
                 "volatile_read": "volatile_access", "atomic_read": "atomic_ordering",
                 "fenced": "atomic_ordering", "tls": "thread_local_state",
                 "fixed_address": "integer_address", "converted": "integer_address",
                 "address_space": "address_space", "counter": "unmodeled_dependency"}
        for root, reason in cases.items():
            with self.subTest(root=root):
                selected = self.invoke(root)["selected_slice"]
                self.assertEqual(selected["classification"], "requires_review")
                self.assertIn(reason, [b["kind"] for b in selected["blockers"]])

    def test_recursion_without_unrolling(self):
        selected = self.invoke("recursive")["selected_slice"]
        self.assertEqual(selected["included_functions"], ["recursive"])
        self.assertEqual(selected["recursive_edges"], [{"caller": "recursive", "callee": "recursive"}])
        self.assertIn("recursion_bound", [r["kind"] for r in selected["state_requirements"]])

    def test_memory_intrinsics_and_ordering_domain(self):
        selected = self.invoke("copy")["selected_slice"]
        self.assertEqual(selected["classification"], "candidate_with_state")
        self.assertEqual(len([r for r in selected["state_requirements"]
                             if r["kind"] == "memory_contract"]), 3)
        selected = self.invoke("volatile_copy")["selected_slice"]
        self.assertEqual(selected["classification"], "requires_review")
        self.assertEqual(len(selected["review_domains"]["environment_state_review"]), 2)
        selected = self.invoke("atomic_read")["selected_slice"]
        self.assertEqual(len(selected["review_domains"]["ordering_review"]), 1)
        self.assertEqual(selected["review_domains"]["architecture_or_address_review"], [])

    def test_module_assembly_blocks_even_computation(self):
        report = self.invoke("pure", ir=IR + '\nmodule asm "nop"\n')
        self.assertEqual(report["selected_slice"]["classification"], "requires_review")
        self.assertTrue(all(c["classification"] == "requires_review" for c in report["candidate_slices"]))

    def test_does_not_hide_recorder_prefix_or_paths(self):
        for root in ("osrec_unreviewed", "dead_branch"):
            self.assertEqual(self.invoke(root)["selected_slice"]["classification"], "requires_review")

    def test_invalid_inputs(self):
        for root in ("missing", "device"):
            self.invoke(root, success=False)
        for name in ("missing", "pure", "llvm.readcyclecounter"):
            self.invoke("pure", self.boundary(name), success=False)
        self.invoke("pure", {"device": {"reason": "incomplete"}}, success=False)

    def test_unused_boundary_and_identity(self):
        report = self.invoke("pure", self.boundary("device"))
        self.assertEqual(report["unused_boundaries"], ["device"])
        self.assertEqual(len(report["input_sha256"]), 64)
        self.assertEqual(report["target"], "aarch64-unknown-linux-gnu")
        self.assertEqual(report["llvm_version"].split(".")[0], str(LLVM_MAJOR))

    def test_complete_callback_sets(self):
        for root, targets in {"selected_callback": ["leaf", "pure"],
                              "constant_callback": ["leaf"],
                              "stack_callback": ["leaf"]}.items():
            with self.subTest(root=root):
                selected = self.invoke(root)["selected_slice"]
                self.assertEqual(selected["blockers"], [])
                callback = selected["callback_sites"][0]
                self.assertTrue(callback["targets_complete"])
                self.assertEqual([target["callee"] for target in callback["targets"]], targets)
                self.assertTrue(set(targets) <= set(selected["included_functions"]))

    def test_incomplete_callbacks_never_become_closed(self):
        for root in ("partial_callback", "registered_callback", "replaceable", "externally_initialized",
                     "dynamic_table_callback", "volatile_callback", "cyclic_callback"):
            with self.subTest(root=root):
                selected = self.invoke(root)["selected_slice"]
                self.assertEqual(selected["classification"], "requires_review")
                self.assertFalse(selected["callback_sites"][0]["targets_complete"])
        selected = self.invoke("partial_callback")["selected_slice"]
        self.assertIn("leaf", selected["included_functions"])

    def test_callback_targets_are_analyzed_and_can_have_models(self):
        selected = self.invoke("constant_table_callback")["selected_slice"]
        self.assertTrue(selected["callback_sites"][0]["targets_complete"])
        self.assertIn("asm_leaf", selected["included_functions"])
        self.assertEqual(selected["classification"], "requires_review")
        selected = self.invoke("phi_callback")["selected_slice"]
        self.assertTrue(selected["callback_sites"][0]["targets_complete"])
        self.assertEqual(selected["classification"], "requires_review")
        boundaries = dict(self.boundary("asm_leaf"), **self.boundary("device"))
        selected = self.invoke("phi_callback", boundaries)["selected_slice"]
        self.assertEqual(selected["classification"], "candidate_with_models")
        self.assertEqual(len(selected["model_boundaries"]), 2)

    def test_instruction_slice_excludes_dead_private_work(self):
        sliced = self.invoke("dead_private_work", slice_return=True)["instruction_slice"]
        self.assertEqual(sliced["total_instructions"], 5)
        self.assertEqual(sliced["retained_instructions"], 2)
        self.assertEqual([r["opcode"] for r in sliced["kept"]], ["add", "ret"])
        self.assertEqual([r["opcode"] for r in sliced["omitted_candidates"]], ["alloca", "mul", "store"])
        self.assertEqual(sliced["candidate_closure"]["classification"], "computation_candidate")
        self.assertFalse(sliced["extraction_applied"])
        self.assertFalse(sliced["equivalence_verified"])

    def test_memory_slice_handles_aliases_partial_stores_and_merges(self):
        sliced = self.invoke("memory_slice", slice_return=True)["instruction_slice"]
        self.assertEqual([r["instruction"] for r in sliced["omitted_candidates"]], [2, 4])
        load = next(r for r in sliced["kept"] if r["opcode"] == "load")
        self.assertIn(3, load["memory_dependencies"])
        self.assertNotIn(4, load["memory_dependencies"])
        sliced = self.invoke("partial_memory_slice", slice_return=True)["instruction_slice"]
        load = next(r for r in sliced["kept"] if r["opcode"] == "load")
        self.assertEqual(load["memory_dependencies"], [2, 3])
        sliced = self.invoke("branched_memory_slice", slice_return=True)["instruction_slice"]
        load = next(r for r in sliced["kept"] if r["opcode"] == "load")
        self.assertEqual(load["memory_dependencies"], [3, 5])
        self.assertEqual(sliced["retained_instructions"], sliced["total_instructions"])

    def test_slice_retains_unselected_effects_and_ordering(self):
        for root in ("unused_external_effect", "atomic_read", "volatile_read", "fenced"):
            with self.subTest(root=root):
                sliced = self.invoke(root, slice_return=True)["instruction_slice"]
                self.assertEqual(sliced["retained_instructions"], sliced["total_instructions"])
                self.assertEqual(sliced["candidate_closure"]["classification"], "requires_review")
        sliced = self.invoke("call_reads_private", slice_return=True)["instruction_slice"]
        self.assertEqual(sliced["retained_instructions"], 4)
        call = next(r for r in sliced["kept"] if r["opcode"] == "call")
        self.assertIn(2, call["memory_dependencies"])
        sliced = self.invoke("call_cannot_read_private", slice_return=True)["instruction_slice"]
        self.assertEqual(sliced["retained_instructions"], 2)

    def test_slice_retains_callback_selection_and_all_control_flow(self):
        sliced = self.invoke("selected_callback", slice_return=True)["instruction_slice"]
        self.assertEqual([r["opcode"] for r in sliced["kept"]], ["select", "call", "ret"])
        sliced = self.invoke("recursive", slice_return=True)["instruction_slice"]
        self.assertEqual(sliced["retained_instructions"], sliced["total_instructions"])
        report = self.invoke("pure", ir=IR + '\nmodule asm "nop"\n', slice_return=True)
        self.assertEqual(report["instruction_slice"]["candidate_closure"]["classification"], "requires_review")

    def test_compiled_c_callback_fixture(self):
        compiler = Path(OPT).resolve().parent / "clang"
        source = ANALYZER.parent.parent / "examples/el0_callback_slice.c"
        with tempfile.TemporaryDirectory() as directory:
            bitcode = Path(directory) / "callback.bc"
            subprocess.run([str(compiler), "-O0", "-g", "-fno-builtin", "-emit-llvm", "-c",
                            str(source), "-o", str(bitcode)], check=True, capture_output=True)
            result = subprocess.run([sys.executable, str(ANALYZER), str(bitcode),
                                     "--root", "callback_scenario", "--slice-return",
                                     "--opt", OPT, "--plugin", PLUGIN], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            callback = report["selected_slice"]["callback_sites"][0]
            self.assertTrue(callback["targets_complete"])
            self.assertEqual([t["callee"] for t in callback["targets"]], ["add_seven", "triple"])
            sliced = report["instruction_slice"]
            self.assertLess(sliced["retained_instructions"], sliced["total_instructions"])
            self.assertIn("mul", [r["opcode"] for r in sliced["omitted_candidates"]])
            harness = Path(directory) / "main.c"
            harness.write_text('''
unsigned callback_scenario(unsigned, unsigned);
int main(void) {
    for (unsigned input = 0; input < 32; ++input)
        for (unsigned choose = 0; choose < 3; ++choose)
            if (callback_scenario(input, choose) != (choose ? input + 7 : input * 3))
                return 1;
    return 0;
}
''')
            executable = Path(directory) / "callback"
            subprocess.run([str(compiler), "-O0", str(source), str(harness), "-o", str(executable)],
                           check=True, capture_output=True)
            subprocess.run([str(executable)], check=True, capture_output=True)

    def test_integer_minmax_is_portable_but_clock_is_not(self):
        selected = self.invoke("maximum")["selected_slice"]
        self.assertEqual(selected["classification"], "computation_candidate")
        self.assertEqual(selected["call_edges"][0]["kind"], "portable_intrinsic")
        self.assertEqual(self.invoke("counter")["selected_slice"]["classification"], "requires_review")


if __name__ == "__main__":
    unittest.main()
