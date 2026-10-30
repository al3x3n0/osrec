#!/usr/bin/env python3
"""Use KLEE to refine a bounded LiteOS-A boundary-observation trace plan."""
import argparse
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import uuid

from klee_liteos import INTEGRATION, build, digest, ktest_objects, run

FIELDS = ["read.result", "errno.value", *[f"read.payload[{i}]" for i in range(4)]]


def field_names(mask):
    return [name for bit, name in enumerate(FIELDS) if mask & (1 << bit)]


def concrete_inputs(test, replay_check=False):
    objects = ktest_objects(test)
    expected = {"user_request", "environment_a"}
    if not replay_check:
        expected.add("environment_b")
    if set(objects) != expected or any(len(value) != 12 for value in objects.values()):
        raise ValueError("unexpected relational KTest objects")
    request = struct.unpack("<III", objects["user_request"])
    environments = [struct.unpack("<II4s", objects[name]) for name in
                    ("environment_a", "environment_a" if replay_check else "environment_b")]
    return {"request": list(request), "environments": [
        {"mode": mode, "success_limit": limit, "payload": payload.hex()}
        for mode, limit, payload in environments]}


def native_check(out, mask, inputs):
    argv = [out / "trace_native", mask, *inputs["request"]]
    for env in inputs["environments"]:
        argv.extend([env["mode"], env["success_limit"], env["payload"]])
    return json.loads(run(argv).stdout)


def prepare(args, out):
    common = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-fno-stack-protector",
              "-fno-builtin", "-DOSREC_NO_SCENARIO_MAIN", "-I", out, "-I", INTEGRATION]
    sources = [out / "kernel_sysread.c", INTEGRATION / "models.c",
               INTEGRATION / "user_program.c", INTEGRATION / "trace_analysis.c"]
    run([args.llvm_bin / "clang", *common, "-O0", *sources, "-o", out / "trace_native"])
    bitcode = ["-emit-llvm", "-c", "-g", "-O1", "-fno-vectorize", "-fno-slp-vectorize",
               "-DOSREC_KLEE", "-I", args.klee_include]
    for source, name in zip(sources[:3], ("analysis-kernel.bc", "analysis-models.bc", "application.bc")):
        run([args.llvm_bin / "clang", *common, *bitcode, source, "-o", out / name])
    return common, bitcode


def check_plan(args, out, compilation, mask, replay_check=False):
    tag = f"{'replay' if replay_check else 'relation'}-{mask}"
    print(f"Checking {tag}: {', '.join(field_names(mask))}", flush=True)
    common, bitcode = compilation
    harness, module = out / f"{tag}-harness.bc", out / f"{tag}.bc"
    definitions = [f"-DOSREC_TRACE_MASK={mask}"]
    if replay_check:
        definitions.append("-DOSREC_TRACE_REPLAY_CHECK")
    run([args.llvm_bin / "clang", *common, *bitcode, *definitions,
         INTEGRATION / "trace_analysis.c", "-o", harness])
    run([args.llvm_bin / "llvm-link", out / "analysis-kernel.bc", out / "analysis-models.bc",
         out / "application.bc", harness, "-o", module])
    symbols = {line.split()[-1].removeprefix("_") for line in
               run([args.llvm_bin / "llvm-nm", "--undefined-only", module]).stdout.splitlines() if line.strip()}
    if symbols - {"klee_make_symbolic", "klee_assume", "klee_report_error"}:
        raise ValueError(f"unmodeled external calls: {symbols}")
    directory = out / f"klee-{tag}-{uuid.uuid4().hex[:8]}"
    result = subprocess.run([str(args.klee), "--solver-backend=z3", "--external-calls=none",
                             "--use-forked-solver=false",
                             "--exit-on-error",
                             f"--max-time={args.max_time}s", "--max-memory=512",
                             f"--output-dir={directory}", str(module)],
                            capture_output=True, text=True, timeout=args.max_time + 20)
    log = out / f"{directory.name}.log"
    log.write_text(result.stdout + result.stderr)
    record = {"mask": mask, "fields": field_names(mask), "module": str(module),
              "module_sha256": digest(module.read_bytes()), "output": str(directory), "log": str(log)}
    errors = list(directory.glob("*.err"))
    if errors and not replay_check and all(path.name.endswith(".trace.err") for path in errors):
        error = errors[0]
        test = error.with_name(error.name.removesuffix(".trace.err") + ".ktest")
        inputs = concrete_inputs(test)
        native = native_check(out, mask, inputs)
        if not native["trace_equal"] or native["contract_equal"]:
            raise ValueError("KLEE counterexample did not reproduce natively")
        record.update(status="insufficient", witness={"test": str(test), "inputs": inputs, "native": native})
        print("  insufficient: native-confirmed trace collision", flush=True)
        return record
    completed = re.search(r"^KLEE: done: completed paths = (\d+)$", result.stderr, re.MULTILINE)
    partial = re.search(r"^KLEE: done: partially completed paths = (\d+)$", result.stderr, re.MULTILINE)
    if errors or result.returncode or not completed or not partial or int(partial.group(1)) or (
            "HaltTimer" in result.stderr):
        record.update(status="unknown", reason="error or incomplete exploration; inspect log")
        print("  unknown: retained observations cannot be certified", flush=True)
        return record
    tests = sorted(directory.glob("*.ktest"))
    if not tests:
        raise ValueError("KLEE generated no relational tests")
    for test in tests:
        native = native_check(out, mask, concrete_inputs(test, replay_check))
        collision = native["trace_equal"] and not native["contract_equal"]
        if collision or not native["replay_supported"] or not native["replay_equal"]:
            raise ValueError("accepted plan failed native relational/replay validation")
    record.update(status="sufficient" if not replay_check else "replay_verified",
                  completed_paths=int(completed.group(1)), partially_completed_paths=0,
                  native_replayed_tests=len(tests))
    print(f"  {record['status']}: {len(tests)} native-replayed tests, no partial paths", flush=True)
    return record


def analyze(args):
    out, seed, base = build(args)
    compilation = prepare(args, out)
    report = {"format": "osrec-bounded-trace-plan-v1", "status": "in_progress",
              "kernel": base["kernel"], "compiler": base["compiler"], "klee": base["klee"],
              "seed": seed, "runner_sha256": digest(Path(__file__).read_bytes()),
              "build_manifest_sha256": digest((out / "manifest.json").read_bytes()),
              "analysis_compilation": ["-O1", "-fno-vectorize", "-fno-slp-vectorize"],
              "solver": {"backend": "z3", "forked": False, "max_time_seconds": args.max_time,
                         "max_memory_mb": 512, "external_calls": "none"},
              "inputs": base["inputs"], "native_sha256": digest((out / "trace_native").read_bytes()),
              "checkpoint": {"request": "fd 0..4, count 0..9, null selector 0..1",
                             "user_memory": "8 bytes initialized to 0xa5",
                             "descriptor_mapping": "3 -> 17; all other descriptors invalid"},
              "varying_environment": {"mode": "success/EINTR/EIO", "success_limit": "0..4",
                                      "payload": "4 independent symbolic bytes"},
              "contract": ["user return", "user errno", "recognition flag", "all 8 user memory bytes",
                           "address/FD/read/errno boundary invocation counts"],
              "observation_encoding": "selected field presence is recorded; payload bytes present only when written",
              "candidate_fields": FIELDS, "checks": [], "eliminations": [],
              "scope": "SysRead and declared sequential dependency models; no scheduler, IRQs or SMP",
              "global_minimum_claimed": False}
    destination = out / "trace-plan.json"

    def save():
        destination.write_text(json.dumps(report, indent=2) + "\n")

    def check(mask, replay_check=False):
        record = check_plan(args, out, compilation, mask, replay_check)
        report["checks"].append(record)
        save()
        return record

    save()
    mask = (1 << len(FIELDS)) - 1
    baseline = check(mask)
    if baseline["status"] != "sufficient":
        report["status"] = "uncertified"
        save()
        raise ValueError("full candidate plan was not certified; see trace-plan.json")
    unknown = False
    retained = []
    for bit, name in enumerate(FIELDS):
        candidate = mask & ~(1 << bit)
        record = check(candidate)
        if record["status"] == "sufficient":
            report["eliminations"].append({"field": name, "from_mask": mask, "to_mask": candidate})
            mask = candidate
        else:
            retained.append((bit, name, record))
            unknown |= record["status"] == "unknown"
    replay_result = check(mask, replay_check=True)
    minimal_witnesses = []
    for bit, name, record in retained:
        if record["status"] != "insufficient":
            continue
        # Reconfirm against the final plan, even if later removals changed it.
        native = native_check(out, mask & ~(1 << bit), record["witness"]["inputs"])
        if not native["trace_equal"] or native["contract_equal"]:
            raise ValueError("minimality witness did not reproduce for final plan")
        minimal_witnesses.append({"required_field": name, "removed_mask": mask & ~(1 << bit),
                                 "inputs": record["witness"]["inputs"], "native": native})
    report.update(status="certified" if replay_result["status"] == "replay_verified" else "uncertified",
                  selected_mask=mask, selected_fields=field_names(mask),
                  inclusion_minimal=not unknown and len(minimal_witnesses) == len(field_names(mask)),
                  minimality_witnesses=minimal_witnesses)
    save()
    if report["status"] != "certified":
        raise ValueError("selected plan did not pass transcript-driven replay")
    print(json.dumps({"report": str(destination), "selected_fields": field_names(mask),
                      "inclusion_minimal": report["inclusion_minimal"]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--llvm-bin", required=True, type=Path)
    parser.add_argument("--klee-include", required=True, type=Path)
    parser.add_argument("--klee", default=shutil.which("klee") or "klee", type=Path)
    parser.add_argument("--seed", default=INTEGRATION / "sysread_seed.json", type=Path)
    parser.add_argument("--max-time", default=60, type=int)
    args = parser.parse_args()
    args.run = True
    if not 1 <= args.max_time <= 60:
        parser.error("--max-time must be between 1 and 60 seconds")
    try:
        analyze(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = (error.stderr or error.stdout) if isinstance(error, subprocess.CalledProcessError) else str(error)
        parser.exit(1, f"trace analysis failed: {detail}\n")


if __name__ == "__main__":
    main()
