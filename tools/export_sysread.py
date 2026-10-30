#!/usr/bin/env python3
"""Capture a modeled SysRead case and export one independently runnable binary."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from analyze_trace import field_names
from klee_liteos import INTEGRATION, ROOT, digest, run, slice_source

MODEL_FILES = ("scenario.h", "models.c", "user_program.c", "trace_analysis.c")
PROVENANCE = "synthetic model capture; not recorded from a running kernel"
CORE_END = "\n#ifdef OSREC_KLEE\nstatic void symbolic_environment"


def keys(value, names, label):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError(f"unsupported {label} fields")


def integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"unsupported {label}")
    return value


def hex_bytes(value, size, label):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{" + str(2 * size) + r"}", value):
        raise ValueError(f"invalid {label}")
    return bytes.fromhex(value)


def load_plan(path, kernel, clang):
    raw = path.read_bytes()
    plan = json.loads(raw)
    if not isinstance(plan, dict) or plan.get("format") != "osrec-bounded-trace-plan-v1" or plan.get("status") != "certified":
        raise ValueError("export requires a completed, certified trace plan")
    mask = plan.get("selected_mask")
    if type(mask) is not int or mask not in (62, 63) or plan.get("selected_fields") != field_names(mask):
        raise ValueError("unsupported trace projection")
    for status in ("sufficient", "replay_verified"):
        checks = [c for c in plan["checks"] if c.get("mask") == mask and c.get("status") == status]
        completed = [c for c in checks if c.get("partially_completed_paths") == 0 and
                     c.get("completed_paths", 0) > 0]
        if not completed:
            raise ValueError("plan lacks a completed sufficiency or reconstruction check")
        proof = completed[-1]
        if digest(Path(proof["module"]).read_bytes()) != proof.get("module_sha256"):
            raise ValueError("analyzed proof module changed")
    sources = {name: (INTEGRATION / name).read_bytes() for name in MODEL_FILES}
    for name in MODEL_FILES:
        source = INTEGRATION / name
        key = str(source.relative_to(ROOT))
        if digest(sources[name]) != plan["inputs"].get(key):
            raise ValueError(f"analyzed source changed: {name}; rerun trace analysis")
    generated, lock = slice_source(kernel)
    if plan.get("kernel") != lock:
        raise ValueError("plan and extracted kernel build disagree")
    directory = path.parent
    manifest_raw = (directory / "manifest.json").read_bytes()
    if digest(manifest_raw) != plan.get("build_manifest_sha256"):
        raise ValueError("analysis build manifest changed")
    manifest = json.loads(manifest_raw)
    if manifest["kernel"] != lock or manifest["seed"] != plan["seed"]:
        raise ValueError("analysis seed or kernel identity changed")
    for name in ("kernel_sysread.c", "seed_config.h"):
        artifact = (directory / name).read_bytes()
        if digest(artifact) != manifest["artifacts"].get(name):
            raise ValueError(f"analysis artifact changed: {name}")
        sources[name] = artifact
    if sources["kernel_sysread.c"].decode() != generated:
        raise ValueError("extracted body differs from the analyzed kernel source")
    version = run([clang, "--version"]).stdout.strip()
    # Symlink resolution changes InstalledDir without changing this compiler.
    identity = lambda text: [line for line in text.splitlines() if not line.startswith("InstalledDir:")]
    if identity(version) != identity(plan.get("compiler", "")):
        raise ValueError("export compiler must match the analyzed compiler")
    # Packaging extracts only the shared execution/capture/reconstruction code.
    source = sources["trace_analysis.c"].decode()
    if source.count(CORE_END) != 1:
        raise ValueError("unsupported replay-code extraction boundary")
    core = source[:source.index(CORE_END)] + "\n"
    return plan, digest(raw), generated, core, sources


def validate_capture(capture, plan, plan_hash):
    keys(capture, ("format", "provenance", "plan_sha256", "kernel", "entry", "trace", "expected"), "capture")
    if capture.get("format") != "osrec-embedded-sysread-v1" or capture.get("provenance") != PROVENANCE:
        raise ValueError("unsupported capture format or provenance")
    if capture.get("plan_sha256") != plan_hash or capture.get("kernel") != plan["kernel"]:
        raise ValueError("capture and analyzed build identity disagree")
    entry = capture["entry"]
    keys(entry, ("fd", "count", "null_buffer", "memory"), "checkpoint")
    integer(entry["fd"], 0, 4, "descriptor")
    integer(entry["count"], 0, 9, "request size")
    integer(entry["null_buffer"], 0, 1, "buffer selector")
    if hex_bytes(entry["memory"], 8, "checkpoint memory") != bytes([0xa5] * 8):
        raise ValueError("unsupported initial memory checkpoint")
    trace = capture["trace"]
    keys(trace, ("mask", "read_present", "read_result", "errno_present", "errno", "payload_present", "payload"), "trace")
    if trace["mask"] != plan["selected_mask"]:
        raise ValueError("capture uses a different trace projection")
    integer(trace["read_present"], 0, 1, "read presence")
    integer(trace["read_result"], -1, 4, "backend return")
    integer(trace["errno_present"], 0, 1, "errno presence")
    integer(trace["errno"], 0, 14, "errno")
    integer(trace["payload_present"], 0, 15, "payload presence")
    payload = hex_bytes(trace["payload"], 4, "trace payload")
    if (not trace["read_present"] and trace["read_result"]) or (
            trace["mask"] == 62 and trace["read_present"]):
        raise ValueError("omitted read observation contains information")
    if not trace["errno_present"] and trace["errno"]:
        raise ValueError("absent errno observation contains information")
    if any(payload[i] for i in range(4) if not trace["payload_present"] & (1 << i)):
        raise ValueError("unwritten payload bytes must be erased")
    expected = capture["expected"]
    keys(expected, ("return", "errno", "recognized", "memory", "boundary_counts"), "expectation")
    integer(expected["return"], -1, 4, "expected return")
    integer(expected["errno"], 0, 14, "expected errno")
    integer(expected["recognized"], 0, 1, "expected recognition flag")
    hex_bytes(expected["memory"], 8, "expected memory")
    if not isinstance(expected["boundary_counts"], list) or len(expected["boundary_counts"]) != 4:
        raise ValueError("unsupported boundary count layout")
    for value in expected["boundary_counts"]:
        integer(value, 0, 1, "boundary count")


def capture_case(case_path, plan_path, plan, plan_hash):
    case = json.loads(case_path.read_bytes())
    keys(case, ("format", "provenance", "request", "environment"), "case")
    if case.get("format") != "osrec-sysread-case-v1" or case.get("provenance") != PROVENANCE:
        raise ValueError("only explicitly synthetic model cases are currently supported")
    request, env = case["request"], case["environment"]
    keys(request, ("fd", "count", "null_buffer"), "request")
    keys(env, ("mode", "success_limit", "payload"), "environment")
    fields = [integer(request["fd"], 0, 4, "descriptor"),
              integer(request["count"], 0, 9, "request size"),
              integer(request["null_buffer"], 0, 1, "buffer selector")]
    environment = [integer(env["mode"], 0, 2, "environment mode"),
                   integer(env["success_limit"], 0, 4, "successful-read limit"),
                   hex_bytes(env["payload"], 4, "device payload").hex()]
    native = plan_path.parent / "trace_native"
    if digest(native.read_bytes()) != plan.get("native_sha256"):
        raise ValueError("analyzed native capture helper changed")
    output = json.loads(run([native, plan["selected_mask"], *fields, *environment, *environment]).stdout)
    if not all(output.get(name) is True for name in (
            "trace_equal", "contract_equal", "replay_supported", "replay_equal")):
        raise ValueError("model capture did not pass independent reconstruction")
    captured = {"format": "osrec-embedded-sysread-v1", "provenance": PROVENANCE,
                "kernel": plan["kernel"], "plan_sha256": plan_hash,
                "entry": {"fd": fields[0], "count": fields[1], "null_buffer": fields[2],
                          "memory": "a5" * 8}, "trace": output["left_trace"], "expected": output["left"]}
    validate_capture(captured, plan, plan_hash)
    return captured


def initializer(data):
    return "{" + ", ".join(str(byte) for byte in data) + "}"


def artifact_source(captured, metadata):
    entry, trace, expected = captured["entry"], captured["trace"], captured["expected"]
    counts = expected["boundary_counts"]
    description = json.dumps(json.dumps(metadata, separators=(",", ":"), ensure_ascii=True))
    return f'''/* Scenario inputs and expectations are embedded; no input file is read. */
#include "replay_core.h"
#include <string.h>

static const struct user_request checkpoint = {{{entry["fd"]}, {entry["count"]}, {entry["null_buffer"]}}};
static const struct observation_trace transcript = {{
    .mask = {trace["mask"]}, .read_present = {trace["read_present"]},
    .read_result = {trace["read_result"]}, .errno_present = {trace["errno_present"]},
    .error = {trace["errno"]}, .payload_present = {trace["payload_present"]},
    .payload = {initializer(bytes.fromhex(trace["payload"]))}
}};
/* Expectations are consulted only after the original code has executed. */
static const struct snapshot expected = {{
    .out = {{{expected["return"]}, {expected["errno"]}, {expected["recognized"]}}},
    .memory = {initializer(bytes.fromhex(expected["memory"]))},
    .range_calls = {counts[0]}, .fd_calls = {counts[1]},
    .read_calls = {counts[2]}, .errno_calls = {counts[3]}
}};
static const char description[] = {description};

int main(int argc, char **argv)
{{
    if (argc == 2 && strcmp(argv[1], "--describe") == 0) {{
        puts(description);
        return 0;
    }}
    if (argc != 1) {{
        fputs("usage: scenario [--describe]\\n", stderr);
        return 2;
    }}
    struct snapshot actual;
    /* replay receives no expected outputs or original environment state. */
    if (!replay(checkpoint, transcript, &actual)) {{
        fputs("scenario reconstruction failed\\n", stderr);
        return 1;
    }}
    if (!same_contract(actual, expected)) {{
        fputs("scenario execution diverged\\n", stderr);
        return 1;
    }}
    printf("scenario verified: return=%d errno=%u recognized=%u\\n",
           actual.out.result, actual.out.error, actual.out.recognized);
    return 0;
}}
'''


def dependencies(binary):
    if sys.platform == "darwin":
        listing = run(["/usr/bin/otool", "-L", binary]).stdout
        paths = [line.strip().split(" (", 1)[0] for line in listing.splitlines()[1:] if line.strip()]
        if any(not path.startswith(("/usr/lib/", "/System/Library/")) for path in paths):
            raise ValueError("artifact depends on a library outside the declared system platform")
        return paths
    if sys.platform.startswith("linux") and shutil.which("readelf"):
        listing = run(["readelf", "-d", binary]).stdout
        names = re.findall(r"\(NEEDED\).*\[(.*?)\]", listing)
        if any(name != "libc.so.6" for name in names):
            raise ValueError("artifact has an unsupported non-platform library dependency")
        if "RPATH" in listing or "RUNPATH" in listing:
            raise ValueError("artifact has an external library search path")
        return names
    raise ValueError("dependency audit currently supports macOS and Linux/readelf")


def export(args):
    plan_path, kernel, compiler, destination = args.plan.resolve(), args.kernel_root.resolve(), args.compiler.resolve(), args.out.resolve()
    protected = {plan_path, compiler, *(path.resolve() for path in INTEGRATION.iterdir())}
    protected.update(path.resolve() for path in (args.case, args.capture) if path is not None)
    if destination in protected or destination.is_relative_to(kernel):
        raise ValueError("output must not overwrite construction inputs or the kernel checkout")
    plan, plan_hash, generated, core, sources = load_plan(plan_path, kernel, compiler)
    captured = (capture_case(args.case, plan_path, plan, plan_hash) if args.case else
                json.loads(args.capture.read_bytes()))
    validate_capture(captured, plan, plan_hash)
    target = run([compiler, "-dumpmachine"]).stdout.strip()
    metadata = {"format": "osrec-standalone-sysread-v1", "provenance": PROVENANCE,
                "kernel": plan["kernel"], "plan_sha256": plan_hash,
                "kernel_license": generated[:generated.index("*/") + 2],
                "capture_sha256": digest(json.dumps(captured, sort_keys=True).encode()),
                "model_sources": {name: plan["inputs"][str((INTEGRATION / name).relative_to(ROOT))]
                                  for name in MODEL_FILES},
                "replay_core_sha256": digest(core.encode()),
                "selected_fields": field_names(plan["selected_mask"]),
                "entry": captured["entry"], "trace": captured["trace"], "expected": captured["expected"],
                "platform": {"compiler_target": target, "requires": "host OS system runtime",
                             "syscall_scalars": "32-bit", "addresses": "host-normalized"},
                "executed_kernel_code": ["SysRead"],
                "modeled_dependencies": ["user syscall entry/errno wrapper", "user address range",
                                         "descriptor mapping", "VFS/device read"],
                "scheduler_irq_execution": False}
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="osrec-export-") as folder:
        stage = Path(folder)
        (stage / "kernel_sysread.c").write_text(generated)
        (stage / "seed_config.h").write_bytes(sources["seed_config.h"])
        for name in ("scenario.h", "models.c", "user_program.c"):
            (stage / name).write_bytes(sources[name])
        (stage / "replay_core.h").write_text(core)
        (stage / "scenario.c").write_text(artifact_source(captured, metadata))
        binary = stage / "scenario"
        run([compiler, "-std=c11", "-O1", "-fno-vectorize", "-fno-slp-vectorize",
             "-Wall", "-Wextra", "-Werror", "-fno-builtin", "-fno-stack-protector",
             "-DOSREC_NO_SCENARIO_MAIN", "kernel_sysread.c", "models.c", "user_program.c",
             "scenario.c", "-o", binary], cwd=stage)
        libraries = dependencies(binary)
        # Delete all generated construction sources before the acceptance run.
        for source in stage.iterdir():
            if source != binary:
                source.unlink()
        with tempfile.TemporaryDirectory(prefix="osrec-isolated-") as isolated:
            isolated_dir = Path(isolated)
            isolated_binary = isolated_dir / "scenario"
            shutil.copy2(binary, isolated_binary)
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
            verified = run([isolated_binary], cwd=isolated_dir, env=env).stdout.strip()
            described = json.loads(run([isolated_binary, "--describe"], cwd=isolated_dir, env=env).stdout)
            if described != metadata:
                raise ValueError("embedded description differs from the exported scenario")
            binary_hash = digest(isolated_binary.read_bytes())
            with tempfile.NamedTemporaryFile(prefix=".osrec-", dir=destination.parent, delete=False) as pending:
                pending_path = Path(pending.name)
            try:
                shutil.copy2(isolated_binary, pending_path)
                os.replace(pending_path, destination)
            finally:
                pending_path.unlink(missing_ok=True)
    manifest = {"artifact": str(destination), "artifact_sha256": binary_hash,
                "artifact_bytes": destination.stat().st_size, "metadata": metadata,
                "system_libraries": libraries, "isolated_execution": verified,
                "exporter_sha256": digest(Path(__file__).read_bytes()),
                "compiler": run([compiler, "--version"]).stdout.strip()}
    Path(str(destination) + ".capture.json").write_text(json.dumps(captured, indent=2) + "\n")
    Path(str(destination) + ".manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"executable": str(destination), "bytes": manifest["artifact_bytes"],
                      "verification": verified, "system_libraries": libraries}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--kernel-root", required=True, type=Path)
    parser.add_argument("--compiler", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--case", type=Path, help="capture this explicitly synthetic model case")
    inputs.add_argument("--capture", type=Path, help="package an existing embedded-scenario capture")
    args = parser.parse_args()
    try:
        export(args)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        detail = (error.stderr or error.stdout) if isinstance(error, subprocess.CalledProcessError) else str(error)
        parser.exit(1, f"standalone export failed: {detail}\n")


if __name__ == "__main__":
    main()
