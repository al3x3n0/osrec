#!/usr/bin/env python3
"""Extract, symbolically compare and package a closed scalar EL0 scenario."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

from analyze_el0 import analyze
from export_sysread import dependencies
from klee_liteos import ktest_objects


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(command, **kwargs):
    return subprocess.run([str(item) for item in command], text=True, capture_output=True,
                          check=True, timeout=60, **kwargs)


def inspect(module, root, args):
    return analyze(SimpleNamespace(module=module, root=root, slice_return=True,
                                   opt=args.llvm_bin / "opt", plugin=args.plugin, boundaries=None))


def supported(report):
    closure = report["selected_slice"]
    if closure["blockers"] or closure["model_boundaries"] or closure["recursive_edges"]:
        raise ValueError("publication requires a closed, unblocked, nonrecursive code closure")
    root = report["function_contracts"][closure["root"]]
    if (root["return_type"] != "i32" or root["variadic"] or root["calling_convention"] != 0
            or len(root["argument_types"]) > 6
            or any(argument != "i32" for argument in root["argument_types"])):
        raise ValueError("initial export ABI requires an i32 return and up to six i32 arguments")
    for name, contract in report["function_contracts"].items():
        if contract["verification_obstacles"]:
            detail = contract["verification_obstacles"][0]["detail"]
            raise ValueError(f"{name}: unsupported verification precondition: {detail}")
    for requirement in closure["state_requirements"]:
        kind = requirement["kind"]
        if kind == "global_binding" or kind == "pointer_arguments":
            raise ValueError("global state or pointer interfaces need an explicit replay contract")
        if kind == "memory_contract" and requirement["origin"] != "stack":
            raise ValueError("initial export supports private stack memory only")
    return len(root["argument_types"])


def shape(count):
    return ", ".join(f"uint32_t p{i}" for i in range(count)) or "void"


def pair_source(count):
    call = ", ".join(f"inputs[{i}]" for i in range(count))
    symbolic = (f'klee_make_symbolic(inputs, {count * 4}, "inputs");' if count else "")
    return f'''#include <stdint.h>
uint32_t osrec_reference_entry({shape(count)});
uint32_t osrec_extracted_entry({shape(count)});
#ifdef OSREC_PROOF_KLEE
#include <klee/klee.h>
int main(void) {{
    uint32_t inputs[{max(count, 1)}] = {{0}};
    {symbolic}
    uint32_t original = osrec_reference_entry({call});
    uint32_t extracted = osrec_extracted_entry({call});
    if (original != extracted)
        klee_report_error(__FILE__, __LINE__, "slice result differs", "equivalence.err");
    return 0;
}}
#else
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {{
    uint32_t inputs[{max(count, 1)}] = {{0}};
    if (argc != {count + 1}) return 2;
    for (unsigned i = 0; i < {count}U; ++i) {{
        char *end;
        if (!argv[i + 1][0] || argv[i + 1][0] == '-') return 2;
        unsigned long long value = strtoull(argv[i + 1], &end, 10);
        if (*end || value > UINT32_MAX) return 2;
        inputs[i] = (uint32_t)value;
    }}
    uint32_t original = osrec_reference_entry({call});
    uint32_t extracted = osrec_extracted_entry({call});
    if (original != extracted) return 1;
    printf("%u\\n", original);
    return 0;
}}
#endif
'''


def proof(args, stage, reference, extracted, count):
    compiler = args.llvm_bin / "clang"
    harness = stage / "equivalence.c"
    harness.write_text(pair_source(count))
    harness_bc, module = stage / "harness.bc", stage / "equivalence.bc"
    run([compiler, "-O0", "-g", "-fno-builtin", "-DOSREC_PROOF_KLEE", "-I", args.klee_include,
         "-emit-llvm", "-c", harness, "-o", harness_bc])
    run([args.llvm_bin / "llvm-link", reference, extracted, harness_bc, "-o", module])
    undefined = run([args.llvm_bin / "llvm-nm", "--undefined-only", module]).stdout.splitlines()
    symbols = [line.split()[-1].removeprefix("_") for line in undefined if line.strip()]
    intrinsic_prefixes = ("llvm.dbg.", "llvm.lifetime.", "llvm.memcpy.", "llvm.memmove.", "llvm.memset.")
    intrinsic_prefixes += ("llvm.umax.", "llvm.umin.", "llvm.smax.", "llvm.smin.")
    unknown = [symbol for symbol in symbols if symbol not in {"klee_make_symbolic", "klee_report_error"}
               and not symbol.startswith(intrinsic_prefixes)]
    if unknown:
        raise ValueError(f"proof module has unmodeled external dependencies: {unknown}")
    directory = stage / "klee-proof"
    result = subprocess.run([str(args.klee), "--solver-backend=z3", "--use-forked-solver=false",
                             "--external-calls=none", "--exit-on-error", "--max-time=40s",
                             "--max-memory=512", f"--output-dir={directory}", str(module)],
                            text=True, capture_output=True, timeout=60)
    log = result.stdout + result.stderr
    (stage / "klee.log").write_text(log)
    completed = re.search(r"^KLEE: done: completed paths = (\d+)$", log, re.MULTILINE)
    partial = re.search(r"^KLEE: done: partially completed paths = (\d+)$", log, re.MULTILINE)
    tests = re.search(r"^KLEE: done: generated tests = (\d+)$", log, re.MULTILINE)
    if (result.returncode or not completed or not partial or not tests or int(completed[1]) == 0
            or int(partial[1]) != 0 or list(directory.glob("*.err"))):
        raise ValueError("symbolic equivalence did not complete without errors and partial paths")
    native = stage / "native-pair"
    run([compiler, "-O0", "-fno-lto", reference, extracted, harness, "-o", native])
    replayed = 0
    for test in sorted(directory.glob("*.ktest")):
        objects = ktest_objects(test)
        if set(objects) != ({"inputs"} if count else set()):
            raise ValueError("unexpected symbolic test objects")
        data = objects.get("inputs", b"")
        if len(data) != count * 4:
            raise ValueError("symbolic test has the wrong argument width")
        values = [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]
        run([native, *values])
        replayed += 1
    if replayed != int(tests[1]) or replayed == 0:
        raise ValueError("not every generated test passed native differential replay")
    return ({"method": "KLEE self-composition", "contract": "equal i32 return bits",
             "inputs": "all bit patterns of each i32 argument; no assumptions or path pruning",
             "memory": "private initialized stack only", "completed_paths": int(completed[1]),
             "partial_paths": 0, "native_replayed_tests": replayed,
             "equivalence_module_sha256": digest(module.read_bytes()),
             "log_sha256": digest(log.encode())}, native)


def standalone_source(count, values, expected, metadata):
    call = ", ".join(f"{value}U" for value in values)
    description = json.dumps(json.dumps(metadata, sort_keys=True))
    return f'''#include <stdint.h>
#include <stdio.h>
#include <string.h>
uint32_t osrec_extracted_entry({shape(count)});
int main(int argc, char **argv) {{
    if (argc == 2 && strcmp(argv[1], "--describe") == 0) {{ puts({description}); return 0; }}
    if (argc != 1) return 2;
    uint32_t actual = osrec_extracted_entry({call});
    if (actual != {expected}U) {{ fputs("scenario mismatch\\n", stderr); return 1; }}
    printf("scenario verified: return=%u\\n", actual);
    return 0;
}}
'''


def export(args):
    source = args.module.read_bytes()
    plugin = args.plugin.read_bytes()
    values = json.loads(args.arguments)
    identity = None
    if args.source_identity:
        identity = json.loads(args.source_identity.read_bytes())
        if (not isinstance(identity, dict) or set(identity) !=
                {"format", "module_sha256", "source", "license", "type_contract"}
                or identity["format"] != "osrec-el0-source-identity-v1"
                or identity["module_sha256"] != digest(source)
                or not isinstance(identity["source"], dict)
                or not isinstance(identity["license"], str)
                or not isinstance(identity["type_contract"], str)):
            raise ValueError("source identity must describe the exact input module")
    if not isinstance(values, list) or any(type(v) is not int or not 0 <= v <= 0xffffffff for v in values):
        raise ValueError("--arguments must be a JSON array of unsigned 32-bit integers")
    destination = args.out.resolve()
    suffixes = (".analysis.json", ".manifest.json", ".reference.bc", ".extracted.bc", ".equivalence.bc", ".klee.log")
    protected = {args.module.resolve(), args.plugin.resolve(), Path(__file__).resolve(),
                 *(path.resolve() for path in args.llvm_bin.iterdir() if path.is_file())}
    if args.source_identity:
        protected.add(args.source_identity.resolve())
    if any(Path(str(destination) + suffix).resolve() in protected for suffix in ("", *suffixes)):
        raise ValueError("output cannot overwrite construction inputs")
    destination.parent.mkdir(parents=True, exist_ok=True)
    compiler = args.llvm_bin / "clang"
    compiler_version = run([compiler, "--version"]).stdout
    klee_version = run([args.klee, "--version"]).stdout
    clang_major = re.search(r"clang version (\d+)", compiler_version)
    klee_major = re.search(r"LLVM version (\d+)", klee_version)
    if not clang_major or not klee_major or clang_major[1] != klee_major[1]:
        raise ValueError("compiler and KLEE must use the same LLVM major")
    with tempfile.TemporaryDirectory(prefix="osrec-el0-export-") as directory:
        stage = Path(directory)
        original = stage / ("input.ll" if args.module.suffix == ".ll" else "input.bc")
        original.write_bytes(source)
        report = inspect(original, args.root, args)
        if report["llvm_version"].split(".")[0] != clang_major[1]:
            raise ValueError("plugin, compiler and KLEE must use the same LLVM major")
        target = run([compiler, "-dumpmachine"]).stdout.strip()
        normalize = lambda value: value.replace("aarch64", "arm64").replace("macosx", "darwin")
        architecture = lambda value: normalize(value).split("-")[0]
        family = lambda value: "apple" if "apple" in value else "linux" if "linux" in value else value
        if architecture(report["target"]) != architecture(target) or family(report["target"]) != family(target):
            raise ValueError("module target must match the native execution platform")
        if not report["data_layout"].startswith("e"):
            raise ValueError("the current concrete test decoder requires little-endian inputs")
        native_ir = run([compiler, "-x", "c", "-", "-emit-llvm", "-S", "-o", "-"], input="").stdout
        native_layout = re.search(r'^target datalayout = "([^"]+)"$', native_ir, re.MULTILINE)
        if not native_layout or report["data_layout"] != native_layout[1]:
            raise ValueError("module data layout differs from the native compiler ABI")
        count = supported(report)
        if len(values) != count:
            raise ValueError("checkpoint argument count differs from the root signature")
        outputs = {}
        for mode, name in (("reference", "reference.bc"), ("extract", "extracted.bc")):
            output = stage / name
            result = run([args.llvm_bin / "opt", "-load-pass-plugin", args.plugin,
                          f"-passes=osrec-el0-{mode}<{args.root}>", original, "-o", output])
            outputs[mode] = json.loads(result.stderr)
        expected_slice = report["instruction_slice"]
        if (outputs["extract"]["before"] != expected_slice["total_instructions"]
                or outputs["extract"]["after"] != expected_slice["retained_instructions"]):
            raise ValueError("extraction differs from the analyzed dependency closure")
        extracted_report = inspect(stage / "extracted.bc", "osrec_extracted_entry", args)
        if supported(extracted_report) != count:
            raise ValueError("extracted interface differs from the original")
        result, pair = proof(args, stage, stage / "reference.bc", stage / "extracted.bc", count)
        expected = int(run([pair, *values]).stdout.strip())
        metadata = {"format": "osrec-standalone-el0-v1", "root": args.root,
                    "provenance": "synthetic scalar checkpoint; not a live kernel capture",
                    "input_sha256": digest(source), "plugin_sha256": digest(plugin),
                    "exporter_sha256": digest(Path(__file__).read_bytes()),
                    "analysis_sha256": digest(json.dumps(report, sort_keys=True).encode()),
                    "extracted_ir_sha256": digest((stage / "extracted.bc").read_bytes()),
                    "extraction": outputs["extract"], "symbolic_equivalence": result,
                    "checkpoint": values, "expected_return_bits": expected,
                    "platform": target, "requires": "host OS system runtime",
                    "scheduler_irq_execution": False}
        if identity:
            metadata["source_identity"] = identity
        main = stage / "scenario.c"
        main.write_text(standalone_source(count, values, expected, metadata))
        binary = stage / "scenario"
        run([compiler, "-O0", "-fno-lto", stage / "extracted.bc", main, "-o", binary])
        libraries = dependencies(binary)
        with tempfile.TemporaryDirectory(prefix="osrec-el0-isolated-") as isolated:
            isolated_path = Path(isolated)
            isolated_binary = isolated_path / "scenario"
            shutil.copy2(binary, isolated_binary)
            environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
            verified = run([isolated_binary], cwd=isolated_path, env=environment).stdout.strip()
            described = json.loads(run([isolated_binary, "--describe"], cwd=isolated_path, env=environment).stdout)
            if described != metadata:
                raise ValueError("embedded artifact description differs from the validated scenario")
        if digest(args.plugin.read_bytes()) != digest(plugin) or args.module.read_bytes() != source:
            raise ValueError("construction inputs changed during validation")
        manifest = {"metadata": metadata, "artifact_sha256": digest(binary.read_bytes()),
                    "artifact_bytes": binary.stat().st_size, "system_libraries": libraries,
                    "isolated_execution": verified, "compiler": compiler_version, "klee": klee_version}
        (stage / "analysis.json").write_text(json.dumps(report, indent=2) + "\n")
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        for suffix in suffixes:
            shutil.copy2(stage / suffix[1:], Path(str(destination) + suffix))
        with tempfile.NamedTemporaryFile(prefix=".osrec-el0-", dir=destination.parent, delete=False) as pending:
            pending_path = Path(pending.name)
        try:
            shutil.copy2(binary, pending_path)
            os.replace(pending_path, destination)
        finally:
            pending_path.unlink(missing_ok=True)
    print(json.dumps({"executable": str(destination), "verification": verified,
                      "extraction": outputs["extract"], "equivalence": result}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path)
    parser.add_argument("--root", required=True)
    parser.add_argument("--arguments", required=True, help="JSON array of checkpoint i32 argument bits")
    parser.add_argument("--llvm-bin", required=True, type=Path)
    parser.add_argument("--plugin", required=True, type=Path)
    parser.add_argument("--klee", type=Path, default=Path("/opt/homebrew/bin/klee"))
    parser.add_argument("--klee-include", type=Path, default=Path("/opt/homebrew/opt/klee/include"))
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--source-identity", type=Path, help="optional hash-bound prepared-source identity and license")
    args = parser.parse_args()
    args.llvm_bin, args.plugin, args.module = args.llvm_bin.resolve(), args.plugin.resolve(), args.module.resolve()
    try:
        export(args)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        print(f"EL0 export rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
