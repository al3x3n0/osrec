#!/usr/bin/env python3
"""Bounded KLEE validation of two aliased-descriptor SysRead calls and checkpoint replay."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

from klee_liteos import ROOT, INTEGRATION, digest, ktest_objects
from syscall_checkpoint import identity, run


def verify(args):
    out = args.out.resolve()
    protected_dirs = [INTEGRATION, ROOT/"runtime", ROOT/"include", ROOT/"tools", args.llvm_bin.resolve()]
    if out.is_relative_to(args.kernel_root.resolve()) or out == ROOT or any(out.is_relative_to(path) for path in protected_dirs):
        raise ValueError("proof output must be a separate build directory")
    out.mkdir(parents=True, exist_ok=True)
    (out / "osrec").mkdir(exist_ok=True)
    record, generated, sources = identity(args.kernel_root)
    for path, source in sources.items():
        target = out / "osrec/checkpoint.h" if path.name == "checkpoint.h" else out / path.name
        target.write_bytes(source)
    proof_source = (INTEGRATION / "syscall_checkpoint_proof.c").read_bytes()
    (out / "proof.c").write_bytes(proof_source)
    (out / "kernel_sysread.c").write_text(generated)
    compiler = args.llvm_bin / "clang"
    compiler_version, klee_version = run([compiler,"--version"]).stdout, run([args.klee,"--version"]).stdout
    major = re.search(r"clang version (\d+)", compiler_version)
    klee_major = re.search(r"LLVM version (\d+)", klee_version)
    if not major or not klee_major or major[1] != klee_major[1]:
        raise ValueError("KLEE and compiler LLVM majors must match")
    files = [out/name for name in ("kernel_sysread.c", "checkpoint.c", "syscall_checkpoint.c", "proof.c")]
    common = ["-std=c11", "-O1", "-g", "-fno-builtin", "-Wall", "-Wextra", "-Werror", "-I", out]
    native = out / "proof_native"
    native_compiler = shutil.which(args.native_compiler)
    if not native_compiler:
        raise ValueError("native compiler is unavailable")
    run([native_compiler, *common, *files, "-o", native])
    components = []
    for source in files:
        bc = source.with_suffix(".bc")
        run([compiler, *common, "-DOSREC_KLEE", "-I", args.klee_include, "-emit-llvm", "-c", source, "-o", bc])
        components.append(bc)
    module = out / "checkpoint_proof.bc"
    run([args.llvm_bin/"llvm-link", *components, "-o", module])
    symbols = [line.split()[-1].removeprefix("_") for line in run([args.llvm_bin/"llvm-nm","--undefined-only",module]).stdout.splitlines() if line.strip()]
    allowed = {"klee_make_symbolic", "klee_assume", "klee_report_error"}
    if any(symbol not in allowed and not symbol.startswith(("llvm.dbg.","llvm.lifetime.","llvm.memcpy.","llvm.memset.")) for symbol in symbols):
        raise ValueError("unmodeled proof-module dependencies")
    directory = out / ("klee-"+uuid.uuid4().hex[:8])
    result = subprocess.run([str(args.klee), "--solver-backend=z3", "--use-forked-solver=false", "--external-calls=none",
                             "--exit-on-error", "--max-time=45s", "--max-memory=512", f"--output-dir={directory}", str(module)],
                            text=True, capture_output=True, timeout=65)
    log = result.stdout+result.stderr
    (out/"klee.log").write_text(log)
    completed = re.search(r"^KLEE: done: completed paths = (\d+)$",log,re.MULTILINE)
    partial = re.search(r"^KLEE: done: partially completed paths = (\d+)$",log,re.MULTILINE)
    count = re.search(r"^KLEE: done: generated tests = (\d+)$",log,re.MULTILINE)
    if result.returncode or not completed or not partial or not count or int(completed[1]) == 0 or int(partial[1]) or list(directory.glob("*.err")):
        raise ValueError("checkpoint reconstruction check did not complete without errors/partial paths")
    tests = sorted(directory.glob("*.ktest"))
    if len(tests) != int(count[1]) or not tests:
        raise ValueError("missing generated proof cases")
    for test in tests:
        objects = ktest_objects(test)
        if set(objects) != {"checkpoint_and_inputs"} or len(objects["checkpoint_and_inputs"]) != 40:
            raise ValueError("unexpected proof input layout")
        run([native, objects["checkpoint_and_inputs"].hex()])
    report = {"format": "osrec-syscall-checkpoint-proof-v1", "status": "verified_within_contract", "identity": record,
              "contract": "two fixed valid SysRead calls using aliased descriptors 3/4 and buffer offsets 2/4; fresh entry objects",
              "symbolic_checkpoint": "all 8 initial buffer bytes and 32-bit cursor bits; user/kernel errno <=4095",
              "symbolic_inputs": "each read result -1..2, arbitrary two payload bytes, EINTR/EIO on failure",
              "observations": "raw/user return, errno, recognition, full buffer, cursor, ordered boundary events after each call",
              "completed_paths": int(completed[1]), "partial_paths": 0, "native_replayed_tests": len(tests),
              "module_sha256": digest(module.read_bytes()), "proof_source_sha256": digest(proof_source),
              "log_sha256": digest(log.encode()), "compiler": compiler_version, "klee": klee_version,
              "native_compiler": run([native_compiler,"--version"]).stdout,
              "arbitrary_sessions_certified": False, "trace_or_checkpoint_omissions": False}
    (out/"proof-report.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({key:report[key] for key in ("status","completed_paths","partial_paths","native_replayed_tests")},indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-root",required=True,type=Path)
    parser.add_argument("--out",required=True,type=Path)
    parser.add_argument("--llvm-bin",default=Path("/opt/homebrew/opt/llvm@16/bin"),type=Path)
    parser.add_argument("--klee",default=Path("/opt/homebrew/bin/klee"),type=Path)
    parser.add_argument("--klee-include",default=Path("/opt/homebrew/opt/klee/include"),type=Path)
    parser.add_argument("--native-compiler",default="cc")
    args=parser.parse_args()
    try:
        verify(args)
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        if isinstance(error,subprocess.CalledProcessError): print(error.stderr,file=sys.stderr)
        print(f"syscall checkpoint proof rejected: {error}",file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
