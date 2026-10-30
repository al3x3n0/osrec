#!/usr/bin/env python3
"""Prepare a pinned scalar LiteOS-A helper with explicit AArch32 type widths."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "integrations/liteos_a/align-source-lock.json"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def prepare(args):
    lock = json.loads(LOCK.read_bytes())
    revision = subprocess.run(["git", "-C", str(args.kernel_root), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()
    if revision != lock["revision"]:
        raise ValueError("kernel revision differs from the helper source lock")
    raw = (args.kernel_root / lock["source"]).read_bytes()
    if digest(raw) != lock["source_sha256"]:
        raise ValueError("kernel helper source differs from the reviewed source lock")
    source = raw.decode()
    match = re.search(r"LITE_OS_SEC_TEXT UINTPTR LOS_Align\(UINTPTR addr, UINT32 boundary\)\s*\{.*?\n\}",
                      source, re.DOTALL)
    if not match or digest(match[0].encode()) != lock["function_sha256"]:
        raise ValueError("helper extraction differs from the pinned function")
    license_text = source[:source.index("*/") + 2]
    generated = (license_text + "\n#include <stdint.h>\n"
                 "/* Preserve Cortex-A7/AArch32 scalar widths; these are integer addresses. */\n"
                 "typedef uint32_t UINTPTR;\ntypedef uint32_t UINT32;\n#define LITE_OS_SEC_TEXT\n"
                 + f'#line {source[:match.start()].count(chr(10)) + 1} "{lock["source"]}"\n'
                 + match[0] + "\n")
    destination = args.out.resolve()
    if destination.is_relative_to(args.kernel_root.resolve()):
        raise ValueError("prepared files must be outside the source checkout")
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "los_align.c"
    module = destination / "los_align.bc"
    path.write_text(generated)
    subprocess.run([str(args.llvm_bin / "clang"), "-O1", "-g", "-ffreestanding", "-fno-builtin",
                    "-fno-stack-protector", "-emit-llvm", "-c", str(path), "-o", str(module)],
                   check=True, capture_output=True, text=True)
    identity = {"format": "osrec-el0-source-identity-v1", "module_sha256": digest(module.read_bytes()),
                "source": lock, "license": license_text,
                "type_contract": "UINTPTR and UINT32 are uint32_t, preserving Cortex-A7/AArch32 scalar widths; no host pointers"}
    (destination / "source-identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    print(json.dumps({"module": str(module), "identity": str(destination / "source-identity.json"),
                      "root": "LOS_Align", "kernel_revision": revision}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-root", type=Path, required=True)
    parser.add_argument("--llvm-bin", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(args)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"LiteOS helper preparation rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
