#!/usr/bin/env python3
"""Build and optionally explore a pinned LiteOS-A SysRead/user scenario."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
INTEGRATION = ROOT / "integrations" / "liteos_a"


def run(argv, **kwargs):
    return subprocess.run([str(arg) for arg in argv], check=True, capture_output=True,
                          text=True, **kwargs)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def slice_source(kernel):
    lock = json.loads((INTEGRATION / "source-lock.json").read_text())
    revision = run(["git", "-C", kernel, "rev-parse", "HEAD"]).stdout.strip()
    if revision != lock["revision"]:
        raise ValueError("kernel revision does not match source-lock.json")
    path = kernel / lock["source"]
    raw = path.read_bytes()
    if digest(raw) != lock["source_sha256"]:
        raise ValueError("kernel source file changed; review and repin before extraction")
    source = raw.decode("utf-8")
    start = source.index("ssize_t SysRead(int fd, void *buf, size_t nbytes)")
    end = source.index("\nssize_t SysWrite", start)
    function = source[start:end].strip() + "\n"
    if digest(function.encode()) != lock["function_sha256"]:
        raise ValueError("function extraction does not match the pinned body")
    license_text = source[:source.index("*/") + 2]
    line = source[:start].count("\n") + 1
    prelude = """
#include <stdint.h>
/* Fixed 32-bit syscall scalars; host-normalized addresses are an abstraction. */
typedef uint32_t size_t;
typedef int32_t ssize_t;
typedef uintptr_t UINTPTR;
typedef uintptr_t vaddr_t;
#define EFAULT 14
extern int osrec_user_address_range(uintptr_t address, uint32_t size);
extern int osrec_associated_fd(int fd);
extern int osrec_vfs_read(int fd, void *buf, uint32_t size);
extern int osrec_get_errno(void);
#define LOS_IsUserAddressRange osrec_user_address_range
#define GetAssociatedSystemFd osrec_associated_fd
#define read osrec_vfs_read
#define get_errno osrec_get_errno
"""
    generated = license_text + "\n" + prelude + f'\n#line {line} "{lock["source"]}"\n' + function
    return generated, lock


def seed_header(path):
    seed = json.loads(path.read_text())
    expected_bounds = {"user_fd_max": 4, "request_bytes_max": 9,
                       "null_buffer_max": 1, "environment_mode_max": 2}
    if seed.get("format") != "osrec-liteos-a-sysread-seed-v1" or (
            seed.get("user_memory_bytes"), seed.get("user_fd"), seed.get("system_fd"),
            seed.get("environment_mode")) != (8, 3, 17, 0) or (
            seed.get("symbolic_bounds") != expected_bounds):
        raise ValueError("unsupported seed layout or exploration bounds")
    payload = bytes.fromhex(seed["device_payload_hex"])
    if len(payload) != 4:
        raise ValueError("this first scenario requires a four-byte device payload")
    initializer = "{" + ", ".join(str(value) for value in payload) + "}"
    header = f"""#ifndef OSREC_SEED_CONFIG_H
#define OSREC_SEED_CONFIG_H
#define OSREC_USER_MEMORY_BYTES 8U
#define OSREC_USER_FD 3
#define OSREC_SYSTEM_FD 17
#define OSREC_PAYLOAD_BYTES 4U
#define OSREC_FD_MAX 4U
#define OSREC_COUNT_MAX 9U
#define OSREC_SEED_MODE 0U
#define OSREC_SEED_PAYLOAD {initializer}
#endif
"""
    return header, seed


def ktest_objects(path):
    """Read bounded KTest v1-v3 files, using the upstream big-endian framing."""
    data = path.read_bytes()
    if len(data) > 65536 or data[:5] != b"KTEST":
        raise ValueError("unsupported KTest header or size")
    position = 5

    def take(size):
        nonlocal position
        if size > len(data) - position:
            raise ValueError("truncated KTest")
        out = data[position:position + size]
        position += size
        return out

    def integer():
        return struct.unpack(">I", take(4))[0]

    def blob():
        size = integer()
        if size > 8192:
            raise ValueError("KTest object exceeds scenario bound")
        return take(size)

    version = integer()
    if version not in (1, 2, 3):
        raise ValueError("unsupported KTest version")
    arguments = integer()
    if arguments > 32:
        raise ValueError("too many KTest arguments")
    for _ in range(arguments):
        blob()
    if version >= 2:
        integer()
        integer()
    count = integer()
    if count > 8:
        raise ValueError("too many KTest objects")
    objects = {}
    for _ in range(count):
        name = blob().decode("utf-8")
        if name in objects:
            raise ValueError("duplicate KTest object")
        objects[name] = blob()
    if position != len(data):
        raise ValueError("trailing KTest bytes")
    return objects


def build(args):
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    kernel = args.kernel_root.resolve()
    generated, lock = slice_source(kernel)
    header, seed = seed_header(args.seed)
    (out / "kernel_sysread.c").write_text(generated)
    (out / "seed_config.h").write_text(header)
    clang = args.llvm_bin / "clang"
    linker = args.llvm_bin / "llvm-link"
    nm = args.llvm_bin / "llvm-nm"
    version = run([clang, "--version"]).stdout
    compiler_major = int(re.search(r"clang version (\d+)", version).group(1))
    klee_version = None
    if args.run:
        klee_version = run([args.klee, "--version"]).stdout
        match = re.search(r"LLVM version (\d+)", klee_version)
        if not match or int(match.group(1)) != compiler_major:
            raise ValueError("KLEE and the bitcode compiler must use the same LLVM major")
    if not (args.klee_include / "klee" / "klee.h").is_file():
        raise ValueError("--klee-include must contain klee/klee.h")
    common = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-fno-stack-protector",
              "-fno-builtin", "-I", out, "-I", INTEGRATION]
    files = [out / "kernel_sysread.c", INTEGRATION / "models.c", INTEGRATION / "user_program.c"]
    native = out / "sysread_native"
    run([clang, *common, "-O0", *files, "-o", native])
    native_result = run([native]).stdout.strip()
    bitcode = ["-emit-llvm", "-c", "-g", "-O0", "-Xclang", "-disable-O0-optnone",
               "-DOSREC_KLEE", "-I", args.klee_include]
    components = []
    for source in files[:2]:
        destination = out / (source.stem + ".bc")
        run([clang, *common, *bitcode, source, "-o", destination])
        components.append(destination)
    for mode in ("fixed", "explore"):
        user = out / f"user_{mode}.bc"
        definitions = ["-DOSREC_EXPLORE_ENVIRONMENT"] if mode == "explore" else []
        run([clang, *common, *bitcode, *definitions, files[2], "-o", user])
        program = out / f"sysread_{mode}.bc"
        run([linker, *components, user, "-o", program])
        undefined = run([nm, "--undefined-only", program]).stdout
        # llvm-nm applies the Darwin object-format underscore to IR names.
        symbols = [line.split()[-1].removeprefix("_") for line in undefined.splitlines() if line.strip()]
        allowed = {"klee_make_symbolic", "klee_assume", "klee_report_error"}
        if set(symbols) - allowed:
            raise ValueError(f"unmodeled external calls in bitcode: {set(symbols) - allowed}")
    manifest = {"kernel": lock, "seed": seed, "compiler": version.strip(),
                "klee": klee_version, "native_verification": native_result,
                "address_model": "host-normalized, one registered user range; no MMU or SVC",
                "scalar_model": "32-bit ssize_t and size_t; host-width pointers",
                "executed_kernel_code": ["SysRead"],
                "modeled_kernel_dependencies": ["LOS_IsUserAddressRange", "GetAssociatedSystemFd",
                                                "read/VFS", "get_errno"],
                "modeled_user_dependencies": ["read syscall dispatch and errno translation"],
                "hardware_or_scheduler_execution": False,
                "runner_sha256": digest(Path(__file__).read_bytes()),
                "seed_sha256": digest(args.seed.read_bytes()),
                "inputs": {str(path.relative_to(ROOT)): digest(path.read_bytes())
                           for path in INTEGRATION.glob("*") if path.is_file()},
                "artifacts": {path.name: digest(path.read_bytes()) for path in [
                    *files[:1], out / "seed_config.h", native,
                    out / "sysread_fixed.bc", out / "sysread_explore.bc"]}}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return out, seed, manifest


def explore(args, out, seed):
    results = {}
    for mode in ("fixed", "explore"):
        output = out / f"klee-{mode}-{uuid.uuid4().hex[:8]}"
        program = out / f"sysread_{mode}.bc"
        result = subprocess.run([str(args.klee), "--solver-backend=z3",
                                 "--external-calls=none", "--exit-on-error",
                                 "--max-time=30s", "--max-memory=512",
                                 f"--output-dir={output}", str(program)],
                                capture_output=True, text=True, timeout=50)
        (out / f"{output.name}.log").write_text(result.stdout + result.stderr)
        summary = result.stderr
        completed = re.search(r"^KLEE: done: completed paths = (\d+)$", summary, re.MULTILINE)
        partial = re.search(r"^KLEE: done: partially completed paths = (\d+)$", summary, re.MULTILINE)
        if result.returncode or list(output.glob("*.err")) or "HaltTimer" in summary or (
                not completed or not partial or int(partial.group(1))):
            raise ValueError(f"KLEE failed or exploration was incomplete; see {output.name}.log")
        tests = sorted(output.glob("*.ktest"))
        if not tests:
            raise ValueError("KLEE produced no tests")
        for test in tests:
            objects = ktest_objects(test)
            expected = {"user_request"} if mode == "fixed" else {
                "user_request", "environment_mode", "device_payload"}
            if set(objects) != expected or len(objects["user_request"]) != 12:
                raise ValueError("KTest objects do not match the supported scenario")
            fd, count, null = struct.unpack("<III", objects["user_request"])
            if mode == "fixed":
                environment = seed["environment_mode"]
                payload = bytes.fromhex(seed["device_payload_hex"])
            else:
                if len(objects["environment_mode"]) != 4 or len(objects["device_payload"]) != 4:
                    raise ValueError("invalid environment object size")
                environment = struct.unpack("<I", objects["environment_mode"])[0]
                payload = objects["device_payload"]
            run([out / "sysread_native", fd, count, null, environment, payload.hex()])
        results[mode] = {"output": str(output), "generated_tests": len(tests),
                         "native_replayed_tests": len(tests),
                         "completed_paths": int(completed.group(1)),
                         "partially_completed_paths": int(partial.group(1))}
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--llvm-bin", required=True, type=Path)
    parser.add_argument("--klee-include", required=True, type=Path)
    parser.add_argument("--klee", default=shutil.which("klee") or "klee", type=Path)
    parser.add_argument("--seed", default=INTEGRATION / "sysread_seed.json", type=Path)
    parser.add_argument("--run", action="store_true", help="run both KLEE modes and native-replay every test")
    args = parser.parse_args()
    try:
        out, seed, manifest = build(args)
        if args.run:
            manifest["exploration"] = explore(args, out, seed)
            (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(json.dumps({"output": str(out), "native": manifest["native_verification"],
                          "exploration": manifest.get("exploration")}, indent=2))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            parser.exit(1, f"scenario failed: {error.stderr or error.stdout}\n")
        parser.exit(1, f"scenario failed: {error}\n")


if __name__ == "__main__":
    main()
