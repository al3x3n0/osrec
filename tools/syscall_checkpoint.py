#!/usr/bin/env python3
"""Capture and export an object-backed, sequential pinned LiteOS-A SysRead session."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from export_sysread import dependencies
from klee_liteos import ROOT, INTEGRATION, digest, slice_source
from object_checkpoint import ObjectType, Reference, byte_string, keys, unsigned, validate_graph
from export_object_checkpoint import unique_pairs
from read_observations import context_hash, decode as decode_reads

FILES = ("syscall_checkpoint.h", "syscall_checkpoint.c", "syscall_checkpoint_io.c")
PROVENANCE = "host execution of pinned SysRead with explicit models; not a live kernel capture"
SCHEMAS = {
    "bytes": ObjectType(),
    "file": ObjectType({"backend_fd": "u32", "position": "u32"}),
    "process": ObjectType({"memory": Reference("bytes"), "fd3": Reference("file", nullable=True),
                           "fd4": Reference("file", nullable=True), "kernel_errno": "u32", "user_errno": "u32"}),
}
SCHEMA_IDS = {"bytes": 1, "file": 2, "process": 3}
TYPES = {"file": "struct session_file", "process": "struct session_process"}


def run(command, **kwargs):
    return subprocess.run([str(value) for value in command], check=True, capture_output=True,
                          text=True, timeout=90, **kwargs)


def load(path):
    with path.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("session exceeds 64 KiB")
    return json.loads(raw, object_pairs_hook=unique_pairs)


def signed(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"invalid {label}")
    return value


def reference(value, memory_id, size):
    keys(value, ("object", "offset"), "syscall buffer")
    unsigned(value["object"], 64, "buffer object")
    unsigned(value["offset"], 64, "buffer offset")
    if value["object"] == 0:
        if value["offset"]:
            raise ValueError("null buffer has nonzero offset")
    elif value["object"] != memory_id or value["offset"] > size:
        raise ValueError("request pointer is outside the registered buffer")


def validate_entry(entry, calls):
    keys(entry, ("boundary", "roots", "objects"), "session entry")
    if entry["boundary"] != "user syscall sequence entry":
        raise ValueError("unsupported checkpoint boundary")
    objects = validate_graph(entry["objects"], entry["roots"], SCHEMAS,
                             {"current_process": Reference("process")})
    groups = {kind: [obj for obj in objects.values() if obj["type"] == kind] for kind in SCHEMAS}
    if len(groups["process"]) != 1 or len(groups["bytes"]) != 1 or len(groups["file"]) > 2:
        raise ValueError("session requires one process, one buffer and at most two file objects")
    process = groups["process"][0]
    fields = process["fields"]
    if fields["memory"]["offset"] or len(groups["bytes"][0]["data"]) != 16:
        raise ValueError("process memory must bind the base of an 8-byte buffer")
    if fields["kernel_errno"] > 4095 or fields["user_errno"] > 4095:
        raise ValueError("errno checkpoint exceeds the modeled range")
    backend_ids = [obj["fields"]["backend_fd"] for obj in groups["file"]]
    if any(not 1 <= fd <= 0x7fffffff for fd in backend_ids) or len(set(backend_ids)) != len(backend_ids):
        raise ValueError("distinct file objects need distinct positive backend handles")
    if not isinstance(calls, list) or not 1 <= len(calls) <= 8:
        raise ValueError("session requires 1..8 syscall invocations")
    for call in calls:
        keys(call, ("syscall", "fd", "count", "buffer"), "syscall")
        if call["syscall"] != "SysRead":
            raise ValueError("this checkpoint contract supports SysRead only")
        signed(call["fd"], 0, 4, "user descriptor")
        signed(call["count"], 0, 9, "request size")
        reference(call["buffer"], groups["bytes"][0]["id"], 8)
    return objects


def read_input(value, call):
    keys(value, ("result", "errno", "payload"), "modeled read input")
    result = signed(value["result"], -1, min(8, call["count"]), "read result")
    signed(value["errno"], 0, 4095, "read errno")
    data = byte_string(value["payload"], "read payload")
    if len(data) != max(result, 0) or (result < 0 and not value["errno"]) or (result >= 0 and value["errno"]):
        raise ValueError("inconsistent modeled read result/errno/payload")


def identity(kernel):
    generated, lock = slice_source(kernel)
    source_paths = [INTEGRATION / name for name in FILES] + [ROOT / "include/osrec/checkpoint.h", ROOT / "runtime/checkpoint.c"]
    sources = {path: path.read_bytes() for path in source_paths}
    record = {"kernel": lock, "kernel_slice_sha256": digest(generated.encode()),
              "models": {str(path.relative_to(ROOT)): digest(data) for path, data in sources.items()}}
    return record, generated, sources


def validate_capture(document, expected_identity):
    fields = ["format", "provenance", "identity", "entry", "calls", "transcript", "expected"]
    if "read_source" in document:
        fields.append("read_source")
        source = document["read_source"]
        keys(source,("kind","records_sha256","context_sha256"),"read source")
        if (source["kind"] not in ("host-file","qemu","emulator","board") or
                not isinstance(source["records_sha256"],str) or len(source["records_sha256"]) != 64 or
                any(character not in "0123456789abcdef" for character in source["records_sha256"]) or
                source["context_sha256"] != context_hash(document["entry"],document["calls"],expected_identity)):
            raise ValueError("invalid recorded read provenance/context")
    keys(document, fields, "session capture")
    if (document["format"] != "osrec-syscall-session-capture-v1" or document["provenance"] != PROVENANCE
            or document["identity"] != expected_identity):
        raise ValueError("unsupported capture provenance or stale kernel/model identity")
    objects = validate_entry(document["entry"], document["calls"])
    if (not isinstance(document["transcript"], list) or not isinstance(document["expected"], list)
            or len(document["transcript"]) != len(document["calls"])
            or len(document["expected"]) != len(document["calls"])):
        raise ValueError("transcript and observations must cover every invocation")
    memory_id = next(obj["id"] for obj in objects.values() if obj["type"] == "bytes")
    file_ids = [str(obj["id"]) for obj in objects.values() if obj["type"] == "file"]
    for call, events, observation in zip(document["calls"], document["transcript"], document["expected"]):
        if not isinstance(events, list) or len(events) > 4:
            raise ValueError("invalid boundary transcript length")
        for event in events:
            keys(event, ("kind", "fd", "count", "buffer", "result", "errno", "position_before", "position_after", "payload"), "boundary event")
            signed(event["kind"], 1, 4, "boundary kind")
            signed(event["fd"], -1, 0x7fffffff, "boundary descriptor")
            signed(event["count"], 0, 9, "boundary size")
            reference(event["buffer"], memory_id, 8)
            signed(event["result"], -1, 0x7fffffff, "boundary result")
            signed(event["errno"], 0, 4095, "boundary errno")
            unsigned(event["position_before"], 32, "file position")
            unsigned(event["position_after"], 32, "file position")
            data = byte_string(event["payload"], "boundary payload")
            if event["kind"] == 3:
                read_input({"result": event["result"], "errno": event["errno"], "payload": event["payload"]}, call)
            elif data:
                raise ValueError("only read boundary events contain payload bytes")
        keys(observation, ("raw", "return", "errno", "recognized", "memory", "file_positions", "kernel_errno"), "syscall observations")
        signed(observation["raw"], -4095, 8, "raw return")
        signed(observation["return"], -1, 8, "user return")
        signed(observation["errno"], 0, 4095, "user errno")
        signed(observation["kernel_errno"], 0, 4095, "kernel errno")
        signed(observation["recognized"], 0, 1, "recognition flag")
        if len(byte_string(observation["memory"], "observed memory")) != 8:
            raise ValueError("observed memory has the wrong size")
        keys(observation["file_positions"], file_ids, "observed file positions")
        for position in observation["file_positions"].values():
            unsigned(position, 32, "observed file position")
    return objects


def initializer(data):
    return "{" + ",".join(str(byte) for byte in data) + "}"


def event_initializer(event):
    fields = {"kind": event["kind"], "fd": event["fd"], "count": event["count"], "result": event["result"],
              "error": event["errno"], "position_before": event["position_before"], "position_after": event["position_after"],
              "size": len(event["payload"]) // 2}
    pieces = [f".{name}={value}" for name, value in fields.items()]
    pieces += [f".buffer={{UINT64_C({event['buffer']['object']}),UINT64_C({event['buffer']['offset']})}}",
               ".payload=" + initializer(bytes.fromhex(event["payload"]) or b"\0")]
    return "{" + ",".join(pieces) + "}"


def setup(entry, objects):
    lines = []
    for identifier, obj in sorted(objects.items()):
        if obj["type"] == "bytes":
            lines.append(f"unsigned char object_{identifier}[] = {initializer(bytes.fromhex(obj['data']))};")
        else:
            lines.append(f"{TYPES[obj['type']]} object_{identifier} = {{0}};")
            for field, contract in SCHEMAS[obj["type"]].fields.items():
                if contract == "u32":
                    lines.append(f"object_{identifier}.{field} = UINT32_C({obj['fields'][field]});")
    lines += [f"struct osrec_object storage[{len(objects)}]; struct osrec_object_table table;",
              f"if (!osrec_objects_init(&table, storage, {len(objects)})) return 1;"]
    for identifier, obj in sorted(objects.items()):
        lines.append(f"if (!osrec_object_add(&table, UINT64_C({identifier}), {SCHEMA_IDS[obj['type']]}, &object_{identifier}, sizeof(object_{identifier}))) return 1;")
    for identifier, obj in sorted(objects.items()):
        for field, contract in (SCHEMAS[obj["type"]].fields or {}).items():
            if isinstance(contract, Reference):
                ref = obj["fields"][field]
                extent = "1" if contract.target == "bytes" else f"sizeof({TYPES[contract.target]})"
                lines += ["{ void *pointer;", f"if (!osrec_object_resolve(&table, (struct osrec_object_ref)"
                          f"{{UINT64_C({ref['object']}),UINT64_C({ref['offset']})}}, {extent}, {SCHEMA_IDS[contract.target]}, &pointer)) return 1;",
                          f"object_{identifier}.{field} = pointer; }}"]
    root = entry["roots"]["current_process"]["object"]
    lines += [f"struct session_process *process = &object_{root};", "process->memory_size = SESSION_BYTES;"]
    return lines


def main_source(document, objects, capturing=False, metadata=None):
    lines = setup(document["entry"], objects)
    if capturing:
        lines.append('fputs("{\\\"steps\\\":[", stdout);')
    for index, call in enumerate(document["calls"]):
        lines.append("{")
        ref = call["buffer"]
        lines.append(f"struct session_call call = {{{call['fd']},{call['count']},{{UINT64_C({ref['object']}),UINT64_C({ref['offset']})}}}};")
        if capturing:
            env = document["environment"][index]
            data = bytes.fromhex(env["payload"])
            lines.append(f"struct session_read_input input = {{{env['result']},{env['errno']},{len(data)},{initializer(data or b'\0')}}};")
            lines.append("struct session_result actual = osrec_session_run(process, &table, call, &input, NULL, 0);")
        else:
            events = document["transcript"][index]
            values = ",".join(event_initializer(event) for event in events) or "{0}"
            lines.append(f"const struct session_event transcript[{max(1,len(events))}] = {{{values}}};")
            lines.append(f"struct session_result actual = osrec_session_run(process, &table, call, NULL, transcript, {len(events)});")
        lines.append('if (actual.failed) { fputs("syscall transcript diverged\\n", stderr); return 1; }')
        if capturing:
            if index:
                lines.append("putchar(',');")
            lines += ['fputs("{\\\"outcome\\\":", stdout);', "osrec_session_print_result(actual);"]
            # Append the observed process state alongside the execution result.
            lines.append('fputs(",\\\"state\\\":{\\\"memory\\\":\\\"", stdout);')
            lines.append('for (unsigned i=0;i<SESSION_BYTES;++i) printf("%02x", process->memory[i]);')
            lines.append('printf("\\\",\\\"kernel_errno\\\":%u,\\\"file_positions\\\":{", process->kernel_errno);')
            files = [obj for obj in objects.values() if obj["type"] == "file"]
            for number, obj in enumerate(files):
                prefix = "," if number else ""
                lines.append(f'printf("{prefix}\\\"{obj["id"]}\\\":%u", object_{obj["id"]}.position);')
            lines.append('fputs("}}}", stdout);')
        else:
            expected = document["expected"][index]
            checks = [f"actual.raw != {expected['raw']}", f"actual.result != {expected['return']}",
                      f"actual.error != {expected['errno']}U", f"actual.recognized != {expected['recognized']}U",
                      f"process->kernel_errno != {expected['kernel_errno']}U"]
            checks += [f"process->memory[{i}] != {byte}" for i, byte in enumerate(bytes.fromhex(expected["memory"]))]
            checks += [f"object_{identifier}.position != UINT32_C({position})" for identifier, position in expected["file_positions"].items()]
            lines.append('if (' + " || ".join(checks) + ') { fputs("syscall observations diverged\\n", stderr); return 1; }')
        lines.append("}")
    lines.append('puts("]}");' if capturing else f'puts("syscall session verified: {len(document["calls"])} calls");')
    lines.append("return 0;")
    description = ""
    if metadata:
        description = f'if (argc == 2 && strcmp(argv[1], "--describe") == 0) {{ puts({json.dumps(json.dumps(metadata, sort_keys=True))}); return 0; }}\n'
    return ('#include "syscall_checkpoint.h"\n#include <stdio.h>\n#include <string.h>\n'
            + "int main(int argc, char **argv) {\n" + description
            + "(void)argv; if (argc != 1) return 2;\n" + "\n".join(lines) + "\n}\n")


def build(stage, generated, sources, main, compiler):
    (stage / "osrec").mkdir()
    for path, data in sources.items():
        target = stage / "osrec/checkpoint.h" if path == ROOT / "include/osrec/checkpoint.h" else stage / path.name
        target.write_bytes(data)
    (stage / "kernel_sysread.c").write_text(generated)
    (stage / "main.c").write_text(main)
    binary = stage / "scenario"
    run([compiler, "-std=c11", "-O0", "-fno-lto", "-fno-builtin", "-Wall", "-Wextra", "-Werror", "-I", stage,
         stage / "kernel_sysread.c", stage / "checkpoint.c", stage / "syscall_checkpoint.c",
         stage / "syscall_checkpoint_io.c", stage / "main.c", "-o", binary])
    return binary


def capture(args):
    case = load(args.case)
    imported = bool(args.reads)
    keys(case, ("format", "entry", "calls") if imported else ("format", "entry", "calls", "environment"), "session case")
    if case["format"] != ("osrec-syscall-session-entry-v1" if imported else "osrec-syscall-session-case-v1"):
        raise ValueError("unsupported session case")
    objects = validate_entry(case["entry"], case["calls"])
    record, generated, sources = identity(args.kernel_root)
    read_source = None
    if imported:
        if not args.source_kind:
            raise ValueError("recorded reads require an explicit --source-kind")
        with args.reads.open("rb") as stream:
            raw = stream.read(65537)
        context = context_hash(case["entry"],case["calls"],record)
        case["environment"] = decode_reads(raw,context,case["entry"],case["calls"],objects)
        read_source = {"kind":args.source_kind,"records_sha256":digest(raw),"context_sha256":context}
    elif args.source_kind:
        raise ValueError("--source-kind requires --reads")
    if not isinstance(case["environment"], list) or len(case["environment"]) != len(case["calls"]):
        raise ValueError("each invocation needs a modeled external input")
    for call, env in zip(case["calls"], case["environment"]):
        read_input(env, call)
    with tempfile.TemporaryDirectory(prefix="osrec-syscall-capture-") as directory:
        binary = build(Path(directory), generated, sources, main_source(case, objects, capturing=True), args.compiler)
        observed = json.loads(run([binary]).stdout)
    result = {"format": "osrec-syscall-session-capture-v1", "provenance": PROVENANCE, "identity": record,
              "entry": case["entry"], "calls": case["calls"], "transcript": [], "expected": []}
    if read_source:
        result["read_source"] = read_source
    for step in observed["steps"]:
        outcome = step["outcome"]
        result["transcript"].append(outcome["events"])
        result["expected"].append({name: outcome[name] for name in ("raw", "return", "errno", "recognized")} | step["state"])
    validate_capture(result, record)
    publish(args.out, json.dumps(result, indent=2).encode() + b"\n")
    print(json.dumps({"capture": str(args.out.resolve()), "calls": len(case["calls"]), "boundary_events": sum(map(len,result["transcript"]))}, indent=2))


def publish(destination, data=None, binary=None):
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=".osrec-session-", dir=destination.parent, delete=False) as pending:
        path = Path(pending.name)
        if data is not None:
            pending.write(data)
    try:
        if binary:
            shutil.copy2(binary, path)
        os.replace(path, destination)
    finally:
        path.unlink(missing_ok=True)


def export(args):
    captured = load(args.capture)
    record, generated, sources = identity(args.kernel_root)
    objects = validate_capture(captured, record)
    metadata = {"format": "osrec-standalone-syscall-session-v1", "capture": captured,
                "executed_kernel_code": ["SysRead"], "kernel_license": generated[:generated.index("*/")+2],
                "state_contract": "typed process/buffer/file objects; sequential calls; modeled 32-bit file cursors",
                "modeled_dependencies": ["user syscall entry and errno adapter", "user address range", "descriptor mapping", "VFS read and file cursor"],
                "scheduler_irq_execution": False, "symbolic_equivalence_verified": False}
    main = main_source(captured, objects, metadata=metadata)
    args.out.resolve().parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="osrec-syscall-export-") as directory:
        stage = Path(directory)
        binary = build(stage, generated, sources, main, args.compiler)
        libraries = dependencies(binary)
        with tempfile.TemporaryDirectory(prefix="osrec-syscall-alone-") as isolated:
            copied = Path(isolated) / "scenario"
            shutil.copy2(binary, copied)
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
            verified = run([copied], cwd=isolated, env=env).stdout.strip()
            if json.loads(run([copied, "--describe"], cwd=isolated, env=env).stdout) != metadata:
                raise ValueError("embedded checkpoint identity differs")
        manifest = {"metadata": metadata, "artifact_sha256": digest(binary.read_bytes()),
                    "artifact_bytes": binary.stat().st_size, "system_libraries": libraries, "isolated_execution": verified}
        # Source bundle is review material, unnecessary at runtime.
        review = Path(str(args.out) + ".sources")
        if review.is_symlink() or (review.exists() and not review.is_dir()):
            raise ValueError("source review destination must be an ordinary directory")
        review.mkdir(exist_ok=True)
        if any(path.is_symlink() for path in review.rglob("*")):
            raise ValueError("source review directory cannot contain symbolic links")
        for source in stage.iterdir():
            if source.is_file() and source != binary:
                shutil.copy2(source, review / source.name)
        (review / "osrec").mkdir(exist_ok=True)
        shutil.copy2(stage / "osrec/checkpoint.h", review / "osrec/checkpoint.h")
        Path(str(args.out) + ".manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        publish(args.out, binary=binary)
    print(json.dumps({"executable": str(args.out.resolve()), "verification": verified, "bytes": manifest["artifact_bytes"]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("capture", "export"):
        child = commands.add_parser(name)
        child.add_argument("--kernel-root", required=True, type=Path)
        child.add_argument("--compiler", default="cc")
        child.add_argument("--out", required=True, type=Path)
        child.add_argument("--case" if name == "capture" else "--capture", required=True, type=Path)
        if name == "capture":
            child.add_argument("--reads",type=Path,help="recorded backend-read stream; --case then supplies only the entry/call manifest")
            child.add_argument("--source-kind",choices=("host-file","qemu","emulator","board"))
    args = parser.parse_args()
    try:
        compiler = shutil.which(args.compiler)
        if not compiler:
            raise ValueError("compiler is unavailable")
        protected = {Path(compiler).resolve(), Path(__file__).resolve(),
                     *(path.resolve() for path in INTEGRATION.iterdir() if path.is_file()),
                     ROOT / "runtime/checkpoint.c", ROOT / "include/osrec/checkpoint.h",
                     *(ROOT / "tools" / name for name in ("export_sysread.py", "object_checkpoint.py", "export_object_checkpoint.py", "klee_liteos.py", "read_observations.py", "record_host_reads.py")),
                     Path(args.case if args.command == "capture" else args.capture).resolve()}
        if args.command == "capture" and args.reads:
            protected.add(args.reads.resolve())
        output = args.out.resolve()
        if any(Path(str(output)+suffix).resolve() in protected for suffix in ("", ".manifest.json", ".sources")) or output.is_relative_to(args.kernel_root.resolve()):
            raise ValueError("output cannot overwrite construction inputs or kernel sources")
        args.compiler = compiler
        (capture if args.command == "capture" else export)(args)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        print(f"syscall checkpoint rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
