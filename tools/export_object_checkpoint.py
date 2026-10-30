#!/usr/bin/env python3
"""Package the supported typed completion checkpoint as one host executable."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from export_sysread import dependencies
from object_checkpoint import ObjectType, Reference, byte_string, keys, unsigned, validate_graph

ROOT = Path(__file__).resolve().parents[1]
REGION = ROOT / "examples/object_region.h"
HEADER = ROOT / "include/osrec/checkpoint.h"
RUNTIME = ROOT / "runtime/checkpoint.c"
SCHEMAS = {
    "completion": ObjectType({"credits": "u32", "next": Reference("completion", nullable=True)}),
    "bytes": ObjectType(),
    "task": ObjectType({"wait": Reference("completion"), "alias": Reference("completion"),
                        "cursor": Reference("bytes", extent=3), "view": Reference("bytes")}),
}
ROOTS = {"current_task": Reference("task")}
SCHEMA_IDS = {"completion": 1, "bytes": 2, "task": 3}
TYPES = {"completion": "struct completion_object", "task": "struct task_object"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON field")
        result[name] = value
    return result


def decode(data, source):
    document = json.loads(data, object_pairs_hook=unique_pairs)
    keys(document, ("format", "schema", "source_sha256", "boundary", "demand", "roots", "objects", "expected"), "checkpoint")
    if (document["format"] != "osrec-object-checkpoint-v1" or document["schema"] != "completion-demo-v1"
            or document["boundary"] != "object_scenario entry" or document["source_sha256"] != digest(source)):
        raise ValueError("unsupported schema/boundary or stale source fingerprint")
    unsigned(document["demand"], 32, "demand")
    objects = validate_graph(document["objects"], document["roots"], SCHEMAS, ROOTS)
    groups = {kind: [entry for entry in objects.values() if entry["type"] == kind] for kind in SCHEMAS}
    if (len(groups["completion"]) != 2 or len(groups["task"]) != 1 or len(groups["bytes"]) != 1
            or len(groups["bytes"][0]["data"]) != 16):
        raise ValueError("scenario requires two completions, one task and one 8-byte buffer")
    task = objects[document["roots"]["current_task"]["object"]]["fields"]
    first = objects[task["wait"]["object"]]
    next_ref = first["fields"]["next"]
    second = objects.get(next_ref["object"])
    if (task["alias"] != task["wait"] or not second or second["id"] == first["id"]
            or second["fields"]["next"] != task["wait"]
            or task["cursor"]["object"] != task["view"]["object"]
            or task["view"]["offset"] != task["cursor"]["offset"] + 2):
        raise ValueError("scenario alias, cycle or buffer-view invariant is invalid")
    expected = document["expected"]
    keys(expected, ("return", "credits", "buffers"), "expected")
    unsigned(expected["return"], 32, "expected return")
    keys(expected["credits"], [str(entry["id"]) for entry in groups["completion"]], "expected credits")
    keys(expected["buffers"], [str(entry["id"]) for entry in groups["bytes"]], "expected buffers")
    for value in expected["credits"].values():
        unsigned(value, 32, "expected credits")
    for value in expected["buffers"].values():
        if len(byte_string(value, "expected buffer")) != 8:
            raise ValueError("expected buffer size differs from the checkpoint")
    return document, objects


def generate(document, objects, source, header, runtime):
    metadata = {"format": "osrec-standalone-object-v1", "checkpoint": document,
                "provenance": "host completion model capture; not a live kernel checkpoint",
                "state_contract": "typed fields, closed object graph, stable ownership at entry",
                "layout_contract": "host structures rebuilt fieldwise; only bytes use interior offsets",
                "runtime_sha256": digest(runtime), "header_sha256": digest(header),
                "scheduler_irq_execution": False, "symbolic_equivalence_verified": False}
    lines = []
    for identifier, entry in sorted(objects.items()):
        name = f"object_{identifier}"
        if entry["type"] == "bytes":
            values = ",".join(str(value) for value in bytes.fromhex(entry["data"]))
            lines.append(f"    uint8_t {name}[] = {{{values}}};")
        else:
            lines.append(f"    {TYPES[entry['type']]} {name} = {{0}};")
            for field, contract in SCHEMAS[entry["type"]].fields.items():
                if contract == "u32":
                    lines.append(f"    {name}.{field} = UINT32_C({entry['fields'][field]});")
    lines += [f"    struct osrec_object storage[{len(objects)}];", "    struct osrec_object_table table;",
              f"    if (!osrec_objects_init(&table, storage, {len(objects)})) return 1;"]
    for identifier, entry in sorted(objects.items()):
        lines.append(f"    if (!osrec_object_add(&table, UINT64_C({identifier}), {SCHEMA_IDS[entry['type']]},"
                     f" &object_{identifier}, sizeof(object_{identifier}))) return 1;")

    def resolve(reference, contract, assignment):
        extent = str(contract.extent) if contract.target == "bytes" else f"sizeof({TYPES[contract.target]})"
        lines.append("    { void *resolved;")
        lines.append(f"      if (!osrec_object_resolve(&table, (struct osrec_object_ref)"
                     f"{{UINT64_C({reference['object']}), UINT64_C({reference['offset']})}},"
                     f" {extent}, {SCHEMA_IDS[contract.target]}, &resolved)) return 1;")
        lines.append(f"      {assignment} = resolved; }}")

    for identifier, entry in sorted(objects.items()):
        for field, contract in (SCHEMAS[entry["type"]].fields or {}).items():
            if isinstance(contract, Reference):
                resolve(entry["fields"][field], contract, f"object_{identifier}.{field}")
    lines.append("    struct task_object *current_task;")
    resolve(document["roots"]["current_task"], ROOTS["current_task"], "current_task")
    lines.append(f"    uint32_t actual = object_scenario(current_task, UINT32_C({document['demand']}));")
    checks = [f"actual != UINT32_C({document['expected']['return']})"]
    for identifier, value in document["expected"]["credits"].items():
        checks.append(f"object_{identifier}.credits != UINT32_C({value})")
    for identifier, value in document["expected"]["buffers"].items():
        for offset, byte in enumerate(bytes.fromhex(value)):
            checks.append(f"object_{identifier}[{offset}] != {byte}")
    lines.append("    if (" + " ||\n        ".join(checks) + ") { fputs(\"object replay diverged\\n\", stderr); return 1; }")
    lines.append('    printf("object replay verified: return=%" PRIu32 "\\n", actual);')
    lines.append("    return 0;")
    description = json.dumps(json.dumps(metadata, sort_keys=True))
    runtime_text = runtime.decode().replace('#include "osrec/checkpoint.h"', '', 1)
    generated = (header.decode() + "\n" + runtime_text + "\n" + source.decode()
                 + '\n#include <stdio.h>\n#include <string.h>\n#include <inttypes.h>\n'
                 + "int main(int argc, char **argv) {\n"
                 + f'    if (argc == 2 && strcmp(argv[1], "--describe") == 0) {{ puts({description}); return 0; }}\n'
                 + "    if (argc != 1) return 2;\n" + "\n".join(lines) + "\n}\n")
    return generated, metadata


def export(args):
    source, header, runtime = REGION.read_bytes(), HEADER.read_bytes(), RUNTIME.read_bytes()
    with args.checkpoint.open("rb") as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError("checkpoint exceeds 64 KiB")
    document, objects = decode(data, source)
    generated, metadata = generate(document, objects, source, header, runtime)
    destination = args.out.resolve()
    protected = {args.checkpoint.resolve(), REGION, HEADER, RUNTIME, Path(__file__).resolve(),
                 ROOT / "tools/object_checkpoint.py", ROOT / "tools/export_sysread.py"}
    compiler_path = shutil.which(str(args.compiler))
    if not compiler_path:
        raise ValueError("compiler executable is unavailable")
    protected.add(Path(compiler_path).resolve())
    if any(Path(str(destination) + suffix).resolve() in protected for suffix in ("", ".c", ".manifest.json")):
        raise ValueError("output cannot overwrite construction inputs")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="osrec-objects-") as directory:
        stage = Path(directory)
        path, binary = stage / "scenario.c", stage / "scenario"
        path.write_text(generated)
        # Keep the computation and reconstruction visible during this prototype;
        # do not fold a constant checkpoint into a precomputed result.
        subprocess.run([compiler_path, "-std=c11", "-O0", "-fno-lto", "-Wall", "-Wextra", "-Werror", str(path), "-o", str(binary)],
                       check=True, capture_output=True, text=True, timeout=60)
        libraries = dependencies(binary)
        with tempfile.TemporaryDirectory(prefix="osrec-objects-isolated-") as isolated:
            copied = Path(isolated) / "scenario"
            shutil.copy2(binary, copied)
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
            result = subprocess.run([str(copied)], cwd=isolated, env=env, text=True,
                                    check=True, capture_output=True, timeout=10).stdout.strip()
            description = subprocess.run([str(copied), "--describe"], cwd=isolated, env=env, text=True,
                                         check=True, capture_output=True, timeout=10).stdout
            if json.loads(description) != metadata:
                raise ValueError("embedded description differs from the checkpoint")
        manifest = {"metadata": metadata, "artifact_sha256": digest(binary.read_bytes()),
                    "artifact_bytes": binary.stat().st_size, "system_libraries": libraries,
                    "isolated_execution": result, "capture_sha256": digest(data)}
        Path(str(destination) + ".c").write_text(generated)
        Path(str(destination) + ".manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        with tempfile.NamedTemporaryFile(prefix=".osrec-objects-", dir=destination.parent, delete=False) as pending:
            pending_path = Path(pending.name)
        try:
            shutil.copy2(binary, pending_path)
            os.replace(pending_path, destination)
        finally:
            pending_path.unlink(missing_ok=True)
    print(json.dumps({"executable": str(destination), "objects": len(objects), "verification": result}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--compiler", default="cc")
    args = parser.parse_args()
    try:
        export(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        print(f"object checkpoint export rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
