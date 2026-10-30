#!/usr/bin/env python3
"""Validate and export the blocking task / nested IRQ host demonstration.

Supports one explicit continuation schema, not arbitrary kernel extraction.
"""
import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct

REGION = Path(__file__).resolve().parents[1] / "examples" / "task_region.h"
IRQ_BASE = 1 << 63
MAX_BYTES = 4096
# Stable sites and event types for the supported demo's continuation boundaries.
SCHEMA = [(200, 1), (210, 2), (220, 3), (230, 5), (240, 3),
          (250, 5), (260, 6), (270, 4), (280, 6), (290, 7),
          (300, 4), (310, 2), (320, 8)]
NAMES = {1: "block", 2: "switch", 3: "IRQ enter", 4: "IRQ exit",
         5: "device input", 6: "memory effect", 7: "wake", 8: "return"}


@dataclass(frozen=True)
class Event:
    site: int
    sequence: int
    cpu: int
    context: int
    parent: int
    task: int
    kind: int
    a: int
    b: int


@dataclass(frozen=True)
class Capture:
    selected_task: int
    initial_tasks: tuple[int, ...]
    available: int
    demand: int
    events: tuple[Event, ...]
    remaining: int
    result: int


def records(data: bytes) -> list[tuple[int, int, bytes]]:
    if len(data) > MAX_BYTES:
        raise ValueError("capture exceeds demo size bound")
    if data[:8] != b"OSRC\x01\x00\x00\x00":
        raise ValueError("invalid header or unsupported version")
    out = []
    position = 8
    while position < len(data):
        if len(data) - position < 12:
            raise ValueError("incomplete record header")
        kind, site, size = struct.unpack_from("<III", data, position)
        position += 12
        if size > len(data) - position:
            raise ValueError("incomplete record payload")
        out.append((kind, site, data[position:position + size]))
        position += size
    return out


def values(record, kind, site, count=None) -> tuple[int, ...]:
    k, s, payload = record
    if k != kind or s != site or len(payload) % 8 or (
            count is not None and len(payload) != count * 8):
        raise ValueError("unexpected record kind, site or payload size")
    return struct.unpack("<" + "Q" * (len(payload) // 8), payload)


def decode(data: bytes, source: bytes) -> Capture:
    trace = records(data)
    if len(trace) != len(SCHEMA) + 5:
        raise ValueError("incomplete or unsupported task transcript")
    expected_hash = hashlib.sha256(source).hexdigest().encode("ascii")
    if trace[0] != (1, 0, expected_hash):
        raise ValueError("source fingerprint mismatch or missing BEGIN")
    config = values(trace[1], 2, 100)
    if len(config) < 3:
        raise ValueError("invalid CPU configuration")
    cpu_count, selected, *initial_tasks = config
    if not 1 <= cpu_count <= 4 or len(initial_tasks) != cpu_count or (
            not 0 < selected < IRQ_BASE) or initial_tasks.count(selected) != 1 or (
            len(set(initial_tasks)) != cpu_count) or any(
            not 0 < task < IRQ_BASE for task in initial_tasks):
        raise ValueError("invalid CPU/task configuration")
    available, demand = values(trace[2], 2, 110, 2)
    remaining, result = values(trace[-2], 4, 330, 2)
    if trace[-1] != (5, 0, b""):
        raise ValueError("missing END or trailing events")

    tasks = list(initial_tasks)
    stacks = [[] for _ in tasks]
    seen_irqs = set()
    blocked = False
    returned = False
    wait = None
    events = []
    pending_input = {}
    applied = set()
    for sequence, ((site, kind), record) in enumerate(zip(SCHEMA, trace[3:-2])):
        e = Event(site, *values(record, 6, site, 8))
        if e.sequence != sequence or e.kind != kind or e.cpu >= cpu_count or returned:
            raise ValueError("invalid event sequence, type, CPU or task lifetime")
        stack = stacks[e.cpu]
        current = stack[-1] if stack else tasks[e.cpu]
        if kind == 3:
            if e.context < IRQ_BASE or e.context in seen_irqs or len(stack) >= 4 or (
                    e.parent != current) or e.a or e.b:
                raise ValueError("invalid IRQ identity, parent or nesting")
            seen_irqs.add(e.context)
            stack.append(e.context)
        current = stack[-1] if stack else tasks[e.cpu]
        parent = stack[-2] if len(stack) > 1 else tasks[e.cpu] if stack else 0
        if (e.context, e.parent, e.task) != (current, parent, tasks[e.cpu]):
            raise ValueError("event does not belong to the current context")

        if kind == 1:
            if stack or e.task != selected or blocked or not e.a or not e.b:
                raise ValueError("invalid task block")
            blocked = True
            wait = (e.a, e.b)
        elif kind == 2:
            if stack or e.a != tasks[e.cpu] or not 0 < e.b < IRQ_BASE or e.a == e.b or (
                    e.b == selected and blocked) or any(
                    task == e.b for cpu, task in enumerate(tasks) if cpu != e.cpu):
                raise ValueError("invalid switch or concurrent task execution")
            tasks[e.cpu] = e.b
        elif kind == 4:
            if not stack or e.a or e.b or e.context not in applied:
                raise ValueError("unbalanced IRQ exit or unconsumed device input")
            stack.pop()
        elif kind == 5:
            expected_object = 9 if site == 230 else 10
            if not stack or e.a != expected_object or e.context in pending_input:
                raise ValueError("invalid device input boundary")
            pending_input[e.context] = e.b
        elif kind == 6:
            if not stack or e.a != 1 or e.context not in pending_input or e.context in applied:
                raise ValueError("invalid handler effect boundary")
            applied.add(e.context)
        elif kind == 7:
            if not blocked or (e.a, e.b) != wait:
                raise ValueError("wake does not match the blocked object generation")
            blocked = False
        elif kind == 8:
            if stack or blocked or e.task != selected or e.b or any(stacks):
                raise ValueError("task returned with unfinished contexts")
            if e.a != result:
                raise ValueError("return event does not match expected output")
            returned = True
        events.append(e)
    if not returned or blocked or any(stacks) or seen_irqs != applied:
        raise ValueError("incomplete contexts or dependency transcript")
    return Capture(selected, tuple(initial_tasks), available, demand,
                   tuple(events), remaining, result)


def export(data: bytes, source: bytes) -> str:
    capture = decode(data, source)
    statements = []
    for e in capture.events:
        statements.append(f"    /* Event {e.sequence}: {NAMES[e.kind]}, CPU {e.cpu}, site {e.site}. */")
        if e.kind == 1:
            statements.append("    if (task_step(&state, demand, &result)) return diverged();")
        elif e.kind == 5:
            statements.append(f"    const uint64_t irq_{e.context}_input = UINT64_C({e.b});")
        elif e.kind == 6:
            statements.extend([
                f"    complete_irq(&state, irq_{e.context}_input);",
                f"    if (state.available != UINT64_C({e.b})) return diverged();"])
        elif e.kind == 7:
            statements.append("    if (state.available < demand) return diverged();")
        elif e.kind == 2 and e.b == capture.selected_task:
            statements.append("    if (!task_step(&state, demand, &result)) return diverged();")
        elif e.kind == 8:
            statements.append(f"    if (result != UINT64_C({e.a})) return diverged();")
    return f"""/* OSREC host task continuation capsule.
 * Source SHA256: {hashlib.sha256(source).hexdigest()}
 * Models recorded boundaries, nested IRQ effects and task resumption.
 * Does not implement a real scheduler or instruction-position IRQ injection.
 */
{source.decode('utf-8')}
#include <stdio.h>
static int diverged(void)
{{
    fputs("task replay diverged\\n", stderr);
    return 1;
}}
int main(void)
{{
    struct completion_state state = {{UINT64_C({capture.available})}};
    const uint64_t demand = UINT64_C({capture.demand});
    uint64_t result = 0;
{chr(10).join(statements)}
    if (state.available != UINT64_C({capture.remaining}) ||
        result != UINT64_C({capture.result})) return diverged();
    puts("task replay verified");
    return 0;
}}
"""


def label(context: int) -> str:
    if not context:
        return "-"
    return f"irq{context - IRQ_BASE}" if context >= IRQ_BASE else f"task{context}"


def inspect(capture: Capture) -> str:
    lines = [" seq  cpu  context   parent    event          site  a / b"]
    for e in capture.events:
        lines.append(f"{e.sequence:4}  {e.cpu:3}  {label(e.context):9} {label(e.parent):9} "
                     f"{NAMES[e.kind]:14} {e.site:4}  {e.a} / {e.b}")
    lines.append(f"output: remaining={capture.remaining}, result={capture.result}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--inspect", action="store_true", help="validate and print the context transcript")
    args = parser.parse_args()
    if not args.inspect and args.output is None:
        parser.error("provide an output C file or --inspect")
    try:
        with args.trace.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        source = REGION.read_bytes()
        if args.inspect:
            print(inspect(decode(data, source)))
        if args.output is not None:
            args.output.write_text(export(data, source), encoding="utf-8")
    except (OSError, ValueError) as error:
        parser.exit(1, f"task export failed: {error}\n")


if __name__ == "__main__":
    main()
