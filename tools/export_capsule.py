#!/usr/bin/env python3
"""Export the explicitly supported budget demo schema as standalone C.

This is a schema-specific proof of capture/replay, not a kernel source slicer.
"""
import argparse
import hashlib
from pathlib import Path
import struct

REGION = Path(__file__).resolve().parents[1] / "examples" / "region.h"
LAYOUT = [(1, 0, 64), (2, 10, 24), (3, 20, 8), (4, 30, 16), (5, 0, 0)]


def decode(data: bytes, source: bytes) -> tuple[int, ...]:
    if data[:8] != b"OSRC\x01\x00\x00\x00":
        raise ValueError("invalid trace header or unsupported version")
    offset = 8
    payloads = []
    for expected in LAYOUT:
        if len(data) - offset < 12:
            raise ValueError("incomplete record header")
        kind, site, size = struct.unpack_from("<III", data, offset)
        offset += 12
        if (kind, site, size) != expected:
            raise ValueError("unexpected record kind, site, size or order")
        if size > len(data) - offset:
            raise ValueError("incomplete record payload")
        payloads.append(data[offset:offset + size])
        offset += size
    if offset != len(data):
        raise ValueError("trailing records after capture end")
    if payloads[0] != hashlib.sha256(source).hexdigest().encode("ascii"):
        raise ValueError("recorded source fingerprint does not match region.h")
    return struct.unpack("<QQQ", payloads[1]) + struct.unpack("<Q", payloads[2]) + struct.unpack("<QQ", payloads[3])


def export(data: bytes, source: bytes) -> str:
    credits, deadline, demand, now, remaining, granted = decode(data, source)
    return f"""/* Generated OSREC demo capsule. Compile with a C11 compiler.
 * Source SHA256: {hashlib.sha256(source).hexdigest()}
 * Functional replay only; host timing is not kernel performance evidence.
 */
{source.decode('utf-8')}
#include <stdio.h>

struct replay_clock {{ unsigned calls; }};
static uint64_t replay_now(void *opaque)
{{
    struct replay_clock *clock = opaque;
    ++clock->calls;
    return UINT64_C({now});
}}

int main(void)
{{
    struct budget state = {{UINT64_C({credits}), UINT64_C({deadline})}};
    struct replay_clock clock = {{0}};
    uint64_t result = take_budget(&state, UINT64_C({demand}), replay_now, &clock);
    if (clock.calls != 1 || state.credits != UINT64_C({remaining}) ||
        result != UINT64_C({granted})) {{
        fputs("replay diverged\\n", stderr);
        return 1;
    }}
    puts("replay verified");
    return 0;
}}
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        # Exact size for this fixed schema; reject oversized input before reading.
        expected_size = 8 + sum(12 + size for _, _, size in LAYOUT)
        with args.trace.open("rb") as stream:
            data = stream.read(expected_size + 1)
        generated = export(data, REGION.read_bytes())
        args.output.write_text(generated, encoding="utf-8")
    except (OSError, ValueError) as error:
        parser.exit(1, f"export failed: {error}\n")


if __name__ == "__main__":
    main()
