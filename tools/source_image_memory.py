"""Canonical user-memory snapshots for source-image/native differential recordings.

Only EL0-accessible leaves are sampled. Page-table pages and physical placement
are excluded from the digest: native and relocated images can use different PFNs.
Invalid and privileged table paths are skipped. Reads use QEMU physical mode and
always restore virtual mode, including on a failed read.
"""
import hashlib
import struct
from kernel_boundary_capture import physical

MASK48 = (1 << 48) - 1


def snapshot(remote, root, tcr, ram_range=None):
    if tcr >> 14 & 3:
        raise ValueError('user-memory comparison requires a 4 KiB TTBR0 granule')
    bits = 64 - (tcr & 63)
    if not 25 <= bits <= 48:
        raise ValueError('unsupported TTBR0 address size')
    start = 3 - (bits - 13) // 9
    pages = []
    def read(pa):
        if ram_range is not None and not (ram_range[0]<=pa and pa+4096<=ram_range[1]):
            raise ValueError('user-memory comparison refuses non-RAM page at 0x%x'%pa)
        return remote.read(pa,4096)
    physical(remote, True)
    try:
        def walk(table, level, prefix, privileged=False):
            shift = 12 + 9 * (3 - level)
            count = 1 << (bits - shift) if level == start else 512
            data = read(table)
            for i in range(count):
                d, = struct.unpack_from('<Q', data, i * 8)
                if not d & 1:
                    continue
                va = prefix | i << shift
                if level < 3 and d & 2:
                    walk(d & MASK48 & ~4095, level + 1, va, privileged or bool(d & (1 << 61)))
                    continue
                if privileged or not d & (1 << 6) or (level == 3 and not d & 2):
                    continue
                pa = d & MASK48 & ~((1 << shift) - 1)
                for offset in range(0, 1 << shift, 4096):
                    content = read(pa + offset)
                    pages.append([hex(va + offset), hashlib.sha256(content).hexdigest()])
        walk(root & MASK48 & ~4095, start, 0)
    finally:
        physical(remote, False)
    return pages
