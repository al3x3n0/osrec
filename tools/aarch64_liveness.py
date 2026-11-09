"""Conservative local liveness for future EL0 call veneers.

Analyse ORIGINAL instructions, before rewriting. Missing code, calls, exits,
memory accesses and undecoded instructions observe all state. In particular, a
potential fault can expose registers to the captured exception handler even if
the normal continuation overwrites them. No ABI assumptions about kernel asm
are made. This deliberately small decoder is an optimisation whitelist.
"""
from collections import deque
from dataclasses import dataclass

SP = 1 << 31
NZCV = 1 << 32
SIMD = ((1 << 32) - 1) << 33
FPCR = 1 << 65
FPSR = 1 << 66
ALL = (1 << 67) - 1


def reg(n, sp=False):
    """Wn and Xn share a liveness bit; a W write also kills the old X value."""
    return 1 << n if n < 31 else SP if sp else 0


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


@dataclass(frozen=True)
class Effect:
    uses: int
    defines: int
    successors: tuple


def effect(pc, word):
    """Unknown semantics are an all-state observation with no proven kills."""
    nxt = (pc + 4,)
    rd, rn, rm = word & 31, word >> 5 & 31, word >> 16 & 31
    if word == 0xd503201f:  # NOP only; other hints can have side effects
        return Effect(0, 0, nxt)
    if word & 0x7c000000 == 0x14000000:  # B / BL immediate
        if word & 0x80000000:  # unknown callee may inspect everything but old LR
            return Effect(ALL & ~reg(30), reg(30), nxt)
        return Effect(0, 0, (pc + 4 * signed(word & 0x3ffffff, 26),))
    if word & 0xff000010 == 0x54000000:  # B.cond
        target = pc + 4 * signed(word >> 5 & 0x7ffff, 19)
        return Effect(NZCV, 0, (pc + 4, target))
    if word & 0x7e000000 == 0x34000000:  # CBZ / CBNZ
        target = pc + 4 * signed(word >> 5 & 0x7ffff, 19)
        return Effect(reg(rd), 0, (pc + 4, target))
    if word & 0x7e000000 == 0x36000000:  # TBZ / TBNZ
        target = pc + 4 * signed(word >> 5 & 0x3fff, 14)
        return Effect(reg(rd), 0, (pc + 4, target))
    if word & 0x1f800000 == 0x12800000:  # MOVN / MOVZ / MOVK
        opc, hw = word >> 29 & 3, word >> 21 & 3
        if opc != 1 and (word >> 31 or hw < 2):
            return Effect(reg(rd) if opc == 3 else 0, reg(rd), nxt)
    if word & 0x1f800000 == 0x11000000:  # ADD/SUB immediate
        sets_flags = bool(word & (1 << 29))
        return Effect(reg(rn, sp=True), reg(rd, sp=not sets_flags) |
                      (NZCV if sets_flags else 0), nxt)
    if word & 0x1f200000 == 0x0b000000:  # ADD/SUB shifted register
        if word >> 22 & 3 != 3 and (word >> 31 or not word & (1 << 15)):
            return Effect(reg(rn) | reg(rm), reg(rd) |
                          (NZCV if word & (1 << 29) else 0), nxt)
    if word & 0x1f000000 == 0x0a000000:  # logical shifted register
        if word >> 31 or not word & (1 << 15):
            return Effect(reg(rn) | reg(rm), reg(rd) |
                          (NZCV if word >> 29 & 3 == 3 else 0), nxt)
    if word & 0x1f000000 == 0x10000000:  # ADR / ADRP
        return Effect(0, reg(rd), nxt)
    # NZCV accesses are legal at EL0 and have fully known register semantics.
    if word & ~31 == 0xd53b4200:  # MRS Xt, NZCV
        return Effect(NZCV, reg(rd), nxt)
    if word & ~31 == 0xd51b4200:  # MSR NZCV, Xt
        return Effect(reg(rd), NZCV, nxt)
    return Effect(ALL, 0, ())


def live_after(words, pc, max_instructions=4096):
    """Return state live at pc+4; words maps original VA to word.

    Follow direct control flow and solve loops to a fixed point. Exceeding the
    local analysis budget loses the optimisation, never a required save.
    This is for fall-through sites, not ERET, syscall entry or other sites that
    select a different continuation/context.
    """
    pending = [pc + 4]
    graph = {}
    while pending:
        at = pending.pop()
        if at in graph:
            continue
        if len(graph) >= max_instructions:
            return ALL
        e = effect(at, words[at]) if at in words else Effect(ALL, 0, ())
        graph[at] = e
        pending.extend(e.successors)
    predecessors = {at: set() for at in graph}
    for at, e in graph.items():
        for successor in e.successors:
            predecessors[successor].add(at)
    live = dict.fromkeys(graph, 0)
    queue = deque(graph)
    queued = set(graph)
    while queue:
        at = queue.popleft()
        queued.remove(at)
        e = graph[at]
        out = 0
        for successor in e.successors:
            out |= live[successor]
        value = e.uses | (out & ~e.defines)
        if value != live[at]:
            live[at] = value
            for predecessor in predecessors[at] - queued:
                queue.append(predecessor)
                queued.add(predecessor)
    return live[pc + 4]


def preservation_mask(live, clobbers, outputs=0):
    """Old values to preserve; handler inputs/output delivery are separate.

    clobbers must include the entire veneer/callee path, including BL's x30 and
    any compiler scratch or flag use. outputs means unconditional full-register
    definitions by the original instruction, not merely possible writes.
    """
    return live & clobbers & ~outputs


def names(mask):
    return ([f'x{i}' for i in range(31) if mask & reg(i)] +
            (['sp'] if mask & SP else []) + (['nzcv'] if mask & NZCV else []) +
            [f'v{i}' for i in range(32) if mask & (1 << (33 + i))] +
            (['fpcr'] if mask & FPCR else []) + (['fpsr'] if mask & FPSR else []))
