"""Stack-free linked veneers for the simple EL1 shadow-register edge.

Only non-faulting, non-stopping shadow field operations are eligible. Other
instructions keep the shared trap emulator. The two temporary registers are
the complete clobber set; no generated instruction writes NZCV or SIMD state.
osrec_branch_state is a private 16-byte spill area immediately before shadow.
Shared-root builds can borrow the hardware TPIDR_EL0 for an address spill.
Single CPU / non-reentrant execution is required, as in the mini-OS backend.
"""
from dataclasses import dataclass

from aarch64_liveness import ALL, live_after, names, preservation_mask, reg

BRANCH_PA = 0x74000000
RESERVATION = 4 << 20


def sysreg(op0, op1, crn, crm, op2):
    return (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2


TPIDR_EL1 = sysreg(3, 0, 13, 0, 4)
TPIDR_EL0 = sysreg(3, 3, 13, 0, 2)
SHADOW_VALUES_OFFSET = 13 * 8 + 65536 // 8


# These offsets are checked against el0.h by the execution test harness.
FIELDS = {
    sysreg(3, 0, 4, 1, 0): (0, 'plain'),   # SP_EL0
    sysreg(3, 4, 4, 1, 0): (8, 'plain'),   # SP_EL1
    sysreg(3, 0, 4, 0, 1): (16, 'plain'),  # ELR_EL1
    sysreg(3, 0, 4, 0, 0): (24, 'plain'),  # SPSR_EL1
    sysreg(3, 0, 5, 2, 0): (32, 'plain'),  # ESR_EL1
    sysreg(3, 0, 6, 0, 0): (40, 'plain'),  # FAR_EL1
    sysreg(3, 3, 4, 2, 1): (48, 'daif'),   # DAIF
    sysreg(3, 0, 4, 2, 3): (56, 'pan'),    # PAN
    sysreg(3, 0, 12, 0, 0): (64, 'plain'), # VBAR_EL1
    sysreg(3, 0, 2, 0, 0): (72, 'readonly'), # TTBR0_EL1 (writes need platform)
    sysreg(3, 0, 4, 2, 2): (None, 'currentel'),
}
EMULATED_OFFSET = 88


def branch(pc, target):
    distance = target - pc
    if distance % 4 or not -(1 << 27) <= distance < (1 << 27):
        raise ValueError('emulation veneer is outside immediate branch range')
    return 0x14000000 | ((distance // 4) & 0x3ffffff)


@dataclass(frozen=True)
class Veneer:
    pc: int
    insn: int
    read: bool
    offset: int | None
    kind: str
    address: int
    temporary: int
    live: int
    saves: int

    def instructions(self, continuation):
        a, b = f'x{self.address}', f'x{self.temporary}'
        rt = f'x{self.insn & 31}' if self.insn & 31 != 31 else 'xzr'
        spill_address = self.saves & reg(self.address)
        spill_temporary = self.saves & reg(self.temporary)
        code = [f'msr tpidr_el0, {a}'] if spill_address else []
        code += [f'adrp {a}, osrec_branch_state',
                 f'add {a}, {a}, :lo12:osrec_branch_state']
        if spill_temporary:
            code.append(f'str {b}, [{a}]')
        code += [f'ldr {b}, [{a}, #{16 + EMULATED_OFFSET}]',
                 f'add {b}, {b}, #1',
                 f'str {b}, [{a}, #{16 + EMULATED_OFFSET}]']
        if not self.read:
            value = rt
            if self.kind == 'daif':
                code.append(f'and {b}, {rt}, #0x3c0')
                value = b
            elif self.kind == 'pan':
                code += [f'lsr {b}, {rt}, #22', f'and {b}, {b}, #1']
                value = b
            if self.kind in ('daifset', 'daifclr'):
                mask = self.insn >> 8 & 15
                if mask:
                    op = 'orr' if self.kind == 'daifset' else 'bic'
                    code.append(f'ldr {b}, [{a}, #{16 + self.offset}]')
                    for bit in range(4):
                        if mask & (1 << bit):
                            code.append(f'{op} {b}, {b}, #{1 << (bit + 6)}')
                    code.append(f'str {b}, [{a}, #{16 + self.offset}]')
            else:
                code.append(f'str {value}, [{a}, #{16 + self.offset}]')
        if spill_temporary:
            code.append(f'ldr {b}, [{a}]')
        if self.read and rt != 'xzr':
            if self.kind == 'currentel':
                code.append(f'mov {rt}, #4')
            elif self.kind == 'percpu':
                code += [f'adrp {rt}, osrec_branch_tpidr',
                         f'ldr {rt}, [{rt}, :lo12:osrec_branch_tpidr]']
            else:
                code.append(f'ldr {rt}, [{a}, #{16 + self.offset}]')
                if self.kind == 'pan':
                    code.append(f'lsl {rt}, {rt}, #22')
        if spill_address:
            code.append(f'mrs {a}, tpidr_el0')
        return code + [f'b {continuation}']

    def report(self):
        return dict(pc=hex(self.pc), insn=hex(self.insn), live=names(self.live),
                    saves=names(self.saves), scratch=names(reg(self.address) | reg(self.temporary)),
                    saves_nzcv=False, stack_bytes=0)


def shadow_operation(insn, percpu=False):
    family = insn & 0xfff00000
    immediate = insn & 0xfffff0ff
    if immediate in (0xd50340df, 0xd50340ff):
        return False, FIELDS[sysreg(3, 3, 4, 2, 1)][0], 'daifset' if immediate == 0xd50340df else 'daifclr'
    if family not in (0xd5300000, 0xd5100000):
        return None
    key = insn >> 5 & 0xffff
    read = family == 0xd5300000
    if percpu and read and key == TPIDR_EL1:
        return True, SHADOW_VALUES_OFFSET + key * 8, 'percpu'
    field = FIELDS.get(key)
    if field is None:
        return None
    offset, kind = field
    if not read and kind in ('readonly', 'currentel'):
        return None
    return read, offset, kind


def plan(pc, insn, live=ALL, *, percpu=False, tls_spill=False):
    operation = shadow_operation(insn, percpu)
    if operation is None:
        return None
    read, offset, kind = operation
    inputs = 0 if read or kind in ('daifset', 'daifclr') else reg(insn & 31)
    outputs = reg(insn & 31) if read else 0
    # Prefer the output or a dead register as the address. The shared-root
    # monitor can loan TPIDR_EL0 when the original address register is live.
    order = [16, 17] + [r for r in range(31) if r not in (16, 17, 18)]
    available = [r for r in order if not reg(r) & inputs and
                 (reg(r) & outputs or not reg(r) & live)]
    if not available:
        if not tls_spill:
            return None
        available = [r for r in order if not reg(r) & inputs]
    a = next((r for r in available if reg(r) & outputs), available[0])
    choices = [r for r in order if r != a and not reg(r) & inputs]
    b = min(choices, key=lambda r: bool(preservation_mask(live, reg(r), outputs)))
    saves = preservation_mask(live, reg(a) | reg(b), outputs)
    assert tls_spill or not saves & reg(a)
    return Veneer(pc, insn, read, offset, kind, a, b, live, saves)


def analyse_sites(sites, words, original_pc=lambda pc: pc, *, percpu=False, tls_spill=False):
    """Reserved metadata belongs to address lowering and keeps its trap path."""
    # A lowering guard/stop can observe state before the original instruction
    # would have overwritten it. Analyse that boundary, not just normal native
    # control flow (notably MOVZ constants and bit-test replacements).
    observations = {original_pc(pc) for pc, _, metadata in sites if metadata}
    original_words = words
    class ObservedWords:
        def __contains__(self, pc):
            return pc in original_words
        def __getitem__(self, pc):
            return 0 if pc in observations else original_words[pc]
    words = ObservedWords()
    result = []
    for pc, word, metadata in sites:
        if metadata or shadow_operation(word, percpu) is None:
            continue
        veneer = plan(pc, word, live_after(words, original_pc(pc)), percpu=percpu, tls_spill=tls_spill)
        if veneer is not None:
            result.append(veneer)
    return result


def assembly(veneers):
    source = '.text\n.balign 4\n'
    for i, veneer in enumerate(veneers):
        name = f'osrec_call_{i}'
        source += f'.global {name}\n.type {name}, %function\n{name}:\n'
        source += ''.join(f'    {line}\n' for line in veneer.instructions(f'osrec_call_return_{i}'))
        source += f'.size {name}, .-{name}\n'
    return source


def choose_base(mapped, veneers, anchor):
    occupied = {va & ~4095 for va, *_ in mapped}
    for offset in range(0x86000000, 0x88000000, RESERVATION):
        base = (anchor & ~0xffffffff) + offset
        if any(base + k in occupied for k in range(0, RESERVATION, 4096)):
            continue
        size = 0
        try:
            for v in veneers:
                branch(v.pc, base + size)
                size += 4 * len(v.instructions('continuation'))
                branch(base + size - 4, v.pc + 4)
        except ValueError:
            continue
        if ((size + 4095) & ~4095) + (3 if any(v.kind == 'percpu' for v in veneers) else 2)*4096 > RESERVATION:
            raise ValueError('emulation veneers exceed their reservation')
        return base, size
    raise ValueError('no reachable address window for emulation veneers')
