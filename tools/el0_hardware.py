"""Inline hardware-memory fast paths for the standalone EL0 executor.

Only captured, static kernel mappings backed by canonical RAM are admitted.
Changing user translations, explicit user accesses and unusual instructions
retain the software path. Fast paths preserve NZCV and their scratch registers
on the private execution stack; they never enter the context gateway.
"""
from el0_flat_lower import LOAD, WB, POST, USER, REGISTER, HINT, EXCLUSIVE, ALIGNED, temporary

PCREL = 1 << 44


def immediate(register, value):
    value &= (1 << 64) - 1
    parts = [(value >> shift) & 65535 for shift in (0, 16, 32, 48)]
    return ['movz x%d,#%d' % (register, parts[0])] + [
        'movk x%d,#%d,lsl #%d' % (register, part, 16 * i)
        for i, part in enumerate(parts) if i and part]


def memory_path(pc, op, following):
    """Return an inline native access followed by the existing slow-path label.

    Exclusive windows keep their existing lowering. No conditional branch is
    inserted within an exclusive window.
    """
    info = op.info
    if op.length != 1 or info & (USER | HINT | EXCLUSIVE):
        return ''
    base, address = info & 31, info >> 10 & 31
    used = {address, base, op.word & 31}
    if info & (1 << 18):
        used.add(op.word >> 10 & 31)
    if info & REGISTER:
        used.add(info >> 5 & 31)
    pointer = temporary(used)
    used.add(pointer)
    scratch = temporary(used)
    a, p, s = ('x%d' % r for r in (address, pointer, scratch))
    prefix = '.Lhw%x_' % pc
    slow, loop, fast = (prefix + name for name in ('slow', 'loop', 'fast'))
    code = ['sub sp,sp,#32', 'stp %s,%s,[sp]' % (a, p),
            'str %s,[sp,#16]' % s, 'mrs %s,nzcv' % s, 'str %s,[sp,#24]' % s,
            'adrp %s,flat_shadow' % p, 'add %s,%s,:lo12:flat_shadow' % (p, p),
            'ldr %s,[%s,#80]' % (s, p), 'cbz %s,%s' % (s, slow)]
    if info & PCREL:
        code += immediate(address, pc)
    elif base == 31:
        code += ['adrp %s,flat_active' % p, 'ldr %s,[%s,:lo12:flat_active]' % (p, p),
                 'ldr %s,[%s]' % (a, p)]
    else:
        code += ['mov %s,x%d' % (a, base)]
    if info & REGISTER:
        offset, extension, shift = info >> 5 & 31, info >> 24 & 7, info >> 27 & 7
        if offset == 31:
            code += ['mov %s,xzr' % s]
        elif extension in (2, 6):
            code += ['%s %s,w%d' % ('uxtw' if extension == 2 else 'sxtw', s, offset)]
        else:
            code += ['mov %s,x%d' % (s, offset)]
        code += ['add %s,%s,%s,lsl #%d' % (a, a, s, shift)]
    elif op.imm and not info & POST:
        if abs(op.imm) < 4096:
            code += ['%s %s,%s,#%d' % ('add' if op.imm > 0 else 'sub', a, a, abs(op.imm))]
        else:
            code += immediate(scratch, op.imm) + ['add %s,%s,%s' % (a, a, s)]
    size = (1 << (info >> 15 & 7)) * (2 if info & (1 << 18) else 1)
    if info & ALIGNED and size > 1:
        code += ['tst %s,#%d' % (a, size - 1), 'b.ne ' + slow]
    name = 'flat_direct_read' if info & LOAD else 'flat_direct_write'
    code += ['adrp %s,%s' % (p, name), 'add %s,%s,:lo12:%s' % (p, p, name),
             loop + ':', 'ldr %s,[%s],#8' % (s, p), 'cbz %s,%s' % (s, slow),
             'cmp %s,%s' % (a, s), 'b.lo ' + slow,
             'ldr %s,[%s],#8' % (s, p), 'sub %s,%s,#%d' % (s, s, size),
             'cmp %s,%s' % (a, s), 'b.hi ' + loop, fast + ':',
             'ldr %s,[sp,#24]' % s, 'msr nzcv,%s' % s,
             '.inst 0x%08x' % op.native]
    if info & WB:
        if info & POST and op.imm:
            if abs(op.imm) < 4096:
                code += ['%s %s,%s,#%d' % ('add' if op.imm > 0 else 'sub', a, a, abs(op.imm))]
            else:
                code += immediate(scratch, op.imm) + ['add %s,%s,%s' % (a, a, s)]
        if base == 31:
            code += ['adrp %s,flat_active' % p, 'ldr %s,[%s,:lo12:flat_active]' % (p, p), 'str %s,[%s]' % (a, p)]
        else:
            code += ['mov x%d,%s' % (base, a)]
    code += ['ldr %s,[sp,#16]' % s, 'ldp %s,%s,[sp]' % (a, p), 'add sp,sp,#32',
             'b ' + following, slow + ':', 'ldr %s,[sp,#24]' % s, 'msr nzcv,%s' % s,
             'ldr %s,[sp,#16]' % s, 'ldp %s,%s,[sp]' % (a, p), 'add sp,sp,#32']
    return ''.join(line + '\n' if line.endswith(':') else '    ' + line + '\n' for line in code)


def stack_path(op):
    """Update logical guest SP inline, leaving actual SP private to the runtime."""
    from el0_flat_lower import SRC_SP, DST_SP
    info = op.info
    value = info >> 10 & 31
    pointer = temporary({value, op.word & 31, op.word >> 5 & 31, op.word >> 16 & 31})
    v, p = 'x%d' % value, 'x%d' % pointer
    code = ['sub sp,sp,#16', 'stp %s,%s,[sp]' % (v, p), 'adrp %s,flat_active' % p,
            'ldr %s,[%s,:lo12:flat_active]' % (p, p),
            'ldr %s,[%s]' % (v, p) if info & SRC_SP else 'mov %s,xzr' % v,
            '.inst 0x%08x' % op.native]
    if info & DST_SP:
        code.append('str %s,[%s]' % (v, p))
    code += ['ldp %s,%s,[sp]' % (v, p), 'add sp,sp,#16']
    return ''.join('    ' + line + '\n' for line in code)


def direct_ranges(mappings, ram_base, ram_size, immutable):
    """Hardware aliases and access ranges, excluding devices and code writes."""
    aliases, reads, writes = [], [], []
    for va, pa, size, attrs in sorted(mappings):
        if not attrs & (1 << 10) or pa < ram_base or size > ram_size or pa - ram_base > ram_size - size:
            continue
        aliases.append(dict(va=va, pa=pa, bytes=size, attrs=attrs))
        reads.append((va, va + size))
        if attrs & (1 << 7):
            continue
        pieces = [(pa, pa + size)]
        for start, length in immutable:
            end = start + length
            pieces = [(lo, hi) for a, b in pieces for lo, hi in ((a, min(b, start)), (max(a, end), b)) if lo < hi]
        writes.extend((va + a - pa, va + b - pa) for a, b in pieces)
    def merge(spans):
        out = []
        for lo, hi in sorted(spans):
            if out and lo <= out[-1][1]:
                out[-1] = (out[-1][0], max(hi, out[-1][1]))
            else:
                out.append((lo, hi))
        return out
    return aliases, merge(reads), merge(writes)
