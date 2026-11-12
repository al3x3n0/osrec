"""Inline hardware-memory fast paths for the standalone EL0 executor.

Only captured, static kernel mappings backed by canonical RAM are admitted.
Changing user translations, explicit user accesses and unusual instructions
retain the software path. Fast paths preserve NZCV and their scratch registers
on the private execution stack; they never enter the context gateway.
"""
from el0_flat_lower import LOAD, WB, POST, USER, REGISTER, EXCLUSIVE, ALIGNED, temporary, sign, local_conditional, Op, MEMORY

PCREL = 1 << 44


def immediate(register, value):
    value &= (1 << 64) - 1
    parts = [(value >> shift) & 65535 for shift in (0, 16, 32, 48)]
    return ['movz x%d,#%d' % (register, parts[0])] + [
        'movk x%d,#%d,lsl #%d' % (register, part, 16 * i)
        for i, part in enumerate(parts) if i and part]


def memory_path(pc, op, following, group=None, target=None, zero_bytes=0):
    """Return an inline native access followed by the existing slow-path label.

    Guards precede an entire exclusive window. Exit cleanup follows its store
    or a native conditional exit; no callback splits the exclusive sequence.
    """
    info = op.info
    if info & USER or (info & EXCLUSIVE and group is None) or (op.length != 1 and not info & EXCLUSIVE):
        return ''
    base, address = info & 31, info >> 10 & 31
    used = {address, base, op.word & 31}
    if info & (1 << 18):
        used.add(op.word >> 10 & 31)
    if info & REGISTER:
        used.add(info >> 5 & 31)
    if group is not None:
        for word in group:used.update((word&31,word>>5&31,word>>10&31,word>>16&31))
    pointer = temporary(used)
    if pointer is None:return ''
    used.add(pointer)
    scratch = temporary(used)
    if scratch is None:return ''
    a, p, s = ('x%d' % r for r in (address, pointer, scratch))
    prefix = '.Lhw%x_' % pc
    slow, loop, fast = (prefix + name for name in ('slow', 'loop', 'fast'))
    code = ['sub sp,sp,#32', 'stp %s,%s,[sp]' % (a, p),
            'str %s,[sp,#16]' % s, 'mrs %s,nzcv' % s, 'str %s,[sp,#24]' % s,
            'adrp %s,flat_shadow' % p, 'add %s,%s,:lo12:flat_shadow' % (p, p),
            'ldr %s,[%s,#80]' % (s, p), 'cbz %s,%s' % (s, slow)]
    if info & PCREL:
        code += immediate(address, pc)
    elif base == 31 and zero_bytes:
        code += ['mov %s,xzr'%a]
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
    size = zero_bytes or (1 << (info >> 15 & 7)) * (2 if info & (1 << 18) else 1)
    if zero_bytes:code.append('and %s,%s,#0x%x'%(a,a,((1<<64)-1)&~(zero_bytes-1)))
    if info & (ALIGNED | EXCLUSIVE) and size > 1:
        code += ['tst %s,#%d' % (a, size - 1), 'b.ne ' + slow]
    name = 'flat_direct_read' if info & LOAD and not info & EXCLUSIVE else 'flat_direct_write'
    code += ['adrp %s,%s' % (p, name), 'add %s,%s,:lo12:%s' % (p, p, name),
             loop + ':', 'ldr %s,[%s],#8' % (s, p), 'cbz %s,%s' % (s, slow),
             'cmp %s,%s' % (a, s), 'b.lo ' + slow,
             'ldr %s,[%s],#8' % (s, p), 'sub %s,%s,#%d' % (s, s, size),
             'cmp %s,%s' % (a, s), 'b.hi ' + loop, fast + ':']
    if zero_bytes:
        code+=['adrp %s,flat_shadow'%p,'add %s,%s,:lo12:flat_shadow'%(p,p),
               'ldr %s,[%s,#88]'%(s,p),'add %s,%s,#1'%(s,s),'str %s,[%s,#88]'%(s,p)]
    code+=['ldr %s,[sp,#24]' % s, 'msr nzcv,%s' % s]
    exits={}
    if group is not None:
        for index,word in enumerate(group):
            here=pc+4*index
            code.append(prefix+'insn%x:'%here)
            direct=word&0xfc000000==0x14000000
            conditional=word&0xff000010==0x54000000 or word&0x7e000000 in (0x34000000,0x36000000)
            if direct or conditional:
                bits=26 if direct else 14 if word&0x7e000000==0x36000000 else 19
                dest=here+sign(word&0x3ffffff,26)*4 if direct else here+sign(word>>5&((1<<bits)-1),bits)*4
                if pc<=dest<pc+4*op.length:to=prefix+'insn%x'%dest
                else:
                    to=prefix+'exit%x'%dest
                    exits[dest]=to
                code.append('b '+to if direct else local_conditional(word,to).strip())
            else:code.append('.inst 0x%08x'%word)
    else:code.append('.inst 0x%08x' % op.native)
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
    restore=['ldr %s,[sp,#16]' % s, 'ldp %s,%s,[sp]' % (a, p), 'add sp,sp,#32']
    code += restore+['b '+following]
    for dest,label in sorted(exits.items()):
        code += [label+':']+restore+['b '+(target(dest) if target else '.Lp%x'%dest)]
    code += [slow + ':', 'ldr %s,[sp,#24]' % s, 'msr nzcv,%s' % s,
             'ldr %s,[sp,#16]' % s, 'ldp %s,%s,[sp]' % (a, p), 'add sp,sp,#32']
    return ''.join(line + '\n' if line.endswith(':') else '    ' + line + '\n' for line in code)


def memory_finish_path(pc, op, following):
    """Restore a checked single access inline; device/exclusive exits stay slow."""
    if op.length!=1 or op.info&EXCLUSIVE:return ''
    base,temp=op.info&31,op.info>>10&31
    pointer=temporary({base,temp});value=temporary({base,temp,pointer})
    p,v,t='x%d'%pointer,'x%d'%value,'x%d'%temp
    slow='.Lmf%x_slow'%pc
    code=['sub sp,sp,#16','stp %s,%s,[sp]'%(p,v),
          'adrp %s,flat_memory_pending'%p,'add %s,%s,:lo12:flat_memory_pending'%(p,p),
          'ldr %s,[%s,#40]'%(v,p),'cbnz %s,%s'%(v,slow),
          'ldr %s,[%s,#8]'%(t,p)]
    if op.info&WB:
        if base==31:
            code+=['ldr %s,[%s,#16]'%(v,p),'adrp %s,flat_active'%p,
                   'ldr %s,[%s,:lo12:flat_active]'%(p,p),'str %s,[%s]'%(v,p)]
        else:code+=['ldr x%d,[%s,#16]'%(base,p)]
    restore=['ldp %s,%s,[sp]'%(p,v),'add sp,sp,#16']
    code+=restore+['b '+following,slow+':']+restore
    return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)


def observe_path(pc, following):
    """Record an outstanding syscall result from admitted static kernel RAM."""
    prefix='.Lob%x_'%pc
    loop,done,slow=(prefix+n for n in ('loop','done','slow'))
    code=['sub sp,sp,#48','stp x16,x17,[sp]','stp x14,x15,[sp,#16]',
          'mrs x14,nzcv','str x14,[sp,#32]',
          'adrp x15,flat_observer_pending','add x15,x15,:lo12:flat_observer_pending',
          'ldr x16,[x15]','cbz x16,'+done,'ldr x17,[x15,#8]',
          'tst x17,#7','b.ne '+slow,
          'adrp x15,flat_direct_read','add x15,x15,:lo12:flat_direct_read',
          loop+':','ldr x14,[x15],#8','cbz x14,'+slow,
          'cmp x17,x14','b.lo '+slow,'ldr x14,[x15],#8','sub x14,x14,#8',
          'cmp x17,x14','b.hi '+loop,
          'ldr x14,[x17]','str x14,[x16,#64]','mov x14,#1','str x14,[x16,#72]',
          'adrp x15,flat_observer_pending','add x15,x15,:lo12:flat_observer_pending',
          'str xzr,[x15]',done+':']
    restore=['ldr x14,[sp,#32]','msr nzcv,x14','ldp x14,x15,[sp,#16]',
             'ldp x16,x17,[sp]','add sp,sp,#48']
    code+=restore+['b '+following,slow+':']+restore
    return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)


def zero_path(pc,word,metadata,following,block_bytes):
    """Run DC ZVA only over writable RAM with model-checked block geometry."""
    if metadata or word&~31!=0xd50b7420 or block_bytes<4 or block_bytes>2048 or block_bytes&(block_bytes-1):return ''
    rt=word&31
    address=temporary({rt})
    op=Op(MEMORY,word,native=(word&~31)|address,info=rt|(address<<10))
    return memory_path(pc,op,following,zero_bytes=block_bytes)


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


def system_path(word, metadata=0):
    """Inline shadow state and maintenance inert in the immutable AOT backend."""
    from source_image_calls import FIELDS, EMULATED_OFFSET
    family = word & 0xfff00000
    pstate=word&0xfff8f01f==0xd500401f
    # These callbacks are empty in program.c: software translations have no
    # TLB, and immutable AOT text never needs instruction-cache maintenance.
    # Match exactly the shared emulator's admitted maintenance families.
    op1,crn,crm,op2=word>>16&7,word>>12&15,word>>8&15,word>>5&7
    maintenance=word&0xfff80000==0xd5080000 and (
        crn==8 or (op1==3 and crn==7 and crm in (5,11) and op2==1) or
        (op1==0 and crn==7 and crm in (1,5) and op2==0) or
        (crn==7 and crm in (6,10,14)))
    if metadata or (not pstate and not maintenance and family not in (0xd5300000, 0xd5100000)):
        return ''
    if maintenance:
        offset,kind=None,'maintenance'
    elif pstate:
        op1,op2,imm=word>>16&7,word>>5&7,word>>8&15
        if (op1,op2) not in ((3,6),(3,7),(0,4),(0,3),(3,1),(3,2),(3,4)):return ''
        offset,kind=None,'pstate'
    else:
        field = FIELDS.get(word >> 5 & 65535)
        if field is None:return ''
        offset, kind = field
    read = family == 0xd5300000
    if not read and kind in ('readonly', 'currentel'):
        return ''
    rt = word & 31
    address = temporary({rt})
    value = temporary({rt, address})
    a, v, r = 'x%d' % address, 'x%d' % value, 'x%d' % rt if rt != 31 else 'xzr'
    code = ['sub sp,sp,#16', 'stp %s,%s,[sp]' % (a, v), 'adrp %s,flat_shadow' % a,
            'add %s,%s,:lo12:flat_shadow' % (a, a),
            'ldr %s,[%s,#%d]' % (v, a, EMULATED_OFFSET), 'add %s,%s,#1' % (v, v),
            'str %s,[%s,#%d]' % (v, a, EMULATED_OFFSET)]
    if maintenance:
        pass
    elif pstate:
        if (op1,op2) in ((3,6),(3,7)) and imm:
            code.append('ldr %s,[%s,#48]'%(v,a))
            for bit in range(4):
                if imm&(1<<bit):code.append('%s %s,%s,#%d'%('orr' if op2==6 else 'bic',v,v,1<<(bit+6)))
            code.append('str %s,[%s,#48]'%(v,a))
        elif (op1,op2)==(0,4):
            code+=['mov %s,#%d'%(v,imm&1),'str %s,[%s,#56]'%(v,a)]
    elif read and rt != 31:
        if kind == 'currentel':
            code.append('mov %s,#4' % r)
        else:
            code.append('ldr %s,[%s,#%d]' % (r, a, offset))
            if kind == 'pan':
                code.append('lsl %s,%s,#22' % (r, r))
    elif not read:
        source = r
        if kind == 'daif':
            code.append('and %s,%s,#0x3c0' % (v, r))
            source = v
        elif kind == 'pan':
            code += ['lsr %s,%s,#22' % (v, r), 'and %s,%s,#1' % (v, v)]
            source = v
        code.append('str %s,[%s,#%d]' % (source, a, offset))
    code += ['ldp %s,%s,[sp]' % (a, v), 'add sp,sp,#16']
    return ''.join('    ' + line + '\n' for line in code)


def guarded_system_path(pc,word,metadata,following):
    """Use the live known bitmap for generic register reads and plain writes."""
    from source_image_calls import FIELDS,sysreg
    family=word&0xfff00000
    key=word>>5&65535
    read=family==0xd5300000
    if metadata or family not in (0xd5300000,0xd5100000) or key in FIELDS:return ''
    if read and key in (0xdf01,0xdf02):return '' # ordered counter inputs
    if not read and key not in (sysreg(3,0,13,0,4),sysreg(3,0,13,0,1),sysreg(3,3,13,0,2),sysreg(3,0,7,4,0)):
        return ''
    rt=word&31
    address=temporary({rt});value=temporary({rt,address})
    a,v,r='x%d'%address,'x%d'%value,'x%d'%rt if rt!=31 else 'xzr'
    slow='.Lsr%x_slow'%pc
    known=104+key//8
    offset=104+8192+8*key
    code=['sub sp,sp,#16','stp %s,%s,[sp]'%(a,v),'adrp %s,flat_shadow'%a,'add %s,%s,:lo12:flat_shadow'%(a,a)]
    if known>>12:code.append('add %s,%s,#%d,lsl #12'%(a,a,known>>12))
    code+=['ldrb w%d,[%s,#%d]'%(value,a,known&4095),'tbz %s,#%d,%s'%(v,key&7,slow),
           'adrp %s,flat_shadow'%a,'add %s,%s,:lo12:flat_shadow'%(a,a),
           'ldr %s,[%s,#88]'%(v,a),'add %s,%s,#1'%(v,v),'str %s,[%s,#88]'%(v,a)]
    if not read or rt!=31:
        code.append('add %s,%s,#%d,lsl #12'%(a,a,offset>>12))
        code.append('%s %s,[%s,#%d]'%('ldr' if read else 'str',r,a,offset&4095))
    restore=['ldp %s,%s,[sp]'%(a,v),'add sp,sp,#16']
    code+=restore+['b '+following,slow+':']+restore
    return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)


def lowered_branch_path(pc, word, metadata, target):
    """Inline lowered TBZ/TBNZ semantics; ambiguous signed pointers fall back."""
    bit=(word>>31)*32+(word>>19&31)
    if metadata not in (0x40000000,0x40000001) or word&0x7e000000!=0x36000000 or bit not in (55,63):
        return ''
    rt=word&31
    address=temporary({rt});pointer=temporary({rt,address});scratch=temporary({rt,address,pointer})
    a,p,s,r='x%d'%address,'x%d'%pointer,'x%d'%scratch,'x%d'%rt if rt!=31 else 'xzr'
    prefix='.Llb%x_'%pc
    loop,native,lowered,taken,fall,slow=(prefix+n for n in ('loop','native','lowered','taken','fall','slow'))
    code=['sub sp,sp,#32','stp %s,%s,[sp]'%(a,p),'str %s,[sp,#16]'%s,
          'mrs %s,nzcv'%s,'str %s,[sp,#24]'%s,
          'adrp %s,osrec_kernel_range_count'%p,'ldr %s,[%s,:lo12:osrec_kernel_range_count]'%(s,p),
          'adrp %s,osrec_kernel_ranges'%p,'add %s,%s,:lo12:osrec_kernel_ranges'%(p,p),
          loop+':','cbz %s,%s'%(s,native),'ldr %s,[%s],#8'%(a,p),
          'cmp %s,%s'%(r,a),'b.lo '+native,'ldr %s,[%s],#8'%(a,p),
          'cmp %s,%s'%(r,a),'b.lo '+lowered,'sub %s,%s,#1'%(s,s),'b '+loop,
          lowered+':','b '+(slow if bit==63 and not metadata&1 else taken if word&(1<<24) else fall),
          native+':',local_conditional(word,taken).strip(),'b '+fall]
    restore=['ldr %s,[sp,#24]'%s,'msr nzcv,%s'%s,'ldr %s,[sp,#16]'%s,
             'ldp %s,%s,[sp]'%(a,p),'add sp,sp,#32']
    dest=(pc+4*sign(word>>5&0x3fff,14))&((1<<64)-1)
    for label,pc_target in ((taken,dest),(fall,(pc+4)&((1<<64)-1))):
        code += [label+':','adrp %s,flat_shadow'%p,'add %s,%s,:lo12:flat_shadow'%(p,p),
                 'ldr %s,[%s,#88]'%(a,p),'add %s,%s,#1'%(a,a),'str %s,[%s,#88]'%(a,p)]
        code += restore+['b '+target(pc_target)]
    code += [slow+':']+restore
    return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)


def indirect_path(pc, word, table='flat_direct_pcs', count='flat_direct_pc_count'):
    """Resolve an original PC without the full-context gateway.

    A matched target enters a 64-byte-frame resume thunk. Misses restore the
    original context and fall through to the existing diagnostic gateway.
    """
    rn = word >> 5 & 31
    prefix = '.Lij%x_' % pc
    loop, less, found, slow = (prefix + s for s in ('loop', 'less', 'found', 'slow'))
    code = ['sub sp,sp,#64', 'stp x12,x13,[sp]', 'stp x14,x15,[sp,#16]',
            'stp x16,x17,[sp,#32]', 'mrs x17,nzcv', 'str x17,[sp,#48]']
    if rn == 17:
        code.append('ldr x16,[sp,#40]')
    else:
        code.append('mov x16,%s' % ('x%d' % rn if rn != 31 else 'xzr'))
    code += ['mov x13,xzr', 'adrp x14,' + count, 'ldr x14,[x14,:lo12:%s]' % count,
             'adrp x17,' + table, 'add x17,x17,:lo12:' + table,
             loop + ':', 'cmp x13,x14', 'b.hs ' + slow,
             'add x15,x13,x14', 'lsr x15,x15,#1', 'add x12,x17,x15,lsl #4',
             'ldr x12,[x12]', 'cmp x12,x16', 'b.eq ' + found, 'b.lo ' + less,
             'mov x14,x15', 'b ' + loop, less + ':', 'add x13,x15,#1', 'b ' + loop,
             found + ':', 'add x15,x17,x15,lsl #4', 'ldr x16,[x15,#8]']
    if word & 0xfffffc1f == 0xd63f0000:
        code += immediate(30, pc + 4)
    code += ['ldr x17,[sp,#48]', 'msr nzcv,x17', 'ldp x12,x13,[sp]',
             'ldp x14,x15,[sp,#16]', 'br x16', slow + ':',
             'ldr x17,[sp,#48]', 'msr nzcv,x17', 'ldp x12,x13,[sp]',
             'ldp x14,x15,[sp,#16]', 'ldp x16,x17,[sp,#32]', 'add sp,sp,#64']
    return ''.join(line + '\n' if line.endswith(':') else '    ' + line + '\n' for line in code)


def indirect_resume(name, target):
    return '%s:\n    ldp x16,x17,[sp,#32]\n    add sp,sp,#64\n    b %s\n' % (name, target)


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
