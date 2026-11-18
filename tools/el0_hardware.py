"""Inline hardware-memory fast paths for the standalone EL0 executor.

Only captured, static kernel mappings backed by canonical RAM are admitted.
Changing user translations, explicit user accesses and unusual instructions
retain the software path. Fast paths preserve NZCV and their scratch registers;
native-SP paths require admitted spill headroom. They never enter the context
gateway. Compact mode converts the payload address to canonical RAM.
"""
from el0_flat_lower import LOAD, WB, POST, USER, REGISTER, EXCLUSIVE, ALIGNED, temporary, sign, local_conditional, Op, MEMORY

PCREL = 1 << 44
COMPACT_LINKED_BIAS = 2
COMPACT_LINKED_BIAS_ENCODING = 'linked-bias-ranked-v1'
COMPACT_WIDTH_BOUNDS = 3
COMPACT_WIDTH_BOUNDS_ENCODING = 'linked-bias-width-bounds-v1'
COMPACT_ACCESS_WIDTHS = tuple(1 << bits for bits in range(12))


def immediate(register, value):
    value &= (1 << 64) - 1
    parts = [(value >> shift) & 65535 for shift in (0, 16, 32, 48)]
    nonzero=[i for i,part in enumerate(parts) if part]
    nonones=[i for i,part in enumerate(parts) if part!=65535]
    inverted=len(nonones)<len(nonzero)
    selected=nonones if inverted else nonzero
    first=selected[0] if selected else 0
    name='x%d'%register if register!=31 else 'xzr'
    initial=parts[first]^65535 if inverted else parts[first]
    return ['%s %s,#%d%s'%('movn' if inverted else 'movz',name,initial,
                          ',lsl #%d'%(16*first) if first else '')]+[
        'movk %s,#%d,lsl #%d'%(name,parts[i],16*i) for i in selected if i!=first]


def add_immediate(destination,base,value,scratch):
    """Flag-free 64-bit address addition, including modular negative offsets."""
    value=sign(value&((1<<64)-1),64)
    d,b='x%d'%destination,'x%d'%base
    if not value:return [] if destination==base else ['mov %s,%s'%(d,b)]
    magnitude=abs(value);operation='sub' if value<0 else 'add'
    if magnitude<=4095:return ['%s %s,%s,#%d'%(operation,d,b,magnitude)]
    if not magnitude&4095 and magnitude>>12<=4095:
        return ['%s %s,%s,#%d,lsl #12'%(operation,d,b,magnitude>>12)]
    if scratch==base:raise ValueError('address constant scratch aliases its base')
    return immediate(scratch,value)+['add %s,%s,x%d'%(d,b,scratch)]


def add_register_offset(destination,base,offset,extension,shift,scratch):
    """Fold memory-index extension/shift into ADD whenever encodable."""
    d,b='x%d'%destination,'x%d'%base
    if offset==31:return [] if destination==base else ['mov %s,%s'%(d,b)]
    if extension in (2,6):
        operation='uxtw' if extension==2 else 'sxtw'
        if shift<=4:return ['add %s,%s,w%d,%s #%d'%(d,b,offset,operation,shift)]
        if scratch==base:raise ValueError('address extension scratch aliases its base')
        return ['%s x%d,w%d'%(operation,scratch,offset),'add %s,%s,x%d,lsl #%d'%(d,b,scratch,shift)]
    return ['add %s,%s,x%d,lsl #%d'%(d,b,offset,shift)]


def memory_path(pc, op, following, group=None, target=None, zero_bytes=0, native_sp=False, page_cache=False, native_store=False, compact=False):
    """Return an inline native access followed by the existing slow-path label.

    Guards precede an entire exclusive window. Exit cleanup follows its store
    or a native conditional exit; no callback splits the exclusive sequence.
    Page-cache fills require immutable range tables with page-aligned endpoints;
    the pretranslated exporter proves this and model admission verifies it.
    Compact writeback restores a saved logical EA, not the translated pointer.
    Native-SP writeback remains slow; changing SP can overlap the spill frame.
    """
    info = op.info
    if compact:
        if page_cache or native_store:raise ValueError('compact conversion cannot bypass backing translation')
    if info & USER or (info & EXCLUSIVE and group is None) or (op.length != 1 and not info & EXCLUSIVE):
        return ''
    original_store=(native_store and native_sp and info&31==31 and not info&(LOAD|EXCLUSIVE)
                    and op.length==1 and group is None and not zero_bytes)
    if native_sp and info&31==31 and info&WB and not original_store:return ''
    if page_cache:
        from el0_memory_elision import page_cache_eligible
        if not page_cache_eligible(op,native_sp) or group is not None or zero_bytes:
            raise ValueError('page cache requires one aligned fixed-range access')
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
    # Conversion overwrites the scratch EA with a canonical pointer. Keep the
    # logical EA separately so writeback cannot leak that pointer into the guest.
    compact_writeback=compact and bool(info&WB)
    frame=48 if compact_writeback else 32
    ranked = compact in (COMPACT_LINKED_BIAS, COMPACT_WIDTH_BOUNDS)
    code = ['stp %s,%s,[sp,#-%d]!' % (a, p, frame)]
    if ranked:
        # The pointer register has already been saved. Pair the stores and
        # reload scratch and flags together before running the payload.
        code += ['mrs %s,nzcv'%p, 'stp %s,%s,[sp,#16]'%(s,p),
                 'adrp %s,flat_shadow'%p, 'ldr %s,[%s,:lo12:flat_shadow+80]'%(s,p)]
        restore_flags = ['ldp %s,%s,[sp,#16]'%(s,p),'msr nzcv,%s'%p]
        restore_scratch = []
    else:
        code += ['str %s,[sp,#16]'%s, 'mrs %s,nzcv'%s, 'str %s,[sp,#24]'%s,
                 'adrp %s,flat_shadow'%p, 'add %s,%s,:lo12:flat_shadow'%(p,p),
                 'ldr %s,[%s,#80]'%(s,p)]
        restore_flags = ['ldr %s,[sp,#24]'%s,'msr nzcv,%s'%s]
        restore_scratch = ['ldr %s,[sp,#16]'%s]
    code.append('cbz %s,%s'%(s,slow))
    ea_base = address
    if info & PCREL:
        code += immediate(address, pc)
    elif base == 31 and zero_bytes:
        code += ['mov %s,xzr'%a]
    elif base == 31:
        code += ['add %s,sp,#%d'%(a,frame)] if native_sp else ['adrp %s,flat_active' % p, 'ldr %s,[%s,:lo12:flat_active]' % (p, p),
                 'ldr %s,[%s]' % (a, p)]
    elif ranked:
        ea_base = base
    else:
        code += ['mov %s,x%d' % (a, base)]
    if info & REGISTER:
        offset, extension, shift = info >> 5 & 31, info >> 24 & 7, info >> 27 & 7
        code += add_register_offset(address,ea_base,offset,extension,shift,scratch)
    elif op.imm and not info & POST:
        code += add_immediate(address,ea_base,op.imm,scratch)
    elif ea_base!=address:
        code.append('mov %s,x%d'%(a,ea_base))
    if compact_writeback:code+=['str %s,[sp,#32]'%a]
    size = zero_bytes or (1 << (info >> 15 & 7)) * (2 if info & (1 << 18) else 1)
    if zero_bytes:code.append('and %s,%s,#0x%x'%(a,a,((1<<64)-1)&~(zero_bytes-1)))
    if info & (ALIGNED | EXCLUSIVE) and size > 1:
        code += ['tst %s,#%d' % (a, size - 1), 'b.ne ' + slow]
    name = 'flat_direct_read' if info & LOAD and not info & EXCLUSIVE else 'flat_direct_write'
    cold_lookup = []
    if compact==COMPACT_WIDTH_BOUNDS:
        if size not in COMPACT_ACCESS_WIDTHS:
            raise ValueError('unsupported compact access width')
        access = 'read' if info&LOAD else 'write'
        name = 'flat_compact_%s_%d' % (access,size)
        search = prefix+'search'
        # Each width table starts on a 32-byte boundary. These three fields
        # and the next-row address all fit on the ADRP's page.
        code += ['adrp %s,%s'%(p,name), 'ldr %s,[%s,:lo12:%s]'%(s,p,name),
                 'cmp %s,%s'%(a,s), 'b.lo '+search,
                 'ldr %s,[%s,:lo12:%s+8]'%(s,p,name), 'cmp %s,%s'%(a,s),
                 'b.hi '+search, 'ldr %s,[%s,:lo12:%s+16]'%(s,p,name),
                 'add %s,%s,%s'%(a,a,s), fast+':']
        cold_lookup = [search+':', 'add %s,%s,:lo12:%s+24'%(p,p,name),
                       loop+':','ldr %s,[%s],#24'%(s,p),'cbz %s,%s'%(s,slow),
                       'cmp %s,%s'%(a,s),'b.lo '+loop,
                       'ldr %s,[%s,#-16]'%(s,p),'cmp %s,%s'%(a,s),'b.hi '+loop,
                       'ldr %s,[%s,#-8]'%(s,p),'add %s,%s,%s'%(a,a,s),'b '+fast]
    elif compact:
        name='flat_compact_read' if info&LOAD else 'flat_compact_write'
        # The ranked table stores the complete linked bias, including the ELF
        # backing address. Its rows can appear in any order.
        code+=['adrp %s,%s'%(p,name),'add %s,%s,:lo12:%s'%(p,p,name),
               loop+':','ldr %s,[%s],#24'%(s,p),'cbz %s,%s'%(s,slow),
               'cmp %s,%s'%(a,s),'b.lo '+(loop if ranked else slow),
               'ldr %s,[%s,#-16]'%(s,p),'sub %s,%s,#%d'%(s,s,size),
               'cmp %s,%s'%(a,s),'b.hi '+loop]
        if not ranked:
            code+=['ldr %s,[%s,#-24]'%(s,p),'sub %s,%s,%s'%(a,a,s)]
        code+=['ldr %s,[%s,#-8]'%(s,p),'add %s,%s,%s'%(a,a,s)]
        if not ranked:
            code+=['adrp %s,flat_phys'%p,'add %s,%s,:lo12:flat_phys'%(p,p),
                   'add %s,%s,%s'%(a,a,p)]
        code.append(fast+':')
    else:code += ['adrp %s,%s' % (p, name), 'add %s,%s,:lo12:%s' % (p, p, name),
             loop + ':', 'ldr %s,[%s],#8' % (s, p), 'cbz %s,%s' % (s, slow),
             'cmp %s,%s' % (a, s), 'b.lo ' + slow,
             'ldr %s,[%s],#8' % (s, p), 'sub %s,%s,#%d' % (s, s, size),
             'cmp %s,%s' % (a, s), 'b.hi ' + loop, fast + ':']
    if page_cache:
        from el0_memory_elision import page_cache_fill
        code+=page_cache_fill(pc,address,pointer,scratch)
    if zero_bytes:
        code.append('adrp %s,flat_shadow'%p)
        if not ranked:
            code.append('add %s,%s,:lo12:flat_shadow'%(p,p))
        slot = ':lo12:flat_shadow+88' if ranked else '#88'
        code+=['ldr %s,[%s,%s]'%(s,p,slot),'add %s,%s,#1'%(s,s),'str %s,[%s,%s]'%(s,p,slot)]
    code+=restore_flags
    if original_store:
        # Admission covers the complete effective-address span. Restore the
        # original SP and all operands BEFORE executing the original store:
        # a pre-index push can occupy our temporary spill frame, and original
        # SP writeback must not be overwritten by adapter cleanup afterward.
        restore=['ldr %s,[sp,#16]'%s,'ldp %s,%s,[sp],#32'%(a,p)]
        code+=restore+['.inst 0x%08x'%op.word,'b '+following,slow+':',
                      'ldr %s,[sp,#24]'%s,'msr nzcv,%s'%s]+restore
        return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)
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
        if compact_writeback:code+=['ldr %s,[sp,#32]'%a]
        if info & POST and op.imm:
            code += add_immediate(address,address,op.imm,pointer if ranked else scratch)
        if base == 31:
            code += ['adrp %s,flat_active' % p, 'ldr %s,[%s,:lo12:flat_active]' % (p, p), 'str %s,[%s]' % (a, p)]
        else:
            code += ['mov x%d,%s' % (base, a)]
    restore=restore_scratch+['ldp %s,%s,[sp],#%d' % (a, p, frame)]
    code += restore+['b '+following]
    for dest,label in sorted(exits.items()):
        code += [label+':']+restore+['b '+(target(dest) if target else '.Lp%x'%dest)]
    code += cold_lookup+[slow + ':']+restore_flags+restore
    return ''.join(line + '\n' if line.endswith(':') else '    ' + line + '\n' for line in code)


def memory_finish_path(pc, op, following, native_sp=False):
    """Restore a checked single access inline; device/exclusive exits stay slow."""
    if op.length!=1 or op.info&EXCLUSIVE:return ''
    if native_sp and op.info&31==31 and op.info&WB:return ''
    base,temp=op.info&31,op.info>>10&31
    pointer=temporary({base,temp});value=temporary({base,temp,pointer})
    p,v,t='x%d'%pointer,'x%d'%value,'x%d'%temp
    slow='.Lmf%x_slow'%pc
    code=['stp %s,%s,[sp,#-16]!'%(p,v),
          'adrp %s,flat_memory_pending'%p,'add %s,%s,:lo12:flat_memory_pending'%(p,p),
          'ldr %s,[%s,#40]'%(v,p),'cbnz %s,%s'%(v,slow),
          'ldr %s,[%s,#8]'%(t,p)]
    if op.info&WB:
        if base==31:
            code+=['ldr %s,[%s,#16]'%(v,p),'adrp %s,flat_active'%p,
                   'ldr %s,[%s,:lo12:flat_active]'%(p,p),'str %s,[%s]'%(v,p)]
        else:code+=['ldr x%d,[%s,#16]'%(base,p)]
    restore=['ldp %s,%s,[sp],#16'%(p,v)]
    code+=restore+['b '+following,slow+':']+restore
    return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)


def observe_path(pc, following):
    """Record an outstanding syscall result from admitted static kernel RAM."""
    prefix='.Lob%x_'%pc
    loop,done,slow=(prefix+n for n in ('loop','done','slow'))
    code=['stp x16,x17,[sp,#-48]!','stp x14,x15,[sp,#16]',
          'mrs x14,nzcv','str x14,[sp,#32]',
          'adrp x15,flat_observer_pending','add x15,x15,:lo12:flat_observer_pending',
          'ldp x16,x17,[x15]','cbz x16,'+done,
          'tst x17,#7','b.ne '+slow,
          'adrp x15,flat_direct_read','add x15,x15,:lo12:flat_direct_read',
          loop+':','ldr x14,[x15],#8','cbz x14,'+slow,
          'cmp x17,x14','b.lo '+slow,'ldr x14,[x15],#8','sub x14,x14,#8',
          'cmp x17,x14','b.hi '+loop,
          'ldr x14,[x17]','str x14,[x16,#64]','mov x14,#1','str x14,[x16,#72]',
          'adrp x15,flat_observer_pending','str xzr,[x15,:lo12:flat_observer_pending]',done+':']
    restore=['ldr x14,[sp,#32]','msr nzcv,x14','ldp x14,x15,[sp,#16]',
             'ldp x16,x17,[sp],#48']
    code+=restore+['b '+following,slow+':']+restore
    return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)


def zero_path(pc,word,metadata,following,block_bytes,compact=False):
    """Run DC ZVA only over writable RAM with model-checked block geometry."""
    if metadata or word&~31!=0xd50b7420 or block_bytes<4 or block_bytes>2048 or block_bytes&(block_bytes-1):return ''
    rt=word&31
    address=temporary({rt})
    op=Op(MEMORY,word,native=(word&~31)|address,info=rt|(address<<10))
    return memory_path(pc,op,following,zero_bytes=block_bytes,compact=compact)


def stack_path(op):
    """Update logical guest SP inline, leaving actual SP private to the runtime."""
    from el0_flat_lower import SRC_SP, DST_SP
    info = op.info
    value = info >> 10 & 31
    pointer = temporary({value, op.word & 31, op.word >> 5 & 31, op.word >> 16 & 31})
    v, p = 'x%d' % value, 'x%d' % pointer
    code = ['stp %s,%s,[sp,#-16]!' % (v, p), 'adrp %s,flat_active' % p,
            'ldr %s,[%s,:lo12:flat_active]' % (p, p),
            'ldr %s,[%s]' % (v, p) if info & SRC_SP else 'mov %s,xzr' % v,
            '.inst 0x%08x' % op.native]
    if info & DST_SP:
        code.append('str %s,[%s]' % (v, p))
    code += ['ldp %s,%s,[sp],#16' % (v, p)]
    return ''.join('    ' + line + '\n' for line in code)


def system_path(word, metadata=0, page_offsets=False, registers=None, body_only=False):
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
    if page_offsets and (EMULATED_OFFSET%8 or EMULATED_OFFSET+8>128 or offset is not None and (offset%8 or offset+8>128)):
        return ''
    rt = word & 31
    if registers is None:
        address = temporary({rt})
        value = temporary({rt, address})
    else:
        address,value=registers
        if address==value or not all(0<=r<31 and r!=rt for r in registers):
            raise ValueError('system scratch registers alias a live operand')
    a, v, r = 'x%d' % address, 'x%d' % value, 'x%d' % rt if rt != 31 else 'xzr'
    def memory(operation,register,offset):
        address=':lo12:flat_shadow+%d'%offset if page_offsets else '#%d'%offset
        return '%s %s,[%s,%s]'%(operation,register,a,address)
    code = [] if body_only else ['stp %s,%s,[sp,#-16]!' % (a, v), 'adrp %s,flat_shadow' % a]
    # The page-relative variant requires the exporter/model's 128-byte header
    # alignment: every accessed field (including the counter) shares a page.
    if not body_only:
        if not page_offsets:code.append('add %s,%s,:lo12:flat_shadow' % (a, a))
        code += [memory('ldr',v,EMULATED_OFFSET),'add %s,%s,#1' % (v, v),memory('str',v,EMULATED_OFFSET)]
    if maintenance:
        pass
    elif pstate:
        if (op1,op2) in ((3,6),(3,7)) and imm:
            code.append(memory('ldr',v,48))
            bit=0
            while bit<4:
                if not imm&(1<<bit):bit+=1;continue
                end=bit+1
                while end<4 and imm&(1<<end):end+=1
                mask=((1<<(end-bit))-1)<<(bit+6)
                code.append('%s %s,%s,#%d'%('orr' if op2==6 else 'bic',v,v,mask))
                bit=end
            code.append(memory('str',v,48))
        elif (op1,op2)==(0,4):
            code+=['mov %s,#%d'%(v,imm&1),memory('str',v,56)]
    elif read and rt != 31:
        if kind == 'currentel':
            code.append('mov %s,#4' % r)
        else:
            code.append(memory('ldr',r,offset))
            if kind == 'pan':
                code.append('lsl %s,%s,#22' % (r, r))
    elif not read:
        source = r
        if kind == 'daif':
            code.append('and %s,%s,#0x3c0' % (v, r))
            source = v
        elif kind == 'pan':
            code += ['ubfx %s,%s,#22,#1' % (v, r)]
            source = v
        code.append(memory('str',source,offset))
    if not body_only:code += ['ldp %s,%s,[sp],#16' % (a, v)]
    return ''.join('    ' + line + '\n' for line in code)


def guarded_system_path(pc,word,metadata,following):
    """Use the live known bitmap for generic register reads and plain writes."""
    from source_image_calls import FIELDS,sysreg
    family=word&0xfff00000
    key=word>>5&65535
    read=family==0xd5300000
    if metadata or family not in (0xd5300000,0xd5100000) or key in FIELDS:return ''
    if read and key in (0xdf01,0xdf02):return '' # ordered counter inputs
    tpidrro_write=not read and key==sysreg(3,3,13,0,3)
    if not read and key not in (sysreg(3,0,13,0,4),sysreg(3,0,13,0,1),sysreg(3,3,13,0,2),sysreg(3,0,7,4,0)) and not tpidrro_write:
        return ''
    rt=word&31
    address=temporary({rt});value=temporary({rt,address})
    a,v,r='x%d'%address,'x%d'%value,'x%d'%rt if rt!=31 else 'xzr'
    slow='.Lsr%x_slow'%pc
    known=104+key//8
    offset=104+8192+8*key
    # Relocate each field's actual page instead of constructing the large
    # shadow object's base and then adding its page offset. This works even
    # when the header, known byte or value straddles a page boundary.
    code=['stp %s,%s,[sp,#-16]!'%(a,v)]
    if not tpidrro_write:
        code+=['adrp %s,flat_shadow+%d'%(a,known),
               'ldrb w%d,[%s,:lo12:flat_shadow+%d]'%(value,a,known),'tbz %s,#%d,%s'%(v,key&7,slow)]
    code+=['adrp %s,flat_shadow+88'%a,'ldr %s,[%s,:lo12:flat_shadow+88]'%(v,a),
           'add %s,%s,#1'%(v,v),'str %s,[%s,:lo12:flat_shadow+88]'%(v,a)]
    if not read or rt!=31:
        code+=['adrp %s,flat_shadow+%d'%(a,offset),
               '%s %s,[%s,:lo12:flat_shadow+%d]'%('ldr' if read else 'str',r,a,offset)]
    if tpidrro_write:
        # The flat backend's TPIDRRO platform callback is inert. Unlike plain
        # writes, the shared emulator admits this register when unknown.
        code+=['adrp %s,flat_shadow+%d'%(a,known),
               'ldrb w%d,[%s,:lo12:flat_shadow+%d]'%(value,a,known),'orr %s,%s,#%d'%(v,v,1<<(key&7)),
               'strb w%d,[%s,:lo12:flat_shadow+%d]'%(value,a,known)]
    restore=['ldp %s,%s,[sp],#16'%(a,v)]
    code+=restore+['b '+following,slow+':']+restore
    return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)


def counter_path(pc,word,metadata,following):
    """Consume a live ordered counter input without entering the context gateway.

    Rejections leave registers, NZCV, shadow state and input cursor untouched,
    then fall through to the shared emulator for the original stop diagnostic.
    """
    key=word>>5&65535
    if metadata or word&0xfff00000!=0xd5300000 or key not in (0xdf01,0xdf02):return ''
    rt=word&31
    used={rt}
    regs=[]
    for _ in range(4):
        reg=temporary(used);used.add(reg);regs.append(reg)
    a,p,v,n=('x%d'%reg for reg in regs)
    slow='.Lct%x_slow'%pc
    code=['stp %s,%s,[sp,#-48]!'%(a,p),'stp %s,%s,[sp,#16]'%(v,n),
          'mrs %s,nzcv'%n,'str %s,[sp,#32]'%n,
          'adrp %s,flat_counter_used'%a,'ldr %s,[%s,:lo12:flat_counter_used]'%(v,a),
          'adrp %s,flat_program'%p,'add %s,%s,:lo12:flat_program'%(p,p),
          'ldr %s,[%s,#104]'%(n,p),'cmp %s,%s'%(v,n),'b.hs '+slow,
          'ldr %s,[%s,#96]'%(p,p),'mov %s,#24'%n,'madd %s,%s,%s,%s'%(p,v,n,p),
          'ldr %s,[%s]'%(n,p)]
    code+=immediate(regs[0],pc)+['cmp %s,%s'%(n,a),'b.ne '+slow,
          'ldr %s,[%s,#8]'%(n,p),'mov %s,#%d'%(a,key),'cmp %s,%s'%(n,a),'b.ne '+slow,
          'add %s,%s,#1'%(v,v),'adrp %s,flat_counter_used'%a,
          'str %s,[%s,:lo12:flat_counter_used]'%(v,a)]
    if rt!=31:code.append('ldr x%d,[%s,#16]'%(rt,p))
    code+=['adrp %s,flat_shadow'%a,'add %s,%s,:lo12:flat_shadow'%(a,a),
           'ldr %s,[%s,#88]'%(v,a),'add %s,%s,#1'%(v,v),'str %s,[%s,#88]'%(v,a)]
    restore=['ldr %s,[sp,#32]'%n,'msr nzcv,%s'%n,'ldp %s,%s,[sp,#16]'%(v,n),
             'ldp %s,%s,[sp],#48'%(a,p)]
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
    code=['stp %s,%s,[sp,#-32]!'%(a,p),'str %s,[sp,#16]'%s,
          'mrs %s,nzcv'%s,'str %s,[sp,#24]'%s,
          'adrp %s,osrec_kernel_range_count'%p,'ldr %s,[%s,:lo12:osrec_kernel_range_count]'%(s,p),
          'adrp %s,osrec_kernel_ranges'%p,'add %s,%s,:lo12:osrec_kernel_ranges'%(p,p),
          loop+':','cbz %s,%s'%(s,native),'ldr %s,[%s],#8'%(a,p),
          'cmp %s,%s'%(r,a),'b.lo '+native,'ldr %s,[%s],#8'%(a,p),
          'cmp %s,%s'%(r,a),'b.lo '+lowered,'sub %s,%s,#1'%(s,s),'b '+loop,
          lowered+':','b '+(slow if bit==63 and not metadata&1 else taken if word&(1<<24) else fall),
          native+':',local_conditional(word,taken).strip(),'b '+fall]
    restore=['ldr %s,[sp,#24]'%s,'msr nzcv,%s'%s,'ldr %s,[sp,#16]'%s,
             'ldp %s,%s,[sp],#32'%(a,p)]
    dest=(pc+4*sign(word>>5&0x3fff,14))&((1<<64)-1)
    for label,pc_target in ((taken,dest),(fall,(pc+4)&((1<<64)-1))):
        code += [label+':','adrp %s,flat_shadow'%p,'add %s,%s,:lo12:flat_shadow'%(p,p),
                 'ldr %s,[%s,#88]'%(a,p),'add %s,%s,#1'%(a,a),'str %s,[%s,#88]'%(a,p)]
        code += restore+['b '+target(pc_target)]
    code += [slow+':']+restore
    return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)


def pc_index_layout(pcs):
    """A page index covers the complete live-PC range, including its holes."""
    pcs = sorted(set(pcs))
    if not pcs or any(pc < 0 or pc >= 1 << 64 or pc & 3 for pc in pcs):
        raise ValueError('PC index requires nonempty aligned 64-bit PCs')
    base = pcs[0] & ~4095
    bits = max(12, (pcs[-1] - base).bit_length())
    if bits > 30:
        raise ValueError('PC index span exceeds construction limit')
    return base, bits


def pc_index_data(name, pcs, layout=None):
    """Read-only two-level index; every slot has direct and context resumes."""
    base, bits = layout or pc_index_layout(pcs)
    if base&4095:raise ValueError('PC index base must be page aligned')
    if any(pc & 3 or not 0 <= pc-base < 1 << bits for pc in pcs):
        raise ValueError('PC outside index layout')
    pages = {}
    for pc in sorted(set(pcs)):
        pages.setdefault((pc-base) >> 12, {})[(pc >> 2) & 1023] = pc
    code = ['.balign 8', name+':']
    for page in range(1 << (bits-12)):
        code.append('.quad '+(name+'_p%x'%page if page in pages else '0'))
    for page, entries in pages.items():
        code.append(name+'_p%x:'%page)
        for slot in range(1024):
            if slot in entries:
                pc = entries[slot]
                code.append('.quad .Li%x,.Lr%x'%(pc, pc))
            else:
                code.append('.quad 0,0')
    return '\n'.join(code)+'\n'


def indirect_cache_probe(rn, cache_name, miss, save_offset=32):
    """Compare the complete live target while retaining a cache page base.

    Every cache is 16-byte aligned, so its two words share a page. X16/X17
    targets come from the spill made before either scratch register changes.
    Neither the hit nor miss path modifies NZCV.
    """
    code=['adrp x17,'+cache_name,'ldr x16,[x17,:lo12:'+cache_name+']']
    if rn in (16,17):
        code+=['ldr x17,[sp,#%d]'%(save_offset+8*(rn-16)),'eor x16,x16,x17','cbnz x16,'+miss,
               'adrp x17,'+cache_name]
    else:
        code+=['eor x16,x16,%s'%('x%d'%rn if rn!=31 else 'xzr'),'cbnz x16,'+miss]
    return code+['ldr x16,[x17,:lo12:'+cache_name+'+8]','cbz x16,'+miss]


def indexed_indirect_path(pc, word, index, cache, compact=False):
    """Use only x16/x17 and flag-free bounds/alignment checks."""
    table, base, bits = index
    if base&4095:raise ValueError('PC index base must be page aligned')
    rn = word >> 5 & 31
    prefix = '.Lij%x_' % pc
    slow, miss, cache_name = (prefix+s for s in ('slow', 'miss', 'cache'))
    save_offset=0 if compact else 32
    code = ['stp x16,x17,[sp,#-32]!'] if compact else ['sub sp,sp,#64', 'stp x16,x17,[sp,#32]']
    if cache:
        code += indirect_cache_probe(rn,cache_name,miss,save_offset)
        if word & 0xfffffc1f == 0xd63f0000:
            code += immediate(30, pc+4)
        code += ['br x16', miss+':']
    code += ['ldr x16,[sp,#%d]'%(save_offset+8*(rn-16))] if rn in (16,17) else ['mov x16,%s'%('x%d'%rn if rn != 31 else 'xzr')]
    code += ['tbnz x16,#0,'+slow, 'tbnz x16,#1,'+slow]
    code += immediate(17, base)
    code += ['sub x16,x16,x17', 'lsr x17,x16,#%d'%bits, 'cbnz x17,'+slow,
             'lsr x16,x16,#12', 'adrp x17,'+table,
             'add x17,x17,:lo12:'+table, 'ldr x17,[x17,x16,lsl #3]', 'cbz x17,'+slow]
    # The index base is page aligned and the target is already 4-byte aligned.
    # Its low 12 bits shifted left twice select the 16-byte PC-index entry.
    # Re-read scratch-register targets from their original spill; other source
    # registers are still live, so no temporary offset spill is needed.
    source='x%d'%rn if rn!=31 else 'xzr'
    if rn in (16,17):
        code+=['ldr x16,[sp,#%d]'%(save_offset+8*(rn-16))]
        source='x16'
    code+=['ubfiz x16,%s,#2,#12'%source,'ldr x16,[x17,x16]', 'cbz x16,'+slow]
    if cache:
        code += ['adrp x17,'+cache_name,'str x16,[x17,:lo12:'+cache_name+'+8]']
        if rn in (16,17):
            code+=['ldr x16,[sp,#%d]'%(save_offset+8*(rn-16)),
                   'str x16,[x17,:lo12:'+cache_name+']','ldr x16,[x17,:lo12:'+cache_name+'+8]']
        else:
            code+=['str %s,[x17,:lo12:%s]'%('x%d'%rn if rn!=31 else 'xzr',cache_name)]
    if word & 0xfffffc1f == 0xd63f0000:
        code += immediate(30, pc+4)
    code += ['br x16', slow+':']+(['ldp x16,x17,[sp],#32'] if compact else ['ldp x16,x17,[sp,#32]', 'add sp,sp,#64'])
    result = ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)
    if cache:
        result += '.pushsection .data,"aw"\n.balign 16\n'+cache_name+':\n.quad 0,0\n.popsection\n'
    return result


def indirect_path(pc, word, table='flat_direct_pcs', count='flat_direct_pc_count', cache=False, index=None,compact=False):
    """Resolve an original PC without the full-context gateway.

    A matched target enters a 64-byte-frame resume thunk. Misses restore the
    original context and fall through to the existing diagnostic gateway.
    """
    if index is not None:
        return indexed_indirect_path(pc, word, index, cache,compact)
    if compact:raise ValueError('compact indirect frames require an immutable PC index')
    rn = word >> 5 & 31
    prefix = '.Lij%x_' % pc
    loop, less, found, slow = (prefix + s for s in ('loop', 'less', 'found', 'slow'))
    cache_name = prefix+'cache'
    code = []
    if cache:
        # The immutable PC table validates every cache fill. A hit compares
        # the live original target, without changing NZCV or x12..x15. The
        # existing resume thunk only restores x16/x17 from the 64-byte frame.
        miss = prefix+'miss'
        code += ['sub sp,sp,#64', 'stp x16,x17,[sp,#32]']+indirect_cache_probe(rn,cache_name,miss)
        if word & 0xfffffc1f == 0xd63f0000:
            code += immediate(30, pc+4)
        code += ['br x16', miss+':', 'ldp x16,x17,[sp,#32]', 'add sp,sp,#64']
    code += ['sub sp,sp,#64', 'stp x12,x13,[sp]', 'stp x14,x15,[sp,#16]',
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
    if cache:
        code += ['adrp x17,'+cache_name, 'add x17,x17,:lo12:'+cache_name,
                 'stp x12,x16,[x17]']
    if word & 0xfffffc1f == 0xd63f0000:
        code += immediate(30, pc + 4)
    code += ['ldr x17,[sp,#48]', 'msr nzcv,x17', 'ldp x12,x13,[sp]',
             'ldp x14,x15,[sp,#16]', 'br x16', slow + ':',
             'ldr x17,[sp,#48]', 'msr nzcv,x17', 'ldp x12,x13,[sp]',
             'ldp x14,x15,[sp,#16]', 'ldp x16,x17,[sp,#32]', 'add sp,sp,#64']
    result = ''.join(line + '\n' if line.endswith(':') else '    ' + line + '\n' for line in code)
    if cache:
        result += '.pushsection .data,"aw"\n.balign 16\n'+cache_name+':\n.quad 0,0\n.popsection\n'
    return result


def indirect_resume(name, target, compact=False):
    if compact:return '%s:\n    ldp x16,x17,[sp],#32\n    b %s\n'%(name,target)
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


def compact_ranges(mappings,ram_base,ram_size,immutable):
    """Permission-filtered VA intervals with offsets into canonical RAM.

    Merge only physically contiguous aliases: a virtual span alone does not
    establish that one converted native transfer can cross its boundary.
    """
    aliases,reads,writes=direct_ranges(mappings,ram_base,ram_size,immutable)
    def rows(ranges):
        result=[]
        for a in aliases:
            for lo,hi in ranges:
                start=max(lo,a['va']);end=min(hi,a['va']+a['bytes'])
                if start>=end:continue
                offset=a['pa']-ram_base+start-a['va']
                if start==0:raise ValueError('compact range zero address conflicts with sentinel')
                if result and start<result[-1][1]:raise ValueError('overlapping compact mappings')
                if result and start==result[-1][1] and offset==result[-1][2]+start-result[-1][0]:
                    result[-1][1]=end
                else:result.append([start,end,offset])
        return result
    return rows(reads),rows(writes)


def ranked_compact_ranges(rows):
    """Put larger admitted regions first without changing their permissions."""
    return sorted(rows, key=lambda row: (row[0]-row[1], row[0]))


def compact_width_ranges(rows,width):
    """Return inclusive start bounds for an access of the selected width."""
    return [(lo,hi-width,offset) for lo,hi,offset in ranked_compact_ranges(rows) if hi-lo>=width]
