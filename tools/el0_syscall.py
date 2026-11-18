"""Inline logical syscall entry, preserving event evidence and kernel execution."""
from el0_hardware import immediate


def native_syscall_path(pc,word,metadata,index,kernel_stack_range):
    """Execution-only native-SP entry, using the existing 32-byte spill ABI.

    All original scratch registers move to an 80-byte private frame before
    any architectural commit. This also handles physical user/kernel stack
    aliases. The guarded stack interval is an immutable kernel write range;
    misses restore the complete entry state and use the original C gateway.
    """
    if (metadata or word&0xffe0001f!=0xd4000001 or pc&3 or
            not 0<=pc<=(1<<64)-5 or index is None or kernel_stack_range is None):return ''
    lo,hi=kernel_stack_range
    if lo<0 or hi>1<<64 or hi-lo<64 or lo+64>=1<<64:return ''
    table,base,bits=index
    slow='.Lnsvc%x_slow'%pc
    code=['stp x12,x13,[sp,#-32]!','stp x16,x17,[sp,#16]','mov x16,sp',
          'adrp x17,flat_active','ldr x17,[x17,:lo12:flat_active]',
          'ldr x17,[x17,#8]','sub x17,x17,#80','stp x14,x15,[x17,#16]',
          'mrs x14,nzcv',
          'ldp x12,x13,[x16]','stp x12,x13,[x17]',
          'ldp x12,x13,[x16,#16]','stp x12,x13,[x17,#32]',
          'add x16,x16,#32','stp x14,x16,[x17,#48]','mov sp,x17',
          'adrp x17,flat_shadow','add x17,x17,:lo12:flat_shadow',
          'ldr x12,[x17,#80]','cbnz x12,'+slow,
          'adrp x16,flat_active','ldr x16,[x16,:lo12:flat_active]',
          'ldr x13,[x16,#64]','and x14,x13,#0xffffffffffffefff','cbnz x14,'+slow,
          'ldr x16,[x17,#8]','tst x16,#15','b.ne '+slow]
    code+=immediate(14,lo+64)+['sub x13,x16,x14']
    code+=immediate(14,hi-lo-64)+['cmp x13,x14','b.hi '+slow,'str x16,[sp,#64]',
          'ldr x12,[x17,#64]','add x12,x12,#1024','tst x12,#3','b.ne '+slow]
    code+=immediate(14,base)+['sub x13,x12,x14','lsr x14,x13,#%d'%bits,'cbnz x14,'+slow,
          'lsr x14,x13,#12','adrp x16,'+table,'add x16,x16,:lo12:'+table,
          'ldr x16,[x16,x14,lsl #3]','cbz x16,'+slow,'ubfiz x13,x13,#2,#12',
          'ldr x15,[x16,x13]','cbz x15,'+slow,
          # No rejecting operation remains after this point.
          'adrp x16,flat_active','ldr x16,[x16,:lo12:flat_active]',
          'ldr x13,[x16,#64]','ldp x12,x14,[sp,#48]','orr x13,x12,x13',
          'str x14,[x17]','ldr x12,[sp,#64]','str x12,[x16]',
          'ldr x12,[x17,#96]','add x12,x12,#1','str x12,[x17,#96]']
    # Saved NZCV/SP and architectural ELR/SPSR are adjacent pairs. X13 keeps
    # SPSR until the paired commit, after every possible rejection above.
    code+=immediate(12,pc+4)+['stp x12,x13,[x17,#16]']
    code+=immediate(12,(0x15<<26)|(1<<25)|(word>>5&65535))+['str x12,[x17,#32]',
          'mov x12,#1','str x12,[x17,#80]','mov x12,#0x3c0','str x12,[x17,#48]',
          # All guest values are now in private RAM, so stack aliases cannot
          # overwrite a source spill while the compact kernel frame is built.
          'ldr x12,[sp,#48]','msr nzcv,x12','ldr x17,[sp,#64]','sub x17,x17,#32',
          'ldp x12,x13,[sp,#32]','stp x12,x13,[x17]','mov x16,x15',
          'ldp x12,x13,[sp]','ldp x14,x15,[sp,#16]','mov sp,x17','br x16',
          slow+':','ldr x12,[sp,#48]','msr nzcv,x12','ldr x17,[sp,#56]','sub x17,x17,#16',
          'ldp x12,x13,[sp,#32]','stp x12,x13,[x17]',
          'ldp x12,x13,[sp]','ldp x14,x15,[sp,#16]','mov sp,x17','ldp x16,x17,[sp],#16']
    return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)


def syscall_path(pc, word, metadata=0):
    """Resolve the vector and check inputs before committing any entry state."""
    if metadata or word&0xffe0001f!=0xd4000001 or pc&3 or not 0<=pc<=(1<<64)-5:return ''
    prefix='.Lsvc%x_'%pc
    loop,less,found,slow=(prefix+n for n in ('loop','less','found','slow'))
    code=['sub sp,sp,#64','stp x12,x13,[sp]','stp x14,x15,[sp,#16]',
          'stp x16,x17,[sp,#32]','mrs x17,nzcv','str x17,[sp,#48]',
          'adrp x17,flat_shadow','add x17,x17,:lo12:flat_shadow',
          'ldr x12,[x17,#80]','cbnz x12,'+slow,
          'adrp x12,flat_active','ldr x12,[x12,:lo12:flat_active]',
          'ldr x13,[x12,#64]','and x13,x13,#0xffffffffffffefff','cbnz x13,'+slow,
          'adrp x12,flat_event_count','ldr x12,[x12,:lo12:flat_event_count]',
          'adrp x13,flat_program','add x13,x13,:lo12:flat_program',
          'ldr x13,[x13,#88]','add x13,x13,#1024','cmp x12,x13','b.hs '+slow,
          'ldr x16,[x17,#64]','add x16,x16,#1024',
          'mov x13,xzr','adrp x14,flat_direct_pc_count','ldr x14,[x14,:lo12:flat_direct_pc_count]',
          'adrp x17,flat_direct_pcs','add x17,x17,:lo12:flat_direct_pcs',
          loop+':','cmp x13,x14','b.hs '+slow,'add x15,x13,x14','lsr x15,x15,#1',
          'add x12,x17,x15,lsl #4','ldr x12,[x12]','cmp x12,x16','b.eq '+found,'b.lo '+less,
          'mov x14,x15','b '+loop,less+':','add x13,x15,#1','b '+loop,
          found+':','add x15,x17,x15,lsl #4','ldr x16,[x15,#8]',
          # X16 holds the admitted resume thunk until the final branch.
          'adrp x12,flat_event_count','add x12,x12,:lo12:flat_event_count',
          'ldr x14,[x12]','add x15,x14,#1','str x15,[x12]',
          'adrp x13,flat_events','add x13,x13,:lo12:flat_events','mov x15,#80','madd x13,x14,x15,x13',
          'str x8,[x13,#8]','stp x0,x1,[x13,#16]','stp x2,x3,[x13,#32]','stp x4,x5,[x13,#48]',
          'adrp x12,flat_observer_pending','add x12,x12,:lo12:flat_observer_pending','str x13,[x12]',
          'adrp x17,flat_shadow','add x17,x17,:lo12:flat_shadow',
          'ldr x14,[x17,#8]','sub x14,x14,#0x150','str x14,[x12,#8]',
          'ldr x14,[x17,#96]','add x14,x14,#1','str x14,[x17,#96]']
    code+=immediate(15,pc+4)+['str x15,[x17,#16]']
    code+=immediate(15,(0x15<<26)|(1<<25)|(word>>5&65535))+['str x15,[x17,#32]',
          'adrp x12,flat_active','ldr x12,[x12,:lo12:flat_active]',
          'ldr x13,[sp,#48]','ldr x14,[x12,#64]','orr x13,x13,x14','str x13,[x17,#24]',
          'ldr x13,[x12]','str x13,[x17]','ldr x13,[x17,#8]','str x13,[x12]',
          'mov x13,#1','str x13,[x17,#80]','mov x13,#0x3c0','str x13,[x17,#48]',
          'ldr x17,[sp,#48]','msr nzcv,x17','ldp x12,x13,[sp]','ldp x14,x15,[sp,#16]','br x16',
          slow+':','ldr x17,[sp,#48]','msr nzcv,x17','ldp x12,x13,[sp]',
          'ldp x14,x15,[sp,#16]','ldp x16,x17,[sp,#32]','add sp,sp,#64']
    return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)
