"""Inline the executor's UART register buffer and output evidence, not a device."""
from el0_flat_lower import LOAD, WB, POST, USER, REGISTER, EXCLUSIVE, ALIGNED, temporary
from el0_hardware import PCREL, immediate,add_immediate,add_register_offset


def uart_path(pc, op, following, uart_va, native_sp=False):
    info=op.info
    size=(1<<(info>>15&7))*(2 if info&(1<<18) else 1)
    if not uart_va or op.length!=1 or info&(USER|EXCLUSIVE) or size>4:return ''
    base,address=info&31,info>>10&31
    if native_sp and base==31:return ''
    used={base,address,op.word&31}
    if info&REGISTER:used.add(info>>5&31)
    scratch=[]
    for _ in range(3):
        r=temporary(used)
        if r is None:return ''
        used.add(r);scratch.append(r)
    pointer,work,offset_reg=scratch
    a,p,s,q=('x%d'%r for r in (address,*scratch))
    prefix='.Luart%x_'%pc
    slow,access,done=(prefix+n for n in ('slow','access','done'))
    code=['stp %s,%s,[sp,#-48]!'%(a,p),'stp %s,%s,[sp,#16]'%(s,q),
          'mrs %s,nzcv'%s,'str %s,[sp,#32]'%s,
          'adrp %s,flat_shadow'%p,'add %s,%s,:lo12:flat_shadow'%(p,p),
          'ldr %s,[%s,#80]'%(s,p),'cbz %s,%s'%(s,slow),
          'adrp %s,flat_program'%p,'add %s,%s,:lo12:flat_program'%(p,p),'ldr %s,[%s,#120]'%(s,p)]
    code+=immediate(offset_reg,uart_va)+['cmp %s,%s'%(s,q),'b.ne '+slow]
    if info&PCREL:code+=immediate(address,pc)
    elif base==31:
        code+=['adrp %s,flat_active'%p,'ldr %s,[%s,:lo12:flat_active]'%(p,p),'ldr %s,[%s]'%(a,p)]
    else:code+=['mov %s,x%d'%(a,base)]
    if info&REGISTER:
        rm,extension,shift=info>>5&31,info>>24&7,info>>27&7
        code+=add_register_offset(address,address,rm,extension,shift,work)
    elif op.imm and not info&POST:
        code+=add_immediate(address,address,op.imm,work)
    if info&WB:
        if info&POST:
            code+=add_immediate(work,address,op.imm,work)+['str %s,[sp,#40]'%s]
        else:code+=['str %s,[sp,#40]'%a]
    code+=['cmp %s,%s'%(a,q),'b.lo '+slow,'sub %s,%s,%s'%(q,a,q),'cmp %s,#4095'%q,'b.hi '+slow]
    if info&ALIGNED and size>1:code+=['tst %s,#%d'%(a,size-1),'b.ne '+slow]
    if info&LOAD:
        code+=['cmp %s,#0x18'%q,'b.ne '+slow]
    else:
        code+=['cbz %s,%s'%(q,prefix+'output'),'cmp %s,#0x38'%q,'b.ne '+slow,'b '+access,
               prefix+'output:','adrp %s,flat_uart_used'%p,'ldr %s,[%s,:lo12:flat_uart_used]'%(s,p),
               'cmp %s,#4096'%s,'b.hs '+slow]
    code+=[access+':','adrp %s,flat_uart_registers'%p,'add %s,%s,:lo12:flat_uart_registers'%(p,p),
           'add %s,%s,%s'%(a,p,q),'ldr %s,[sp,#32]'%s,'msr nzcv,%s'%s,'.inst 0x%08x'%op.native]
    if not info&LOAD:
        code+=['cbnz %s,%s'%(q,done),'adrp %s,flat_uart_used'%p,'add %s,%s,:lo12:flat_uart_used'%(p,p),
               'ldr %s,[%s]'%(s,p),'adrp %s,flat_uart_registers'%a,
               'ldrb w%d,[%s,:lo12:flat_uart_registers]'%(offset_reg,a),
               'adrp %s,flat_uart'%a,'add %s,%s,:lo12:flat_uart'%(a,a),
               'strb w%d,[%s,%s]'%(offset_reg,a,s),'add %s,%s,#1'%(s,s),'str %s,[%s]'%(s,p)]
    code+=[done+':']
    if info&WB:
        if base==31:
            code+=['ldr %s,[sp,#40]'%s,'adrp %s,flat_active'%p,'ldr %s,[%s,:lo12:flat_active]'%(p,p),
                   'str %s,[%s]'%(s,p)]
        else:code+=['ldr x%d,[sp,#40]'%base]
    restore=['ldp %s,%s,[sp,#16]'%(s,q),'ldp %s,%s,[sp],#48'%(a,p)]
    code+=restore+['b '+following,slow+':','ldr %s,[sp,#32]'%s,'msr nzcv,%s'%s]+restore
    return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)
