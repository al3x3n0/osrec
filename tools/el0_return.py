"""Checked, generated ERET-to-user transitions for the pretranslated backend."""
from el0_hardware import immediate


def user_resume_ranges(aliases,immutable):
    """Writable native user-stack intervals excluding every immutable alias."""
    result=[]
    for row in aliases:
        if row['attrs']&128:continue
        start=row['pa'];end=start+row['bytes'];cursor=start
        for pa,size in sorted(immutable):
            if pa>=end:break
            if pa+size<=cursor:continue
            if cursor<pa:result.append((row['va']+cursor-start,row['va']+min(pa,end)-start))
            cursor=max(cursor,pa+size)
        if cursor<end:result.append((row['va']+cursor-start,row['va']+end-start))
    merged=[]
    for lo,hi in sorted(result):
        if merged and merged[-1][1]==lo:merged[-1]=(merged[-1][0],hi)
        else:merged.append((lo,hi))
    return [(lo,hi) for lo,hi in merged if hi-lo>=64]


def descriptor_check_path(prefix,slow,count=None,restore_shadow=False):
    """Check every live descriptor; specialize only a bounded record count.

    The count is a construction hint, never an admission assumption. A live
    count mismatch executes the generic loop, including the empty-table case.
    Pointer, mask and expected value still come from each original record.
    With restore_shadow, X17 remains the shadow base on every successful path.
    """
    checks,checked,unrolled=(prefix+s for s in ('checks','checked','unrolled'))
    specialized=count is not None and 0<=count<=32
    code=['adrp x16,flat_pretranslated_check_count','ldr x16,[x16,:lo12:flat_pretranslated_check_count]',
          'adrp x13,flat_pretranslated_checks','add x13,x13,:lo12:flat_pretranslated_checks']
    if specialized:code+=['cmp x16,#%d'%count,'b.eq '+unrolled]
    # Post-index the record and test the decremented count at the back edge.
    # Both paths restore NZCV on rejection, and successful returns install SPSR.
    body=['ldp x12,x14,[x13],#24','ldr x12,[x12]','ldur x17,[x13,#-8]',
          'eor x12,x12,x17','and x12,x12,x14','cbnz x12,'+slow]
    code+=['cbz x16,'+checked,checks+':']+body+['subs x16,x16,#1','b.ne '+checks]
    # The unrolled path no longer needs the count register. Keep X17 (the
    # shadow base) live there; only the generic loop must reconstruct it.
    if restore_shadow:code+=['adrp x17,flat_shadow','add x17,x17,:lo12:flat_shadow']
    if specialized:
        unrolled_body=[line.replace('x17','x16') for line in body]
        code+=['b '+checked,unrolled+':']+unrolled_body*count
    return code+[checked+':']


def user_return_path(pc,word,metadata,index,descriptor_count=None,validation=True,tracked=False):
    """Commit only after checking the live context, bindings and user PC index.

    Every rejection restores the entry context and falls into the original
    ERET gateway. No C calls, guest SIMD spills or hardware ERET occur here.
    """
    if word!=0xd69f03e0 or metadata or index is None:return ''
    table,base,bits=index
    prefix='.Lur%x_'%pc
    slow,skip_x0,expected_pc=(prefix+s for s in ('slow','skip_x0','expected_pc'))
    code=['stp x12,x13,[sp,#-64]!','stp x14,x15,[sp,#16]',
          'stp x16,x17,[sp,#32]','mrs x17,nzcv','str x17,[sp,#48]',
          'adrp x17,flat_shadow','add x17,x17,:lo12:flat_shadow',
          'ldr x12,[x17,#80]','cmp x12,#1','b.ne '+slow,
          'ldr x12,[x17,#24]']
    # EL0t plus precisely the shared emulator's NZCV/SSBS/DAIF/PAN bits.
    code+=immediate(14,0xf04013c0)+['bic x14,x12,x14','cbnz x14,'+slow,'str x12,[sp,#56]']
    if validation:code+=[
          'adrp x13,flat_user_return_state','add x13,x13,:lo12:flat_user_return_state',
          'ldr x12,[x13,#272]','cbz x12,'+slow]
    code+=[
          'adrp x16,flat_program','add x16,x16,:lo12:flat_program',
          'ldp x12,x13,[x16,#32]','and x12,x12,#0x0000fffffffff000',
          'adrp x14,flat_pretranslated_root','ldr x14,[x14,:lo12:flat_pretranslated_root]',
          'cmp x12,x14',
          'adrp x14,flat_pretranslated_tcr','ldr x14,[x14,:lo12:flat_pretranslated_tcr]',
          'ccmp x13,x14,#0,eq','b.ne '+slow,
          'ldr x15,[x17,#16]','tst x15,#3','b.ne '+slow]
    code+=immediate(12,base)+['sub x14,x15,x12','lsr x12,x14,#%d'%bits,'cbnz x12,'+slow,
          'lsr x12,x14,#12','adrp x16,'+table,'add x16,x16,:lo12:'+table,
          'ldr x16,[x16,x12,lsl #3]','cbz x16,'+slow,'ubfiz x14,x14,#2,#12',
          'ldr x15,[x16,x14]','cbz x15,'+slow]
    if tracked:
        code+=['adrp x16,flat_translation_dirty','ldr x16,[x16,:lo12:flat_translation_dirty]',
               'cbz x16,'+prefix+'clean']
    code+=descriptor_check_path(prefix,slow,descriptor_count,restore_shadow=True)
    if tracked:
        code+=['adrp x16,flat_translation_dirty','str xzr,[x16,:lo12:flat_translation_dirty]',prefix+'clean:']
    if validation:code+=return_context_checks(slow,skip_x0,expected_pc)
    else:
        # This SP supplies the user resume frame, so headroom/alignment are
        # execution requirements even without saved-context comparisons.
        code+=['ldr x12,[x17]','tst x12,#15','b.ne '+slow,'cmp x12,#64','b.lo '+slow,
               'sub x12,x12,#64','adrp x13,flat_user_resume_ranges','add x13,x13,:lo12:flat_user_resume_ranges',
               prefix+'stack:','ldp x14,x16,[x13],#16','cbz x16,'+slow,
               'cmp x12,x14','b.lo '+slow,'sub x16,x16,#64','cmp x12,x16','b.hi '+prefix+'stack']
    # X15 is the immutable user resume thunk. Commit only after admission.
    # Mode/counter and DAIF/PAN are adjacent fields; pair their final writes.
    code+=['ldr x12,[x17,#88]','add x12,x12,#1','stp xzr,x12,[x17,#80]',
           'add x12,sp,#64','str x12,[x17,#8]','ldr x12,[sp,#56]',
           'and x14,x12,#0x3c0','ubfx x13,x12,#22,#1',
           'stp x14,x13,[x17,#48]',
           'adrp x16,flat_active','ldr x16,[x16,:lo12:flat_active]',
           'and x14,x12,#0x1000','str x14,[x16,#64]','msr nzcv,x12',
           'ldr x14,[x17]','str x14,[x16]','sub x17,x14,#64',
           # The thunk restores X16/X17 from SP+32 and releases its 64-byte
           # frame. Only the same 32-byte user headroom as capture is touched.
           'ldp x12,x13,[sp,#32]','stp x12,x13,[x17,#32]','mov x16,x15',
           'ldp x12,x13,[sp]','ldp x14,x15,[sp,#16]','mov sp,x17','br x16',
           slow+':','ldr x17,[sp,#48]','msr nzcv,x17','ldp x12,x13,[sp]',
           'ldp x14,x15,[sp,#16]','ldp x16,x17,[sp,#32]','add sp,sp,#64']
    return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)


def return_context_checks(slow,skip_x0,expected_pc):
    """Optional equivalence checks against the recorded entry context."""
    code=[
          'adrp x13,flat_user_return_state','add x13,x13,:lo12:flat_user_return_state',
          'ldr x12,[x13,#280]','cbnz x12,'+skip_x0,
          'ldr x12,[x13]','cmp x0,x12','b.ne '+slow,skip_x0+':']
    for r in range(1,31,2):
        code.append('ldp x12,x14,[x13,#%d]'%(r*8))
        for register,expected in ((r,'x12'),(r+1,'x14')):
            if 12<=register<=17:
                code.append('ldr x16,[sp,#%d]'%((register-12)*8))
                actual='x16'
            else:actual='x%d'%register
            operation='cmp' if register==1 else 'ccmp'
            # All expected-register loads are bounded internal-state reads.
            # Keep Z clear after any mismatch and reject once before commit.
            code.append('%s %s,%s%s'%(operation,actual,expected,',#0,eq' if operation=='ccmp' else ''))
    code+=['b.ne '+slow,'ldp x12,x16,[x13,#248]','ldr x14,[x17]','cmp x12,x14','b.ne '+slow,
           'tst x12,#15','b.ne '+slow,'cmp x12,#64','b.lo '+slow,
           'ldr x14,[x13,#280]','cbz x14,'+expected_pc,
           'add x16,x16,#4',expected_pc+':','ldr x14,[x17,#16]','cmp x16,x14','b.ne '+slow,
           'str xzr,[x13,#272]']
    return code
