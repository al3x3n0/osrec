"""Live user-translation fast paths without context gateways or EL1 services."""
from el0_flat_lower import LOAD, WB, POST, USER, REGISTER, EXCLUSIVE, ALIGNED, temporary
from el0_hardware import PCREL, immediate,add_immediate,add_register_offset


def ram_offset_path(pointer,work,ram_base,ram_bytes,bytes_,slow):
    """Convert an admitted physical address to a RAM offset before dereference.

    For B=2**k and L<=B, PA xor B equals PA-B for every admitted PA.
    If PA's B bit is clear, xor sets it, making the result >=B>L-bytes.
    The same unsigned upper-bound test therefore rejects every other PA.
    """
    p,s='x%d'%pointer,'x%d'%work
    if ram_base>0 and not ram_base&(ram_base-1) and ram_bytes<=ram_base:
        code=['eor %s,%s,#0x%x'%(p,p,ram_base)]
    else:code=immediate(work,ram_base)+['sub %s,%s,%s'%(p,p,s)]
    return code+immediate(work,ram_bytes-bytes_)+['cmp %s,%s'%(p,s),'b.hi '+slow]


def immutable_page_bitmap(ram_base,ram_bytes,spans):
    """One construction-time bit for every canonical RAM page."""
    if ram_base&4095 or ram_bytes<=0 or ram_base<0 or ram_base+ram_bytes>1<<64:
        raise ValueError('invalid immutable bitmap RAM extent')
    pages=(ram_bytes+4095)//4096;result=bytearray((pages+7)//8)
    for address,size in spans:
        if size<0 or address<ram_base or address+size>ram_base+ram_bytes:
            raise ValueError('immutable span outside canonical RAM')
        if not size:continue
        for page in range((address-ram_base)//4096,(address+size-1-ram_base)//4096+1):
            result[page>>3]|=1<<(page&7)
    return bytes(result)


def user_memory_path(pc, op, following, ram_base, ram_bytes, tcr, native_sp=False,immutable_bitmap=False,accesses=None,exclusion_buckets=False):
    """Check fresh captured PTEs, then execute against canonical RAM at EL0.

    Single-page accesses only. Every rejection restores the input context and
    falls through to the existing software handler before executing the access.
    """
    bits=64-(tcr&63)
    if op.length!=1 or op.info&EXCLUSIVE or tcr>>14&3 or not 25<=bits<=48 or ram_bytes<4096:
        return ''
    info=op.info; base,address=info&31,info>>10&31
    if native_sp and base==31 and info&WB:return ''
    used={base,address,op.word&31}
    if accesses:
        if any(o.word&31==address for o in accesses):return ''
        used.update(o.word&31 for o in accesses)
    if info&(1<<18):used.add(op.word>>10&31)
    if info&REGISTER:used.add(info>>5&31)
    scratch=[]
    for _ in range(4):
        r=temporary(used)
        if r is None:return ''
        used.add(r);scratch.append(r)
    pointer,descriptor,work,parent=scratch
    a,p,d,s,q=('x%d'%r for r in (address,*scratch))
    prefix='.Lum%x_'%pc+('group_' if accesses else '')
    slow,leaf,ready=(prefix+n for n in ('slow','leaf','ready'))
    user_address=prefix+'user'
    code=['stp %s,%s,[sp,#-64]!'%(a,p),'stp %s,%s,[sp,#16]'%(d,s),
          'str %s,[sp,#32]'%q,'mrs %s,nzcv'%s,'str %s,[sp,#40]'%s]
    if not info&USER:
        code+=['adrp %s,flat_shadow'%p,'add %s,%s,:lo12:flat_shadow'%(p,p),
               'ldr %s,[%s,#80]'%(s,p),'cbnz %s,%s'%(s,slow)]
    # Root and TCR are read fresh together. Address/exclusion calculations do
    # not mutate this internal control block; retain the root in a free slot.
    code+=['adrp %s,flat_program'%p,'add %s,%s,:lo12:flat_program'%(p,p),
           'ldp %s,%s,[%s,#32]'%(p,d,p),'str %s,[sp,#56]'%p]
    code+=immediate(work,tcr)+['cmp %s,%s'%(d,s),'b.ne '+slow]
    if info&PCREL:code+=immediate(address,pc)
    elif base==31:
        code+=['add %s,sp,#64'%a] if native_sp else ['adrp %s,flat_active'%p,'ldr %s,[%s,:lo12:flat_active]'%(p,p),'ldr %s,[%s]'%(a,p)]
    else:code+=['mov %s,x%d'%(a,base)]
    if info&REGISTER:
        offset,extension,shift=info>>5&31,info>>24&7,info>>27&7
        code+=add_register_offset(address,address,offset,extension,shift,work)
    elif op.imm and not info&POST:
        code+=add_immediate(address,address,op.imm,work)
    if info&WB:
        if info&POST:
            code+=add_immediate(work,address,op.imm,work)+['str %s,[sp,#48]'%s]
        else:code+=['str %s,[sp,#48]'%a]
    size=(1<<(info>>15&7))*(2 if info&(1<<18) else 1)
    if accesses:size*=len(accesses)
    # Static kernel mappings take precedence over TTBR0 in flat_translate.
    code+=immediate(work,1<<bits)+['cmp %s,%s'%(a,s),'b.hs '+slow]
    from el0_user_exclusion import exclusion_path
    code+=exclusion_path(address,pointer,descriptor,work,parent,slow,user_address,prefix,exclusion_buckets)
    code+=[user_address+':','and %s,%s,#4095'%(s,a),'cmp %s,#%d'%(s,4096-size),'b.hi '+slow]
    if info&ALIGNED:code+=['tst %s,#%d'%(a,size-1),'b.ne '+slow] if size>1 else []
    code+=['ldr %s,[sp,#56]'%p,'and %s,%s,#0x0000fffffffff000'%(p,p),
           'adrp %s,flat_phys'%q,'add %s,%s,:lo12:flat_phys'%(q,q)]

    def backing(bytes_):
        # P holds captured PA on entry, an offset into flat_phys on exit.
        return ram_offset_path(pointer,work,ram_base,ram_bytes,bytes_,slow)

    for level in range(3-(bits-13)//9,4):
        shift=12+9*(3-level)
        code+=['ubfx %s,%s,#%d,#9'%(s,a,shift),'add %s,%s,%s,lsl #3'%(p,p,s)]
        code+=backing(8)+['ldr %s,[%s,%s]'%(d,q,p),'tbz %s,#0,%s'%(d,slow)]
        if level in (0,3):code+=['tbz %s,#1,%s'%(d,slow)]
        else:code+=['tbz %s,#1,%s%d'%(d,leaf,level)]
        if level<3:
            # Reject table AP restrictions before continuing. A rejection
            # restores inputs and lets the shared walker select the fault,
            # including when a later descriptor is invalid as well.
            code+=['tbnz %s,#61,%s'%(d,slow)]
            if not info&LOAD:code+=['tbnz %s,#62,%s'%(d,slow)]
            code+=['and %s,%s,#0x0000fffffffff000'%(p,d)]
    code+=['b '+leaf+'3']
    for level in range(max(1,3-(bits-13)//9),4):
        shift=12+9*(3-level)
        code+=[leaf+str(level)+':','tbz %s,#10,%s'%(d,slow),'tbz %s,#6,%s'%(d,slow)]
        if not info&LOAD:
            code+=['tbnz %s,#7,%s'%(d,slow)]
        mask=0x0000fffffffff000&~((1<<shift)-1)
        code+=['and %s,%s,#0x%x'%(p,d,mask),'and %s,%s,#0x%x'%(s,a,(1<<shift)-1),
               'add %s,%s,%s'%(p,p,s),'b '+ready]
    code+=[ready+':']
    if immutable_bitmap:
        # Reject out-of-RAM translations before indexing. P becomes the RAM
        # offset and remains intact through the immutable-page test.
        code+=backing(size)
    if not info&LOAD and immutable_bitmap:
        code+=['lsr %s,%s,#12'%(d,p),'lsr %s,%s,#3'%(s,d),
               'adrp %s,flat_immutable_page_bits'%a,'add %s,%s,:lo12:flat_immutable_page_bits'%(a,a),
               'ldrb %s,[%s,%s]'%('w%d'%work,a,s),'and %s,%s,#7'%(d,d),
               'lsr %s,%s,%s'%(s,s,d),'tbnz %s,#0,%s'%(s,slow)]
    elif not info&LOAD:
        # Protect all physical aliases of AOT text before executing a store.
        loop,clean=prefix+'immutable',prefix+'clean'
        # Legacy span scanning still needs Q as its cursor. Restore the RAM
        # base after the scan, before the common final address calculation.
        code+=['adrp %s,flat_immutable_text_count'%d,'ldr %s,[%s,:lo12:flat_immutable_text_count]'%(d,d),
               'adrp %s,flat_immutable_text'%q,'add %s,%s,:lo12:flat_immutable_text'%(q,q),
               loop+':','cbz %s,%s'%(d,clean),'ldr %s,[%s],#8'%(s,q),
               'add %s,%s,#%d'%(a,p,size),'cmp %s,%s'%(s,a),'b.hs '+clean,
               'ldr %s,[%s],#8'%(a,q),'add %s,%s,%s'%(s,s,a),'cmp %s,%s'%(p,s),
               'b.lo '+slow,'sub %s,%s,#1'%(d,d),'b '+loop,clean+':',
               'adrp %s,flat_phys'%q,'add %s,%s,:lo12:flat_phys'%(q,q)]
    if not immutable_bitmap:code+=backing(size)
    code+=['add %s,%s,%s'%(a,q,p),'ldr %s,[sp,#40]'%s,'msr nzcv,%s'%s]
    if accesses:
        for i,other in enumerate(accesses):
            if i:code+=add_immediate(address,address,other.imm-accesses[i-1].imm,work)
            code+=['.Lhw%x_insn%x:'%(pc,pc+4*i),'.inst 0x%08x'%((other.native&~(31<<5))|(address<<5))]
    else:code+=['.inst 0x%08x'%op.native]
    if info&WB:
        if base==31:
            code+=['ldr %s,[sp,#48]'%s,'adrp %s,flat_active'%p,'ldr %s,[%s,:lo12:flat_active]'%(p,p),
                   'str %s,[%s]'%(s,p)]
        else:code+=['ldr x%d,[sp,#48]'%base]
    restore=['ldr %s,[sp,#32]'%q,'ldp %s,%s,[sp,#16]'%(d,s),'ldp %s,%s,[sp],#64'%(a,p)]
    code+=restore+['b '+following,slow+':','ldr %s,[sp,#40]'%s,'msr nzcv,%s'%s]+restore
    return ''.join(line+'\n' if line.endswith(':') else '    '+line+'\n' for line in code)


def excluded_ranges(mappings):
    """Merge all static kernel/device VA ranges, regardless of backing or AP."""
    spans=[]
    for lo,hi in sorted((va,va+size) for va,pa,size,attrs in mappings if size):
        if spans and lo<=spans[-1][1]:spans[-1]=(spans[-1][0],max(hi,spans[-1][1]))
        else:spans.append((lo,hi))
    return spans
