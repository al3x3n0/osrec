"""Read-only coarse lookup for static kernel-mapping precedence over TTBR0.

Each of 512 buckets covers 2**39 addresses. An empty or out-of-bounds bucket
proves no static mapping can contain the address. Exact intervals reject
directly; mixed buckets retain the original range scan for holes.
"""
import hashlib
import struct

SHIFT=39
ENTRIES=512


def exclusion_buckets(spans):
    merged=[]
    for lo,hi in sorted(spans):
        if not 0<=lo<=hi<=1<<64:raise ValueError('invalid user exclusion range')
        if lo==hi or lo>=1<<48:continue
        hi=min(hi,1<<48)
        if merged and lo<=merged[-1][1]:merged[-1]=(merged[-1][0],max(hi,merged[-1][1]))
        else:merged.append((lo,hi))
    rows=[]
    for index in range(ENTRIES):
        start=index<<SHIFT;end=start+(1<<SHIFT)
        pieces=[(max(start,lo),min(end,hi)) for lo,hi in merged if lo<end and start<hi]
        if not pieces:rows.append((0,0));continue
        lo,hi=pieces[0][0],pieces[-1][1]
        length=hi-lo
        # A low bit marks a mixed bucket. Rounding an even mixed length up by
        # one can only cause extra fallback, never admission inside a mapping.
        rows.append((lo,length|(len(pieces)>1)))
    return b''.join(struct.pack('<2Q',*row) for row in rows)


def exclusion_path(address,pointer,descriptor,work,parent,slow,ready,prefix,buckets=False):
    a,p,d,s,q=('x%d'%r for r in (address,pointer,descriptor,work,parent))
    lines=[]
    if buckets:
        lines+=['ubfx %s,%s,#39,#9'%(s,a),
            'adrp %s,flat_user_exclusion_buckets'%q,'add %s,%s,:lo12:flat_user_exclusion_buckets'%(q,q),
            'add %s,%s,%s,lsl #4'%(q,q,s),'ldp %s,%s,[%s]'%(d,s,q),'cbz %s,%s'%(s,ready),
            'sub %s,%s,%s'%(d,a,d),'cmp %s,%s'%(d,s),'b.hs '+ready,'tbz %s,#0,%s'%(s,slow)]
    loop=prefix+'kernel'
    lines+=['adrp %s,flat_user_excluded'%q,'add %s,%s,:lo12:flat_user_excluded'%(q,q),
        'ldr %s,[%s],#8'%(p,q),loop+':','cbz %s,%s'%(p,ready),
        'ldp %s,%s,[%s],#16'%(d,s,q),'cmp %s,%s'%(a,d),'b.lo '+ready,
        'cmp %s,%s'%(a,s),'b.lo '+slow,'sub %s,%s,#1'%(p,p),'b '+loop]
    return lines


def validate_exclusion_buckets(elf,checked,metadata):
    """Bind the lookup to the actual immutable kernel maps and exclusion list."""
    from el0_user_memory import excluded_ranges
    symbols={s['name']:s for s in elf.symbols if s['shndx']}
    flag=symbols.get('flat_user_exclusion_bucket_mode')
    mode=struct.unpack('<Q',elf.read(flag['value'],8))[0] if flag else 0
    config=metadata.get('user_exclusion_buckets')
    if mode not in (0,1) or bool(mode)!=bool(config):raise ValueError('user exclusion bucket mode differs from metadata')
    if not mode:return
    if any(config.get(k)!=v for k,v in (('shift',SHIFT),('entries',ENTRIES),('entry_bytes',16))):
        raise ValueError('invalid user exclusion bucket geometry')
    def readonly(symbol,size):
        lo=symbol['value']&-4096;hi=(symbol['value']+size+4095)&-4096
        if elf.sections[symbol['shndx']]['flags']&1 or any(
                s['flags']&2 and lo<((s['address']+s['memory_bytes']+4095)&-4096) and
                (s['address']&-4096)<hi for s in checked['load_segments']):
            raise ValueError('user exclusion bucket inputs are writable')
    readonly(flag,8)
    program=symbols['flat_program']['value']
    pointer,count=struct.unpack('<2Q',elf.read(program+16,16))
    maps=symbols['flat_maps']
    if pointer!=maps['value']:raise ValueError('user exclusion kernel map binding differs')
    readonly(maps,count*32)
    spans=excluded_ranges(list(struct.iter_unpack('<4Q',elf.read(pointer,count*32))))
    excluded=symbols['flat_user_excluded'];readonly(excluded,8+16*len(spans))
    actual=elf.read(excluded['value'],8+16*len(spans))
    expected=struct.pack('<Q',len(spans))+b''.join(struct.pack('<2Q',*row) for row in spans)
    if actual!=expected:raise ValueError('user exclusion ranges differ from kernel maps')
    expected=exclusion_buckets(spans);table=symbols['flat_user_exclusion_buckets'];readonly(table,len(expected))
    actual=elf.read(table['value'],len(expected))
    if actual!=expected or hashlib.sha256(actual).hexdigest()!=config.get('sha256'):
        raise ValueError('user exclusion buckets differ from kernel maps')
