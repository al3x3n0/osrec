#!/usr/bin/env python3
"""Rehash the kernel tables keyed by addresses that a virtual relocation moved (Linux 6.10, arm64).

A relocated object keeps its contents, but a table that chose its bucket from the object's address (or from a
hash salted with one) no longer finds it. For each such table: walk every bucket; SELF-CHECK that the bucket
recomputed from the old addresses is the bucket the entry is in (proof that the reimplemented hash is the
kernel's); recompute the bucket from the new addresses; relink the chains. Hash functions follow the pinned
source:

- dentry_hashtable: full_name_hash(parent, name, len) (fs/namei.c, 64-bit word-at-a-time HASH_MIX and
  fold_hash), bucket = hash >> d_hash_shift; the hash is also stored in d_name and is rewritten;
- mount_hashtable: m_hash(&parent->mnt, mountpoint) (fs/namespace.c);
- mountpoint_hashtable: mp_hash(m_dentry);
- inode_hashtable: hash(sb, i_ino) (fs/inode.c).

Tables that hold only waiters (futex queues, page and bit wait tables) and in-progress lookups must be empty at
the captured syscall boundary; otherwise the relocation is refused.
"""
M64=(1<<64)-1;GOLDEN_RATIO_64=0x61C8864680B583EB;L1_CACHE_BYTES=64


def rol64(v,n):return ((v<<n)|(v>>(64-n)))&M64


def full_name_hash(salt,name):
    """fs/namei.c full_name_hash (CONFIG_DCACHE_WORD_ACCESS, 64-bit, little-endian)."""
    x=0;y=salt&M64;i=0;n=len(name)
    while True:
        if n==0:break
        a=int.from_bytes(name[i:i+8].ljust(8,b'\0'),'little')
        if n<8:
            x^=a&((1<<(8*n))-1);break
        x^=a;y^=x;x=rol64(x,12);x=(x+y)&M64;y=rol64(y,45);y=(y*9)&M64
        i+=8;n-=8
    y^=(x*GOLDEN_RATIO_64)&M64;y=(y*GOLDEN_RATIO_64)&M64
    return y>>32


def m_hash(mnt,dentry,shift,mask):
    tmp=(mnt//L1_CACHE_BYTES+dentry//L1_CACHE_BYTES)&M64;tmp=(tmp+(tmp>>shift))&M64;return tmp&mask


def mp_hash(dentry,shift,mask):
    tmp=dentry//L1_CACHE_BYTES;tmp=(tmp+(tmp>>shift))&M64;return tmp&mask


def inode_hash(sb,ino,shift,mask):
    tmp=((ino*sb)&M64)^(((GOLDEN_RATIO_64+ino)&M64)//L1_CACHE_BYTES);tmp=tmp^((tmp^GOLDEN_RATIO_64)>>shift);return tmp&mask


class Tables:
    def __init__(self,read,pa,move,put,lay,var):
        self.q=lambda va:read(pa(va));self.pa=pa;self.move=move;self.put=put;self.lay=lay;self.var=var
    def u32(self,va):return self.q(va&~7)>>(32*((va>>2)&1))&0xffffffff
    def cstring(self,va):
        out=b''
        while len(out)<256:
            w=self.q((va+len(out))&~7).to_bytes(8,'little')[(va+len(out))&7:]
            if b'\0' in w:return out+w[:w.index(b'\0')]
            out+=w
        return out
    def chains(self,table,count,bl):
        """{bucket: [node addresses in order]} of an hlist (bl: low bit of each head is a lock) table."""
        out={}
        for i in range(count):
            node=self.q(table+8*i)&(~1 if bl else M64);items=[]
            while node and len(items)<100000:items.append(node);node=self.q(node)
            if items:out[i]=items
        return out
    def relink(self,table,count,old_chains,new_index,why):
        """Rewrite the chains: nodes grouped by their new bucket, in their old order; heads, next and pprev
        written at their unchanged physical addresses with the new (moved) addresses."""
        new={}
        for i in sorted(old_chains):
            for node in old_chains[i]:new.setdefault(new_index(node),[]).append(node)
        for i in set(old_chains)|set(new):
            head=table+8*i;nodes=new.get(i,[])
            self.put(self.pa(head),self.move(nodes[0]) if nodes else 0,why+' head %d'%i)
            prev=self.move(head)
            for k,node in enumerate(nodes):
                self.put(self.pa(node),self.move(nodes[k+1]) if k+1<len(nodes) else 0,why+' next')
                self.put(self.pa(node+8),prev,why+' pprev');prev=self.move(node)
        return sum(len(v) for v in new.values())


def rehash(read,pa,move,put,lay,var,lookup_buckets):
    """Rehash all address-keyed tables; returns a summary. Raises on a failed self-check or a non-empty waiter table."""
    t=Tables(read,pa,move,put,lay,var);summary={};q=t.q;u32=lambda name:t.u32(var(name))
    # Dentries.
    table=q(var('dentry_hashtable'));shift=u32('d_hash_shift');count=1<<(32-shift)
    o_hash=lay.offset('struct:dentry','d_hash');o_name=lay.offset('struct:dentry','d_name');o_parent=lay.offset('struct:dentry','d_parent')
    chains=t.chains(table,count,True);fixed={}
    for i,nodes in chains.items():
        for node in nodes:
            d=node-o_hash;hash_len=q(d+o_name);length=hash_len>>32;name=t.cstring(q(d+o_name+8))[:length];parent=q(d+o_parent)
            old=full_name_hash(parent,name)
            if old!=hash_len&0xffffffff or old>>shift!=i:raise ValueError('dentry %#x (%r): hash self-check failed'%(d,name))
            new=full_name_hash(move(parent),name);fixed[node]=new>>shift
            put(pa(d+o_name),new|length<<32,'d_name.hash')
    summary['dentries']=t.relink(table,count,chains,lambda node:fixed[node],'dentry_hashtable')
    # Mounts and mountpoints.
    o_mhash=lay.offset('struct:mount','mnt_hash');o_mparent=lay.offset('struct:mount','mnt_parent')
    o_mnt=lay.offset('struct:mount','mnt');o_mpoint=lay.offset('struct:mount','mnt_mountpoint')
    shift,mask=u32('m_hash_shift'),u32('m_hash_mask');table=q(var('mount_hashtable'));chains=t.chains(table,mask+1,False);fixed={}
    for i,nodes in chains.items():
        for node in nodes:
            m=node-o_mhash;parent=q(m+o_mparent);point=q(m+o_mpoint)
            if m_hash(parent+o_mnt,point,shift,mask)!=i:raise ValueError('mount %#x: hash self-check failed'%m)
            fixed[node]=m_hash(move(parent)+o_mnt,move(point),shift,mask)
    summary['mounts']=t.relink(table,mask+1,chains,lambda node:fixed[node],'mount_hashtable')
    o_phash=lay.offset('struct:mountpoint','m_hash');o_pdentry=lay.offset('struct:mountpoint','m_dentry')
    shift,mask=u32('mp_hash_shift'),u32('mp_hash_mask');table=q(var('mountpoint_hashtable'));chains=t.chains(table,mask+1,False);fixed={}
    for i,nodes in chains.items():
        for node in nodes:
            dentry=q(node-o_phash+o_pdentry)
            if mp_hash(dentry,shift,mask)!=i:raise ValueError('mountpoint %#x: hash self-check failed'%node)
            fixed[node]=mp_hash(move(dentry),shift,mask)
    summary['mountpoints']=t.relink(table,mask+1,chains,lambda node:fixed[node],'mountpoint_hashtable')
    # Inodes.
    o_ihash=lay.offset('struct:inode','i_hash');o_sb=lay.offset('struct:inode','i_sb');o_ino=lay.offset('struct:inode','i_ino')
    shift,mask=u32('i_hash_shift'),u32('i_hash_mask');table=q(var('inode_hashtable'));chains=t.chains(table,mask+1,False);fixed={}
    for i,nodes in chains.items():
        for node in nodes:
            inode=node-o_ihash;sb=q(inode+o_sb);ino=q(inode+o_ino)
            if inode_hash(sb,ino,shift,mask)!=i:raise ValueError('inode %#x (ino %d): hash self-check failed'%(inode,ino))
            fixed[node]=inode_hash(move(sb),ino,shift,mask)
    summary['inodes']=t.relink(table,mask+1,chains,lambda node:fixed[node],'inode_hashtable')
    # Waiters and in-progress lookups: must be empty.
    # __futex_data {queues, hashsize}; clang may split a static struct into __futex_data.0 and .1.
    try:data=var('__futex_data');queues=q(data);size=q(data+8)
    except KeyError:queues=q(var('__futex_data.0'));size=q(var('__futex_data.1'))
    o_waiters=lay.offset('struct:futex_hash_bucket','waiters')
    bucket=lay.size('struct:futex_hash_bucket')
    busy=[i for i in range(size) if t.u32(queues+i*bucket+o_waiters)]
    if busy:raise ValueError('futex hash buckets with waiters: %s'%busy[:8])
    for name in ('folio_wait_table','bit_wait_table'):
        base=var(name);o_head=lay.offset('struct:wait_queue_head','head');step=lay.size('struct:wait_queue_head')
        for i in range(256):
            head=base+i*step+o_head
            if q(head)!=head:raise ValueError('%s[%d] has waiters'%(name,i))
    base=var('in_lookup_hashtable')
    if any(q(base+8*i)&~1 for i in range(lookup_buckets)):raise ValueError('lookups in progress at the boundary')
    summary['empty_waiter_tables']=['futex queues (%d)'%size,'folio_wait_table','bit_wait_table','in_lookup_hashtable (%d)'%lookup_buckets]
    return summary
