"""Construct a deterministic tiny Linux root disk without host filesystem tools.

One 1-KiB-block ext2 group, 128 inodes, /init and /dev/console. The ext4 driver
can mount this filesystem; capture uses a readonly disk. No host device nodes,
mount privileges or external mkfs programs are needed.
"""
import struct

def root_disk(program,blocks=2048):
    if not program or len(program)>256*1024:raise ValueError('minimal root init size is out of range')
    if type(blocks) is not int or not 512<=blocks<=8192:raise ValueError('minimal root block count is out of range')
    data=bytearray(blocks*1024);next_block=21
    def allocate(payload):
        nonlocal next_block
        if len(payload)>1024 or next_block>=blocks:raise ValueError('minimal root disk is full')
        index=next_block;next_block+=1;data[index*1024:index*1024+len(payload)]=payload;return index
    def directory(entries):
        raw=bytearray(1024);offset=0
        for i,(inode,name,kind) in enumerate(entries):
            name=name.encode('ascii');size=(8+len(name)+3)&~3
            length=size if i+1<len(entries) else 1024-offset
            struct.pack_into('<IHBB',raw,offset,inode,length,len(name),kind);raw[offset+8:offset+8+len(name)]=name;offset+=size
        return allocate(raw)
    root=directory([(2,'.',2),(2,'..',2),(11,'dev',2),(12,'init',1)])
    dev=directory([(11,'.',2),(2,'..',2),(13,'console',3)])
    parts=[allocate(program[i:i+1024]) for i in range(0,len(program),1024)]
    indirect=allocate(struct.pack('<'+'I'*len(parts[12:]),*parts[12:])) if len(parts)>12 else None
    def inode(index,mode,size,links,pointers,sectors):
        offset=5*1024+(index-1)*128
        struct.pack_into('<HHI',data,offset,mode,0,size)
        struct.pack_into('<HHI',data,offset+24,0,links,sectors)
        for i,block in enumerate(pointers):struct.pack_into('<I',data,offset+40+4*i,block)
    inode(2,0o40755,1024,3,[root],2);inode(11,0o40755,1024,2,[dev],2)
    inode(12,0o100755,len(program),1,parts[:12]+([indirect] if indirect else []),2*(len(parts)+(1 if indirect else 0)))
    inode(13,0o20600,0,1,[(5<<8)|1],0)
    # Superblock and sole group descriptor.
    sb=1024
    struct.pack_into('<IIIIIIIIIII',data,sb,128,blocks,0,blocks-next_block,115,1,0,0,8192,8192,128)
    struct.pack_into('<HHHHHH',data,sb+52,0,0xffff,0xef53,1,2,0)
    struct.pack_into('<IIIIHH',data,sb+64,0,0,0,1,0,0)
    struct.pack_into('<IHHIII',data,sb+84,11,128,0,0,2,0)
    data[sb+104:sb+120]=b'osrec-linux-root'
    data[sb+120:sb+131]=b'osrec-linux'
    struct.pack_into('<IIIHHH',data,2048,3,4,5,blocks-next_block,115,2)
    for bit in range(8192):
        if bit<next_block-1 or bit>=blocks-1:data[3072+bit//8]|=1<<(bit%8)
        if bit<13 or bit>=128:data[4096+bit//8]|=1<<(bit%8)
    assert len(data)==blocks*1024
    return bytes(data)
