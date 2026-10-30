"""Construct a deterministic Linux initramfs (newc cpio) without host tools.

The archive holds /dev, /dev/console (character device 5:1) and /init. The
kernel unpacks it into rootfs, which is ramfs when tmpfs is not configured, and
runs /init as PID 1 (`rdinit=/init`). No device nodes, privileges or cpio
programs are needed on the host; timestamps and ownership are fixed at zero.
"""

def _entry(number,name,mode,data=b'',rdev=(0,0)):
    name=name.encode('ascii')+b'\0'
    fields=(number,mode,0,0,1 if mode&0o170000!=0o040000 else 2,0,len(data),0,0,rdev[0],rdev[1],len(name),0)
    header=b'070701'+b''.join(b'%08X'%f for f in fields)
    pad=lambda n:b'\0'*((4-n%4)%4)
    return header+name+pad(len(header)+len(name))+data+pad(len(data))

def initramfs(program):
    if not program or len(program)>256*1024:raise ValueError('initramfs init size is out of range')
    archive=(_entry(1,'dev',0o040755)+_entry(2,'dev/console',0o020600,rdev=(5,1))+
             _entry(3,'init',0o100755,program)+_entry(4,'TRAILER!!!',0))
    return archive+b'\0'*((512-len(archive)%512)%512)
