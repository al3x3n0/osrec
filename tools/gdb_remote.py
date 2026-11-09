#!/usr/bin/env python3
"""Minimal GDB remote-serial-protocol client for QEMU's TCG gdbstub.

Only stop-mode packets are used: register/memory reads, software breakpoints,
single steps and continue. Register numbers come from the target description.
"""
import re,socket,time

class Exited(Exception):
    """The target terminated (W/X stop reply) or the stub closed the connection."""

class Remote:
    def __init__(self,port,host='127.0.0.1',timeout=60):
        self.timeout=timeout;self.buffer=b'';deadline=time.monotonic()+timeout
        while True:
            try:self.socket=socket.create_connection((host,port),timeout=timeout);break
            except OSError:
                if time.monotonic()>deadline:raise TimeoutError('gdbstub connection timed out')
                time.sleep(.05)
        # RSP sends acknowledgements separately from the next small request.
        # Nagle plus delayed ACKs otherwise stalls page-by-page state reads.
        self.socket.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        self.request('qSupported:xmlRegisters=aarch64');self.numbers={}
        for name in re.findall(r'xi:include href="([^"]+)"',self.document('target.xml')):
            number=0
            for reg,bits,explicit in re.findall(r'<reg name="([^"]+)" bitsize="(\d+)"(?:[^>]*regnum="(\d+)")?',self.document(name)):
                number=int(explicit) if explicit else number;self.numbers[reg]=(number,int(bits));number+=1
    def document(self,name):
        data='';offset=0
        while True:
            chunk=self.request('qXfer:features:read:%s:%x,ffff'%(name,offset))
            if chunk[:1] not in ('m','l'):raise ValueError('target description unavailable: '+name)
            data+=chunk[1:];offset+=len(chunk)-1
            if chunk[0]=='l':return data
    def send(self,packet):self.socket.sendall(b'$'+packet.encode()+b'#%02x'%(sum(packet.encode())&255))
    def receive(self,timeout=None):
        self.socket.settimeout(timeout or self.timeout)
        while True:
            match=re.search(rb'\$([^#]*)#[0-9a-fA-F]{2}',self.buffer)
            if match:
                self.buffer=self.buffer[match.end():];self.socket.sendall(b'+');return match.group(1).decode()
            try:chunk=self.socket.recv(65536)
            except ConnectionResetError:chunk=b''
            if not chunk:raise Exited('gdbstub closed')
            self.buffer+=chunk
    def request(self,packet):self.send(packet);return self.receive()
    def register(self,name):
        if name not in self.numbers:raise KeyError('target has no register '+name)
        value=self.request('p%x'%self.numbers[name][0])
        if value.startswith('E') or len(value)!=self.numbers[name][1]//4:raise ValueError('register read failed: '+name)
        return int.from_bytes(bytes.fromhex(value),'little')
    def registers(self,names):return {n:self.register(n) for n in names}
    def read(self,address,size):
        data=b''
        while len(data)<size:
            part=min(1024,size-len(data));value=self.request('m%x,%x'%(address+len(data),part))
            if value.startswith('E') or len(value)!=2*part:raise ValueError('memory unreadable at 0x%x'%(address+len(data)))
            data+=bytes.fromhex(value)
        return data
    def u(self,address,size=8):return int.from_bytes(self.read(address,size),'little')
    def breakpoint(self,address,insert=True):
        if self.request(('Z0' if insert else 'z0')+',%x,4'%address)!='OK':raise ValueError('breakpoint update failed at 0x%x'%address)
    def step(self):
        stop=self.request('s')
        if not stop.startswith(('T05','S05')):raise ValueError('unexpected single-step stop: '+stop)
    def resume(self):self.send('c')
    def wait(self,timeout=None):
        stop=self.receive(timeout)
        if stop[:1] in ('W','X'):raise Exited(stop)
        if not stop.startswith(('T05','S05')):raise ValueError('unexpected stop: '+stop)
        return self.register('pc')
    def detach(self):self.request('D');self.socket.close()
