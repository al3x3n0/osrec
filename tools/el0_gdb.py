"""Bounded all-stop GDB transport for an externally configured AArch64 EL0 model.

Uses target XML register numbers, checked RSP packets and hardware breakpoints.
No monitor, semihosting, target-process creation or privileged register setup.
"""
import re
import time
import xml.etree.ElementTree as ET

from aarch64_entry_state import decode_packet
from gdb_remote import Remote,Exited


class GdbTarget(Remote):
    packet_bytes=1024

    def __init__(self,port,host='127.0.0.1',timeout=60):
        try:
            super().__init__(port,host,timeout)
            self.numbers={};seen=set();number=0;architectures=set();used_numbers=set()
            def visit(name):
                nonlocal number
                if name in seen or len(seen)>=32:raise ValueError('recursive/oversized target XML')
                seen.add(name)
                tree=ET.fromstring(self.document(name).replace('xi:include','include'))
                for node in tree.iter():
                    tag=node.tag.rsplit('}',1)[-1]
                    if tag=='include':visit(node.attrib['href'])
                    elif tag=='architecture':architectures.add((node.text or '').strip())
                    elif tag=='reg':
                        number=int(node.get('regnum',str(number)),0)
                        # QEMU exposes FPCR/FPSR system-register aliases alongside the
                        # lowercase standard FP feature. Preserve distinct XML names.
                        key=node.attrib['name'];bits=int(node.attrib['bitsize'])
                        if key in self.numbers or number in used_numbers or number<0 or bits<=0 or bits>2048:
                            raise ValueError(f'invalid/duplicate target register {key}: number={number}, bits={bits}')
                        self.numbers[key]=(number,bits);used_numbers.add(number);number+=1
            visit('target.xml')
            if architectures!={'aarch64'}:raise ValueError('target XML must declare aarch64')
            def named(key):
                if key in self.numbers:return key
                matches=[n for n in self.numbers if n.lower()==key]
                if len(matches)!=1:raise ValueError('missing or ambiguous target register '+key)
                return matches[0]
            self.aliases={n:named(n) for n in ('pc','x0')}
            for name,bits in [('pc',64),('x0',64)]:
                if self.numbers[self.aliases[name]][1]!=bits:
                    raise ValueError('missing or invalid target register '+name)
            self.pstate=named('cpsr' if any(n.lower()=='cpsr' for n in self.numbers) else 'pstate')
            if self.numbers[self.pstate][1] not in (32,64):
                raise ValueError('target must expose CPSR/PSTATE')
        except Exception:
            if hasattr(self,'socket'):self.socket.close()
            raise

    def request(self,packet):
        reply=super().request(packet)
        if packet.startswith('qSupported'):
            match=re.search(r'(?:^|;)PacketSize=([0-9a-fA-F]+)(?:;|$)',reply)
            if match:
                self.packet_bytes=int(match[1],16)
                if not 128<=self.packet_bytes<=1<<20:raise ValueError('unsupported GDB PacketSize')
        return reply

    def receive(self,timeout=None):
        deadline=time.monotonic()+(self.timeout if timeout is None else timeout)
        while True:
            match=re.search(rb'\$([^#]*)#([0-9a-fA-F]{2})',self.buffer)
            if match:
                self.buffer=self.buffer[match.end():]
                if sum(match[1])&255!=int(match[2],16):
                    self.socket.sendall(b'-');raise ValueError('GDB packet checksum mismatch')
                self.socket.sendall(b'+');data=decode_packet(match[1])
                if len(data)>2<<20:raise ValueError('oversized decoded GDB packet')
                return data.decode('ascii')
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('GDB response timed out')
            self.socket.settimeout(remaining)
            try:chunk=self.socket.recv(65536)
            except ConnectionResetError:chunk=b''
            if not chunk:raise Exited('gdbstub closed')
            self.buffer+=chunk
            if len(self.buffer)>2<<20:raise ValueError('oversized GDB packet')

    def document(self,name):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+',name):raise ValueError('invalid target XML annex')
        data=''
        while len(data)<1<<20:
            reply=self.request('qXfer:features:read:%s:%x,%x'%(name,len(data),min(1024,self.packet_bytes//2)))
            if reply[:1] not in ('m','l') or (reply[:1]=='m' and len(reply)==1):
                raise ValueError('target description unavailable: '+name)
            data+=reply[1:]
            if reply[0]=='l':return data
        raise ValueError('oversized target XML')

    @property
    def transfer_bytes(self):return min(65536,(self.packet_bytes-64)//2)

    def read(self,address,size):
        data=bytearray()
        while len(data)<size:
            count=min(self.transfer_bytes,size-len(data));at=address+len(data)
            reply=self.request('m%x,%x'%(at,count))
            if len(reply)!=2*count or not re.fullmatch('[0-9a-fA-F]*',reply):
                raise ValueError('memory unreadable at '+hex(at))
            data.extend(bytes.fromhex(reply))
        return bytes(data)

    def write(self,address,data):
        for offset in range(0,len(data),self.transfer_bytes):
            block=data[offset:offset+self.transfer_bytes]
            if self.request('M%x,%x:%s'%(address+offset,len(block),block.hex()))!='OK':
                raise ValueError('memory write failed at '+hex(address+offset))

    def set_pc(self,address):
        number,bits=self.numbers[self.aliases['pc']]
        if self.request('P%x=%s'%(number,address.to_bytes(bits//8,'little').hex()))!='OK' or self.register('pc')!=address:
            raise ValueError('target did not accept ELF entry PC')

    def register(self,name):return super().register(self.aliases.get(name,name))

    def breakpoint(self,address,insert=True):
        if self.request(('Z1' if insert else 'z1')+',%x,4'%address)!='OK':
            raise ValueError('hardware completion breakpoint unavailable at '+hex(address))

    def crc32(self,address,size):
        reply=self.request('qCRC:%x,%x'%(address,size))
        if not re.fullmatch('C[0-9a-fA-F]{1,8}',reply):
            raise ValueError('target qCRC unavailable; use byte verification')
        return int(reply[1:],16)

    def interrupt(self):
        self.socket.sendall(b'\x03');reply=self.receive(2)
        if not reply.startswith(('T02','S02','T05','S05')):raise ValueError('target did not halt after interrupt')

    def close(self):self.socket.close()
