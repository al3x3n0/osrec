"""Bounded AArch64 entry checks and read-only QEMU register observation."""
import os
import re
import select
import time
import xml.etree.ElementTree as ET


def higher_el_registers(implementation):
    if not isinstance(implementation,dict) or any(type(implementation.get(k)) is not bool for k in ('el2_implemented','el3_implemented')):
        raise ValueError('higher EL implementation requires explicit boolean EL2/EL3 presence')
    names=['mdscr_el1']
    if implementation['el2_implemented']:names+=['hcr_el2','cptr_el2','mdcr_el2']
    if implementation['el3_implemented']:names+=['scr_el3','cptr_el3','mdcr_el3']
    return names


def check_entry_state(layout,state):
    if layout['isa']!='AArch64':raise ValueError('CPU entry checking requires AArch64')
    if not isinstance(state,dict) or state.get('format') not in ('osrec-aarch64-entry-state-v1','osrec-aarch64-entry-state-v2'):
        raise ValueError('expected osrec-aarch64-entry-state-v1/v2 register snapshot')
    extended=state['format']=='osrec-aarch64-entry-state-v2'
    extra=higher_el_registers(state.get('implementation')) if extended else []
    for name,width in [('pc',64),('pstate',32),('sctlr_el1',64)]+[(k,64) for k in extra]:
        value=state.get(name)
        if type(value) is not int or not 0<=value<1<<width:
            raise ValueError(f'{name} must be an unsigned {width}-bit integer')
    pc,pstate,sctlr=(state[k] for k in ('pc','pstate','sctlr_el1'))
    if pc!=layout['entry']:raise ValueError('CPU PC differs from ELF entry')
    if pstate&31 not in (4,5):raise ValueError('CPU must enter in AArch64 EL1t or EL1h')
    if pstate&0x3c0!=0x3c0:raise ValueError('entry profile requires all DAIF masks set')
    if pstate&(3<<20):raise ValueError('entry profile requires PSTATE IL and SS clear')
    for name,bit in (('MMU',0),('data cache',2),('instruction cache',12),('EL1 big-endian data',25)):
        if sctlr&(1<<bit):raise ValueError(f'entry profile requires {name} disabled')
    report={'format':'osrec-aarch64-entry-verification-v1','status':'verified',
        'profile':'osrec-aarch64-mmu-off-entry-v1','registers':{k:state[k] for k in ('pc','pstate','sctlr_el1')},
        'checked_fields':['PC','PSTATE.M','PSTATE.DAIF','PSTATE.IL','PSTATE.SS',
            'SCTLR_EL1.M','SCTLR_EL1.C','SCTLR_EL1.I','SCTLR_EL1.EE'],
        'cpu_entry_state_verified':True,'snapshot_phase_verified':False,
        'scope':'listed register fields under a conservative MMU-off EL1 entry profile',
        'higher_el_trap_configuration_verified':False,'architecture_features_verified':False,
        'runtime_host_interaction':False,'rtl_execution_verified':False}
    if extended:
        implementation=state['implementation']
        for level,names in ((2,('hcr_el2','cptr_el2','mdcr_el2')),(3,('scr_el3','cptr_el3','mdcr_el3'))):
            if not implementation[f'el{level}_implemented'] and any(k in state for k in names):
                raise ValueError(f'EL{level} registers contradict declared absent implementation')
        if state['mdscr_el1']!=0:raise ValueError('extended entry profile requires MDSCR_EL1 zero')
        if implementation['el2_implemented']:
            if state['hcr_el2']!=1<<31:raise ValueError('extended entry profile requires HCR_EL2 RW only: no stage 2, routing, injection or traps')
            if state['cptr_el2']&~0x33ff:raise ValueError('extended entry profile requires CPTR_EL2 baseline trap/control bits clear')
            if state['mdcr_el2']&~31:raise ValueError('extended entry profile requires MDCR_EL2 control bits clear; HPMN is allowed')
        if implementation['el3_implemented']:
            if state['scr_el3']&~0x30!=0x401:raise ValueError('extended entry profile requires SCR_EL3 NS/RW only, apart from FW/AW')
            if state['cptr_el3']!=0:raise ValueError('extended entry profile requires CPTR_EL3 zero')
            if state['mdcr_el3']!=0:raise ValueError('extended entry profile requires MDCR_EL3 zero')
        report.update({'format':'osrec-aarch64-entry-verification-v2','profile':'osrec-aarch64-mmu-off-entry-v2',
            'implementation':{k:implementation[k] for k in ('el2_implemented','el3_implemented')},
            'implementation_presence_observed':False,
            'higher_el_trap_configuration_verified':True,
            'higher_el_verification_basis':'explicit implementation presence and conservative listed controls; absent levels require no register reads',
            'scope':'listed entry/debug/higher-EL controls under a conservative baseline profile; extension-specific controls are not verified'})
        report['registers'].update({k:state[k] for k in extra})
        report['checked_fields']+=['implementation.el2_implemented','implementation.el3_implemented']+extra
    return report


def decode_packet(data):
    result=bytearray();i=0
    while i<len(data):
        value=data[i];i+=1
        if value==ord('}'):
            if i==len(data):raise ValueError('truncated escaped debugger packet')
            result.append(data[i]^0x20);i+=1
        elif value==ord('*'):
            if not result or i==len(data) or data[i]<29:raise ValueError('invalid debugger repeat')
            result.extend(bytes([result[-1]])*(data[i]-29));i+=1
        else:result.append(value)
    return bytes(result)


class RegisterReader:
    """GDB remote protocol over local FIFOs; sends no execution/write packets."""
    def __init__(self,path):
        self.input=os.open(str(path)+'.in',os.O_WRONLY|os.O_NONBLOCK)
        try:self.output=os.open(str(path)+'.out',os.O_RDONLY|os.O_NONBLOCK)
        except Exception:os.close(self.input);raise
        self.buffer=bytearray()

    def close(self):
        os.close(self.input);os.close(self.output)

    def request(self,command):
        if not (command=='qSupported:qXfer:features:read+' or
                re.fullmatch(r'qXfer:features:read:[A-Za-z0-9_.-]+:[0-9a-f]+,1000',command) or
                re.fullmatch(r'p[0-9a-f]+',command)):
            raise ValueError('register observer permits only description/register reads')
        return self._exchange(command)

    def _exchange(self,command):
        raw=command.encode('ascii');os.write(self.input,b'$'+raw+b'#'+f'{sum(raw)%256:02x}'.encode())
        return self._receive()

    def _receive(self):
        deadline=time.monotonic()+5
        while True:
            if b'$' in self.buffer:
                start=self.buffer.index(ord('$'))
                if b'#' in self.buffer[start:]:
                    end=self.buffer.index(ord('#'),start)
                    if len(self.buffer)>=end+3:
                        data=bytes(self.buffer[start+1:end]);checksum=bytes(self.buffer[end+1:end+3])
                        del self.buffer[:end+3]
                        if int(checksum,16)!=sum(data)%256:raise ValueError('debugger packet checksum mismatch')
                        os.write(self.input,b'+');return decode_packet(data)
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([self.output],[],[],remaining)[0]:
                raise ValueError('register observer timed out')
            block=os.read(self.output,65536)
            if not block:raise ValueError('register observer closed')
            self.buffer.extend(block)
            if len(self.buffer)>4*1024*1024:raise ValueError('oversized debugger packet')

    def xml(self,name):
        result=bytearray()
        while True:
            block=self.request(f'qXfer:features:read:{name}:{len(result):x},1000')
            if block[:1] not in (b'm',b'l'):raise ValueError('register description unavailable')
            result.extend(block[1:])
            if len(result)>4*1024*1024:raise ValueError('oversized register description')
            if block[:1]==b'l':
                # GDB's DTD supplies the xi namespace; ElementTree deliberately
                # does not fetch external DTDs, so supply that default locally.
                if b'xmlns:xi=' not in result:
                    result=re.sub(rb'<target\b',b'<target xmlns:xi="http://www.w3.org/2001/XInclude"',bytes(result),count=1)
                return ET.fromstring(result)
            if len(block)==1:raise ValueError('empty register description continuation')

    def snapshot(self,implementation=None):
        extra=higher_el_registers(implementation) if implementation is not None else []
        self.request('qSupported:qXfer:features:read+')
        registers={};seen=set();next_register=0
        def visit(name):
            nonlocal next_register
            if name in seen or len(seen)>=32:raise ValueError('recursive/oversized register descriptions')
            seen.add(name)
            for item in self.xml(name).iter():
                if item.tag.endswith('}include'):visit(item.attrib['href'])
                elif item.tag=='reg':
                    number=int(item.get('regnum',str(next_register)),0);next_register=number+1
                    key=item.attrib['name'].lower()
                    # QEMU Cortex-A53 uses its shared AArch32/AArch64 name for
                    # the EL1 system control register in the dynamic XML.
                    if key=='sctlr':key='sctlr_el1'
                    if key in ['pc','cpsr','sctlr_el1']+extra:
                        if key in registers:raise ValueError('duplicate entry register description')
                        registers[key]=(number,int(item.attrib['bitsize']))
        visit('target.xml');state={'format':'osrec-aarch64-entry-state-v2' if implementation is not None else 'osrec-aarch64-entry-state-v1'}
        if implementation is not None:state['implementation']={k:implementation[k] for k in ('el2_implemented','el3_implemented')}
        for source,destination,width in [('pc','pc',64),('cpsr','pstate',32),('sctlr_el1','sctlr_el1',64)]+[(k,k,64) for k in extra]:
            if source not in registers or registers[source][1]!=width:raise ValueError(f'{source} register unavailable or wrong width')
            reply=self.request(f'p{registers[source][0]:x}')
            try:data=bytes.fromhex(reply.decode('ascii'))
            except ValueError as error:raise ValueError(f'{source} register read failed') from error
            if len(data)!=width//8:raise ValueError(f'incomplete {source} register read')
            state[destination]=int.from_bytes(data,'little')
        return state


def capture_qemu_entry(path,implementation=None):
    reader=RegisterReader(path)
    try:return reader.snapshot(implementation)
    finally:reader.close()


class EntryBreakpointController(RegisterReader):
    """External testbench control: one hardware entry breakpoint, no guest writes."""
    def arm(self,address):
        if type(address) is not int or not 0<=address<1<<64 or address%4:
            raise ValueError('entry breakpoint requires an aligned unsigned address')
        self.address=address
        if self._exchange(f'Z1,{address:x},4')!=b'OK':
            raise ValueError('entry hardware breakpoint unavailable')

    def run_and_remove(self):
        reply=self._exchange('c')
        if not reply.startswith((b'T05',b'S05')):
            raise ValueError('unexpected entry breakpoint stop')
        if self._exchange(f'z1,{self.address:x},4')!=b'OK':
            raise ValueError('entry hardware breakpoint removal failed')
