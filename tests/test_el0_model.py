"""EL0 model acceptance: loading, entry, completion, diagnostics and GDB packets."""
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from audit_el0_image import audit
from check_el0_program import load_plan
from el0_gdb import GdbTarget
from gdb_remote import Exited
from el0_model import run,initial_blocks,rsp_crc,decode_result,MAX64

LLVM=Path('/opt/homebrew/opt/llvm@16/bin')
GOOD=[0x324c55464652534f,2,1,1,1,1,1,0,0,0,0,0,MAX64,0,0,0]+[0]*24
# A protocol fixture, not a captured-kernel demonstration. Its small copy loop
# produces a known result record so a real stub can exercise loading and stops.
SOURCE='''
.text
.global _start,flat_completed
_start:
    adr x1,fixture_result
    adr x2,flat_full_result
    mov x3,#40
1:  ldr x4,[x1],#8
    str x4,[x2],#8
    subs x3,x3,#1
    b.ne 1b
    mov x0,#0
flat_completed:
    mov x8,#93
    svc #0
.data
fixture_result:
'''+'.quad '+','.join(map(str,GOOD))+'''
.bss
.balign 16
.global flat_full_result
.type flat_full_result,%object
flat_full_result:
    .space 320
.size flat_full_result,.-flat_full_result
.space 4096
'''


class CrcTests(unittest.TestCase):
    def test_qcrc_against_independent_bitwise_polynomial(self):
        for data in (b'',b'123456789',bytes(range(256)),bytes(10003)):
            crc=0xffffffff
            for b in data:
                crc^=b<<24
                for _ in range(8):crc=((crc<<1)^(0x04c11db7 if crc&0x80000000 else 0))&0xffffffff
            self.assertEqual(rsp_crc(data),crc)

    def test_result_rejects_truncation_failure_and_inconsistent_metadata(self):
        self.assertEqual(decode_result(struct.pack('<40Q',*GOOD))['events'],1)
        with self.assertRaises(ValueError):decode_result(bytes(319))
        for index,value in [(0,0),(1,3),(2,2),(3,0),(4,0),(5,0),(6,3),(12,0),(13,4)]:
            words=GOOD.copy();words[index]=value
            with self.subTest(index=index),self.assertRaises(ValueError):decode_result(struct.pack('<40Q',*words))


class MemoryTarget:
    pstate='cpsr'
    timeout=1
    def __init__(self,plan,binary):
        self.plan=plan;self.pc=int(plan['entry'],0);self.mode=0;self.x0=0;self.memory={}
        self.writes=[];self.pc_writes=[];self.resumes=0;self.interrupts=0;self.breaks=[]
        self.result=GOOD.copy();self.stop=int(plan['stop_before_optional_exit'],0)
        self.wait_error=None;self.no_break=False;self.closed=False
        for address,data,_ in initial_blocks(binary,plan['load_segments']):
            self.memory.update((address+i,b) for i,b in enumerate(data))
    def request(self,packet):return 'T05'
    def register(self,name):return {'pc':self.pc,'cpsr':self.mode,'x0':self.x0}[name]
    def read(self,address,size):return bytes(self.memory.get(address+i,0) for i in range(size))
    def write(self,address,data):
        self.writes.append((address,len(data)));self.memory.update((address+i,b) for i,b in enumerate(data))
    def set_pc(self,address):self.pc_writes.append(address);self.pc=address
    def crc32(self,address,size):return rsp_crc(self.read(address,size))
    def breakpoint(self,address,insert=True):
        if self.no_break:raise ValueError('hardware breakpoint unsupported')
        self.breaks.append((address,insert))
    def resume(self):self.resumes+=1
    def wait(self,timeout):
        if self.wait_error:raise self.wait_error
        self.pc=self.stop;self.write(int(self.plan['result']['address'],0),struct.pack('<40Q',*self.result))
        return self.pc
    def interrupt(self):self.interrupts+=1
    def close(self):self.closed=True


@unittest.skipUnless((LLVM/'llvm-mc').exists() and (LLVM/'ld.lld').exists(),'AArch64 LLVM tools required')
class ModelTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.image=self.root/'image';self.image.mkdir()
        (self.root/'a.S').write_text(SOURCE)
        subprocess.run([str(LLVM/'llvm-mc'),'-triple=aarch64-linux-gnu','-filetype=obj',str(self.root/'a.S'),
                        '-o',str(self.root/'a.o')],check=True,capture_output=True)
        subprocess.run([str(LLVM/'ld.lld'),'-static','-e','_start',str(self.root/'a.o'),
                        '-o',str(self.image/'checkpoint')],check=True,capture_output=True)
        self.plan=load_plan(self.image,audit(self.image/'checkpoint'))
        self.target=MemoryTarget(self.plan,self.image/'checkpoint')

    def run_model(self,**options):
        return run(self.image,self.root/'evidence',12345,target_factory=lambda *a:self.target,**options)

    def test_loads_file_bytes_and_zero_tails_then_checks_result(self):
        self.target.pc=0
        self.target.memory={a:0xa5 for a in self.target.memory}
        report=self.run_model()
        self.assertTrue(report['verified'],report)
        memory=report['initial_memory']
        self.assertGreater(memory['zero_tail_bytes'],0)
        self.assertEqual(memory['written_bytes'],sum(s['memory_bytes'] for s in self.plan['load_segments']))
        self.assertTrue(memory['exact_byte_comparison']);self.assertEqual(self.target.resumes,1)
        self.assertEqual(self.target.pc_writes,[int(self.plan['entry'],0)])
        self.assertTrue(self.target.closed);self.assertFalse(report['rtl_execution_verified'])
        self.assertFalse(report['terminal_exit_executed_before_observation'])
        self.assertEqual((self.root/'evidence/result.bin').stat().st_size,320)

    def test_preloaded_crc_mode_has_no_host_memory_or_register_writes(self):
        # Simulate target computation separately, outside the loader's write API.
        def compute(timeout):
            self.target.pc=self.target.stop
            raw=struct.pack('<40Q',*GOOD);at=int(self.plan['result']['address'],0)
            self.target.memory.update((at+i,b) for i,b in enumerate(raw));return self.target.stop
        self.target.wait=compute
        report=self.run_model(preloaded=True,memory_check='crc32')
        self.assertTrue(report['verified'],report)
        self.assertEqual(self.target.writes,[]);self.assertEqual(self.target.pc_writes,[])
        self.assertFalse(report['initial_memory']['exact_byte_comparison'])
        self.assertIsNone(report['cycle_count'])

    def test_wrong_preloaded_code_and_zero_tail_stop_before_execution(self):
        for segment,offset in [(self.plan['load_segments'][0],0),(self.plan['load_segments'][-1],-1)]:
            target=MemoryTarget(self.plan,self.image/'checkpoint');self.target=target
            at=segment['address']+(segment['memory_bytes']-1 if offset==-1 else offset)
            target.memory[at]^=1
            report=run(self.image,self.root/('bad-'+str(at)),12345,preloaded=True,target_factory=lambda *a:target)
            self.assertFalse(report['verified']);self.assertEqual(target.resumes,0)
            self.assertEqual(report['failed_stage'],'initial-memory')

    def test_changed_plan_rejected_before_connecting(self):
        self.plan['execution_level']=1;(self.image/'load-plan.json').write_text(json.dumps(self.plan))
        connect=Mock(side_effect=AssertionError('connected before preflight'))
        with self.assertRaisesRegex(ValueError,'load plan'):
            run(self.image,self.root/'evidence',12345,target_factory=connect)
        connect.assert_not_called();self.assertFalse((self.root/'evidence').exists())

    def test_el1_entry_is_rejected_before_memory_writes(self):
        self.target.mode=5
        report=self.run_model()
        self.assertFalse(report['verified']);self.assertEqual(self.target.writes,[])
        self.assertEqual(self.target.resumes,0)

    def test_wrong_preloaded_pc_is_rejected_before_memory_access(self):
        self.target.pc+=4
        report=self.run_model(preloaded=True)
        self.assertFalse(report['verified']);self.assertEqual(self.target.resumes,0)
        self.assertEqual(self.target.writes,[])

    def test_no_hardware_breakpoint_does_not_resume(self):
        self.target.no_break=True
        report=self.run_model(preloaded=True)
        self.assertFalse(report['verified']);self.assertEqual(self.target.resumes,0)

    def test_optional_crc_support_is_not_assumed(self):
        self.target.crc32=Mock(side_effect=ValueError('qCRC unavailable'))
        report=self.run_model(preloaded=True,memory_check='crc32')
        self.assertFalse(report['verified']);self.assertEqual(self.target.resumes,0)
        self.assertEqual(report['failed_stage'],'initial-memory')

    def test_timeout_interrupts_target_and_preserves_failed_evidence(self):
        self.target.wait_error=TimeoutError('expired')
        report=self.run_model(preloaded=True)
        self.assertFalse(report['verified']);self.assertEqual(self.target.interrupts,1)
        self.assertEqual(self.target.breaks[-1],(self.target.stop,False))
        self.assertEqual(json.loads((self.root/'evidence/verification.json').read_text())['failed_stage'],'execution')

    def test_unexpected_signal_does_not_interrupt_an_already_halted_target(self):
        def stopped(timeout):
            self.target.execution_state='halted';self.target.last_stop_reply='S04'
            raise ValueError('unexpected stop: S04')
        self.target.wait=stopped
        report=self.run_model(preloaded=True)
        self.assertFalse(report['verified']);self.assertEqual(self.target.interrupts,0)
        self.assertEqual(report['execution_stop_reply'],'S04')
        self.assertEqual(self.target.breaks[-1],(self.target.stop,False))
        self.assertNotIn('cleanup_error',report);self.assertTrue(self.target.closed)

    def test_exit_does_not_interrupt_or_update_breakpoints_on_a_dead_target(self):
        def exited(timeout):
            self.target.execution_state='exited';self.target.last_stop_reply='W00'
            raise Exited('W00')
        self.target.wait=exited
        report=self.run_model(preloaded=True)
        self.assertFalse(report['verified']);self.assertEqual(self.target.interrupts,0)
        self.assertEqual(self.target.breaks,[(self.target.stop,True)])
        self.assertEqual(report['execution_stop_reply'],'W00');self.assertTrue(self.target.closed)
        self.assertIsNone(report['terminal_exit_executed_before_observation'])

    def test_cleanup_failure_revokes_success_and_closes_connection(self):
        original=self.target.breakpoint
        def breakpoint(address,insert=True):
            if not insert:raise ValueError('cannot remove breakpoint')
            original(address,insert)
        self.target.breakpoint=breakpoint
        report=self.run_model(preloaded=True)
        self.assertFalse(report['verified']);self.assertEqual(report['failed_stage'],'cleanup')
        self.assertIn('cannot remove',report['cleanup_error']);self.assertTrue(self.target.closed)
        self.assertTrue((self.root/'evidence/result.bin').is_file())

    def test_failed_runtime_result_is_saved_and_rejected(self):
        self.target.result[2]=2
        report=self.run_model(preloaded=True)
        self.assertFalse(report['verified']);self.assertTrue((self.root/'evidence/result.bin').is_file())

    def test_unexpected_stop_and_nonzero_return_are_rejected(self):
        self.target.stop+=4
        report=self.run_model(preloaded=True)
        self.assertFalse(report['verified']);self.assertEqual(report['failed_stage'],'execution')
        self.assertEqual(self.target.resumes,1)

    def test_nonzero_executor_return_is_rejected(self):
        self.target.x0=9
        report=self.run_model(preloaded=True)
        self.assertFalse(report['verified']);self.assertIn('nonzero',report['error'])

    def test_memory_budget_rejected_before_mutating_model(self):
        with self.assertRaisesRegex(ValueError,'memory budget'):self.run_model(max_memory_bytes=1)
        self.assertEqual(self.target.writes,[]);self.assertEqual(self.target.resumes,0)

    def test_nonfinite_timeouts_rejected_before_connecting(self):
        connect=Mock(side_effect=AssertionError('connected before preflight'))
        for timeout in (float('nan'),float('inf'),-float('inf')):
            with self.subTest(timeout=timeout),self.assertRaisesRegex(ValueError,'invalid runner limits'):
                run(self.image,self.root/'evidence',12345,timeout=timeout,target_factory=connect)
        connect.assert_not_called();self.assertFalse((self.root/'evidence').exists())

    def test_elf_changed_during_initialization_is_not_executed(self):
        read=self.target.read;changed=False
        def changing_read(address,size):
            nonlocal changed
            data=read(address,size)
            if not changed:
                changed=True;path=self.image/'checkpoint';binary=bytearray(path.read_bytes())
                binary[-1]^=1;path.write_bytes(binary)
            return data
        self.target.read=changing_read
        report=self.run_model(preloaded=True)
        self.assertFalse(report['verified']);self.assertIn('ELF changed',report['error'])
        self.assertEqual(self.target.resumes,0)


class ScriptedSocket:
    def __init__(self,annexes,packet_size='80'):
        self.annexes=annexes;self.buffer=b'';self.commands=[];self.memory={};self.packet_size=packet_size;self.closed=False
    def setsockopt(self,*a):pass
    def settimeout(self,*a):pass
    def close(self):self.closed=True
    def sendall(self,packet):
        if not packet.startswith(b'$'):return
        command=packet[1:packet.rindex(b'#')].decode();self.commands.append(command)
        if command.startswith('qSupported'):reply='PacketSize='+self.packet_size+';qXfer:features:read+'
        elif command.startswith('qXfer'):
            name,extent=command.split(':')[-2:];offset,length=(int(v,16) for v in extent.split(','))
            text=self.annexes[name];part=text[offset:offset+length]
            reply=('l' if offset+len(part)==len(text) else 'm')+part
        elif command.startswith('M'):
            extent,data=command[1:].split(':');address,count=(int(v,16) for v in extent.split(','))
            raw=bytes.fromhex(data);assert count==len(raw)
            self.memory.update((address+i,b) for i,b in enumerate(raw));reply='OK'
        elif command.startswith('m'):
            address,count=(int(v,16) for v in command[1:].split(','))
            reply=bytes(self.memory.get(address+i,0) for i in range(count)).hex()
        elif command.startswith('P'):reply='OK' # Deliberately acknowledge without changing PC.
        elif command.startswith('p'):reply='0000000000000000'
        elif command.startswith(('Z1','z1')):reply='OK'
        else:raise AssertionError('unexpected command '+command)
        data=reply.encode();self.buffer+=b'+$'+data+b'#%02x'%(sum(data)&255)
    def recv(self,size):
        if not self.buffer:raise TimeoutError('no scripted response')
        data=self.buffer[:size];self.buffer=self.buffer[size:];return data


class TransportTests(unittest.TestCase):
    def open_target(self,annexes,packet_size='80'):
        peer=ScriptedSocket(annexes,packet_size)
        with patch('gdb_remote.socket.create_connection',return_value=peer):target=GdbTarget(1234)
        return target,peer

    def test_inline_xml_and_packet_bounded_memory_writes(self):
        target,peer=self.open_target({'target.xml':'''<target><architecture>aarch64</architecture><feature name="core">
            <reg regnum="0" name="x0" bitsize="64"/><reg name="pc" regnum="32" bitsize="64"/>
            <reg name="cpsr" bitsize="32"/></feature></target>'''})
        self.assertEqual(target.numbers['cpsr'],(33,32))
        data=bytes(range(256));target.write(0x1000,data);self.assertEqual(target.read(0x1000,256),data)
        self.assertTrue(all(len(c)<=128 for c in peer.commands if c.startswith('M')))
        target.breakpoint(0x2000);self.assertIn('Z1,2000,4',peer.commands)

    def test_nested_xml_numbering_continues_across_features(self):
        target,peer=self.open_target({'target.xml':'<target><architecture>aarch64</architecture><xi:include href="core.xml"/><xi:include href="fp.xml"/></target>',
            'core.xml':'<feature><reg name="x0" bitsize="64" regnum="0"/><reg name="pc" bitsize="64" regnum="32"/><reg name="cpsr" bitsize="32"/></feature>',
            'fp.xml':'<feature><reg name="v0" bitsize="128"/><reg name="fpcr" bitsize="32"/><reg name="FPCR" bitsize="64"/></feature>'})
        self.assertEqual(target.numbers['v0'],(34,128));self.assertEqual(target.numbers['fpcr'],(35,32))
        self.assertEqual(target.numbers['FPCR'],(36,64))

    def test_checksum_corruption_is_rejected(self):
        target=GdbTarget.__new__(GdbTarget);target.timeout=1
        target.buffer=b'$T05#00';target.socket=ScriptedSocket({})
        with self.assertRaisesRegex(ValueError,'checksum'):target.receive()

    def test_acknowledged_but_ignored_pc_write_is_rejected(self):
        target,_=self.open_target({'target.xml':'''<target><architecture>aarch64</architecture><feature>
            <reg name="x0" bitsize="64" regnum="0"/><reg name="pc" bitsize="64" regnum="32"/>
            <reg name="cpsr" bitsize="32"/></feature></target>'''})
        with self.assertRaisesRegex(ValueError,'did not accept ELF entry PC'):target.set_pc(0x40200000)

    def test_large_advertised_packet_capacity_keeps_local_transfer_limit(self):
        target,peer=self.open_target({'target.xml':'''<target><architecture>aarch64</architecture><feature>
            <reg name="x0" bitsize="64" regnum="0"/><reg name="pc" bitsize="64" regnum="32"/>
            <reg name="cpsr" bitsize="32"/></feature></target>'''},packet_size='10000000')
        self.assertEqual(target.transfer_bytes,65536)
        data=bytes(range(256))*600;target.write(0x1000,data)
        self.assertEqual(target.read(0x1000,len(data)),data)
        self.assertTrue(all(len(c)<1<<20 for c in peer.commands))

    def test_stop_replies_record_execution_state_before_error_or_register_read(self):
        for reply,state,error in [('S04','halted',ValueError),('T0bthread:1;','halted',ValueError),
                                  ('W00','exited',Exited),('X0b;process:1','exited',Exited),
                                  ('S05extra','running',ValueError),('OK','running',ValueError)]:
            target=GdbTarget.__new__(GdbTarget);target.execution_state='running'
            target.receive=Mock(return_value=reply);target.register=Mock()
            with self.subTest(reply=reply),self.assertRaises(error):target.wait(1)
            self.assertEqual(target.execution_state,state);self.assertEqual(target.last_stop_reply,reply)
            target.register.assert_not_called()
        target.receive=Mock(return_value='T05hwbreak:;');target.register=Mock(side_effect=ValueError('unreadable PC'))
        with self.assertRaisesRegex(ValueError,'unreadable PC'):target.wait(1)
        self.assertEqual(target.execution_state,'halted')


@unittest.skipUnless(os.environ.get('OSREC_EL0_MODEL_IMAGE') and shutil.which('qemu-aarch64'),
                     'set OSREC_EL0_MODEL_IMAGE and install qemu-aarch64 for the functional GDB integration')
class QemuIntegration(unittest.TestCase):
    def workspace(self):
        destination=os.environ.get('OSREC_EL0_MODEL_EVIDENCE')
        if destination:
            Path(destination).mkdir(parents=True,exist_ok=True)
            root=Path(tempfile.mkdtemp(prefix='gdb-',dir=destination))
            print('GDB integration evidence:',root,flush=True)
            return root
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        return Path(temp.name)

    def execute(self,image,root,preloaded,expected_verified=True):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        with (root/'qemu.log').open('wb') as log:
            process=subprocess.Popen(['qemu-aarch64','-cpu','cortex-a53','-g',str(port),str(image/'checkpoint')],
                                     stdout=log,stderr=log)
            try:
                report=run(image,root/'evidence',port,preloaded=preloaded,timeout=120,
                           label='QEMU user-mode functional GDB stub',
                           progress=lambda done,total:print(f'Initial RAM checked: {done}/{total}',flush=True))
                self.assertEqual(report['verified'],expected_verified,report)
                self.assertFalse(report['rtl_execution_verified'])
                self.assertTrue(report['initial_memory']['exact_byte_comparison'])
                return report
            finally:
                process.terminate();process.wait(timeout=10)

    def test_preloaded_real_executor_over_gdb(self):
        image=Path(os.environ['OSREC_EL0_MODEL_IMAGE']).resolve()
        report=self.execute(image,self.workspace(),True)
        self.assertEqual(report['initial_memory']['written_bytes'],0)

    @unittest.skipUnless(shutil.which('clang-19'),'AArch64 clang-19 required')
    def test_load_small_protocol_fixture(self):
        root=self.workspace();image=self.fixture(root,SOURCE)
        report=self.execute(image,root,False)
        self.assertGreater(report['initial_memory']['written_bytes'],0)

    def fixture(self,root,source):
        image=root/'image';image.mkdir();(root/'fixture.S').write_text(source)
        subprocess.run(['clang-19','-nostdlib','-static','-fuse-ld=lld','-Wl,-e,_start',str(root/'fixture.S'),
                        '-o',str(image/'checkpoint')],check=True,capture_output=True)
        load_plan(image,audit(image/'checkpoint'))
        return image

    @unittest.skipUnless(shutil.which('clang-19'),'AArch64 clang-19 required')
    def test_invalid_instruction_stop_preserves_failure_without_cleanup_error(self):
        root=self.workspace();image=self.fixture(root,SOURCE.replace('flat_completed:', '.inst 0\nflat_completed:'))
        report=self.execute(image,root,False,expected_verified=False)
        self.assertEqual(report['failed_stage'],'execution');self.assertEqual(report['target_execution_state'],'halted')
        self.assertIn(report['execution_stop_reply'][:3],('S04','T04'))
        self.assertIsNone(report['terminal_exit_executed_before_observation'])
        self.assertNotIn('cleanup_error',report)

    @unittest.skipUnless(shutil.which('clang-19'),'AArch64 clang-19 required')
    def test_failed_embedded_result_is_rejected_over_gdb(self):
        words=GOOD.copy();words[2]=2
        root=self.workspace();image=self.fixture(root,SOURCE.replace(','.join(map(str,GOOD)),','.join(map(str,words))))
        report=self.execute(image,root,False,expected_verified=False)
        self.assertEqual(report['failed_stage'],'result');self.assertNotIn('cleanup_error',report)
        self.assertFalse(report['terminal_exit_executed_before_observation'])
        self.assertEqual(struct.unpack('<40Q',(root/'evidence/result.bin').read_bytes())[2],2)

    @unittest.skipUnless(shutil.which('clang-19'),'AArch64 clang-19 required')
    def test_terminal_exit_before_completion_is_rejected_without_dead_target_cleanup(self):
        root=self.workspace()
        # Execute the admitted exit instruction while bypassing its completion breakpoint.
        image=self.fixture(root,SOURCE.replace('flat_completed:', 'mov x8,#93\nb flat_completed+4\nflat_completed:'))
        report=self.execute(image,root,False,expected_verified=False)
        self.assertEqual(report['failed_stage'],'execution');self.assertEqual(report['execution_stop_reply'],'W00')
        self.assertEqual(report['target_execution_state'],'exited')
        self.assertIsNone(report['terminal_exit_executed_before_observation']);self.assertNotIn('cleanup_error',report)


if __name__=='__main__':unittest.main()
