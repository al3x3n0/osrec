"""Resident RAM preflight includes startup, stack, NOLOAD storage and raw loading."""
import argparse,json,os,shutil,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from freestanding_elf import describe,prepare_target,target_metadata
from freestanding_armv7 import run,audit
from image_memory import memory_contract,require_coverage,validate_raw,verify_loaded_memory
from check_image_memory import check,ram_region,memory_dump
from rtl_load_bundle import prepare as prepare_bundle,verify as verify_bundle,check_loaded
from aarch64_entry_state import check_entry_state,RegisterReader,decode_packet
from aarch64_boot import build as build_boot,verify as verify_boot,check_loaded as check_boot,expected_payload,BOOT_ADDRESS
from rtl_boot_bundle import prepare as prepare_boot_bundle,verify as verify_boot_bundle,check_loaded as check_boot_bundle
LLVM=Path('/opt/homebrew/opt/llvm@16/bin')

class ImageMemoryTests(unittest.TestCase):
    def test_boot_payload_and_physical_dumps(self):
        layout={'isa':'AArch64','entry':0x40200000,'raw_image_load_address':0x40200000,
            'load_segments':[{'address':0x40200000,'file_bytes':128,'memory_bytes':256}],
            'startup_zero_range':{'address':0x40200080,'bytes':128},
            'stack_range':{'address':0x40201000,'bytes':16384},'startup_zero_tail_bytes':0,
            'result_address':0x40180000,'result_bytes':128}
        ram=[{'address':0x40000000,'bytes':64*1024*1024}]
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);boot=stage/'boot';plan=build_boot(layout,boot,LLVM)
            raw=(boot/'boot.bin').read_bytes();self.assertEqual(raw,expected_payload(layout['entry']))
            self.assertEqual(verify_boot(layout,boot),plan)
            # Decode the entry immediate, including bits beyond the QEMU RAM map.
            for entry in (0x40200000,0x40400000,0x123456789abcdef0):
                words=struct.unpack('<26I',expected_payload(entry))
                decoded=sum(((words[19+i]>>5)&0xffff)<<(16*i) for i in range(4))
                self.assertEqual(decoded,entry)
            first=stage/'first.bin';second=stage/'second.bin'
            first.write_bytes(raw[:51]);second.write_bytes(raw[51:])
            dumps=[{'address':BOOT_ADDRESS,'file':first},{'address':BOOT_ADDRESS+51,'file':second}]
            report=check_boot(layout,boot,ram,dumps)
            self.assertEqual(report['initial_memory_verification']['verified_bytes'],len(raw))
            self.assertFalse(report['snapshot_phase_verified'])
            for index in (0,len(raw)-1):
                broken=bytearray(raw);broken[index]^=1;first.write_bytes(broken[:51]);second.write_bytes(broken[51:])
                with self.assertRaises(ValueError):check_boot(layout,boot,ram,dumps)
            first.write_bytes(raw[:51]);second.write_bytes(raw[51:])
            with self.assertRaises(ValueError):check_boot(layout,boot,ram,dumps[:1])
            with self.assertRaises(ValueError):check_boot(layout,boot,[{'address':BOOT_ADDRESS,'bytes':len(raw)}],dumps)
            for index in range(0,len(raw),4):
                altered=bytearray(raw);altered[index]^=1;(boot/'boot.bin').write_bytes(altered)
                with self.assertRaisesRegex(ValueError,'instruction template'):verify_boot(layout,boot)
            (boot/'boot.bin').write_bytes(raw)
            for key,value in (('entry',True),('replay_entry',layout['entry']+4),('runtime_host_interaction',True)):
                (boot/'boot-plan.json').write_text(json.dumps({**plan,key:value}))
                with self.assertRaises(ValueError):verify_boot(layout,boot)
            (boot/'boot-plan.json').write_text(json.dumps({**plan,'payload':{**plan['payload'],'file':'../../elsewhere'}}))
            with self.assertRaisesRegex(ValueError,'derived entry contract'):verify_boot(layout,boot)

    def test_aarch64_higher_el_profile(self):
        layout={'isa':'AArch64','entry':0x40200000}
        base={'format':'osrec-aarch64-entry-state-v2','pc':layout['entry'],'pstate':0x3c5,'sctlr_el1':0,'mdscr_el1':0}
        for el2,el3 in ((False,False),(True,False),(False,True),(True,True)):
            state={**base,'implementation':{'el2_implemented':el2,'el3_implemented':el3}}
            if el2:state.update(hcr_el2=1<<31,cptr_el2=0x33ff,mdcr_el2=6)
            if el3:state.update(scr_el3=0x431,cptr_el3=0,mdcr_el3=0)
            report=check_entry_state(layout,state)
            self.assertTrue(report['higher_el_trap_configuration_verified'])
            self.assertEqual(report['implementation'],state['implementation'])
            self.assertEqual(report['format'],'osrec-aarch64-entry-verification-v2')
            for key in ('mdscr_el1','hcr_el2','cptr_el2','mdcr_el2','scr_el3','cptr_el3','mdcr_el3'):
                if key not in state:continue
                missing=dict(state);del missing[key]
                with self.assertRaises(ValueError):check_entry_state(layout,missing)
                for invalid in (True,-1,1<<64,'0'):
                    with self.subTest(key=key,invalid=invalid),self.assertRaises(ValueError):check_entry_state(layout,{**state,key:invalid})
            for name in ('el2_implemented','el3_implemented'):
                for invalid in (0,1,'false',None):
                    with self.assertRaises(ValueError):check_entry_state(layout,{**state,'implementation':{**state['implementation'],name:invalid}})
        for key,values in (('mdscr_el1',[1,1<<13,1<<15]),
                           ('hcr_el2',[0]+[(1<<31)|(1<<bit) for bit in (0,6,7,8,12,26,27,30,34,63)]),
                           ('cptr_el2',[1<<bit for bit in (10,20,31,63)]),
                           ('mdcr_el2',[1<<bit for bit in (5,9,10,11,12,63)]),
                           ('scr_el3',[0,1,1<<10]+[0x401|(1<<bit) for bit in (1,2,3,9,18,63)]),
                           ('cptr_el3',[1,1<<10,1<<20,1<<31]),('mdcr_el3',[1,1<<16])):
            for value in values:
                with self.subTest(register=key,value=value),self.assertRaises(ValueError):check_entry_state(layout,{**state,key:value})
        absent={**base,'implementation':{'el2_implemented':False,'el3_implemented':False}}
        for key in ('hcr_el2','scr_el3'):
            with self.assertRaisesRegex(ValueError,'contradict'):check_entry_state(layout,{**absent,key:0})
        with self.assertRaises(ValueError):check_entry_state(layout,base)

    def verify_portable_boot(self,sources,replay,ram,layout):
        portable=sources/'portable-boot'
        if layout['isa']!='AArch64':
            with self.assertRaisesRegex(ValueError,'requires AArch64'):prepare_boot_bundle(replay,portable,LLVM)
            self.assertFalse(portable.exists());return
        plan=prepare_boot_bundle(replay,portable,LLVM)
        self.assertEqual(verify_boot_bundle(portable),plan)
        with self.assertRaises(FileExistsError):prepare_boot_bundle(replay,portable,LLVM)
        dumps=[]
        for i,load in enumerate(plan['loads']):
            target=sources/f'portable-dump-{i}.bin';shutil.copyfile(portable/load['file'],target)
            dumps.append({'address':load['address'],'file':target})
        report=check_boot_bundle(portable,ram,dumps)
        self.assertTrue(report['model_initial_memory_verified']);self.assertFalse(report['snapshot_phase_verified'])
        for key,value in (('entry',True),('replay_entry',layout['entry']+4),('artifact_bytes_verified',False)):
            (portable/'load-plan.json').write_text(json.dumps({**plan,key:value}))
            with self.assertRaises(ValueError):verify_boot_bundle(portable)
        altered=json.loads(json.dumps(plan));altered['loads'][-1]['file']='../../outside'
        (portable/'load-plan.json').write_text(json.dumps(altered))
        with self.assertRaises(ValueError):verify_boot_bundle(portable)
        (portable/'load-plan.json').write_text(json.dumps(plan))
        for load in plan['loads']:
            target=portable/load['file'];original=target.read_bytes();target.write_bytes(bytes([original[0]^1])+original[1:])
            with self.assertRaises(ValueError):verify_boot_bundle(portable)
            target.write_bytes(original)
        for dump in dumps:
            original=dump['file'].read_bytes();dump['file'].write_bytes(original[:-1]+bytes([original[-1]^1]))
            with self.assertRaises(ValueError):check_boot_bundle(portable,ram,dumps)
            dump['file'].write_bytes(original)
        with self.assertRaises(ValueError):check_boot_bundle(portable,ram,dumps[:-1])
        shutil.rmtree(portable)
        from unittest.mock import patch
        with patch('aarch64_boot.build',side_effect=ValueError('build failed')):
            with self.assertRaisesRegex(ValueError,'build failed'):prepare_boot_bundle(replay,portable,LLVM)
        self.assertFalse(portable.exists())
        with self.assertRaisesRegex(ValueError,'overlaps'):prepare_boot_bundle(replay,portable,LLVM,layout['entry'])
        self.assertFalse(portable.exists())

    def test_aarch64_cpu_entry_profile(self):
        layout={'isa':'AArch64','entry':0x40200000}
        state={'format':'osrec-aarch64-entry-state-v1','pc':layout['entry'],'pstate':0x3c5,'sctlr_el1':0}
        for pstate in (0x3c4,0x400003c5):
            self.assertTrue(check_entry_state(layout,{**state,'pstate':pstate})['cpu_entry_state_verified'])
        for name,values in (('pc',[layout['entry']+4,True,-1,1<<64,'0x40200000']),
                            ('pstate',[0x3c0,0x3c9,0x3cd,0x3d5,0x3c7,0x3c5|(1<<20),0x3c5|(1<<21),1<<32,True]),
                            ('sctlr_el1',[1,4,4096,1<<25,True,-1,1<<64])):
            for value in values:
                with self.subTest(register=name,value=value),self.assertRaises(ValueError):check_entry_state(layout,{**state,name:value})
        for bit in (6,7,8,9):
            with self.assertRaisesRegex(ValueError,'DAIF'):check_entry_state(layout,{**state,'pstate':state['pstate']&~(1<<bit)})
        for name in ('pc','pstate','sctlr_el1'):
            missing=dict(state);del missing[name]
            with self.assertRaises(ValueError):check_entry_state(layout,missing)
        with self.assertRaises(ValueError):check_entry_state({'isa':'ARMv7-A A32','entry':0},state)
        with self.assertRaises(ValueError):check_entry_state(layout,{**state,'format':'unknown'})
        self.assertEqual(decode_packet(b'0* '+b'}'+bytes([ord('$')^0x20])),b'0000$')
        for packet in (b'}',b'* ',b'0*'):
            with self.assertRaises(ValueError):decode_packet(packet)
        reader=RegisterReader.__new__(RegisterReader)
        for packet in ('c','s','P0=00','M0,1:00','D'):
            with self.assertRaisesRegex(ValueError,'only description/register reads'):reader.request(packet)
        request_read,request_write=os.pipe();response_read,response_write=os.pipe()
        try:
            reader.input=request_write;reader.output=response_read
            reader.buffer=bytearray(b'+$A#00')
            with self.assertRaisesRegex(ValueError,'checksum'):reader.request('p0')
            payload=b'0* '+b'}'+bytes([ord('$')^0x20])
            reader.buffer=bytearray(b'+$'+payload+b'#'+f'{sum(payload)%256:02x}'.encode())
            self.assertEqual(reader.request('p0'),b'0000$')
        finally:
            for descriptor in (request_read,request_write,response_read,response_write):os.close(descriptor)
        # Discover arbitrary XML register numbers; no Cortex-A53 register index
        # or host debugger package is hard-coded into the observer.
        descriptions={'target.xml':b'<target><xi:include href="core.xml"/><xi:include href="system.xml"/></target>',
            'core.xml':b'<feature><reg name="pc" bitsize="64" regnum="51"/><reg name="cpsr" bitsize="32" regnum="77"/></feature>',
            'system.xml':b'<feature><reg name="SCTLR" bitsize="64" regnum="400"/></feature>'}
        replies={'p33':struct.pack('<Q',state['pc']).hex().encode(),'p4d':struct.pack('<I',state['pstate']).hex().encode(),'p190':b'0000000000000000'}
        def respond(command):
            if command.startswith('qSupported'):return b'qXfer:features:read+'
            if command.startswith('qXfer:'):
                name,offset=command.split(':')[3:5];start=int(offset.split(',')[0],16);data=descriptions[name]
                end=min(len(data),start+17);return (b'l' if end==len(data) else b'm')+data[start:end]
            return replies[command]
        reader.request=respond
        self.assertEqual(reader.snapshot(),state)
        replies['p190']=b'E01'
        with self.assertRaisesRegex(ValueError,'read failed'):reader.snapshot()
        replies['p190']=b'00'
        with self.assertRaisesRegex(ValueError,'incomplete'):reader.snapshot()
        replies['p190']=b'0000000000000000'
        for description in (b'<feature/>',b'<feature><reg name="SCTLR" bitsize="32" regnum="400"/></feature>',
                            b'<feature><reg name="SCTLR" bitsize="64" regnum="400"/><reg name="SCTLR_EL1" bitsize="64" regnum="401"/></feature>'):
            descriptions['system.xml']=description
            with self.assertRaises(ValueError):reader.snapshot()
        descriptions['system.xml']=b'<feature><reg name="SCTLR" bitsize="64" regnum="400"/><reg name="MDSCR_EL1" bitsize="64" regnum="401"/></feature>'
        replies['p191']=b'0000000000000000'
        implementation={'el2_implemented':False,'el3_implemented':False}
        extended=reader.snapshot(implementation)
        self.assertEqual(extended,{**state,'format':'osrec-aarch64-entry-state-v2','implementation':implementation,'mdscr_el1':0})
        self.assertTrue(check_entry_state(layout,extended)['higher_el_trap_configuration_verified'])
        self.assertEqual(reader.snapshot(),state)
        with self.assertRaisesRegex(ValueError,'hcr_el2 register unavailable'):
            reader.snapshot({**implementation,'el2_implemented':True})

    def verify_bundles(self,sources,elf,binary,layout,ram):
        for raw_mode in (False,True):
            directory=sources/('raw-bundle' if raw_mode else 'elf-bundle')
            result=prepare_bundle(elf,ram,directory,binary if raw_mode else None)
            self.assertTrue(result['bank_files_verified']);self.assertFalse(result['model_initial_memory_verified'])
            document=json.loads((directory/'load-plan.json').read_text())
            self.assertEqual(document['entry'],layout['entry'])
            self.assertEqual(result,verify_bundle(directory))
            # Paths remain relative when the entire package moves.
            moved=sources/(directory.name+'-moved');directory.rename(moved);directory=moved
            completed=subprocess.run([sys.executable,str(ROOT/'tools/rtl_load_bundle.py'),'verify',str(directory)],cwd='/tmp',capture_output=True,text=True)
            self.assertEqual(completed.returncode,0,completed.stderr)
            with self.assertRaises(FileExistsError):prepare_bundle(elf,ram,directory,binary if raw_mode else None)
            path=directory/'load-plan.json'
            for mutate in (lambda d:d.update(entry=d['entry']+4),lambda d:d.update(bank_files_verified=1),
                           lambda d:d['banks'][0].update(file='../outside.bin'),
                           lambda d:d['source_files'][0].update(sha256='0'*64)):
                changed=json.loads(json.dumps(document));mutate(changed);path.write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError,'manifest or hashes'):verify_bundle(directory)
            path.write_text(json.dumps(document))
            bank=directory/document['banks'][0]['file'];original=bank.read_bytes()
            bank.write_bytes(original+b'\0')
            with self.assertRaisesRegex(ValueError,'extent'):verify_bundle(directory)
            corrupted=bytearray(original);corrupted[0]^=1;bank.write_bytes(corrupted)
            with self.assertRaisesRegex(ValueError,'loaded memory differs'):verify_bundle(directory)
            bank.write_bytes(original)
            image=directory/'image.elf';source=image.read_bytes();image.write_bytes(source+b'\0')
            with self.assertRaisesRegex(ValueError,'manifest or hashes'):verify_bundle(directory)
            image.write_bytes(source);self.assertEqual(result,verify_bundle(directory))
            dumps=[]
            for i,bank in enumerate(document['banks']):
                content=(directory/bank['file']).read_bytes();split=min(3,len(content)-1)
                for suffix,address,data in (('a',bank['address'],content[:split]),('b',bank['address']+split,content[split:])):
                    dump=sources/f'loaded-{i}-{suffix}.bin';dump.write_bytes(data)
                    dumps.append({'address':address,'file':dump})
            loaded=check_loaded(directory,ram,dumps)
            self.assertTrue(loaded['model_initial_memory_verified']);self.assertFalse(loaded['snapshot_phase_verified'])
            self.assertFalse(loaded['cpu_entry_state_verified'])
            self.assertEqual(loaded['initial_memory_verification']['verified_bytes'],result['bank_bytes'])
            self.verify_portable_boot(sources,directory,ram,layout)
            cpu_file=sources/'cpu-entry.json'
            cpu={'format':'osrec-aarch64-entry-state-v1','pc':layout['entry'],'pstate':0x3c5,'sctlr_el1':0}
            cpu_file.write_text(json.dumps(cpu))
            if layout['isa']=='AArch64':
                checked=check_loaded(directory,ram,dumps,cpu_file)
                self.assertTrue(checked['cpu_entry_state_verified']);self.assertFalse(checked['cpu_entry_verification']['snapshot_phase_verified'])
                self.assertEqual(checked['format'],'osrec-rtl-loaded-bundle-verification-v2')
            else:
                with self.assertRaisesRegex(ValueError,'requires AArch64'):check_loaded(directory,ram,dumps,cpu_file)
            output=sources/'loaded-report.json'
            command=[sys.executable,str(ROOT/'tools/rtl_load_bundle.py'),'check-loaded',str(directory),'--ram','0x40000000:0x4000000','--out',str(output)]
            for dump in dumps:command+=['--memory-dump',f"{dump['address']}:{dump['file']}"]
            completed=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(completed.returncode,0,completed.stderr)
            self.assertTrue(json.loads(output.read_text())['model_initial_memory_verified']);output.unlink()
            if layout['isa']=='AArch64':
                completed=subprocess.run(command+['--cpu-state',str(cpu_file)],capture_output=True,text=True)
                self.assertEqual(completed.returncode,0,completed.stderr)
                self.assertTrue(json.loads(output.read_text())['cpu_entry_state_verified']);output.unlink()
                extended={**cpu,'format':'osrec-aarch64-entry-state-v2','implementation':{'el2_implemented':False,'el3_implemented':False},'mdscr_el1':0}
                cpu_file.write_text(json.dumps(extended))
                completed=subprocess.run(command+['--cpu-state',str(cpu_file)],capture_output=True,text=True)
                self.assertEqual(completed.returncode,0,completed.stderr)
                self.assertTrue(json.loads(output.read_text())['cpu_entry_verification']['higher_el_trap_configuration_verified']);output.unlink()
                cpu_file.write_text(json.dumps({**cpu,'pc':cpu['pc']+4}))
                completed=subprocess.run(command+['--cpu-state',str(cpu_file)],capture_output=True,text=True)
                self.assertNotEqual(completed.returncode,0);self.assertFalse(output.exists())
            for dump in dumps:
                original=dump['file'].read_bytes();bad=bytearray(original);bad[-1]^=1;dump['file'].write_bytes(bad)
                with self.assertRaisesRegex(ValueError,f"0x{dump['address']+len(bad)-1:x}"):
                    check_loaded(directory,ram,dumps)
                dump['file'].write_bytes(original)
            with self.assertRaises(ValueError):check_loaded(directory,ram,dumps[:-1])
            with self.assertRaises(ValueError):check_loaded(directory,[{'address':0,'bytes':128}],dumps)
            dump=dumps[0];dump['file'].write_bytes(b'\xff'*dump['file'].stat().st_size)
            completed=subprocess.run(command,capture_output=True,text=True)
            self.assertNotEqual(completed.returncode,0);self.assertFalse(output.exists())
            shutil.rmtree(directory)
        outside=sources/'invalid-bundle'
        with self.assertRaises(ValueError):prepare_bundle(elf,[{'address':0,'bytes':128}],outside)
        self.assertFalse(outside.exists())

    def verify_dumps(self,sources,elf,binary,layout,ram):
        # Independent loader fixture: dirty RAM, copy payload/segments, zero tails.
        segments=layout['load_segments'];base=min(s['address'] for s in segments)
        end=max(s['address']+s['memory_bytes'] for s in segments)
        source=elf.read_bytes()
        for raw_mode in (False,True):
            content=bytearray(b'\xa5'*(end-base))
            if raw_mode:
                offset=layout['raw_image_load_address']-base
                content[offset:offset+binary.stat().st_size]=binary.read_bytes()
            for segment in segments:
                offset=segment['address']-base;size=segment['file_bytes'];tail=segment['memory_bytes']-size
                content[offset:offset+size]=source[segment['file_offset']:segment['file_offset']+size]
                content[offset+size:offset+size+tail]=bytes(tail)
            split=layout['startup_zero_range']['address']-base+65535
            first=sources/'first.dump';second=sources/'second.dump'
            def save():
                first.write_bytes(content[:split]);second.write_bytes(content[split:])
            save();dumps=[{'address':base,'file':first},{'address':base+split,'file':second}]
            payload=binary if raw_mode else None
            report=check(elf,ram,payload,dumps)
            verified=report['initial_memory_verification']
            self.assertTrue(report['initial_memory_verified']);self.assertEqual(report['format'],'osrec-image-memory-preflight-v2')
            self.assertEqual(verified['verified_bytes'],sum(s['memory_bytes'] for s in segments)+(binary.stat().st_size-sum(s['file_bytes'] for s in segments) if raw_mode else 0))
            self.assertTrue(all(len(d['sha256'])==64 for d in verified['dump_files']))
            # Corrupt executable bytes, BSS/stack, result storage, and raw gaps.
            addresses=[layout['entry'],layout['startup_zero_range']['address'],layout['result_address'],layout['stack_range']['address']]
            addresses.extend(s['address'] for s in segments if s['file_bytes'])
            if raw_mode:
                backed=sorted((s['address'],s['address']+s['file_bytes']) for s in segments if s['file_bytes'])
                addresses.extend(b for (_,b),(c,_) in zip(backed,backed[1:]) if b<c)
            for address in addresses:
                content[address-base]^=1;save()
                with self.subTest(raw=raw_mode,address=address),self.assertRaisesRegex(ValueError,f'0x{address:x}'):
                    check(elf,ram,payload,dumps)
                content[address-base]^=1
            save()
            second.write_bytes(second.read_bytes()[:-1])
            with self.assertRaisesRegex(ValueError,'RAM does not cover'):check(elf,ram,payload,dumps)
            save();first.write_bytes(b'')
            with self.assertRaises(ValueError):check(elf,ram,payload,dumps)
            save()
            for bad in ([],dumps[:1],[dumps[0],{**dumps[1],'address':base+split-1}],
                        [dumps[0],{**dumps[1],'address':base+split+1}]):
                with self.subTest(dumps=bad),self.assertRaises(ValueError):check(elf,ram,payload,bad)
            with self.assertRaisesRegex(ValueError,'RAM does not cover'):
                check(elf,memory_contract(layout)['resident_ram_ranges'],payload,dumps)
            output=sources/('raw-initial.json' if raw_mode else 'elf-initial.json')
            command=[sys.executable,str(ROOT/'tools/check_image_memory.py'),'--image',str(elf),'--ram','0x40000000:0x4000000',
                '--memory-dump',f'{base}:{first}','--memory-dump',f'{base+split}:{second}','--out',str(output)]
            if raw_mode:command+=['--binary',str(binary)]
            completed=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(completed.returncode,0,completed.stderr)
            self.assertTrue(json.loads(output.read_text())['initial_memory_verified'])
            output.unlink();content[layout['entry']-base]^=1;save()
            completed=subprocess.run(command,capture_output=True,text=True)
            self.assertNotEqual(completed.returncode,0);self.assertFalse(output.exists())

    def test_ranges_and_gaps(self):
        regions=[{'address':0x1000,'bytes':16},{'address':0x1010,'bytes':16}]
        needed=[{'address':0x1000,'bytes':32,'purpose':'test'}]
        require_coverage(needed,regions)
        for bad in ([{'address':0x1000,'bytes':31}], [{'address':0x1000,'bytes':15},{'address':0x1010,'bytes':16}], [{'address':True,'bytes':32}], [{'address':0x1000,'bytes':0}], [{'address':(1<<64)-1,'bytes':2}]):
            with self.subTest(ram=bad),self.assertRaises(ValueError):require_coverage(needed,bad)
        self.assertEqual(ram_region('0x40000000:0x4000000'),{'address':0x40000000,'bytes':64*1024*1024})
        for value in ('0:0','-1:1','0:1:2','x:1'):
            with self.subTest(region=value),self.assertRaises(argparse.ArgumentTypeError):ram_region(value)
        self.assertEqual(memory_dump('0x1000:path:with:colons')['file'],Path('path:with:colons'))
        for value in ('0:','-1:file','x:file',str(1<<64)+':file','missing-colon'):
            with self.subTest(dump=value),self.assertRaises(argparse.ArgumentTypeError):memory_dump(value)

    def test_zero_fill_overrides_raw_gap(self):
        # Raw gaps can cover a NOLOAD tail; ELF zero-fill wins, while the
        # remaining raw gap retains its original offset after span splitting.
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name);elf=stage/'source';binary=stage/'raw';dump=stage/'memory'
            elf.write_bytes(b'abcdEF');binary.write_bytes(b'abcdXXXXXXXXEF')
            layout={'raw_image_load_address':0x1000,'load_segments':[
                {'address':0x1000,'file_offset':0,'file_bytes':4,'memory_bytes':8},
                {'address':0x100c,'file_offset':4,'file_bytes':2,'memory_bytes':4}]}
            dump.write_bytes(b'abcd\0\0\0\0XXXXEF\0\0')
            views=[{'address':0x1000,'file':dump}];ram=[{'address':0x1000,'bytes':16}]
            report=verify_loaded_memory(elf,layout,views,ram,binary)
            self.assertEqual(report['verified_bytes'],16)
            dump.write_bytes(b'abcdXXXXXXXXEF\0\0')
            with self.assertRaisesRegex(ValueError,'0x1004 .*zero-fill'):
                verify_loaded_memory(elf,layout,views,ram,binary)

    def test_actual_elf_and_raw_memory_contract(self):
        with tempfile.TemporaryDirectory() as name:
            stage=Path(name)
            for arch in ('aarch64','armv7'):
                with self.subTest(arch=arch):
                    sources=stage/arch;sources.mkdir()
                    flags=prepare_target(SimpleNamespace(arch=arch,entry_address=0x40200000 if arch=='aarch64' else 0x40010000,result_address=0x40180000 if arch=='aarch64' else 0x40000000),sources)
                    # A high-alignment BSS object and an odd tail expose both linker-padding issues.
                    (sources/'fixture.c').write_text('''#include <stdint.h>
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
volatile unsigned char aligned_object[70001] __attribute__((aligned(64)));
volatile unsigned char odd;
void replay_fault(void) { for (;;) {} }
void replay_main(void) { aligned_object[64]=1;odd=2;osrec_result[0]=aligned_object[64]+odd;for (;;) {} }
''')
                    elf=sources/'fixture.elf';binary=sources/'fixture.bin'
                    run([LLVM/'clang',*flags,'-O1','-ffreestanding','-fno-builtin','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'fixture.c','-o',elf])
                    run([LLVM/'llvm-objcopy','-O','binary',elf,binary]);layout=audit(elf,LLVM)
                    self.assertEqual(layout['startup_zero_tail_bytes'],0)
                    self.assertEqual(layout['stack_range']['bytes'],16384)
                    self.assertEqual(layout['startup_zero_range']['address']%64,0)
                    contract=memory_contract(layout);self.assertFalse(contract['mmu_enabled_at_entry']);self.assertFalse(contract['dynamic_access_coverage_proven'])
                    self.assertEqual(target_metadata(layout,10)['memory_contract'],contract)
                    ram=contract['resident_ram_ranges'];check(elf,ram)
                    whole=[{'address':0x40000000,'bytes':64*1024*1024}]
                    result=check(elf,whole,binary);self.assertEqual(result['status'],'verified')
                    self.assertFalse(result['initial_memory_verified'])
                    self.verify_dumps(sources,elf,binary,layout,whole)
                    self.verify_bundles(sources,elf,binary,layout,whole)
                    writable=[{'address':s['address'],'bytes':s['memory_bytes']} for s in layout['load_segments'] if s['flags']&2]
                    require_coverage([{**layout['startup_zero_range'],'purpose':'startup'}],writable)
                    # File-backed code alone omits stack and NOLOAD result memory.
                    only_file=[{'address':s['address'],'bytes':s['file_bytes']} for s in layout['load_segments'] if s['file_bytes']]
                    with self.assertRaisesRegex(ValueError,'RAM does not cover'):check(elf,only_file)
                    for region in ram:
                        bad=[dict(r) for r in ram];bad[ram.index(region)]['bytes']-=1
                        with self.subTest(missing_byte=region),self.assertRaises(ValueError):check(elf,bad)
                    bad_binary=sources/'bad.bin';bad_binary.write_bytes(binary.read_bytes()+b'\0')
                    with self.assertRaisesRegex(ValueError,'extent'):check(elf,whole,bad_binary)
                    data=bytearray(binary.read_bytes());data[0]^=1;bad_binary.write_bytes(data)
                    with self.assertRaisesRegex(ValueError,'bytes differ'):validate_raw(bad_binary,elf,layout)
                    # A RAM map missing declared storage is rejected.
                    bad_ram=[{'address':0,'bytes':128}]
                    with self.assertRaises(ValueError):check(elf,bad_ram)
                    output=sources/'preflight.json'
                    completed=subprocess.run([sys.executable,str(ROOT/'tools/check_image_memory.py'),'--image',str(elf),'--binary',str(binary),'--ram','0x40000000:0x4000000','--out',str(output)],capture_output=True,text=True)
                    self.assertEqual(completed.returncode,0,completed.stderr)
                    self.assertEqual(json.loads(output.read_text())['status'],'verified')
                    # Truncated tables and unaligned entry points fail closed.
                    # Legacy end alignment outside the section remains supported,
                    # but its extra startup-cleared bytes must also be resident.
                    linker=(sources/'image.ld').read_text()
                    old=linker.replace('    . = ALIGN('+('16' if arch=='aarch64' else '4')+');\n    __bss_end = .;\n  }', '  }\n  . = ALIGN('+('16' if arch=='aarch64' else '4')+');\n  __bss_end = .;')
                    (sources/'image.ld').write_text(old)
                    start=(sources/'start.S').read_text();(sources/'start.S').write_text(start.replace(' .global __stack_bottom\n__stack_bottom:\n',''))
                    legacy=sources/'legacy.elf'
                    run([LLVM/'clang',*flags,'-O1','-ffreestanding','-fno-builtin','-nostdlib','-static','-fuse-ld=lld','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'fixture.c','-o',legacy])
                    legacy_layout=describe(legacy);self.assertGreater(legacy_layout['startup_zero_tail_bytes'],0)
                    exact=[{'address':s['address'],'bytes':s['memory_bytes']} for s in legacy_layout['load_segments'] if s['memory_bytes']]
                    with self.assertRaisesRegex(ValueError,'startup BSS'):check(legacy,exact)
                    check(legacy,memory_contract(legacy_layout)['resident_ram_ranges'])
                    # ELF-only checks leave legacy startup padding unconstrained.
                    # An exact bundle load check must nevertheless match it.
                    legacy_bundle=sources/'legacy-bundle';prepare_bundle(legacy,whole,legacy_bundle)
                    legacy_plan=json.loads((legacy_bundle/'load-plan.json').read_text());legacy_dumps=[]
                    for i,bank in enumerate(legacy_plan['banks']):
                        dump=sources/f'legacy-loaded-{i}.bin';dump.write_bytes((legacy_bundle/bank['file']).read_bytes())
                        legacy_dumps.append({'address':bank['address'],'file':dump})
                    padding_address=legacy_layout['startup_zero_range']['address']+legacy_layout['startup_zero_range']['bytes']-1
                    padding_dump=next(d for d in legacy_dumps if d['address']<=padding_address<d['address']+d['file'].stat().st_size)
                    data=bytearray(padding_dump['file'].read_bytes());data[padding_address-padding_dump['address']]=0xff;padding_dump['file'].write_bytes(data)
                    check(legacy,whole,dumps=legacy_dumps)
                    with self.assertRaisesRegex(ValueError,f'0x{padding_address:x}'):
                        check_loaded(legacy_bundle,whole,legacy_dumps)
                    (sources/'start.S').write_text(start);(sources/'image.ld').write_text(linker)
                    if arch=='aarch64':
                        # Coverage is checked before the runner can launch QEMU.
                        (sources/'image.ld').write_text(linker.replace('0x40200000','0x45200000').replace('0x40180000','0x45180000'))
                        outside=sources/'outside.elf'
                        run([LLVM/'clang',*flags,'-O1','-ffreestanding','-fno-builtin','-nostdlib','-static','-fuse-ld=lld','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'fixture.c','-o',outside])
                        from run_freestanding_armv7 import observe
                        with self.assertRaisesRegex(ValueError,'RAM does not cover'):observe(outside,'does-not-exist-qemu')
                        (sources/'image.ld').write_text(linker)
                    raw=elf.read_bytes();bad_elf=sources/'bad.elf';bad_elf.write_bytes(raw[:48])
                    with self.assertRaises(ValueError):describe(bad_elf)
                    data=bytearray(raw);struct.pack_into('<Q' if arch=='aarch64' else '<I',data,24,layout['entry']+1);bad_elf.write_bytes(data)
                    with self.assertRaisesRegex(ValueError,'alignment'):describe(bad_elf)

if __name__=='__main__':
    if len(sys.argv)>2 and sys.argv[1]=='--llvm-bin':
        LLVM=Path(sys.argv[2]);sys.argv=sys.argv[:1]+sys.argv[3:]
    unittest.main()
