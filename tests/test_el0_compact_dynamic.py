from pathlib import Path
import shutil,subprocess,tempfile,unittest,struct,copy
from types import SimpleNamespace
from el0_flat_lower import decode,LOAD,PAIR,REGISTER,ALIGNED,POST,WB
from el0_hardware import (COMPACT_ACCESS_WIDTHS, COMPACT_WIDTH_BOUNDS, COMPACT_WIDTH_BOUNDS_ENCODING,
                          compact_ranges, compact_width_ranges, memory_path, ranked_compact_ranges)

CC=Path('/opt/homebrew/opt/llvm@16/bin/clang');QEMU=shutil.which('qemu-system-aarch64')


class Ranges(unittest.TestCase):
    def test_permissions_aliases_and_physical_discontinuities(self):
        maps=[(0x10000,0x4000,4096,1024),(0x11000,0x5000,4096,1024),
              (0x12000,0x7000,4096,1024),(0xffffc39f7000,0x4000,4096,1024),
              (0x30000,0x6000,4096,1152),(0x40000,0x9000000,4096,1024),
              (0x50000,0x4000,4096,0)]
        reads,writes=compact_ranges(maps,0x4000,16384,[(0x5000,4096)])
        self.assertEqual(reads,[[0x10000,0x12000,0],[0x12000,0x13000,12288],
                              [0x30000,0x31000,8192],[0xffffc39f7000,0xffffc39f8000,0]])
        self.assertEqual(writes,[[0x10000,0x11000,0],[0x12000,0x13000,12288],
                               [0xffffc39f7000,0xffffc39f8000,0]])

    def test_writeback_and_alias_shortcuts_cannot_bypass_conversion(self):
        self.assertIn('[sp,#32]',memory_path(0,decode(0xf8408420),'next',compact=True))
        self.assertEqual(memory_path(0,decode(0xf84087e0),'next',compact=True,native_sp=True),'')
        with self.assertRaises(ValueError):
            memory_path(0,decode(0xf9400020),'next',compact=True,native_store=True)

    def test_linked_tables_must_match_mappings_permissions_and_readonly_storage(self):
        from el0_compact_dynamic import validate_tables
        maps=[(0x10000,0x400000,8192,1024)]
        reads,writes=compact_ranges(maps,0x400000,8192,[(0x401000,4096)])
        addresses=dict(flat_compact_memory_mode=0x1000,flat_program=0x2000,
                       flat_compact_read=0x4000,flat_compact_write=0x5000)
        data={0x1000:struct.pack('<Q',1),0x2010:struct.pack('<2Q',0x3000,1),
              0x3000:struct.pack('<4Q',*maps[0]),
              0x4000:b''.join(struct.pack('<3Q',*row) for row in reads+[[0,0,0]]),
              0x5000:b''.join(struct.pack('<3Q',*row) for row in writes+[[0,0,0]])}
        elf=SimpleNamespace(symbols=[dict(name=n,value=a,shndx=1) for n,a in addresses.items()],
                            sections=[{},dict(flags=2)],read=lambda a,n:data[a][:n])
        metadata=dict(ram_base=0x400000,ram_bytes=8192,compact_dynamic_memory=dict(read=reads,write=writes))
        checked=dict(load_segments=[dict(address=0x1000,memory_bytes=0x5000,flags=4)])
        manifest=dict(compact_dynamic_memory=True)
        validate_tables(elf,checked,metadata,manifest,{0x401000})
        corrupted=copy.deepcopy(metadata);corrupted['compact_dynamic_memory']['write'][0][1]+=4096
        with self.assertRaisesRegex(ValueError,'captured mappings'):
            validate_tables(elf,checked,corrupted,manifest,{0x401000})
        original=data[0x4000];data[0x4000]=original[:16]+struct.pack('<Q',4096)+original[24:]
        with self.assertRaisesRegex(ValueError,'differs from ELF'):
            validate_tables(elf,checked,metadata,manifest,{0x401000})
        data[0x4000]=original;checked['load_segments'][0]['flags']=6
        with self.assertRaisesRegex(ValueError,'writable'):
            validate_tables(elf,checked,metadata,manifest,{0x401000})
        checked['load_segments'][0]['flags']=4
        for name,address in (('flat_alias_free_memory_mode',0x5100),
                             ('flat_direct_read',0x5200),('flat_direct_write',0x5300)):
            elf.symbols.append(dict(name=name,value=address,shndx=1))
        data.update({0x5100:struct.pack('<Q',1),0x5200:bytes(16),0x5300:bytes(16)})
        metadata['alias_free_memory']=manifest['alias_free_memory']=True
        validate_tables(elf,checked,metadata,manifest,{0x401000})
        metadata['aliases']=[dict(va=0x10000)]
        with self.assertRaisesRegex(ValueError,'logical guest stacks'):
            validate_tables(elf,checked,metadata,manifest,{0x401000})
        metadata['aliases']=[]
        data[0x5200]=struct.pack('<2Q',0x10000,0x12000)
        with self.assertRaisesRegex(ValueError,'native address range'):
            validate_tables(elf,checked,metadata,manifest,{0x401000})
        data[0x5200]=bytes(16)
        elf.symbols.append(dict(name='flat_phys',value=0x8000,shndx=1))
        data[0x1000]=struct.pack('<Q',2)
        metadata['compact_dynamic_memory']['encoding']='linked-bias-ranked-v1'
        for at,rows in ((0x4000,reads),(0x5000,writes)):
            data[at]=b''.join(struct.pack('<3Q',lo,hi,(0x8000+off-lo)%2**64)
                              for lo,hi,off in ranked_compact_ranges(rows))+bytes(24)
        validate_tables(elf,checked,metadata,manifest,{0x401000})
        data[0x4000]=data[0x4000][:16]+struct.pack('<Q',0)+data[0x4000][24:]
        with self.assertRaisesRegex(ValueError,'compact translation table differs'):
            validate_tables(elf,checked,metadata,manifest,{0x401000})
        data[0x1000]=struct.pack('<Q',COMPACT_WIDTH_BOUNDS)
        metadata['compact_dynamic_memory']['encoding']=COMPACT_WIDTH_BOUNDS_ENCODING
        for is_write,rows in enumerate((reads,writes)):
            access='write' if is_write else 'read'
            for index,width in enumerate(COMPACT_ACCESS_WIDTHS):
                at=0x6000+(is_write*len(COMPACT_ACCESS_WIDTHS)+index)*0x100
                elf.symbols.append(dict(name='flat_compact_%s_%d'%(access,width),value=at,shndx=1))
                data[at]=b''.join(struct.pack('<3Q',lo,last,(0x8000+off-lo)%2**64)
                                  for lo,last,off in compact_width_ranges(rows,width))+bytes(24)
        validate_tables(elf,checked,metadata,manifest,{0x401000})
        last,=struct.unpack_from('<Q',data[0x6000],8)
        data[0x6000]=data[0x6000][:8]+struct.pack('<Q',last+1)+data[0x6000][16:]
        with self.assertRaisesRegex(ValueError,'compact translation table differs'):
            validate_tables(elf,checked,metadata,manifest,{0x401000})

    def test_width_bounds_exclude_short_ranges_and_include_exact_fit(self):
        rows=[(0x10000,0x10007,0),(0x20000,0x20008,10),(0x30000,0x30020,20)]
        self.assertEqual(compact_width_ranges(rows,8),[(0x30000,0x30018,20),(0x20000,0x20000,10)])
        self.assertEqual(compact_width_ranges(rows,64),[])


@unittest.skipUnless(CC.exists() and QEMU,'cross compiler and QEMU required')
class Execution(unittest.TestCase):
    def test_unmapped_logical_addresses_aliases_and_failed_accesses(self):
        self.check_accesses(compact_mode=1)

    def test_ranked_linked_bias_with_unmapped_logical_addresses(self):
        self.check_accesses(compact_mode=2)

    def test_width_bounds_with_unmapped_logical_addresses(self):
        self.check_accesses(compact_mode=COMPACT_WIDTH_BOUNDS)

    def check_accesses(self,compact_mode):
        maps=[(0x10000,0x400000,8192,1024),(0x12000,0x404000,4096,1024),
              (0x30000,0x402000,4096,1152),(0x80008000,0x400000,12288,1024),
              (0xffffc39f7000,0x400000,4096,1024)]
        reads,writes=compact_ranges(maps,0x400000,32768,[])
        words=[0x39400020,0x79400020,0xb9400020,0xf9400020,0x39800020,
               0x39000020,0x79000020,0xb9000020,0xf9000020,0xa9400820,0xa9000820,
               0xf9400c20,0xf9000c20,0xf85f8020,0xf81f8020,0xf8626820,0xf8226820,0xc8dffc20,
               0xf8408420,0xf8408c20,0xf8008420,0xf8008c20,0xa8c10820,0xa8810820,
               0xf85f8c20,0xf81f8c20,
               0xbc408420,0xfc408c20,0x3cc08420,0xbc008420,0xfc008c20,0x3c808420,
               0xacc10820,0xac810820]
        addresses=[0x10000,0x10ffc,0x11ffc,0x12ffc,0x13000,0x30000,
                   0xffffc39f7000,0xffffc39f7ffc,0xffffffffc39f7000,0xffffffffffffffff]
        if compact_mode==COMPACT_WIDTH_BOUNDS:
            addresses += [0x11ff8,0x11ff9]
        lines=['.text','.global _start','_start:','mov x0,#0x300000','msr cpacr_el1,x0','isb',
               'adr x0,vectors','msr vbar_el1,x0','adrp x0,root_table','add x0,x0,:lo12:root_table',
               'msr ttbr0_el1,x0','mov x0,#255','msr mair_el1,x0','mov x0,#0x3510','msr tcr_el1,x0',
               'isb','mrs x0,sctlr_el1','bic x0,x0,#2','orr x0,x0,#1','msr sctlr_el1,x0','isb',
               'adrp x0,stack_end','add x0,x0,:lo12:stack_end','mov sp,x0']
        count=0
        for word in words:
            op=decode(word);size=(1<<(op.info>>15&7))*(2 if op.info&PAIR else 1)
            for va in addresses:
                for mode in (0,1):
                    ranges=reads if op.info&LOAD else writes
                    delta=(102<<(op.info>>27&7)) if op.info&REGISTER else 0 if op.info&POST else op.imm
                    ea=(va+delta)&((1<<64)-1)
                    offset=next((off+ea-lo for lo,hi,off in ranges if lo<=ea and ea+size<=hi),None)
                    fast=mode==1 and offset is not None and (not op.info&ALIGNED or ea%size==0)
                    prefix='case%d_'%count;flags=(count%16)<<28
                    # Reset both actual and independent expected backing.
                    lines+=['adrp x0,flat_phys','add x0,x0,:lo12:flat_phys',
                            'adrp x1,expected','add x1,x1,:lo12:expected','mov x2,#4096',
                            'ldr x3,=0x8080808080808080',prefix+'reset:',
                            'str x3,[x0],#8','str x3,[x1],#8','subs x2,x2,#1','b.ne '+prefix+'reset',
                            'movi v0.16b,#100','movi v2.16b,#102']
                    if fast and not op.info&LOAD:
                        lines+=['adrp x1,expected','add x1,x1,:lo12:expected','ldr x3,=%d'%offset,
                                'add x1,x1,x3','ldr x3,=0x%x'%(delta&((1<<64)-1)),
                                'sub x1,x1,x3','mov x0,#100','mov x2,#102','.inst 0x%08x'%word]
                    lines+=['adrp x0,flat_shadow','mov x1,#%d'%mode,'str x1,[x0,:lo12:flat_shadow+80]',
                            'mov x0,#0x%x'%flags,'msr nzcv,x0']
                    lines+=['mov x%d,#%d'%(r,100+r) for r in range(31)]
                    lines+=['ldr x1,=0x%x'%va]
                    lines+=memory_path(0x1000+count*4,op,prefix+'fast',compact=compact_mode,native_sp=True).splitlines()
                    lines+=['b '+('failed' if fast else prefix+'capture'),prefix+'fast:',
                            'b '+(prefix+'capture' if fast else 'failed'),prefix+'capture:',
                            'msr tpidr_el0,x30','adrp x30,snapshot','add x30,x30,:lo12:snapshot']
                    lines+=['str x%d,[x30,#%d]'%(r,r*8) for r in range(30)]
                    lines+=['mrs x0,tpidr_el0','str x0,[x30,#240]','mrs x0,nzcv',
                            'str q0,[x30,#256]','str q2,[x30,#272]',
                            'mov x1,#0x%x'%flags,'cmp x0,x1','b.ne failed',
                            'adrp x0,stack_end','add x0,x0,:lo12:stack_end','mov x1,sp','cmp x0,x1','b.ne failed']
                    for r in range(31):
                        value=va if r==1 else 100+r
                        if fast and op.info&WB and r==1:value=(va+op.imm)&((1<<64)-1)
                        if fast and op.info&LOAD and not word&(1<<26) and r in ([0,2] if op.info&PAIR else [0]):
                            width=1<<(op.info>>15&7)
                            value=int.from_bytes(bytes([128])*width,'little',signed=word==0x39800020)&((1<<64)-1)
                        lines+=['ldr x0,[x30,#%d]'%(r*8),'ldr x1,=0x%x'%value,'cmp x0,x1','b.ne failed']
                    for r,at in ((0,256),(2,272)):
                        data=bytes([100+r])*16
                        if fast and op.info&LOAD and word&(1<<26) and (r==0 or op.info&PAIR):
                            width=1<<(op.info>>15&7);data=bytes([128])*width+bytes(16-width)
                        for part in (0,8):
                            value=int.from_bytes(data[part:part+8],'little')
                            lines+=['ldr x0,[x30,#%d]'%(at+part),'ldr x1,=0x%x'%value,'cmp x0,x1','b.ne failed']
                    lines+=['adrp x0,flat_phys','add x0,x0,:lo12:flat_phys',
                            'adrp x1,expected','add x1,x1,:lo12:expected','mov x2,#4096',prefix+'compare:',
                            'ldr x3,[x0],#8','ldr x4,[x1],#8','cmp x3,x4','b.ne failed',
                            'subs x2,x2,#1','b.ne '+prefix+'compare','b '+prefix+'next','.ltorg',prefix+'next:']
                    count+=1
        lines+=['mov x2,#0','b finish','failed:','mov x2,#1','finish:',
                'adrp x1,exit_status','add x1,x1,:lo12:exit_status','str x2,[x1,#8]',
                'mov x0,#0x20','hlt #0xf000','b .','.balign 2048','vectors:',
                '.rept 16','b failed','.space 124','.endr','.section .rodata,"a"']
        for access,rows in [('read',reads),('write',writes)]:
            if compact_mode==COMPACT_WIDTH_BOUNDS:
                for width in COMPACT_ACCESS_WIDTHS:
                    lines+=['.balign 32','flat_compact_%s_%d:'%(access,width)]
                    bounds=compact_width_ranges(rows,width)
                    lines+=(['.quad %d,%d,flat_phys%+d'%(lo,last,off-lo) for lo,last,off in bounds]
                            or ['.quad 1,0,0'])
                    lines+=['.quad 0,0,0']
                continue
            lines+=['.balign 8','flat_compact_'+access+':']
            if compact_mode==2:
                lines+=['.quad %d,%d,flat_phys%+d'%(lo,hi,off-lo) for lo,hi,off in ranked_compact_ranges(rows)]
            else:
                lines+=['.quad %d,%d,%d'%tuple(r) for r in rows]
            lines+=['.quad 0,0,0']
        lines+=['.data','.balign 4096','root_table: .quad level1+3','.space 4088',
                'level1: .quad 0,0x40000701','.space 4080','flat_phys: .space 32768',
                'expected: .space 32768','snapshot: .space 288','exit_status: .quad 0x20026,1',
                '.balign 4096','flat_shadow: .space 4096','.space 16384','stack_end:']
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'fixture.S').write_text('\n'.join(lines)+'\n')
            built=subprocess.run([str(CC),'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib',
                '-Wl,-Ttext=0x40200000,-e,_start',str(root/'fixture.S'),'-o',str(root/'fixture')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            run=subprocess.run([QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                '-nodefaults','-display','none','-monitor','none','-serial','none','-d','int','-D',str(root/'exceptions.log'),
                '-semihosting-config','enable=on,target=native','-device','loader,file='+str(root/'fixture')+',cpu-num=0'],
                capture_output=True,text=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr+(root/'exceptions.log').read_text()[:2000])
        print('%d dynamic compact access cases'%count)
