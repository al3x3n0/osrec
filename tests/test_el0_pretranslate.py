"""Build-time proofs and loader initialization without runtime memory adapters."""
import json
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from el0_pretranslate import user_aliases,user_proofs
from el0_instruction_profile import segments
from kernel_source_verify import Elf
from pretranslate_el0_image import finalize, merge_ram_loads, program_headers, verify_merged_ram

LLVM=Path('/opt/homebrew/opt/llvm@16/bin');QEMU=shutil.which('qemu-system-aarch64')


class SegmentClustering(unittest.TestCase):
    def test_budget_keeps_largest_gap_in_zero_fill_and_checks_merged_bytes(self):
        page = 4096
        backing = 0x40000000
        source = b'a' * page + b'b' * page + b'c' * page
        extents = [[page, page, 0], [3 * page, page, page], [8 * page, page, 2 * page]]
        data = bytearray(source)
        loads = merge_ram_loads(data, source, backing, 10 * page, extents, budget=3)
        self.assertEqual([(va-backing, size, mem) for _, _, _, va, _, size, mem, _ in loads],
                         [(0, 0, page), (page, 3*page, 7*page), (8*page, page, 2*page)])
        segments = [dict(address=va, flags=flags, file_offset=offset, file_bytes=size, memory_bytes=mem)
                    for _, flags, offset, va, _, size, mem, _ in loads]
        elf = SimpleNamespace(data=data, sections=[dict(type=1, addr=0x1000, offset=0, size=len(source))])
        verify_merged_ram(elf, backing, 10 * page, 0x1000, segments, extents)
        data[segments[1]['file_offset'] + page] = 1
        with self.assertRaisesRegex(ValueError, 'canonical RAM loads differ from merged ELF extents'):
            verify_merged_ram(elf, backing, 10 * page, 0x1000, segments, extents)


class Proofs(unittest.TestCase):
    def test_snapshot_resolution_checks_af_parent_permissions_ram_and_cycles(self):
        ram=bytearray(5*4096);shadow=bytearray(80);base=0x40000000
        p=SimpleNamespace(h=[0,0,base,len(ram),16],memory=ram,shadow=shadow,maps=[])
        struct.pack_into('<Q',shadow,72,base)
        for i in range(3):struct.pack_into('<Q',ram,i*4096,base+(i+1)*4096|3)
        leaf=base+4*4096|3|(1<<6)|(1<<10);at=3*4096+5*8
        struct.pack_into('<Q',ram,at,leaf)
        self.assertEqual([(a['va'],a['pa']) for a in user_aliases(p)],[(0x5000,base+4*4096)])
        aliases,checks=user_aliases(p,with_checks=True)
        self.assertEqual(len(checks),4)
        address,mask,value=next(row for row in checks if row[0]==base+at)
        self.assertEqual(((value^(1<<55))^value)&mask,0) # software dirty bit
        self.assertNotEqual(((value^128)^value)&mask,0) # access permission
        struct.pack_into('<Q',ram,at,leaf&~(1<<10));self.assertEqual(user_aliases(p),[])
        struct.pack_into('<Q',ram,at,leaf)
        struct.pack_into('<Q',ram,0,base+4096|3|(1<<61));self.assertEqual(user_aliases(p),[])
        struct.pack_into('<Q',ram,0,base+4096|3|(1<<62));self.assertTrue(user_aliases(p)[0]['attrs']&128)
        p.maps=[(0x5000,base,4096,0)];self.assertEqual(user_aliases(p),[]);p.maps=[]
        struct.pack_into('<Q',ram,0,base|3)
        with self.assertRaisesRegex(ValueError,'cyclic'):user_aliases(p)

    def test_syscall_preservation_unknown_loads_calls_permissions_and_jump_table(self):
        ram=bytearray(3*4096);package=SimpleNamespace(h=[0,0,0x40000000,len(ram)],memory=ram)
        aliases=[dict(va=0x3000,pa=0x40002000,bytes=4096,attrs=128),
                 dict(va=0x5000,pa=0x40000000,bytes=4096,attrs=0)]
        initial=[0]*34;initial[1]=0x5000;initial[2]=0x5000;initial[31]=0x5ff0;initial[32]=0x100
        def prove(words,immutable=()):return user_proofs(words,initial,package,aliases,immutable)
        detailed=user_proofs({0x100:0xf9400020,0x104:0x14000000},initial,package,aliases,[],with_addresses=True)
        self.assertEqual(detailed[0x100],dict(addresses=[0x5000],physical=[0x40000000],bytes=8))
        self.assertIn(0x104,prove({0x100:0xd4000001,0x104:0xb9000020,0x108:0x14000000}))
        self.assertNotIn(0x104,prove({0x100:0xf9400041,0x104:0xb9000020,0x108:0x14000000}))
        self.assertNotIn(0x104,prove({0x100:0x94000040,0x104:0xb9000020,0x108:0x14000000,0x200:0xd65f03c0}))
        initial[1]=0x3000
        self.assertNotIn(0x100,prove({0x100:0xb9000020,0x104:0x14000000}))
        initial[1]=0x5ffe
        self.assertNotIn(0x100,prove({0x100:0xb9000020,0x104:0x14000000}))
        # A computed branch selects either block from an immutable table. The
        # analysis follows both; it never uses a recorded selector or outcome.
        initial[1]=0x5000;initial[6]=0x3000;initial[8]=0x2000;initial[32]=0xffc
        for i in range(16):struct.pack_into('<i',ram,8192+4*i,0x100 if i&1 else 0)
        words={0xffc:0xd4000001,0x1000:0x92400c05,0x1004:0xb8a578d1,0x1008:0x8b110108,0x100c:0xd61f0100,
               0x2000:0xb9000020,0x2004:0x14000000,0x2100:0xb9000020,0x2104:0x14000000}
        self.assertTrue({0x2000,0x2100}.issubset(prove(words,[(0x40002000,4096)])))
        self.assertFalse({0x2000,0x2100}&prove(words)) # mutable target table loses the proof
        initial[32]=0x100
        words={0x100:0xd4000001,0x104:0xb4000084,0x108:0xb9000020,0x10c:0x14000000,
               0x114:0xf9400041,0x118:0xd65f0000} # unknown RET may re-enter the known store
        self.assertNotIn(0x108,prove(words))


@unittest.skipUnless(QEMU and (LLVM/'clang').exists(),'cross clang and system QEMU required')
class Loader(unittest.TestCase):
    def test_ram_and_table_bytes_are_loaded_from_elf_without_copy_code(self):
        source='''.text
.global _start
_start:
    adrp x1,flat_phys
    add x1,x1,:lo12:flat_phys
    ldr x2,[x1]
    cbnz x2,failed
    add x1,x1,#4096
    ldr x2,[x1]
    mov x3,#0x1234
    cmp x2,x3
    b.ne failed
    add x1,x1,#4096
    ldr x2,[x1]
    cbnz x2,failed
    adrp x1,flat_embedded_page_tables
    add x1,x1,:lo12:flat_embedded_page_tables
    ldr x2,[x1]
    mov x3,#0x5678
    cmp x2,x3
    b.ne failed
    mov x2,#0
    b finish
failed: mov x2,#1
finish:
    adrp x1,exit_status
    add x1,x1,:lo12:exit_status
    str x2,[x1,#8]
    mov x0,#0x20
    hlt #0xf000
.section .rodata,"a"
.balign 4096
.global flat_payload
flat_payload: .quad 0x1234
.space 4088
.global flat_embedded_page_tables
flat_embedded_page_tables: .space 4096
.data
exit_status: .quad 0x20026,1
.bss
.balign 4096
.space 4096
.global flat_phys
flat_phys: .space 12288
.space 4096
'''
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);(out/'fixture.S').write_text(source)
            built=subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-fuse-ld=lld','-nostdlib',
                                  '-Wl,-Ttext=0x40200000,-e,_start,--build-id=none',str(out/'fixture.S'),'-o',str(out/'checkpoint')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            elf=Elf(out/'checkpoint');syms={s['name']:s['value'] for s in elf.symbols}
            (out/'manifest.json').write_text(json.dumps(dict(pretranslated_memory=True)))
            (out/'hardware-memory.json').write_text(json.dumps(dict(ram_bytes=12288,pretranslated_memory=dict(
                initial_extents=[[4096,4096,0]],user_aliases=[],table_capacity=4096))))
            original=(out/'checkpoint').read_bytes()
            with patch('pretranslate_el0_image.prepare',side_effect=ValueError('unresolved mappings')):
                with self.assertRaisesRegex(ValueError,'unresolved mappings'):finalize(out)
            self.assertEqual((out/'checkpoint').read_bytes(),original)
            with patch('pretranslate_el0_image.prepare',return_value=dict(address=syms['flat_embedded_page_tables'],bytes=8,data=struct.pack('<Q',0x5678))):
                report=finalize(out)
            self.assertEqual(finalize(out),report)
            self.assertFalse(report['runtime_snapshot_copy'])
            self.assertFalse(report['external_page_table_image_required'])
            headers=segments((out/'checkpoint').read_bytes());base=syms['flat_phys']
            for offset in (0,4096,8192):
                self.assertEqual(sum(h[0]==1 and h[3]<=base+offset<h[3]+h[6] for h in headers),1)
            command = [QEMU,'-M','virt-9.2,secure=off,virtualization=off','-cpu','cortex-a53',
                       '-nodefaults','-display','none','-monitor','none','-serial','none',
                       '-semihosting-config','enable=on,target=native','-device',
                       'loader,file='+str(out/'checkpoint')+',cpu-num=0']
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            # Repackage the already-finalized image without relinking.
            with patch('pretranslate_el0_image.prepare', return_value=dict(
                    address=syms['flat_embedded_page_tables'], bytes=8, data=struct.pack('<Q', 0x5678))):
                merged = finalize(out, merge_segments=True)
            self.assertEqual(finalize(out, merge_segments=True), merged)
            self.assertLess(merged['load_segments'], report['load_segments'])
            self.assertEqual(merged['ram_load_segments'], 2)
            for kind, _, offset, va, _, _, _, _ in program_headers((out/'checkpoint').read_bytes()):
                if kind == 1:
                    self.assertEqual((offset-va) % 4096, 0)
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(os.environ.get('OSREC_EL0_EMBEDDED_RAM_IMAGE'),'set embedded RAM image for linked checks')
class EmbeddedRamImage(unittest.TestCase):
    def test_corrupted_ram_load_and_embedded_table_are_rejected(self):
        from el0_hardware_model import prepare
        from pretranslate_el0_image import file_offset
        image = Path(os.environ['OSREC_EL0_EMBEDDED_RAM_IMAGE']).resolve()
        elf = Elf(image/'checkpoint')
        symbols = {s['name']:s for s in elf.symbols if s['shndx']}
        backing = symbols['flat_phys']['value']
        end = backing + symbols['flat_phys']['size']
        header, = struct.unpack_from('<Q',elf.data,32)
        stride, count = struct.unpack_from('<HH',elf.data,54)
        for i in range(count):
            at = header + i*stride
            kind, _, offset, address, _, size, _, _ = struct.unpack_from('<II6Q',elf.data,at)
            if kind==1 and size and backing<=address<end:
                break
        else:
            self.fail('no file-backed canonical RAM segment')
        table_offset = file_offset(elf,symbols['flat_embedded_page_tables']['value'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for label, message in (('load','canonical RAM loads differ'),('table','matching embedded page tables')):
                with self.subTest(label=label):
                    changed = root/label
                    changed.mkdir()
                    data = bytearray(elf.data)
                    if label=='load':
                        struct.pack_into('<Q',data,at+8,offset+4096)
                    else:
                        data[table_offset] ^= 1
                    (changed/'checkpoint').write_bytes(data)
                    for name in ('manifest.json','hardware-memory.json'):
                        (changed/name).symlink_to(image/name)
                    with self.assertRaisesRegex(ValueError,message):
                        prepare(changed,root/(label+'-model'),LLVM)


@unittest.skipUnless(os.environ.get('OSREC_EL0_PRETRANSLATED_IMAGE'),'set pretranslated image for full negative checks')
class PretranslatedImage(unittest.TestCase):
    def test_bitmap_cannot_be_writable_or_unbound_from_metadata(self):
        from el0_hardware_model import prepare
        image=Path(os.environ['OSREC_EL0_PRETRANSLATED_IMAGE']).resolve();elf=Elf(image/'checkpoint')
        symbol=next((s for s in elf.symbols if s['name']=='flat_immutable_page_bits'),None)
        if not symbol:self.skipTest('image predates immutable bitmap')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for mode in ('writable','unbound'):
                changed=root/mode;changed.mkdir();data=bytearray(elf.data)
                metadata=json.loads((image/'hardware-memory.json').read_text())
                if mode=='writable':
                    at,=struct.unpack_from('<Q',data,32);stride,count=struct.unpack_from('<HH',data,54)
                    for i in range(count):
                        kind,flags,off,va,pa,size,mem,align=struct.unpack_from('<II6Q',data,at+i*stride)
                        if kind==1 and va<=symbol['value']<va+mem:
                            struct.pack_into('<I',data,at+i*stride+4,flags|2)
                else:metadata.pop('immutable_page_bitmap')
                (changed/'checkpoint').write_bytes(data)
                raw=(json.dumps(metadata,indent=2)+'\n').encode();(changed/'hardware-memory.json').write_bytes(raw)
                manifest=json.loads((image/'manifest.json').read_text());manifest['hardware_memory_sha256']=hashlib.sha256(raw).hexdigest()
                (changed/'manifest.json').write_text(json.dumps(manifest))
                # The whole read-only LOAD also contains the shadow flag;
                # its established diagnostic can precede the bitmap check.
                message='(bitmap|shadow header alignment flag).*writable' if mode=='writable' else 'bitmap mode differs'
                with self.assertRaisesRegex(ValueError,message):
                    prepare(changed,root/(mode+'-model'),LLVM)

    def test_corrupted_tables_and_guard_metadata_are_rejected(self):
        from el0_hardware_model import prepare
        image=Path(os.environ['OSREC_EL0_PRETRANSLATED_IMAGE']).resolve();elf=Elf(image/'checkpoint')
        syms={s['name']:s['value'] for s in elf.symbols if s['shndx']}
        def offset(va):
            section=next(s for s in elf.sections if s['addr']<=va<s['addr']+s['size'])
            return section['offset']+va-section['addr']
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            cases=[('tables',syms['flat_embedded_page_tables'],'embedded pretranslated page tables'),
                   ('guard',syms['flat_pretranslated_checks']+8,'descriptor checks differ')]
            if 'flat_immutable_page_bits' in syms:
                cases.append(('bitmap',syms['flat_immutable_page_bits'],'immutable page bitmap differs'))
            for label,va,message in cases:
                changed=root/label;changed.mkdir();data=bytearray(elf.data);data[offset(va)]^=1
                (changed/'checkpoint').write_bytes(data)
                for name in ('manifest.json','hardware-memory.json'):(changed/name).symlink_to(image/name)
                with self.assertRaisesRegex(ValueError,message):prepare(changed,root/(label+'-model'),LLVM)

    def test_descriptor_mismatch_stops_at_return_without_hardware_service(self):
        from el0_hardware_model import prepare,run
        image=Path(os.environ['OSREC_EL0_PRETRANSLATED_IMAGE']).resolve();elf=Elf(image/'checkpoint')
        syms={s['name']:s['value'] for s in elf.symbols if s['shndx']}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);changed=root/'changed';changed.mkdir()
            va=syms['flat_pretranslated_checks']+16
            section=next(s for s in elf.sections if s['addr']<=va<s['addr']+s['size'])
            data=bytearray(elf.data);data[section['offset']+va-section['addr']]^=1
            (changed/'checkpoint').write_bytes(data)
            metadata=json.loads((image/'hardware-memory.json').read_text())
            metadata['pretranslated_memory']['descriptor_checks'][0][2]^=1
            raw=(json.dumps(metadata,indent=2)+'\n').encode();(changed/'hardware-memory.json').write_bytes(raw)
            manifest=json.loads((image/'manifest.json').read_text());manifest['hardware_memory_sha256']=hashlib.sha256(raw).hexdigest()
            (changed/'manifest.json').write_text(json.dumps(manifest))
            prepared=root/'model';prepare(changed,prepared,LLVM)
            (prepared/'page-tables.bin').rename(prepared/'page-tables.debug.bin')
            checked=run(changed,prepared,root/'validation')
            self.assertFalse(checked['verified']);self.assertEqual(checked['result']['detail'],0x105)
            self.assertEqual(checked['hardware_exceptions'],0)
            self.assertFalse(checked['runtime_el1_services']);self.assertEqual(checked['host_calls_before_completion'],0)
            self.assertFalse(checked['external_page_tables_loaded'])


if __name__=='__main__':unittest.main()
