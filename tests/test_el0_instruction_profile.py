"""Check per-instruction counts across a taken loop and exclusive window edges."""
from pathlib import Path
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from el0_instruction_profile import assess_budget, annotate, make_map, segments, symbols
from el0_instruction_hotspots import hotspots

LLVM = Path('/opt/homebrew/opt/llvm@16/bin')
QEMU = shutil.which('qemu-system-aarch64')
PLUGIN = ROOT/'build/qemu-plugins/libinstruction_profile.dylib'


class Budget(unittest.TestCase):
    def test_ten_percent_target_twenty_percent_ceiling_and_failure(self):
        at_target=assess_budget(dict(kernel_source_visits=1000,runtime_adapter=100))
        self.assertTrue(at_target['target_met'])
        self.assertTrue(at_target['maximum_met'])
        at_maximum=assess_budget(dict(kernel_source_visits=1000,runtime_adapter=200))
        self.assertFalse(at_maximum['target_met'])
        self.assertTrue(at_maximum['maximum_met'])
        above=assess_budget(dict(kernel_source_visits=1000,runtime_adapter=201))
        self.assertFalse(above['maximum_met'])
        with self.assertRaises(ValueError):
            assess_budget(dict(kernel_source_visits=0,runtime_adapter=0))


@unittest.skipUnless((LLVM/'clang').exists(),'cross clang required')
class HotspotRanges(unittest.TestCase):
    def test_c_functions_before_or_after_generated_sections_are_runtime(self):
        from el0_instruction_profile import digest
        with tempfile.TemporaryDirectory() as directory:
            for runtime_first in (True,False):
                with self.subTest(runtime_first=runtime_first):
                    root=Path(directory)/str(runtime_first);root.mkdir()
                    (root/'program.S').write_text('''.text
.Lp1000:
__osrec_ip_4_0:
    nop
.pushsection .text.resumes,"ax"
.global sample_resume
sample_resume:
    ret
.popsection
.section .rodata,"a"
    .quad 0x1000,0,0,0,0,3,0,0
''')
                    (root/'runtime.S').write_text('.text\n.global runtime_helper\nruntime_helper:\n    ret\n')
                    for source,obj in (('program.S','program-asm.o'),('runtime.S','runtime.o')):
                        subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-c',str(root/source),
                                        '-o',str(root/obj)],check=True,capture_output=True)
                    objects=['runtime.o','program-asm.o'] if runtime_first else ['program-asm.o','runtime.o']
                    subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-nostdlib','-fuse-ld=lld',
                                    '-Wl,-e,runtime_helper,--build-id=none,-Map,'+str(root/'checkpoint.map'),
                                    *(str(root/p) for p in objects),'-o',str(root/'checkpoint')],check=True,capture_output=True)
                    data=(root/'checkpoint').read_bytes();syms=dict(symbols(data))
                    text=next(s for s in segments(data) if s[0]==1 and s[1]&1)
                    samples=[0]*(text[5]//4)
                    for name,count in (('runtime_helper',11),('__osrec_ip_4_0',3),('sample_resume',5)):
                        samples[(syms[name]-text[3])//4]=count
                    (root/'histogram.bin').write_bytes(struct.pack('<%dQ'%len(samples),*samples))
                    (root/'pc-map.bin').write_bytes(b'')
                    (root/'profile-plan.json').write_text(json.dumps(dict(image=str(root),image_sha256=digest(data),
                        annotated_sha256=digest(data))))
                    (root/'counts.json').write_text(json.dumps(dict(execution_interval=dict(runtime_adapter=19,total_instructions=19))))
                    result=hotspots(root,root,root/'histogram.bin')
                    self.assertEqual(result['runtime_by_adapter'],{'runtime-functions':11,'resume-thunks':5,'system':3})
                    self.assertEqual(result['top_runtime_functions'],{'runtime_helper':11})


@unittest.skipUnless(QEMU and (LLVM/'clang').exists() and PLUGIN.exists(),
                     'cross clang, QEMU and built instruction_profile plugin required')
class InstructionProfile(unittest.TestCase):
    def test_grouped_system_operations_keep_each_source_visit_without_native_payload(self):
        from el0_system_groups import system_group_path
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/'original';image.mkdir()
            source='.text\n.global _start,flat_main,flat_run,flat_completed\n_start:\nflat_main: bl flat_run\nflat_completed: b .\nflat_run:\n.Lp40100000:\n'
            source+=system_group_path(0x40100000,(0xd5384100,0xd5384101,0xd508871f),'.Lp4010000c')
            source+='.Lp4010000c:\n    b .Lp40100000\n.bss\n.balign 128\nflat_shadow: .zero 128\n'
            (image/'program.S').write_text(source)
            def build(path):
                subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-nostdlib','-fuse-ld=lld',
                    '-Wl,-Ttext=0x40100000,-e,_start,--build-id=none',str(path/'program.S'),'-o',str(path/'checkpoint')],check=True,capture_output=True)
            build(image);(image/'native.bin').write_bytes(bytes(80))
            (image/'manifest.json').write_text(json.dumps(dict(kernel=str(image/'checkpoint'),user_elf=str(image/'checkpoint'),package=str(image))))
            marked=root/'marked';report=annotate(image,marked)
            self.assertEqual(report['assembly_markers'],dict(source_markers=4,payload_markers=1))
            build(marked);plan=make_map(image,marked,root/'profile',LLVM)
            self.assertTrue(plan['loaded_code_data_identical'])
            rows=list(struct.iter_unpack('<2Q',(root/'profile/pc-map.bin').read_bytes()))
            self.assertEqual(sum(bool(flags&12) for pc,flags in rows),4)
            self.assertEqual(sum(bool(flags&3) for pc,flags in rows),1)

    def test_immutable_literal_load_counts_one_payload_instruction_and_no_pool_data(self):
        from el0_memory_elision import literal_path
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/'original';image.mkdir()
            source='.text\n.global _start,flat_main,flat_run,flat_completed\n_start:\nflat_main: bl flat_run\nflat_completed: b .\nflat_run:\n.Lp40100000:\n'
            source+=literal_path(dict(word=0x58000040,data=bytes.fromhex('fedcba9876543210')),'.Lp40100004')
            source+='.Lp40100004:\n    b .Lp40100000\n'
            (image/'program.S').write_text(source)
            def build(path):
                subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-nostdlib','-fuse-ld=lld',
                    '-Wl,-Ttext=0x40100000,-e,_start,--build-id=none',str(path/'program.S'),'-o',str(path/'checkpoint')],check=True,capture_output=True)
            build(image);(image/'native.bin').write_bytes(bytes(80))
            (image/'manifest.json').write_text(json.dumps(dict(kernel=str(image/'checkpoint'),user_elf=str(image/'checkpoint'),package=str(image))))
            marked=root/'marked';report=annotate(image,marked)
            self.assertEqual(report['assembly_markers'],dict(source_markers=2,payload_markers=2))
            build(marked);plan=make_map(image,marked,root/'profile',LLVM)
            self.assertTrue(plan['loaded_code_data_identical'])
            rows=list(struct.iter_unpack('<2Q',(root/'profile/pc-map.bin').read_bytes()))
            self.assertEqual(sum(bool(flags&3) for pc,flags in rows),2)

    def test_short_conditionals_and_one_to_four_instruction_links_keep_payload_provenance(self):
        from el0_hardware import immediate
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/'original';image.mkdir()
            lines=['.text','.global _start,flat_main,flat_run,flat_completed',
                   '_start:','flat_main: bl flat_run','flat_completed: b .','flat_run:']
            values=[sum(4<<(16*k) for k in range(i)) for i in range(1,5)]
            values += [((1<<64)-1)^sum(4<<(16*k) for k in range(i)) for i in range(1,4)]
            for i,value in enumerate(values):
                lines+=['.Lp%x:'%(0x40100000+4*i)]+immediate(30,value)+['b .Lp40100000']
            for i,branch in enumerate(('b.eq','cbz w0,','cbnz xzr,','tbnz x3,#63,'),len(values)):
                lines+=['.Lp%x:'%(0x40100000+4*i),branch+(' ' if branch=='b.eq' else '')+'.Lp40100000']
            # A conditional inside an adapter must remain runtime overhead.
            lines+=['.Lp%x:'%(0x40100000+4*(len(values)+4)),'stp x16,x17,[sp,#-16]!','b.eq .Lp40100000']
            (image/'program.S').write_text('\n'.join(lines)+'\n')
            def build(path):
                subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-nostdlib','-fuse-ld=lld',
                    '-Wl,-Ttext=0x40100000,-e,_start,--build-id=none',str(path/'program.S'),'-o',str(path/'checkpoint')],check=True,capture_output=True)
            build(image);(image/'native.bin').write_bytes(bytes(80))
            (image/'manifest.json').write_text(json.dumps(dict(kernel=str(image/'checkpoint'),user_elf=str(image/'checkpoint'),package=str(image))))
            marked=root/'marked';report=annotate(image,marked)
            self.assertEqual(report['assembly_markers'],dict(source_markers=12,payload_markers=11))
            build(marked);plan=make_map(image,marked,root/'profile',LLVM)
            self.assertTrue(plan['loaded_code_data_identical'])
            rows=list(struct.iter_unpack('<2Q',(root/'profile/pc-map.bin').read_bytes()))
            self.assertEqual(sum(bool(flags&3) for pc,flags in rows),11)

    def test_clone_sources_and_direct_calls_keep_provenance_without_changing_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/'original';image.mkdir()
            source='''.text
.global _start,flat_main,flat_run,flat_completed
_start:
flat_main: bl flat_run
flat_completed: b .
flat_run:
.Lp40100000:
    movz x30,#4
    movk x30,#0,lsl #16
    movk x30,#0,lsl #32
    movk x30,#0,lsl #48
    b .Lclone40100000_p40100004
.Lclone40100000_p40100004:
    b .Lclone10000000000000000_p40100008
.Lclone10000000000000000_p40100008:
    b .Lp40100000
'''
            (image/'program.S').write_text(source)
            def build(path):
                subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-nostdlib','-fuse-ld=lld',
                                '-Wl,-Ttext=0x40100000,-e,_start,--build-id=none',str(path/'program.S'),
                                '-o',str(path/'checkpoint')],check=True)
            build(image)
            (image/'native.bin').write_bytes(bytes(80))
            (image/'manifest.json').write_text(json.dumps(dict(kernel=str(image/'checkpoint'),
                user_elf=str(image/'checkpoint'),package=str(image))))
            marked=root/'marked';report=annotate(image,marked)
            self.assertEqual(report['assembly_markers'],dict(source_markers=3,payload_markers=3))
            build(marked);plan=make_map(image,marked,root/'profile',LLVM)
            self.assertTrue(plan['loaded_code_data_identical'])
            rows=list(struct.iter_unpack('<2Q',(root/'profile/pc-map.bin').read_bytes()))
            self.assertEqual(sum(bool(flags&12) for pc,flags in rows),3)
            self.assertEqual(sum(bool(flags&3) for pc,flags in rows),3)

    def test_provenance_map_requires_identical_loaded_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = '''.text
.global _start,flat_main,flat_run,flat_completed
_start:
flat_main:
    bl flat_run
flat_completed:
    b .
flat_run:
%s
    %s
'''
            for name, marker, operation in (('original', '', 'ret'),
                                             ('marked', '__osrec_ip_a_0:', 'ret'),
                                             ('changed', '__osrec_ip_a_0:', 'nop')):
                image = root/name; image.mkdir()
                (image/'program.S').write_text(source % (marker, operation))
                subprocess.run([str(LLVM/'clang'), '--target=aarch64-none-elf', '-nostdlib',
                                '-fuse-ld=lld', '-Wl,-Ttext=0x40100000,-e,_start,--build-id=none',
                                str(image/'program.S'), '-o', str(image/'checkpoint')], check=True)
            plan = make_map(root/'original', root/'marked', root/'profile', LLVM)
            self.assertTrue(plan['loaded_code_data_identical'])
            self.assertEqual(plan['pc_map_entries'], 1)
            user_entry = plan['boundaries']['begin']
            user_plan = make_map(root/'original', root/'marked', root/'user-profile', LLVM, user_entry=user_entry)
            self.assertEqual(user_plan['boundaries']['begin'], user_entry)
            self.assertEqual(user_plan['boundaries']['end'], plan['boundaries']['stop'])
            with_moved_load = root/'moved'
            with_moved_load.mkdir()
            data = bytearray((root/'marked/checkpoint').read_bytes())
            index, load = next((i, h) for i, h in enumerate(segments(data)) if h[0] == 1 and h[1] & 1)
            _, _, offset, va, _, filesz, _, align = load
            phoff, = struct.unpack_from('<Q', data, 32)
            stride, count = struct.unpack_from('<HH', data, 54)
            headers = data[phoff:phoff+stride*count]
            data.extend(bytes((va-len(data)) % align))
            struct.pack_into('<Q', headers, index*stride+8, len(data))
            data.extend(data[offset:offset+filesz])
            data.extend(bytes((-len(data)) % 8))
            struct.pack_into('<Q', data, 32, len(data))
            data.extend(headers)
            (with_moved_load/'checkpoint').write_bytes(data)
            moved_plan = make_map(root/'original', with_moved_load, root/'moved-profile', LLVM, user_entry=user_entry)
            self.assertEqual(moved_plan['pc_map_sha256'], user_plan['pc_map_sha256'])
            with self.assertRaisesRegex(ValueError, 'not a linked user source site'):
                make_map(root/'original', root/'marked', root/'invalid-entry', LLVM, user_entry=user_entry+1)
            with self.assertRaisesRegex(ValueError, 'changed loaded code/data'):
                make_map(root/'original', root/'changed', root/'invalid', LLVM)

    def test_taken_loop_and_window_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            source = out/'fixture.S'
            source.write_text('''.text
.global _start,begin,end,stop,loop
_start: mov x2,#0
begin: mov x0,#5
loop: subs x0,x0,#1
      b.ne loop
end: mov x1,#9
stop: mov x0,#0x20
      adr x1,exit_block
      hlt #0xf000
.balign 8
exit_block: .quad 0x20026,0
''')
            elf = out/'fixture'
            subprocess.run([str(LLVM/'clang'), '--target=aarch64-none-elf', '-nostdlib',
                            '-fuse-ld=lld', '-Wl,-Ttext=0x40100000,-e,_start,--build-id=none',
                            str(source), '-o', str(elf)], check=True)
            syms = dict(symbols(elf.read_bytes()))
            self.assertTrue(any(s[0] == 1 for s in segments(elf.read_bytes())))
            pcmap = out/'map.bin'
            rows = [(syms['_start'], 16)] + [(syms['begin']+4*i, 5) for i in range(3)] + [(syms['end'], 10)]
            pcmap.write_bytes(b''.join(struct.pack('<2Q', *row) for row in rows))
            counters = out/'counts.bin'
            histogram = out/'histogram.bin'
            plugin = ','.join([str(PLUGIN), 'map='+str(pcmap), 'out='+str(counters)] +
                              [key+'='+hex(syms[label]) for key, label in
                               (('start', '_start'), ('begin', 'begin'), ('end', 'end'), ('stop', 'stop'))] +
                              ['hist='+str(histogram), 'text='+hex(syms['_start']), 'bytes=24'])
            process = subprocess.run([QEMU, '-M', 'virt', '-cpu', 'cortex-a53', '-smp', '1', '-m', '128M',
                            '-nodefaults', '-display', 'none', '-monitor', 'none', '-serial', 'none',
                            '-semihosting-config', 'enable=on,target=native', '-device',
                            'loader,file='+str(elf)+',cpu-num=0', '-plugin', plugin],
                           timeout=30, capture_output=True, text=True)
            self.assertEqual(process.returncode, 0, process.stderr)
            counts = struct.unpack('<20Q', counters.read_bytes())
            self.assertEqual(counts[2:6], (1, 1, 1, 1))
            self.assertEqual(counts[8:14], (1, 11, 1, 11, 1, 1))
            self.assertEqual(counts[14:20], (0, 11, 0, 11, 0, 0))
            self.assertEqual(struct.unpack('<6Q', histogram.read_bytes()), (0, 1, 5, 5, 0, 0))


if __name__ == '__main__':
    unittest.main()
