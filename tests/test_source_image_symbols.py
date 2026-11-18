import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from kernel_boundary_replay import elf
from kernel_source_verify import Elf
from source_image_symbols import embed
from source_image_trace import frame_links


def code_image(base, symbols):
    return SimpleNamespace(
        sections=[{}, dict(name='.text', flags=6, addr=base, size=0x2000)],
        symbols=[dict(name=name, value=address, shndx=1, type=2, size=32, bind=1)
                 for name, address in symbols])


class CheckpointSymbols(unittest.TestCase):
    def test_embed_preserves_load_bytes_and_maps_symbol_addresses(self):
        kernel_base = 0xffff800000000000
        delta = 1 << 48
        live = (kernel_base + delta) % (1 << 64)
        kernel = code_image(kernel_base, [('do_work', kernel_base + 4), ('unmapped', kernel_base + 4096)])
        monitor = code_image(0x10000000000, [('minios_sync', 0x10000000000)])
        veneers = code_image(live + 0x4000, [('osrec_call_0', live + 0x4000)])
        raw = elf([(0x71000000, b'checkpoint bytes')], 0x71000000)
        manifest = dict(kernel_shift=hex(delta), pages=[dict(kind='text', va=hex(live), original_va=hex(kernel_base))])
        labelled, counts = embed(raw, manifest, kernel, monitor, veneers,
                                 [dict(pc=hex(live + 8), insn='0xd50342df')])
        self.assertEqual(counts, dict(kernel=1, runtime=2, veneer=1))
        self.assertEqual(labelled[:40], raw[:40])
        self.assertEqual(labelled[64:len(raw)], raw[64:])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'image.elf'
            path.write_bytes(labelled)
            names = {symbol['name']: symbol['value'] for symbol in Elf(path).symbols}
        self.assertEqual(names['do_work'], live + 4)
        self.assertNotIn('unmapped', names)
        self.assertEqual(names['minios_sync'], 0x10000000000)
        self.assertEqual(names['osrec_veneer_do_work_daifset_2_%x' % (live + 8)], live + 0x4000)

    def test_frame_walk_stops_at_cycles_and_outside_the_kernel_stack_window(self):
        base = 1 << 39
        memory = {base: (base+16, base+0x1000), base+16: (base+16, base+0x2000)}
        remote = SimpleNamespace(read=lambda va, _: struct.pack('<QQ', *memory[va]))
        in_kernel = lambda va: base <= va < 2*base
        self.assertEqual(list(frame_links(remote, base, in_kernel)), [base+0x1000, base+0x2000])
        self.assertEqual(list(frame_links(remote, base-16, in_kernel)), [])
        self.assertEqual(list(frame_links(remote, base+1, in_kernel)), [])
