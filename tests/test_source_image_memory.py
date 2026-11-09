"""Differential checking must catch wrong bytes even with correct syscall results."""
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from source_image import compare
from source_image_memory import snapshot


class RemoteMemory:
    def __init__(self):
        self.physical = False
        self.pages = {}
    def request(self, packet):
        self.physical = packet.endswith(':1')
        return 'OK'
    def read(self, address, size):
        assert self.physical
        return self.pages[address][:size]
    def table(self, address, index, descriptor):
        b = bytearray(self.pages.get(address, bytes(4096)))
        struct.pack_into('<Q', b, index * 8, descriptor)
        self.pages[address] = bytes(b)


class UserMemory(unittest.TestCase):
    def test_walk_hashes_user_leaves_and_respects_table_permissions(self):
        r = RemoteMemory()
        # 39-bit lower VA space: L1 -> L2 -> L3.
        r.table(0x1000, 0, 0x2003)
        r.table(0x2000, 0, 0x3003)
        r.table(0x3000, 1, 0x4043)
        r.table(0x3000, 2, 0x5003)  # privileged leaf excluded
        r.pages[0x4000] = b'a' * 4096
        self.assertEqual(snapshot(r, 0xbeef000000001001, 25), [['0x1000', hashlib.sha256(b'a' * 4096).hexdigest()]])
        self.assertFalse(r.physical)
        r.table(0x2000, 0, 0x3003 | (1 << 61))  # APTable denies EL0
        self.assertEqual(snapshot(r, 0x1000, 25), [])
        self.assertFalse(r.physical)

    def test_mmio_is_rejected_without_reading_it(self):
        r = RemoteMemory()
        r.table(0x1000, 0, 0x2003)
        r.table(0x2000, 0, 0x3003)
        r.table(0x3000, 1, 0x9000043)
        with self.assertRaisesRegex(ValueError, 'non-RAM'):
            snapshot(r, 0x1000, 25, (0x1000, 0x4000))
        self.assertFalse(r.physical)

    def test_read_failure_restores_virtual_mode(self):
        r = RemoteMemory()
        with self.assertRaises(KeyError):
            snapshot(r, 0x1000, 25)
        self.assertFalse(r.physical)

    def test_unsupported_translation_regime_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'granule'):
            snapshot(RemoteMemory(), 0x1000, 25 | 1 << 14)

    def check(self, a, b):
        with tempfile.TemporaryDirectory() as tmp:
            x, y = Path(tmp) / 'a.json', Path(tmp) / 'b.json'
            x.write_text(json.dumps(dict(calls=a)))
            y.write_text(json.dumps(dict(calls=b)))
            return compare(x, y)

    def test_equal_returns_do_not_hide_changed_memory(self):
        call = dict(number=63, arguments=[3, 4096, 1], result=1)
        a = dict(call, memory=[['0x1000', 'a']])
        b = dict(call, memory=[['0x1000', 'b']])
        r = self.check([a], [b])
        self.assertFalse(r['matches'])
        self.assertEqual(r['first_difference'], 0)
        self.assertEqual(r['first_memory_difference'], 0)
        self.assertEqual(r['memory_identical'], 0)
        self.assertFalse(self.check([a], [call])['matches'])
        self.assertTrue(self.check([a], [a])['matches'])

    def test_unmatched_tail_is_a_failure(self):
        call = dict(number=172, arguments=[0] * 6, result=1)
        r = self.check([call], [call, call])
        self.assertFalse(r['matches'])
        self.assertEqual(r['first_difference'], 1)


if __name__ == '__main__':
    unittest.main()
