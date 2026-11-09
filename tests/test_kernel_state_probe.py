"""Register probes must leave both the stopped instruction and GPRs intact."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from kernel_state_dump import PROBES, probe_registers


class Remote:
    numbers = {'x0': (0, 64), 'pc': (32, 64)}
    def __init__(self, trap=False):
        self.code = b'\xff\x43\x05\xd1'
        self.regs = dict(x0=99, pc=0x800400)
        self.trap = trap
    def read(self, address, size):
        assert address == 0x800400 and size == 4
        return self.code
    def register(self, name):
        return self.regs[name]
    def request(self, packet):
        if packet.startswith('M800400,4:'):
            self.code = bytes.fromhex(packet.split(':')[1])
        else:
            number, value = packet[1:].split('=')
            name = 'x0' if int(number, 16) == 0 else 'pc'
            self.regs[name] = int.from_bytes(bytes.fromhex(value), 'little')
        return 'OK'
    def step(self):
        word = int.from_bytes(self.code, 'little')
        self.regs['x0'] = word
        self.regs['pc'] += 8 if self.trap else 4


class CaptureProbe(unittest.TestCase):
    def test_register_values_and_complete_restore(self):
        r = Remote()
        self.assertEqual(probe_registers(r, 0x800400), PROBES)
        self.assertEqual(r.code, b'\xff\x43\x05\xd1')
        self.assertEqual(r.regs, dict(x0=99, pc=0x800400))

    def test_failed_probe_still_restores_and_aborts(self):
        r = Remote(trap=True)
        with self.assertRaisesRegex(ValueError, 'probe trapped'):
            probe_registers(r, 0x800400)
        self.assertEqual(r.code, b'\xff\x43\x05\xd1')
        self.assertEqual(r.regs, dict(x0=99, pc=0x800400))


if __name__ == '__main__':
    unittest.main()
