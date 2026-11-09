"""Optional hardware check: user code cannot read EL0-accessible kernel mappings.

OSREC_EL0_IMAGE=build/my-image python3 -m unittest discover -s tests -p test_el0_user_guard.py
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from gdb_remote import Remote
from svc_boundary import free_port
from source_image import QEMU


@unittest.skipUnless(os.environ.get('OSREC_EL0_IMAGE'), 'set OSREC_EL0_IMAGE for the QEMU permission check')
class UserPermissions(unittest.TestCase):
    def test_kernel_read_is_a_named_stop(self):
        self.probe(False)

    def test_lowered_kernel_pointer_in_write_is_a_named_stop(self):
        self.probe(True)

    def test_branch_veneer_is_not_user_readable(self):
        self.probe(False,'va')

    def test_branch_shadow_alias_is_not_user_readable(self):
        self.probe(False,'state_va')

    def probe(self,syscall,branch_target=None):
        image = Path(os.environ['OSREC_EL0_IMAGE']).resolve()
        m = json.loads((image / 'manifest.json').read_text())
        if syscall and not m.get('lowered'):self.skipTest('requires a lowered image')
        state = json.loads((Path(m['dump']) / 'state.json').read_text())
        user_pc = state['cpu']['sysregs']['ELR_EL1'] - 4
        kernel_va = int(m['vector_base'], 16)
        if branch_target:
            if not m.get('branch_veneers') or branch_target not in m['branch_veneers']:
                self.skipTest('requires an image with linked branch veneers and state alias')
            kernel_va=int(m['branch_veneers'][branch_target],16)
        port = free_port()
        with tempfile.TemporaryDirectory() as tmp:
            with open(Path(tmp) / 'qemu.log', 'wb') as log:
                command = [QEMU, '-M', 'virt-9.2,secure=off,virtualization=off', '-cpu', 'cortex-a53',
                           '-accel', 'tcg', '-smp', '1', '-m', str(m['image_ram_mb']) + 'M',
                           '-nodefaults', '-display', 'none', '-monitor', 'none', '-serial', 'none',
                           '-device', 'loader,file=%s,cpu-num=0' % (image / 'image.elf'),
                           '-S', '-gdb', 'tcp:127.0.0.1:%d' % port]
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                try:
                    r = Remote(port, timeout=30)
                    stop = int(m['stop'], 16)
                    r.breakpoint(stop)
                    r.breakpoint(user_pc)
                    r.resume()
                    self.assertEqual(r.wait(), user_pc)
                    self.assertEqual(r.register('cpsr') & 15, 0)
                    # A synthetic user read of kernel text must fault before it
                    # can observe the rewritten bytes. The shared core names it.
                    def setreg(name,value):
                        self.assertEqual(r.request('P%x=%s'%(r.numbers[name][0],value.to_bytes(8,'little').hex())),'OK')
                    if syscall:
                        setreg('x8',64);setreg('x0',3);setreg('x2',1)  # write(memfd, kernel_text, 1)
                    else:self.assertEqual(r.request('M%x,4:200040f9' % user_pc), 'OK')  # ldr x0,[x1]
                    setreg('x1',kernel_va)
                    r.breakpoint(user_pc, False)
                    r.resume()
                    self.assertEqual(r.wait(), stop)
                    self.assertEqual(r.register('x0'), 8)
                    if not syscall:self.assertEqual(r.register('x1'), user_pc)
                    self.assertEqual(r.register('x3'), kernel_va)
                    if m.get('lowered'):
                        self.assertTrue(r.register('TCR_EL1')&(1<<23))  # TTBR1 disabled
                        self.assertEqual(r.register('TTBR1_EL1')&0x0000fffffffff000,0)
                    r.socket.close()
                finally:
                    process.terminate()
                    process.wait(timeout=10)


if __name__ == '__main__':
    unittest.main()
