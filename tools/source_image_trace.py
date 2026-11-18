"""Record native AArch64 frame chains at checkpoint symbol breakpoints."""

import bisect
import struct
from collections import Counter

from gdb_remote import Exited
from kernel_replay_tables import KERNEL_BASE
from kernel_source_verify import Elf


def frame_links(remote, fp, stack_address, limit=32):
    """Yield saved return addresses from aligned, ascending frame records."""
    for _ in range(limit):
        if fp & 7 or not stack_address(fp) or not stack_address(fp + 15):
            break
        try:
            previous, link = struct.unpack('<QQ', remote.read(fp, 16))
        except (OSError, ValueError, Exited):
            break
        if not link:
            break
        yield link
        if previous <= fp:
            break
        fp = previous


class Callstacks:
    def __init__(self, image, manifest, requested, limit):
        if limit <= 0:
            raise ValueError('trace limit must be positive')
        if not manifest.get('shared_root'):
            raise ValueError('callstack tracing requires a symbolized shared-root checkpoint')
        elf = Elf(image)
        self.symbols = {symbol['name']: symbol['value'] for symbol in elf.symbols}
        self.locations = {}
        self.samples = []
        self.hits = Counter()
        self.limit = limit
        self.monitor = int(manifest['monitor_va'], 16)
        self.rows = []
        for symbol in elf.symbols:
            section = elf.sections[symbol['shndx']]
            if section['flags'] & 4 and section['name'].startswith('.osrec.'):
                role = section['name'].split('.')[2]
                if role != 'boot':
                    self.rows.append((symbol['value'], role, symbol))
        self.rows.sort(key=lambda row: (row[0], row[2]['type'] == 2, row[2]['size']))
        self.addresses = [row[0] for row in self.rows]
        for name in requested:
            matches = [(address, role) for address, role, s in self.rows if s['name'] == name]
            if not matches:
                raise ValueError(f'no checkpoint code symbol named {name}')
            for address, role in matches:
                self.locations[address] = name, role

    def describe(self, pc):
        index = bisect.bisect_right(self.addresses, pc) - 1
        if index >= 0:
            address, role, symbol = self.rows[index]
            size = symbol['size']
            if (size and pc < address + size) or pc == address:
                return dict(pc=hex(pc), symbol=symbol['name'], offset=pc - address, role=role)
        return dict(pc=hex(pc))

    def enabled(self, pc):
        return pc in self.locations and self.hits[pc] < self.limit

    def capture(self, remote, pc):
        name, role = self.locations[pc]
        self.hits[pc] += 1
        result = dict(at=dict(pc=hex(pc), symbol=name, role=role), kernel=[])
        self.samples.append(result)
        live = remote.registers(['x29', 'x30'])
        fp, lr = live['x29'], live['x30']
        guest_pc = pc
        if role == 'runtime':
            if name == 'minios_sync':
                context = remote.register('x0')
            else:
                context = remote.u(self.symbols['osrec_active_context'])
            # The monitor stores the interrupted EL0 registers on its stack.
            if not self.monitor <= context <= self.monitor + (16 << 20) - 272:
                return
            fp, lr, _, guest_pc = struct.unpack('<4Q', remote.read(context + 29*8, 32))
        if role == 'veneer':
            guest_pc = int(name.rsplit('_', 1)[-1], 16)
        result['guest_pc'] = hex(guest_pc)
        if not KERNEL_BASE <= guest_pc < 2*KERNEL_BASE:
            return

        result['kernel'].append(self.describe(guest_pc))
        # At a native function-entry breakpoint x29 still describes the caller.
        # At an interrupted instruction, the saved x29 is the frame to follow.
        links = frame_links(remote, fp, lambda va: KERNEL_BASE <= va < 2*KERNEL_BASE)
        returns = [lr] if role == 'kernel' and lr else []
        returns.extend(links)
        for link in returns:
            if not KERNEL_BASE < link <= 2*KERNEL_BASE:
                break
            result['kernel'].append(self.describe(link - 4))
