"""Construction-time compact backing layout; never infer pointers from integers.

This inventories initial bindings, not future mappings or pointer provenance.
The entire captured RAM gets backing, including currently unmapped/zero pages.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path


class CompactBacking:
    def __init__(self, ram_base, ram_bytes, backing_base, aliases):
        if (min(ram_base, backing_base) < 0 or ram_bytes <= 0 or
                (ram_base | ram_bytes | backing_base) & 4095 or
                ram_base + ram_bytes > 1 << 64 or backing_base + ram_bytes > 1 << 48):
            raise ValueError('invalid compact RAM layout')
        self.ram_base, self.ram_bytes, self.backing_base = ram_base, ram_bytes, backing_base
        self.aliases = sorted(aliases, key=lambda a: a['va'])
        end = 0
        for a in self.aliases:
            va, pa, size = (a[k] for k in ('va', 'pa', 'bytes'))
            if (va < end or va < 0 or size <= 0 or (va | pa | size) & 4095 or
                    va + size > 1 << 64 or pa < ram_base or pa + size > ram_base + ram_bytes):
                raise ValueError('overlapping or invalid initial alias')
            end = va + size
        self.starts = [a['va'] for a in self.aliases]

    def resolve(self, address, size=1):
        """Return compact address only for a completely contiguous initial span.

        Permission/fault proofs are deliberately separate from address resolution.
        """
        if address < 0 or size <= 0 or address + size > 1 << 64:
            return None
        i = bisect.bisect_right(self.starts, address) - 1
        if i < 0:
            return None
        done = 0
        result = None
        while done < size and i < len(self.aliases):
            a = self.aliases[i]
            offset = address + done - a['va']
            if not 0 <= offset < a['bytes']:
                return None
            target = self.backing_base + a['pa'] - self.ram_base + offset
            if result is None:
                result = target
            elif target != result + done:
                return None
            done += min(size - done, a['bytes'] - offset)
            i += 1
        return result if done == size else None

    def report(self):
        return dict(format='osrec-compact-relocation-plan-v1', executable=False,
                    ram_base=self.ram_base, ram_bytes=self.ram_bytes,
                    backing_base=self.backing_base,
                    aliases=[dict(a, backing=self.backing_base+a['pa']-self.ram_base)
                             for a in self.aliases],
                    unresolved=['pointer provenance in RAM and saved registers',
                                'dynamic address construction and mutable mappings',
                                'access permissions, faults, and address-observing operations',
                                'executable pages not identified by supplied ELF mapping symbols'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--backing-base', type=lambda x: int(x, 0), required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    from export_el0_program import Package
    from el0_pretranslate import user_aliases
    package = Package(args.package)
    # Device aliases have no RAM backing and remain explicit architecture edges.
    aliases, devices = [], []
    for va, pa, size, attrs in package.maps:
        row = dict(va=va, pa=pa, bytes=size, attrs=attrs, domain='kernel')
        (aliases if package.h[2] <= pa and pa+size <= package.h[2]+package.h[3]
         else devices).append(row)
    aliases += [dict(a, domain='user') for a in user_aliases(package)]
    result = CompactBacking(package.h[2], package.h[3], args.backing_base, aliases).report()
    result.update(package=str(args.package.resolve()), devices=devices,
                  native_state_sha256=hashlib.sha256(package.data).hexdigest(),
                  ram_sha256=hashlib.sha256(package.memory).hexdigest())
    args.out.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(ram_bytes=result['ram_bytes'], aliases=len(aliases),
                         device_aliases=len(devices), executable=False)))


if __name__ == '__main__':
    main()
