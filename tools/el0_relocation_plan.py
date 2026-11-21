"""Construction-time compact backing layout; never infer pointers from integers.

This inventories initial bindings, not future mappings or pointer provenance.
The entire captured RAM gets backing, including currently unmapped/zero pages.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path


CAPTURE_PAGE = 4096
MACOS_PAGE = 16384
MACOS_ALIAS_WINDOW = (1 << 32, 1 << 47)


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

    def host_page_projection(self, page_size, va_min, va_end):
        """Project existing VAs onto shared backing at the host mapping granule.

        A host page can be shared only if every captured subpage belongs to
        the same backing page, at the same offset and with the same access
        permissions. Missing subpages must stay inaccessible.
        """
        if (page_size < CAPTURE_PAGE or page_size & (page_size - 1) or
                not 0 <= va_min < va_end <= 1 << 64 or (va_min | va_end) % page_size):
            raise ValueError('invalid host page size or address window')
        host_pages = {}
        for row in self.aliases:
            va, pa, size = (row[key] for key in ('va', 'pa', 'bytes'))
            attrs = row['attrs']
            xn = 54 if row['domain'] == 'user' else 53
            flags = 4 | (0 if attrs & (1 << 7) else 2) | (0 if attrs & (1 << xn) else 1)
            for offset in range(0, size, CAPTURE_PAGE):
                address = va + offset
                backing = self.backing_base + pa + offset - self.ram_base
                host_va = address & -page_size
                host_pages.setdefault(host_va, []).append((address, backing, flags))

        bindings = []
        blocked = []
        compatible_pages = 0
        for va, pages in sorted(host_pages.items()):
            _, backing, flags = pages[0]
            backing &= -page_size
            reasons = []
            if not va_min <= va < va_end:
                reasons.append('outside-host-address-window')
            if len(pages) * CAPTURE_PAGE != page_size:
                reasons.append('partially-mapped-host-page')
            if any(address - va != target - backing for address, target, _ in pages):
                reasons.append('incompatible-backing')
            if flags == 7 or any(access != flags for _, _, access in pages):
                reasons.append('incompatible-permissions')
            if reasons:
                if (blocked and blocked[-1]['va'] + blocked[-1]['bytes'] == va and
                        blocked[-1]['reasons'] == reasons):
                    blocked[-1]['bytes'] += page_size
                    blocked[-1]['captured_pages'] += len(pages)
                else:
                    blocked.append(dict(va=va, bytes=page_size, reasons=reasons, captured_pages=len(pages)))
                continue

            compatible_pages += len(pages)
            if (bindings and bindings[-1]['va'] + bindings[-1]['bytes'] == va and
                    bindings[-1]['backing'] + bindings[-1]['bytes'] == backing and
                    bindings[-1]['flags'] == flags):
                bindings[-1]['bytes'] += page_size
            else:
                bindings.append(dict(va=va, backing=backing, bytes=page_size, flags=flags))

        return dict(page_size=page_size, address_window=[va_min, va_end],
                    compatible_captured_pages=compatible_pages,
                    blocked_captured_pages=sum(row['captured_pages'] for row in blocked),
                    initial_ram_representable=not blocked,
                    host_alias_candidates=bindings, blocked_ranges=blocked)


def macos_direct_aliases(base, size, maps, user, immutable=()):
    """Return original data VAs and canonical RAM offsets for a native ELF."""
    aliases = []
    captures = [(va, pa, length, attrs) for va, pa, length, attrs in maps
                if attrs & (1 << 10) and base <= pa and pa + length <= base + size]
    captures.extend((a['va'], a['pa'], a['bytes'], a['attrs']) for a in user)
    for va, pa, length, attrs in captures:
        cursor = pa
        end = pa + length
        attrs |= 1 << 53  # Linked code executes separately. These aliases are data only.
        for start, count in immutable:
            low, high = max(pa, start), min(end, start + count)
            if low >= high:
                continue
            if cursor < low:
                aliases.append(dict(va=va + cursor - pa, pa=cursor, bytes=low - cursor,
                                    attrs=attrs, domain='kernel'))
            aliases.append(dict(va=va + low - pa, pa=low, bytes=high - low,
                                attrs=attrs | (1 << 7), domain='kernel'))
            cursor = high
        if cursor < end:
            aliases.append(dict(va=va + cursor - pa, pa=cursor, bytes=end - cursor,
                                attrs=attrs, domain='kernel'))
    layout = CompactBacking(base, size, 0, aliases).host_page_projection(MACOS_PAGE, *MACOS_ALIAS_WINDOW)
    if not layout['initial_ram_representable']:
        first = layout['blocked_ranges'][0]
        raise ValueError(f"native macOS direct mappings cannot represent {layout['blocked_captured_pages']} "
                         f"captured pages. First blocked VA {first['va']:#x}: {', '.join(first['reasons'])}")
    if not layout['host_alias_candidates']:
        raise ValueError('native macOS direct memory requires captured RAM aliases')
    return layout['host_alias_candidates']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--backing-base', type=lambda x: int(x, 0), required=True)
    parser.add_argument('--host-page-size', type=lambda x: int(x, 0),
                        help='check whether captured aliases fit this host mapping granule')
    parser.add_argument('--host-va-min', type=lambda x: int(x, 0), default=0)
    parser.add_argument('--host-va-end', type=lambda x: int(x, 0), default=1 << 64)
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
    layout = CompactBacking(package.h[2], package.h[3], args.backing_base, aliases)
    result = layout.report()
    if args.host_page_size is not None:
        result['host_page_projection'] = layout.host_page_projection(
            args.host_page_size, args.host_va_min, args.host_va_end)
    result.update(package=str(args.package.resolve()), devices=devices,
                  native_state_sha256=hashlib.sha256(package.data).hexdigest(),
                  ram_sha256=hashlib.sha256(package.memory).hexdigest())
    args.out.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(ram_bytes=result['ram_bytes'], aliases=len(aliases),
                         device_aliases=len(devices), executable=False)))


if __name__ == '__main__':
    main()
