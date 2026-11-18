#!/usr/bin/env python3
"""Attribute execution-window instruction histograms to source adapters.

Uses the same zero-size provenance symbols and exact-code-identity plan as
el0_instruction_profile.py; it never uses a reference branch trace to run code.
"""
import argparse
from array import array
import bisect
from collections import Counter
import json
from pathlib import Path
import re
import struct

from el0_instruction_profile import MARKER, digest, segments, symbols

KINDS = ('native-control', 'memory', 'stack', 'system', 'indirect', 'svc',
         'boundary', 'unsupported', 'observe', 'coverage')


def hotspots(profile, annotated, histogram):
    profile, annotated = Path(profile), Path(annotated)
    plan = json.loads((profile/'profile-plan.json').read_text())
    original = (Path(plan['image'])/'checkpoint').read_bytes()
    marked = (annotated/'checkpoint').read_bytes()
    if digest(original) != plan['image_sha256'] or digest(marked) != plan['annotated_sha256']:
        raise ValueError('ELF identity differs from provenance plan')
    text = [s for s in segments(original) if s[0] == 1 and s[1] & 1]
    if len(text) != 1:
        raise ValueError('one executable segment required')
    text_base, text_bytes = text[0][3], text[0][5]
    samples = array('Q'); samples.frombytes(Path(histogram).read_bytes())
    if len(samples)*4 != text_bytes:
        raise ValueError('histogram size differs from executable segment')
    entries = {}
    for name, address in symbols(marked):
        if name.startswith(MARKER) and int(name[len(MARKER):].split('_')[0], 16) & 28:
            entries[name] = address
    source, pending, kinds = [], None, {}
    with (annotated/'program.S').open() as stream:
        for line in stream:
            match=re.fullmatch(r'(?:\.Lp([0-9a-f]+)|\.Lclone[0-9a-f]+_p([0-9a-f]+)):\n',line)
            if match:
                pending = int(match[1] or match[2], 16)
            elif pending is not None:
                name = line.strip().rstrip(':')
                if name not in entries:
                    raise ValueError('missing source marker after .Lp')
                source.append((entries[name], pending)); pending = None
            elif line.startswith('    .quad 0x'):
                fields = line.strip()[6:].split(',')
                if len(fields) == 8:
                    kinds[int(fields[0], 16)] = int(fields[5])
    source.sort(); starts = [address for address, pc in source]
    main_start = main_end = None
    resumes = []
    with (annotated/'checkpoint.map').open() as stream:
        for line in stream:
            if line.rstrip().endswith('program-asm.o:(.text)'):
                fields = line.split(); main_start = int(fields[0], 16)
                main_end = main_start+int(fields[2], 16)
            elif line.rstrip().endswith('program-asm.o:(.text.resumes)'):
                fields = line.split(); start = int(fields[0], 16)
                resumes.append((start,start+int(fields[2], 16)))
    if main_end is None:
        raise ValueError('main generated section extent missing')
    native = dict(struct.iter_unpack('<2Q', (profile/'pc-map.bin').read_bytes()))
    categories, sites, payload = Counter(), Counter(), Counter()
    def is_resume(pc):
        return any(lo <= pc < hi for lo,hi in resumes)
    # LTO may place C functions after the generated text and resume section.
    # Attribute by actual input-section extents instead of relative ordering.
    runtime_symbols = sorted((address, name) for name, address in symbols(original)
                             if text_base <= address < text_base+text_bytes and
                             not main_start <= address < main_end and not is_resume(address) and
                             name and not name.startswith(('$', '.')))
    runtime_starts = [address for address, name in runtime_symbols]
    runtime_functions = Counter()
    for i, count in enumerate(samples):
        if not count:
            continue
        pc = text_base+4*i
        flags = native.get(pc, 0)
        if flags & 3:
            payload['kernel' if flags & 3 == 1 else 'application'] += count
            continue
        if main_start <= pc < main_end:
            index = bisect.bisect_right(starts, pc)-1
            original_pc = source[index][1]
            categories[KINDS[kinds.get(original_pc, 0)]] += count
            sites[original_pc] += count
        elif is_resume(pc):
            categories['resume-thunks'] += count
        else:
            categories['runtime-functions'] += count
            index = bisect.bisect_right(runtime_starts, pc)-1
            runtime_functions[runtime_symbols[index][1] if index >= 0 else 'unknown'] += count
    measured = json.loads((profile/'counts.json').read_text())['execution_interval']
    if sum(categories.values()) != measured['runtime_adapter'] or sum(samples) != measured['total_instructions']:
        raise ValueError('histogram differs from accepted instruction counts')
    result = dict(image_sha256=plan['image_sha256'], total=sum(samples), runtime=sum(categories.values()),
                  runtime_by_adapter=dict(categories.most_common()), native_payload=dict(payload),
                  top_runtime_functions=dict(runtime_functions.most_common(20)),
                  top_source_sites=[dict(pc=hex(pc), kind=KINDS[kinds.get(pc, 0)], instructions=count)
                                    for pc, count in sites.most_common(30)])
    (profile/'hotspots.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--annotated', required=True)
    parser.add_argument('--histogram', required=True)
    print(json.dumps(hotspots(**vars(parser.parse_args())), indent=2))
