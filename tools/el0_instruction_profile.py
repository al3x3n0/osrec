#!/usr/bin/env python3
"""Measure the original checkpoint with a QEMU per-instruction plugin.

The annotate/map steps add zero-size symbols to a throwaway assembly copy.
The map step requires identical loadable code/data; run always uses the original
ELF, with the derived PC map. No profiling instructions are added to the guest.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
from fractions import Fraction

from kernel_source_verify import Elf

MARKER = '__osrec_ip_'
MASK48 = (1 << 48) - 1
NAMES = ('runtime_adapter', 'native_kernel', 'native_application',
         'kernel_source_visits', 'application_source_visits', 'synthetic_source_visits')
BUDGET = Path(__file__).resolve().parents[1]/'runtime/el0_flat/instruction-budget.json'


def assess_budget(counts, specification=None):
    specification = specification or json.loads(BUDGET.read_text())
    denominator = counts[specification['denominator']]
    numerator = counts[specification['numerator']]
    maximum = Fraction(str(specification['maximum_fraction']))
    target = Fraction(str(specification['target_fraction']))
    if denominator <= 0 or numerator < 0 or not 0 < target <= maximum:
        raise ValueError('invalid instruction budget or dynamic counts')
    allowed = int(denominator*maximum); desired = int(denominator*target)
    return dict(**specification, runtime_instructions=numerator, original_kernel_operations=denominator,
                measured_fraction=numerator/denominator, maximum_instructions=allowed,
                target_instructions=desired, maximum_met=numerator <= allowed,
                target_met=numerator <= desired)


def check_budget(profile):
    profile = Path(profile)
    counts = json.loads((profile/'counts.json').read_text())
    specification = json.loads(BUDGET.read_text())
    result = assess_budget(counts[specification['window']], specification)
    (profile/'budget.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


def digest(data):
    return hashlib.sha256(data).hexdigest()


def annotate(image, out):
    image, out = Path(image).resolve(), Path(out).resolve()
    manifest = json.loads((image / 'manifest.json').read_text())
    ranges = []
    for key, category in (('kernel', 1), ('user_elf', 2)):
        elf = Elf(manifest[key])
        for s in elf.sections:
            if s['flags'] & 4 and s['size']:
                lo = s['addr'] & MASK48
                ranges.append((lo, lo+s['size'], category))
    ranges.sort()
    starts = [r[0] for r in ranges]
    with (Path(manifest['package']) / 'native.bin').open('rb') as stream:
        header = struct.unpack('<10Q', stream.read(80))
    veneer_lo, veneer_hi = header[7], header[7] + 16*header[8]

    def category(pc):
        if veneer_lo <= pc < veneer_hi:
            return 0
        i = bisect.bisect_right(starts, pc)-1
        return ranges[i][2] if i >= 0 and pc < ranges[i][1] else 0

    out.mkdir(parents=True, exist_ok=False)
    # Reuse immutable payloads and their objects. Only the generated assembly is rebuilt.
    for path in image.iterdir():
        if path.name not in ('program.S', 'program-asm.o', 'checkpoint', 'checkpoint.map', 'pretranslated-elf.json'):
            (out / path.name).symlink_to(path)
    serial = 0
    def marker(stream, flags):
        nonlocal serial
        stream.write('%s%x_%x:\n' % (MARKER, flags, serial))
        serial += 1

    pc, cat, section_depth, atomic_next = None, 0, 0, False
    prefix = []
    counts = {'source_markers': 0, 'payload_markers': 0}
    with (image / 'program.S').open() as src, (out / 'program.S').open('w') as dst:
        for line in src:
            text = line.strip()
            if text.startswith('.pushsection'):
                section_depth += 1
            elif text == '.popsection':
                section_depth -= 1
            elif text.startswith('.section') or text == '.rodata':
                pc = None
            match = re.fullmatch(r'(?:\.Lp([0-9a-f]+)|\.Lclone[0-9a-f]+_p([0-9a-f]+)):', text) if not section_depth else None
            if match:
                pc = int(match[1] or match[2], 16); cat = category(pc); prefix = []; atomic_next = False
                dst.write(line)
                marker(dst, (4 if cat == 1 else 8 if cat == 2 else 16))
                counts['source_markers'] += 1
                continue
            if pc is not None and not section_depth:
                grouped=re.fullmatch(r'\.Lsg([0-9a-f]+)_op([0-9a-f]+):',text)
                if grouped:
                    if int(grouped[1],16)!=pc:raise ValueError('system group/source mismatch')
                    dst.write(line)
                    if int(grouped[2],16)!=pc:
                        marker(dst,4 if cat==1 else 8 if cat==2 else 16)
                        counts['source_markers']+=1
                    atomic_next=False
                    continue
                atomic = re.fullmatch(r'\.Lhw([0-9a-f]+)_insn([0-9a-f]+):|\.La([0-9a-f]+):', text)
                if atomic:
                    here = int(atomic[2] or atomic[3], 16)
                    if atomic[1] and int(atomic[1], 16) != pc:
                        raise ValueError('exclusive group/source mismatch')
                    dst.write(line)
                    if here != pc:
                        marker(dst, 4 if cat == 1 else 8 if cat == 2 else 16)
                        counts['source_markers'] += 1
                    atomic_next = True
                    continue
                # First group instruction is counted at .Lp. Reject internal back edges
                # that would require a separate first-body source-visit counter.
                if re.search(r'\s\.L(?:hw%x_insn%x|a%x)\s*$' % (pc, pc, pc), text):
                    raise ValueError('back edge to first exclusive instruction at %x' % pc)
                instruction = bool(text and not text.startswith(('.', '#')) and not text.endswith(':')) or text.startswith('.inst ')
                if instruction:
                    source_target=r'\.L(?:p[0-9a-f]+|clone[0-9a-f]+_p[0-9a-f]+)'
                    link_constant=(1<=len(prefix)<=4 and re.match(r'mov[zn] x30,',prefix[0]) and
                                   all(re.match(r'movk x30,',x) for x in prefix[1:]))
                    direct = re.fullmatch(r'b '+source_target,text) and (not prefix or link_constant)
                    conditional=(not prefix and re.fullmatch(
                        r'(?:b\.[a-z]{2} |(?:cbz|cbnz) [xw](?:[0-9]+|zr),|(?:tbz|tbnz) [xw](?:[0-9]+|zr),#[0-9]+,)'+source_target,text))
                    payload = text.startswith('.inst ') or atomic_next or direct or conditional
                    if payload and cat:
                        marker(dst, cat); counts['payload_markers'] += 1
                    atomic_next = False
                    # Only the first four instructions matter to direct B/BL recognition.
                    if len(prefix) < 5:
                        prefix.append(text)
            dst.write(line)
    report = dict(original_image=str(image), assembly_markers=counts,
                  source_categories='kernel/user executable sections; captured lowering veneers are synthetic')
    (out / 'annotation.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def segments(data):
    at, = struct.unpack_from('<Q', data, 32)
    size, count = struct.unpack_from('<HH', data, 54)
    return [struct.unpack_from('<II6Q', data, at+i*size) for i in range(count)]


def symbols(data):
    """Stream ELF symbols instead of allocating dictionaries for millions of labels."""
    at, = struct.unpack_from('<Q', data, 40)
    size, count = struct.unpack_from('<HH', data, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, at+i*size) for i in range(count)]
    for s in sections:
        if s[1] != 2:
            continue
        strings = sections[s[6]][4]
        for offset in range(s[4], s[4]+s[5], s[9]):
            name, info, other, section, value, length = struct.unpack_from('<IBBHQQ', data, offset)
            start = strings+name
            yield data[start:data.index(b'\0', start)].decode(), value


def make_map(image, annotated, out, llvm):
    image, annotated, out = (Path(p).resolve() for p in (image, annotated, out))
    original = (image / 'checkpoint').read_bytes()
    marked = (annotated / 'checkpoint').read_bytes()
    original_segments, marked_segments = segments(original), segments(marked)
    if original_segments != marked_segments:
        raise ValueError('annotated ELF changed program headers')
    hashes = []
    for kind, flags, offset, va, pa, filesz, memsz, align in original_segments:
        if kind != 1:
            continue
        a, b = original[offset:offset+filesz], marked[offset:offset+filesz]
        if offset == 0:
            # ELF program/section-table coordinates change with added symbols
            # and with the post-link program-header table appended at EOF.
            # These bytes are never used for the PC map, and we run the ORIGINAL ELF.
            b = bytearray(b)
            b[32:40] = a[32:40]
            b[40:48] = a[40:48]; b[60:64] = a[60:64]
        if a != b:
            raise ValueError('annotated ELF changed loaded code/data at %x' % va)
        hashes.append(dict(address=hex(va), file_bytes=filesz, memory_bytes=memsz, sha256=digest(a)))
    rows, syms = {}, {}
    for name, value in symbols(marked):
        if name.startswith(MARKER):
            flags = int(name[len(MARKER):].split('_')[0], 16)
            old = rows.get(value, 0)
            if old & 3 and flags & 3 and old & 3 != flags & 3:
                raise ValueError('conflicting payload provenance')
            rows[value] = old | flags
        elif name in ('_start', 'flat_run', 'flat_main', 'flat_completed', 'flat_memory_profile'):
            syms[name] = value
    disassembly = subprocess.check_output([str(Path(llvm) / 'llvm-objdump'), '-d', '--no-show-raw-insn',
                                          '--disassemble-symbols=flat_main', str(image / 'checkpoint')], text=True)
    calls = re.findall(r'^\s*([0-9a-f]+):\s+bl\s+0x[0-9a-f]+ <flat_run>', disassembly, re.M)
    if len(calls) != 1:
        raise ValueError('expected exactly one flat_run call')
    boundaries = dict(start=syms['_start'], begin=syms['flat_run'],
                      end=int(calls[0], 16)+4, stop=syms['flat_completed'])
    out.mkdir(parents=True, exist_ok=False)
    with (out / 'pc-map.bin').open('wb') as stream:
        for row in sorted(rows.items()):
            stream.write(struct.pack('<2Q', *row))
    report = dict(image=str(image), image_sha256=digest(original), annotated_sha256=digest(marked),
                  loaded_code_data_identical=True, load_segments=hashes, pc_map_entries=len(rows),
                  pc_map_sha256=digest((out/'pc-map.bin').read_bytes()), boundaries=boundaries,
                  guest_profile_enabled='flat_memory_profile' in syms,
                  identity_note='Only ELF program/section-table header coordinates may differ; measurement executes the original ELF.')
    (out / 'profile-plan.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def report(profile, validation, counters):
    profile = Path(profile).resolve()
    plan = json.loads((profile/'profile-plan.json').read_text())
    checked = json.loads(Path(validation).read_text())
    raw = struct.unpack('<20Q', Path(counters).read_bytes())
    if raw[:5] != (0x3150434952534f, 1, 1, 1, 1) or raw[5] != 0:
        raise ValueError('invalid counts/window boundaries (completion is stopped before execution)')
    if not checked['verified'] or checked['image_sha256'] != plan['image_sha256']:
        raise ValueError('measurement did not validate the intended image')
    result = dict(format='osrec-dynamic-instruction-profile-v1', image_sha256=plan['image_sha256'],
                  verified=True, guest_profile_enabled=plan['guest_profile_enabled'],
                  runtime_validation=checked.get('runtime_validation',True),
                  trust_syscall_abi=checked.get('trust_syscall_abi',False),
                  verification_scope=checked.get('verification_scope','workload-results'),
                  model='QEMU TCG Cortex-A53, single vCPU, per-instruction execution callbacks',
                  denominator_note='Source visits include emulated operations; native payload excludes them. '
                  'Runtime includes inline guards, address translation, control adapters, gateways, emulation, and guest profiling when enabled. '
                  'Application instructions are excluded from runtime. These are instruction counts, not cycles.')
    for i, name in enumerate(('whole_elf', 'execution_interval')):
        counts = dict(zip(NAMES, raw[8+6*i:14+6*i]))
        counts['total_instructions'] = sum(counts[k] for k in NAMES[:3])
        counts['runtime_per_kernel_source_visit'] = counts['runtime_adapter']/counts['kernel_source_visits']
        counts['runtime_per_native_kernel_instruction'] = counts['runtime_adapter']/counts['native_kernel']
        result[name] = counts
    result['instruction_budget'] = assess_budget(result['execution_interval'])
    result['validation'] = dict(events=checked['result']['events'], counters=checked['result']['counters'],
                                uart_bytes=checked['result']['uart_bytes'], gateways=checked['result']['transitions'],
                                hardware_exceptions=checked['hardware_exceptions'])
    (profile/'counts.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


def run(profile, prepared, out, plugin, timeout=600, histogram=False):
    from el0_hardware_model import run as validate
    profile, plugin, out = (Path(p).resolve() for p in (profile, plugin, out))
    plan = json.loads((profile/'profile-plan.json').read_text())
    pcmap = profile/'pc-map.bin'
    if digest(pcmap.read_bytes()) != plan['pc_map_sha256']:
        raise ValueError('PC provenance map changed')
    counters = profile/'instruction-counts.bin'
    arguments = ','.join([str(plugin), 'map='+str(pcmap), 'out='+str(counters)] +
                         [key+'='+hex(value) for key, value in plan['boundaries'].items()])
    if histogram:
        executable = [s for s in segments((Path(plan['image'])/'checkpoint').read_bytes()) if s[0] == 1 and s[1] & 1]
        if len(executable) != 1:
            raise ValueError('histogram requires one executable segment')
        arguments += ',hist='+str(profile/'histogram.bin')+',text='+hex(executable[0][3])+',bytes='+hex(executable[0][5])
    checked = validate(plan['image'], prepared, out, timeout, plugin=arguments)
    if not checked['verified']:
        raise ValueError('instruction-profile workload did not validate')
    result = report(profile, out/'validation.json', counters)
    result['plugin_sha256'] = digest(plugin.read_bytes())
    result['qemu_version'] = subprocess.check_output(['qemu-system-aarch64', '--version'], text=True).splitlines()[0]
    (profile/'counts.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    a = sub.add_parser('annotate'); a.add_argument('--image', required=True); a.add_argument('--out', required=True)
    m = sub.add_parser('map'); m.add_argument('--image', required=True); m.add_argument('--annotated', required=True); m.add_argument('--out', required=True)
    m.add_argument('--llvm', default='/opt/homebrew/opt/llvm@16/bin')
    r = sub.add_parser('report'); r.add_argument('--profile', required=True); r.add_argument('--validation', required=True); r.add_argument('--counters', required=True)
    v = sub.add_parser('run'); v.add_argument('--profile', required=True); v.add_argument('--prepared', required=True); v.add_argument('--out', required=True)
    v.add_argument('--plugin', required=True); v.add_argument('--timeout', type=int, default=600)
    v.add_argument('--histogram', action='store_true', help='also count every executed PC inside the execution interval')
    b = sub.add_parser('check-budget'); b.add_argument('--profile', required=True)
    args = vars(parser.parse_args()); command = args.pop('command')
    result = {'annotate': annotate, 'map': make_map, 'report': report, 'run': run, 'check-budget': check_budget}[command](**args)
    print(json.dumps(result, indent=2))
    if command == 'check-budget' and not result['maximum_met']:
        raise SystemExit(1)
