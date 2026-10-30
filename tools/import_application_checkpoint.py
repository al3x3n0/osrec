#!/usr/bin/env python3
"""Import an explicit AArch64 application checkpoint and patch its recorded SVC sites.

No section tables, symbols, target addresses or kernel syscall numbers are inferred.
The output C embeds all initial memory; the guest never opens the supplied ELF.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

FORMAT = 'osrec-aarch64-application-checkpoint-v1'
ROUTE = 0xd4200000 | (0x5353 << 5)
EXIT = 0xd4200000 | (0x5354 << 5)
LIMIT = 16 * 1024 * 1024

def digest(data):
    return hashlib.sha256(data).hexdigest()

def integer(value, name, bits=64):
    if isinstance(value, str):
        try: value = int(value, 0)
        except ValueError: raise ValueError('invalid ' + name) from None
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError('invalid ' + name)
    return value

def bounds(address, size):
    return size > 0 and address > 0 and address + size <= (1 << 64) - 1

def overlaps(a, an, b, bn):
    return a < b + bn and b < a + an

def elf_layout(raw):
    if len(raw) < 64 or raw[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('expected little-endian AArch64 ELF64')
    kind, machine, version = struct.unpack_from('<HHI', raw, 16)
    entry, phoff = struct.unpack_from('<QQ', raw, 24)
    ehsize, phsize, phcount = struct.unpack_from('<HHH', raw, 52)
    if (kind, machine, version, ehsize, phsize) != (2, 183, 1, 64, 56) or not 0 < phcount <= 4096:
        raise ValueError('expected static AArch64 ET_EXEC with ordinary program headers')
    if phoff < 64 or phoff + phsize * phcount > len(raw):
        raise ValueError('invalid ELF program header table')
    segments = []
    for i in range(phcount):
        typ, flags, off, va, pa, files, mem, align = struct.unpack_from('<IIQQQQQQ', raw, phoff + i * phsize)
        if typ in (2, 3): raise ValueError('dynamic application loading is unsupported')
        if typ != 1: continue
        if not bounds(va, mem) or files > mem or off > len(raw) or files > len(raw) - off or va != pa:
            raise ValueError('invalid or nonidentity ELF load segment')
        if flags & ~7 or not flags & 4 or flags & 3 == 3:
            raise ValueError('segments must be readable and may not be writable executable')
        if align not in (0, 1) and (align & (align - 1) or va % align != off % align):
            raise ValueError('invalid ELF segment alignment')
        if flags & 1 and (va & 3 or files & 3):
            raise ValueError('executable segment requires instruction alignment')
        if any(overlaps(va, mem, s['address'], s['memory_bytes']) for s in segments):
            raise ValueError('overlapping ELF load segments')
        if files and any(s['file_bytes'] and overlaps(off, files, s['file_offset'], s['file_bytes']) for s in segments):
            raise ValueError('overlapping ELF file ranges are unsupported')
        segments.append(dict(address=va, file_offset=off, file_bytes=files, memory_bytes=mem, flags=flags))
    if not segments or sum(s['memory_bytes'] for s in segments) > LIMIT:
        raise ValueError('application memory exceeds bounded importer limit')
    def instruction(pc):
        return pc % 4 == 0 and any(s['flags'] & 1 and s['address'] <= pc and pc + 4 <= s['address'] + s['file_bytes'] for s in segments)
    if not instruction(entry): raise ValueError('ELF entry is outside file-backed executable bytes')
    return dict(entry=entry, load_segments=segments)

def frame_image(frame, entry):
    if not isinstance(frame, dict): raise ValueError('missing saved CPU frame')
    out = {}
    for key in ('sp', 'pc', 'pstate', 'tpidr_el0', 'tpidrro_el0', 'fpcr', 'fpsr'):
        value = frame.get(key, entry if key == 'pc' else 0x3c0 if key == 'pstate' else 0)
        out[key] = integer(value, key, 32 if key in ('fpcr', 'fpsr') else 64)
    out['x'] = frame.get('x', [0] * 31)
    if not isinstance(out['x'], list) or len(out['x']) != 31: raise ValueError('frame needs 31 GPRs')
    out['x'] = [integer(v, 'GPR') for v in out['x']]
    vectors = frame.get('v', [[0, 0] for _ in range(32)])
    if not isinstance(vectors, list) or len(vectors) != 32 or any(not isinstance(v, list) or len(v) != 2 for v in vectors):
        raise ValueError('frame needs 32 SIMD lane pairs')
    out['v'] = [[integer(v, 'SIMD lane') for v in pair] for pair in vectors]
    if out['pstate'] & ~0xf00003c0 or out['pstate'] & 0x3c0 != 0x3c0 or out['sp'] < 16 or out['sp'] & 15:
        raise ValueError('frame requires masked EL0t and aligned SP')
    return out

def plan(raw, checkpoint, ram, reserved=()):
    if checkpoint.get('format') != FORMAT or checkpoint.get('elf_sha256') != digest(raw):
        raise ValueError('checkpoint format or ELF identity mismatch')
    layout = elf_layout(raw)
    loads = []
    for s in layout['load_segments']:
        data = raw[s['file_offset']:s['file_offset'] + s['file_bytes']] + bytes(s['memory_bytes'] - s['file_bytes'])
        loads.append({**s, 'original': data, 'data': bytearray(data)})
    for extra in checkpoint.get('extra_memory', []):
        a, n = integer(extra['address'], 'memory address'), integer(extra['bytes'], 'memory size')
        perms = integer(extra['permissions'], 'memory permissions', 32)
        if not bounds(a, n) or perms not in (1, 3) or n > LIMIT or sum(s['memory_bytes'] for s in loads) + n > LIMIT:
            raise ValueError('invalid additional checkpoint memory')
        if any(overlaps(a, n, s['address'], s['memory_bytes']) for s in loads): raise ValueError('overlapping checkpoint memory')
        loads.append(dict(address=a, file_bytes=0, memory_bytes=n, flags=4 | (2 if perms == 3 else 0), original=bytes(n), data=bytearray(n)))
    def owner(address, count, executable=False):
        return next((s for s in loads if s['address'] <= address and address + count <= s['address'] + (s['file_bytes'] if executable else s['memory_bytes']) and (not executable or s['flags'] & 1)), None)
    for s in loads:
        if not any(a <= s['address'] and s['address'] + s['memory_bytes'] <= a + n for a, n in ram):
            raise ValueError('checkpoint memory is outside supplied RAM banks')
        if any(overlaps(s['address'], s['memory_bytes'], a, n) for a, n in reserved):
            raise ValueError('checkpoint memory overlaps reserved container memory')
    snapshots = []
    for snap in checkpoint.get('snapshots', []):
        a = integer(snap['address'], 'snapshot address')
        try: data = bytes.fromhex(snap['data'])
        except (TypeError, ValueError): raise ValueError('invalid snapshot bytes') from None
        s = owner(a, len(data))
        if not data or not s or s['flags'] & 1 or any(overlaps(a, len(data), b, n) for b, n in snapshots):
            raise ValueError('snapshot overlaps code, another snapshot or unmapped memory')
        s['data'][a - s['address']:a - s['address'] + len(data)] = data
        snapshots.append((a, len(data)))
    calls = checkpoint.get('calls')
    if not isinstance(calls, list) or not 0 < len(calls) <= 65536: raise ValueError('missing ordered syscall sites')
    first = integer(checkpoint.get('first_ordinal', 0), 'first ordinal')
    if first + len(calls) >= 1 << 64: raise ValueError('ordinal overflow')
    patches, sites = {}, []
    def patch(pc, replacement, kind, expected=None):
        s = owner(pc, 4, True)
        if pc & 3 or not s: raise ValueError('patch is outside file-backed executable bytes')
        offset = pc - s['address']; original = bytes(s['original'][offset:offset + 4])
        file_offset = s['file_offset'] + offset
        phoff = struct.unpack_from('<Q',raw,32)[0]; phcount = struct.unpack_from('<H',raw,56)[0]
        if overlaps(file_offset,4,0,64) or overlaps(file_offset,4,phoff,56*phcount):
            raise ValueError('patch overlaps ELF loading metadata')
        if expected is not None and original != expected: raise ValueError('exit instruction identity mismatch')
        if kind == 'syscall' and struct.unpack('<I', original)[0] & 0xffe0001f != 0xd4000001:
            raise ValueError('declared syscall site is not SVC')
        if pc in patches:
            if patches[pc]['kind'] != kind: raise ValueError('conflicting patch roles')
            return
        patches[pc] = dict(address=pc, original=original.hex(), replacement=struct.pack('<I', replacement).hex(), kind=kind)
        s['data'][offset:offset + 4] = struct.pack('<I', replacement)
    for i, call in enumerate(calls):
        pc = integer(call['pc'], 'syscall PC')
        if not owner(pc + 4, 4, True): raise ValueError('syscall continuation is outside executable bytes')
        patch(pc, ROUTE, 'syscall')
        sites.append(dict(ordinal=first + i, svc_pc=pc, continuation_pc=pc + 4))
    completed_sites = []
    if 'completed_calls' in checkpoint:
        completed = checkpoint['completed_calls']
        if not isinstance(completed, list) or len(completed) != first or first > 65536:
            raise ValueError('completed syscall history must match the first ordinal')
        for ordinal, call in enumerate(completed):
            if not isinstance(call, dict): raise ValueError('invalid completed syscall site')
            pc = integer(call.get('pc'), 'completed syscall PC')
            if not owner(pc + 4, 4, True): raise ValueError('completed syscall continuation is outside executable bytes')
            # Historical sites stay patched, but never enter the active table.
            # A branch back to a prefix-only PC is rejected by the gateway.
            patch(pc, ROUTE, 'syscall')
            completed_sites.append(dict(ordinal=ordinal, svc_pc=pc, continuation_pc=pc + 4))
    exit_site = checkpoint.get('exit', {})
    exit_pc = integer(exit_site.get('pc'), 'exit PC')
    try: expected = bytes.fromhex(exit_site['original'])
    except (KeyError, TypeError, ValueError): raise ValueError('exit needs explicit original instruction bytes') from None
    if len(expected) != 4: raise ValueError('exit needs four original bytes')
    patch(exit_pc, EXIT, 'exit', expected)
    # Conservative word scan; instruction/data ambiguity is rejected, not guessed.
    for s in loads:
        if not s['flags'] & 1: continue
        for off in range(0, s['file_bytes'], 4):
            w = struct.unpack_from('<I', s['original'], off)[0]; pc = s['address'] + off
            if w & 0xffe0001f == 0xd4000001 and pc not in patches: raise ValueError('unrouted SVC candidate in executable segment')
            if w & 0xffe0001f in (0xd4200000, 0xd4400000, 0xd4000002, 0xd4000003):
                raise ValueError('unreviewed service/trap candidate in executable segment')
    frame = frame_image(checkpoint.get('frame'), layout['entry'])
    if frame['pc'] & 3 or not owner(frame['pc'], 4, True): raise ValueError('saved PC is outside executable bytes')
    stack = owner(frame['sp'] - 16, 16)
    if not stack or not stack['flags'] & 2: raise ValueError('saved stack is outside writable checkpoint memory')
    objects, ids = [], set()
    for obj in checkpoint.get('objects', []):
        a, n, ident = integer(obj['address'], 'object address'), integer(obj['bytes'], 'object size'), integer(obj['id'], 'object id', 32)
        if not bounds(a, n) or not ident or ident in ids or not owner(a, n) or any(overlaps(a, n, b['address'], b['bytes']) for b in objects):
            raise ValueError('invalid or overlapping named memory object')
        ids.add(ident); objects.append(dict(address=a, bytes=n, id=ident))
    regions = []; next_id = 1
    for index, s in enumerate(loads):
        cuts = sorted((o for o in objects if s['address'] <= o['address'] < s['address'] + s['memory_bytes']), key=lambda o: o['address'])
        cursor = s['address']; parts = []
        for o in cuts:
            if cursor < o['address']: parts.append(dict(address=cursor, bytes=o['address'] - cursor))
            parts.append(o); cursor = o['address'] + o['bytes']
        if cursor < s['address'] + s['memory_bytes']: parts.append(dict(address=cursor, bytes=s['address'] + s['memory_bytes'] - cursor))
        for p in parts:
            if 'id' not in p:
                while next_id in ids: next_id += 1
                p['id'] = next_id; ids.add(next_id)
            regions.append({**p, 'permissions': 3 if s['flags'] & 2 else 1, 'load': index, 'original_view': bool(s['flags'] & 1)})
    if len(regions) > 4096: raise ValueError('too many memory regions')
    assertions = []
    for item in checkpoint.get('assertions', []):
        a = integer(item['address'], 'assertion address')
        try: data = bytes.fromhex(item['data'])
        except (TypeError, ValueError): raise ValueError('invalid assertion bytes') from None
        if not data or not owner(a, len(data)): raise ValueError('assertion is outside checkpoint memory')
        assertions.append(dict(address=a, data=data.hex()))
    result = dict(layout=layout, loads=loads, sites=sites, patches=sorted(patches.values(), key=lambda p: p['address']), frame=frame, regions=regions, exit_pc=exit_pc, snapshot_count=len(snapshots), assertions=assertions)
    if 'completed_calls' in checkpoint: result['completed_sites'] = completed_sites
    return result

def c_bytes(name, data):
    return 'static const unsigned char ' + name + '[]={\n' + '\n'.join(','.join(str(b) for b in data[i:i+32])+',' for i in range(0, len(data), 32)) + '\n};\n'

def generate(p, windows=False):
    text = '#include "application_checkpoint.h"\n'
    for i, s in enumerate(p['loads']):
        text += c_bytes('load_' + str(i), s['data'])
        if s['flags'] & 1: text += c_bytes('original_' + str(i), s['original'])
    f = p['frame']
    u = lambda v: 'UINT64_C(' + str(v) + ')'
    text += 'static const struct osrec_aarch64_frame initial={.x={' + ','.join(map(u, f['x'])) + '},.v={' + ','.join('{'+','.join(map(u, v))+'}' for v in f['v']) + '},' + ','.join('.'+k+'='+u(f[k]) for k in ('sp','pc','pstate','fpcr','fpsr','tpidr_el0','tpidrro_el0')) + '};\n'
    text += 'static const struct osrec_user_region regions[]={\n'
    for r in p['regions']:
        pointer = '((unsigned char *)original_' + str(r['load']) + '+' + str(r['address']-p['loads'][r['load']]['address']) + ')' if r['original_view'] else '(unsigned char *)(uintptr_t)' + u(r['address'])
        text += '{'+u(r['address'])+','+pointer+','+str(r['bytes'])+','+str(r['permissions'])+','+str(r['id'])+'},\n'
    text += '};\nstatic const struct osrec_aarch64_site sites[]={\n'
    for s in p['sites']: text += '{'+','.join(u(s[k]) for k in ('ordinal','svc_pc','continuation_pc'))+',{regions,sizeof(regions)/sizeof(regions[0])}},\n'
    text += '};\nstatic const struct osrec_user_region executable[]={\n'
    for i, s in enumerate(p['loads']):
        if s['flags'] & 1: text += '{'+u(s['address'])+',(unsigned char *)(uintptr_t)'+u(s['address'])+','+str(s['file_bytes'])+',1,'+str(i+1)+'},\n'
    text += '};\nvoid osrec_import_restore(struct osrec_aarch64_frame *f){\n'
    for i, s in enumerate(p['loads']): text += '{unsigned char *out=(unsigned char *)(uintptr_t)'+u(s['address'])+';for(size_t j=0;j<sizeof(load_'+str(i)+');++j)out[j]=load_'+str(i)+'[j];}\n'
    text += '*f=initial;__asm__ volatile("dsb sy\\nisb":::"memory");}\n'
    text += 'void osrec_import_bind(struct osrec_aarch64_gateway *g,struct osrec_slice_session *s,const struct osrec_aarch64_syscall_abi *abi,struct osrec_aarch64_frame *f,unsigned char *stack,size_t bytes){\n*g=(struct osrec_aarch64_gateway){.abi=OSREC_AARCH64_GATEWAY_ABI,.session=s,.registers=abi,.application=f,.sites=sites,.site_count=sizeof(sites)/sizeof(sites[0]),.exit_pc='+u(p['exit_pc'])+',.stack=stack,.stack_bytes=bytes,.executables=executable,.executable_count=sizeof(executable)/sizeof(executable[0])};}\n'
    if windows:
        text += '''uint32_t osrec_import_bind_window(struct osrec_aarch64_gateway *g,struct osrec_slice_session *s,const struct osrec_aarch64_syscall_abi *abi,struct osrec_aarch64_frame *f,unsigned char *stack,size_t bytes,size_t first,size_t count){
const size_t total=sizeof(sites)/sizeof(sites[0]);
if(!g || !s || !f || !abi || !stack || !count || first>=total || count>total-first || s->initialized!=1 || s->next!=sites[first].ordinal || (first && f->pc!=sites[first].svc_pc))return OSREC_SLICE_BAD_INPUT;
if(g->active || s->active)return OSREC_SLICE_BUSY;
osrec_import_bind(g,s,abi,f,stack,bytes);g->sites=sites+first;g->site_count=count;
if(first+count<total)g->exit_pc=sites[first+count].svc_pc;
return OSREC_SLICE_OK;}
'''
    for i, a in enumerate(p['assertions']): text += c_bytes('assertion_'+str(i), bytes.fromhex(a['data']))
    text += 'uint32_t osrec_import_check(void){\n'
    for i, a in enumerate(p['assertions']): text += '{const unsigned char *p=(const unsigned char *)(uintptr_t)'+u(a['address'])+';for(size_t j=0;j<sizeof(assertion_'+str(i)+');++j)if(p[j]!=assertion_'+str(i)+'[j])return 1;}\n'
    text += 'return 0;}\n'
    text += 'uint32_t osrec_import_check_initial(void){\n'
    for i, s in enumerate(p['loads']): text += '{const unsigned char *p=(const unsigned char *)(uintptr_t)'+u(s['address'])+';for(size_t j=0;j<sizeof(load_'+str(i)+');++j)if(p[j]!=load_'+str(i)+'[j])return 1;}\n'
    text += 'return 0;}\n'
    return text

def import_checkpoint(elf, checkpoint, out, ram=((0x40000000, 64*1024*1024),), reserved=()):
    elf, checkpoint, out = Path(elf), Path(checkpoint), Path(out)
    if out.exists(): raise FileExistsError(out)
    raw, document = elf.read_bytes(), json.loads(checkpoint.read_text())
    p = plan(raw, document, ram, reserved)
    patched = bytearray(raw)
    for patch in p['patches']:
        segment = next(s for s in p['layout']['load_segments'] if s['address'] <= patch['address'] < s['address'] + s['file_bytes'])
        off = segment['file_offset'] + patch['address'] - segment['address']
        patched[off:off+4] = bytes.fromhex(patch['replacement'])
    out.mkdir(parents=True)
    (out/'original.elf').write_bytes(raw); (out/'patched.elf').write_bytes(patched)
    (out/'checkpoint.json').write_bytes(checkpoint.read_bytes())
    header = '#ifndef OSREC_APPLICATION_CHECKPOINT_H\n#define OSREC_APPLICATION_CHECKPOINT_H\n#include "osrec/aarch64_gateway.h"\nvoid osrec_import_restore(struct osrec_aarch64_frame *);\nuint32_t osrec_import_check(void);\nuint32_t osrec_import_check_initial(void);\nvoid osrec_import_bind(struct osrec_aarch64_gateway *,struct osrec_slice_session *,const struct osrec_aarch64_syscall_abi *,struct osrec_aarch64_frame *,unsigned char *,size_t);\n#endif\n'
    header=header.replace('#endif\n','uint32_t osrec_import_bind_window(struct osrec_aarch64_gateway *,struct osrec_slice_session *,const struct osrec_aarch64_syscall_abi *,struct osrec_aarch64_frame *,unsigned char *,size_t,size_t,size_t);\n#endif\n')
    (out/'application_checkpoint.h').write_text(header); (out/'application_checkpoint.c').write_text(generate(p,windows=True))
    loads = []
    for i, s in enumerate(p['loads']):
        filename = 'memory-' + str(i) + '.bin'; (out/filename).write_bytes(s['data'])
        loads.append({k:v for k,v in s.items() if k not in ('original','data')} | dict(file=filename, sha256=digest(s['data'])))
    manifest = dict(format='osrec-aarch64-application-routes-v1', elf_sha256=digest(raw), checkpoint_sha256=digest(checkpoint.read_bytes()), importer_sha256=digest(Path(__file__).read_bytes()), entry=p['layout']['entry'], frame=p['frame'], loads=loads, sites=p['sites'], patches=p['patches'], regions=p['regions'], exit_pc=p['exit_pc'], snapshot_count=p['snapshot_count'], assertions=p['assertions'], runtime_host_interaction=False, gateway_abi=2, mmu_enabled=False, ram=[dict(address=a,bytes=n) for a,n in ram], reserved=[dict(address=a,bytes=n) for a,n in reserved])
    manifest['window_bindings']=True
    if 'completed_sites' in p: manifest['completed_sites'] = p['completed_sites']
    manifest['artifact_hashes'] = {f.name:digest(f.read_bytes()) for f in out.iterdir() if f.is_file()}
    (out/'route-plan.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return manifest

def memory_range(text):
    a, n = text.split(':'); a, n = int(a, 0), int(n, 0)
    if not bounds(a, n): raise argparse.ArgumentTypeError('invalid address:bytes range')
    return a, n

def verify_package(directory):
    """Reconstruct routing metadata and generated code from the pinned ELF/checkpoint."""
    directory=Path(directory).resolve()
    route=json.loads((directory/'route-plan.json').read_text())
    if route.get('format')!='osrec-aarch64-application-routes-v1':raise ValueError('unsupported application route package')
    files={p.name:digest(p.read_bytes()) for p in directory.iterdir() if p.is_file() and p.name!='route-plan.json'}
    if files!=route['artifact_hashes']:raise ValueError('application artifact identity mismatch')
    raw=(directory/'original.elf').read_bytes();checkpoint=(directory/'checkpoint.json').read_bytes()
    if digest(raw)!=route['elf_sha256'] or digest(checkpoint)!=route['checkpoint_sha256']:raise ValueError('application checkpoint identity mismatch')
    ranges=lambda rows:[(integer(r['address'],'range address'),integer(r['bytes'],'range size')) for r in rows]
    p=plan(raw,json.loads(checkpoint),ranges(route['ram']),ranges(route['reserved']))
    expected=dict(entry=p['layout']['entry'],frame=p['frame'],sites=p['sites'],patches=p['patches'],regions=p['regions'],exit_pc=p['exit_pc'],snapshot_count=p['snapshot_count'],assertions=p['assertions'])
    if 'completed_sites' in p: expected['completed_sites'] = p['completed_sites']
    elif 'completed_sites' in route: raise ValueError('unrecorded completed syscall history')
    if any(route.get(k)!=v for k,v in expected.items()) or (directory/'application_checkpoint.c').read_text()!=generate(p,windows=route.get('window_bindings',False)):
        raise ValueError('application route package differs from the pinned checkpoint')
    if len(route['loads'])!=len(p['loads']):raise ValueError('application load count mismatch')
    for i,s in enumerate(p['loads']):
        load=route['loads'][i]
        if load.get('file')!='memory-'+str(i)+'.bin' or any(load.get(k)!=v for k,v in s.items() if k not in ('data','original')) or (directory/load['file']).read_bytes()!=s['data']:
            raise ValueError('application memory image differs from checkpoint')
    patched=bytearray(raw)
    for patch in p['patches']:
        s=next(s for s in p['layout']['load_segments'] if s['address']<=patch['address']<s['address']+s['file_bytes'])
        off=s['file_offset']+patch['address']-s['address'];patched[off:off+4]=bytes.fromhex(patch['replacement'])
    if (directory/'patched.elf').read_bytes()!=patched:raise ValueError('application patch image differs from recorded sites')
    return route

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True); parser.add_argument('--checkpoint', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True); parser.add_argument('--ram', type=memory_range, action='append')
    parser.add_argument('--reserved', type=memory_range, action='append', default=[])
    args = parser.parse_args()
    print(json.dumps(import_checkpoint(args.elf, args.checkpoint, args.out, args.ram or [(0x40000000,64*1024*1024)], args.reserved), indent=2))

if __name__ == '__main__': main()
