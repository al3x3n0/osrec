"""AOT rewrite of proven single-target integer loads to compact ELF backing.

The load destination is dead on entry, so it can materialize its own address.
No guest stack spill, live register reservation, lookup, or flag change is needed.
Proofs are supplied by the existing finite-set analysis and return contract.
"""
from el0_flat_lower import MEMORY, LOAD, PAIR, WB, USER, EXCLUSIVE, HINT


def compact_load_proof(op, proof, ram_base, ram_bytes):
    if (op.kind != MEMORY or op.length != 1 or not op.info & LOAD or
            op.info & (PAIR | WB | USER | EXCLUSIVE | HINT) or
            op.word & (1 << 26) or op.word & 31 == 31):
        return None
    targets = proof.get('physical', [])
    size = 1 << (op.info >> 15 & 7)
    if len(targets) != 1 or proof.get('bytes') != size:
        return None
    pa = targets[0]
    if pa < ram_base or size > ram_bytes or pa-ram_base > ram_bytes-size:
        return None
    return dict(word=op.word, native=op.native, physical=pa,
                offset=pa-ram_base, bytes=size, addresses=proof['addresses'])


def compact_load_path(proof, following):
    destination = proof['word'] & 31
    target = 'flat_phys+0x%x' % proof['offset']
    word = (proof['native'] & ~(31 << 5)) | (destination << 5)
    return ('    adrp x%d,%s\n    add x%d,x%d,:lo12:%s\n'
            '    .inst 0x%08x\n    b %s\n' %
            (destination, target, destination, destination, target, word, following))


def verify_compiled(image):
    """Rebuild address proofs and decode linked ADRP/ADD/load operands."""
    import hashlib
    import json
    import struct
    from pathlib import Path
    from export_el0_program import Package
    from kernel_source_verify import Elf
    from source_image_el0 import instruction_ranges
    from el0_pretranslate import user_aliases, user_proofs
    from el0_flat_lower import decode, sign
    from el0_control import layout, gateway_sizes
    image=Path(image)
    manifest=json.loads((image/'manifest.json').read_text())
    if not (manifest['runtime_validation'] or manifest['trust_syscall_abi']):
        raise ValueError('compact load proofs require a return preservation contract')
    package=Package(Path(manifest['package']));user=Elf(manifest['user_elf'])
    if hashlib.sha256(package.data).hexdigest()!=manifest['native_state_sha256']:
        raise ValueError('captured state identity mismatch')
    if hashlib.sha256(user.data).hexdigest()!=json.loads((package.path/'manifest.json').read_text())['application']['user_elf_sha256']:
        raise ValueError('user ELF identity mismatch')
    words={};metadata={}
    ranges=instruction_ranges(user,[(s['addr'],s['addr']+s['size']) for s in user.sections if s['flags']&4 and s['size']])
    for lo,hi in ranges:
        for pc in range(lo,hi,4):
            word=package.word(pc)
            if word==0xd421e000 and pc in package.sites:word,metadata[pc]=package.sites[pc]
            words[pc]=word
    immutable=set()
    for s in user.sections:
        if s['flags']&2 and not s['flags']&1 and s['size']:
            immutable.update(package.pa(va)&-4096 for va in range(s['addr']&-4096,(s['addr']+s['size']+4095)&-4096,4096))
    mapping=json.loads((image/'hardware-memory.json').read_text())
    spans=[(pa,4096) for pa in sorted(immutable)]+[(pa,4096) for pa in mapping['pretranslated_memory'].get('watched_pages',[])]
    proofs=user_proofs(words,struct.unpack_from('<34Q',package.data,80),package,user_aliases(package),spans,with_addresses=True)
    expected={}
    for pc,proof in proofs.items():
        row=compact_load_proof(decode(words[pc]),proof,package.h[2],package.h[3])
        if row and not metadata.get(pc,0):expected[pc]=dict(pc=pc,**row)
    package.memory.close();package.file.close()
    report=json.loads((image/'compact-loads.json').read_text())
    if report['sites']!=[expected[pc] for pc in sorted(expected)]:
        raise ValueError('compact load records differ from reconstructed proofs')
    labels,_,size=layout(image/'program.S',gateway_sizes(Path(__file__).resolve().parents[1]/'runtime/el0_flat/gateway.inc'))
    bases=[]
    for line in (image/'checkpoint.map').read_text().splitlines():
        if line.rstrip().endswith('program-asm.o:(.text)'):
            fields=line.split()
            if int(fields[2],16)!=size:raise ValueError('generated text layout mismatch')
            bases.append(int(fields[0],16))
    if len(bases)!=1:raise ValueError('missing or ambiguous generated text')
    elf=Elf(image/'checkpoint');symbols={s['name']:s['value'] for s in elf.symbols if s['shndx']}
    for pc,row in expected.items():
        at=bases[0]+labels['.Lp%x'%pc]
        adrp,add,load=struct.unpack('<3I',elf.read(at,12));rd=row['word']&31
        if adrp&0x9f00001f != 0x90000000|rd or add&0xffc003ff != 0x91000000|(rd<<5)|rd:
            raise ValueError('compact address instructions clobber unexpected state')
        displacement=sign((adrp>>29&3)|((adrp>>5&0x7ffff)<<2),21)<<12
        target=(at&-4096)+displacement+(add>>10&4095)
        if target!=symbols['flat_phys']+row['offset'] or load!=(row['native']&~(31<<5))|(rd<<5):
            raise ValueError('linked compact memory operand differs from proof')
    result=dict(sites=len(expected),image_sha256=hashlib.sha256(elf.data).hexdigest(),
                source_proofs_reconstructed=True,linked_operands_verified=True,complete_static_relocation=False)
    (image/'compact-loads-compiled.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    import argparse,json
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True)
    print(json.dumps(verify_compiled(parser.parse_args().image),indent=2))
