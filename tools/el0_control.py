"""Compact original conditional edges using a conservative same-section layout.

No execution profile selects a branch. All targets and conditions come from the
existing lowering. Removing long-form tails only shrinks distances in .text;
word alignment and strictly measured gateway macros preserve that bound.
"""
import hashlib
from pathlib import Path
import re

from el0_flat_lower import local_conditional

SOURCE=re.compile(r'\.L(?:p[0-9a-f]+|clone[0-9a-f]+_p[0-9a-f]+)')


def gateway_sizes(path):
    """Count fixed-width gateway code; reject unmodelled macro directives."""
    source=re.sub(r'/\*.*?\*/','',Path(path).read_text(),flags=re.S)
    names=set(re.findall(r'^\s*\.macro\s+([^\s,]+)',source,re.M))
    result={};name=None;depth=0;conditional=False;size=0
    for raw in source.splitlines():
        line=raw.strip()
        if not line:continue
        if line.startswith('.macro '):
            if name is not None:raise ValueError('nested gateway macro')
            name=line.split()[1].split(',')[0];size=0;depth=0;conditional=False
        elif line=='.endm':
            if name is None or depth or conditional:raise ValueError('unbalanced gateway macro')
            result[name]=size;name=None
        elif name is not None:
            if line.startswith('.pushsection '):depth+=1
            elif line=='.popsection':
                depth-=1
                if depth<0:raise ValueError('unbalanced gateway section')
            elif depth:continue
            elif line=='.if \\export':
                if conditional:raise ValueError('nested gateway condition')
                conditional=True
            elif line=='.endif':
                if not conditional:raise ValueError('unbalanced gateway condition')
                conditional=False
            elif line.startswith('.global '):continue
            elif conditional:raise ValueError('conditional gateway code has no fixed size')
            elif line.endswith(':') or line=='.balign 4':continue
            elif line.startswith('.') or line.split()[0] in names:
                raise ValueError('unsupported gateway layout: '+line)
            else:size+=4
    if name is not None:raise ValueError('unterminated gateway macro')
    return result


def inverted_condition(word):
    """Recognize only the exporter's inverse-condition, skip-one-long-B form."""
    if word&0xff000010==0x54000000 and word&15<14 and word>>5&0x7ffff==2:
        return word^1,19
    if word&0x7e000000 in (0x34000000,0x36000000):
        bits=14 if word&0x7e000000==0x36000000 else 19
        if word>>5&((1<<bits)-1)==2:return word^(1<<24),bits
    return None


def layout(path,macros):
    labels={};candidates=[];section=None;sections=[];offset=0;previous=None;source=None
    with Path(path).open() as stream:
        for number,raw in enumerate(stream):
            line=raw.strip();at=offset if section=='.text' else None
            if line.startswith('.pushsection '):
                sections.append(section);section=line.split()[1].split(',')[0]
            elif line=='.popsection':
                if not sections:raise ValueError('unbalanced assembly section')
                section=sections.pop()
            elif line.startswith('.section '):section=line.split()[1].split(',')[0]
            elif line in ('.text','.data','.rodata','.bss'):section=line
            elif section=='.text' and line:
                if line.endswith(':'):
                    label=line[:-1]
                    if label in labels:raise ValueError('duplicate text label: '+label)
                    labels[label]=offset
                    if SOURCE.fullmatch(label):source=label
                elif line.startswith('#') or line.startswith(('.global ','.type ','.size ','.arch ')):pass
                elif line.startswith('.balign '):
                    if line!='.balign 4':raise ValueError('control layout requires word alignment')
                elif line.startswith('.inst '):
                    if not re.fullmatch(r'\.inst 0x[0-9a-fA-F]{1,8}',line):raise ValueError('unsupported .inst layout')
                    offset+=4
                elif line.startswith('.word '):
                    if not re.fullmatch(r'\.word 0x[0-9a-fA-F]{1,8}',line):raise ValueError('unsupported literal pool layout')
                    offset+=4
                elif not line.startswith('.'):
                    parts=line.split();name=parts[0]
                    if name in macros:offset+=macros[name]
                    elif name.startswith('flat_') or '=' in line:
                        raise ValueError('unmodelled text expansion: '+line)
                    else:offset+=4
                    if name=='b' and len(parts)==2 and SOURCE.fullmatch(parts[1]) and previous:
                        prev_number,prev_line,prev_at=previous
                        if (prev_number==number-1 and prev_at is not None and at==prev_at+4 and
                            source is not None and labels[source]==prev_at and prev_line.startswith('.inst ')):
                            condition=inverted_condition(int(prev_line[6:],16))
                            if condition:
                                word,bits=condition
                                candidates.append(dict(line=prev_number,source=source,target=parts[1],
                                                       word=word,bits=bits,offset=prev_at))
                else:raise ValueError('unmodelled text directive: '+line)
            previous=number,line,at
    if sections:raise ValueError('unbalanced assembly sections')
    return labels,candidates,offset


def relax_branches(path,gateway):
    """Shorten only edges proved in range before any instructions are removed."""
    path=Path(path);macros=gateway_sizes(gateway)
    labels,candidates,size=layout(path,macros);selected=[];replacements={}
    for row in candidates:
        if row['target'] not in labels:continue
        delta=labels[row['target']]-row['offset'];limit=1<<(row['bits']+1)
        if delta%4 or not -limit<=delta<limit:continue
        row=dict(row,distance_bound=delta);selected.append(row)
        replacements[row['line']]=local_conditional(row['word'],row['target'])
    temporary=path.with_name(path.name+'.control-tmp')
    try:
        skip=False
        with path.open() as src,temporary.open('w') as dst:
            for number,line in enumerate(src):
                if skip:skip=False;continue
                if number in replacements:dst.write(replacements[number]);skip=True
                else:dst.write(line)
        new_labels,_,new_size=layout(temporary,macros)
        if new_size!=size-4*len(selected):raise ValueError('control layout size changed unexpectedly')
        for row in selected:
            delta=new_labels[row['target']]-new_labels[row['source']];limit=1<<(row['bits']+1)
            if delta%4 or not -limit<=delta<limit or abs(delta)>abs(row['distance_bound']):
                raise ValueError('short conditional exceeds its construction bound')
            row['native_offset']=new_labels[row['source']];row['native_target_offset']=new_labels[row['target']]
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return dict(format='osrec-compact-control-v1',rule='same .text section; fixed-width instructions; monotone distance bounds',
                candidates=len(candidates),shortened=len(selected),remaining_long=len(candidates)-len(selected),
                text_bytes_before=size,text_bytes_after=new_size,gateway_macro_bytes=macros,
                assembly_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),branches=selected)


def verify_branches(image,annotated):
    """Bind every shortened edge to compiler-emitted offsets and instruction bits."""
    import json
    import struct
    from el0_instruction_profile import MARKER,segments,symbols
    image,annotated=Path(image),Path(annotated)
    proof=json.loads((image/'control-lowering.json').read_text())
    if hashlib.sha256((image/'program.S').read_bytes()).hexdigest()!=proof['assembly_sha256']:
        raise ValueError('control assembly differs from construction proof')
    extents=[]
    for line in (annotated/'checkpoint.map').read_text().splitlines():
        if line.rstrip().endswith('program-asm.o:(.text)'):
            fields=line.split();extents.append((int(fields[0],16),int(fields[2],16)))
    if len(extents)!=1 or extents[0][1]!=proof['text_bytes_after']:
        raise ValueError('compiled main text differs from construction layout')
    base,size=extents[0]
    fallthrough_path=image/'adapter-fallthrough.json'
    fallthroughs=json.loads(fallthrough_path.read_text())['sites'] if fallthrough_path.exists() else []
    needed={row[k] for row in proof['branches'] for k in ('source','target')}
    needed.update('.Lp%x'%pc for row in fallthroughs for pc in (row['pc'],row['pc']+4))
    markers={};pending=None
    with (annotated/'program.S').open() as stream:
        for line in stream:
            label=line.strip().removesuffix(':')
            if label in needed:pending=label
            elif pending is not None:
                if not label.startswith(MARKER):raise ValueError('control source marker missing')
                markers[label]=pending;pending=None
    addresses={markers[name]:address-base for name,address in symbols((annotated/'checkpoint').read_bytes()) if name in markers}
    if set(addresses)!=needed:raise ValueError('compiled control labels are missing')
    data=(image/'checkpoint').read_bytes()
    executable=[s for s in segments(data) if s[0]==1 and s[1]&1 and s[3]<=base and base+size<=s[3]+s[5]]
    if len(executable)!=1:raise ValueError('control text is not in one executable load')
    segment=executable[0]
    for row in proof['branches']:
        source,target=addresses[row['source']],addresses[row['target']]
        if source!=row['native_offset'] or target!=row['native_target_offset']:
            raise ValueError('compiled control offset differs from proof')
        delta=target-source;limit=1<<(row['bits']+1);mask=(1<<row['bits'])-1
        if delta%4 or not -limit<=delta<limit:raise ValueError('compiled conditional exceeds signed range')
        expected=(row['word']&~(mask<<5))|(((delta//4)&mask)<<5)
        actual,=struct.unpack_from('<I',data,segment[2]+base+source-segment[3])
        if actual!=expected:raise ValueError('compiled conditional differs from original operands or target')
    if fallthroughs:
        from export_el0_program import Package
        from el0_flat_lower import decode,STACK,SYSTEM
        from el0_hardware import stack_path,system_path
        package=Package(Path(json.loads((image/'manifest.json').read_text())['package']))
        for row in fallthroughs:
            pc=row['pc'];word=package.word(pc);metadata=0
            if word==0xd421e000 and pc in package.sites:word,metadata=package.sites[pc]
            if (word,metadata)!=(row['word'],row['metadata']):
                raise ValueError('adapter fallthrough source differs from captured code')
            op=decode(word)
            code=(stack_path(op) if op.kind==STACK else
                  system_path(word,metadata,page_offsets=True) if op.kind==SYSTEM else '')
            if not code or op.kind!=row['kind']:
                raise ValueError('adapter fallthrough crosses a rejecting operation')
            source,target=(addresses['.Lp%x'%at] for at in (pc,pc+4))
            if target!=source+4*len(code.splitlines()):
                raise ValueError('adapter continuation does not immediately follow its body')
            last,=struct.unpack_from('<I',data,segment[2]+base+target-4-segment[3])
            # Both non-rejecting helpers finish by restoring their scratch pair
            # and releasing exactly their own 16-byte frame, without NZCV use.
            if last&0xffc003e0!=0xa8c003e0 or (last>>15&127)!=2:
                raise ValueError('adapter fallthrough does not restore its scratch frame')
    report=dict(image_sha256=hashlib.sha256(data).hexdigest(),assembly_sha256=proof['assembly_sha256'],
                branches_verified=len(proof['branches']),main_text_bytes=size,
                compiler_offsets_match=True,conditions_registers_bits_and_targets_match=True)
    if fallthroughs:report['adapter_fallthroughs_verified']=len(fallthroughs)
    (image/'control-compiled.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    import argparse
    import json
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True);parser.add_argument('--annotated',required=True)
    print(json.dumps(verify_branches(**vars(parser.parse_args())),indent=2))
