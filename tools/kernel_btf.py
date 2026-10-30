#!/usr/bin/env python3
"""Read struct layouts from a kernel image's embedded BTF and resolve typed paths.

BTF is the running kernel's own type record, so member offsets are not supplied
by hand. Paths still name reviewed fields; BTF does not establish semantics.
"""
import re,struct

KINDS={1:'int',2:'ptr',3:'array',4:'struct',5:'union',6:'enum',7:'fwd',8:'typedef',9:'volatile',10:'const',11:'restrict',12:'func',13:'func_proto',14:'var',15:'datasec',16:'float',17:'decl_tag',18:'type_tag',19:'enum64'}
QUALIFIERS=('typedef','volatile','const','restrict','type_tag')

def locate(blob):
    hits=[];i=0
    while (i:=blob.find(b'\x9f\xeb\x01\x00',i))>=0:
        size,types,type_bytes,strings,string_bytes=struct.unpack_from('<IIIII',blob,i+4)
        if size==24 and types==0 and strings==type_bytes and i+size+strings+string_bytes<=len(blob):hits.append(i)
        i+=1
    if len(hits)!=1:raise ValueError('expected one embedded BTF blob, found %d'%len(hits))
    return hits[0]

class TypeTable:
    """Shared view over a kernel type source: `types[i]` dicts with kind/name/value,
    struct/union `members` (name, type, bit offset, bit width), array element/count
    and optional pointer `bytes`. `records` maps struct names to definitions."""
    pointer_bytes=8
    def strip(self,i):
        while self.types[i]['kind'] in QUALIFIERS:i=self.types[i]['value']
        return i
    def sizeof(self,i):
        t=self.types[self.strip(i)]
        if t['kind']=='ptr':return t.get('bytes',self.pointer_bytes)
        if t['kind']=='array':return t['count']*self.sizeof(t['element'])
        if t['kind'] in ('int','struct','union','enum','float'):return t['value']
        raise ValueError('type has no size: '+t['kind'])
    def struct(self,name):
        found=self.records.get(name,[])
        if len(found)!=1:raise ValueError('%s struct %s is not unique (%d definitions)'%(self.source,name,len(found)))
        return found[0]
    def member(self,i,name):
        """Return (byte offset, type id), including members of anonymous records."""
        t=self.types[self.strip(i)]
        if t['kind'] not in ('struct','union'):raise ValueError('member access on non-record type')
        for member,target,bits,width in t['members']:
            if member==name:
                if width or bits%8:raise ValueError('bitfield member is not admitted: '+name)
                return bits//8,target
            if not member and self.types[self.strip(target)]['kind'] in ('struct','union'):
                try:offset,found=self.member(target,name);return bits//8+offset,found
                except KeyError:pass
        raise KeyError(name)
    def scalar(self,i):
        t=self.types[self.strip(i)]
        if t['kind'] in ('int','enum','ptr'):return self.sizeof(i)
        raise ValueError('path does not end at a scalar: '+t['kind'])

class BTF(TypeTable):
    source='BTF'
    def __init__(self,blob,offset=None):
        offset=locate(blob) if offset is None else offset
        size,types,type_bytes,strings,string_bytes=struct.unpack_from('<IIIII',blob,offset+4);base=offset+size
        self.strings=blob[base+strings:base+strings+string_bytes];data=blob[base+types:base+types+type_bytes];self.types=[None];p=0
        while p<len(data):
            name,info,value=struct.unpack_from('<III',data,p);p+=12
            if (info>>24)&31 not in KINDS:raise ValueError('unsupported BTF kind')
            kind=KINDS[(info>>24)&31];count=info&0xffff;t=dict(kind=kind,name=self.text(name),value=value)
            if kind in ('int','var','decl_tag'):p+=4
            elif kind=='array':t['element'],_,t['count']=struct.unpack_from('<III',data,p);p+=12
            elif kind in ('struct','union'):
                t['members']=[]
                for _ in range(count):
                    member,target,bits=struct.unpack_from('<III',data,p);p+=12
                    t['members'].append((self.text(member),target,bits&0xffffff if info>>31 else bits,bits>>24 if info>>31 else 0))
            elif kind in ('enum','func_proto'):p+=8*count
            elif kind in ('datasec','enum64'):p+=12*count
            self.types.append(t)
        if p!=len(data):raise ValueError('truncated BTF type section')
        self.records={}
        for i,t in enumerate(self.types[1:],1):
            if t['kind']=='struct' and t['name'] and t['value']:self.records.setdefault(t['name'],[]).append(i)
    def text(self,offset):return self.strings[offset:self.strings.index(b'\0',offset)].decode()

PATH=re.compile(r'(->|\.)([A-Za-z_][A-Za-z_0-9]*)|\[(\d+)\]|-><([A-Za-z_]\w*)\.([A-Za-z_]\w*)>')
def resolve(btf,read,address,record,path):
    """Read a scalar at `path` below a `record` object; `read(address,size)` returns int."""
    current=btf.struct(record);place=address;position=0
    if not path.startswith(('->','.','[')):raise ValueError('typed path must start with an accessor')
    while position<len(path):
        m=PATH.match(path,position)
        if not m:raise ValueError('invalid typed path: '+path)
        position=m.end();t=btf.types[btf.strip(current)]
        if m.group(4):
            # `-><record.member>`: the pointer targets `member` of an enclosing `record` (container_of).
            if t['kind']!='ptr':raise ValueError('container step on non-pointer in '+path)
            place=read(place,btf.sizeof(current))
            if not place:raise ValueError('null pointer in '+path)
            record=btf.struct(m.group(4));offset,member=btf.member(record,m.group(5))
            if btf.strip(member)!=btf.strip(t['value']):raise ValueError('container member type differs in '+path)
            place-=offset;current=record
        elif m.group(1)=='->':
            if t['kind']!='ptr':raise ValueError('-> on non-pointer in '+path)
            place=read(place,btf.sizeof(current));current=t['value']
            if not place:raise ValueError('null pointer in '+path)
            place,current=(lambda o:(place+o[0],o[1]))(btf.member(current,m.group(2)))
        elif m.group(1)=='.':
            offset,current=btf.member(current,m.group(2));place+=offset
        else:
            index=int(m.group(3))
            if t['kind']=='ptr':
                place=read(place,btf.sizeof(current));current=t['value']
                if not place:raise ValueError('null pointer in '+path)
            elif t['kind']=='array':
                if index>=t['count']:raise ValueError('array index out of BTF bounds in '+path)
                current=t['element']
            else:raise ValueError('index on non-pointer in '+path)
            place+=index*btf.sizeof(current)
    return place,current
