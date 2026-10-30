#!/usr/bin/env python3
"""Kernel type table from an ELF's DWARF, through llvm-dwarfdump's DIE listing.

Produces the same `TypeTable` view as the BTF reader, so typed paths, live
bindings and binding drafts work on kernels built with debug information.
Identical struct definitions repeated across compile units are merged; a name
with differing definitions stays ambiguous and `struct()` rejects it. Anonymous
structs take their typedef name. Pointer width is the unit address size unless
the pointer DIE states its own.
"""
import re,subprocess
from pathlib import Path
from kernel_btf import TypeTable

DIE=re.compile(r'^0x([0-9a-f]+):(\s+)(DW_TAG_\w+|NULL)')
ATTRIBUTE=re.compile(r'^\s+(DW_AT_\w+)\s*\((.*)\)\s*$')
UNIT=re.compile(r'^0x[0-9a-f]+: Compile Unit:.*addr_size = 0x([0-9a-f]+)')
KINDS={'DW_TAG_base_type':'int','DW_TAG_pointer_type':'ptr','DW_TAG_structure_type':'struct','DW_TAG_union_type':'union',
    'DW_TAG_enumeration_type':'enum','DW_TAG_typedef':'typedef','DW_TAG_const_type':'const','DW_TAG_volatile_type':'volatile',
    'DW_TAG_restrict_type':'restrict','DW_TAG_array_type':'array','DW_TAG_subroutine_type':'func_proto'}

def number(text):
    m=re.match(r'(?:DW_OP_plus_uconst\s+)?(-?0x[0-9a-f]+|-?\d+)\b',text.strip())
    return int(m.group(1),0) if m else None
def reference(text):
    m=re.match(r'0x([0-9a-f]+)',text.strip());return int(m.group(1),16) if m else None
def string(text):
    m=re.match(r'"(.*)"$',text.strip());return m.group(1) if m else None

def parse(lines):
    """Return DIEs as dicts with offset, tag, depth, attributes, parent and unit address size."""
    dies=[];stack=[];address=None;current=None
    for line in lines:
        m=UNIT.match(line)
        if m:address=int(m.group(1),16);stack=[];continue
        m=DIE.match(line)
        if m:
            depth=len(m.group(2))
            while stack and stack[-1]['depth']>=depth:stack.pop()
            if m.group(3)=='NULL':current=None;continue
            current=dict(offset=int(m.group(1),16),tag=m.group(3),depth=depth,attributes={},parent=stack[-1]['offset'] if stack else None,address_size=address,children=[],unit=stack[0]['offset'] if stack else int(m.group(1),16))
            if stack:stack[-1]['children'].append(current)
            dies.append(current);stack.append(current);continue
        m=ATTRIBUTE.match(line)
        if m and current is not None:current['attributes'][m.group(1)]=m.group(2)
    return dies

class DWARF(TypeTable):
    source='DWARF'
    def __init__(self,elf,dwarfdump='llvm-dwarfdump',text=None):
        if text is None:text=subprocess.run([str(dwarfdump),'--debug-info',str(elf)],capture_output=True,text=True,check=True,timeout=600).stdout
        dies=parse(text.splitlines());index={};self.types=[None];self.units={}
        for d in dies:
            if d['tag'] in KINDS:index[d['offset']]=len(self.types);self.types.append(None)
            if d['tag']=='DW_TAG_compile_unit':self.units[d['offset']]=d
        sizes={d['address_size'] for d in dies if d['address_size']}
        if len(sizes)!=1:raise ValueError('DWARF units disagree on address size')
        self.pointer_bytes=sizes.pop();self.names={}
        target=lambda d:index.get(reference(d['attributes'].get('DW_AT_type','')),0)
        for d in dies:
            if d['tag'] not in KINDS:continue
            a=d['attributes'];kind=KINDS[d['tag']];t=dict(kind=kind,name=string(a.get('DW_AT_name',''))or '',offset=d['offset'],unit=d['unit'])
            if 'DW_AT_declaration' in a and kind in ('struct','union'):t['kind']='fwd'
            elif kind in ('int','enum','struct','union'):t['value']=number(a.get('DW_AT_byte_size','0')) or 0
            elif kind=='ptr':
                t['value']=target(d)
                if 'DW_AT_byte_size' in a:t['bytes']=number(a['DW_AT_byte_size'])
            elif kind=='array':
                ranges=[c for c in d['children'] if c['tag']=='DW_TAG_subrange_type']
                counts=[number(r['attributes']['DW_AT_count']) if 'DW_AT_count' in r['attributes'] else number(r['attributes']['DW_AT_upper_bound'])+1 if 'DW_AT_upper_bound' in r['attributes'] else 0 for r in ranges] or [0]
                # Multi-dimensional arrays become nested single-dimension arrays.
                element=target(d)
                for count in reversed(counts[1:]):self.types.append(dict(kind='array',name='',element=element,count=count));element=len(self.types)-1
                t.update(element=element,count=counts[0])
            else:t['value']=target(d)
            if t['kind'] in ('struct','union'):
                t['members']=[]
                for c in d['children']:
                    if c['tag']!='DW_TAG_member':continue
                    ca=c['attributes'];byte=number(ca.get('DW_AT_data_member_location','0')) or 0;width=number(ca.get('DW_AT_bit_size','0')) or 0
                    bits=byte*8
                    if 'DW_AT_data_bit_offset' in ca:bits=number(ca['DW_AT_data_bit_offset'])
                    elif width:bits+=1  # DWARF2 big-endian bit offsets: marked bitfield, never byte-addressable
                    t['members'].append((string(ca.get('DW_AT_name',''))or '',index.get(reference(ca.get('DW_AT_type','')),0),bits,width))
            self.types[index[d['offset']]]=t
        self.records={};signatures={}
        for i,t in enumerate(self.types[1:],1):
            if t['kind']=='typedef' and t['name'] and t['value']:
                u=self.types[t['value']]
                if u and u['kind']=='struct' and not u['name']:self.names.setdefault(t['value'],t['name'])
        for i,t in enumerate(self.types[1:],1):
            if t['kind']!='struct' or not t['value']:continue
            name=t['name'] or self.names.get(i)
            if not name:continue
            key=self.signature(i);entry=signatures.setdefault(name,{})
            if key not in entry:entry[key]=i;self.records.setdefault(name,[]).append(i)
        # Typedef names of named structs resolve to the same definitions (LosTaskCB -> TagTaskCB).
        for t in self.types[1:]:
            if t['kind']=='typedef' and t['name'] and t['name'] not in self.records and t['value']:
                u=self.strip(t['value']);name=self.types[u]['name'] or self.names.get(u)
                if self.types[u]['kind']=='struct' and name in self.records:self.records[t['name']]=self.records[name]
    def unit_source(self,unit):
        a=self.units[unit]['attributes'];name=string(a.get('DW_AT_name','')) or '';base=string(a.get('DW_AT_comp_dir','')) or ''
        return str((Path(base)/name).resolve()) if name else None
    def unit_records(self,unit):
        """Complete named records defined in one compile unit: (name, spelling, type id)."""
        found=[]
        for i,t in enumerate(self.types[1:],1):
            if t['kind']=='struct' and t['value'] and t['unit']==unit:
                if t['name']:found.append((t['name'],'struct '+t['name'],i))
                elif i in self.names:found.append((self.names[i],self.names[i],i))
        return found
    def describe(self,i,depth=0):
        """Stable cross-unit layout text used to decide whether two definitions are the same."""
        if not i:return 'void'
        t=self.types[i]
        if depth>3:return t['kind']+':'+t['name']
        if t['kind']=='ptr':return self.describe(t['value'],depth+1)+'*'
        if t['kind']=='array':return self.describe(t['element'],depth+1)+'[%d]'%t['count']
        # Layout identity: typedef spellings and qualifiers do not change size or placement.
        if t['kind'] in ('typedef','const','volatile','restrict'):return self.describe(t['value'],depth)
        if t['kind'] in ('struct','union','fwd'):
            name=t['name'] or self.names.get(i)
            # Tags compare by name: a pointee may be complete in one unit and declared in another.
            if name:return ('union ' if t['kind']=='union' else 'struct ')+name
            return '{'+';'.join('%s:%d:%s'%(n,b,self.describe(m,depth+1)) for n,m,b,w in t['members'])+'}'
        if t['kind']=='func_proto':return 'function'
        return '%s %s %s'%(t['kind'],t['name'],t.get('value',''))
    def signature(self,i):
        t=self.types[i];return (t['value'],tuple((n,b,w,self.describe(m)) for n,m,b,w in t['members']))
