#!/usr/bin/env python3
"""Type and static-variable database of a kernel, from its DWARF through pyelftools.

Run with the DWARF virtualenv (build/.venv-dwarf: pyelftools). Compile units are independent, so worker
processes take slices of them and the results are merged.

Type keys are canonical across units: base:NAME:SIZE, typedef:NAME, ptr:KEY, array:KEY:COUNT, enum:NAME:SIZE,
struct:NAME, union:NAME, anon:HASH (unnamed record, by layout), func; qualifiers are transparent. A record name
with differing layouts keeps every layout (`definitions`), each with its size, and is listed as ambiguous; users
choose by size. Variables: static storage only (file scope and function statics) whose location is one address
operation (DW_OP_addr / DW_OP_addrx), as [name, address, type key, byte size].
"""
import argparse,gzip,hashlib,json,multiprocessing,sys,time
from pathlib import Path

QUALIFIERS={'DW_TAG_const_type','DW_TAG_volatile_type','DW_TAG_restrict_type','DW_TAG_atomic_type'}


def text(die,attr):
    a=die.attributes.get(attr);v=a.value if a else None
    return v.decode() if isinstance(v,bytes) else v


class Unit:
    """Canonical keys for one compile unit's type DIEs."""
    def __init__(self,cu):
        self.cu=cu;self.keys={};self.sizes={};self.records={}
    def target(self,die):
        return die.get_DIE_from_attribute('DW_AT_type') if 'DW_AT_type' in die.attributes else None
    def key(self,die):
        if die is None:return 'void'
        if die.offset in self.keys:return self.keys[die.offset]
        tag=die.tag;n=text(die,'DW_AT_name')
        if tag in QUALIFIERS:k=self.key(self.target(die))
        elif tag=='DW_TAG_base_type':k='base:%s:%s'%(n,text(die,'DW_AT_byte_size'))
        elif tag=='DW_TAG_pointer_type':
            self.keys[die.offset]='ptr:?';k='ptr:'+self.key(self.target(die))
        elif tag=='DW_TAG_subroutine_type':k='func'
        elif tag=='DW_TAG_enumeration_type':k='enum:%s:%s'%(n or '',text(die,'DW_AT_byte_size'))
        elif tag=='DW_TAG_typedef':
            k='typedef:%s'%n;self.keys[die.offset]=k
            self.records.setdefault(k,dict(kind='typedef',target=self.key(self.target(die))))
        elif tag=='DW_TAG_array_type':
            counts=[]
            for c in die.iter_children():
                if c.tag!='DW_TAG_subrange_type':continue
                count=text(c,'DW_AT_count');upper=text(c,'DW_AT_upper_bound')
                counts.append(count if isinstance(count,int) else upper+1 if isinstance(upper,int) else 0)
            k=self.key(self.target(die))
            for count in reversed(counts or [0]):k='array:%s:%d'%(k,count)
        elif tag in ('DW_TAG_structure_type','DW_TAG_union_type'):
            kind='struct' if tag=='DW_TAG_structure_type' else 'union'
            if 'DW_AT_declaration' in die.attributes:k='%s:%s'%(kind,n)
            else:
                self.keys[die.offset]='%s:%s'%(kind,n) if n else 'anon:?'
                members=[]
                for c in die.iter_children():
                    if c.tag!='DW_TAG_member':continue
                    loc=text(c,'DW_AT_data_member_location');bit=text(c,'DW_AT_data_bit_offset')
                    offset=bit if isinstance(bit,int) else 8*(loc if isinstance(loc,int) else 0)
                    members.append([text(c,'DW_AT_name') or '',offset,text(c,'DW_AT_bit_size') or 0,self.key(self.target(c))])
                record=dict(kind=kind,name=n or '',size=text(die,'DW_AT_byte_size') or 0,members=members)
                if n:k='%s:%s'%(kind,n)
                else:k='anon:'+hashlib.sha1(json.dumps([kind,record['size'],members]).encode()).hexdigest()[:16]
                self.records.setdefault(k,[]).append(record) if n else self.records.setdefault(k,record)
        else:k='other:'+tag
        self.keys[die.offset]=k;return k
    def size(self,die):
        """Byte size of a type DIE."""
        if die is None:return 0
        if 'DW_AT_byte_size' in die.attributes:return text(die,'DW_AT_byte_size')
        if die.tag=='DW_TAG_pointer_type':return self.cu['address_size']
        if die.tag=='DW_TAG_array_type':
            n=1
            for c in die.iter_children():
                if c.tag=='DW_TAG_subrange_type':
                    count=text(c,'DW_AT_count');upper=text(c,'DW_AT_upper_bound')
                    n*=count if isinstance(count,int) else upper+1 if isinstance(upper,int) else 0
            return n*self.size(self.target(die))
        return self.size(self.target(die)) if 'DW_AT_type' in die.attributes else 0


def work(job):
    path,offsets=job
    from elftools.elf.elffile import ELFFile
    from elftools.dwarf.dwarf_expr import DWARFExprParser
    info=ELFFile(open(path,'rb')).get_dwarf_info();parser=DWARFExprParser(info.structs)
    records={};variables=[]
    for offset in offsets:
        cu=info.get_CU_at(offset);unit=Unit(cu)
        for die in cu.iter_DIEs():
            if die.tag in ('DW_TAG_structure_type','DW_TAG_union_type','DW_TAG_typedef'):unit.key(die)
            if die.tag!='DW_TAG_variable' or 'DW_AT_location' in die.attributes and die.attributes['DW_AT_location'].form!='DW_FORM_exprloc':continue
            if 'DW_AT_location' not in die.attributes:continue
            ops=parser.parse_expr(die.attributes['DW_AT_location'].value)
            if len(ops)!=1 or ops[0].op_name not in ('DW_OP_addr','DW_OP_addrx'):continue
            address=ops[0].args[0] if ops[0].op_name=='DW_OP_addr' else info.get_addr(cu,ops[0].args[0])
            if not address:continue
            decl=die.get_DIE_from_attribute('DW_AT_specification') if 'DW_AT_specification' in die.attributes else die
            t=unit.target(die) or unit.target(decl)
            variables.append([text(die,'DW_AT_name') or text(decl,'DW_AT_name') or '',address,unit.key(t),unit.size(t)])
        for k,v in unit.records.items():
            if isinstance(v,list):
                have=records.setdefault(k,[])
                for r in v:
                    if r not in have:have.append(r)
            else:records.setdefault(k,v)
    return records,variables


def build(vmlinux,out,workers):
    from elftools.elf.elffile import ELFFile
    info=ELFFile(open(vmlinux,'rb')).get_dwarf_info();offsets=[cu.cu_offset for cu in info.iter_CUs()]
    # Interleaved slices balance large and small units across workers.
    jobs=[(str(vmlinux),offsets[i::workers*4]) for i in range(workers*4)]
    records={};variables=[];start=time.time()
    with multiprocessing.Pool(workers) as pool:
        for i,(r,v) in enumerate(pool.imap_unordered(work,jobs),1):
            for k,x in r.items():
                if isinstance(x,list):
                    have=records.setdefault(k,[])
                    for d in x:
                        if d not in have:have.append(d)
                else:records.setdefault(k,x)
            variables+=v
            print('%d/%d slices, %.0f s'%(i,len(jobs),time.time()-start),file=sys.stderr,flush=True)
    types={};ambiguous=[]
    for k,x in records.items():
        if isinstance(x,list):
            types[k]=dict(kind=x[0]['kind'],name=x[0]['name'],definitions=x)
            if len(x)>1:ambiguous.append(k)
        else:types[k]=x
    db=dict(format='osrec-kernel-dwarf-db-v1',vmlinux=str(Path(vmlinux).resolve()),units=len(offsets),types=types,
            variables=sorted(variables,key=lambda v:v[1]),ambiguous=sorted(ambiguous))
    with gzip.open(out,'wt') as f:json.dump(db,f)
    return dict(units=len(offsets),types=len(types),records=sum(1 for t in types.values() if 'definitions' in t),
                ambiguous=len(ambiguous),variables=len(variables),seconds=round(time.time()-start))


def load(path):
    with gzip.open(path,'rt') as f:return json.load(f)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--vmlinux',required=True);p.add_argument('--out',required=True)
    p.add_argument('--workers',type=int,default=multiprocessing.cpu_count())
    a=p.parse_args();print(json.dumps(build(a.vmlinux,a.out,a.workers)))


if __name__=='__main__':main()
