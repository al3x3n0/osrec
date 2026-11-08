#!/usr/bin/env python3
"""Check that kernel functions are what their translation units compile to.

Runs inside the kernel build container (osrec-kbuild-clang19, the build volume at /kbuild). Input is a JSON
list of {"tu": source path relative to the kernel tree, "source": its absolute path (the DWARF compile unit),
"function": name, "address": vmlinux address}. The compile command is the one for exactly that source path; when
none is (DWARF names an included assembler template), it is the one whose built object alone defines the symbol
with vmlinux's st_size. Each translation unit is compiled again with its own compile command (compile_commands.json) plus
-ffunction-sections. The object and vmlinux are read as ELF (no disassembly): a function is its symbol's
st_size bytes, and its relocations come from the RELA section of its section. The function is compared with
vmlinux word by word. A word the object relocates is compared outside the relocated field only (by relocation
type), lld's ADRP+ADD -> NOP+ADR relaxation is accepted by shape, and every other word must be identical.
Output (stdout) is a JSON report per function.
"""
import json,os,shlex,struct,subprocess,sys,tempfile
from pathlib import Path

# AArch64 relocation types: the bits each writes in an instruction word (the rest must match).
RELOCATIONS={283:('R_AARCH64_CALL26',0x03ffffff),282:('R_AARCH64_JUMP26',0x03ffffff),280:('R_AARCH64_CONDBR19',0x00ffffe0),
             279:('R_AARCH64_TSTBR14',0x0007ffe0),275:('R_AARCH64_ADR_PREL_PG_HI21',0x60ffffe0),276:('R_AARCH64_ADR_PREL_PG_HI21_NC',0x60ffffe0),
             274:('R_AARCH64_ADR_PREL_LO21',0x60ffffe0),277:('R_AARCH64_ADD_ABS_LO12_NC',0x003ffc00),278:('R_AARCH64_LDST8_ABS_LO12_NC',0x003ffc00),
             284:('R_AARCH64_LDST16_ABS_LO12_NC',0x003ffc00),285:('R_AARCH64_LDST32_ABS_LO12_NC',0x003ffc00),
             286:('R_AARCH64_LDST64_ABS_LO12_NC',0x003ffc00),299:('R_AARCH64_LDST128_ABS_LO12_NC',0x003ffc00),273:('R_AARCH64_LD_PREL_LO19',0x00ffffe0)}
ADR_PREL_PG_HI21,ADD_ABS_LO12_NC=275,277
NOP=0xd503201f
SHT_SYMTAB,SHT_RELA,SHT_NOBITS=2,4,8


class Elf:
    """A little-endian ELF64 file: section headers, symbol table and RELA relocations, read directly."""
    def __init__(self,path):
        self.data=Path(path).read_bytes()
        if self.data[:4]!=b'\x7fELF' or self.data[4]!=2 or self.data[5]!=1:raise ValueError('not a little-endian ELF64 file: %s'%path)
        shoff,=struct.unpack_from('<Q',self.data,0x28);shentsize,shnum,shstrndx=struct.unpack_from('<HHH',self.data,0x3a)
        fields=('name','type','flags','addr','offset','size','link','info','align','entsize')
        self.sections=[dict(zip(fields,struct.unpack_from('<IIQQQQIIQQ',self.data,shoff+i*shentsize))) for i in range(shnum)]
        names=self.sections[shstrndx]
        for s in self.sections:s['name']=self.string(names,s['name'])
        self.symbols=[]
        for s in self.sections:
            if s['type']!=SHT_SYMTAB:continue
            strings=self.sections[s['link']]
            for k in range(s['offset'],s['offset']+s['size'],24):
                name,info,_other,shndx,value,size=struct.unpack_from('<IBBHQQ',self.data,k)
                self.symbols.append(dict(name=self.string(strings,name),type=info&15,bind=info>>4,shndx=shndx,value=value,size=size))
    def string(self,section,offset):
        start=section['offset']+offset;return self.data[start:self.data.index(b'\0',start)].decode()
    def bytes(self,section,offset,n):
        if section['type']==SHT_NOBITS or offset+n>section['size']:raise ValueError('outside section %s'%section['name'])
        return self.data[section['offset']+offset:section['offset']+offset+n]
    def read(self,va,n):
        """Bytes at a virtual address of a linked image."""
        for s in self.sections:
            if s['addr'] and s['type']!=SHT_NOBITS and s['addr']<=va and va+n<=s['addr']+s['size']:return self.bytes(s,va-s['addr'],n)
        raise ValueError('address outside the image sections: %x'%va)
    def relocations(self,index):
        """[(offset, type, symbol index, addend)] applied to section `index`."""
        result=[]
        for s in self.sections:
            if s['type']==SHT_RELA and s['info']==index:
                for k in range(s['offset'],s['offset']+s['size'],24):
                    offset,info,addend=struct.unpack_from('<QQq',self.data,k);result.append((offset,info&0xffffffff,info>>32,addend))
        return sorted(result)
    def function(self,name):
        """(instruction bytes, {word index: (type, symbol, addend)}) of a defined symbol, over its st_size."""
        found=[s for s in self.symbols if s['name']==name and 0<s['shndx']<len(self.sections) and s['size']]
        if not found:return None,{}
        if len(found)>1:raise ValueError('symbol %s defined %d times in the object'%(name,len(found)))
        symbol=found[0];section=self.sections[symbol['shndx']]
        code=self.bytes(section,symbol['value'],symbol['size'])
        relocated={(offset-symbol['value'])//4:(kind,sym,addend) for offset,kind,sym,addend in self.relocations(symbol['shndx'])
                   if symbol['value']<=offset<symbol['value']+symbol['size']}
        return code,relocated


def compile_unit(entry,out):
    arguments=shlex.split(entry['command']) if 'command' in entry else list(entry['arguments'])
    arguments[arguments.index('-o')+1]=str(out);arguments.insert(1,'-ffunction-sections')
    result=subprocess.run(arguments,cwd=entry['directory'],capture_output=True,text=True)
    if result.returncode:raise ValueError('compile failed: %s\n%s'%(entry['file'],result.stderr[-2000:]))


def compare(code,relocated,live):
    """Word-by-word comparison; returns (mismatched word indexes, unchecked relocations, relaxed pairs).

    A relocated word matches outside the field its relocation writes. lld's ADRP+ADD relaxation (an adrp
    with ADR_PREL_PG_HI21 directly followed by add Xd, Xd, #lo12 with ADD_ABS_LO12_NC against the same symbol
    and addend) links as `nop; adr Xd, target`: accepted when the live words have exactly that shape.
    """
    words=[int.from_bytes(code[k:k+4],'little') for k in range(0,len(code),4)]
    lives=[int.from_bytes(live[k:k+4],'little') for k in range(0,len(live),4)]
    mismatched=[];unknown=0;relaxed=0;k=0
    while k<len(words):
        a,b=words[k],lives[k];kind=relocated.get(k)
        if kind and kind[0]==ADR_PREL_PG_HI21 and k+1<len(words) and relocated.get(k+1,(None,))[0]==ADD_ABS_LO12_NC \
           and relocated[k+1][1:]==kind[1:] and b==NOP:
            rd=a&31;add=words[k+1]
            if add&0xffc003ff==0x91000000|rd<<5|rd and lives[k+1]&0x9f00001f==0x10000000|rd:relaxed+=1;k+=2;continue
        if kind is None:
            if a!=b:mismatched.append(k)
        elif kind[0] in RELOCATIONS:
            if (a^b)&~RELOCATIONS[kind[0]][1]&0xffffffff:mismatched.append(k)
        else:unknown+=1
        k+=1
    return mismatched,unknown,relaxed


def source_path(entry):
    return os.path.normpath(os.path.join(entry['directory'],entry['file']))


def object_path(entry):
    arguments=shlex.split(entry['command']) if 'command' in entry else list(entry['arguments'])
    return Path(os.path.normpath(os.path.join(entry['directory'],arguments[arguments.index('-o')+1])))


class Units:
    """Compile commands by exact source path, and (lazily) the build's objects by defined symbol."""
    def __init__(self,build,image):
        self.image=image;self.entries=json.load(open(build/'compile_commands.json'))
        self.by_source={}
        for entry in self.entries:self.by_source.setdefault(source_path(entry),entry)
        self.by_symbol=None
    def defining(self,name,address):
        """Compile commands whose built object defines `name` with vmlinux's st_size for the symbol at `address`."""
        size={s['value']:s['size'] for s in self.image.symbols if s['name']==name}.get(address)
        if not size:return []
        if self.by_symbol is None:
            self.by_symbol={}
            for entry in self.entries:
                obj=object_path(entry)
                if not obj.exists():continue
                try:symbols=Elf(obj).symbols
                except (ValueError,struct.error):continue
                for s in symbols:
                    if s['size'] and s['shndx']:self.by_symbol.setdefault((s['name'],s['size']),[]).append(entry)
        return self.by_symbol.get((name,size),[])
    def entry(self,request):
        """(compile command, how it was found) for a request, or (None, reason)."""
        exact=self.by_source.get(os.path.normpath(request['source'])) if request.get('source') else None
        if exact:return exact,'source'
        # DWARF can name a file the unit includes (an assembler template); the object defining the symbol decides.
        found=self.defining(request['function'],request['address'])
        if len(found)==1:return found[0],'symbol'
        return None,'no_compile_command' if not found else 'ambiguous_symbol'


def main():
    requests=json.load(open(sys.argv[1]));build=Path(sys.argv[2] if len(sys.argv)>2 else '/kbuild')
    image=Elf(build/'vmlinux');units=Units(build,image);report=[];by_entry={}
    for request in requests:
        entry,how=units.entry(request)
        if entry is None:report.append(dict(request,status=how));continue
        by_entry.setdefault(source_path(entry),(entry,[]))[1].append(dict(request,compiled=source_path(entry),resolved_by=how))
    with tempfile.TemporaryDirectory() as tmp:
        for index,(_,(entry,items)) in enumerate(sorted(by_entry.items())):
            obj=Path(tmp)/('tu%d.o'%index)
            try:compile_unit(entry,obj)
            except ValueError as error:report+=[dict(item,status='compile_failed',detail=str(error)[:500]) for item in items];continue
            unit=Elf(obj)
            for item in items:
                try:code,relocated=unit.function(item['function'])
                except ValueError as error:report.append(dict(item,status='unreadable',detail=str(error)));continue
                if not code:report.append(dict(item,status='not_in_object'));continue
                mismatched,unknown,relaxed=compare(code,relocated,image.read(item['address'],len(code)))
                report.append(dict(item,status='identical' if not mismatched else 'differs',words=len(code)//4,relocated=len(relocated),
                                   relaxed_pairs=relaxed,unchecked_relocations=unknown,mismatched_words=mismatched[:16]))
    json.dump(report,sys.stdout,indent=1)


if __name__=='__main__':main()
