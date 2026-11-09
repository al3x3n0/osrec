#!/usr/bin/env python3
"""System-register names (as QEMU's gdbstub reports them) to AArch64 encodings, through llvm-mc.

An encoding is the 16-bit field [20:5] of an MRS/MSR instruction (op0, op1, CRn, CRm, op2). Each name is
assembled as `mrs x0, NAME`; a name QEMU reports without its level suffix (SCTLR, VBAR, CPACR...) is tried
again with `_EL1`. Names llvm-mc does not accept are reported, never guessed.
"""
import re,subprocess
from pathlib import Path

LLVM_MC=Path('/opt/homebrew/opt/llvm@16/bin/llvm-mc')


def encodings(names,features='+v8.5a,+mte,+sve,+sme,+tme,+spe,+ras,+rcpc,+lor,+pan,+vh,+uaops,+ccdp,+amvs,+fgt,+ecv,+brbe,+the,+d128'):
    """{name: 16-bit encoding} for every name llvm-mc accepts, and the names it does not."""
    found={};missing=[]
    candidates={n:[n,n+'_EL1'] if not re.search(r'_EL\d$',n) else [n] for n in names}
    for attempt in range(2):
        pending=[n for n in names if n not in found and attempt<len(candidates[n])]
        if not pending:break
        source=''.join('mrs x0, %s\n'%candidates[n][attempt] for n in pending)
        r=subprocess.run([str(LLVM_MC),'-triple=aarch64','-mattr='+features,'-show-encoding'],input=source,capture_output=True,text=True)
        bad=set()
        for line in r.stderr.splitlines():
            m=re.search(r'<stdin>:(\d+):',line)
            if m:bad.add(int(m.group(1))-1)
        lines=iter(l for l in r.stdout.splitlines() if 'encoding:' in l)
        for i,n in enumerate(pending):
            if i in bad:continue
            line=next(lines);b=[int(x,16) for x in re.search(r'encoding: \[(.*)\]',line).group(1).split(',')]
            word=b[0]|b[1]<<8|b[2]<<16|b[3]<<24;found[n]=(word>>5)&0xffff
    # QEMU's names for reserved ID registers carry their encoding: RES_0_C<CRn>_C<CRm>_<op2> (op0 3, op1 0).
    for n in names:
        m=re.fullmatch(r'RES_0_C(\d+)_C(\d+)_(\d+)',n)
        if m and n not in found:found[n]=0xc000|int(m.group(1))<<7|int(m.group(2))<<3|int(m.group(3))
    missing=[n for n in names if n not in found]
    return found,missing


def name_of(key):
    return 'S%d_%d_C%d_C%d_%d'%(2+(key>>14&1),key>>11&7,key>>7&15,key>>3&15,key&7)


def from_cpu_data(ram, image, database):
    """Registers omitted by QEMU's gdbstub, from the captured Linux CPU record.

    Offsets come from this build's DWARF; no ID value is invented. cpu_data is
    per-CPU, relative to TPIDR_EL1. MPIDR is deliberately not reconstructed from
    __cpu_logical_map, which drops architectural bits (including MPIDR.U).
    """
    import struct
    symbols={s['name']:s['value'] for s in image.symbols if s['value']}
    pages={va:pa for va,pa,_ in ram.mappings(1)[0]}
    def read(va):
        pa=pages.get(va&~4095)
        if pa is None:raise ValueError('CPU record is unmapped at 0x%x'%va)
        return struct.unpack_from('<Q',ram.page(pa),va&4095)[0]
    definitions=database['types']['struct:cpuinfo_arm64']['definitions']
    if len(definitions)!=1:raise ValueError('ambiguous cpuinfo_arm64 DWARF layout')
    result={}
    special={'ctr':'CTR_EL0','cntfrq':'CNTFRQ_EL0','dczid':'DCZID_EL0'}
    base=(symbols['cpu_data']+ram.sysregs['TPIDR_EL1'])&((1<<64)-1)
    for field,offset,bits,_ in definitions[0]['members']:
        if not field.startswith('reg_') or bits or offset%8:continue
        suffix=field[4:]
        name=special.get(suffix,suffix.upper()+'_EL1')
        result[name]=read(base+offset//8)
    return result
