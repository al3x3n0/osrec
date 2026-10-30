"""Shared ARM/AArch64 image audit and construction tool helpers."""
import re
import subprocess
from klee_liteos import ROOT

TARGET=ROOT/'integrations/rtl_armv7'


def run(command):
    return subprocess.run(list(map(str,command)),check=True,capture_output=True,text=True,timeout=60)


def audit(image,llvm_bin,allowed_breakpoints=None):
    from freestanding_elf import describe
    description=describe(image)
    undefined=run([llvm_bin/'llvm-nm','--undefined-only',image]).stdout.strip()
    if undefined:raise ValueError('unresolved image symbols: '+undefined)
    relocations=run([llvm_bin/'llvm-readelf','--relocations',image]).stdout
    if 'There are no relocations' not in relocations:raise ValueError('image has unresolved relocations')
    disassembly=run([llvm_bin/'llvm-objdump','--no-show-raw-insn','-d',image]).stdout
    allowed_breakpoints=allowed_breakpoints or {};seen={}
    for address,instruction,immediate in re.findall(r'^\s*([0-9a-f]+):\s+(svc|bkpt|brk|hvc|smc|hlt)\b(?:\s+#(0x[0-9a-f]+|[0-9]+))?',disassembly,re.M):
        address=int(address,16);value=int(immediate,0) if immediate else None
        if instruction!='brk' or description['isa']!='AArch64' or allowed_breakpoints.get(address)!=value or value is None:
            raise ValueError('image contains an external service/trap instruction')
        seen[address]=value
    if seen!=allowed_breakpoints:raise ValueError('reviewed embedded breakpoint is absent from image')
    return {**description,'undefined_symbols':[],
            'dynamic_dependencies':[],'relocations':False,'service_trap_instructions':bool(seen),
            'external_service_instructions':False,'embedded_breakpoints':[{'address':a,'immediate':v} for a,v in sorted(seen.items())]}

