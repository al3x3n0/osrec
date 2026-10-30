"""Generate assembly offsets from the target compiler's public gateway/frame types."""
import json,subprocess
from contextify_slice import walk

def generate(sources,clang):
    fields={'APP':'application','CONTAINER':'container','KERNEL_SP':'kernel_sp','STATUS':'status',
        'VBAR':'saved_vbar','TPIDR_EL1':'saved_tpidr_el1','CPACR':'saved_cpacr','SP_EL0':'saved_sp_el0',
        'ELR':'saved_elr','SPSR':'saved_spsr'}
    frame={'SP':'sp','PC':'pc','PSTATE':'pstate','V':'v','FPCR':'fpcr','FPSR':'fpsr','TPIDR':'tpidr_el0','TPIDRRO':'tpidrro_el0'}
    constants={**{'G_'+k:'offsetof(struct osrec_aarch64_gateway,'+v+')' for k,v in fields.items()},
        **{'F_'+k:'offsetof(struct osrec_aarch64_frame,'+v+')' for k,v in frame.items()},
        'F_STACK_BYTES':'(sizeof(struct osrec_aarch64_frame)+15)&~15',
        'G_ABI':'OSREC_AARCH64_GATEWAY_ABI',
        'G_BYTES':'sizeof(struct osrec_aarch64_gateway)'}
    probe=sources/'slice_gateway_layout_probe.c'
    probe.write_text('#include "osrec/aarch64_gateway.h"\nenum {\n'+',\n'.join(k+'='+v for k,v in constants.items())+'\n};\n')
    result=subprocess.run([str(clang),'--target=aarch64-none-elf','-std=c11','-ffreestanding','-I'+str(sources),'-Xclang','-ast-dump=json','-fsyntax-only',str(probe)],capture_output=True,text=True,timeout=60)
    if result.returncode:raise ValueError('gateway layout compilation failed: '+result.stderr)
    values={}
    for n in walk(json.loads(result.stdout)):
        if n['kind']=='EnumConstantDecl' and n.get('name') in constants:
            c=[c for c in walk(n) if c['kind']=='ConstantExpr' and 'value' in c]
            if len(c)!=1:raise ValueError('gateway layout is not constant')
            values[n['name']]=int(c[0]['value'])
    if values.keys()!=constants.keys():raise ValueError('gateway layout missing fields')
    (sources/'slice_gateway_offsets.h').write_text('#ifndef OSREC_GATEWAY_OFFSETS_H\n#define OSREC_GATEWAY_OFFSETS_H\n'+''.join('#define '+k+' '+str(v)+'\n' for k,v in values.items())+'#endif\n')
    return values
