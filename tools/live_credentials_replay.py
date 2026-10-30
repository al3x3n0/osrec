"""Normalize live effective credential queries to a pointer-free semantic checkpoint."""
import json
import re
import struct
from klee_liteos import ROOT,digest
from freestanding_armv7 import run
CALLS=(201,202,201,202)

def prepare_source(kernel_root):
    lock=json.loads((ROOT/'integrations/liteos_a/credentials-source-lock.json').read_text())
    if run(['git','-C',kernel_root,'rev-parse','HEAD']).stdout.strip()!=lock['revision']:
        raise ValueError('credentials kernel revision differs')
    for root in (kernel_root,ROOT/'build/ohos/kernel/liteos_a'):
        for relative,expected in {lock['source']:lock['source_sha256'],**lock['headers']}.items():
            if digest((root/relative).read_bytes())!=expected:raise ValueError('credentials source/header changed')
    config=(ROOT/'build/ohos/kernel/liteos_a/.config').read_text()
    if not re.search(r'^LOSCFG_SECURITY_CAPABILITY=y$',config,re.M) or re.search(r'^LOSCFG_USER_CONTAINER=(?:y|1)$',config,re.M):
        raise ValueError('credential replay requires capabilities enabled and user containers disabled')
    source=(kernel_root/lock['source']).read_text();bodies=[]
    for name,contract in lock['functions'].items():
        match=re.search(r'int '+name+r'\(void\)\s*\{.*?\n\}',source,re.S)
        if not match or digest(match[0].encode())!=contract['sha256']:raise ValueError('credentials syscall body changed')
        bodies.append(match[0])
    license_text=source[:source.index('*/')+2]
    generated=license_text+'\n#include "credentials_model.h"\n'+'\n\n'.join(bodies)+'\n'
    model=(ROOT/'integrations/liteos_a/credentials_model.h').read_bytes()
    return generated,{'source':lock,'license':license_text,'generated_source_sha256':digest(generated.encode()),
        'model_header_sha256':digest(model),'configuration':{'LOSCFG_SECURITY_CAPABILITY':True,'LOSCFG_USER_CONTAINER':False},
        'type_contract':'32-bit credential fields and raw return bits; target-native pointers reconstructed from logical objects'}

def decode_credentials(user,kernel):
    if len(user)!=48 or len(kernel)!=96:raise ValueError('credential observation size differs')
    calls=[];state=None
    for index,number in enumerate(CALLS):
        actual,raw,mode=struct.unpack_from('<3I',user,index*12)
        syscall,pid,euid,egid,kernel_raw,kernel_mode=struct.unpack_from('<6I',kernel,index*24)
        if actual!=number or syscall!=number or mode!=16 or kernel_mode!=0x113 or kernel_raw!=raw:
            raise ValueError('credential syscall, mode or user/kernel result differs')
        entry=(pid,euid,egid)
        if state is None:state=entry
        elif entry!=state:raise ValueError('credential entry state changed during session')
        calls.append({'number':number,'raw_bits':raw,'user_mode':mode})
    pid,euid,egid=state
    return {'format':'osrec-credentials-checkpoint-v1',
        'configuration':{'LOSCFG_SECURITY_CAPABILITY':True,'LOSCFG_USER_CONTAINER':False},
        'current_process_id':pid,'current_credentials':1,
        'objects':[{'id':1,'type':'credentials','effective_uid':euid,'effective_gid':egid}],
        'calls':calls}

def export_live_credentials(args,user,kernel,kernel_hash):
    _,identity=prepare_source(args.kernel_root);checkpoint=decode_credentials(user,kernel)
    if checkpoint['current_process_id']!=1:raise ValueError('credential capture owner differs from PID 1')
    report={'format':'osrec-live-credentials-checkpoint-v1','source_identity':identity,'checkpoint':checkpoint,
        'kernel_image_sha256':kernel_hash,'user_observations_sha256':digest(user),'kernel_observations_sha256':digest(kernel),
        'provenance':'actual LiteOS-A PID 1 SVC calls; entry fields sampled under scheduler lock',
        'scheduler_irq_reproduction':False,'native_layout_reproduction':False,'runtime_host_interaction':False}
    (args.out/'credentials-user-observations.bin').write_bytes(user)
    (args.out/'credentials-kernel-observations.bin').write_bytes(kernel)
    (args.out/'credentials-checkpoint.manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    return report
