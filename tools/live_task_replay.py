"""Normalize live parent/task queries to a pointer-free semantic checkpoint."""
import json
import re
import struct
from klee_liteos import ROOT,digest
from freestanding_armv7 import run
CALLS=(64,224,64,224)

def prepare_source(kernel_root):
    lock=json.loads((ROOT/'integrations/liteos_a/task-source-lock.json').read_text())
    if run(['git','-C',kernel_root,'rev-parse','HEAD']).stdout.strip()!=lock['revision']:
        raise ValueError('task kernel revision differs')
    for root in (kernel_root,ROOT/'build/ohos/kernel/liteos_a'):
        for relative,expected in {lock['source']:lock['source_sha256'],**lock['headers']}.items():
            if digest((root/relative).read_bytes())!=expected:raise ValueError('task source/header changed')
    config=(ROOT/'build/ohos/kernel/liteos_a/.config').read_text()
    if re.search(r'^LOSCFG_PID_CONTAINER=(?:y|1)$',config,re.M):
        raise ValueError('task replay requires PID containers disabled')
    source=(kernel_root/lock['source']).read_text();bodies=[]
    for name,contract in lock['functions'].items():
        match=re.search(r'unsigned int '+name+r'\(void\)\s*\{.*?\n\}',source,re.S)
        if not match or digest(match[0].encode())!=contract['sha256']:raise ValueError('task syscall body changed')
        bodies.append(match[0])
    license_text=source[:source.index('*/')+2]
    generated=license_text+'\n#include "task_model.h"\n#ifdef LOSCFG_PID_CONTAINER\n#error Unsupported PID container configuration\n#endif\n'+'\n\n'.join(bodies)+'\n'
    model=(ROOT/'integrations/liteos_a/task_model.h').read_bytes()
    return generated,{'source':lock,'license':license_text,'generated_source_sha256':digest(generated.encode()),
        'model_header_sha256':digest(model),'configuration':{'LOSCFG_PID_CONTAINER':False},
        'type_contract':'32-bit unsigned syscall scalars; target-native pointers reconstructed from logical objects'}

def decode_task(user,kernel):
    if len(user)!=48 or len(kernel)!=96:raise ValueError('task observation size differs')
    calls=[];state=None
    for index,number in enumerate(CALLS):
        actual,raw,mode=struct.unpack_from('<3I',user,index*12)
        syscall,pid,parent,tid,kernel_raw,kernel_mode=struct.unpack_from('<6I',kernel,index*24)
        if actual!=number or syscall!=number or mode!=16 or kernel_mode!=0x113 or kernel_raw!=raw:
            raise ValueError('task syscall, mode or user/kernel result differs')
        entry=(pid,parent,tid)
        if state is None:state=entry
        elif entry!=state:raise ValueError('task entry state changed during session')
        calls.append({'number':number,'raw':raw,'user_mode':mode})
    pid,parent,tid=state
    checkpoint={'format':'osrec-task-checkpoint-v1','configuration':{'LOSCFG_PID_CONTAINER':False},
        'current_process':1,'current_task':3,'objects':[
            {'id':1,'type':'process','process_id':pid,'parent':2},
            {'id':2,'type':'process','process_id':parent,'parent':0},
            {'id':3,'type':'task','task_id':tid}],'calls':calls}
    return checkpoint

def export_live_task(args,user,kernel,kernel_hash):
    _,identity=prepare_source(args.kernel_root);checkpoint=decode_task(user,kernel)
    if checkpoint['objects'][0]['process_id']<=1 or checkpoint['objects'][1]['process_id']!=1:
        raise ValueError('task capture must come from a child of PID 1')
    report={'format':'osrec-live-task-checkpoint-v1','source_identity':identity,'checkpoint':checkpoint,
        'kernel_image_sha256':kernel_hash,'user_observations_sha256':digest(user),'kernel_observations_sha256':digest(kernel),
        'provenance':'actual LiteOS-A child-of-PID-1 SVC calls; entry fields sampled under scheduler lock',
        'scheduler_irq_reproduction':False,'native_layout_reproduction':False,'runtime_host_interaction':False}
    (args.out/'task-user-observations.bin').write_bytes(user)
    (args.out/'task-kernel-observations.bin').write_bytes(kernel)
    (args.out/'task-checkpoint.manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    return report
