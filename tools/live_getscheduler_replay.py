"""Reviewed process-mode sched_getscheduler dependency capture."""
import json
import re
import struct
from klee_liteos import ROOT,digest
from freestanding_armv7 import run
CALLS=(0,1,0xffffffff,63)

def prepare_source(kernel_root,task=False):
    lock=json.loads((ROOT/('integrations/liteos_a/getscheduler-task-source-lock.json' if task else 'integrations/liteos_a/getscheduler-source-lock.json')).read_text())
    if run(['git','-C',kernel_root,'rev-parse','HEAD']).stdout.strip()!=lock['revision']:
        raise ValueError('getscheduler kernel revision differs')
    for root in (kernel_root,ROOT/'build/ohos/kernel/liteos_a'):
        for relative,expected in {lock['source']:lock['source_sha256'],**lock['headers']}.items():
            if digest((root/relative).read_bytes())!=expected:raise ValueError('getscheduler source/header changed')
    source=(kernel_root/lock['source']).read_text()
    body=re.search(r'int SysSchedGetScheduler\(int id, int flag\)\s*\{.*?\n\}',source,re.S)
    if not body or digest(body[0].encode())!=lock['function_sha256']:raise ValueError('getscheduler body changed')
    license_text=source[:source.index('*/')+2]
    generated=license_text+'\n#include "getscheduler_model.h"\n'+body[0]+'\n'
    return generated,{'source':lock,'license':license_text,'generated_source_sha256':digest(generated.encode()),
        'type_contract':('32-bit int/unsigned int; 16-bit callback policy; normalized task identity and typed callback binding; task mode only; process dependencies trap' if task else '32-bit signed int arguments, return and policy output; process mode only; task operations trap')}

def decode_getscheduler(user,transcript):
    if len(user)!=64 or len(transcript)!=120:raise ValueError('getscheduler observation size differs')
    calls=[]
    for i,id in enumerate(CALLS):
        a,flag,raw,mode=struct.unpack_from('<4I',user,i*16)
        if (a,flag,mode)!=(id,0,16):raise ValueError('getscheduler arguments or mode differ')
        calls.append({'id_bits':id,'flag_bits':0,'raw_bits':raw,'user_mode':mode})
    events=[]
    for inv,kind,id,raw,policy,written in struct.iter_unpack('<6I',transcript):
        events.append({'invocation':inv,'kind':kind,'id_bits':id,'result_bits':raw,'policy_bits':policy,'policy_written':written})
    expected=((0,1,0),(0,2,1),(1,2,1),(2,2,0xffffffff),(3,2,63))
    for event,(inv,kind,id) in zip(events,expected):
        if (event['invocation'],event['kind'],event['id_bits'])!=(inv,kind,id):raise ValueError('getscheduler dependency order/arguments differ')
        raw=event['result_bits'];policy=event['policy_bits'];written=event['policy_written']
        if kind==1:
            if (raw,policy,written)!=(1,0,0):raise ValueError('getscheduler current PID differs')
        else:
            if inv<2:
                if raw!=0 or written!=1 or policy not in (0,1,2,6):raise ValueError('getscheduler success policy output differs')
                result=policy
            else:
                expected_error=0xffffffea if inv==2 else 0xfffffffd
                if (raw,policy,written)!=(expected_error,0,0):raise ValueError('getscheduler failure must have no policy output')
                result=raw
            if calls[inv]['raw_bits']!=result:raise ValueError('getscheduler return differs from boundary outcome')
    if calls[0]['raw_bits']!=calls[1]['raw_bits']:raise ValueError('same process policy differs')
    return {'format':'osrec-getscheduler-checkpoint-v1','calls':calls,'dependency_transcript':events}

def export_live_getscheduler(args,user,transcript,kernel_hash):
    task=getattr(args,'getscheduler_task',False)
    _,identity=prepare_source(args.kernel_root,task);checkpoint=(decode_task_getscheduler if task else decode_getscheduler)(user,transcript)
    report={'format':'osrec-live-getscheduler-checkpoint-v2' if task else 'osrec-live-getscheduler-checkpoint-v1','source_identity':identity,'checkpoint':checkpoint,
        'kernel_image_sha256':kernel_hash,'user_observations_sha256':digest(user),'dependency_transcript_sha256':digest(transcript),
        'provenance':('actual LiteOS-A PID 1 SVC calls, real task permissions and forwarded callback under syscall scheduler lock; flag=-1' if task else 'actual LiteOS-A PID 1 SVC calls and root dependency outcomes; flag=0 only'),
        'scheduler_irq_reproduction':False,'dependency_internals_replayed':False,'runtime_host_interaction':False}
    if task:report['profile']='task'
    for suffix,data in (('user-observations',user),('dependencies',transcript)):
        (args.out/f'getscheduler-{suffix}.bin').write_bytes(data)
    (args.out/'getscheduler-checkpoint.manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

def decode_task_getscheduler(user,transcript):
    if len(user)!=64 or len(transcript)!=192:raise ValueError('task getscheduler observation size differs')
    calls=[]
    for inv,(id,flag,raw,mode) in enumerate(struct.iter_unpack('<4I',user)):
        if flag!=0xffffffff or mode!=16:raise ValueError('task getscheduler flag or user mode differs')
        if inv==0 and not 0<id<127:raise ValueError('current task ID outside reviewed bounds')
        if inv and id!=(0xffffffff,127,0)[inv-1]:raise ValueError('task getscheduler ID differs')
        calls.append({'id_bits':id,'flag_bits':flag,'raw_bits':raw,'user_mode':mode})
    events=[dict(zip(('invocation','kind','id_bits','result_bits','policy_bits','policy_written'),row)) for row in struct.iter_unpack('<6I',transcript)]
    expected=((0,3),(0,4),(0,5),(1,3),(2,3),(2,4),(3,3),(3,4))
    for event,(inv,kind) in zip(events,expected):
        if (event['invocation'],event['kind'],event['id_bits'])!=(inv,kind,calls[inv]['id_bits']):raise ValueError('task getscheduler event order/identity differs')
        raw,policy,written=(event[k] for k in ('result_bits','policy_bits','policy_written'))
        if kind==3:
            if (raw,policy,written)!=(128,0,0):raise ValueError('task limit snapshot differs')
        elif kind==4:
            if (raw,policy,written)!=({0:0,2:22,3:1}[inv],0,0):raise ValueError('task permission outcome differs')
        else:
            if raw!=0 or policy not in (0,1,2,3,6) or written!=1:raise ValueError('task callback outcome differs')
            if calls[inv]['raw_bits']!=policy:raise ValueError('task policy return differs')
    if [c['raw_bits'] for c in calls[1:]]!=[0xffffffea,0xffffffea,0xffffffff]:raise ValueError('task error return differs')
    return {'format':'osrec-getscheduler-task-checkpoint-v1','task_limit':128,'calls':calls,'dependency_transcript':events}


def verify_task_config(config):
    """Accept the two canonical native capture defines exactly once."""
    for name in ('OSREC_GETSCHEDULER_CAPTURE','OSREC_GETSCHEDULER_TASK_CAPTURE'):
        definitions=re.findall(r'(?m)^[ \t]*#[ \t]*define[ \t]+'+name+r'\b[^\n]*$',config)
        if definitions!=['#define '+name+' 1'] or re.search(r'(?m)^[ \t]*#[ \t]*undef[ \t]+'+name+r'\b',config):
            raise ValueError('task capture config differs')
