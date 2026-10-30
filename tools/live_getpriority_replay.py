"""Capture-normalized process-priority queries with ordered scalar boundaries."""
import json
import re
import struct
from klee_liteos import ROOT,digest
from freestanding_armv7 import run
CALLS=((0,0),(0,1),(0,0xffffffff),(1,0),(0xffffffff,0),(0,0))

def prepare_source(kernel_root):
    lock=json.loads((ROOT/'integrations/liteos_a/getpriority-source-lock.json').read_text())
    if run(['git','-C',kernel_root,'rev-parse','HEAD']).stdout.strip()!=lock['revision']:
        raise ValueError('getpriority kernel revision differs')
    for root in (kernel_root,ROOT/'build/ohos/kernel/liteos_a'):
        for relative,expected in {lock['source']:lock['source_sha256'],**lock['headers']}.items():
            if digest((root/relative).read_bytes())!=expected:raise ValueError('getpriority source/header changed')
    source=(kernel_root/lock['source']).read_text()
    match=re.search(r'int SysGetProcessPriority\(int which, int who\)\s*\{.*?\n\}',source,re.S)
    if not match or digest(match[0].encode())!=lock['function_sha256']:raise ValueError('getpriority body changed')
    license_text=source[:source.index('*/')+2]
    generated=license_text+'\nextern unsigned int LOS_GetCurrProcessID(void);\nextern int OsGetProcessPriority(int which,int who);\n'+match[0]+'\n'
    return generated,{'source':lock,'license':license_text,'generated_source_sha256':digest(generated.encode()),
        'type_contract':'32-bit int/unsigned int and argument/return bits; ordered scalar boundary model'}

def decode_getpriority(user,transcript):
    if len(user)!=96:raise ValueError('getpriority user observation size differs')
    calls=[]
    for index,(which,who) in enumerate(CALLS):
        a,b,raw,mode=struct.unpack_from('<4I',user,index*16)
        if (a,b)!=(which,who) or mode!=16:raise ValueError('getpriority arguments or user mode differ')
        calls.append({'which_bits':which,'who_bits':who,'raw_bits':raw,'user_mode':mode})
    if not transcript or len(transcript)%20 or len(transcript)>240:
        raise ValueError('getpriority dependency transcript size differs')
    events=[]
    for invocation,kind,which,who,raw in struct.iter_unpack('<5I',transcript):
        if invocation>=6 or kind not in (1,2) or (kind==1 and (which or who)):
            raise ValueError('invalid getpriority boundary event')
        events.append({'invocation':invocation,'kind':kind,'which_bits':which,'who_bits':who,'result_bits':raw})
    return {'format':'osrec-getpriority-checkpoint-v1','calls':calls,'dependency_transcript':events}

def export_live_getpriority(args,user,transcript,kernel_hash):
    _,identity=prepare_source(args.kernel_root);checkpoint=decode_getpriority(user,transcript)
    report={'format':'osrec-live-getpriority-checkpoint-v1','source_identity':identity,'checkpoint':checkpoint,
        'kernel_image_sha256':kernel_hash,'user_observations_sha256':digest(user),'dependency_transcript_sha256':digest(transcript),
        'provenance':'actual LiteOS-A PID 1 SVC calls and root dependency boundaries',
        'scheduler_irq_reproduction':False,'dependency_internals_replayed':False,'runtime_host_interaction':False}
    (args.out/'getpriority-user-observations.bin').write_bytes(user)
    (args.out/'getpriority-dependencies.bin').write_bytes(transcript)
    (args.out/'getpriority-checkpoint.manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    return report
