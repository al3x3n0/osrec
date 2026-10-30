"""Reviewed SysDup capture with descriptor allocation, aliases, flags and native file references."""
import json
import re
import struct
from klee_liteos import ROOT,digest
from freestanding_armv7 import run


def prepare_source(kernel_root):
    lock=json.loads((ROOT/'integrations/liteos_a/dup-source-lock.json').read_text())
    if run(['git','-C',kernel_root,'rev-parse','HEAD']).stdout.strip()!=lock['revision']:raise ValueError('dup kernel revision differs')
    for root in (kernel_root,ROOT/'build/ohos/kernel/liteos_a'):
        for name,expected in {lock['source']:lock['source_sha256'],**lock['headers']}.items():
            if digest((root/name).read_bytes())!=expected:raise ValueError('dup source/header changed')
    for base,key in ((ROOT/'build/ohos/third_party/musl','libc_headers'),(ROOT/'build/ohos/third_party/NuttX','vfs_sources')):
        for name,expected in lock[key].items():
            if digest((base/name).read_bytes())!=expected:raise ValueError('dup provider/ABI source changed')
    source=(kernel_root/lock['source']).read_text();license_text=source[:source.index('*/')+2]
    body=re.search(r'int SysDup\(int fd\)\s*\{.*?\n\}',source,re.S)
    if not body or digest(body[0].encode())!=lock['function_sha256']:raise ValueError('dup syscall body changed')
    generated=license_text+'\n#include "dup_model.h"\n'+body[0]+'\n'
    return generated,{'source':lock,'license':license_text,'generated_source_sha256':digest(generated.encode())}


def decode(user,kernel,dependencies):
    if (len(user),len(kernel),len(dependencies))!=(80,520,1248):raise ValueError('dup capture extents differ')
    keys=('invocation','kind','argument','argument2','raw','error',*[f'before_{i}' for i in range(10)],*[f'after_{i}' for i in range(10)])
    events=[dict(zip(keys,row)) for row in struct.iter_unpack('<26I',dependencies)]
    limit=struct.unpack_from('<I',kernel,16)[0];system=struct.unpack_from('<I',kernel,24)[0]
    if not 8<=limit<=65536 or not 3<=system<limit:raise ValueError('dup initial system descriptor/bound differs')
    state=[system,1,1,0xffffffff,0,0,0xffffffff,0,0,1];calls=[];cursor=0
    def event(inv,kind,arg,arg2,raw,after):
        nonlocal state,cursor
        if cursor>=len(events):raise ValueError('dup event missing')
        e=events[cursor];cursor+=1
        if list(e.values())!=[inv,kind,arg,arg2,raw,0,*state,*after]:raise ValueError('dup event order/state/outcome differs')
        state=list(after)
    for inv in range(5):
        number,fd,raw,mode=struct.unpack_from('<4I',user,inv*16)
        kn,kf,kr,error,kl,km,*witness=struct.unpack_from('<26I',kernel,inv*104)
        descriptor=5 if inv==2 else 0xffffffff if inv==3 else 1024 if inv==4 else 4
        expected_raw=0xffffffe8 if inv==0 else 5 if inv==1 else 6 if inv==2 else 0xfffffff7
        if (number,fd,raw,mode,kn,kf,kr,error,kl,km)!=(41,descriptor,expected_raw,16,41,descriptor,expected_raw,0,limit,0x113):raise ValueError('dup identity/result/errno/bound differs')
        before=list(state);mapped=system if inv<3 else 0xffffffff
        event(inv,1,fd,0,mapped,state)
        if inv<3:
            after=list(state)
            if inv:after[3*inv+1]=1
            event(inv,2,0,0,0xffffffff if inv==0 else inv+4,after)
            if inv:
                after=list(state);after[9]+=1;event(inv,3,system,0,0,after)
                after=list(state);after[3*inv]=system;event(inv,4,inv+4,system,0,after)
        if witness!=before+state:raise ValueError('dup entry/effect state differs')
        calls.append({'number':number,'fd_bits':fd,'raw_bits':raw,'errno':error,'before':before,'after':list(state)})
    if cursor!=len(events):raise ValueError('dup unused events')
    return {'format':'osrec-dup-checkpoint-v1','calls':calls,'dependency_transcript':events,
        'initial_system_fd':system,'system_fd_limit':limit,'injected_first_allocation_failure':True,
        'state_scope':'process descriptors 4..6 with allocation/cloexec flags; shared native system-file reference count'}


def export_capture(args,user,kernel,dependencies,kernel_hash):
    _,identity=prepare_source(args.kernel_root);checkpoint=decode(user,kernel,dependencies)
    metadata={'format':'osrec-live-dup-checkpoint-v1','source_identity':identity,'checkpoint':checkpoint,
        'kernel_image_sha256':kernel_hash,'entry_errno_fixture':0,'injected_first_allocation_failure':True,
        'provenance':'actual LiteOS-A PID 1 dup SVC calls; native descriptor operations and file references, with first allocation returning scoped failure before changes',
        'provider_internals_replayed':False,'runtime_host_interaction':False}
    for name,data in (('user',user),('kernel',kernel),('dependencies',dependencies)):
        (args.out/('dup-'+name+'.bin')).write_bytes(data);metadata[name+'_sha256']=digest(data)
    (args.out/'dup-checkpoint.manifest.json').write_text(json.dumps(metadata,indent=2)+'\n')
    return metadata
