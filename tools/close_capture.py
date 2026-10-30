"""Reviewed SysClose capture with descriptor rollback, release and errno propagation."""
import json
import re
import struct
from klee_liteos import ROOT,digest
from freestanding_armv7 import run


def prepare_source(kernel_root):
    lock=json.loads((ROOT/'integrations/liteos_a/close-source-lock.json').read_text())
    if run(['git','-C',kernel_root,'rev-parse','HEAD']).stdout.strip()!=lock['revision']:raise ValueError('close kernel revision differs')
    for root in (kernel_root,ROOT/'build/ohos/kernel/liteos_a'):
        for name,expected in {lock['source']:lock['source_sha256'],**lock['headers']}.items():
            if digest((root/name).read_bytes())!=expected:raise ValueError('close source/header changed')
    for base,key in ((ROOT/'build/ohos/third_party/musl','libc_headers'),(ROOT/'build/ohos/third_party/NuttX','vfs_sources')):
        for name,expected in lock[key].items():
            if digest((base/name).read_bytes())!=expected:raise ValueError('close provider/ABI source changed')
    source=(kernel_root/lock['source']).read_text();license_text=source[:source.index('*/')+2]
    body=re.search(r'int SysClose\(int fd\)\s*\{.*?\n\}',source,re.S)
    if not body or digest(body[0].encode())!=lock['function_sha256']:raise ValueError('close syscall body changed')
    generated=license_text+'\n#include "close_model.h"\n'+body[0]+'\n'
    return generated,{'source':lock,'license':license_text,'generated_source_sha256':digest(generated.encode())}


def decode(user,kernel,dependencies):
    if (len(user),len(kernel),len(dependencies))!=(80,220,720):raise ValueError('close capture extents differ')
    keys=('invocation','kind','argument','argument2','raw','error','before_map','before_allocated','before_cloexec','after_map','after_allocated','after_cloexec')
    events=[dict(zip(keys,row)) for row in struct.iter_unpack('<12I',dependencies)]
    system=struct.unpack_from('<I',kernel,16)[0]
    if not 3<=system<1024:raise ValueError('close initial system descriptor differs')
    state=[system,1,1];calls=[];cursor=0
    def event(inv,kind,arg,arg2,raw,error,after):
        nonlocal state,cursor
        if cursor>=len(events):raise ValueError('close event missing')
        e=events[cursor];cursor+=1
        if list(e.values())!=[inv,kind,arg,arg2,raw,error,*state,*after]:raise ValueError('close event order/state/outcome differs')
        state=list(after)
    for inv in range(5):
        number,fd,raw,mode=struct.unpack_from('<4I',user,inv*16)
        kn,kf,kr,error,*witness=struct.unpack_from('<11I',kernel,inv*44)
        descriptor=0xffffffff if inv==3 else 1024 if inv==4 else 4
        expected_error=5 if inv==0 else 0 if inv==1 else 9
        expected_raw=(-expected_error)&0xffffffff
        if (number,fd,raw,mode,kn,kf,kr,error,witness[-1])!=(6,descriptor,expected_raw,16,6,descriptor,expected_raw,expected_error,0x113):raise ValueError('close identity/result/errno differs')
        before=list(state)
        mapped=system if inv<2 else 0xffffffff
        detached=[0xffffffff,*state[1:]]
        event(inv,1,fd,0,mapped,0,detached)
        event(inv,2,mapped,0,0 if inv==1 else 0xffffffff,expected_error,detached)
        if inv==1:event(inv,5,fd,0,0,0,[0xffffffff,0,0])
        else:event(inv,4,fd,mapped,0,expected_error,before)
        if witness[:-1]!=before+state:raise ValueError('close entry/effect state differs')
        calls.append({'number':number,'fd_bits':fd,'raw_bits':raw,'errno':error,'before':before,'after':list(state)})
    if cursor!=len(events):raise ValueError('close unused events')
    return {'format':'osrec-close-checkpoint-v1','calls':calls,'dependency_transcript':events,
        'initial_system_fd':system,'injected_first_close_failure':True,'state_scope':'one process descriptor, allocation and close-on-exec flags; modeled system-descriptor lifetime'}


def export_capture(args,user,kernel,dependencies,kernel_hash):
    _,identity=prepare_source(args.kernel_root);checkpoint=decode(user,kernel,dependencies)
    metadata={'format':'osrec-live-close-checkpoint-v1','source_identity':identity,'checkpoint':checkpoint,
        'kernel_image_sha256':kernel_hash,'entry_errno_fixture':0,'injected_first_close_failure':True,
        'provenance':'actual LiteOS-A PID 1 close SVC calls; native descriptor operations, with first close provider returning scoped EIO before release',
        'provider_internals_replayed':False,'runtime_host_interaction':False}
    for name,data in (('user',user),('kernel',kernel),('dependencies',dependencies)):
        (args.out/('close-'+name+'.bin')).write_bytes(data);metadata[name+'_sha256']=digest(data)
    (args.out/'close-checkpoint.manifest.json').write_text(json.dumps(metadata,indent=2)+'\n')
    return metadata
