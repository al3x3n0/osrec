"""Reviewed SysUgetrlimit capture, provider/copy boundary validation and source binding."""
import json
import re
import struct
from klee_liteos import ROOT,digest
from freestanding_armv7 import run


def prepare_source(kernel_root):
    lock=json.loads((ROOT/'integrations/liteos_a/rlimit-source-lock.json').read_text())
    if run(['git','-C',kernel_root,'rev-parse','HEAD']).stdout.strip()!=lock['revision']:
        raise ValueError('rlimit kernel revision differs')
    for root in (kernel_root,ROOT/'build/ohos/kernel/liteos_a'):
        for name,expected in {lock['source']:lock['source_sha256'],**lock['headers']}.items():
            if digest((root/name).read_bytes())!=expected:raise ValueError('rlimit source/header changed')
    for name,expected in lock['libc_headers'].items():
        if digest((ROOT/'build/ohos/third_party/musl'/name).read_bytes())!=expected:raise ValueError('rlimit libc ABI header changed')
    source=(kernel_root/lock['source']).read_text();license_text=source[:source.index('*/')+2]
    body=re.search(r'int SysUgetrlimit\(int resource, unsigned long long k_rlim\[2\]\)\s*\{.*?\n\}',source,re.S)
    if not body or digest(body[0].encode())!=lock['function_sha256']:raise ValueError('rlimit syscall body changed')
    generated=license_text+'\n#include "rlimit_model.h"\n'+body[0]+'\n'
    return generated,{'source':lock,'license':license_text,'generated_source_sha256':digest(generated.encode())}


def decode(user,kernel,dependencies):
    if (len(user),len(kernel),len(dependencies))!=(192,96,360):raise ValueError('rlimit capture extents differ')
    events=[dict(zip(('invocation','kind','argument_bits','raw_bits','bytes','cur_lo','cur_hi','max_lo','max_hi'),row)) for row in struct.iter_unpack('<9I',dependencies)]
    calls=[];cursor=0;before=[0x11223344,0x55667788,0x99aabbcc,0xddeeff00]
    for inv in range(6):
        number,resource,raw,mode,*output=struct.unpack_from('<8I',user,inv*32)
        kn,kr,kv,error=struct.unpack_from('<4I',kernel,inv*16)
        expected_resource=1 if inv==1 else 0xffffffff if inv==2 else 0 if inv==5 else 7
        pointer_kind=1 if inv in (3,5) else 2 if inv==4 else 0
        expected_raw=(-22 if inv in (2,5) else -14 if inv in (3,4) else 0)&0xffffffff
        if (number,resource,mode,kn,kr,kv,error)!=(191,expected_resource,16,191,resource,raw,0) or raw!=expected_raw:
            raise ValueError('rlimit call identity/result/errno differs')
        if cursor>=len(events):raise ValueError('rlimit provider event missing')
        provider=events[cursor];cursor+=1
        if tuple(provider[k] for k in ('invocation','kind','argument_bits','bytes'))!=(inv,1,resource,0):raise ValueError('rlimit provider order/argument differs')
        payload=[provider[k] for k in ('cur_lo','cur_hi','max_lo','max_hi')]
        after=before
        if inv in (2,5):
            if provider['raw_bits']!=0xffffffea or any(payload):raise ValueError('rlimit provider failure differs')
        else:
            if provider['raw_bits'] or (payload[0]|payload[1]<<32)>(payload[2]|payload[3]<<32):raise ValueError('rlimit provider success differs')
            if cursor>=len(events):raise ValueError('rlimit copy event missing')
            copy=events[cursor];cursor+=1
            if tuple(copy.values())!=(inv,2,pointer_kind,16 if inv in (3,4) else 0,16,*payload):raise ValueError('rlimit copy outcome/payload differs')
            if inv<2:after=payload
        if output!=after:raise ValueError('rlimit user output differs from copy effects')
        calls.append({'number':number,'resource_bits':resource,'pointer_kind':pointer_kind,'raw_bits':raw,'errno':error,'before':before,'after':after})
    if cursor!=len(events):raise ValueError('rlimit capture has unused events')
    return {'format':'osrec-rlimit-checkpoint-v1','calls':calls,'dependency_transcript':events,
        'limit_abi':'16 bytes: unsigned 64-bit current and maximum limits'}


def export_capture(args,user,kernel,dependencies,kernel_hash):
    _,identity=prepare_source(args.kernel_root);checkpoint=decode(user,kernel,dependencies)
    metadata={'format':'osrec-live-rlimit-checkpoint-v1','source_identity':identity,'checkpoint':checkpoint,
        'kernel_image_sha256':kernel_hash,'entry_errno_fixture':0,
        'provenance':'actual LiteOS-A PID 1 ugetrlimit SVC calls; forwarded native getrlimit and safe-copy operations',
        'provider_internals_replayed':False,'runtime_host_interaction':False}
    for name,data in (('user',user),('kernel',kernel),('dependencies',dependencies)):
        (args.out/('rlimit-'+name+'.bin')).write_bytes(data);metadata[name+'_sha256']=digest(data)
    (args.out/'rlimit-checkpoint.manifest.json').write_text(json.dumps(metadata,indent=2)+'\n')
    return metadata
