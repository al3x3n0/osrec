"""Reviewed LiteOS clock query capture and ABI-preserving source binding."""
import json
import re
import struct
from klee_liteos import ROOT,digest
from freestanding_armv7 import run


def prepare_source(kernel_root):
    lock=json.loads((ROOT/'integrations/liteos_a/clock-source-lock.json').read_text())
    if run(['git','-C',kernel_root,'rev-parse','HEAD']).stdout.strip()!=lock['revision']:
        raise ValueError('clock kernel revision differs')
    for root in (kernel_root,ROOT/'build/ohos/kernel/liteos_a'):
        for name,expected in {lock['source']:lock['source_sha256'],**lock['headers']}.items():
            if digest((root/name).read_bytes())!=expected:raise ValueError('clock source/header changed')
    source=(kernel_root/lock['source']).read_text();license_text=source[:source.index('*/')+2]
    for name,expected in lock['libc_headers'].items():
        if digest((ROOT/'build/ohos/third_party/musl'/name).read_bytes())!=expected:raise ValueError('clock libc ABI header changed')
    bodies=[]
    for name,expected in lock['functions'].items():
        match=re.search(r'int '+name+r'\(clockid_t clockID, struct timespec \*tp\)\s*\{.*?\n\}',source,re.S)
        if not match or digest(match[0].encode())!=expected:raise ValueError('clock syscall body changed')
        bodies.append(match[0])
    generated=license_text+'\n#include "clock_model.h"\n'+'\n'.join(bodies)+'\n'
    return generated,{'source':lock,'license':license_text,'generated_source_sha256':digest(generated.encode())}


def decode(user,kernel,dependencies):
    if (len(user),len(kernel),len(dependencies))!=(320,160,560):raise ValueError('clock capture extents differ')
    events=[dict(zip(('invocation','kind','argument_bits','raw_bits','errno','sec_lo','sec_hi','nsec_bits','padding','bytes'),row)) for row in struct.iter_unpack('<10I',dependencies)]
    calls=[];cursor=0
    for inv in range(10):
        number,id,raw,mode,*output=struct.unpack_from('<8I',user,inv*32)
        kn,ki,kr,error=struct.unpack_from('<4I',kernel,inv*16)
        local=inv%5;expected_number=263 if inv<5 else 264
        expected_id=1 if local==1 else 0xffffffff if local==2 else 0
        if (number,id,mode,kn,ki,kr)!=(expected_number,expected_id,16,number,id,raw):raise ValueError('clock call identity/mode differs')
        pointer_kind=1 if local==3 else 2 if local==4 else 0
        before=[0x11223344,0x55667788,0x99aabbcc,0xddeeff00];after=before
        expected_error=22 if local in (2,3) else 14 if local==4 else 0
        expected_raw=(-expected_error)&0xffffffff
        if (raw,error)!=(expected_raw,expected_error):raise ValueError('clock return/errno differs')
        if local!=3:
            if cursor>=len(events):raise ValueError('clock provider event missing')
            provider=events[cursor];cursor+=1
            kind=1 if number==263 else 2
            if (provider['invocation'],provider['kind'],provider['argument_bits'],provider['bytes'])!=(inv,kind,id,0):raise ValueError('clock provider order/arguments differ')
            if local==2:
                if (provider['raw_bits'],provider['errno'],provider['sec_lo'],provider['sec_hi'],provider['nsec_bits'],provider['padding'])!=(0xffffffff,22,0,0,0,0):raise ValueError('clock provider failure differs')
            else:
                if provider['raw_bits'] or provider['errno'] or provider['sec_hi']>=1<<31 or provider['nsec_bits']>=1000000000 or provider['padding']:raise ValueError('clock provider output differs')
                if number==264 and (provider['sec_lo'],provider['sec_hi'],provider['nsec_bits'])!=(0,0,1000):raise ValueError('clock resolution differs from pinned provider')
                if cursor>=len(events):raise ValueError('clock copy event missing')
                copy=events[cursor];cursor+=1
                expected=(inv,3,pointer_kind,16 if local==4 else 0,0,provider['sec_lo'],provider['sec_hi'],provider['nsec_bits'],0,16)
                if tuple(copy.values())!=expected:raise ValueError('clock copy event differs')
                if local!=4:after=[provider['sec_lo'],provider['sec_hi'],provider['nsec_bits'],0]
        if output!=after:raise ValueError('clock user output differs from dependency effects')
        calls.append({'number':number,'clock_id_bits':id,'pointer_kind':pointer_kind,'raw_bits':raw,'errno':error,'before':before,'after':after})
    if cursor!=len(events):raise ValueError('clock capture has unused events')
    return {'format':'osrec-clock-checkpoint-v1','calls':calls,'dependency_transcript':events,
        'time_abi':'16-byte OHOS timespec: signed 64-bit seconds, signed 32-bit nanoseconds and 4 zero padding bytes; preserved in AArch64 replay'}


def export_capture(args,user,kernel,dependencies,kernel_hash):
    _,identity=prepare_source(args.kernel_root);checkpoint=decode(user,kernel,dependencies)
    for name,data in (('user',user),('kernel',kernel),('dependencies',dependencies)):
        (args.out/('clock-'+name+'.bin')).write_bytes(data)
    metadata={'format':'osrec-live-clock-checkpoint-v1','source_identity':identity,'checkpoint':checkpoint,
        'kernel_image_sha256':kernel_hash,'user_sha256':digest(user),'kernel_sha256':digest(kernel),'dependencies_sha256':digest(dependencies),
        'provenance':'actual PID 1 LiteOS-A SVC clock_gettime32/getres_time32; forwarded native provider and user-copy calls',
        'entry_errno_fixture':0,'provider_internals_replayed':False,'live_clock_service_required':False}
    (args.out/'clock-checkpoint.manifest.json').write_text(json.dumps(metadata,indent=2)+'\n')
    return metadata
