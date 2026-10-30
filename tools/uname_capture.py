"""Source-bound OHOS uname capture with complete input/provider/output bytes."""
import json
import re
import struct
from klee_liteos import ROOT,digest
from freestanding_armv7 import run


def prepare_source(kernel_root):
    lock=json.loads((ROOT/'integrations/liteos_a/uname-source-lock.json').read_text())
    if run(['git','-C',kernel_root,'rev-parse','HEAD']).stdout.strip()!=lock['revision']:
        raise ValueError('uname kernel revision differs')
    for root in (kernel_root,ROOT/'build/ohos/kernel/liteos_a'):
        for name,expected in {lock['source']:lock['source_sha256'],**lock['headers']}.items():
            if digest((root/name).read_bytes())!=expected:raise ValueError('uname source/header changed')
    for name,expected in lock['libc_headers'].items():
        if digest((ROOT/'build/ohos/third_party/musl'/name).read_bytes())!=expected:raise ValueError('uname libc ABI header changed')
    source=(kernel_root/lock['source']).read_text();license_text=source[:source.index('*/')+2]
    body=re.search(r'int SysUname\(struct utsname \*name\)\s*\{.*?\n\}',source,re.S)
    if not body or digest(body[0].encode())!=lock['function_sha256']:raise ValueError('uname syscall body changed')
    generated=license_text+'\n#include "uname_model.h"\n'+body[0]+'\n'
    return generated,{'source':lock,'license':license_text,'generated_source_sha256':digest(generated.encode())}


def decode(user,kernel,dependencies):
    fault=(len(user),len(kernel),len(dependencies))==(3264,128,7072)
    if not fault and (len(user),len(kernel),len(dependencies))!=(1632,64,3328):raise ValueError('uname capture extents differ')
    count=8 if fault else 4
    events=[]
    for i in range(17 if fault else 8):
        inv,kind,arg,raw,size,mode=struct.unpack_from('<6I',dependencies,i*416)
        payload=dependencies[i*416+24:(i+1)*416]
        if size!=390 or mode!=0x113 or any(payload[390:]):raise ValueError('uname event size/mode/padding differs')
        events.append({'invocation':inv,'kind':kind,'argument':arg,'raw':raw,'size':size,'mode':mode,'memory':payload[:390].hex()})
    calls=[];cursor=0
    def event(inv,kind,arg,raw):
        nonlocal cursor
        if cursor>=len(events):raise ValueError('uname event missing')
        e=events[cursor];cursor+=1
        if tuple(e[k] for k in ('invocation','kind','argument','raw'))!=(inv,kind,arg,raw):raise ValueError('uname event order/outcome differs')
        return bytes.fromhex(e['memory'])
    for inv in range(count):
        number,pointer,raw,mode=struct.unpack_from('<4I',user,inv*408)
        kn,kp,kr,error=struct.unpack_from('<4I',kernel,inv*16)
        expected_pointer=inv-1 if inv in (2,3) else 0
        expected_raw=0 if inv<2 else 0xfffffffb if inv==5 else 0xfffffff2
        if (number,pointer,raw,mode,kn,kp,kr,error)!=(122,expected_pointer,expected_raw,16,122,expected_pointer,expected_raw,0):raise ValueError('uname identity/result/errno differs')
        before=bytes([0xa1+inv])*390
        output=user[inv*408+16:(inv+1)*408]
        input_raw=390 if inv in (2,3) else 195 if inv==4 else 0
        copied=event(inv,1,pointer,input_raw)
        if copied!=before[:390-input_raw]+bytes(input_raw):raise ValueError('uname input copy differs')
        after=before
        if input_raw==0:
            provider=event(inv,2,0,0xfffffffb if inv==5 else 0)
            if inv==5:
                if provider!=before:raise ValueError('uname failed provider changed buffer')
            else:
                for j in range(6):
                    field=provider[j*65:(j+1)*65]
                    if b'\0' not in field:raise ValueError('uname identity field is unterminated')
                    end=field.index(0)+1
                    if field[end:]!=before[j*65+end:(j+1)*65]:raise ValueError('uname untouched identity tail differs')
                output_raw=390 if inv==6 else 195 if inv==7 else 0
                if event(inv,3,0,output_raw)!=provider:raise ValueError('uname output copy differs')
                after=provider[:390-output_raw]+before[390-output_raw:]
        if output!=after+b'\x5a\xc3':raise ValueError('uname output/guard differs')
        calls.append({'number':number,'pointer_kind':pointer,'raw_bits':raw,'errno':error,'before':before.hex(),'after':after.hex()})
    if cursor!=len(events):raise ValueError('uname unused events')
    # Both calls query the same native identity while preserving different input tails.
    for j in range(6):
        fields=[bytes.fromhex(c['after'])[65*j:65*(j+1)].split(b'\0',1)[0] for c in calls[:2]]
        if fields[0]!=fields[1]:raise ValueError('uname identity differs across calls')
    checkpoint={'format':'osrec-uname-checkpoint-v1','calls':calls,'dependency_transcript':events,
        'identity_abi':'390 bytes: six 65-byte fields with preserved input tails'}
    if fault:checkpoint['fault_profile']='boundaries'
    return checkpoint


def export_capture(args,user,kernel,dependencies,kernel_hash):
    _,identity=prepare_source(args.kernel_root);checkpoint=decode(user,kernel,dependencies)
    metadata={'format':'osrec-live-uname-checkpoint-v1','source_identity':identity,'checkpoint':checkpoint,
        'kernel_image_sha256':kernel_hash,'entry_errno_fixture':0,
        'provenance':'actual LiteOS-A PID 1 uname SVC calls; forwarded native provider and safe-copy operations',
        'provider_internals_replayed':False,'runtime_host_interaction':False,
        'injected_boundary_faults':checkpoint.get('fault_profile')=='boundaries'}
    for name,data in (('user',user),('kernel',kernel),('dependencies',dependencies)):
        (args.out/('uname-'+name+'.bin')).write_bytes(data);metadata[name+'_sha256']=digest(data)
    (args.out/'uname-checkpoint.manifest.json').write_text(json.dumps(metadata,indent=2)+'\n')
    return metadata
