"""Source-bound shared-state OHOS file session and strict boundary/effect validation."""
import json,re,struct
from klee_liteos import ROOT,digest
from freestanding_armv7 import run
from file_profile import CASES,COUNT,MAIN,MISSING,before
ROOTS=('SysOpen','SysOpenat','SysWrite','SysRead','SysLseek64','SysFstat64','SysStat','SysDup2','SysClose')


def prepare_source(kernel_root):
    lock=json.loads((ROOT/'integrations/liteos_a/files-source-lock.json').read_text())
    if run(['git','-C',kernel_root,'rev-parse','HEAD']).stdout.strip()!=lock['revision']:raise ValueError('files kernel revision differs')
    for base in (kernel_root,ROOT/'build/ohos/kernel/liteos_a'):
        for name,h in {lock['source']:lock['source_sha256'],**lock['headers']}.items():
            if digest((base/name).read_bytes())!=h:raise ValueError('files source/header changed')
    for base,key in ((ROOT/'build/ohos/third_party/musl','libc_headers'),(ROOT/'build/ohos/third_party/NuttX','vfs_sources')):
        for name,h in lock[key].items():
            if digest((base/name).read_bytes())!=h:raise ValueError('files provider/ABI source changed')
    source=(kernel_root/lock['source']).read_text();license_text=source[:source.index('*/')+2];bodies=[]
    for name in ('GetPath',*ROOTS):
        body=re.search(r'(?:static )?(?:int|ssize_t|off64_t) '+name+r'\([^\n]*\)\s*\{.*?\n\}',source,re.S)
        if not body or digest(body[0].encode())!=lock['functions'][name]:raise ValueError('files syscall/helper body changed')
        bodies.append(body[0])
    macro=(kernel_root/'syscall/syscall_pub.h').read_text();check=re.search(r'#define CHECK_ASPACE\(.*?\n\s*\} while \(0\)',macro,re.S)[0]
    generated=license_text+'\n#include "files_model.h"\n'+check+'\n'+'\n\n'.join(bodies)+'\n'
    return generated,{'source':lock,'license':license_text,'generated_source_sha256':digest(generated.encode())}


def sequence(index):
    nr,args,_,_=CASES[index]
    if nr==5 or nr==322:
        p=args[0] if nr==5 else args[1]
        if p==3:return [1]
        if p==2:return [1,2,4,6,16]
        return [1,2]+([3] if nr==5 else [])+[4,5,6]
    if nr==63:return [7,7] if index==24 else [7,7,17] if index==1 else [7,7,17,18,15,19,5,20]
    if nr==4:return [] if index in (22,23) else [22,21,23,7,8]
    if nr==3:return [] if index in (28,31) else [7,9]
    if nr==140:return [7,10] if index==25 else [7,10,11]
    if nr==197:return [7,12] if index==19 else [7,12,11]
    if nr==106:return [13] if index==20 else [1,13]+([11] if index in (12,26) else [])+[6]
    if nr==6:return [14,15,16]
    raise ValueError('files unrecognized syscall')


class State:
    def __init__(self,abi):
        self.values=[0xffffffff,0,0]*3+[0]*6;self.systems=[];self.data=bytearray();self.path=False;self.abi=abi;self.lock=0;self.error=0
    def slot(self,fd):
        if fd not in (4,5,6):raise ValueError('files descriptor outside bounded slots')
        return 3*(fd-4)
    def file(self,fd):
        if fd not in self.systems:raise ValueError('files unknown system descriptor')
        return 9+3*self.systems.index(fd)
    def pos(self,i):return self.values[i+1]|self.values[i+2]<<32
    def setpos(self,i,pos):
        if not 0<=pos<=8:raise ValueError('files position outside reviewed extent')
        self.values[i+1]=pos;self.values[i+2]=0
    def apply(self,e,index):
        s=self.values;a,b,c,raw,error=(e[k] for k in ('a','b','c','raw','error'));payload=bytes.fromhex(e['data']);kind=e['kind']
        expected=0;data=b'';nr,args,_,_=CASES[index]
        if kind==1:
            expected=0xfffffff2 if a==3 else 0
            data=(MAIN if a==1 else MISSING) if not expected else b''
            if a not in (1,2,3) or self.path:raise ValueError('files path copy identity/lifetime differs')
            self.path=not expected
        elif kind==2:
            fd=next((i+4 for i in range(3) if not s[3*i+1]),None)
            if fd is None:raise ValueError('files bounded allocator exhausted')
            expected=fd;s[self.slot(fd)+1]=1
        elif kind in (3,20):s[self.slot(a)+2]=int(kind==3)
        elif kind==4:
            mode=args[2] if nr==5 else args[3];data=struct.pack('<I',mode)
            if a!=0xffffff9c or b not in (1,2) or c!=(args[1] if nr==5 else args[2]):raise ValueError('files open arguments differ')
            if b==2:expected=0xffffffff;self.error=2
            else:
                if len(self.systems)>=2 or raw<3 or raw>=self.abi[4] or raw in self.systems:raise ValueError('files open system identity differs')
                self.systems.append(raw);expected=raw;i=self.file(raw);s[i]=1;self.setpos(i,0)
                if c&0x200:self.data.clear()
        elif kind==5:
            i=self.slot(a)
            if b not in self.systems or not s[i+1]:raise ValueError('files association identity/allocation differs')
            s[i]=b
        elif kind==6:
            if (a,b,c)!=(1,1,0) or not self.path:raise ValueError('files path release differs')
            self.path=False
        elif kind==7:expected=s[self.slot(a)] if a in (4,5,6) else 0xffffffff
        elif kind in (8,9):
            if b!=1 or c>8:raise ValueError('files I/O extent/pointer differs')
            if a==0xffffffff:expected=0xffffffff;self.error=9;data=before(index)[:c] if kind==8 else b''
            else:
                i=self.file(a);pos=self.pos(i)
                if kind==8:
                    data=before(index)[:c];expected=c
                    end=pos+c
                    if end>8:raise ValueError('files write exceeds extent')
                    if end>len(self.data):self.data.extend(bytes(end-len(self.data)))
                    self.data[pos:end]=data;self.setpos(i,end)
                else:data=bytes(self.data[pos:pos+c]);expected=len(data);self.setpos(i,pos+expected)
        elif kind==10:
            low=args[2];data=struct.pack('<I',low)
            if (b,c)!=(args[4],args[1]):raise ValueError('files seek arguments differ')
            if a==0xffffffff:expected=0xfffffff7;self.error=9
            else:
                i=self.file(a);offset=(c<<32)|low
                if offset>>63:offset-=1<<64
                pos=offset+(self.pos(i) if b==1 else len(self.data) if b==2 else 0)
                self.setpos(i,pos);data+=struct.pack('<Q',pos)
        elif kind==11:
            if c or b not in (8,self.abi[1]) or a not in (1,2):raise ValueError('files copy extent/argument differs')
            expected=b if a==2 else 0;data=payload
            if len(data)!=b:raise ValueError('files copy payload extent differs')
        elif kind in (12,13):
            if c or b!=1:raise ValueError('files metadata destination differs')
            valid=a in self.systems if kind==12 else a==1
            expected=0 if valid else 0xffffffff
            if not valid:self.error=9 if kind==12 else 14 if a==0 else 2
            if valid:
                data=payload
                if len(data)!=self.abi[0] or struct.unpack_from('<q',data,self.abi[2])[0]!=len(self.data):raise ValueError('files stat ABI/size differs')
        elif kind==14:
            i=self.slot(a);expected=s[i];s[i]=0xffffffff
        elif kind==15:
            i=self.file(a)
            if s[i]<1:raise ValueError('files close has no reference')
            s[i]-=1
            if not s[i]:self.setpos(i,0)
        elif kind==16:i=self.slot(a);s[i:i+3]=[0xffffffff,0,0]
        elif kind==17:expected=0 if 0<=a<1024 else 0xffffffff
        elif kind==18:
            i=self.slot(a);s[i]=0xffffffff;s[i+1]=1
        elif kind==19:
            i=self.file(a)
            if s[i]<1 or s[i]>=2:raise ValueError('files reference count outside reviewed extent')
            s[i]+=1
        elif kind==21:
            if a!=1 or b>8 or c or self.lock!=1:raise ValueError('files region-check arguments/lock differ')
        elif kind==22:
            if (a,b,c)!=(1,0xffffffff,0) or self.lock:raise ValueError('files VM lock differs')
            self.lock=1
        elif kind==23:
            if (a,b,c)!=(1,0,0) or self.lock!=1:raise ValueError('files VM unlock differs')
            self.lock=0
        else:raise ValueError('files unknown dependency')
        if raw!=expected or payload!=data:raise ValueError('files dependency result/payload differs')
        # Provider errno, including direct-negative seek API, is bound by call-level consistency and transcript replay.
        if error!=self.error:raise ValueError('files dependency errno propagation differs')
        return data


def decode(user,kernel,dependencies,abi_blob):
    if (len(user),len(kernel),len(abi_blob))!=(COUNT*224,COUNT*168,32) or len(dependencies)%344 or not 0<len(dependencies)<=192*344:raise ValueError('files capture extents differ')
    abi=list(struct.unpack('<8I',abi_blob))
    if not (abi[0]==152 and abi[1]==104 and abi[2]==48 and abi[3]==8 and 8<=abi[4]<=65536 and abi[5:]==[1,0,0]):raise ValueError('files native ABI/config differs')
    keys=('invocation','kind','a','b','c','raw','error','length');events=[]
    for offset in range(0,len(dependencies),344):
        words=struct.unpack_from('<38I',dependencies,offset);e=dict(zip(keys,words[:8]));e['before']=list(words[8:23]);e['after']=list(words[23:38]);data=dependencies[offset+152:offset+344]
        if e['length']>192 or any(data[e['length']:]):raise ValueError('files payload length/padding differs')
        e['data']=data[:e['length']].hex();events.append(e)
    state=State(abi);cursor=0;calls=[];stat_payload=None
    for inv,(number,args,expected_raw,_) in enumerate(CASES):
        un,*uw=struct.unpack_from('<8I',user,inv*224);ua=uw[:5];raw,mode=uw[5:];row=struct.unpack_from('<42I',kernel,inv*168)
        if (un,ua,raw,mode)!=(number,args,expected_raw&0xffffffff,16) or list(row[:7])!=[number,*args,raw] or list(row[8:12])!=[0x113,*abi[:3]]:raise ValueError('files syscall identity/result/ABI differs')
        entry=list(state.values);state.error=0;output=bytearray(before(inv));kinds=sequence(inv);start=cursor
        lookups=0
        for kind in kinds:
            if cursor>=len(events):raise ValueError('files dependency missing')
            e=events[cursor];cursor+=1
            if (e['invocation'],e['kind'],e['before'])!=(inv,kind,state.values):raise ValueError('files dependency order/entry differs')
            def mapped(fd):return entry[3*(fd-4)] if fd in (4,5,6) else 0xffffffff
            expected_args=None
            if kind==1:expected_args=(args[1] if number==322 else args[0],0,0)
            elif kind==2:expected_args=(0,0,0)
            elif kind==3:expected_args=(expected_raw,0,0)
            elif kind==4:expected_args=(0xffffff9c,args[1] if number==322 else args[0],args[2] if number==322 else args[1])
            elif kind==5:expected_args=(args[1],mapped(args[0]),0) if number==63 else (expected_raw,state.systems[-1],0)
            elif kind==6:expected_args=(1,1,0)
            elif kind==7:
                expected_args=(args[lookups] if number==63 else args[0],0,0);lookups+=1
            elif kind in (8,9):expected_args=(mapped(args[0]),args[1],args[2])
            elif kind==10:expected_args=(mapped(args[0]),args[4],args[1])
            elif kind==11:expected_args=(args[3] if number==140 else args[1],8 if number==140 else abi[1],0)
            elif kind==12:expected_args=(mapped(args[0]),int(args[1]!=0),0)
            elif kind==13:expected_args=(args[0],int(args[1]!=0),0)
            elif kind==14:expected_args=(args[0],0,0)
            elif kind==15:expected_args=(mapped(args[1] if number==63 else args[0]),0,0)
            elif kind==16:expected_args=(4 if number in (5,322) else args[0],0,0)
            elif kind in (17,18,20):expected_args=(args[1],0,0)
            elif kind==19:expected_args=(mapped(args[0]),0,0)
            elif kind==21:expected_args=(args[1],args[2],0)
            elif kind==22:expected_args=(1,0xffffffff,0)
            elif kind==23:expected_args=(1,0,0)
            if (e['a'],e['b'],e['c'])!=expected_args:raise ValueError('files dependency arguments differ from syscall')
            data=state.apply(e,inv)
            if e['after']!=state.values:raise ValueError('files dependency effects differ')
            if kind in (12,13) and not e['raw']:stat_payload=data[:abi[1]]
            if kind==10 and not e['raw']:seek_payload=data[4:]
            if kind==11:
                expected=seek_payload if number==140 else stat_payload
                if data!=expected:raise ValueError('files copied metadata/seek result differs')
                if not e['raw']:output[:len(data)]=data
            if kind==9 and e['raw']!=0xffffffff:output[:len(data)]=data
        if list(row[12:27])!=entry or list(row[27:])!=state.values or state.path or state.lock:raise ValueError('files syscall effect/lifetime differs')
        if user[inv*224+32:(inv+1)*224]!=output:raise ValueError('files caller buffer/guard differs')
        error=row[7]
        if error!=state.error:raise ValueError('files call errno differs')
        calls.append({'number':number,'args':args,'raw_bits':raw,'errno':error,'before':entry,'after':list(state.values),
            'buffer_before':before(inv).hex(),'buffer_after':bytes(output).hex(),'event_start':start,'event_end':cursor})
    if cursor!=len(events) or state.data!=b'abXY' or state.values!=[0xffffffff,0,0]*3+[0]*6:raise ValueError('files final state/unused events differ')
    return {'format':'osrec-files-checkpoint-v1','abi':abi,'calls':calls,'dependency_transcript':events,'system_fds':state.systems,
        'final_file_bytes':bytes(state.data).hex(),'scope':'one RAM filesystem path, two open-file descriptions and three process slots; native metadata bytes and bounded VM/user-copy outcomes'}


def export_capture(args,user,kernel,dependencies,abi,kernel_hash):
    _,identity=prepare_source(args.kernel_root);checkpoint=decode(user,kernel,dependencies,abi)
    metadata={'format':'osrec-live-files-checkpoint-v1','source_identity':identity,'checkpoint':checkpoint,
        'kernel_image_sha256':kernel_hash,'entry_errno_fixture':0,'runtime_host_interaction':False,'provider_internals_replayed':False,
        'provenance':'actual LiteOS-A PID 1 shared-state file SVC session; forwarded native dependency operations; no injected errors'}
    for name,data in (('user',user),('kernel',kernel),('dependencies',dependencies),('abi',abi)):
        (args.out/('files-'+name+'.bin')).write_bytes(data);metadata[name+'_sha256']=digest(data)
    (args.out/'files-checkpoint.manifest.json').write_text(json.dumps(metadata,indent=2)+'\n');return metadata
