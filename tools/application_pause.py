"""Quiescent producer/consumer drivers and portable joint-checkpoint validation."""
import json,struct
from pathlib import Path
from import_application_checkpoint import digest,verify_package,import_checkpoint


def record_check(raw,codec):
    if len(raw)!=codec['record_bytes'] or raw[:8]!=b'OSRECKP1' or struct.unpack_from('<II',raw,8)!=(1,len(raw)) or raw[16:48].hex()!=codec['schema_sha256']:raise ValueError('kernel checkpoint schema/header mismatch')
    h=14695981039346656037
    for i,v in enumerate(raw):
        if i<56 or i>=64:h=((h^v)*1099511628211)&((1<<64)-1)
    if h!=struct.unpack_from('<Q',raw,56)[0]:raise ValueError('kernel checkpoint checksum mismatch')
    return struct.unpack_from('<Q',raw,48)[0]


def decode_frame(raw):
    if len(raw)!=808:raise ValueError('saved frame size mismatch')
    q=struct.unpack_from('<98Q',raw)
    f=dict(x=list(q[:31]),sp=q[31],pc=q[32],pstate=q[33],v=[list(q[34+2*i:36+2*i]) for i in range(32)])
    f['fpcr'],f['fpsr']=struct.unpack_from('<II',raw,784)
    f['tpidr_el0'],f['tpidrro_el0']=struct.unpack_from('<QQ',raw,792)
    return f


def driver(route,codec,pause,resume=None,advance=False):
    total=resume['total_calls'] if resume else len(route['sites'])
    start=resume['pause_ordinal'] if resume else 0
    terminal=bool(resume) and not advance
    runs=2 if resume else 1
    source='''#include "application_checkpoint.h"
#include "slice_layout.h"
#include "osrec/slice_checkpoint.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
_Alignas(OSREC_SLICE_STATE_ALIGNMENT) unsigned char osrec_checkpoint_state[OSREC_SLICE_STATE_BYTES];
static _Alignas(16) unsigned char stack[OSREC_AARCH64_GATEWAY_STACK_MIN];
static struct osrec_slice_session session;
struct osrec_aarch64_frame osrec_saved_frame;
static struct osrec_aarch64_gateway gateway;
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(uint32_t n){osrec_result[3]=n;osrec_result[2]=3;stop();}
void replay_fault(void){uint64_t esr,pc;__asm__ volatile("mrs %0,esr_el1\\nmrs %1,elr_el1":"=r"(esr),"=r"(pc));osrec_result[28]=(uint32_t)esr;osrec_result[29]=(uint32_t)pc;fail(99);}
'''
    n=codec['record_bytes']
    if resume:source+='static const unsigned char kernel_record['+str(n)+']={'+','.join(str(v) for v in resume['record'])+'};\n'
    if not terminal:source+='unsigned char osrec_saved_kernel['+str(n)+'];\n'
    source+='void replay_main(void){\nosrec_result[0]=0x4f535243;osrec_result[1]='+str(25 if advance else 24 if resume else 23)+';\n'
    source+='if(osrec_slice_session_init(&session,&osrec_kernel_adapter,osrec_checkpoint_state,sizeof(osrec_checkpoint_state)))fail(1);\n'
    source+='for(unsigned run=0;run<'+str(runs)+';++run){\n'
    if resume:source+='if(osrec_slice_checkpoint_load(&session,&osrec_kernel_checkpoint_codec,kernel_record,sizeof(kernel_record)) || session.next!='+str(start)+')fail(2);++osrec_result[8];\n'
    source+='osrec_import_restore(&osrec_saved_frame);if(osrec_import_check_initial())fail(3);++osrec_result[21];\n'
    source+='for(unsigned j=0;j<16;++j){stack[j]=0x6a;stack[sizeof(stack)-16+j]=0x6a;}\n'
    source+='if(osrec_import_bind_window(&gateway,&session,&osrec_application_abi,&osrec_saved_frame,stack,sizeof(stack),0,'+str(len(route['sites']) if terminal else pause-start)+'))fail(4);\n'
    source+='if('+('osrec_aarch64_gateway_run' if terminal else 'osrec_aarch64_gateway_run_window')+'(&gateway) || session.poisoned || session.active || gateway.active || gateway.entries!=gateway.site_count || gateway.cursor!=gateway.site_count || gateway.exits!=1)fail(5);\n'
    source+='if(session.next!='+str(total if terminal else pause)+')fail(6);\n'
    if terminal:
        source+='if(osrec_slice_finish(&session) || osrec_import_check())fail(7);++osrec_result[14];\n'
        source+='if(osrec_saved_frame.pc!=gateway.exit_pc)fail(8);\n'
    else:
        source+='if(osrec_saved_frame.pc!=gateway.exit_pc || osrec_slice_finish(&session)!=OSREC_SLICE_BAD_INPUT)fail(8);\n'
        source+='if(osrec_slice_checkpoint_save(&session,&osrec_kernel_checkpoint_codec,osrec_saved_kernel,sizeof(osrec_saved_kernel)))fail(9);++osrec_result[8];\n'
    source+='++osrec_result[15];for(unsigned j=0;j<16;++j)if(stack[j]!=0x6a || stack[sizeof(stack)-16+j]!=0x6a)fail(10);++osrec_result[17];\n'
    source+='osrec_result[4]+=(uint32_t)gateway.entries;osrec_result[9]+=(uint32_t)gateway.entries;++osrec_result[10];++osrec_result[7];}\n'
    source+='osrec_result[5]='+str(total)+';osrec_result[6]='+str(pause)+';osrec_result[11]='+str(n)+';\n'
    source+='osrec_result[12]='+ (str(resume['producer_state_address']) if resume else '(uint32_t)(uintptr_t)osrec_checkpoint_state')+';osrec_result[13]=(uint32_t)(uintptr_t)osrec_checkpoint_state;\n'
    if advance:source+='osrec_result[22]='+str(start)+';osrec_result[23]='+str(runs)+';osrec_result[24]='+str(runs)+';\n'
    source+='osrec_result[16]=OSREC_AARCH64_GATEWAY_ABI;osrec_result[18]=OSREC_AARCH64_FRAME_ABI;osrec_result[20]=OSREC_SLICE_CHECKPOINT_ABI;osrec_result[2]=2;stop();}\n'
    return source


def observation_plan(elf,route,codec,llvm_bin):
    from freestanding_armv7 import run
    symbols={r.split()[0]:int(r.split()[2],16) for r in run([llvm_bin/'llvm-nm','--defined-only','--format=posix',elf]).stdout.splitlines() if len(r.split())>=3}
    return [dict(address=symbols['osrec_saved_kernel'],bytes=codec['record_bytes'],file='kernel.bin'),dict(address=symbols['osrec_saved_frame'],bytes=808,file='frame.bin')]+[dict(address=s['address'],bytes=s['memory_bytes'],file='memory-'+str(i)+'.bin') for i,s in enumerate(route['loads'])]


def freeze(producer,out):
    """Build a joint checkpoint using only stopped-QEMU external observations."""
    producer,out=Path(producer).resolve(),Path(out).resolve()
    if out.exists():raise FileExistsError(out)
    if out.is_relative_to(producer):raise ValueError('joint checkpoint output overlaps producer')
    m=json.loads((producer/'manifest.json').read_text());route=verify_package(producer/'application')
    if m.get('checkpoint_mode') not in ('save','advance'):raise ValueError('not a checkpoint producer')
    from run_freestanding_armv7 import require_success
    require_success(m['target_observations'])
    from export_application_replay import checked_files
    checked_files(producer,{'kernel-manifest.json':m['kernel_library_manifest_sha256'],'slices.a':m['archive_sha256'],'slices.elf':m['elf_sha256'],'slices.bin':m['binary_sha256'],'application/route-plan.json':m['application_manifest_sha256']})
    kernel=json.loads((producer/'kernel-manifest.json').read_text());codec=kernel['checkpoint_codec'];pause=m['checkpoint_pause_ordinal']
    start=route['sites'][0]['ordinal'];total=kernel['target_observations']['call_count'];index=pause-start;parent=None
    if m['checkpoint_mode']=='advance':
        parent=verify_joint(producer/'joint-checkpoint',kernel)
        if parent['pause_ordinal']!=start or digest((producer/'joint-checkpoint/manifest.json').read_bytes())!=m['joint_checkpoint_manifest_sha256']:raise ValueError('producer input checkpoint mismatch')
    if type(pause) is not int or not 0<=start<pause<total or not 0<index<len(route['sites']) or (not parent and start) or m['target_observations']['abi_version']!=(25 if parent else 23) or m['target_observations']['pause_ordinal']!=pause or m['target_observations']['call_count']!=total:raise ValueError('invalid producer pause contract')
    checked_files(producer/'pause-records',m['checkpoint_observation_hashes'])
    raw=(producer/'pause-records/kernel.bin').read_bytes()
    if record_check(raw,codec)!=pause:raise ValueError('kernel checkpoint ordinal mismatch')
    frame=decode_frame((producer/'pause-records/frame.bin').read_bytes())
    if frame['pc']!=route['sites'][index]['svc_pc']:raise ValueError('pause frame PC mismatch')
    checkpoint=json.loads((producer/'application/checkpoint.json').read_text())
    history=checkpoint.get('completed_calls',[])
    if len(history)!=start:raise ValueError('checkpoint chaining requires complete syscall PC history')
    checkpoint.update(frame=frame,first_ordinal=pause,completed_calls=history+checkpoint['calls'][:index],calls=checkpoint['calls'][index:],snapshots=[])
    for i,s in enumerate(route['loads']):
        data=(producer/'pause-records'/('memory-'+str(i)+'.bin')).read_bytes()
        if len(data)!=s['memory_bytes']:raise ValueError('incomplete user memory snapshot')
        if s['flags']&1:
            if data!=(producer/'application'/s['file']).read_bytes():raise ValueError('application code changed at checkpoint')
        else:checkpoint['snapshots'].append(dict(address=s['address'],data=data.hex()))
    out.mkdir(parents=True)
    (out/'kernel.bin').write_bytes(raw)
    (out/'checkpoint.json').write_text(json.dumps(checkpoint,indent=2)+'\n')
    import_checkpoint(producer/'application/original.elf',out/'checkpoint.json',out/'application',reserved=[(0x43f00000,65536)])
    doc=dict(format='osrec-joint-application-kernel-checkpoint-v1',pause_ordinal=pause,total_calls=total,kernel_schema_sha256=codec['schema_sha256'],kernel_archive_sha256=m['archive_sha256'],kernel_manifest_sha256=m['kernel_library_manifest_sha256'],producer_manifest_sha256=digest((producer/'manifest.json').read_bytes()),producer_state_address=m['target_observations']['current_state_address'],producer_entry=m['target']['entry'],application_manifest_sha256=digest((out/'application/route-plan.json').read_bytes()),runtime_host_interaction=False)
    doc.update(checkpoint_start_ordinal=start,generation=parent.get('generation',1)+1 if parent else 1,input_checkpoint_manifest_sha256=m['joint_checkpoint_manifest_sha256'] if parent else None)
    if parent:(out/'parent-checkpoint-manifest.json').write_bytes((producer/'joint-checkpoint/manifest.json').read_bytes())
    doc['artifact_hashes']={str(p.relative_to(out)):digest(p.read_bytes()) for p in out.rglob('*') if p.is_file()}
    (out/'manifest.json').write_text(json.dumps(doc,indent=2)+'\n');return doc


def verify_joint(directory,parent):
    from export_application_replay import checked_files
    directory=Path(directory);m=json.loads((directory/'manifest.json').read_text())
    if m.get('format')!='osrec-joint-application-kernel-checkpoint-v1':raise ValueError('unsupported joint checkpoint')
    actual={str(p.relative_to(directory)) for p in directory.rglob('*') if p.is_file() and p!=directory/'manifest.json'}
    if actual!=m['artifact_hashes'].keys():raise ValueError('joint checkpoint artifact set mismatch')
    checked_files(directory,m['artifact_hashes']);route=verify_package(directory/'application')
    if digest((directory/'application/route-plan.json').read_bytes())!=m['application_manifest_sha256'] or parent['archive_sha256']!=m['kernel_archive_sha256'] or digest(json.dumps(parent,indent=2).encode()+b'\n')!=m['kernel_manifest_sha256']:raise ValueError('joint checkpoint kernel/application identity mismatch')
    raw=(directory/'kernel.bin').read_bytes();pause=record_check(raw,parent['checkpoint_codec'])
    if pause!=m['pause_ordinal'] or not 0<pause<m['total_calls'] or m['total_calls']!=parent['target_observations']['call_count'] or len(route['sites'])!=m['total_calls']-pause or route['sites'][0]['ordinal']!=pause or route['frame']['pc']!=route['sites'][0]['svc_pc'] or m['kernel_schema_sha256']!=parent['checkpoint_codec']['schema_sha256']:raise ValueError('joint checkpoint ordinal/schema mismatch')
    if 'generation' in m:
        start=m['checkpoint_start_ordinal'];generation=m['generation']
        if type(start) is not int or type(generation) is not int or not 0<=start<pause or generation<1:raise ValueError('invalid checkpoint generation')
        if start:
            parent_raw=(directory/'parent-checkpoint-manifest.json').read_bytes();previous=json.loads(parent_raw)
            if previous.get('format')!=m['format'] or digest(parent_raw)!=m['input_checkpoint_manifest_sha256'] or previous['pause_ordinal']!=start or previous.get('generation',1)+1!=generation or any(previous[k]!=m[k] for k in ('total_calls','kernel_schema_sha256','kernel_archive_sha256','kernel_manifest_sha256')):raise ValueError('checkpoint parent identity/ordinal mismatch')
        elif generation!=1 or m['input_checkpoint_manifest_sha256'] is not None:raise ValueError('invalid root checkpoint generation')
    return m|dict(record=raw)


def main():
    import argparse
    parser=argparse.ArgumentParser(description='Freeze stopped-QEMU producer observations into a joint checkpoint')
    parser.add_argument('--producer',type=Path,required=True);parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(freeze(args.producer,args.out),indent=2))

if __name__=='__main__':main()
