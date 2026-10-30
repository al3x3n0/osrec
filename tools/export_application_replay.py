#!/usr/bin/env python3
"""Compose an imported AArch64 application and a pinned returning kernel-slice library."""
import argparse
import json
import shutil
import tempfile
from pathlib import Path
from import_application_checkpoint import digest, overlaps, verify_package
from freestanding_armv7 import run, audit
from freestanding_elf import prepare_target, target_metadata
from run_freestanding_armv7 import observe, require_success

def checked_files(directory, hashes):
    for name, expected in hashes.items():
        path = directory/name
        if not path.resolve().is_relative_to(directory.resolve()) or digest(path.read_bytes()) != expected:
            raise ValueError('published artifact identity mismatch: '+name)

def driver_source(route,window_calls=0):
    values = [len(route['sites']), len(route['loads']), sum(bool(s['flags']&1) for s in route['loads']), len(route['patches']), route['snapshot_count'], len(route['assertions'])]
    source='''#include "application_checkpoint.h"
#include "slice_layout.h"
volatile uint32_t osrec_result[32] __attribute__((section(".result"),aligned(16)));
static _Alignas(OSREC_SLICE_STATE_ALIGNMENT) unsigned char state[OSREC_SLICE_STATE_BYTES];
static _Alignas(16) unsigned char stack[OSREC_AARCH64_GATEWAY_STACK_MIN];
static struct osrec_slice_session session;
static struct osrec_aarch64_frame frame;
static struct osrec_aarch64_gateway gateway;
static void stop(void){for(;;)__asm__ volatile("wfe");}
static void fail(uint32_t n){osrec_result[3]=n;osrec_result[2]=3;stop();}
void replay_fault(void){uint64_t esr,pc;__asm__ volatile("mrs %0,esr_el1\\nmrs %1,elr_el1":"=r"(esr),"=r"(pc));osrec_result[28]=(uint32_t)esr;osrec_result[29]=(uint32_t)pc;fail(99);}
void replay_main(void){
    osrec_result[0]=0x4f535243;osrec_result[1]=21;
    if(osrec_slice_session_init(&session,&osrec_kernel_adapter,state,sizeof(state)))fail(1);
    for(unsigned run=0;run<2;++run){
        if(run && osrec_slice_session_restore(&session))fail(2);
        osrec_import_restore(&frame);
        if(osrec_import_check_initial())fail(3);
        ++osrec_result[7];
        for(unsigned j=0;j<16;++j){stack[j]=0x6a;stack[sizeof(stack)-16+j]=0x6a;}
        osrec_import_bind(&gateway,&session,&osrec_application_abi,&frame,stack,sizeof(stack));
        if(osrec_aarch64_gateway_run(&gateway) || session.poisoned || session.active || gateway.cursor!=gateway.site_count || gateway.entries!=gateway.site_count || gateway.exits!=1)fail(4);
        if(osrec_import_check())fail(5);
        ++osrec_result[8];
        if(osrec_slice_finish(&session))fail(6);
        for(unsigned j=0;j<16;++j)if(stack[j]!=0x6a || stack[sizeof(stack)-16+j]!=0x6a)fail(7);
        ++osrec_result[17];osrec_result[4]+=(uint32_t)session.next;
        osrec_result[9]+=(uint32_t)gateway.entries;osrec_result[10]+=(uint32_t)gateway.exits;
        ++osrec_result[6];
    }
''' + ''.join('    osrec_result['+str(index)+']='+str(value)+';\n' for index,value in zip((5,11,12,13,14,15),values)) + '''    osrec_result[16]=OSREC_AARCH64_GATEWAY_ABI;osrec_result[18]=OSREC_AARCH64_FRAME_ABI;
    osrec_result[2]=2;stop();
}
'''
    if window_calls:
        source=source.replace('osrec_result[1]=21;','osrec_result[1]=22;')
        begin=source.index('        osrec_import_bind(&gateway,')
        end=source.index('        if(osrec_import_check())',begin)
        source=source[:begin]+'''        const size_t total='''+str(len(route['sites']))+''',limit='''+str(window_calls)+''';
        for(size_t first=0;first<total;){
            size_t count=total-first;if(count>limit)count=limit;
            int final=first+count==total;
            if(osrec_import_bind_window(&gateway,&session,&osrec_application_abi,&frame,stack,sizeof(stack),first,count))fail(8);
            if(first){if(frame.pc!=gateway.sites[0].svc_pc)fail(9);++osrec_result[21];}
            uint32_t status=final ? osrec_aarch64_gateway_run(&gateway) : osrec_aarch64_gateway_run_window(&gateway);
            if(status || session.poisoned || session.active || gateway.active || gateway.cursor!=count || gateway.entries!=count || gateway.exits!=1)fail(4);
            if(session.next!=first+count)fail(10);++osrec_result[22];
            if(final)++osrec_result[10];
            else{if(frame.pc!=gateway.exit_pc || osrec_slice_finish(&session)!=OSREC_SLICE_BAD_INPUT)fail(11);++osrec_result[20];}
            for(unsigned j=0;j<16;++j)if(stack[j]!=0x6a || stack[sizeof(stack)-16+j]!=0x6a)fail(7);
            ++osrec_result[17];osrec_result[9]+=(uint32_t)gateway.entries;++osrec_result[23];
            first+=count;
        }
'''+source[end:]
        source=source.replace('        for(unsigned j=0;j<16;++j)if(stack[j]!=0x6a || stack[sizeof(stack)-16+j]!=0x6a)fail(7);\n        ++osrec_result[17];osrec_result[4]+=(uint32_t)session.next;\n        osrec_result[9]+=(uint32_t)gateway.entries;osrec_result[10]+=(uint32_t)gateway.exits;', '        osrec_result[4]+=(uint32_t)session.next;')
        source=source.replace('    osrec_result[2]=2;stop();', '    osrec_result[19]='+str((len(route['sites'])+window_calls-1)//window_calls)+';osrec_result[24]='+str(window_calls)+';\n    osrec_result[2]=2;stop();')
    return source

def execution_windows(route,limit):
    total=len(route['sites']);limit=limit or total
    return [dict(first=i,count=min(limit,total-i),pause_pc=route['sites'][i+limit]['svc_pc'] if i+limit<total else None) for i in range(0,total,limit)]

def export(args):
    library, app, out = args.slices.resolve(), args.application.resolve(), args.out.resolve()
    if out.exists(): raise FileExistsError(out)
    if out.is_relative_to(library) or out.is_relative_to(app): raise ValueError('output overlaps an input package')
    parent = json.loads((library/'manifest.json').read_text())
    route = verify_package(app)
    window_calls=getattr(args,'window_calls',0)
    checkpoint_mode=getattr(args,'checkpoint_mode',None);resume=None;pause=getattr(args,'pause_ordinal',None)
    if checkpoint_mode is not None:
        from application_pause import verify_joint
        if checkpoint_mode not in ('save','load','advance') or window_calls or not parent.get('checkpoint_codec'):raise ValueError('unsupported checkpoint composition')
        if checkpoint_mode in ('load','advance'):
            resume=verify_joint(args.checkpoint,parent)
            if checkpoint_mode=='load':pause=resume['pause_ordinal']
            elif type(pause) is not int or not resume['pause_ordinal']<pause<resume['total_calls']:raise ValueError('next pause ordinal must advance inside the call sequence')
            if checkpoint_mode=='advance' and len(route.get('completed_sites',[]))!=resume['pause_ordinal']:raise ValueError('checkpoint chaining requires complete syscall PC history')
            if args.application.resolve()!= (args.checkpoint/'application').resolve():raise ValueError('resume application differs from joint checkpoint')
            if args.entry_address==resume['producer_entry']:raise ValueError('resume container must relocate to exercise reference rebinding')
        elif type(pause) is not int or not 0<pause<len(route['sites']):raise ValueError('pause ordinal must be inside the call sequence')
    if type(window_calls) is not int or not 0<=window_calls<=65536:raise ValueError('invalid window call limit')
    if window_calls and (not parent.get('hardware_cpu_windows_included') or not route.get('window_bindings')):
        raise ValueError('window execution requires updated kernel and application packages')
    if parent.get('format') != 'osrec-callable-slices-image-v1' or not parent.get('hardware_cpu_gateway_included') or parent['gateway_layout'].get('G_ABI') != 2:
        raise ValueError('composition requires a slice library built with gateway ABI 2')
    if route.get('format') != 'osrec-aarch64-application-routes-v1' or route.get('gateway_abi') != 2:
        raise ValueError('unsupported application route package')
    checked_files(library, {'slices.a': parent['archive_sha256']})
    require_success(parent['target_observations'])
    actual = {str(p.relative_to(library/'sources')):digest(p.read_bytes()) for p in (library/'sources').rglob('*') if p.is_file()}
    if actual != parent['source_hashes']: raise ValueError('slice source identity mismatch')
    from slice_port_bundle import verify_published
    verify_published(library/'port-inputs',parent)
    checked_files(app, route['artifact_hashes'])
    if not route['sites'] or (checkpoint_mode not in ('load','advance') and route['sites'][0]['ordinal'] != 0):
        raise ValueError('composition starts a fresh kernel session at ordinal zero')
    with tempfile.TemporaryDirectory(prefix='osrec-application-replay-') as name:
        stage = Path(name); sources=stage/'sources'; sources.mkdir()
        shutil.copytree(library/'sources/osrec', sources/'osrec')
        for f in ('slice_layout.h',): shutil.copyfile(library/'sources'/f,sources/f)
        for f in ('application_checkpoint.h','application_checkpoint.c'): shutil.copyfile(app/f,sources/f)
        if checkpoint_mode:
            from application_pause import driver
            driver_text=driver(route,parent['checkpoint_codec'],pause,resume,advance=checkpoint_mode=='advance')
        else:driver_text=driver_source(route,window_calls)
        (sources/'slice_driver.c').write_text(driver_text)
        # The composed image starts as the slice library's own image did (MMU mode included).
        mmu=parent['target'].get('mmu',{}).get('mode')
        flags = prepare_target(args,sources,mmu)
        compiler=[args.llvm_bin/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-I'+str(sources)]
        archive=stage/'slices.a'; shutil.copyfile(library/'slices.a',archive)
        elf, binary=stage/'slices.elf',stage/'slices.bin'
        run([*compiler,'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'slice_driver.c',sources/'application_checkpoint.c',archive,'-o',elf])
        inspected=audit(elf,args.llvm_bin)
        for load in route['loads']:
            if any(overlaps(load['address'],load['memory_bytes'],s['address'],s['memory_bytes']) for s in inspected['load_segments']) or overlaps(load['address'],load['memory_bytes'],inspected['startup_zero_range']['address'],inspected['startup_zero_range']['bytes']):
                raise ValueError('application memory overlaps the linked container')
            if overlaps(load['address'],load['memory_bytes'],0x43f00000,65536): raise ValueError('application overlaps QEMU EL3 boot area')
        run([args.llvm_bin/'llvm-objcopy','-O','binary',elf,binary])
        dump_plan=[];dumps=[]
        if checkpoint_mode in ('save','advance'):
            from application_pause import observation_plan
            dump_plan=observation_plan(elf,route,parent['checkpoint_codec'],args.llvm_bin)
            (stage/'pause-records').mkdir();dumps=[d|dict(file=stage/'pause-records'/d['file']) for d in dump_plan]
        observed, raw=observe(elf,args.qemu,memory_dumps=dumps); require_success(observed)
        expected=dict(call_count=len(route['sites']),load_segments=len(route['loads']),executable_segments=sum(bool(s['flags']&1) for s in route['loads']),unique_patches=len(route['patches']),snapshots=route['snapshot_count'],assertions=len(route['assertions']))
        if checkpoint_mode:expected=dict(call_count=resume['total_calls'] if resume else len(route['sites']),pause_ordinal=pause,checkpoint_bytes=parent['checkpoint_codec']['record_bytes'])
        if checkpoint_mode=='advance':expected.update(checkpoint_start_ordinal=resume['pause_ordinal'],checkpoint_loads=2,checkpoint_saves=2)
        if window_calls:expected.update(window_count=len(execution_windows(route,window_calls)),window_call_limit=window_calls)
        if any(observed.get(k)!=v for k,v in expected.items()): raise ValueError('application result differs from routing contract')
        raw_dumps=[]
        if dumps:
            (stage/'raw-records').mkdir();raw_dumps=[d|dict(file=stage/'raw-records'/d['file']) for d in dump_plan]
        _, raw_result=observe(binary,args.qemu,descriptor=elf,memory_dumps=raw_dumps)
        for d in dump_plan:
            if (stage/'pause-records'/d['file']).read_bytes()!=(stage/'raw-records'/d['file']).read_bytes():raise ValueError('ELF/raw pause checkpoint differs')
        if raw_result!=raw: raise ValueError('ELF/raw application execution differs')
        publish=stage/'published'; publish.mkdir()
        for p in (archive,elf,binary): shutil.copyfile(p,publish/p.name)
        shutil.copytree(sources,publish/'sources'); shutil.copytree(app,publish/'application')
        shutil.copytree(library/'sources',publish/'kernel-sources')
        shutil.copyfile(library/'manifest.json',publish/'kernel-manifest.json')
        if 'bundle' in parent['port']:shutil.copytree(library/'port-inputs',publish/'kernel-port-inputs')
        if dumps:shutil.copytree(stage/'pause-records',publish/'pause-records')
        if resume:shutil.copytree(args.checkpoint,publish/'joint-checkpoint')
        (publish/'target-result.bin').write_bytes(raw)
        report=dict(format='osrec-callable-slices-image-v1',composition='imported-application-elf',target=target_metadata(inspected,21,mmu),target_observations=observed,expected_result=expected,image_audit=inspected,archive_sha256=digest(archive.read_bytes()),elf_sha256=digest(elf.read_bytes()),binary_sha256=digest(binary.read_bytes()),source_hashes={str(p.relative_to(sources)):digest(p.read_bytes()) for p in sources.rglob('*') if p.is_file()},application_manifest_sha256=digest((app/'route-plan.json').read_bytes()),application_artifact_hashes=route['artifact_hashes'],application_code_audit=dict(scope='file-backed executable PT_LOAD word candidates and exact recorded patches',embedded_breakpoints=route['patches'],external_service_instructions=False),kernel_library_manifest_sha256=digest((library/'manifest.json').read_bytes()),construction_sha256=digest(Path(__file__).read_bytes()),application_frame_proof=True,cpu_gateway_proof=True,hardware_cpu_restore_integrated=True,app_checkpoint_loader_integrated=True,runtime_host_interaction=False,raw_image_execution_match=True,concurrent_session_execution_supported=False,application_required_ranges=[dict(address=s['address'],bytes=s['memory_bytes']) for s in route['loads']],application_checkpoint_format='osrec-aarch64-application-checkpoint-v1')
        report.update(kernel_port=parent['port'],kernel_source_identity=parent['source_identity'],state_layout=parent['state_layout'],gateway_layout=parent['gateway_layout'])
        report['target']['result_abi_version']=(25 if checkpoint_mode=='advance' else 24 if resume else 23) if checkpoint_mode else 22 if window_calls else 21
        if checkpoint_mode:
            report.update(checkpoint_construction_sha256=digest((Path(__file__).parent/'application_pause.py').read_bytes()),checkpoint_mode=checkpoint_mode,checkpoint_pause_ordinal=pause,checkpoint_start_ordinal=resume['pause_ordinal'] if resume else 0,checkpoint_observation_plan=dump_plan,checkpoint_observation_hashes={d['file']:digest((stage/'pause-records'/d['file']).read_bytes()) for d in dump_plan},joint_checkpoint_manifest_sha256=digest((args.checkpoint/'manifest.json').read_bytes()) if resume else None)
        else:report.update(application_windows_integrated=bool(window_calls),application_execution_windows=execution_windows(route,window_calls),application_window_call_limit=window_calls)
        (publish/'manifest.json').write_text(json.dumps(report,indent=2)+'\n'); shutil.copytree(publish,out)
    return report

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slices',type=Path,required=True); parser.add_argument('--application',type=Path);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));parser.add_argument('--qemu',default='qemu-system-aarch64')
    parser.add_argument('--entry-address',type=lambda v:int(v,0),default=0x40400000);parser.add_argument('--result-address',type=lambda v:int(v,0),default=0x40380000)
    parser.add_argument('--window-calls',type=int,default=0,help='pause and resume after at most N calls; zero runs the whole sequence')
    parser.add_argument('--pause-ordinal',type=int,help='absolute next checkpoint ordinal; may be combined with --resume-checkpoint');parser.add_argument('--resume-checkpoint',type=Path)
    args=parser.parse_args();args.checkpoint_mode=('advance' if args.pause_ordinal is not None else 'load') if args.resume_checkpoint else 'save' if args.pause_ordinal is not None else None;args.checkpoint=args.resume_checkpoint
    if args.resume_checkpoint:args.application=args.resume_checkpoint/'application'
    if args.application is None:parser.error('--application is required unless --resume-checkpoint is supplied')
    args.arch='aarch64';print(json.dumps(export(args),indent=2))

if __name__=='__main__':main()
