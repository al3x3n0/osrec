#!/usr/bin/env python3
"""Verify a published syscall-slice library/image in all four QEMU load/start modes."""
import argparse,json
from pathlib import Path
from klee_liteos import digest
from rtl_load_bundle import prepare,ram_region
from rtl_boot_bundle import prepare as prepare_boot
from verify_qemu_bundle import verify
from run_freestanding_armv7 import require_success
from freestanding_armv7 import audit

def verify_matrix(image,out,ram=None,qemu='qemu-system-aarch64',llvm_bin=Path('/opt/homebrew/opt/llvm@16/bin')):
    image=Path(image).resolve();out=Path(out).resolve()
    if out.exists():raise FileExistsError(out)
    if out.is_relative_to(image):raise ValueError('verification output overlaps the published image')
    manifest=json.loads((image/'manifest.json').read_text())
    if manifest.get('format')!='osrec-callable-slices-image-v1':raise ValueError('not a published callable-slice image')
    for filename,key in (('slices.elf','elf_sha256'),('slices.bin','binary_sha256'),('slices.a','archive_sha256')):
        if digest((image/filename).read_bytes())!=manifest[key]:raise ValueError('published artifact hash mismatch: '+filename)
    hashes={str(p.relative_to(image/'sources')):digest(p.read_bytes()) for p in (image/'sources').rglob('*') if p.is_file()}
    if hashes!=manifest['source_hashes']:raise ValueError('published source hash mismatch')
    from slice_port_bundle import verify_published
    verify_published(image/'port-inputs',manifest)
    if manifest.get('composition')=='imported-application-elf':
        from export_application_replay import checked_files, execution_windows
        from import_application_checkpoint import verify_package
        checked_files(image/'application',manifest['application_artifact_hashes'])
        route=verify_package(image/'application')
        if digest((image/'application/route-plan.json').read_bytes())!=manifest['application_manifest_sha256']:raise ValueError('application route identity mismatch')
        ranges=[{'address':s['address'],'bytes':s['memory_bytes']} for s in route['loads']]
        if manifest['application_required_ranges']!=ranges or manifest['application_code_audit']['embedded_breakpoints']!=route['patches'] or manifest['application_code_audit']['external_service_instructions'] is not False:raise ValueError('application memory or instruction audit differs from checkpoint')
        if digest((image/'kernel-manifest.json').read_bytes())!=manifest['kernel_library_manifest_sha256']:raise ValueError('kernel library identity mismatch')
        kernel=json.loads((image/'kernel-manifest.json').read_text())
        verify_published(image/'kernel-port-inputs',kernel)
        kernel_hashes={str(p.relative_to(image/'kernel-sources')):digest(p.read_bytes()) for p in (image/'kernel-sources').rglob('*') if p.is_file()}
        if kernel_hashes!=kernel['source_hashes'] or kernel['archive_sha256']!=manifest['archive_sha256']:raise ValueError('kernel library source/archive mismatch')
        if manifest.get('checkpoint_mode'):
            from application_pause import verify_joint,observation_plan,record_check
            mode=manifest['checkpoint_mode'];pause=manifest['checkpoint_pause_ordinal']
            if mode not in ('save','load','advance') or manifest['target']['result_abi_version']!=dict(save=23,load=24,advance=25)[mode] or not kernel.get('checkpoint_codec'):raise ValueError('invalid checkpoint composition')
            start=route['sites'][0]['ordinal']
            if mode in ('load','advance'):
                joint=verify_joint(image/'joint-checkpoint',kernel)
                if digest((image/'joint-checkpoint/manifest.json').read_bytes())!=manifest['joint_checkpoint_manifest_sha256'] or joint['pause_ordinal']!=start or joint['application_manifest_sha256']!=manifest['application_manifest_sha256']:raise ValueError('resume composition differs from joint checkpoint')
                if mode=='load' and start!=pause:raise ValueError('invalid terminal restore ordinal')
                if mode=='advance' and (manifest.get('checkpoint_start_ordinal')!=start or not start<pause<joint['total_calls']):raise ValueError('invalid advance checkpoint ordinal')
            if mode in ('save','advance'):
                plan=observation_plan(image/'slices.elf',route,kernel['checkpoint_codec'],llvm_bin)
                if plan!=manifest['checkpoint_observation_plan'] or {d['file'] for d in plan}!=manifest['checkpoint_observation_hashes'].keys():raise ValueError('checkpoint observation plan differs from image')
                checked_files(image/'pause-records',manifest['checkpoint_observation_hashes'])
                if record_check((image/'pause-records/kernel.bin').read_bytes(),kernel['checkpoint_codec'])!=pause:raise ValueError('checkpoint observation ordinal mismatch')
                if (mode=='save' and start) or not start<pause<start+len(route['sites']):raise ValueError('invalid producer pause ordinal')
        if 'application_execution_windows' in manifest:
            limit=manifest['application_window_call_limit']
            if type(limit) is not int or not 0<=limit<=65536 or manifest['application_execution_windows']!=execution_windows(route,limit):raise ValueError('application windows differ from routing contract')
            if bool(limit)!=manifest['application_windows_integrated'] or manifest['target']['result_abi_version']!=(22 if limit else 21):raise ValueError('application window capability mismatch')
            if limit and (not kernel.get('hardware_cpu_windows_included') or not route.get('window_bindings')):raise ValueError('application window package lacks runtime support')
    reviewed={r['address']:r['immediate'] for r in manifest['image_audit'].get('embedded_breakpoints',[])}
    audit(image/'slices.elf',llvm_bin,reviewed)
    observed=manifest['target_observations'];require_success(observed)
    if observed['abi_version']!=manifest['target']['result_abi_version'] or any(observed.get(k)!=v for k,v in manifest['expected_result'].items()):raise ValueError('published result differs from the port contract')
    expected=(image/'target-result.bin').read_bytes()
    ram=ram if ram is not None else [{'address':0x40000000,'bytes':64*1024*1024}]
    from image_memory import require_coverage
    require_coverage(manifest.get('application_required_ranges',[]),ram)
    out.mkdir(parents=True);rows=[]
    try:
        for raw in (False,True):
            mode='raw' if raw else 'elf';base=out/mode;base.mkdir();replay=base/'replay'
            prepare(image/'slices.elf',ram,replay,image/'slices.bin' if raw else None)
            boot=base/'boot';prepare_boot(replay,boot,llvm_bin)
            for bundle,start in ((replay,'el1'),(boot,'el3')):
                evidence=base/(start+'-verification')
                dump_plan=manifest.get('checkpoint_observation_plan',[])
                dumps=[d|dict(file=evidence/d['file']) for d in dump_plan]
                checked=verify(bundle,evidence,qemu,memory_dumps=dumps)
                for d in dump_plan:
                    if digest((evidence/d['file']).read_bytes())!=manifest['checkpoint_observation_hashes'][d['file']]:raise ValueError('QEMU joint checkpoint differs from producer observation')
                actual=json.loads((evidence/'execution-report.json').read_text())
                if (evidence/'target-result.bin').read_bytes()!=expected or any(actual.get(k)!=v for k,v in observed.items() if k not in ('result_address',)):
                    raise ValueError('QEMU result differs from the published proof')
                rows.append({'loading_mode':mode,'start':start,'status':checked['status'],'completed_calls':checked['completed_calls'],
                    'evidence':str((evidence/'verification.json').relative_to(out))})
        report={'format':'osrec-qemu-syscall-slices-matrix-v1','status':'verified','image_manifest_sha256':digest((image/'manifest.json').read_bytes()),
            'result_sha256':digest(expected),'abi_version':observed['abi_version'],'calls_per_execution':observed['completed_calls'],'executions':rows,
            'application_frame_proof':manifest.get('application_frame_proof',False),'runtime_host_interaction':False,
            'cpu_gateway_proof':manifest.get('cpu_gateway_proof',False),'embedded_breakpoints':len(reviewed)+len(manifest.get('application_code_audit',{}).get('embedded_breakpoints',[])),
            'container_embedded_breakpoints':len(reviewed),'application_embedded_breakpoints':len(manifest.get('application_code_audit',{}).get('embedded_breakpoints',[])),
            'application_windows_integrated':manifest.get('application_windows_integrated',False),'application_window_call_limit':manifest.get('application_window_call_limit',0),
            'app_checkpoint_loader_integrated':manifest['app_checkpoint_loader_integrated'],'hardware_cpu_restore_integrated':manifest.get('hardware_cpu_restore_integrated',False)}
    except Exception as error:
        report={'format':'osrec-qemu-syscall-slices-matrix-v1','status':'failed','executions':rows,'error':str(error)}
        (out/'verification-matrix.json').write_text(json.dumps(report,indent=2)+'\n');raise
    (out/'verification-matrix.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image',type=Path,required=True);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--ram',type=ram_region,action='append');parser.add_argument('--qemu',default='qemu-system-aarch64')
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));args=parser.parse_args()
    print(json.dumps(verify_matrix(args.image,args.out,args.ram,args.qemu,args.llvm_bin),indent=2))
if __name__=='__main__':main()
