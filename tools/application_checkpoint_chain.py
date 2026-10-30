"""Shared execution and verification of application/kernel checkpoint chains."""
import json
from pathlib import Path
from types import SimpleNamespace
from import_application_checkpoint import digest,verify_package
from export_application_replay import export,checked_files
from application_pause import freeze,verify_joint
from verify_syscall_slices import verify_matrix
from run_freestanding_armv7 import require_success


def checked_ordinals(points,total,start=0,allow_empty=False):
    if type(total) is not int or type(start) is not int or not 0<=start<total<=65536 or not isinstance(points,list) or not (0 if allow_empty else 1)<=len(points)<=64 or any(type(p) is not int or not start<p<total for p in points) or any(a>=b for a,b in zip(points,points[1:])):raise ValueError('pause ordinals must strictly increase inside the remaining syscall sequence')
    return points


def run_stages(args,out,library,parent,kernel,points,checkpoint=None):
    total=kernel['target_observations']['call_count'];start=0;first_entry=0x40400000
    if checkpoint:
        joint=verify_joint(checkpoint,kernel);start=joint['pause_ordinal']
        if joint['producer_entry']==first_entry:first_entry=0x40600000
    checked_ordinals(points,total,start,allow_empty=bool(checkpoint))
    route=verify_package(out/'routes')
    if len(route['sites'])!=total-start or route['sites'][0]['ordinal']!=start:raise ValueError('application route count/ordinal differs from kernel sequence')
    if checkpoint and points and len(route.get('completed_sites',[]))!=start:raise ValueError('checkpoint chaining requires complete syscall PC history')
    base=dict(slices=library,llvm_bin=args.llvm_bin,qemu=args.qemu,arch='aarch64',result_address=0x40380000,window_calls=0)
    rows=[]
    entry=lambda i: first_entry if i%2==0 else 0x40600000 if first_entry==0x40400000 else 0x40400000
    for i,pause in enumerate(points):
        stage=out/('stage-'+str(i));stage.mkdir()
        mode='advance' if checkpoint else 'save'
        image=export(SimpleNamespace(**base,application=checkpoint/'application' if checkpoint else out/'routes',out=stage/'image',entry_address=entry(i),checkpoint_mode=mode,checkpoint=checkpoint,pause_ordinal=pause))
        matrix=verify_matrix(stage/'image',stage/'qemu',qemu=args.qemu,llvm_bin=args.llvm_bin)
        freeze(stage/'image',stage/'checkpoint');joint=verify_joint(stage/'checkpoint',kernel)
        rows.append(dict(stage='stage-'+str(i),input_ordinal=start,output_ordinal=pause,logical_calls=pause-start,generation=joint['generation'],observations=image['target_observations'],qemu_executions=len(matrix['executions']),input_checkpoint_manifest_sha256=joint['input_checkpoint_manifest_sha256']))
        checkpoint=stage/'checkpoint';start=pause
    final=out/'finish';final.mkdir()
    image=export(SimpleNamespace(**base,application=checkpoint/'application',out=final/'image',entry_address=entry(len(points)),checkpoint_mode='load',checkpoint=checkpoint,pause_ordinal=None))
    matrix=verify_matrix(final/'image',final/'qemu',qemu=args.qemu,llvm_bin=args.llvm_bin)
    rows.append(dict(stage='finish',input_ordinal=start,output_ordinal=total,logical_calls=total-start,generation=None,observations=image['target_observations'],qemu_executions=len(matrix['executions']),input_checkpoint_manifest_sha256=digest((checkpoint/'manifest.json').read_bytes())))
    if (library/'manifest.json').read_bytes()!=parent:raise ValueError('kernel package changed during chain construction')
    return rows


def publish_report(out,report,files):
    # Pin stage evidence without recursively duplicating ancestor payloads.
    files=list(files)
    for row in report['stages']:
        folder=row['stage'];files += [folder+'/'+name for name in ('image/manifest.json','image/target-result.bin','qemu/verification-matrix.json')]
        if folder!='finish':files.append(folder+'/checkpoint/manifest.json')
    report['artifact_hashes']={f:digest((out/f).read_bytes()) for f in files}
    report['chain_construction_sha256']=digest(Path(__file__).read_bytes())
    (out/'workflow.json').write_text(json.dumps(report,indent=2)+'\n');verify_chain(out)
    return report


def verify_chain(directory):
    directory=Path(directory).resolve();report=json.loads((directory/'workflow.json').read_text())
    generic=report.get('format')=='osrec-application-joint-checkpoint-chain-v1'
    if report.get('format') not in ('osrec-c-joint-checkpoint-chain-v1','osrec-application-joint-checkpoint-chain-v1') or report.get('status')!='verified':raise ValueError('not a verified checkpoint chain')
    checked_files(directory,report['artifact_hashes']);total=report['total_calls'];start=report.get('first_ordinal',0)
    if not generic and start:raise ValueError('C chain must begin at ordinal zero')
    points=checked_ordinals(report['pause_ordinals'],total,start,allow_empty=generic and start>0)
    if len(report['stages'])!=len(points)+1 or report['logical_calls']!=total-start:raise ValueError('incomplete checkpoint chain')
    initial=verify_package(directory/'routes');previous=None;generation=0
    if len(initial['sites'])!=total-start or initial['sites'][0]['ordinal']!=start:raise ValueError('checkpoint chain initial route mismatch')
    if generic:
        if report['input_mode']=='elf':
            if start or report['initial_checkpoint_manifest_sha256'] is not None:raise ValueError('ELF chain must begin with captured kernel entry state')
            if digest((directory/'inputs/application.elf').read_bytes())!=initial['elf_sha256'] or digest((directory/'inputs/checkpoint.json').read_bytes())!=initial['checkpoint_sha256']:raise ValueError('checkpoint chain ELF input mismatch')
        elif report['input_mode']=='joint-checkpoint':
            first=directory/('stage-0' if points else 'finish')/'image'
            kernel=json.loads((first/'kernel-manifest.json').read_text());joint=verify_joint(directory/'initial-checkpoint',kernel)
            previous=digest((directory/'initial-checkpoint/manifest.json').read_bytes());generation=joint.get('generation',1)
            if not start or joint['pause_ordinal']!=start or previous!=report['initial_checkpoint_manifest_sha256'] or joint['application_manifest_sha256']!=digest((directory/'routes/route-plan.json').read_bytes()):raise ValueError('checkpoint chain initial joint state mismatch')
        else:raise ValueError('unsupported checkpoint chain input mode')
    for i,row in enumerate(report['stages']):
        stop=points[i] if i<len(points) else total;folder='stage-'+str(i) if i<len(points) else 'finish';stage=directory/folder
        if row['stage']!=folder or row['input_ordinal']!=start or row['output_ordinal']!=stop or row['logical_calls']!=stop-start or row['input_checkpoint_manifest_sha256']!=previous:raise ValueError('checkpoint chain interval/parent mismatch')
        image=json.loads((stage/'image/manifest.json').read_text());kernel=json.loads((stage/'image/kernel-manifest.json').read_text());observed=image['target_observations'];require_success(observed)
        from slice_port_bundle import verify_published
        verify_published(stage/'image/kernel-port-inputs',kernel)
        if digest((stage/'image/kernel-manifest.json').read_bytes())!=report['kernel_manifest_sha256'] or image['checkpoint_mode']!=('load' if folder=='finish' else 'advance' if previous else 'save') or observed!=row['observations'] or observed['call_count']!=total or observed['pause_ordinal']!=(start if folder=='finish' else stop):raise ValueError('checkpoint chain image mismatch')
        if not i and image['application_manifest_sha256']!=digest((directory/'routes/route-plan.json').read_bytes()):raise ValueError('checkpoint chain initial application mismatch')
        if any(observed.get(k)!=v for k,v in image['expected_result'].items()) or (image['checkpoint_mode']=='advance' and observed['checkpoint_start_ordinal']!=start):raise ValueError('checkpoint chain result interval mismatch')
        checked_files(stage/'image',{f:image[k] for f,k in (('slices.elf','elf_sha256'),('slices.bin','binary_sha256'),('slices.a','archive_sha256'),('kernel-manifest.json','kernel_library_manifest_sha256'))})
        for tree,expected in (('sources',image['source_hashes']),('kernel-sources',kernel['source_hashes'])):
            actual={str(p.relative_to(stage/'image'/tree)):digest(p.read_bytes()) for p in (stage/'image'/tree).rglob('*') if p.is_file()}
            if actual!=expected:raise ValueError('checkpoint chain image source mismatch')
        verify_package(stage/'image/application')
        if digest((stage/'image/application/route-plan.json').read_bytes())!=image['application_manifest_sha256']:raise ValueError('checkpoint chain application identity mismatch')
        if previous:verify_joint(stage/'image/joint-checkpoint',kernel)
        matrix=json.loads((stage/'qemu/verification-matrix.json').read_text())
        if matrix['status']!='verified' or len(matrix['executions'])!=4 or row['qemu_executions']!=4 or matrix['image_manifest_sha256']!=digest((stage/'image/manifest.json').read_bytes()) or matrix['result_sha256']!=digest((stage/'image/target-result.bin').read_bytes()):raise ValueError('checkpoint chain QEMU evidence mismatch')
        if previous and image['joint_checkpoint_manifest_sha256']!=previous:raise ValueError('checkpoint chain input image mismatch')
        if folder!='finish':
            joint=verify_joint(stage/'checkpoint',kernel)
            generation+=1
            if joint['pause_ordinal']!=stop or joint['checkpoint_start_ordinal']!=start or joint['input_checkpoint_manifest_sha256']!=previous or joint['generation']!=generation or row['generation']!=generation:raise ValueError('checkpoint chain generation mismatch')
            previous=digest((stage/'checkpoint/manifest.json').read_bytes())
        start=stop
    return report


