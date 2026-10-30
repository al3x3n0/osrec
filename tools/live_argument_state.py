"""Live argument-object helper snapshots and standalone, pointer-free replay."""
import argparse
import json
from pathlib import Path
import re
import shutil
import struct
import tempfile

from klee_liteos import ROOT,digest

HELPER='OsProcessExitCodeSignalIsSet'
ROUTE=65536  # Capture-adapter helper route, not a Linux/OHOS syscall number.
ARGUMENT_POLICY=ROOT/'integrations/liteos_a/entry-argument-boundaries.json'
SOURCE_LOCK=ROOT/'integrations/liteos_a/entry-argument-source-lock.json'
MODEL='''#include <stdint.h>
/* Capture uses ARMv7 UINT32 exitCode and size_t/BOOL, independent of host ABI. */
typedef uint32_t BOOL;
typedef struct { uint32_t exitCode; } LosProcessCB;
#define STATIC static
#define INLINE inline
'''
CONST_HELPER='OsProcessIsPGroupLeader'
CONST_POLICY=ROOT/'integrations/liteos_a/entry-const-argument-boundaries.json'
CONST_SOURCE_LOCK=ROOT/'integrations/liteos_a/entry-const-argument-source-lock.json'
CONST_MODEL=MODEL.replace('UINT32 exitCode','UINT16 processStatus').replace('uint32_t exitCode','uint16_t processStatus')+'#define OS_PROCESS_FLAG_GROUP_LEADER UINT32_C(2048)\n'


def profile_settings(profile='exit-code'):
    if profile=='exit-code':
        return dict(helper=HELPER,route=ROUTE,policy=ARGUMENT_POLICY,lock=SOURCE_LOCK,model=MODEL,
                    field='exitCode',width=4,field_type='unsigned int',pointer='LosProcessCB *')
    if profile=='process-group-leader':
        return dict(helper=CONST_HELPER,route=65537,policy=CONST_POLICY,lock=CONST_SOURCE_LOCK,model=CONST_MODEL,
                    field='processStatus',width=2,field_type='const unsigned short',pointer='const LosProcessCB *')
    if profile=='exit-signal-write':
        return dict(helper='OsProcessExitCodeSignalSet',route=65538,
                    policy=ROOT/'integrations/liteos_a/entry-write-argument-boundaries.json',
                    lock=ROOT/'integrations/liteos_a/entry-write-argument-source-lock.json',
                    model=MODEL+'typedef uint32_t UINT32;\n#define VOID void\n',
                    field='exitCode',width=4,field_type='unsigned int',pointer='LosProcessCB *',
                    effects=True,return_type='VOID',parameter_suffix=', UINT32 signal')
    if profile=='exit-signal-session':
        settings=profile_settings('exit-signal-write')
        return {**settings,'route':65539,'continuous':True,
                'policy':ROOT/'integrations/liteos_a/entry-session-argument-boundaries.json'}
    if profile=='parent-exit-signal-session':
        settings=profile_settings('exit-signal-session')
        return {**settings,'helper':'OsrecParentExitSignalSet','source_helper':'OsProcessExitCodeSignalSet',
                'route':65540,'nested':True,
                'adapter':ROOT/'integrations/liteos_qemu/parent_argument_adapter.h',
                'policy':ROOT/'integrations/liteos_a/entry-parent-argument-boundaries.json',
                'model':settings['model'].replace('typedef struct { uint32_t exitCode; } LosProcessCB;',
                    'typedef struct ProcessCB { uint32_t exitCode; struct ProcessCB *parentProcess; } LosProcessCB;')}
    raise ValueError('unsupported live argument profile')


def expected_return(value,profile):
    return value&0x7f if profile=='exit-code' else int(bool(value&2048))


def prepare_source(kernel_root,profile='exit-code'):
    from freestanding_armv7 import run
    settings=profile_settings(profile);lock=json.loads(settings['lock'].read_text())
    revision=run(['git','-C',kernel_root,'rev-parse','HEAD']).stdout.strip()
    if revision!=lock['revision']:raise ValueError('argument helper revision differs')
    for base in (kernel_root,ROOT/'build/ohos/kernel/liteos_a'):
        for file,expected in lock['files'].items():
            if digest((base/file).read_bytes())!=expected:raise ValueError('argument helper source/type changed: '+file)
    text=(kernel_root/lock['source']).read_text()
    parameter=re.escape(settings['pointer'])
    match=re.search(r'STATIC INLINE '+settings.get('return_type','BOOL')+' '+settings.get('source_helper',settings['helper'])+r'\('+parameter+
                    r'processCB'+re.escape(settings.get('parameter_suffix',''))+r'\)\s*\{.*?\n\}',text,re.S)
    if not match or digest(match[0].encode())!=lock['function_sha256']:raise ValueError('argument helper body changed')
    if profile=='process-group-leader':
        constant=re.search(r'^#define OS_PROCESS_FLAG_GROUP_LEADER\s+(0x[0-9a-fA-F]+)U\s*$',text,re.M)
        if not constant or int(constant[1],16)!=2048 or lock.get('constants')!={'OS_PROCESS_FLAG_GROUP_LEADER':2048}:
            raise ValueError('process group leader constant differs')
    license_text=text[:text.index('*/')+2]
    source=license_text+'\n'+match[0]+'\n'
    if settings.get('adapter'):
        source+=settings['adapter'].read_text()
        lock={**lock,'capture_adapter':str(settings['adapter'].relative_to(ROOT)),
              'capture_adapter_sha256':digest(settings['adapter'].read_bytes()),'capture_root':settings['helper']}
    return source,lock


def validate_capture(frames,plan,witness,profile='exit-code'):
    from automated_entry_state import validate_snapshot
    from reconstruct_entry_state import reconstruction_header
    s=profile_settings(profile)
    policy=json.loads(s['policy'].read_text())['argument_objects'][s['helper']]['processCB']
    providers=plan['object_providers']
    if (plan['root']!=s['helper'] or plan['blockers'] or plan.get('state_writes') or
        plan['arguments']!=[{'name':'processCB','type':s['pointer'],'pointer':True}] or
        len(providers)!=1 or providers[0]!={'function':'osrec_argument_processCB','return_type':s['pointer'],
            'contract':policy,'binding_kind':'root_argument','argument':'processCB','argument_index':0} or
        len(plan['entry_reads'])!=1 or plan['entry_reads'][0]['path']!='osrec_argument_processCB()->'+s['field'] or
        plan['entry_reads'][0]['pointer_edge'] or plan['entry_reads'][0]['type']!=s['field_type']):
        raise ValueError('live argument helper discovery contract differs')
    if len(witness)!=6*12 or [(f.get('invocation'),f.get('syscall')) for f in frames]!=list(enumerate([s['route']]*6)):
        raise ValueError('live argument helper observations are incomplete')
    calls=[];sessions=set()
    for index,frame in enumerate(frames):
        validate_snapshot(frame,plan)
        if len(frame['objects'])!=1 or frame['objects'][0]['type']!='LosProcessCB' or frame.get('arguments'):
            raise ValueError('live argument root must bind one process, with no scalar pointer bytes')
        oid=frame['objects'][0]['id'];session=frame['objects'][0].get('session_id')
        if type(session) is not int or session<=0:raise ValueError('live argument process lifetime identity is missing')
        sessions.add(session)
        if frame['roots']!=[{'name':'osrec_argument_processCB()','object_id':oid}]:raise ValueError('live argument process binding differs')
        if len(frame['fields'])!=1:raise ValueError('live argument field footprint differs')
        field=frame['fields'][0]
        if field['name']!=s['field'] or field['kind']!='scalar' or field['bytes']!=s['width']:raise ValueError('live argument field schema differs')
        ordinal,value,raw=struct.unpack_from('<3I',witness,index*12)
        if ordinal!=index or int.from_bytes(bytes.fromhex(field['data']),'little')!=value or raw!=expected_return(value,profile):
            raise ValueError('live argument snapshot, direct field or original return differs')
        calls.append({'number':s['route'],'raw_bits':raw,'exit_code' if profile=='exit-code' else 'process_status':value})
    if len(sessions)!=1:raise ValueError('live argument process identity changed')
    # Also rejects extra objects/fields and unsupported storage before publication.
    reconstruction_header(frames,[plan]*6)
    return calls


def parse_capture(text,plan,profile='exit-code'):
    if re.search(r'^OSREC_ARGUMENT_EFFECT ',text,re.M):raise ValueError('readonly argument capture contains write effects')
    frames=[json.loads(value) for value in re.findall(r'^OSREC_ARGUMENT_ENTRY (.+)\r?$',text,re.M)]
    rows=re.findall(r'^OSREC_ARGUMENT_KERNEL ([0-9a-f]+)\r?$',text,re.M)
    if len(rows)!=1:raise ValueError('live argument kernel witness missing or duplicated')
    witness=bytes.fromhex(rows[0]);validate_capture(frames,plan,witness,profile)
    return frames,witness


def load_capture(capture,kernel_root):
    from reconstruct_entry_state import load_reconstruction
    report=json.loads((capture/'report.json').read_text());metadata=report.get('argument_entry_capture',{})
    profile=metadata.get('profile','exit-code');s=profile_settings(profile)
    if s.get('effects'):
        from live_argument_effects import load_capture as load_effect_capture
        return load_effect_capture(capture,kernel_root)
    source,identity=prepare_source(kernel_root,profile)
    bundle=json.loads((capture/'entry-state-plan.json').read_text())
    if bundle.get('argument_boundary_policy_sha256')!=digest(s['policy'].read_bytes()):
        raise ValueError('argument boundary policy changed')
    if metadata.get('function')!=s['helper'] or metadata.get('calls')!=6 or metadata.get('source_identity')!=identity:
        raise ValueError('argument helper source/capture metadata differs')
    witness=(capture/'argument-entry-kernel.bin').read_bytes()
    if digest(witness)!=metadata.get('sha256'):raise ValueError('argument helper witness hash differs')
    header,frames,hashes=load_reconstruction(capture,{s['route']:s['helper']},[s['route']]*6)
    plans=[p for p in bundle['plans'] if p['root']==s['helper']]
    if len(plans)!=1:raise ValueError('argument helper plan is missing or duplicated')
    calls=validate_capture(frames,plans[0],witness,profile)
    # Bind the binary witness and normalized frames back to the retained native log.
    log=(capture/'boot.log').read_text()
    if digest((capture/'boot.log').read_bytes())!=report['boot_log_sha256']:raise ValueError('argument boot log hash differs')
    logged_frames,logged_witness=parse_capture(log,plans[0],profile)
    if logged_frames!=frames or logged_witness!=witness:raise ValueError('argument capture differs from native log')
    return header,frames,calls,hashes,source,identity


def export(args):
    from freestanding_elf import target_metadata
    from entry_state_image import build_and_verify
    if args.arch!='aarch64':raise ValueError('live argument images currently require AArch64')
    if args.out.exists():raise FileExistsError(args.out)
    if any(args.out.is_relative_to(p) for p in (args.capture,args.kernel_root,ROOT/'build/ohos')):
        raise ValueError('image output must be outside capture and kernel source')
    header,frames,calls,hashes,source,identity=load_capture(args.capture,args.kernel_root)
    profile=json.loads((args.capture/'report.json').read_text())['argument_entry_capture'].get('profile','exit-code')
    s=profile_settings(profile)
    with tempfile.TemporaryDirectory(prefix='osrec-live-arguments-') as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir()
        (sources/'entry_model.h').write_text(s['model'])
        (sources/'entry_reconstruction.h').write_text(header)
        adapter='''uint32_t osrec_invoke(uint32_t number) {
 if(number!=@ROUTE@) return UINT32_MAX;
 return (uint32_t)@HELPER@(osrec_bound_osrec_argument_processCB);
}
'''
        if s.get('effects'):
            adapter='''static uint32_t osrec_invocation;
uint32_t osrec_invoke(uint32_t number) {
 if(number!=@ROUTE@ || osrec_invocation>=6) return UINT32_MAX;
 @HELPER@(osrec_bound_osrec_argument_processCB,osrec_argument(osrec_invocation,1));
 ++osrec_invocation;
 return 0; /* Adapter completion marker: the original helper returns VOID. */
}
'''
        (sources/'entry_adapter.h').write_text(source+adapter.replace('@ROUTE@',str(s['route'])).replace('@HELPER@',s['helper']))
        (sources/'entry_checkpoint.h').write_text('#define OSREC_CHECKPOINT_CALLS 6\nstruct checkpoint_call {uint32_t number,raw;};\nstatic const struct checkpoint_call checkpoint_calls[6]={'+
            ','.join('{'+str(s['route'])+',UINT32_C('+str(c['raw_bits'])+')}' for c in calls)+'};\n')
        shutil.copy2(ROOT/'integrations/rtl_aarch64/entry_state_replay.c',sources/'entry_state_replay.c')
        continuous=s.get('continuous',False)
        inspection,observed,raw,image,binary=build_and_verify(args,sources,calls,continuous,bool(s.get('effects')),'arguments')
        report={'format':'osrec-live-argument-image-v1','profile':profile,'function':s['helper'],'source_identity':identity,
            'capture_scope':'six explicit capture-adapter helper calls on the real current process under scheduler lock',
            'kernel_scheduler_reproduction':False,'entry_states_restored_independently':not continuous,
            'state_continuity_reproduced':continuous,
            'runtime_host_interaction':False,'rtl_validated':False,'cycle_timing_equivalence_verified':False,
            'target':target_metadata(inspection,8),'image_audit':inspection,'target_observations':observed,
            'raw_image_execution_match':True,'automated_capture_hashes':hashes,
            'capture_report_sha256':digest((args.capture/'report.json').read_bytes()),
            'kernel_witness_sha256':digest((args.capture/'argument-entry-kernel.bin').read_bytes()),
            'elf_sha256':digest(image.read_bytes()),'binary_sha256':digest(binary.read_bytes()),
            'source_hashes':{p.name:digest(p.read_bytes()) for p in sorted(sources.iterdir())}}
        if s.get('effects'):
            report.update(capture_scope='six controlled original helper writes on PID 1 current process; field restored before scheduler unlock',
                          captured_scalar_write_effects=True,native_field_restored_after_each_call=True,
                          return_semantics='VOID helper; zero is the replay adapter completion marker')
            if continuous:
                report.update(capture_scope='six original helper writes in one locked batch; native field restored once after the session',
                              native_field_restored_after_each_call=False,native_field_restored_after_session=True)
            if s.get('nested'):
                report.update(capture_scope='before workload child first getppid, capture adapter follows parentProcess; six original helper writes on distinct PID 1 parent in one locked batch; parent exitCode restored once',
                              original_helper=s['source_helper'],capture_adapter=s['helper'],nested_scalar_write_effects=True)
        publish=stage/'publish';publish.mkdir();shutil.copytree(sources,publish/'sources')
        for file in (image,binary):shutil.copy2(file,publish/file.name)
        (publish/'target-result.bin').write_bytes(raw)
        (publish/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
        (publish/'entry-state-snapshots.json').write_text(json.dumps(frames,indent=2)+'\n')
        if s.get('effects'):shutil.copy2(args.capture/'entry-state-effects.json',publish/'entry-state-effects.json')
        args.out.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(publish,args.out)
    return report


def main():
    from freestanding_elf import add_target_arguments
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',required=True,type=Path);parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--kernel-root',type=Path,default=ROOT/'build/kernel_liteos_a')
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--qemu',default='qemu-system-aarch64');add_target_arguments(parser);args=parser.parse_args()
    for key in ('capture','out','kernel_root','llvm_bin'):setattr(args,key,getattr(args,key).resolve())
    report=export(args)
    print(json.dumps({'image':str(args.out/'arguments.elf'),'completed_calls':report['target_observations']['completed_calls'],
        'runtime_host_interaction':False},indent=2))


if __name__=='__main__':main()
