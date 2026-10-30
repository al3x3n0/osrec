#!/usr/bin/env python3
"""Export original getresuid with reviewed ordered copies into host-free AArch64 images."""
import argparse,json,re,shutil,struct,tempfile
from pathlib import Path
from klee_liteos import ROOT,digest
from export_freestanding_setgroups import prepare_source
from getresuid_capture import validate_credential_query,credential_state,PROFILES,output_offsets,credential_values
from getgroups_capture import output_bytes
from freestanding_armv7 import run,audit
from freestanding_elf import prepare_target,add_target_arguments,target_metadata
from run_freestanding_armv7 import observe,require_success

def load_capture(capture,lock,kind='getresuid'):
    profile=PROFILES[kind];macro='OSREC_'+kind.upper()+'_CAPTURE';prefix=profile['prefix']
    report=json.loads((capture/'report.json').read_text());m=report[f'{kind}_capture']
    if m.get('file')!=f'{kind}-capture.json' or m.get('calls')!=4 or m.get('original_syscall_executed') is not True or m.get('scoped_credential_fixture') is not True:raise ValueError(f'{kind} capture scope differs')
    for name,expected in [(f'{kind}-capture.json',m['sha256']),('entry-state-lifetimes.json',report['automated_capture_hashes']['lifetimes']),('boot.log',report['boot_log_sha256']),('liteos.bin',report['kernel_image_sha256']),('auto-entry-config.h',report['auto_entry_config_sha256'])]:
        if digest((capture/name).read_bytes())!=expected:raise ValueError(f'{kind} provenance differs: '+name)
    config=(ROOT/'build/ohos/kernel/liteos_a/.config').read_bytes();auto=(capture/'auto-entry-config.h').read_bytes()
    if digest(config)!=report['kernel_config_sha256'] or not re.search(rb'^LOSCFG_SECURITY_CAPABILITY=y$',config,re.M) or re.search(rb'^LOSCFG_USER_CONTAINER=(?:y|1)$',config,re.M):raise ValueError(f'{kind} kernel configuration differs')
    if len(re.findall(('^#define '+macro+' 1$').encode(),auto,re.M))!=1 or re.search(('^#define OSREC_'+('GETRESGID' if kind=='getresuid' else 'GETRESUID')+'_CAPTURE ').encode(),auto,re.M) or re.search(rb'^#define OSREC_GETGROUPS_CAPTURE ',auto,re.M) or re.search(rb'^#define OSREC_SETGROUPS_(?:FAILURES|COPY_FAILURES|PARTIAL_COPY_FAILURES) ',auto,re.M):raise ValueError(f'{kind} capture construction differs')
    bundle=json.loads((capture/f'{kind}-capture.json').read_text())
    if bundle['source_sha256']!=lock['source_sha256'] or bundle['type_header_sha256']!=lock['headers']['kernel/base/include/los_process_pri.h']:raise ValueError(f'{kind} source identity differs')
    calls=validate_credential_query(bundle,json.loads((capture/'entry-state-lifetimes.json').read_text()),kind)
    offsets=output_offsets(bundle,kind)
    configured=[]
    for i in range(3):
        rows=re.findall(('^#define OSREC_CREDENTIAL_OUTPUT_'+str(i)+r' (.*)$').encode(),auto,re.M)
        if len(rows)>1 or (rows and not re.fullmatch(rb'[0-9]+',rows[0])):raise ValueError(kind+' output configuration differs')
        configured.append(int(rows[0]) if rows else None)
    if configured not in ([None,None,None],offsets) or (bundle['format'].endswith(('-v2','-v3')) and configured!=offsets):raise ValueError(kind+' output configuration differs')

    configured_ids=[]
    for key in ('REAL','EFFECTIVE'):
        rows=re.findall(('^#define OSREC_CREDENTIAL_'+key+r'_ID (.*)$').encode(),auto,re.M)
        if len(rows)>1 or (rows and not re.fullmatch(rb'(?:0|[1-9][0-9]*)U',rows[0])):raise ValueError(kind+' credential configuration differs')
        configured_ids.append(int(rows[0][:-1]) if rows else None)
    values=credential_values(bundle,kind)
    if configured_ids not in ([None,None],values) or (bundle['format'].endswith('-v3') and configured_ids!=values):raise ValueError(kind+' credential configuration differs')

    user=re.findall(('^OSREC_'+prefix+'_USER ([0-9a-f]+)\r?$').encode(),(capture/'boot.log').read_bytes(),re.M)
    expected=b''.join(struct.pack('<3I',i,c['raw'],16)+output_bytes(c['exit']) for i,c in enumerate(calls))
    if len(user)!=1 or bytes.fromhex(user[0].decode())!=expected:raise ValueError(f'{kind} independent user observations differ')
    return report,bundle,calls

def verify_generated_fields(capture,report,bundle,kind,llvm_bin):
    from automated_entry_state import generate,validate_snapshot
    from credential_entry_state import QUERY_ROOTS,COPY_MODEL,GENERATION
    metadata=report[kind+'_capture'];auto=(capture/'auto-entry-config.h').read_bytes()
    markers=re.findall(rb'^#define OSREC_GENERATED_CREDENTIAL_FIELDS (.*)$',auto,re.M)
    if not markers and 'generated_entry_fields' not in metadata and 'entry_state_generation' not in bundle:return None
    if markers!=[b'1'] or metadata.get('generated_entry_fields') is not True or bundle.get('entry_state_generation')!=GENERATION:raise ValueError(kind+' generated field construction differs')
    for filename,key in [('entry-state-plan.json','plan'),('entry-state-capture.h','generated_hooks')]:
        if digest((capture/filename).read_bytes())!=report['automated_capture_hashes'][key]:raise ValueError(kind+' generated field provenance differs')
    plan=json.loads((capture/'entry-state-plan.json').read_text());header=(capture/'entry-state-capture.h').read_text();root=QUERY_ROOTS[kind]
    if plan.get('format')!='osrec-entry-state-plan-v1' or plan.get('credential_queries')!=[root] or plan.get('additional_boundary_models')!={'LOS_ArchCopyToUser':COPY_MODEL} or plan.get('capture_header_sha256')!=digest(header.encode()):raise ValueError(kind+' generated field policy differs')
    # Reanalyze the verified configured source with controlled compiler arguments.
    # Rehashing a forged plan/header does not satisfy this independent check.
    with tempfile.TemporaryDirectory(prefix='osrec-credential-analysis-') as directory:
        fresh,fresh_header=generate(ROOT/'build/ohos',llvm_bin,Path(directory),credential_queries=[root])
    if len(plan['source_identities'])!=len(fresh['source_identities']) or any(any(old[key]!=new[key] for key in ('source','source_sha256','dependencies','compiler')) for old,new in zip(plan['source_identities'],fresh['source_identities'])):raise ValueError(kind+' generated field source identity differs')
    discovered=[p for p in plan['plans'] if p['root']==root]
    expected=[p for p in fresh['plans'] if p['root']==root]
    projected=[p for p in plan['capture_plans'] if p['root']=='credential_'+root]
    if discovered!=expected or projected!=[p for p in fresh['capture_plans'] if p['root']=='credential_'+root] or header!=fresh_header or plan['boundary_policy_sha256']!=fresh['boundary_policy_sha256']:raise ValueError(kind+' generated field analysis differs')
    for call in bundle['calls']:
        for key in ('entry','exit'):validate_snapshot(call[key],projected[0])
    return {'generation':GENERATION,'analysis':'configured Clang may-read discovery; completeness and minimality not proven','provider_bridge':projected[0]['provider_bridge'],'memory_effect_model':COPY_MODEL,'plan_sha256':digest((capture/'entry-state-plan.json').read_bytes()),'generated_hooks_sha256':digest(header.encode()),'independent_source_reanalysis':True}

def checkpoint_header(calls,kind='getresuid'):
    number=PROFILES[kind]['number']
    constants=lambda vs:','.join('UINT32_C('+str(v)+')' for v in vs)
    offsets=[ref['offset'] for ref in calls[0]['arguments']]
    rows=','.join('{{'+constants(struct.unpack('<4I',output_bytes(c['entry'])))+'},{'+constants(struct.unpack('<4I',output_bytes(c['exit'])))+'}}' for c in calls)
    return '#define OSREC_CHECKPOINT_CALLS 4\nstruct checkpoint_call {uint32_t number,raw;};\nstatic const struct checkpoint_call checkpoint_calls[4]={'+','.join('{'+str(number)+',UINT32_C('+str(c['raw'])+')}' for c in calls)+'};\nstatic const uint32_t checkpoint_ids[2]={'+constants(credential_state(calls[0]['entry'],kind)[0])+'};\nstatic const uint32_t checkpoint_offsets[3]={'+constants(offsets)+'};\nstruct output_state {uint32_t before[4],after[4];};\nstatic const struct output_state checkpoint_output[4]={'+rows+'};\n'

def export(args,kind='getresuid'):
    profile=PROFILES[kind];number=profile['number'];function='SysGetRealEffSave'+('UserID' if kind=='getresuid' else 'GroupID');fields='/'.join(profile['fields']);label='UID' if kind=='getresuid' else 'GID'
    if args.arch!='aarch64' or args.out.exists() or any(args.out.is_relative_to(p.resolve()) for p in (args.capture,args.kernel_root,ROOT/'build/ohos')):raise ValueError('choose a new AArch64 output outside capture/source directories')
    source,lock=prepare_source(args.kernel_root,ROOT/f'integrations/liteos_a/{kind}-source-lock.json',f'{kind}_model.h')
    report,bundle,calls=load_capture(args.capture,lock,kind)
    generated=verify_generated_fields(args.capture,report,bundle,kind,args.llvm_bin)
    with tempfile.TemporaryDirectory(prefix=f'osrec-{kind}-') as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(args,sources)
        (sources/f'{kind}.c').write_text(source)
        shutil.copy2(ROOT/f'integrations/liteos_a/{kind}_model.h',sources/f'{kind}_model.h')
        (sources/'entry_model.h').write_text(f'#include "{kind}_model.h"\n')
        (sources/'entry_reconstruction.h').write_text('#define OSREC_HAS_WRITE_EFFECTS 1\n#define OSREC_CONTINUOUS_REPLAY 1\nstatic int osrec_restore(unsigned);\nstatic int osrec_entry_matches(unsigned);\nstatic int osrec_state_matches(unsigned);\n')
        (sources/'entry_checkpoint.h').write_text(checkpoint_header(calls,kind))
        shutil.copy2(ROOT/'integrations/rtl_aarch64/credential_output_adapter.h',sources/'entry_adapter.h')
        shutil.copy2(ROOT/'integrations/rtl_aarch64/entry_state_replay.c',sources/'entry_state_replay.c')
        image=stage/f'{kind}.elf';binary=stage/f'{kind}.bin'
        run([args.llvm_bin/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/f'{kind}.c','-o',image])
        inspection=audit(image,args.llvm_bin);run([args.llvm_bin/'llvm-objcopy','-O','binary',image,binary])
        observed,raw=observe(image,args.qemu);require_success(observed)
        raw_observed,binary_raw=observe(binary,args.qemu,descriptor=image);require_success(raw_observed)
        if raw!=binary_raw or observed['actual_calls']!=[{'number':number,'raw_bits':c['raw']} for c in calls]:raise ValueError(f'{kind} ELF/raw observations differ')
        manifest={'format':f'osrec-freestanding-{kind}-'+bundle['format'].rsplit('-',1)[1],'source_identity':lock,'target':target_metadata(inspection,8),'capture_sha256':report[f'{kind}_capture']['sha256'],'live_report_sha256':digest((args.capture/'report.json').read_bytes()),'kernel_image_sha256':report['kernel_image_sha256'],'credential_fixture':bundle['credential_fixture'],'credential_value_semantics':'32-bit User field bit patterns; original signed-int output locals preserve these bits on the verified AArch32/AArch64 builds','output_offsets':output_offsets(bundle,kind),'output_copy_semantics':'ordered four-byte little-endian stores; shared, overlapping and unaligned output ranges supported within the witness',
            'scope':f'four original {function} calls: success and NULL in each of three output positions in a shared 16-byte witness; initial state restored once; subsequent entry/exit states asserted',
            'entry_state_generation':generated or {'generation':'reviewed-fields-legacy','independent_source_reanalysis':False},
            'entry_state_reconstruction':f'User {fields} scalar fields and current process-to-user edge; target-native pointers',
            'modeled_dependencies':['scheduler lock/unlock','stable current User provider','three ordered 4-byte user copies; NULL range rejection'],
            'saved_id_semantics':f'pinned LiteOS-A body reports {profile["fields"][1]} as saved {label}; no separate saved {label} field',
            'copy_failure_contract':'native NULL range rejection; earlier copies remain visible and later copies are not attempted; MMU faults excluded',
            'runtime_host_interaction':False,'guest_io':False,'system_libraries':[],'native_layout_reproduction':False,'scheduler_irq_reproduction':False,'generic_copy_analysis':False,'rtl_validated':False,'cycle_timing_equivalence_verified':False,
            'target_observations':observed,'raw_image_execution_match':True,'image_audit':inspection,'target_result_sha256':digest(raw),'source_hashes':{p.name:digest(p.read_bytes()) for p in sorted(sources.iterdir())},'elf_sha256':digest(image.read_bytes()),'binary_sha256':digest(binary.read_bytes())}
        published=stage/'published';published.mkdir();shutil.copytree(sources,published/'sources')
        shutil.copy2(image,published/f'{kind}.elf');shutil.copy2(binary,published/f'{kind}.bin');shutil.copy2(args.capture/f'{kind}-capture.json',published/f'{kind}-capture.json');shutil.copy2(args.capture/'entry-state-lifetimes.json',published/'entry-state-lifetimes.json')
        if generated:
            shutil.copy2(args.capture/'entry-state-plan.json',published/'entry-state-plan.json');shutil.copy2(args.capture/'entry-state-capture.h',published/'entry-state-capture.h')
        (published/'target-result.bin').write_bytes(raw);(published/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        args.out.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(published,args.out)
    print(json.dumps({'image':str(args.out/f'{kind}.elf'),'completed_calls':4,'user_copy_attempts':observed['user_copy_attempts'],'user_copy_bytes':observed['user_copy_bytes'],'runtime_host_interaction':False},indent=2))

def main(kind='getresuid'):
    parser=argparse.ArgumentParser(description=f'Export original {kind} with reviewed ordered copies into host-free AArch64 images.');parser.add_argument('--capture',required=True,type=Path);parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--kernel-root',type=Path,default=ROOT/'build/kernel_liteos_a');parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));parser.add_argument('--qemu',default='qemu-system-aarch64')
    add_target_arguments(parser);args=parser.parse_args()
    for key in ('capture','out','kernel_root','llvm_bin'):setattr(args,key,getattr(args,key).resolve())
    export(args,kind)
if __name__=='__main__':main()
