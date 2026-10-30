#!/usr/bin/env python3
"""Export reviewed live SysGetGroups into host-free AArch64 ELF and raw images."""
import argparse,json,re,shutil,struct,tempfile
from pathlib import Path
from klee_liteos import ROOT,digest
from export_freestanding_setgroups import prepare_source
from getgroups_capture import validate_getgroups,credential_state,output_bytes,null_output_profile
from freestanding_armv7 import run,audit
from freestanding_elf import prepare_target,add_target_arguments,target_metadata
from run_freestanding_armv7 import observe,require_success

def load_capture(capture,lock):
    report=json.loads((capture/'report.json').read_text());metadata=report['getgroups_capture']
    if metadata['file']!='getgroups-capture.json' or metadata['calls']!=3 or metadata['original_syscall_executed'] is not True:raise ValueError('getgroups capture scope differs')
    if digest((capture/metadata['file']).read_bytes())!=metadata['sha256']:raise ValueError('getgroups capture hash differs')
    for filename,expected in [('entry-state-lifetimes.json',report['automated_capture_hashes']['lifetimes']),('liteos.bin',report['kernel_image_sha256']),('boot.log',report['boot_log_sha256']),('auto-entry-config.h',report['auto_entry_config_sha256'])]:
        if digest((capture/filename).read_bytes())!=expected:raise ValueError('getgroups capture provenance differs: '+filename)
    config=(ROOT/'build/ohos/kernel/liteos_a/.config').read_bytes();auto=(capture/'auto-entry-config.h').read_bytes()
    if digest(config)!=report['kernel_config_sha256'] or not re.search(rb'^LOSCFG_SECURITY_CAPABILITY=y$',config,re.M) or re.search(rb'^LOSCFG_USER_CONTAINER=(?:y|1)$',config,re.M):raise ValueError('getgroups configuration differs')
    if not re.search(rb'^#define OSREC_GETGROUPS_CAPTURE 1$',auto,re.M) or re.search(rb'^#define OSREC_SETGROUPS_(?:FAILURES|COPY_FAILURES|PARTIAL_COPY_FAILURES) 1$',auto,re.M):raise ValueError('getgroups capture construction differs')
    if not report['automated_session_identity']['allocation_reuse_tracking'] or 205 not in report['automated_session_identity']['allocation_reuse_scope']:raise ValueError('getgroups allocator scope missing')
    bundle=json.loads((capture/metadata['file']).read_text())
    if bundle['source_sha256']!=lock['source_sha256'] or bundle['type_header_sha256']!=lock['headers']['kernel/base/include/los_process_pri.h']:raise ValueError('getgroups source identity differs')
    prefixes=re.findall(rb'^#define OSREC_GETGROUPS_COPY_BYTES ([0-9]+)$',auto,re.M)
    if bundle['format']!='osrec-live-getgroups-v11' and (prefixes or 'copy_bytes' in bundle or 'copy_bytes' in metadata):raise ValueError('legacy getgroups capture cannot claim copy prefix')
    if bundle['format'] in ('osrec-live-getgroups-v2','osrec-live-getgroups-v3','osrec-live-getgroups-v4','osrec-live-getgroups-v5','osrec-live-getgroups-v6','osrec-live-getgroups-v7','osrec-live-getgroups-v8','osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12'):
        injected=bool(re.search(rb'^#define OSREC_GETGROUPS_COPY_FAILURES 1$',auto,re.M))
        partial=bool(re.search(rb'^#define OSREC_GETGROUPS_PARTIAL_COPY_FAILURES 1$',auto,re.M))
        prefix_profile=bundle['format']=='osrec-live-getgroups-v11'
        if prefix_profile:
            if type(metadata.get('copy_bytes')) is not int or len(prefixes)!=1 or int(prefixes[0])!=bundle.get('copy_bytes') or bundle.get('copy_bytes')!=metadata.get('copy_bytes') or not injected or partial:raise ValueError('getgroups copy prefix provenance differs')
        outcome='partial' if prefix_profile else 'half' if partial else 'none' if injected else 'success'
        if (partial and not injected) or outcome!=bundle.get('copy_outcome') or outcome!=metadata.get('copy_outcome'):raise ValueError('getgroups copy injection provenance differs')
    elif re.search(rb'^#define OSREC_GETGROUPS_(?:COPY_FAILURES|PARTIAL_COPY_FAILURES) 1$',auto,re.M):raise ValueError('legacy getgroups capture cannot claim copy injection')
    allocation_injected=bool(re.search(rb'^#define OSREC_GETGROUPS_ALLOCATION_FAILURE 1$',auto,re.M))
    if bundle['format'] in ('osrec-live-getgroups-v3','osrec-live-getgroups-v4','osrec-live-getgroups-v5','osrec-live-getgroups-v6','osrec-live-getgroups-v7','osrec-live-getgroups-v8','osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12'):
        if allocation_injected!=bundle.get('allocation_fault_injected') or allocation_injected!=metadata.get('allocation_fault_injected'):raise ValueError('getgroups allocation injection provenance differs')
    elif allocation_injected:raise ValueError('legacy getgroups capture cannot claim allocation injection')
    null_output=bool(re.search(rb'^#define OSREC_GETGROUPS_NULL_OUTPUT 1$',auto,re.M))
    boundaries=bool(re.search(rb'^#define OSREC_GETGROUPS_NULL_BOUNDARIES 1$',auto,re.M))
    negative=bool(re.search(rb'^#define OSREC_GETGROUPS_NEGATIVE_SIZES 1$',auto,re.M))
    if negative and bundle['format'] not in ('osrec-live-getgroups-v6','osrec-live-getgroups-v7','osrec-live-getgroups-v8','osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12'):raise ValueError('legacy getgroups capture cannot claim negative sizes')
    if bundle['format'] in ('osrec-live-getgroups-v5','osrec-live-getgroups-v6','osrec-live-getgroups-v7','osrec-live-getgroups-v8','osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12'):
        profile='negative-sizes' if negative else 'boundaries' if boundaries else 'short' if null_output else 'none'
        if sum((boundaries,null_output,negative))>1 or profile!=null_output_profile(bundle) or profile!=metadata.get('null_output_profile') or metadata.get('null_output_case')!=(profile!='none'):raise ValueError('getgroups null-output provenance differs')
    elif bundle['format']=='osrec-live-getgroups-v4':
        if boundaries:raise ValueError('legacy getgroups capture cannot claim null-boundary case')
        if null_output!=bundle.get('null_output_case') or null_output!=metadata.get('null_output_case'):raise ValueError('getgroups null-output provenance differs')
    elif null_output or boundaries:raise ValueError('legacy getgroups capture cannot claim null-output case')
    sizes=re.findall(rb'^#define OSREC_GETGROUPS_OUTPUT_SIZE ([0-9]+)$',auto,re.M)
    if bundle['format'] in ('osrec-live-getgroups-v7','osrec-live-getgroups-v8','osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12'):
        if len(sizes)!=1 or int(sizes[0])!=bundle.get('output_size') or bundle.get('output_size')!=metadata.get('output_size'):raise ValueError('getgroups output size provenance differs')
    elif sizes and (len(sizes)!=1 or int(sizes[0])!=4):raise ValueError('legacy getgroups capture cannot claim changed output size')
    offsets=re.findall(rb'^#define OSREC_GETGROUPS_OUTPUT_OFFSET ([0-9]+)$',auto,re.M)
    if bundle['format'] in ('osrec-live-getgroups-v8','osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12'):
        if len(offsets)!=1 or int(offsets[0])!=bundle.get('output_offset') or bundle.get('output_offset')!=metadata.get('output_offset'):raise ValueError('getgroups output offset provenance differs')
    elif offsets and (len(offsets)!=1 or int(offsets[0])!=0):raise ValueError('legacy getgroups capture cannot claim changed output offset')
    counts=re.findall(rb'^#define OSREC_GETGROUPS_GROUP_COUNT ([0-9]+)$',auto,re.M)
    if bundle['format'] in ('osrec-live-getgroups-v9','osrec-live-getgroups-v10','osrec-live-getgroups-v11','osrec-live-getgroups-v12'):
        if len(counts)!=1 or int(counts[0])!=bundle.get('group_count') or bundle.get('group_count')!=metadata.get('group_count'):raise ValueError('getgroups group count provenance differs')
    elif counts and (len(counts)!=1 or int(counts[0])!=3):raise ValueError('legacy getgroups capture cannot claim changed group count')
    calls=validate_getgroups(bundle,json.loads((capture/'entry-state-lifetimes.json').read_text()))
    user=re.findall(rb'^OSREC_GETGROUPS_USER ([0-9a-f]+)\r?$',(capture/'boot.log').read_bytes(),re.M)
    expected=b''.join(struct.pack('<3I',c['arguments']['size'] & 0xffffffff,c['raw'],16)+output_bytes(c['exit']) for c in calls)
    if len(user)!=1 or bytes.fromhex(user[0].decode())!=expected:raise ValueError('getgroups independent user observations differ')
    return report,calls

def checkpoint_header(calls,prefix_profile=False):
    values=credential_state(calls[0]['entry'])[1]
    constants=lambda vs:','.join('UINT32_C('+str(v)+')' for v in vs)
    rows=[]
    for c in calls:
        a=c['exit']['allocation_attempts'];before=struct.unpack('<4I',output_bytes(c['entry']));after=struct.unpack('<4I',output_bytes(c['exit']))
        copies=c['exit']['user_copy_attempts']
        rows.append('{'+constants((c['arguments']['size'] & 0xffffffff,int(c['arguments']['list'] is None),c['arguments']['list']['offset'] if c['arguments']['list'] is not None else 0,int(bool(a)),a[0]['id'] if a else 0,int(a[0]['reuse']) if a else 0,copies[0]['result'] if copies else 0))+',{'+constants(before)+'},{'+constants(after)+'}}')
    return '#define OSREC_COPY_PREFIX_PROFILE '+str(int(prefix_profile))+'\n#define OSREC_GROUP_COUNT '+str(values[4])+'\n#define OSREC_GROUP_BYTES '+str(4*values[4])+'''\n#define OSREC_CHECKPOINT_CALLS 3
struct checkpoint_call {uint32_t number,raw;};
static const struct checkpoint_call checkpoint_calls[3]={'''+','.join('{205,UINT32_C('+str(c['raw'])+')}' for c in calls)+'''};
static const uint32_t checkpoint_credential[5+OSREC_GROUP_COUNT]={'''+constants(values)+'''};
struct getgroup_call {uint32_t size,list_is_null,output_offset,allocation_attempted,allocation_id,reuse,copy_result,before[4],after[4];};
static const struct getgroup_call checkpoint_getgroups[3]={'''+','.join(rows)+'};\n'

def export(args):
    if args.arch!='aarch64':raise ValueError('getgroups replay requires AArch64')
    if args.out.exists() or any(args.out.is_relative_to(p.resolve()) for p in (args.capture,args.kernel_root,ROOT/'build/ohos')):raise ValueError('choose a new output outside capture/source directories')
    source,lock=prepare_source(args.kernel_root,ROOT/'integrations/liteos_a/getgroups-source-lock.json','getgroups_model.h')
    report,calls=load_capture(args.capture,lock)
    with tempfile.TemporaryDirectory(prefix='osrec-getgroups-') as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(args,sources)
        (sources/'getgroups.c').write_text(source)
        for filename in ('getgroups_model.h','setgroups_model.h'):shutil.copy2(ROOT/'integrations/liteos_a'/filename,sources/filename)
        (sources/'entry_model.h').write_text('#include "getgroups_model.h"\n')
        (sources/'entry_reconstruction.h').write_text('#define OSREC_HAS_WRITE_EFFECTS 1\n#define OSREC_CONTINUOUS_REPLAY 1\nstatic int osrec_restore(unsigned);\nstatic int osrec_entry_matches(unsigned);\nstatic int osrec_state_matches(unsigned);\n')
        (sources/'entry_checkpoint.h').write_text(checkpoint_header(calls,report['getgroups_capture'].get('copy_outcome')=='partial'))
        shutil.copy2(ROOT/'integrations/rtl_aarch64/getgroups_adapter.h',sources/'entry_adapter.h')
        shutil.copy2(ROOT/'integrations/rtl_aarch64/entry_state_replay.c',sources/'entry_state_replay.c')
        image=stage/'getgroups.elf';binary=stage/'getgroups.bin'
        run([args.llvm_bin/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'getgroups.c','-o',image])
        inspection=audit(image,args.llvm_bin);run([args.llvm_bin/'llvm-objcopy','-O','binary',image,binary])
        observed,raw=observe(image,args.qemu);require_success(observed)
        raw_observed,binary_raw=observe(binary,args.qemu,descriptor=image);require_success(raw_observed)
        if raw!=binary_raw or observed['user_copy_bytes']!=sum(a['bytes_copied'] for c in calls for a in c['exit']['user_copy_attempts']) or observed['actual_calls']!=[{'number':205,'raw_bits':c['raw']} for c in calls] or observed['address_reuses']!=sum(int(a['reuse']) for c in calls for a in c['exit']['allocation_attempts']):raise ValueError('getgroups target observations differ')
        manifest={'format':'osrec-freestanding-getgroups-v1','source_identity':lock,'target':target_metadata(inspection,8),
            'capture_sha256':report['getgroups_capture']['sha256'],'live_report_sha256':digest((args.capture/'report.json').read_bytes()),'lifetime_sha256':report['automated_capture_hashes']['lifetimes'],'kernel_image_sha256':report['kernel_image_sha256'],
            'entry_state_reconstruction':'reviewed SysGetGroups adapter with one stable credential and one shared 16-byte output object',
            'scope':'three-call reviewed argument/copy profile with captured 1..3-group credentials; initial state and shared output witness restored once; later states are assertions',
            'group_count':credential_state(calls[0]['entry'])[1][4],
            'output_offset':json.loads((args.capture/'getgroups-capture.json').read_text()).get('output_offset',0),
            'output_offset_contract':'final nonnull list may point 0..4 bytes into a shared 16-byte object; prefix and suffix guards checked',
            'declared_output_size':json.loads((args.capture/'getgroups-capture.json').read_text()).get('output_size',4),
            'output_capacity_contract':'nonnull final call declares group_count..INT32_MAX groups; only actual captured group list copied into shared 16-byte object',
            'null_output_case':any(c['arguments']['list'] is None for c in calls),
            'null_output_profile':null_output_profile(json.loads((args.capture/'getgroups-capture.json').read_text())),
            'allocation_fault_injected_capture':json.loads((args.capture/'getgroups-capture.json').read_text()).get('allocation_fault_injected',False),
            'allocation_failure_contract':'explicit null return under scheduler lock; physical memory pressure not reproduced',
            'copy_outcome':json.loads((args.capture/'getgroups-capture.json').read_text()).get('copy_outcome','success'),
            'copy_bytes':observed['user_copy_bytes'],
            'copy_failure_contract':'explicit failure after the captured byte prefix (including zero); natural MMU faults excluded',
            'modeled_dependencies':['bounded temporary allocation/free of 4 * captured group count bytes','scheduler lock','current user/process providers','kernel group copy','user output copy'],
            'allocator_strategy':'one static temporary region; recorded logical generation ID and reuse eligibility; native address history not reconstructed',
            'native_layout_reproduction':False,'scheduler_irq_reproduction':False,'generic_allocator_analysis':False,'runtime_host_interaction':False,'guest_io':False,'system_libraries':[],
            'target_observations':observed,'raw_image_execution_match':True,'image_audit':inspection,
            'source_hashes':{p.name:digest(p.read_bytes()) for p in sorted(sources.iterdir())},'elf_sha256':digest(image.read_bytes()),'binary_sha256':digest(binary.read_bytes()),'target_result_sha256':digest(raw),
            'compiler':run([args.llvm_bin/'clang','--version']).stdout.splitlines()[0],'qemu':run([args.qemu,'--version']).stdout.splitlines()[0],'rtl_validated':False,'cycle_timing_equivalence_verified':False}
        published=stage/'published';published.mkdir();shutil.copytree(sources,published/'sources')
        for p in (image,binary):shutil.copy2(p,published/p.name)
        (published/'target-result.bin').write_bytes(raw);(published/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        for name in ('getgroups-capture.json','entry-state-lifetimes.json'):shutil.copy2(args.capture/name,published/name)
        args.out.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(published,args.out)
    print(json.dumps({'image':str(args.out/'getgroups.elf'),'completed_calls':3,'user_copy_bytes':observed['user_copy_bytes'],'user_copy_failures':observed.get('user_copy_failures',0),'allocation_failures':observed['allocation_failures'],'runtime_host_interaction':False},indent=2))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--capture',required=True,type=Path);parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--kernel-root',type=Path,default=ROOT/'build/kernel_liteos_a');parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    add_target_arguments(parser);parser.add_argument('--qemu',default='qemu-system-aarch64');args=parser.parse_args()
    for key in ('capture','out','kernel_root','llvm_bin'):setattr(args,key,getattr(args,key).resolve())
    export(args)
if __name__=='__main__':main()
