#!/usr/bin/env python3
"""Build host-free AArch64 replay of reviewed bounded live SysSetGroups captures."""
import argparse
import json
from pathlib import Path
import re
import shutil
import struct
import tempfile
from klee_liteos import ROOT,digest
from freestanding_armv7 import run,audit
from freestanding_elf import prepare_target,add_target_arguments,target_metadata
from run_freestanding_armv7 import observe,require_success
from setgroups_capture import validate_setgroups,input_values
from entry_state_continuity import canonical_state

MODEL=ROOT/'integrations/liteos_a/setgroups_model.h'
ADAPTER=ROOT/'integrations/rtl_aarch64/setgroups_adapter.h'

def prepare_source(kernel_root,lock_path=ROOT/'integrations/liteos_a/setgroups-source-lock.json',model_header='setgroups_model.h'):
    lock=json.loads(lock_path.read_text())
    if run(['git','-C',kernel_root,'rev-parse','HEAD']).stdout.strip()!=lock['revision']:
        raise ValueError('setgroups source revision differs')
    for root in (kernel_root,ROOT/'build/ohos/kernel/liteos_a'):
        for relative,expected in {lock['source']:lock['source_sha256'],**lock['headers']}.items():
            if digest((root/relative).read_bytes())!=expected:raise ValueError('setgroups source/header changed: '+relative)
    text=(kernel_root/lock['source']).read_text();bodies=[]
    for name,expected in lock['functions'].items():
        match=re.search(r'(?:static )?int '+name+r'\([^\n]+\)\s*\{.*?\n\}',text,re.S)
        if not match or digest(match[0].encode())!=expected:raise ValueError('setgroups function changed: '+name)
        bodies.append(match[0])
    license_text=text[:text.index('*/')+2]
    return license_text+'\n#include "'+model_header+'"\n'+'\n\n'.join(bodies)+'\n',lock

def load_capture(capture,lock):
    report=json.loads((capture/'report.json').read_text());metadata=report['setgroups_capture']
    if metadata['file']!='setgroups-capture.json' or metadata['sha256']!=digest((capture/metadata['file']).read_bytes()):
        raise ValueError('setgroups capture hash differs')
    if not metadata['original_syscall_executed'] or metadata['calls']!=3:raise ValueError('setgroups capture scope differs')
    if not report['automated_session_identity'].get('allocation_reuse_tracking') or 206 not in report['automated_session_identity'].get('allocation_reuse_scope',[]):
        raise ValueError('setgroups allocator coverage contract missing')
    config=(ROOT/'build/ohos/kernel/liteos_a/.config').read_bytes()
    if digest(config)!=report['kernel_config_sha256'] or not re.search(rb'^LOSCFG_SECURITY_CAPABILITY=y$',config,re.M) or re.search(rb'^LOSCFG_USER_CONTAINER=(?:y|1)$',config,re.M):
        raise ValueError('setgroups captured configuration differs')
    for filename,key in [('entry-state-lifetimes.json','lifetimes')]:
        if digest((capture/filename).read_bytes())!=report['automated_capture_hashes'][key]:raise ValueError('setgroups lifetime hash differs')
    if digest((capture/'boot.log').read_bytes())!=report['boot_log_sha256'] or digest((capture/'liteos.bin').read_bytes())!=report['kernel_image_sha256']:
        raise ValueError('setgroups live boot provenance differs')
    bundle=json.loads((capture/'setgroups-capture.json').read_text())
    if bundle['format'] in ('osrec-live-setgroups-v3','osrec-live-setgroups-v4','osrec-live-setgroups-v5'):
        auto_config=(capture/'auto-entry-config.h').read_bytes()
        injected=bool(re.search(rb'^#define OSREC_SETGROUPS_FAILURES 1$',auto_config,re.M))
        copy_injected=bool(re.search(rb'^#define OSREC_SETGROUPS_COPY_FAILURES 1$',auto_config,re.M))
        if bundle['format'] in ('osrec-live-setgroups-v4','osrec-live-setgroups-v5') and (copy_injected!=bundle.get('copy_fault_injected') or copy_injected!=report.get('setgroups_copy_fault_injected') or (copy_injected and injected)):
            raise ValueError('setgroups copy fault injection configuration differs')
        partial_injected=bool(re.search(rb'^#define OSREC_SETGROUPS_PARTIAL_COPY_FAILURES 1$',auto_config,re.M))
        if bundle['format']=='osrec-live-setgroups-v5' and (partial_injected!=bundle.get('partial_copy_fault_injected') or partial_injected!=report.get('setgroups_partial_copy_fault_injected') or (partial_injected and not copy_injected)):
            raise ValueError('setgroups partial copy injection configuration differs')
        injected=injected or copy_injected
        if digest(auto_config)!=report['auto_entry_config_sha256'] or injected!=bundle.get('fault_injected') or injected!=report.get('setgroups_fault_injected'):
            raise ValueError('setgroups fault injection configuration differs')
    if bundle['source_sha256']!=lock['source_sha256'] or bundle['type_header_sha256']!=lock['headers']['kernel/base/include/los_process_pri.h']:
        raise ValueError('setgroups captured source identity differs')
    lifetimes=json.loads((capture/'entry-state-lifetimes.json').read_text())
    calls=validate_setgroups(bundle,lifetimes)
    matches=re.findall(rb'^OSREC_SETGROUPS_USER ([0-9a-f]+)\r?$',(capture/'boot.log').read_bytes(),re.M)
    expected=[v for c in calls for v in (c['arguments']['size'],c['raw'],16)]
    if len(matches)!=1 or bytes.fromhex(matches[0].decode())!=struct.pack('<9I',*expected):
        raise ValueError('setgroups independent user observations differ')
    return report,bundle,calls

def checkpoint_header(calls):
    names=('userID','effUserID','gid','effGid','groupNumber','groups[0]','groups[1]','groups[2]')
    def state(frame):
        _,roots,fields=canonical_state(frame);process=roots['OsCurrProcessGet()'];user=fields[process,'user'][1]
        values=[int.from_bytes(fields[user,name][2],'little') if (user,name) in fields else 0 for name in names]
        return '{UINT32_C('+str(user)+'),{'+','.join('UINT32_C('+str(v)+')' for v in values)+'}}'
    header='''#define OSREC_CHECKPOINT_CALLS 3
struct checkpoint_call {uint32_t number,raw;};
static const struct checkpoint_call checkpoint_calls[3]={@CALLS@};
struct group_state {uint32_t user,values[8];};
struct group_event {uint32_t kind,id,size,reuse;};
struct group_allocation {uint32_t size,id,reuse;};
struct group_call {struct group_state before,after;uint32_t reuse,size,input[2],event_count;struct group_event events[4];uint32_t raw,allocation_count;struct group_allocation allocations[2];uint32_t copy_result;};
static const struct group_call checkpoint_groups[3]={
'''.replace('@CALLS@',','.join('{206,UINT32_C('+str(c['raw'])+')}' for c in calls))
    rows=[]
    for call in calls:
        inputs=input_values(call['arguments']);before=canonical_state(call['entry']);after=canonical_state(call['exit'])
        user=lambda state:state[2][state[1]['OsCurrProcessGet()'],'user'][1]
        events=call.get('events',[{'kind':'allocate','id':user(after),'size':24},{'kind':'release','id':user(before),'size':0}])
        reuses=iter(call['exit'].get('allocation_reuses',[call['exit']['allocation_address_reused']]))
        attempts=call['exit'].get('allocation_attempts')
        if attempts is None:attempts=[{'size':e['size'],'id':e['id'],'reuse':next(reuses)} for e in events if e['kind']=='allocate']
        reuse_ids={a['id']:a['reuse'] for a in attempts if a['id']}
        event_rows=[]
        for event in events:
            values=(1 if event['kind']=='allocate' else 2,event['id'],event['size'],int(reuse_ids[event['id']]) if event['kind']=='allocate' else 0)
            event_rows.append('{'+','.join('UINT32_C('+str(v)+')' for v in values)+'}')
        copy_attempts=call['exit'].get('user_copy_attempts',[])
        copy_result=copy_attempts[0]['result'] if copy_attempts else 0
        allocation_rows=['{'+','.join('UINT32_C('+str(int(a[k]))+')' for k in ('size','id','reuse'))+'}' for a in attempts]
        rows.append('{'+state(call['entry'])+','+state(call['exit'])+','+str(int(call['exit']['allocation_address_reused']))+','+str(len(inputs))+', {'+','.join(str(v) for v in inputs+[0]*(2-len(inputs)))+'},'+str(len(events))+',{'+','.join(event_rows)+'},UINT32_C('+str(call['raw'])+'),'+str(len(attempts))+',{'+','.join(allocation_rows)+'},UINT32_C('+str(copy_result)+')}')
    header+=',\n'.join(rows)+'};\n'
    return header

def export(args):
    if args.arch!='aarch64':raise ValueError('setgroups dynamic replay requires AArch64')
    if args.out.exists():raise ValueError('choose a new output directory')
    if any(args.out.is_relative_to(root.resolve()) for root in (args.kernel_root,args.capture,ROOT/'build/ohos')):
        raise ValueError('output must be outside capture/source directories')
    generated,lock=prepare_source(args.kernel_root);report,bundle,calls=load_capture(args.capture,lock)
    checkpoint=checkpoint_header(calls)
    with tempfile.TemporaryDirectory(prefix='osrec-setgroups-image-') as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir();flags=prepare_target(args,sources)
        (sources/'setgroups.c').write_text(generated);shutil.copy2(MODEL,sources/'setgroups_model.h')
        (sources/'entry_model.h').write_text('#include "setgroups_model.h"\n')
        (sources/'entry_reconstruction.h').write_text('''#define OSREC_HAS_WRITE_EFFECTS 1
#define OSREC_CONTINUOUS_REPLAY 1
static int osrec_restore(unsigned);
static int osrec_entry_matches(unsigned);
static int osrec_state_matches(unsigned);
''')
        (sources/'entry_checkpoint.h').write_text(checkpoint);shutil.copy2(ADAPTER,sources/'entry_adapter.h')
        shutil.copy2(ROOT/'integrations/rtl_aarch64/entry_state_replay.c',sources/'entry_state_replay.c')
        image=stage/'setgroups.elf';binary=stage/'setgroups.bin'
        run([args.llvm_bin/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector',
            '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-Wno-sign-compare','-nostdlib','-static',
            '-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',sources/'entry_state_replay.c',sources/'setgroups.c','-o',image])
        inspection=audit(image,args.llvm_bin);run([args.llvm_bin/'llvm-objcopy','-O','binary',image,binary])
        observed,raw=observe(image,args.qemu);require_success(observed)
        raw_observed,binary_raw=observe(binary,args.qemu,descriptor=image);require_success(raw_observed)
        if raw!=binary_raw:raise ValueError('setgroups ELF/raw results differ')
        reuses=sum(sum(a['reuse'] for a in c['exit']['allocation_attempts']) if 'allocation_attempts' in c['exit'] else sum(c['exit'].get('allocation_reuses',[c['exit']['allocation_address_reused']])) for c in calls)
        if not observed.get('dynamic_object_replay') or observed.get('address_reuses')!=reuses or observed['actual_calls']!=[{'number':206,'raw_bits':c['raw']} for c in calls]:
            raise ValueError('setgroups target allocation/call observations differ')
        manifest={'format':'osrec-freestanding-setgroups-v1','source_identity':lock,'target':target_metadata(inspection,8),
            'capture_sha256':digest((args.capture/'setgroups-capture.json').read_bytes()),
            'live_report_sha256':digest((args.capture/'report.json').read_bytes()),
            'lifetime_sha256':report['automated_capture_hashes']['lifetimes'],'kernel_image_sha256':report['kernel_image_sha256'],
            'dynamic_object_replay':True,'entry_state_reconstruction':'reviewed bounded SysSetGroups dynamic adapter',
            'generic_allocator_analysis':False,'native_layout_reproduction':False,'scheduler_irq_reproduction':False,
            'allocator_strategy':'eight static 32-byte slots; captured reuse decisions and generation IDs; one live credential after each call',
            'modeled_dependencies':['bounded trace-driven allocator/free','24-byte credential copy','bounded group-list copy','target-native input region and user copy','successful CAP_SETGID permission','scheduler lock','current process/user bindings'],
            'scope':'three SysSetGroups calls with lists of 0..2 groups and captured allocation and user-copy outcomes; target-native pointers; initial state restored once',
            'fault_injected_capture':bundle.get('fault_injected',False),
            'copy_fault_injected_capture':bundle.get('copy_fault_injected',False),
            'partial_copy_fault_injected_capture':bundle.get('partial_copy_fault_injected',False),
            'user_copy_failure_contract':'explicit injection after zero or half the requested bytes; copied prefix checked before release; natural MMU faults excluded',
            'normalized_input_regions':[c['arguments']['list'] for c in calls if c['arguments']['list'] is not None],
            'runtime_host_interaction':False,'guest_io':False,'system_libraries':[],
            'target_observations':observed,'raw_image_execution_match':True,'image_audit':inspection,
            'source_hashes':{p.name:digest(p.read_bytes()) for p in sorted(sources.iterdir())},
            'elf_sha256':digest(image.read_bytes()),'binary_sha256':digest(binary.read_bytes()),'target_result_sha256':digest(raw),
            'compiler':run([args.llvm_bin/'clang','--version']).stdout.splitlines()[0],
            'qemu':run([args.qemu,'--version']).stdout.splitlines()[0],
            'rtl_validated':False,'cycle_timing_equivalence_verified':False}
        published=stage/'published';published.mkdir();shutil.copytree(sources,published/'sources')
        shutil.copy2(image,published/'setgroups.elf');shutil.copy2(binary,published/'setgroups.bin')
        (published/'target-result.bin').write_bytes(raw);(published/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        shutil.copy2(args.capture/'setgroups-capture.json',published/'setgroups-capture.json')
        shutil.copy2(args.capture/'entry-state-lifetimes.json',published/'entry-state-lifetimes.json')
        args.out.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(published,args.out)
    print(json.dumps({'image':str(args.out/'setgroups.elf'),'completed_calls':observed['completed_calls'],
        'allocations':observed['allocations'],'releases':observed['releases'],'copies':observed['copies'],
        'allocation_attempts':observed.get('allocation_attempts',observed['allocations']),
        'allocation_failures':observed.get('allocation_failures',0),
        'user_copies':observed.get('user_copies',0),
        'user_copy_failures':observed.get('user_copy_failures',0),
        'user_copy_bytes':observed.get('user_copy_bytes',0),
        'runtime_host_interaction':False},indent=2))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',required=True,type=Path);parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--kernel-root',type=Path,default=ROOT/'build/kernel_liteos_a')
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    add_target_arguments(parser);parser.add_argument('--qemu',default='qemu-system-aarch64');args=parser.parse_args()
    for key in ('capture','out','kernel_root','llvm_bin'):setattr(args,key,getattr(args,key).resolve())
    export(args)
if __name__=='__main__':main()
