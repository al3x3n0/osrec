"""Live bridge for shared wrappers, retaining the original independent witnesses."""
import json
from pathlib import Path
import re
import shutil
import struct

from klee_liteos import ROOT,digest
from entry_capture import generate,import_session
from live_argument_state import profile_settings,prepare_source
from live_argument_effects import validate_capture,SESSION_PROFILE

FILES=('shared-capture-spec.json','shared-capture.h','shared-model.h','shared-adapter.h',
       'shared-capture-runtime.c','shared-capture-runtime.h','shared-capture.json','shared-capture-verification.json')


def capture_spec(mixed=False):
    settings=profile_settings(SESSION_PROFILE)
    spec={'format':'osrec-entry-capture-spec-v1','mode':'continuous',
        'contract':{'fixed_lifetimes':True,'exclusive_capture':True,
            'reason':'the current process remains live throughout one selected six-call batch',
            'implementation':'single-CPU scheduler lock across all helper calls; exitCode restored once before unlock'},
        'sites':[{'root':settings['helper'],'number':settings['route'],'return_kind':'void'}],
        'model_header':'shared-model.h','adapter_header':'shared-adapter.h'}
    if mixed:
        query=profile_settings('exit-code')
        spec['sites'].append({'root':query['helper'],'number':query['route'],'return_kind':'u32'})
        spec['composition']='six-writes-with-query-after-third-write'
    return spec


def mixed_spec(spec):
    if spec==capture_spec():return False
    if spec==capture_spec(True):return True
    raise ValueError('unsupported shared live capture specification')


def prepare(directory,kernel_root,mixed=False):
    directory=Path(directory);settings=profile_settings(SESSION_PROFILE)
    source,_=prepare_source(kernel_root,SESSION_PROFILE)
    spec=directory/'shared-capture-spec.json';spec.write_text(json.dumps(capture_spec(mixed),indent=2)+'\n')
    (directory/'shared-model.h').write_text(settings['model'])
    adapter=source+'''\nuint32_t osrec_invoke(uint32_t number){
 static unsigned invocation;if(number!=65539 || invocation>=6)return UINT32_MAX;
 OsProcessExitCodeSignalSet(osrec_bound_osrec_argument_processCB,osrec_argument(invocation++,1));return 0;}
'''
    if mixed:
        query_source,identity=prepare_source(kernel_root,'exit-code')
        (directory/'shared-query-source.json').write_text(json.dumps(identity,indent=2)+'\n')
        adapter=source+query_source+'''\nuint32_t osrec_invoke(uint32_t number){
 static unsigned invocation;unsigned index=invocation++;if(index>=7)return UINT32_MAX;
 if(index==3){if(number!=65536)return UINT32_MAX;return OsProcessExitCodeSignalIsSet(osrec_bound_osrec_argument_processCB);}
 if(number!=65539)return UINT32_MAX;
 OsProcessExitCodeSignalSet(osrec_bound_osrec_argument_processCB,osrec_argument(index,1));return 0;}
'''
    (directory/'shared-adapter.h').write_text(adapter)
    header=generate(directory/'plan.json',spec,include_hooks=False)
    (directory/'shared-capture.h').write_text(header)
    return header


def parse_log(text):
    rows=re.findall(r'^OSREC_SHARED_CAPTURE (.+)\r?$',text,re.M)
    if len(rows)!=1:raise ValueError('shared capture missing or duplicated in native log')
    return json.loads(rows[0])


def validate_shared(data,plan_bytes,spec_bytes,witness,legacy_entries,legacy_posts,query_witness=None):
    settings=profile_settings(SESSION_PROFILE);report=json.loads(plan_bytes)
    plans=[p for p in report['plans'] if p['root']==settings['helper']]
    mixed=mixed_spec(json.loads(spec_bytes))
    if len(plans)!=1:raise ValueError('shared live capture plan differs')
    if (data.get('format')!='osrec-entry-capture-v1' or data.get('plan_sha256')!=digest(plan_bytes) or
        data.get('spec_sha256')!=digest(spec_bytes)):raise ValueError('shared live capture plan/spec identity differs')
    records=data.get('calls',[])
    if len(records)!=(7 if mixed else 6):raise ValueError('shared live capture call count differs')
    for index,record in enumerate(records):
        if any(state.get('invocation')!=index or state.get('syscall')!=record.get('number') for state in (record['entry'],record['post'])):
            raise ValueError('shared wire invocation/route differs')
    writers=[c for i,c in enumerate(records) if not mixed or i!=3]
    if any(c.get('root')!=settings['helper'] or c.get('number')!=settings['route'] or c.get('raw_bits')!=0 for c in writers):
        raise ValueError('shared live capture call sequence differs')
    entries=[{**c['entry'],'invocation':i} for i,c in enumerate(writers)]
    posts=[{**c['post'],'invocation':i} for i,c in enumerate(writers)]
    calls=validate_capture(entries,posts,plans[0],witness,SESSION_PROFILE)
    def comparable(frame):
        return {**{k:v for k,v in frame.items() if k not in ('objects','lifetime_cursor')},
                'objects':[{k:v for k,v in obj.items() if k!='session_id'} for obj in frame['objects']]}
    if ([comparable(f) for f in entries]!=[comparable(f) for f in legacy_entries] or
        [comparable(f) for f in posts]!=[comparable(f) for f in legacy_posts]):
        raise ValueError('shared capture differs from independent legacy snapshots')
    if mixed:
        from automated_entry_state import validate_snapshot
        from reconstruct_entry_state import reconstruction_header
        query=profile_settings('exit-code');by_root={p['root']:p for p in report['plans']}
        query_plan=by_root.get(query['helper']);record=records[3]
        if (query_plan is None or query_plan['state_writes'] or report.get('shared_query_boundary_policy_sha256')!=digest(query['policy'].read_bytes()) or
            record.get('root')!=query['helper'] or record.get('number')!=query['route'] or query_witness is None or len(query_witness)!=16):
            raise ValueError('shared query root/policy/witness differs')
        position,before,raw,after=struct.unpack('<4I',query_witness)
        if position!=3 or before!=after or raw!=(before&127) or type(record.get('raw_bits')) is not int or record['raw_bits']!=raw:
            raise ValueError('shared query native result or state preservation differs')
        for frame in (record['entry'],record['post']):
            validate_snapshot(frame,query_plan)
            if frame.get('arguments',[]) or len(frame['objects'])!=1 or len(frame['fields'])!=1:
                raise ValueError('shared query footprint differs')
            field=frame['fields'][0]
            if (field['name']!='exitCode' or field['kind']!='scalar' or field['bytes']!=4 or
                int.from_bytes(bytes.fromhex(field['data']),'little')!=before):raise ValueError('shared query snapshot differs from native witness')
        reconstruction_header([r['entry'] for r in records],[by_root[r['root']] for r in records],
            post_states=[r['post'] for r in records],scalar_arguments=True,continuous=True)
        calls.insert(3,{'number':query['route'],'raw_bits':raw,'before':before,'after':after,'read_only':True})
    elif query_witness is not None:raise ValueError('unexpected shared query witness')
    return calls


def parse_query_log(text,mixed):
    rows=re.findall(r'^OSREC_SHARED_QUERY_KERNEL ([0-9a-f]+)\r?$',text,re.M)
    if len(rows)!=(1 if mixed else 0):raise ValueError('shared query witness missing, duplicated or unexpected')
    return bytes.fromhex(rows[0]) if mixed else None


def publish_capture(out,generated,text,entries,posts,witness):
    out=Path(out);generated=Path(generated);data=parse_log(text)
    spec_bytes=(generated/'shared-capture-spec.json').read_bytes();mixed=mixed_spec(json.loads(spec_bytes));query_witness=parse_query_log(text,mixed)
    calls=validate_shared(data,(out/'entry-state-plan.json').read_bytes(),spec_bytes,witness,entries,posts,query_witness)
    for filename in FILES[:4]:shutil.copy2(generated/filename,out/filename)
    if mixed:
        (out/'shared-query-kernel.bin').write_bytes(query_witness)
        shutil.copy2(generated/'shared-query-source.json',out/'shared-query-source.json')
    shutil.copy2(ROOT/'runtime/entry_capture.c',out/'shared-capture-runtime.c')
    shutil.copy2(ROOT/'include/osrec/entry_capture.h',out/'shared-capture-runtime.h')
    (out/'shared-capture.json').write_text(json.dumps(data,indent=2)+'\n')
    imported=import_session(out/'entry-state-plan.json',out/'shared-capture-spec.json',out/'shared-capture.json',out/'shared-request')
    result={'format':'osrec-live-shared-capture-verification-v1','profile':SESSION_PROFILE,'calls':len(calls),
        'shared_wrapper_used':True,'legacy_snapshots_match':True,'direct_native_witness_match':True,
        'single_lock_region':True,'native_field_restored_before_unlock':True,'typed_request_imported':True,
        'import_manifest_sha256':digest((out/'shared-request/import-manifest.json').read_bytes()),
        'native_witness_sha256':digest(witness),'before':[c['before'] for c in calls],'after':[c['after'] for c in calls]}
    if mixed:result.update(profile='exit-signal-mixed-session',query_witness_sha256=digest(query_witness),mixed_roots=True)
    (out/'shared-capture-verification.json').write_text(json.dumps(result,indent=2)+'\n')
    return imported


def metadata(out):
    out=Path(out)
    result={'format':'osrec-live-shared-capture-v1','files':{f:digest((out/f).read_bytes()) for f in FILES},
        'request_manifest_sha256':digest((out/'shared-request/import-manifest.json').read_bytes()),
        'scope':'generated wrapper around six original helper calls in one locked PID 1 batch, with direct native witness and legacy snapshots'}
    if mixed_spec(json.loads((out/'shared-capture-spec.json').read_text())):
        result.update(mixed_roots=True,scope='six writes and one interleaved original read helper in a locked PID 1 batch, with independent write/read witnesses')
        for name in ('shared-query-kernel.bin','shared-query-source.json'):result['files'][name]=digest((out/name).read_bytes())
    return result


def load_capture(out,kernel_root):
    from live_argument_state import load_capture as load_original
    out=Path(out);report=json.loads((out/'report.json').read_text())
    if report.get('shared_argument_capture',{}).get('format')=='osrec-live-configured-capture-v1':
        from live_configured_capture import load_capture as load_configured
        return load_configured(out,kernel_root)
    stored=report.get('shared_argument_capture',{})
    if stored!=metadata(out):raise ValueError('shared capture files/import metadata differ')
    if (digest((out/'liteos.bin').read_bytes())!=report.get('kernel_image_sha256') or
        digest((out/'liteos.elf').read_bytes())!=report.get('kernel_elf_sha256')):raise ValueError('shared capture kernel image differs')
    _,entries,_,_,_,_=load_original(out,kernel_root)
    posts=[f for f in json.loads((out/'entry-state-effects.json').read_text())['snapshots'] if f['syscall']==65539]
    data=json.loads((out/'shared-capture.json').read_text())
    mixed=mixed_spec(json.loads((out/'shared-capture-spec.json').read_text()));text=(out/'boot.log').read_text()
    if data!=parse_log(text):raise ValueError('shared capture differs from native log')
    query_witness=parse_query_log(text,mixed)
    if mixed:
        _,source_identity=prepare_source(kernel_root,'exit-code')
        if (query_witness!=(out/'shared-query-kernel.bin').read_bytes() or
            source_identity!=json.loads((out/'shared-query-source.json').read_text())):raise ValueError('shared query native source or log binding differs')
    calls=validate_shared(data,(out/'entry-state-plan.json').read_bytes(),(out/'shared-capture-spec.json').read_bytes(),
        (out/'argument-entry-kernel.bin').read_bytes(),entries,posts,query_witness)
    expected=generate(out/'entry-state-plan.json',out/'shared-capture-spec.json',include_hooks=False)
    if expected!=(out/'shared-capture.h').read_text():raise ValueError('generated shared wrapper differs')
    from export_entry_state import prepare_request
    imported=json.loads((out/'shared-request/import-manifest.json').read_text())
    if imported.get('request_sha256')!=digest((out/'shared-request/request.json').read_bytes()):raise ValueError('imported shared request hash differs')
    prepared=prepare_request(out/'shared-request/request.json')
    if (prepared['mode']!='continuous' or prepared['inputs']['plan']['data']!=(out/'entry-state-plan.json').read_bytes() or
        prepared['model']!=(out/'shared-model.h').read_bytes() or prepared['adapter']!=(out/'shared-adapter.h').read_bytes() or
        prepared['entries']!=[c['entry'] for c in data['calls']] or prepared['posts']!=[c['post'] for c in data['calls']] or
        prepared['calls']!=[{k:c[k] for k in ('root','number','raw_bits')} for c in data['calls']]):
        raise ValueError('imported shared request differs from validated native session')
    return data,calls


def export_verified(args):
    from export_entry_state import export
    report=json.loads((args.capture/'report.json').read_text())
    if report.get('shared_argument_capture',{}).get('format')=='osrec-live-configured-capture-v1':
        from live_configured_capture import export_verified as export_configured
        return export_configured(args)
    if args.out.is_relative_to(args.capture):raise ValueError('image output must be outside native capture')
    data,calls=load_capture(args.capture,args.kernel_root)
    native=json.loads((args.capture/'report.json').read_text())
    args.request=args.capture/'shared-request/request.json'
    if getattr(args,'generated_dispatch',False):
        import tempfile
        from copy import copy
        from export_entry_state import prepare_request
        prepared=prepare_request(args.request)
        # Reuse validated capture inputs, but obtain original bodies directly
        # from their pinned sources instead of carrying over handwritten routing.
        with tempfile.TemporaryDirectory(prefix='osrec-live-dispatch-') as name:
            stage=Path(name);request=dict(prepared['request'])
            for key,item in prepared['inputs'].items():
                if key.startswith('file:'):continue
                request[key]=str(item['path'])
            source,_=prepare_source(args.kernel_root,SESSION_PROFILE)
            spec=json.loads((args.capture/'shared-capture-spec.json').read_text())
            if mixed_spec(spec):source+=prepare_source(args.kernel_root,'exit-code')[0]
            (stage/'original-bodies.h').write_text(source)
            request['adapter_header']='original-bodies.h'
            request['files']={k:str(prepared['inputs']['file:'+k]['path']) for k in request.get('files',{})}
            request['dispatch']={'format':'osrec-entry-dispatch-v1','sites':spec['sites']}
            (stage/'request.json').write_text(json.dumps(request,indent=2)+'\n')
            generated_args=copy(args);generated_args.request=stage/'request.json'
            result=export(generated_args)
    else:result=export(args)
    verification={'format':'osrec-live-shared-image-verification-v1','native_witness_verified':True,
        'legacy_snapshot_comparison_verified':True,'calls':len(calls),'profile':SESSION_PROFILE,
        'native_source_identity':native['argument_entry_capture']['source_identity'],
        'kernel_image_sha256':native['kernel_image_sha256'],'kernel_elf_sha256':native['kernel_elf_sha256'],
        'native_report_sha256':digest((args.capture/'report.json').read_bytes()),
        'native_boot_log_sha256':native['boot_log_sha256'],
        'native_witness_sha256':digest((args.capture/'argument-entry-kernel.bin').read_bytes()),
        'shared_capture_sha256':digest((args.capture/'shared-capture.json').read_bytes()),
        'plan_sha256':data['plan_sha256'],'spec_sha256':data['spec_sha256'],
        'generated_wrapper_sha256':digest((args.capture/'shared-capture.h').read_bytes()),
        'generic_manifest_sha256':digest((args.out/'manifest.json').read_bytes()),
        'generic_input_sha256':result['input_sha256'],
        'scope':'controlled original helper batch on PID 1 under scheduler lock; field restored before unlock',
        'scheduler_reproduction':False,'rtl_validated':False}
    if getattr(args,'generated_dispatch',False):verification['generated_dispatch']=result['generated_dispatch']
    if mixed_spec(json.loads((args.capture/'shared-capture-spec.json').read_text())):
        verification.update(profile='exit-signal-mixed-session',mixed_roots=True,
            query_native_witness_verified=True,legacy_writer_snapshot_comparison_verified=True,
            query_native_source_identity=json.loads((args.capture/'shared-query-source.json').read_text()),
            query_native_witness_sha256=digest((args.capture/'shared-query-kernel.bin').read_bytes()))
    (args.out/'native-capture-verification.json').write_text(json.dumps(verification,indent=2)+'\n')
    return result


def main():
    import argparse
    import subprocess
    import sys
    from freestanding_elf import add_target_arguments
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',required=True,type=Path);parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--generated-dispatch',action='store_true',help='generate typed invocation routing from validated sites and original pinned helper bodies')
    parser.add_argument('--kernel-root',type=Path,default=ROOT/'build/kernel_liteos_a')
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--qemu',default='qemu-system-aarch64');add_target_arguments(parser);args=parser.parse_args()
    for key in ('capture','out','kernel_root','llvm_bin'):setattr(args,key,getattr(args,key).resolve())
    try:
        result=export_verified(args)
        print(json.dumps({'image':str(args.out/'entry-state.elf'),'completed_calls':result['target_observations']['completed_calls'],
                          'native_witness_verified':True},indent=2));return 0
    except (ValueError,KeyError,OSError,subprocess.SubprocessError) as error:
        print('live shared capture export failed: '+str(error),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
