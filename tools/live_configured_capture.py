"""Configured live sequences of reviewed original process signal helpers."""
import json
from pathlib import Path
import re
import shutil
import struct

from klee_liteos import ROOT,digest
from entry_capture import generate,import_session
from live_argument_state import profile_settings,prepare_source
from live_shared_capture import FILES,parse_log

FORMAT='osrec-live-configured-capture-v1'
WRITER='OsProcessExitCodeSignalSet'
READER='OsProcessExitCodeSignalIsSet'
EXTRA=('shared-session.json','shared-session-schedule.h','shared-session-sources.json','shared-session-kernel.bin')


def validate_session(session):
    if (not isinstance(session,dict) or set(session)!={'format','calls'} or
        session['format']!='osrec-live-helper-session-v1' or not isinstance(session['calls'],list) or not 1<=len(session['calls'])<=256):
        raise ValueError('live helper session requires 1 through 256 configured calls')
    for call in session['calls']:
        if not isinstance(call,dict) or set(call)!={'root','arguments'} or call['root'] not in (WRITER,READER):
            raise ValueError('live helper session requires a reviewed signal helper root')
        arguments=call['arguments']
        if not isinstance(arguments,dict) or set(arguments)!=({'signal'} if call['root']==WRITER else set()):
            raise ValueError('live helper arguments differ from reviewed root')
        if call['root']==WRITER and (type(arguments['signal']) is not int or not 0<=arguments['signal']<=0xffffffff):
            raise ValueError('live helper signal must be an unsigned 32-bit integer')
    return session


def spec_for(session):
    validate_session(session)
    return {'format':'osrec-entry-capture-spec-v1','mode':'continuous','max_calls':len(session['calls']),
        'replay_dispatch':'generated','native_session':session,
        'contract':{'fixed_lifetimes':True,'exclusive_capture':True,
            'reason':'PID 1 stays live throughout this configured original-helper session',
            'implementation':'single CPU; existing scheduler lock spans all configured calls; exitCode restored before unlock'},
        'sites':[{'root':WRITER,'number':65539,'return_kind':'void'},{'root':READER,'number':65536,'return_kind':'u32'}],
        'model_header':'shared-model.h','adapter_header':'shared-adapter.h'}


def schedule(session):
    validate_session(session)
    return ('/* Generated reviewed-helper schedule; process binding is supplied by the kernel. */\n'
        'static const struct {UINT32 number,argument;} shared_schedule[OSREC_CAPTURE_CALLS]={'+','.join(
        '{'+str(65539 if c['root']==WRITER else 65536)+',UINT32_C('+str(c['arguments'].get('signal',0))+')}' for c in session['calls'])+'};\n')


def source_inputs(kernel_root):
    writer,wi=prepare_source(kernel_root,'exit-signal-session');reader,ri=prepare_source(kernel_root,'exit-code')
    return writer+reader,{WRITER:wi,READER:ri}


def prepare(directory,kernel_root,session):
    directory=Path(directory);spec=spec_for(session);body,identities=source_inputs(kernel_root)
    for name,value in [('shared-session.json',session),('shared-session-sources.json',identities),('shared-capture-spec.json',spec)]:
        (directory/name).write_text(json.dumps(value,indent=2)+'\n')
    (directory/'shared-session-schedule.h').write_text(schedule(session))
    (directory/'shared-model.h').write_text(profile_settings('exit-signal-session')['model'])
    (directory/'shared-adapter.h').write_text(body)
    wrapper=generate(directory/'plan.json',directory/'shared-capture-spec.json',include_hooks=False)
    (directory/'shared-capture.h').write_text(wrapper)
    return wrapper


def parse_witness(text):
    rows=re.findall(r'^OSREC_SHARED_SESSION_KERNEL ([0-9a-f]+)\r?$',text,re.M)
    if len(rows)!=1:raise ValueError('configured native witness missing or duplicated')
    return bytes.fromhex(rows[0])


def validate_capture(data,plan_bytes,spec_bytes,witness):
    from automated_entry_state import validate_snapshot,effect_plan
    from reconstruct_entry_state import reconstruction_header
    spec=json.loads(spec_bytes);session=validate_session(spec.get('native_session'));count=len(session['calls'])
    if spec!=spec_for(session):raise ValueError('configured capture specification differs')
    if (data.get('format')!='osrec-entry-capture-v1' or data.get('plan_sha256')!=digest(plan_bytes) or
        data.get('spec_sha256')!=digest(spec_bytes) or len(data.get('calls',[]))!=count):
        raise ValueError('configured capture plan/spec/count differs')
    if len(witness)!=20+24*count:raise ValueError('configured native witness extent differs')
    words=struct.unpack('<'+str(len(witness)//4)+'I',witness)
    pid,n,initial,final,restored=words[:5]
    if (pid,n,initial,restored)!=(1,count,0,0):raise ValueError('configured native PID/count/restore differs')
    report=json.loads(plan_bytes);plans={p['root']:p for p in report['plans']}
    query=profile_settings('exit-code')
    if report.get('shared_query_boundary_policy_sha256')!=digest(query['policy'].read_bytes()) or plans[READER]['state_writes']:
        raise ValueError('configured query policy or readonly plan differs')
    state=initial;calls=[]
    for index,(configured,record) in enumerate(zip(session['calls'],data['calls'])):
        root=configured['root'];number=65539 if root==WRITER else 65536;argument=configured['arguments'].get('signal',0)
        position,route,signal,before,raw,after=words[5+6*index:11+6*index]
        expected_raw=0 if root==WRITER else before&127
        expected_after=before|(argument&127) if root==WRITER else before
        if ((position,route,signal,before,raw,after)!=(index,number,argument,state,expected_raw,expected_after) or
            record.get('root')!=root or record.get('number')!=number or type(record.get('raw_bits')) is not int or record['raw_bits']!=raw):
            raise ValueError('configured native call/result/state differs at '+str(index))
        arguments=[{'name':'signal','bytes':4,'data':struct.pack('<I',argument).hex()}] if root==WRITER else []
        for key,value in [('entry',before),('post',after)]:
            frame=record[key];validate_snapshot(frame,effect_plan(plans[root]) if key=='post' else plans[root])
            if (type(frame.get('invocation')) is not int or frame['invocation']!=index or frame.get('syscall')!=number or
                frame.get('arguments',[])!=arguments or len(frame['objects'])!=1 or len(frame['fields'])!=1):
                raise ValueError('configured snapshot footprint/arguments differ')
            obj=frame['objects'][0];field=frame['fields'][0]
            if (frame['roots']!=[{'name':'osrec_argument_processCB()','object_id':obj['id']}] or
                field!={'object_id':obj['id'],'name':'exitCode','kind':'scalar','bytes':4,'data':struct.pack('<I',value).hex()}):
                raise ValueError('configured snapshot differs from direct native field witness')
        calls.append({'number':number,'raw_bits':raw,'before':before,'after':after});state=after
    if state!=final:raise ValueError('configured final native state differs')
    reconstruction_header([c['entry'] for c in data['calls']],[plans[c['root']] for c in data['calls']],
        post_states=[c['post'] for c in data['calls']],scalar_arguments=True,continuous=True)
    return calls


def publish_capture(out,generated,text):
    out=Path(out);generated=Path(generated);data=parse_log(text);witness=parse_witness(text)
    spec_bytes=(generated/'shared-capture-spec.json').read_bytes()
    calls=validate_capture(data,(out/'entry-state-plan.json').read_bytes(),spec_bytes,witness)
    for name in (*FILES[:4],*EXTRA[:3]):shutil.copy2(generated/name,out/name)
    (out/'shared-session-kernel.bin').write_bytes(witness)
    shutil.copy2(ROOT/'runtime/entry_capture.c',out/'shared-capture-runtime.c')
    shutil.copy2(ROOT/'include/osrec/entry_capture.h',out/'shared-capture-runtime.h')
    (out/'shared-capture.json').write_text(json.dumps(data,indent=2)+'\n')
    imported=import_session(out/'entry-state-plan.json',out/'shared-capture-spec.json',out/'shared-capture.json',out/'shared-request')
    proof={'format':'osrec-configured-native-verification-v1','calls':len(calls),'pid':1,'direct_native_witness_verified':True,
        'all_entries_and_posts_match_witness':True,'continuous_reconstruction_verified':True,'field_restored_before_unlock':True,
        'legacy_six_call_baseline':'separate original calls; excluded from this session',
        'native_witness_sha256':digest(witness),'before':[c['before'] for c in calls],'after':[c['after'] for c in calls]}
    (out/'shared-capture-verification.json').write_text(json.dumps(proof,indent=2)+'\n')
    return imported


def metadata(out):
    out=Path(out)
    return {'format':FORMAT,'files':{f:digest((out/f).read_bytes()) for f in (*FILES,*EXTRA)},
        'request_manifest_sha256':digest((out/'shared-request/import-manifest.json').read_bytes()),
        'scope':'configured reviewed helper session on PID 1 under one lock, with direct witnesses and restoration'}


def load_capture(out,kernel_root):
    from live_argument_state import load_capture as load_baseline
    from export_entry_state import prepare_request
    out=Path(out);report=json.loads((out/'report.json').read_text())
    if report.get('shared_argument_capture')!=metadata(out):raise ValueError('configured capture file/import metadata differs')
    for name,key in [('liteos.bin','kernel_image_sha256'),('liteos.elf','kernel_elf_sha256')]:
        if digest((out/name).read_bytes())!=report[key]:raise ValueError('configured kernel image differs')
    load_baseline(out,kernel_root)
    text=(out/'boot.log').read_text();data=json.loads((out/'shared-capture.json').read_text())
    spec=json.loads((out/'shared-capture-spec.json').read_text());session=json.loads((out/'shared-session.json').read_text())
    if spec!=spec_for(session) or data!=parse_log(text):raise ValueError('configured spec/session/native log differs')
    witness=(out/'shared-session-kernel.bin').read_bytes()
    if witness!=parse_witness(text):raise ValueError('configured native witness differs from log')
    body,identities=source_inputs(kernel_root)
    if (identities!=json.loads((out/'shared-session-sources.json').read_text()) or body!=(out/'shared-adapter.h').read_text() or
        (out/'shared-model.h').read_text()!=profile_settings('exit-signal-session')['model'] or
        (out/'shared-session-schedule.h').read_text()!=schedule(session)):
        raise ValueError('configured native source/model/schedule differs')
    calls=validate_capture(data,(out/'entry-state-plan.json').read_bytes(),(out/'shared-capture-spec.json').read_bytes(),witness)
    if generate(out/'entry-state-plan.json',out/'shared-capture-spec.json',include_hooks=False)!=(out/'shared-capture.h').read_text():
        raise ValueError('configured wrapper differs')
    imported=json.loads((out/'shared-request/import-manifest.json').read_text());request=out/'shared-request/request.json'
    if imported.get('request_sha256')!=digest(request.read_bytes()):raise ValueError('configured imported request hash differs')
    prepared=prepare_request(request)
    if (prepared['mode']!='continuous' or prepared['inputs']['plan']['data']!=(out/'entry-state-plan.json').read_bytes() or
        prepared['model']!=(out/'shared-model.h').read_bytes() or prepared['inputs']['adapter_header']['data']!=(out/'shared-adapter.h').read_bytes() or
        prepared['request'].get('dispatch')!={'format':'osrec-entry-dispatch-v1','sites':spec['sites']} or
        prepared['request'].get('files')!={} or prepared['translation_units'] or
        prepared['entries']!=[c['entry'] for c in data['calls']] or prepared['posts']!=[c['post'] for c in data['calls']] or
        prepared['calls']!=[{k:c[k] for k in ('root','number','raw_bits')} for c in data['calls']]):
        raise ValueError('configured imported replay inputs differ')
    return data,calls


def export_verified(args):
    from export_entry_state import export
    if args.out.is_relative_to(args.capture):raise ValueError('image output must be outside native capture')
    data,calls=load_capture(args.capture,args.kernel_root);args.request=args.capture/'shared-request/request.json'
    result=export(args);native=json.loads((args.capture/'report.json').read_text())
    witness=struct.unpack('<5I',(args.capture/'shared-session-kernel.bin').read_bytes()[:20])
    proof={'format':'osrec-live-configured-image-verification-v1','calls':len(calls),'native_witness_verified':True,
        'all_entry_and_post_fields_verified':True,'generated_dispatch':result['generated_dispatch'],
        'native_source_identities':json.loads((args.capture/'shared-session-sources.json').read_text()),
        'kernel_image_sha256':native['kernel_image_sha256'],'kernel_elf_sha256':native['kernel_elf_sha256'],
        'native_report_sha256':digest((args.capture/'report.json').read_bytes()),'native_boot_log_sha256':native['boot_log_sha256'],
        'native_witness_sha256':digest((args.capture/'shared-session-kernel.bin').read_bytes()),
        'baseline_witness_sha256':digest((args.capture/'argument-entry-kernel.bin').read_bytes()),
        'shared_capture_sha256':digest((args.capture/'shared-capture.json').read_bytes()),
        'schedule_sha256':digest((args.capture/'shared-session-schedule.h').read_bytes()),'plan_sha256':data['plan_sha256'],'spec_sha256':data['spec_sha256'],
        'initial_final_restored':list(witness[2:]),'generic_manifest_sha256':digest((args.out/'manifest.json').read_bytes()),
        'scope':'configured original helper calls on PID 1; one scheduler lock; separate six-call legacy baseline; field restored before unlock',
        'scheduler_reproduction':False,'rtl_validated':False}
    (args.out/'native-capture-verification.json').write_text(json.dumps(proof,indent=2)+'\n')
    return result
