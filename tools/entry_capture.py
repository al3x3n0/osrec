#!/usr/bin/env python3
"""Generate call-site capture wrappers and import their sessions into replay requests."""
import argparse
import json
from pathlib import Path
import re
import sys
import tempfile

from entry_state import capture_header,snapshot_providers,digest
from automated_entry_state import effect_plan
from export_entry_state import prepare_request
from entry_state_result import MAX_CALLS

IDENTIFIER=re.compile(r'^[A-Za-z_]\w*$')
RESULTS={'u32':'unsigned int','i32':'int','void':'void'}


def configuration(plan_path,spec_path):
    plan_bytes=Path(plan_path).read_bytes();spec_bytes=Path(spec_path).read_bytes()
    report=json.loads(plan_bytes);spec=json.loads(spec_bytes)
    if report.get('format')!='osrec-entry-state-plan-v1' or spec.get('format')!='osrec-entry-capture-spec-v1':raise ValueError('unsupported plan or capture specification')
    contract=spec.get('contract',{})
    if any(contract.get(k) is not True for k in ('fixed_lifetimes','exclusive_capture')) or not contract.get('reason') or not contract.get('implementation'):
        raise ValueError('capture requires explicit fixed-lifetime and exclusive-owner/synchronization contracts')
    if spec.get('mode','independent') not in ('independent','continuous'):raise ValueError('unsupported replay mode')
    if spec.get('replay_dispatch','reviewed') not in ('reviewed','generated'):raise ValueError('unsupported replay dispatch')
    if type(spec.get('max_calls',7)) is not int or not 1<=spec.get('max_calls',7)<=MAX_CALLS:
        raise ValueError('capture max_calls must be between 1 and '+str(MAX_CALLS))
    plans={}
    for plan in report['plans']:
        if plan['root'] in plans:raise ValueError('duplicate plan root')
        plans[plan['root']]=plan
    sites=spec.get('sites');routes=set();roots=set();selected=[]
    if not isinstance(sites,list) or not sites:raise ValueError('capture specification needs sites')
    for site in sites:
        root=site['root'];route=site['number']
        if (not isinstance(root,str) or not IDENTIFIER.fullmatch(root) or root.startswith('osrec_') or root not in plans or root in roots or
            type(route) is not int or not 0<=route<=0xffffffff or route in routes or site.get('return_kind') not in RESULTS):
            raise ValueError('sites require unique C roots/routes and u32, i32 or void returns')
        plan=plans[root];providers=snapshot_providers(plan)
        bound={p['argument'] for p in providers if p.get('binding_kind')=='root_argument'}
        if len(plan['arguments'])>16:raise ValueError('capture supports at most 16 parameters')
        for argument in plan['arguments']:
            name=argument['name']
            if not IDENTIFIER.fullmatch(name):raise ValueError('unsupported parameter name')
            if name not in bound and argument['type'] not in ('unsigned int','int'):raise ValueError('unbound pointer or unsupported scalar argument')
        routes.add(route);roots.add(root);selected.append(plan)
    hook_roots=[p['root'] for p in selected]+['effects_'+p['root'] for p in selected]
    if len(set(hook_roots))!=len(hook_roots):raise ValueError('selected roots collide with generated effect hook names')
    return report,spec,selected,plan_bytes,spec_bytes


def generate(plan_path,spec_path,include_hooks=True):
    _,spec,plans,plan_bytes,spec_bytes=configuration(plan_path,spec_path)
    hooks=capture_header(plans+[{**effect_plan(p),'root':'effects_'+p['root']} for p in plans])
    if not include_hooks:hooks='/* Snapshot hooks are supplied by the capture frontend. */'
    lines=['/* Generated call-site wrappers. Include after original declarations. */',
           '#include "osrec/entry_capture.h"',hooks,
           '#define OSREC_CAPTURE_PLAN_SHA256 '+json.dumps(digest(plan_bytes)),
           '#define OSREC_CAPTURE_SPEC_SHA256 '+json.dumps(digest(spec_bytes))]
    if 'max_calls' in spec:
        lines.append('_Static_assert(OSREC_CAPTURE_CALLS=='+str(spec['max_calls'])+',"capture capacity differs from specification");')
    for site,plan in zip(spec['sites'],plans):
        root=site['root'];typ=RESULTS[site['return_kind']]
        post_hook='effects_'+root if plan.get('state_writes') else root
        names={a['name']:'osrec_arg_'+str(i) for i,a in enumerate(plan['arguments'])}
        parameters=''.join(', '+a['type']+' '+names[a['name']] for a in plan['arguments'])
        arguments=','.join(names[a['name']] for a in plan['arguments']);call=root+'('+arguments+')'
        providers=snapshot_providers(plan)
        bindings=''.join(', '+names[p['argument']] for p in providers if p.get('binding_kind')=='root_argument')
        lines += ['static inline '+typ+' osrec_capture_'+root+'(struct osrec_capture_session *osrec_session'+parameters+') {',
                  '  _Static_assert(__builtin_types_compatible_p(__typeof__('+call+'),'+typ+'),"capture return ABI differs");',
                  '  _Static_assert(sizeof(unsigned int)==4 && sizeof(int)==4,"capture scalar ABI differs");',
                  '  struct osrec_capture_call *osrec_record=osrec_capture_begin(osrec_session,'+json.dumps(root)+',UINT32_C('+str(site['number'])+'));',
                  '  if(osrec_record) {',
                  '    if(!osrec_snapshot_'+root+'(&osrec_record->entry'+bindings+'))osrec_session->failed=1;']
        bound={p['argument'] for p in providers if p.get('binding_kind')=='root_argument'}
        for argument in plan['arguments']:
            if argument['name'] not in bound:
                name=argument['name'];variable=names[name];lines.append('    if(!osrec_capture_argument(osrec_session,osrec_record,'+json.dumps(name)+',&'+variable+',sizeof('+variable+')))osrec_session->failed=1;')
        lines += ['  }',('  '+call+';' if typ=='void' else '  '+typ+' osrec_value='+call+';'),
                  '  if(osrec_record) {',
                  '    if(!osrec_snapshot_'+post_hook+'(&osrec_record->post'+bindings+'))osrec_session->failed=1;',
                  '    osrec_capture_end(osrec_session,osrec_record,'+('0' if typ=='void' else '(uint32_t)osrec_value')+');','  }']
        if typ!='void':lines.append('  return osrec_value;')
        lines.append('}')
    return '\n'.join(lines)+'\n'


def import_session(plan_path,spec_path,capture_path,out):
    plan_path=Path(plan_path).resolve();spec_path=Path(spec_path).resolve();capture_path=Path(capture_path).resolve();out=Path(out).resolve()
    if out.exists():raise ValueError('choose a new import output directory')
    _,spec,plans,plan_bytes,spec_bytes=configuration(plan_path,spec_path)
    capture_bytes=capture_path.read_bytes();capture=json.loads(capture_bytes)
    if (not isinstance(capture,dict) or set(capture)!={'format','plan_sha256','spec_sha256','calls'} or
        capture['format']!='osrec-entry-capture-v1' or capture['plan_sha256']!=digest(plan_bytes) or capture['spec_sha256']!=digest(spec_bytes)):
        raise ValueError('capture format or generated plan/spec identity differs')
    records=capture['calls'];sites={(s['root'],s['number']) for s in spec['sites']}
    capacity=spec.get('max_calls',7)
    if not isinstance(records,list) or not 1<=len(records)<=capacity:raise ValueError('capture requires 1 through '+str(capacity)+' completed calls')
    calls=[];entries=[];posts=[]
    for index,record in enumerate(records):
        if (not isinstance(record,dict) or set(record)!={'root','number','raw_bits','entry','post'} or
            (record['root'],record['number']) not in sites or type(record['number']) is not int or
            type(record['raw_bits']) is not int or not 0<=record['raw_bits']<=0xffffffff):raise ValueError('capture call identity/result differs at '+str(index))
        for state in (record['entry'],record['post']):
            if type(state.get('invocation')) is not int or state['invocation']!=index or state.get('syscall')!=record['number']:
                raise ValueError('capture invocation/route differs at '+str(index))
        if record['entry'].get('arguments',[])!=record['post'].get('arguments',[]):raise ValueError('capture arguments changed between entry and post')
        calls.append({k:record[k] for k in ('root','number','raw_bits')});entries.append(record['entry']);posts.append(record['post'])
    out.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.osrec-capture-import-',dir=out.parent) as name:
        stage=Path(name);publish=stage/'publish';publish.mkdir()
        (publish/'plan.json').write_bytes(plan_bytes);(publish/'capture-spec.json').write_bytes(spec_bytes);(publish/'capture.json').write_bytes(capture_bytes)
        (publish/'entries.json').write_text(json.dumps(entries,indent=2)+'\n');(publish/'posts.json').write_text(json.dumps(posts,indent=2)+'\n')
        request={'format':'osrec-entry-replay-request-v1','mode':spec.get('mode','independent'),'plan':'plan.json',
                 'entries':'entries.json','post_states':'posts.json','calls':calls,'files':{},'translation_units':spec.get('translation_units',[])}
        if spec.get('replay_dispatch')=='generated':
            request['dispatch']={'format':'osrec-entry-dispatch-v1','sites':spec['sites']}
        for role in ('model_header','adapter_header'):
            filename=role+'.h';(publish/filename).write_bytes((spec_path.parent/spec[role]).read_bytes());request[role]=filename
        for filename,reference in spec.get('files',{}).items():
            if not re.fullmatch(r'[A-Za-z_]\w*(?:[.-]\w+)*',filename):raise ValueError('unsupported support filename')
            target='support-'+filename;(publish/target).write_bytes((spec_path.parent/reference).read_bytes());request['files'][filename]=target
        request_path=publish/'request.json';request_path.write_text(json.dumps(request,indent=2)+'\n');prepare_request(request_path)
        manifest={'format':'osrec-entry-capture-import-v1','plan_sha256':digest(plan_bytes),'spec_sha256':digest(spec_bytes),
                  'capture_sha256':digest(capture_bytes),'contract':spec['contract'],'calls':len(calls),'mode':request['mode'],
                  'typed_reconstruction_validated':True,'target_execution_verified':False,'native_source_attested':False,
                  'request_sha256':digest(request_path.read_bytes())}
        (publish/'import-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        if out.exists():raise ValueError('import output appeared during validation')
        publish.rename(out)
    return manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    for command in ('generate','import'):
        p=sub.add_parser(command);p.add_argument('--plan',type=Path,required=True);p.add_argument('--spec',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
        if command=='import':p.add_argument('--capture',type=Path,required=True)
    args=parser.parse_args()
    try:
        if args.command=='generate':
            header=generate(args.plan,args.spec)
            with args.out.open('x') as output:output.write(header)
            result={'header':str(args.out)}
        else:result=import_session(args.plan,args.spec,args.capture,args.out)
        print(json.dumps(result,indent=2));return 0
    except (ValueError,KeyError,TypeError,AttributeError,OSError) as error:
        print(json.dumps({'format':'osrec-entry-capture-error-v1','operation':args.command,'detail':str(error)}),file=sys.stderr);return 2


if __name__=='__main__':sys.exit(main())
