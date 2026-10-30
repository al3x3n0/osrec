#!/usr/bin/env python3
"""Export a request-selected typed entry-state replay without a profile-specific exporter."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from entry_state import digest
from reconstruct_entry_state import reconstruction_header
from freestanding_elf import add_target_arguments,target_metadata
from entry_state_image import build_and_verify
from entry_state_result import MAX_CALLS

ROOT=Path(__file__).resolve().parents[1]
RESERVED={'entry_model.h','entry_adapter.h','entry_reconstruction.h','entry_checkpoint.h','entry_state_replay.c','start.S','image.ld'}


class RequestError(ValueError):
    def __init__(self,stage,detail):self.stage=stage;super().__init__(detail)


def prepare_request(path):
    path=Path(path).resolve();inputs={}
    try:
        request_bytes=path.read_bytes();request=json.loads(request_bytes)
        if not isinstance(request,dict) or request.get('format')!='osrec-entry-replay-request-v1':raise ValueError('unsupported request format')
        mode=request.get('mode','independent')
        if mode not in ('independent','continuous'):raise ValueError('mode must be independent or continuous')
        def read(key,reference=None):
            reference=request.get(key) if reference is None else reference
            if not isinstance(reference,str) or not reference:raise ValueError(key+' requires a file path')
            file=(path.parent/reference).resolve();data=file.read_bytes()
            inputs[key]={'path':file,'data':data,'sha256':digest(data)}
            return data
        plan_report=json.loads(read('plan'));entries_document=json.loads(read('entries'))
        posts_document=json.loads(read('post_states')) if request.get('post_states') is not None else None
        model=read('model_header');adapter=read('adapter_header')
        files=request.get('files',{});translation_units=request.get('translation_units',[])
        if not isinstance(files,dict) or not isinstance(translation_units,list):raise ValueError('files must be a map and translation_units a list')
        for name,reference in files.items():
            if not re.fullmatch(r'[A-Za-z_]\w*(?:[.-]\w+)*',name) or name in RESERVED:raise ValueError('invalid or reserved support filename: '+name)
            read('file:'+name,reference)
        if len(set(translation_units))!=len(translation_units) or any(name not in files or not name.endswith('.c') for name in translation_units):
            raise ValueError('translation_units must name distinct declared C support files')
    except (ValueError,TypeError,OSError) as error:raise RequestError('inputs',str(error)) from error
    try:
        if not isinstance(plan_report,dict) or plan_report.get('format')!='osrec-entry-state-plan-v1':raise ValueError('unsupported plan format')
        plans={}
        for plan in plan_report['plans']:
            if not isinstance(plan,dict) or not isinstance(plan.get('root'),str) or not plan['root']:raise ValueError('plan root must be a nonempty string')
            if plan['root'] in plans:raise ValueError('duplicate plan root: '+plan['root'])
            plans[plan['root']]=plan
        def snapshots(document,format):
            if isinstance(document,list):return document
            if not isinstance(document,dict) or document.get('format')!=format:raise ValueError('unsupported snapshot bundle format')
            return document['snapshots']
        entries=snapshots(entries_document,'osrec-live-entry-state-v1')
        posts=snapshots(posts_document,'osrec-live-entry-effects-v1') if posts_document is not None else None
        calls=request.get('calls')
        if not isinstance(calls,list) or not 1<=len(calls)<=MAX_CALLS:raise ValueError('entry-state replay requires 1 through '+str(MAX_CALLS)+' calls')
        if not isinstance(entries,list) or len(entries)!=len(calls) or (posts is not None and (not isinstance(posts,list) or len(posts)!=len(calls))):
            raise ValueError('call, entry and post-state counts differ')
        selected=[];routes={}
        for index,call in enumerate(calls):
            if (not isinstance(call,dict) or call.get('root') not in plans or
                any(type(call.get(k)) is not int or not 0<=call[k]<=0xffffffff for k in ('number','raw_bits'))):
                raise ValueError('invalid root or 32-bit call record at invocation '+str(index))
            if call['number'] in routes and routes[call['number']]!=call['root']:raise ValueError('one route cannot select multiple roots')
            routes[call['number']]=call['root'];selected.append(plans[call['root']])
            for state in (entries[index],)+( (posts[index],) if posts is not None else ()):
                if not isinstance(state,dict):raise ValueError('snapshot must be an object at invocation '+str(index))
                if 'syscall' in state and (type(state['syscall']) is not int or state['syscall']!=call['number']):raise ValueError('snapshot route differs at invocation '+str(index))
            if posts is not None and entries[index].get('invocation')!=posts[index].get('invocation'):
                raise ValueError('entry/post invocation identity differs at invocation '+str(index))
    except (ValueError,KeyError,TypeError) as error:raise RequestError('calls',str(error)) from error
    try:
        header=reconstruction_header(entries,selected,post_states=posts,scalar_arguments=True,continuous=mode=='continuous')
    except (ValueError,KeyError,TypeError) as error:raise RequestError('reconstruction',str(error)) from error
    dispatch=None
    if 'dispatch' in request:
        try:
            from entry_state_dispatch import generate_dispatch
            dispatch=generate_dispatch(plans,calls,request['dispatch'])
            adapter+=b'\n'+dispatch.encode()
        except (ValueError,KeyError,TypeError) as error:raise RequestError('dispatch',str(error)) from error
    return {'request':request,'request_bytes':request_bytes,'request_sha256':digest(request_bytes),'inputs':inputs,'entries':entries,'posts':posts,'plans':selected,'header':header,
            'model':model,'adapter':adapter,'dispatch':dispatch,'calls':calls,'mode':mode,'translation_units':translation_units,
            'write_effects':any(p.get('state_writes') for p in selected)}


def export(args):
    if args.arch!='aarch64':raise RequestError('target','entry-state images currently require AArch64')
    if args.out.exists():raise RequestError('output','choose a new output directory')
    prepared=prepare_request(args.request)
    if any(p['path'].is_relative_to(args.out) for p in prepared['inputs'].values()) or args.request.is_relative_to(args.out):
        raise RequestError('output','output must not contain request inputs')
    args.out.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.osrec-entry-export-',dir=args.out.parent) as name:
        stage=Path(name);sources=stage/'sources';sources.mkdir()
        (sources/'entry_model.h').write_bytes(prepared['model']);(sources/'entry_adapter.h').write_bytes(prepared['adapter'])
        (sources/'entry_reconstruction.h').write_text(prepared['header'])
        for key,item in prepared['inputs'].items():
            if key.startswith('file:'):(sources/key[5:]).write_bytes(item['data'])
        calls=prepared['calls']
        checkpoint='#define OSREC_CHECKPOINT_CALLS '+str(len(calls))+'\nstruct checkpoint_call {uint32_t number,raw;};\n'
        checkpoint+='static const struct checkpoint_call checkpoint_calls[OSREC_CHECKPOINT_CALLS]={'+','.join(
            '{UINT32_C('+str(c['number'])+'),UINT32_C('+str(c['raw_bits'])+')}' for c in calls)+'};\n'
        (sources/'entry_checkpoint.h').write_text(checkpoint)
        shutil.copy2(ROOT/'integrations/rtl_aarch64/entry_state_replay.c',sources/'entry_state_replay.c')
        try:
            inspection,observed,raw,image,binary=build_and_verify(args,sources,calls,prepared['mode']=='continuous',
                prepared['write_effects'],translation_units=prepared['translation_units'])
        except subprocess.CalledProcessError as error:
            raise RequestError('build_or_verify',str(error)+'\n'+(error.stderr or '')[-12000:]) from error
        except (ValueError,subprocess.SubprocessError,OSError) as error:raise RequestError('build_or_verify',str(error)) from error
        publish=stage/'publish';publish.mkdir();shutil.copytree(sources,publish/'sources')
        for file in (image,binary):shutil.copy2(file,publish/file.name)
        (publish/'target-result.bin').write_bytes(raw)
        portable={**prepared['request'],'mode':prepared['mode'],'files':{}}
        retained=publish/'inputs';retained.mkdir()
        (retained/'original-request.json').write_bytes(prepared['request_bytes'])
        for key,item in prepared['inputs'].items():
            filename=key[5:] if key.startswith('file:') else key+('.h' if key.endswith('_header') else '.json')
            # Prefix support names to avoid collisions with input-role names.
            if key.startswith('file:'):filename='support-'+filename
            (retained/filename).write_bytes(item['data'])
            if key.startswith('file:'):portable['files'][key[5:]]='inputs/'+filename
            else:portable[key]='inputs/'+filename
        (publish/'request.json').write_text(json.dumps(portable,indent=2)+'\n')
        report={'format':'osrec-entry-state-image-v1','mode':prepared['mode'],'calls':calls,
            'input_sha256':{key:item['sha256'] for key,item in prepared['inputs'].items()},
            'request_sha256':prepared['request_sha256'],'target':target_metadata(inspection,observed['abi_version']),'image_audit':inspection,
            'portable_request_sha256':digest((publish/'request.json').read_bytes()),
            'target_observations':observed,'raw_image_execution_match':True,'runtime_host_interaction':False,
            'native_capture_attested':False,'capture_provenance':'supplied by capture frontend; generic export validates typed reconstruction and target replay',
            'minimality_proven':False,'whole_kernel_completeness_proven':False,'rtl_validated':False,
            'elf_sha256':digest(image.read_bytes()),'binary_sha256':digest(binary.read_bytes()),'target_result_sha256':digest(raw),
            'source_sha256':{p.name:digest(p.read_bytes()) for p in sorted(sources.iterdir())}}
        if prepared['dispatch'] is not None:
            report['generated_dispatch']={'format':'osrec-entry-dispatch-v1','sha256':digest(prepared['dispatch'].encode()),
                                          'signature_checks':'original return and parameter ABI checked during compilation'}
        (publish/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
        if args.out.exists():raise RequestError('output','output appeared during verification')
        publish.rename(args.out)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request',required=True,type=Path);parser.add_argument('--out',type=Path)
    parser.add_argument('--check-only',action='store_true',help='validate request and reconstruction without compilation or output')
    parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--qemu',default='qemu-system-aarch64');add_target_arguments(parser);args=parser.parse_args()
    args.request=args.request.resolve();args.llvm_bin=args.llvm_bin.resolve()
    if args.out is not None:args.out=args.out.resolve()
    if not args.check_only and args.out is None:parser.error('--out is required unless --check-only')
    try:
        if args.arch!='aarch64':raise RequestError('target','entry-state images currently require AArch64')
        if args.check_only:
            prepared=prepare_request(args.request)
            result={'format':'osrec-entry-export-check-v1','status':'validated','calls':len(prepared['calls']),
                    'mode':prepared['mode'],'write_effects':prepared['write_effects'],'native_capture_attested':False,
                    'validation_scope':'typed reconstruction; compilation and target execution not performed'}
        else:
            report=export(args);result={'image':str(args.out/'entry-state.elf'),'completed_calls':report['target_observations']['completed_calls']}
        print(json.dumps(result,indent=2))
    except RequestError as error:
        print(json.dumps({'format':'osrec-entry-export-error-v1','stage':error.stage,'detail':str(error)}),file=sys.stderr)
        return 2
    return 0


if __name__=='__main__':sys.exit(main())
