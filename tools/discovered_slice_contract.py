"""Bind configured discovery footprints to a reviewed joint-execution slice port.

This checks source identity and checkpoint coverage and generates typed user-memory
resolvers. Provider-to-context bindings remain explicit reviewed port contracts.
"""
import json,re
from pathlib import Path
from entry_state import capture_header,digest,entry_accesses,snapshot_providers
from discover_call_closure import analysis_sources,abi_identity
from slice_port_bundle import relative_name

PATH=re.compile(r'[A-Za-z_]\w*(?:\[\d+\]|\.[A-Za-z_]\w*)*\Z')
FIELD=re.compile(r'[A-Za-z_]\w*(?:\[\d+\])?(?:\.[A-Za-z_]\w*(?:\[\d+\])?)*\Z')

def prepare(sources,contract_path,port,context_plan):
    sources=Path(sources);raw=Path(contract_path).read_bytes();contract=json.loads(raw)
    if contract.get('format')!='osrec-discovered-slice-contract-v1':raise ValueError('unsupported discovered slice contract')
    roots={r['function']:r for r in port['roots']}
    if contract.get('roots',{}).keys()!=roots.keys():raise ValueError('discovery contract must cover every port root exactly')
    copies=contract.get('source_copies',{})
    if not isinstance(copies,dict) or not copies:raise ValueError('discovery contract needs configured source copies')
    for name in copies.values():relative_name(name)
    owned={r['name'] for r in context_plan['owned_state']};expected_engine=analysis_sources()
    header=['/* Generated typed bindings; invocation-local user pointers are never restored as kernel state. */',
            '#ifndef OSREC_DISCOVERY_BINDINGS_H','#define OSREC_DISCOVERY_BINDINGS_H',
            '#include "osrec/syscall_slice.h"']
    checked=[];kernel_fields=set();validated_copies=set();assertions=set()
    for root,recipe in roots.items():
        spec=contract['roots'][root];report_file=sources/relative_name(spec['report'])
        if digest(report_file.read_bytes())!=spec.get('report_sha256'):raise ValueError('discovery report identity mismatch: '+root)
        report=json.loads(report_file.read_bytes());plan=report['plan']
        if report.get('status')!='candidate' or plan.get('root')!=root or report.get('analysis_sources_sha256')!=expected_engine:
            raise ValueError('discovery requires a current candidate for the exact port root: '+root)
        capture_header([plan])
        identities=report.get('program',{}).get('source_identities',[])
        if not identities:raise ValueError('discovery lacks configured source identities')
        for identity in identities:
            abi=abi_identity(identity)
            if abi[0]!='aarch64-none-elf' or abi[2]:raise ValueError('discovered joint bridge requires the default freestanding AArch64 ABI')
            original=identity['source'];copy=copies.get(original)
            if copy not in context_plan['input_sha256'] or context_plan['input_sha256'][copy]!=identity['source_sha256']:
                raise ValueError('discovered source differs from prepared kernel code: '+original)
            validated_copies.add(copy)
            for path,sha in identity['dependencies'].items():
                if path in copies and context_plan['input_sha256'].get(copies[path])!=sha:
                    raise ValueError('discovered dependency differs from prepared code: '+path)
                if path in copies:validated_copies.add(copies[path])
        providers=snapshot_providers(plan);byname={p['function']:p for p in providers}
        objects={p['argument']:p for p in providers if p.get('binding_kind')=='root_argument'}
        persistent={p['function']:p for p in providers if p.get('binding_kind')!='root_argument'}
        if spec.get('providers',{}).keys()!=persistent.keys() or spec.get('arguments',{}).keys()!=objects.keys():
            raise ValueError('discovery bindings must cover each provider and typed pointer argument exactly')
        for name,binding in spec.get('providers',{}).items():
            if not isinstance(binding,dict) or not PATH.fullmatch(binding.get('context_path','')) or not binding.get('reason') or not binding.get('implementation'):
                raise ValueError('provider mapping requires an explicit reviewed context binding')
            if re.split(r'[.\[]',binding['context_path'])[0] not in owned:raise ValueError('provider maps outside persistent context')
        fields=[]
        for access in [*entry_accesses(plan),*plan.get('state_writes',[])]:
            path=access['path'];match=re.fullmatch(r'([A-Za-z_]\w*)\(\)->(.+)',path)
            if not match or match[1] not in byname or not FIELD.fullmatch(match[2].replace('->','.')) or '->' in match[2]:
                raise ValueError('discovery bridge requires inline typed record fields: '+path)
            if '*' in access['type']:raise ValueError('discovery bridge does not persist pointer-valued fields')
            provider=byname[match[1]]
            if provider.get('binding_kind')=='root_argument':fields.append(dict(domain='user',argument=provider['argument'],field=match[2],type=access['type']))
            else:
                target=spec['providers'][provider['function']]['context_path']+'.'+match[2]
                kernel_fields.add(target);fields.append(dict(domain='kernel',context_path=target,type=access['type']))
                assertions.add('_Static_assert(__builtin_types_compatible_p(__typeof__(((struct osrec_kernel_context *)0)->'+target+'),'+access['type']+'),"discovered kernel field type differs");')
        writes={a['path'] for a in plan.get('state_writes',[])}
        for name,provider in objects.items():
            binding=spec['arguments'][name];index=provider['argument_index'];typ=provider['return_type']
            if index>=len(recipe['arguments']) or recipe['arguments'][index]!='buffer':raise ValueError('typed argument must map to a buffer route')
            if binding.get('kind')!='user_memory' or type(binding.get('object_id')) is not int or not 0<binding['object_id']<=0xffffffff:
                raise ValueError('typed user argument requires a positive logical object identity')
            permissions=3 if any(p.startswith(provider['function']+'()->') for p in writes) else 1
            if binding.get('permissions')!=permissions:raise ValueError('user memory permissions differ from discovered write footprint')
            pointee=typ.rsplit('*',1)[0].strip()
            if not re.fullmatch(r'(?:const )?(?:struct )?[A-Za-z_]\w*',pointee):raise ValueError('user binding needs a named record pointer')
            function='osrec_discovered_'+root+'_'+name
            header+=['static inline '+typ+' '+function+'(const struct osrec_slice_invocation *in) {',
                '  if(!in || osrec_user_memory_validate(&in->memory)) return 0;',
                '  const struct osrec_user_region *region=osrec_user_memory_object(&in->memory,'+str(binding['object_id'])+',sizeof('+pointee+'),'+str(permissions)+');',
                '  void *view=osrec_user_memory_resolve(&in->memory,in->args['+str(index)+'],sizeof('+pointee+'),'+str(permissions)+');',
                '  if(!region || !view || (uintptr_t)view%_Alignof('+pointee+') || (uintptr_t)view<(uintptr_t)region->image_address || (uintptr_t)view-(uintptr_t)region->image_address>region->bytes || sizeof('+pointee+')>region->bytes-((uintptr_t)view-(uintptr_t)region->image_address)) return 0;',
                '  return ('+typ+')view;','}']
        checked.append(dict(root=root,report_sha256=spec['report_sha256'],plan_sha256=digest(json.dumps(plan,sort_keys=True).encode()),fields=fields,
            provider_bindings=spec.get('providers',{}),user_bindings=spec.get('arguments',{})))
    if set(context_plan['input_sha256'])!=validated_copies:raise ValueError('discovery does not cover every prepared source and header')
    header+=sorted(assertions)+['#endif'];(sources/'discovery_bindings.h').write_text('\n'.join(header)+'\n')
    return dict(format='osrec-discovered-slice-validation-v1',contract_sha256=digest(raw),analysis_sources_sha256=expected_engine,
        bindings_header_sha256=digest((sources/'discovery_bindings.h').read_bytes()),roots=checked,kernel_fields=sorted(kernel_fields),
        provider_binding_semantics='explicit reviewed port mapping; source identity, typed fields and checkpoint coverage are checked',
        native_capture_attested=False,user_execution_required=True,
        source_validation_scope='Copied configured source/header hashes and default AArch64 ABI; portability of compiler options, builtins and reviewed provider mappings remains a port obligation.')


def check_checkpoint_coverage(discovery,codec):
    if not codec:raise ValueError('discovered joint execution requires a complete checkpoint codec')
    persisted={f['path'] for f in codec['fields'] if f['policy']!='transient'}
    if not set(discovery['kernel_fields'])<=persisted:
        raise ValueError('checkpoint omits discovered kernel fields: '+str(sorted(set(discovery['kernel_fields'])-persisted)))
    discovery['checkpoint_coverage_verified']=True
