#!/usr/bin/env python3
"""Build explicit-context AArch64 syscall slices from a reviewed kernel port."""
import argparse,importlib,json,re,shutil,subprocess,tempfile
from copy import copy
from pathlib import Path
from klee_liteos import ROOT,digest
from contextify_slice import transform,owned_paths
from aarch64_gateway_layout import generate as gateway_layout
from freestanding_armv7 import audit,run
from freestanding_elf import prepare_target,add_target_arguments,target_metadata
from run_freestanding_armv7 import observe,require_success
from slice_port_bundle import validate_bundle,snapshot,publish_inputs

# iovec: a user array of struct iovec whose length is the next argument (readv/writev).
# pointer: a user address the call passes on without a bound object (a null timeout, futex's uaddr2).
KINDS={'signed':1,'unsigned':2,'buffer':3,'path':4,'iovec':5,'pointer':6}
def validate_port(port):
    if port.get('format')!='osrec-kernel-slice-port-v1' or port.get('target_isa')!='aarch64' or port.get('argument_width') not in (32,64):raise ValueError('unsupported kernel port ABI')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9-]*',port.get('name','')) or not port.get('kernel_abi'):raise ValueError('kernel port module/ABI missing')
    if 'bundle' in port:
        if 'capture_adapter' in port:raise ValueError('choose one kernel port construction mechanism')
        validate_bundle(port['bundle'])
    elif not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*',port.get('capture_adapter','')):raise ValueError('kernel port module/ABI missing')
    seen=set()
    for root in port.get('roots',[]):
        number=root.get('number');name=root.get('function');arguments=root.get('arguments')
        if type(number) is not int or not 0<=number<1<<64 or number in seen or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*',name or '') or not isinstance(arguments,list) or not 0<=len(arguments)<=6 or any(a not in KINDS for a in arguments):raise ValueError('invalid syscall root recipe')
        seen.add(number)
    if not seen:raise ValueError('kernel port has no roots')
    if 'application_abi' in port:validate_application_abi(port['application_abi'])
    if port.get('target_mmu','identity')!='identity':raise ValueError('unsupported target MMU mode')
    # The kernel's automatic-variable initialization (CONFIG_INIT_STACK_ALL_ZERO / _PATTERN), applied to C slices.
    if port.get('stack_init','none') not in ('none','zero','pattern'):raise ValueError('unsupported stack initialization')
    if 'entry' in port and (not isinstance(port['entry'],dict) or not {'function'}<=set(port['entry'])<={'function','assembly'} or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*',port['entry']['function'] or '') or port['entry'].get('assembly',False) not in (True,False)):raise ValueError('invalid system call entry recipe')

def validate_application_abi(abi):
    if not isinstance(abi,dict) or abi.get('format')!='osrec-aarch64-syscall-registers-v1' or abi.get('continuation')!='svc-pc-plus-4':raise ValueError('unsupported application frame ABI')
    registers=[abi.get('number_register'),abi.get('result_register')];arguments=abi.get('argument_registers')
    if not isinstance(arguments,list) or len(arguments)!=6 or any(type(r) is not int or not 0<=r<31 for r in registers+arguments) or len(set(arguments))!=6 or registers[0] in arguments:raise ValueError('invalid application register recipe')

def application_abi_source(abi,roots):
    validate_application_abi(abi)
    text='#include "osrec/aarch64_frame.h"\nstatic const struct osrec_aarch64_syscall_recipe syscalls[]={\n'
    text+=''.join('    {UINT64_C('+str(root['number'])+'),'+str(len(root['arguments']))+'},\n' for root in sorted(roots,key=lambda root:root['number']))
    return text+'};\nconst struct osrec_aarch64_syscall_abi osrec_application_abi={OSREC_AARCH64_FRAME_ABI,'+str(abi['number_register'])+',{'+','.join(map(str,abi['argument_registers']))+'},'+str(abi['result_register'])+',syscalls,sizeof(syscalls)/sizeof(syscalls[0])};\n'

def dispatch_header(port,plan):
    for root in port['roots']:
        signature=plan['signatures'].get(root['function'])
        if not signature:raise ValueError('root is outside the supplied closure')
        count=len(signature['parameters']);actual=len(root['arguments'])
        if actual<count or (actual!=count and not signature['variadic']):raise ValueError('root recipe differs from the extracted function signature')
    text='#ifndef OSREC_SLICE_DISPATCH_H\n#define OSREC_SLICE_DISPATCH_H\n'
    text+='#define OSREC_CONTEXT_FUNCTIONS '+str(len(plan['context_functions']))+'\n#define OSREC_STATE_OBJECTS '+str(len(plan['owned_state']))+'\n'
    text+='static inline unsigned osrec_argument_kind(uint64_t number,unsigned index)\n{switch(number){\n'
    for root in port['roots']:
        text+='case UINT64_C('+str(root['number'])+'): {static const unsigned kinds[6]={'+(','.join(str(KINDS[a]) for a in root['arguments']) or '0')+'};return index<6 ? kinds[index] : 0;}\n'
    text+='default:return 0;}}\n'
    # osrec_kernel_dispatch_root calls the root directly; analyses that start at the root use it.
    def direct(name):
        body='static inline int64_t '+name+'(struct osrec_kernel_context *ctx,uint64_t number,const uintptr_t *arguments)\n{(void)ctx;(void)arguments;switch(number){\n'
        for root in port['roots']:
            casts={'signed':'int'+str(port['argument_width'])+'_t','unsigned':'uint'+str(port['argument_width'])+'_t','buffer':'void *','path':'const char *','iovec':'void *','pointer':'void *'}
            arguments=', '.join('('+casts[k]+')arguments['+str(i)+']' for i,k in enumerate(root['arguments']))
            body+='case UINT64_C('+str(root['number'])+'): return (int64_t)'+plan['symbols'][root['function']]+'('+(', '.join(['ctx',arguments] if arguments else ['ctx']) if root['function'] in plan['context_functions'] else arguments)+');\n'
        return body+'default:return 0;}}\n'
    text+=direct('osrec_kernel_dispatch_root')+'#define OSREC_ROOT_DISPATCH osrec_kernel_dispatch_root\n'
    if 'entry' not in port:return text+direct('osrec_kernel_dispatch')+'#endif\n'
    # Every root is entered through the port's system call entry (number, six argument registers).
    entry=port['entry']['function']
    if port['entry'].get('assembly'):
        text+='int64_t '+entry+'(struct osrec_kernel_context *ctx,uint64_t number,const uintptr_t *arguments);\n';call=entry+'(ctx, number, arguments)'
    else:
        signature=plan['signatures'].get(entry)
        if not signature or len(signature['parameters'])!=2:raise ValueError('system call entry is outside the supplied closure')
        call=plan['symbols'][entry]+('(ctx, ' if entry in plan['context_functions'] else '(')+'number, arguments)'
    text+='static inline int64_t osrec_kernel_dispatch(struct osrec_kernel_context *ctx,uint64_t number,const uintptr_t *arguments)\n{switch(number){\n'
    text+=''.join('case UINT64_C('+str(root['number'])+'):\n' for root in port['roots'])
    return text+'return (int64_t)'+call+';\ndefault:(void)ctx;(void)arguments;return 0;}}\n#endif\n'


def state_layout(sources,clang):
    probe=sources/'slice_layout_probe.c'
    probe.write_text('#include "slice_context.h"\nenum {OSREC_SLICE_STATE_BYTES=sizeof(struct osrec_kernel_context),OSREC_SLICE_STATE_ALIGNMENT=_Alignof(struct osrec_kernel_context)};\n')
    result=subprocess.run([str(clang),'--target=aarch64-none-elf','-std=c11','-ffreestanding','-I'+str(sources),'-Xclang','-ast-dump=json','-fsyntax-only',str(probe)],capture_output=True,text=True,timeout=60)
    if result.returncode:raise ValueError('target state layout compilation failed: '+result.stderr)
    from contextify_slice import walk
    values={}
    for n in walk(json.loads(result.stdout)):
        if n['kind']=='EnumConstantDecl' and n.get('name','').startswith('OSREC_SLICE_STATE_'):
            constants=[c for c in walk(n) if c['kind']=='ConstantExpr' and 'value' in c]
            if len(constants)!=1:raise ValueError('target layout is not constant')
            values[n['name']]=int(constants[0]['value'])
    if len(values)!=2:raise ValueError('target state layout missing')
    (sources/'slice_layout.h').write_text('#ifndef OSREC_SLICE_LAYOUT_H\n#define OSREC_SLICE_LAYOUT_H\n'+''.join('#define '+k+' '+str(v)+'u\n' for k,v in values.items())+'#endif\n')
    return values

def export(args):
    if args.out.exists():raise ValueError('choose a new output directory')
    if getattr(args,'arch','aarch64')!='aarch64':raise ValueError('callable slice backend requires AArch64')
    if any(args.out.resolve().is_relative_to(p.resolve()) for p in (args.capture,args.kernel_root,ROOT/'build/ohos')):raise ValueError('output overlaps construction input')
    port_raw=args.port.read_bytes();port=json.loads(port_raw);validate_port(port)
    if 'bundle' in port and args.out.resolve().is_relative_to(args.port.resolve().parent):raise ValueError('output overlaps port bundle')
    cpu_proof=getattr(args,'cpu_gateway',False)
    frame_proof=getattr(args,'application_frame',False) or cpu_proof
    if frame_proof and 'application_abi' not in port:raise ValueError('application-frame proof requires a port register ABI')
    with tempfile.TemporaryDirectory(prefix='osrec-callable-slices-') as name:
        stage=Path(name).resolve();sources=stage/'sources';sources.mkdir();flags=prepare_target(args,sources,port.get('target_mmu'))
        mode='cpu' if cpu_proof else 'frame' if frame_proof else 'session'
        bundle_root=stage/'port-inputs';external_proof=None
        if 'bundle' in port:
            module,external_proof=snapshot(args.port,port,bundle_root,mode)
            adapter_args=copy(args);adapter_args.port_root=bundle_root
            package=module.prepare(adapter_args,sources)
        else:package=importlib.import_module(port['capture_adapter']).prepare(args,sources)
        if not set(package['required_syscalls'])<={r['number'] for r in port['roots']}:raise ValueError('capture syscall has no root recipe in the port')
        shutil.copytree(ROOT/'include/osrec',sources/'osrec')
        plan=transform(sources,package['sources'],package['headers'],args.llvm_bin/'clang',include_dirs=[sources])
        discovery={}
        if package.get('discovery_contract'):
            from discovered_slice_contract import prepare as discovery_bindings
            discovery=discovery_bindings(sources,sources/package['discovery_contract'],port,plan)
            probe=sources/'discovery_binding_probe.c'
            probe.write_text('#include "slice_context.h"\n#include "discovery_bindings.h"\n')
            run([args.llvm_bin/'clang',*flags,'-std=c11','-ffreestanding','-fno-builtin','-I'+str(sources),'-fsyntax-only',probe])
            discovery['target_binding_syntax_verified']=True
        (sources/'slice_dispatch.h').write_text(dispatch_header(port,plan))
        layout=state_layout(sources,args.llvm_bin/'clang')
        codec={};codec_sources=[]
        if package.get('checkpoint_policy'):
            from slice_checkpoint_codec import generate as checkpoint_codec
            codec=checkpoint_codec(sources,args.llvm_bin/'clang',sources/package['checkpoint_policy'],dict(port=port,source=package['identity'],capture_sha256=digest((args.capture/package['capture_manifest']).read_bytes()),context_sha256=digest((sources/'slice_context.h').read_bytes()),closure_sha256={n:digest((sources/n).read_bytes()) for n in (*package['sources'],*package['headers'],package['adapter_source'],package['data_source'])}))
            shutil.copyfile(ROOT/'runtime/slice_checkpoint.c',sources/'slice_checkpoint_runtime.c')
            codec_sources=['slice_codec.c','slice_checkpoint_runtime.c']
        if discovery:
            from discovered_slice_contract import check_checkpoint_coverage
            check_checkpoint_coverage(discovery,codec)
        shutil.copyfile(ROOT/'runtime/syscall_slice.c',sources/'slice_runtime.c')
        shutil.copyfile(ROOT/'runtime/slice_bytes.c',sources/'slice_bytes.c')
        shutil.copyfile(ROOT/'runtime/syscall_slice_aarch64.S',sources/'slice_guard.S')
        bridge_sources=[];gateway_offsets={};proof_sources=[]
        if 'application_abi' in port:
            shutil.copyfile(ROOT/'runtime/aarch64_frame.c',sources/'slice_frame.c')
            (sources/'slice_application_abi.c').write_text(application_abi_source(port['application_abi'],port['roots']))
            shutil.copyfile(ROOT/'runtime/aarch64_gateway.c',sources/'slice_gateway.c')
            shutil.copyfile(ROOT/'runtime/aarch64_gateway.S',sources/'slice_gateway_aarch64.S')
            gateway_offsets=gateway_layout(sources,args.llvm_bin/'clang')
            bridge_sources=['slice_frame.c','slice_application_abi.c','slice_gateway.c','slice_gateway_aarch64.S']
        # The proof driver is port-owned; kernel/runtime construction is shared.
        proof=bundle_root/external_proof['source'] if external_proof else ROOT/'integrations/slices'/ (port['name']+('-cpu-driver.c' if cpu_proof else '-frame-driver.c' if frame_proof else '-driver.c'))
        if not proof.is_file():raise ValueError('kernel port QEMU proof driver missing')
        shutil.copyfile(proof,sources/'slice_driver.c')
        if cpu_proof:
            application=bundle_root/external_proof['application'] if external_proof else ROOT/'integrations/slices'/(port['name']+'-app.S')
            shutil.copyfile(application,sources/'slice_app.S')
            proof_sources=['slice_app.S']
        elf=stage/'slices.elf';binary=stage/'slices.bin'
        compiled=owned_paths(sources,(*package['sources'],*package.get('assembly_sources',()),package['adapter_source'],package['data_source'],'slice_runtime.c','slice_bytes.c','slice_guard.S',*codec_sources,*bridge_sources,*proof_sources,'slice_driver.c'))
        compiler=[args.llvm_bin/'clang',*flags,'-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-I'+str(sources)]
        stack_init=['-ftrivial-auto-var-init='+port['stack_init']] if port.get('stack_init','none')!='none' else []
        objects=stage/'objects';objects.mkdir();library_objects=[]
        # Preserve existing flat archive names, but never reuse an object or
        # archive member when two prepared paths have the same stem.
        colliding=len({p.stem for p in compiled})!=len(compiled)
        object_paths={p:objects/((str(i)+'-'+p.name if colliding else p.stem)+'.o') for i,p in enumerate(compiled)}
        proof_paths={sources/n for n in (*proof_sources,'slice_driver.c')}
        options=package.get('assembly_options',{})
        if not isinstance(options,dict) or set(options)-set(package.get('assembly_sources',())):raise ValueError('assembly options name no assembly source')
        def assembly_flags(name):
            """Port-declared preprocessor setup of one assembly source (a kernel's own include tree)."""
            o=options.get(name)
            if o is None:return []
            if not isinstance(o,dict) or set(o)-{'defines','preincludes','include_dirs'}:raise ValueError('invalid assembly options')
            inside=lambda d:(sources/d).resolve().is_relative_to(sources) and (sources/d).exists()
            if any(not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*',d) for d in o.get('defines',[])) or not all(inside(d) for d in (*o.get('preincludes',[]),*o.get('include_dirs',[]))):raise ValueError('invalid assembly options')
            return ['-nostdinc',*('-D'+d for d in o.get('defines',[])),*(x for f in o.get('preincludes',[]) for x in ('-include',str(sources/f))),*('-I'+str(sources/d) for d in o.get('include_dirs',[]))]
        for source in compiled:
            # Only the explicit CPU-state assembly may move FP/SIMD registers.
            compile_flags=[*(f for f in compiler if f!='-mgeneral-regs-only'),*assembly_flags(source.relative_to(sources).as_posix())] if source.suffix=='.S' else [*compiler,*stack_init]
            obj=object_paths[source];run([*compile_flags,'-c',source,'-o',obj])
            if source not in proof_paths:library_objects.append(obj)
        archive=stage/'slices.a';run([args.llvm_bin/'llvm-ar','rcs',archive,*library_objects])
        run([*compiler,'-nostdlib','-static','-fuse-ld=lld','-Wl,--no-undefined','-Wl,-T,'+str(sources/'image.ld'),sources/'start.S',object_paths[sources/'slice_driver.c'],*[object_paths[sources/n] for n in proof_sources],archive,'-o',elf])
        reviewed={}
        if cpu_proof:
            symbols={row.split()[0]:int(row.split()[2],16) for row in run([args.llvm_bin/'llvm-nm','--defined-only','--format=posix',elf]).stdout.splitlines() if len(row.split())>=3}
            traps=package.get('cpu_breakpoints')
            if not isinstance(traps,dict) or not traps or any(not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*',n) or type(v) is not int or v not in (0x5353,0x5354) for n,v in traps.items()):raise ValueError('CPU proof has no reviewed embedded breakpoint contract')
            reviewed={symbols[n]:v for n,v in traps.items()}
        inspected=audit(elf,args.llvm_bin,reviewed);run([args.llvm_bin/'llvm-objcopy','-O','binary',elf,binary])
        proof_abi=external_proof['result_abi'] if external_proof else 20 if cpu_proof else 19 if frame_proof else 18
        observed,raw=observe(elf,args.qemu);require_success(observed)
        if observed['abi_version']!=proof_abi:raise ValueError('kernel-port proof result ABI differs from descriptor')
        if any(observed.get(k)!=v for k,v in package['expected_result'].items()):raise ValueError('kernel-port proof output differs from capture contract')
        raw_observed,raw_result=observe(binary,args.qemu,descriptor=elf);require_success(raw_observed)
        if raw_result!=raw:raise ValueError('ELF/raw callable slice results differ')
        publish=stage/'published';publish.mkdir();shutil.copyfile(elf,publish/elf.name);shutil.copyfile(binary,publish/binary.name);shutil.copyfile(archive,publish/archive.name);shutil.copytree(sources,publish/'sources')
        (publish/'target-result.bin').write_bytes(raw);(publish/'checkpoint.json').write_text(json.dumps(package['checkpoint'],indent=2)+'\n')
        if external_proof:publish_inputs(bundle_root,publish/'port-inputs',port['bundle'])
        if args.port.read_bytes()!=port_raw:raise ValueError('kernel port descriptor changed during construction')
        report={'format':'osrec-callable-slices-image-v1','port':port,'port_sha256':digest(port_raw),'state_layout':layout,'checkpoint_codec':codec,'gateway_layout':gateway_offsets,'archive_sha256':digest(archive.read_bytes()),'source_identity':package['identity'],'context_plan':plan,
            'target':target_metadata(inspected,proof_abi,port.get('target_mmu')),'cpu_breakpoint_contract':package.get('cpu_breakpoints',{}) if cpu_proof else {},'image_audit':inspected,'target_observations':observed,'elf_sha256':digest(elf.read_bytes()),'binary_sha256':digest(binary.read_bytes()),
            'capture_manifest_sha256':digest((args.capture/package['capture_manifest']).read_bytes()),'expected_result':package['expected_result'],
            'construction_sha256':{n:digest((ROOT/'tools'/n).read_bytes()) for n in ('contextify_slice.py','export_syscall_slices.py','aarch64_gateway_layout.py','slice_checkpoint_codec.py','slice_port_bundle.py',*(() if external_proof else (port['capture_adapter']+'.py',)))},
            'source_hashes':{str(p.relative_to(sources)):digest(p.read_bytes()) for p in sources.rglob('*') if p.is_file()},'kernel_image_sha256':package['metadata']['kernel_image_sha256'],
            'application_frame_bridge':bool(bridge_sources),'application_frame_proof':frame_proof,'hardware_cpu_gateway_included':bool(gateway_offsets),'hardware_cpu_windows_included':bool(gateway_offsets),'cpu_gateway_proof':cpu_proof,'hardware_cpu_restore_integrated':cpu_proof,'runtime_host_interaction':False,'raw_image_execution_match':True,'app_checkpoint_loader_integrated':False,'concurrent_session_execution_supported':False}
        if discovery:
            report['discovered_state_contract']=discovery
            report['construction_sha256']['discovered_slice_contract.py']=digest((ROOT/'tools/discovered_slice_contract.py').read_bytes())
        (publish/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');shutil.copytree(publish,args.out)
    return report

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--capture',type=Path,required=True);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--port',type=Path,default=ROOT/'integrations/liteos_a/files-slice-port.json')
    parser.add_argument('--kernel-root',type=Path,default=ROOT/'build/kernel_liteos_a');parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'))
    parser.add_argument('--cpu-gateway',action='store_true',help='verify real EL0 CPU entry, embedded syscall routing and return')
    parser.add_argument('--application-frame',action='store_true',help='verify saved AArch64 application frames with the kernel-port proof driver')
    add_target_arguments(parser);parser.add_argument('--qemu',default='qemu-system-aarch64');args=parser.parse_args()
    for key in ('capture','out','port','kernel_root','llvm_bin'):setattr(args,key,getattr(args,key).resolve())
    print(json.dumps(export(args)['target_observations'],indent=2))
if __name__=='__main__':main()
