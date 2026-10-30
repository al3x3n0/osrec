#!/usr/bin/env python3
"""Build C code exercising the complete captured OHOS file lifecycle at EL0."""
import argparse
import json
import struct
from pathlib import Path
from compile_c_application import compile_application

def build(library,out,llvm_bin,prefix_calls=0):
    library,out=Path(library),Path(out)
    if out.exists():raise FileExistsError(out)
    calls=json.loads((library/'checkpoint.json').read_text())['calls']
    if type(prefix_calls) is not int or not 0<=prefix_calls<len(calls):raise ValueError('prefix call count must be smaller than the sequence')
    port=json.loads((library/'manifest.json').read_text())['port']
    roots={r['number']:r for r in port['roots']}
    text='''#include "osrec_application.h"
_Alignas(8) unsigned char app_witness[192];
uint64_t app_returns[32],app_count,app_failed,app_cpu[2];
volatile uint64_t app_marker=42;
static const char main_path[]="/dev/shm/osrec-file.bin",missing_path[]="/dev/shm/osrec-missing.bin";
struct call {uint64_t number,args[6],raw;unsigned char before[192],after[192];};
static const struct call calls[]={
'''
    u=lambda v:'UINT64_C('+str(v)+')'
    expected=[]
    for c in calls:
        args=[]
        for i,kind in enumerate(roots[c['number']]['arguments']):
            v=c['args'][i]
            if kind=='buffer':value='(uint64_t)(uintptr_t)app_witness' if v==1 else u(0xdead00000000) if v==2 else '0'
            elif kind=='path':value='(uint64_t)(uintptr_t)main_path' if v==1 else '(uint64_t)(uintptr_t)missing_path' if v==2 else u(0xdead00000000) if v==3 else '0'
            else:value=u(v)
            args.append(value)
        args+=['0']*(6-len(args))
        raw=c['raw_bits'] if c['raw_bits']<0x80000000 else (c['raw_bits']-0x100000000)&0xffffffffffffffff
        expected.append(raw)
        text+='{'+u(c['number'])+',{'+','.join(args)+'},'+u(raw)+',{'+','.join(map(str,bytes.fromhex(c['buffer_before'])))+'},{'+','.join(map(str,bytes.fromhex(c['buffer_after'])))+'}},\n'
    text+='''};
void osrec_application_main(void){
    uint64_t failed=app_marker!=42 || app_count || app_returns[0];
    for(unsigned i=0;i<sizeof(calls)/sizeof(calls[0]);++i){
        const struct call *c=&calls[i];
        for(unsigned j=0;j<192;++j)app_witness[j]=c->before[j];
        uint64_t raw=(uint64_t)osrec_app_syscall(c->number,c->args[0],c->args[1],c->args[2],c->args[3],c->args[4],c->args[5]);
        app_returns[i]=raw;failed|=raw!=c->raw;
        for(unsigned j=0;j<192;++j)failed|=app_witness[j]!=c->after[j];
        ++app_count;
    }
    ++app_marker;app_failed=failed;
    __asm__ volatile("mrs %0,tpidr_el0":"=r"(app_cpu[0]));
    __asm__ volatile("mrs %0,tpidrro_el0":"=r"(app_cpu[1]));
}
'''
    if prefix_calls:
        expression='osrec_app_syscall(c->number,c->args[0],c->args[1],c->args[2],c->args[3],c->args[4],c->args[5])'
        text=text.replace(expression,'(i<'+str(prefix_calls)+' ? '+expression.replace('osrec_app_syscall(','osrec_app_syscall_prefix(')+' : '+expression+')')
    out.mkdir(parents=True);(out/'application.c').write_text(text)
    spec=dict(frame=dict(tpidr_el0=0x1234567890,tpidrro_el0=0xabcdef0123),objects=[dict(symbol='app_witness',bytes=192,id=1)],assertions=[dict(symbol='app_returns',data=struct.pack('<32Q',*expected).hex()),dict(symbol='app_marker',data=struct.pack('<Q',43).hex()),dict(symbol='app_count',data=struct.pack('<Q',32).hex()),dict(symbol='app_failed',data=struct.pack('<Q',0).hex()),dict(symbol='app_cpu',data=struct.pack('<2Q',0x1234567890,0xabcdef0123).hex())])
    if prefix_calls:spec['call_sites']=['prefix']*prefix_calls+['default']*(len(calls)-prefix_calls)
    (out/'spec.json').write_text(json.dumps(spec,indent=2)+'\n')
    (out/'port.json').write_text(json.dumps(port,indent=2)+'\n')
    return compile_application([out/'application.c'],out/'port.json',out/'compiled',llvm_bin,spec,len(calls))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--slices',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));parser.add_argument('--prefix-calls',type=int,default=0,help='use a separate wrapper for the first N calls')
    a=parser.parse_args();build(a.slices,a.out,a.llvm_bin,a.prefix_calls)
if __name__=='__main__':main()
