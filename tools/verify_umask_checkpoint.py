#!/usr/bin/env python3
"""Check six-call umask reconstruction for arbitrary 32-bit entry masks and arguments."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from klee_liteos import digest, ktest_objects
from live_umask_replay import MODEL_HEADER, driver_source, prepare_source


def run(command, **kwargs):
    return subprocess.run(list(map(str,command)),check=True,capture_output=True,text=True,timeout=60,**kwargs)


def verify(args):
    generated, identity=prepare_source(args.kernel_root)
    if args.out.exists() or args.out.resolve().is_relative_to(args.kernel_root.resolve()):
        raise ValueError('proof output must be a new directory outside the checkout')
    args.out.mkdir(parents=True)
    (args.out/'umask.c').write_text(generated)
    (args.out/'umask_model.h').write_text(MODEL_HEADER)
    # Keep the production model's guards/counters; select two independent semantic objects.
    # Fatal model violations become KLEE errors rather than successful process exits.
    prefix=driver_source([{'mask_before':0,'mask_bits':0,'raw':0,'mask_after':0}],{}).split('int main(')[0]
    prefix=prefix.replace('static struct osrec_process process;', 'static struct osrec_process *active;')
    prefix=prefix.replace('return &process;', 'return active;').replace('exit(1)', 'require(0)')
    harness='''#include <stdint.h>
#ifdef OSREC_PROOF_KLEE
#include <klee/klee.h>
static void require(int condition) {
if(!condition) klee_report_error(__FILE__,__LINE__,"umask reconstruction or model contract differs","umask.err");
}
#else
#include <stdlib.h>
static void require(int condition) { if(!condition) exit(1); }
#endif
'''+prefix+'''
static void check_session(const uint32_t inputs[7]) {
struct osrec_process captured={inputs[0]}, restored={inputs[0]};
uint32_t raw[6],after[6];
active=&captured; locked=locks=unlocks=accesses=0;
for(unsigned i=0;i<6;++i) {
uint32_t before=captured.umask;
raw[i]=SysUmask(inputs[i+1]); after[i]=captured.umask;
require(raw[i]==before && after[i]==(inputs[i+1]&UINT32_C(511)));
require(!locked && locks==i+1 && unlocks==i+1 && accesses==2*(i+1));
}
/* Restore the original checkpoint into a fresh object; never restore captured post-state. */
active=&restored; locked=locks=unlocks=accesses=0;
for(unsigned i=0;i<6;++i) {
require(SysUmask(inputs[i+1])==raw[i] && restored.umask==after[i]);
require(!locked && locks==i+1 && unlocks==i+1 && accesses==2*(i+1));
}
require(captured.umask==restored.umask);
}
#ifdef OSREC_PROOF_KLEE
int main(void) {
uint32_t inputs[7]; klee_make_symbolic(inputs,sizeof(inputs),"inputs");
check_session(inputs); return 0;
}
#else
int main(int argc,char **argv) {
if(argc!=8) return 2;
uint32_t inputs[7];
for(unsigned i=0;i<7;++i) {
char *end; if(!argv[i+1][0] || argv[i+1][0]=='-') return 2;
unsigned long long value=strtoull(argv[i+1],&end,10);
if(*end || value>UINT32_MAX) return 2;
inputs[i]=(uint32_t)value;
}
check_session(inputs); puts("umask reconstruction verified"); return 0;
}
#endif
'''
    (args.out/'proof.c').write_text(harness)
    compiler=args.llvm_bin/'clang'
    for name,flags in [('umask',[]),('proof',['-DOSREC_PROOF_KLEE','-I',args.klee_include])]:
        run([compiler,'-O0','-g','-fno-builtin',*flags,'-emit-llvm','-c',args.out/(name+'.c'),'-o',args.out/(name+'.bc')])
    module=args.out/'equivalence.bc'
    run([args.llvm_bin/'llvm-link',args.out/'umask.bc',args.out/'proof.bc','-o',module])
    native=args.out/'native-proof'
    run([compiler,'-std=c11','-O0','-Wall','-Wextra','-Werror',args.out/'umask.c',args.out/'proof.c','-o',native])
    result=subprocess.run(list(map(str,[args.klee,'--solver-backend=z3','--use-forked-solver=false',
        '--external-calls=none','--exit-on-error','--max-time=40s','--max-memory=512',
        '--output-dir='+str(args.out/'klee'),module])),capture_output=True,text=True,timeout=60)
    log=result.stdout+result.stderr;(args.out/'klee.log').write_text(log)
    completed=re.search(r'^KLEE: done: completed paths = (\d+)$',log,re.M)
    partial=re.search(r'^KLEE: done: partially completed paths = (\d+)$',log,re.M)
    tests=re.search(r'^KLEE: done: generated tests = (\d+)$',log,re.M)
    if result.returncode or not completed or not partial or not tests or int(completed[1])==0 or int(partial[1]) or list((args.out/'klee').glob('*.err')):
        raise ValueError('umask proof did not complete without errors and partial paths')
    replayed=0
    for test in sorted((args.out/'klee').glob('*.ktest')):
        objects=ktest_objects(test)
        if set(objects)!={'inputs'} or len(objects['inputs'])!=28:
            raise ValueError('unexpected symbolic umask test objects')
        data=objects['inputs'];values=[int.from_bytes(data[i:i+4],'little') for i in range(0,28,4)]
        run([native,*values]);replayed+=1
    if replayed!=int(tests[1]) or not replayed:
        raise ValueError('not every symbolic test passed native replay')
    report={'format':'osrec-umask-reconstruction-proof-v1','source_identity':identity,
            'contract':'six sequential calls; all 32-bit entry mask and six argument patterns; no assumptions or pruning; original body executes against explicit process/lock models; fresh entry restoration; independent masking/old-return assertions',
            'completed_paths':int(completed[1]),'partial_paths':int(partial[1]),'native_replayed_tests':replayed,
            'module_sha256':digest(module.read_bytes()),'harness_sha256':digest(harness.encode()),
            'production_driver_sha256':digest(Path(__file__).with_name('live_umask_replay.py').read_bytes()),
            'log_sha256':digest(log.encode()),'scope':'bounded semantic model; no actual kernel locks, concurrency or process layout equivalence'}
    (args.out/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:report[key] for key in ['completed_paths','partial_paths','native_replayed_tests']},indent=2))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-root',required=True,type=Path)
    parser.add_argument('--llvm-bin',required=True,type=Path)
    parser.add_argument('--klee',default='klee')
    parser.add_argument('--klee-include',type=Path,default=Path('/opt/homebrew/opt/klee/include'))
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    for key in ('kernel_root','llvm_bin','klee_include','out'):setattr(args,key,getattr(args,key).resolve())
    verify(args)


if __name__=='__main__':main()
