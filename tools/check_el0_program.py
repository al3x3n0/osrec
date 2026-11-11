#!/usr/bin/env python3
"""Observe the complete EL0 executor at exec and terminal exit only.

An incomplete run still produces a coverage report with the original PC.
The separate ptrace observer is never part of the delivery executable.
"""
import argparse,json,re,subprocess,time
from pathlib import Path
from audit_el0_image import audit

def make_load_plan(checked):
    return dict(format='osrec-el0-program-load-v1',image='checkpoint',image_sha256=checked['image_sha256'],
              entry=checked['entry'],execution_level=0,load_segments=checked['load_segments'],
              initialization='Load ELF bytes at segment addresses and zero every memory tail.',
              requirements='Initial EL0 execution, normal RAM covering segment memory extents, FP/SIMD enabled.',
              bootstrap='Image supplies its own stack; no privileged bootstrap or ELF arguments.',
              guest_translation='Software page-table walks against linked RAM; no guest hardware MMU changes.',
              result=dict(address=checked['result_address'],bytes=checked['result_bytes'],status_offset=16,passed=1,failed=2),
              stop_before_optional_exit=checked['terminal_pc'],
              optional_terminal_exit=dict(instruction_pc=checked['terminal_exit_sites'][0],number=93),
              hardware_inputs='Embedded timer values and RAM-backed UART registers; no physical devices or interrupts.',
              cycles_verified=False,rtl_execution_verified=False)

def load_plan(image,checked):
    plan=make_load_plan(checked)
    (Path(image)/'load-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    return plan

def run(image,out,observer,timeout=120):
    image,out,observer=map(lambda p:Path(p).resolve(),(image,out,observer))
    checked=audit(image/'checkpoint')
    out.mkdir(parents=True,exist_ok=False)
    command=['docker','run','--rm','--network','none','--read-only','--cap-add','SYS_PTRACE',
             '--mount','type=bind,src='+str(image/'checkpoint')+',dst=/checkpoint,readonly',
             '--mount','type=bind,src='+str(observer)+',dst=/observer,readonly',
             '--entrypoint','/observer','alpine:3','/checkpoint',checked['result_address']]
    started=time.monotonic();observed=subprocess.run(command,capture_output=True,text=True,timeout=timeout)
    (out/'observer.stdout').write_text(observed.stdout);(out/'observer.stderr').write_text(observed.stderr)
    if observed.returncode:raise ValueError('EL0 observation failed: '+observed.stderr)
    execution=json.loads(observed.stdout);values=execution.pop('words')
    names=('magic','version','status','events','expected','transitions','reason','pc','detail','far',
           'counters','uart_bytes','first_mismatch','missing_pc','elapsed','reserved')
    result=dict(zip(names,values[:16]));result['debug']=values[16:]
    verified=(result['magic']==0x324c55464652534f and result['version']==2 and result['status']==1 and
              execution['exit_argument']==0 and not execution['exit_status'])
    if execution['entry_pc']!=int(checked['entry'],0) or execution['exit_pc']!=int(checked['terminal_pc'],0)+8:
        raise ValueError('image entry or terminal address differs')
    if execution['syscall']!=93:raise ValueError('first service is not exit')
    report=dict(checked,result=result,verified=verified,execution=execution,
                scope='complete checkpoint continuation',host_calls_before_terminal_exit=0,
                full_checkpoint_executed=verified,
                seconds=round(time.monotonic()-started,3))
    (out/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
    if verified:load_plan(image,checked)
    return report

def run_qemu(image,out,docker_image='osrec-qemu-user:20261109',timeout=120):
    image,out=Path(image).resolve(),Path(out).resolve();checked=audit(image/'checkpoint')
    out.mkdir(parents=True,exist_ok=False)
    command=['docker','run','--rm','--network','none','--read-only',
             '--mount','type=bind,src='+str(image/'checkpoint')+',dst=/checkpoint,readonly',
             '--entrypoint','qemu-aarch64',docker_image,'-cpu','cortex-a53','-strace','/checkpoint']
    started=time.monotonic();observed=subprocess.run(command,capture_output=True,text=True,timeout=timeout)
    (out/'qemu.stdout').write_text(observed.stdout);(out/'qemu.stderr').write_text(observed.stderr)
    calls=[line.strip() for line in observed.stderr.splitlines() if re.match(r'^\d+\s+',line)]
    verified=not observed.returncode and len(calls)==1 and bool(re.fullmatch(r'\d+\s+exit\(0\)',calls[0]))
    report=dict(checked,verified=verified,full_checkpoint_executed=verified,qemu_mode='Linux user/application mode',
                cpu='cortex-a53',guest_services=calls,cycles_measured=False,
                observation='guest exit status after in-RAM verification; guest syscall trace',
                seconds=round(time.monotonic()-started,3))
    (out/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
    if not verified:raise ValueError('QEMU application execution failed: '+observed.stderr)
    load_plan(image,checked)
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('image','out'):p.add_argument('--'+name,required=True)
    p.add_argument('--observer',help='separate native Linux observation tool')
    p.add_argument('--qemu',action='store_true',help='run in QEMU Linux application mode')
    p.add_argument('--timeout',type=int,default=120)
    a=p.parse_args()
    if not a.qemu and not a.observer:p.error('--observer is required for native execution')
    r=run_qemu(a.image,a.out,timeout=a.timeout) if a.qemu else run(a.image,a.out,a.observer,a.timeout)
    print(json.dumps({k:r[k] for k in ('verified','result','qemu_mode','guest_services','seconds') if k in r},indent=2))
