#!/usr/bin/env python3
"""Observe one live SVC boundary inside a resumed full-machine checkpoint.

A configurable contract supplies the trap encoding, number/argument/result
registers, exception vectors and the register that anchors kernel state. The
observer stops at the lower-EL synchronous vector, so no user binary layout or
kernel symbol is needed. Kernel objects are projected through a reviewed BTF
binding at entry and at the first later kernel entry (no kernel instruction runs
between the return and that observation). The guest must still produce its
checkpoint oracle afterwards, so observation cannot silently perturb it.
"""
import argparse,contextlib,hashlib,json,os,re,socket
from types import SimpleNamespace
from pathlib import Path
from gdb_remote import Exited,Remote
from kernel_btf import BTF
from live_kernel_binding import check_config,project,validate as validate_binding
import qemu_vm_checkpoint as machine

FORMAT='osrec-svc-boundary-observation-v1';CONTRACT='osrec-svc-boundary-contract-v1'
MODES={'EL0t':0,'EL1t':4,'EL1h':5}
GPRS=['x%d'%i for i in range(31)]
def sha(data):return hashlib.sha256(data).hexdigest()

def validate_contract(c):
    if c.get('format')!=CONTRACT or c.get('isa')!='aarch64':raise ValueError('unsupported SVC boundary contract')
    t=c.get('trap',{});e=c.get('entry',{});a=c.get('kernel_anchor',{})
    if type(t.get('word')) is not int or t.get('bytes')!=4 or t.get('user_mode') not in MODES or c.get('return',{}).get('user_mode')!=t['user_mode']:raise ValueError('invalid trap description')
    registers=[c.get('number_register'),c.get('result_register'),*c.get('argument_registers',[])]
    if any(r not in GPRS for r in registers) or len(set(c['argument_registers']))!=len(c['argument_registers']) or not 1<=len(c['argument_registers'])<=8 or c['number_register'] in c['argument_registers']:raise ValueError('invalid syscall register description')
    if any(r not in GPRS+['user_sp'] for r in c.get('preserved_registers',[])) or c['result_register'] in c.get('preserved_registers',[]):raise ValueError('invalid preserved register set')
    offsets=[e.get('synchronous_vector_offset'),*e.get('asynchronous_vector_offsets',[])]
    if any(type(o) is not int or o%0x80 or not 0<=o<0x800 for o in offsets) or len(set(offsets))!=len(offsets) or e.get('kernel_mode') not in MODES or type(e.get('syndrome_class')) is not int:raise ValueError('invalid exception entry description')
    if c.get('return',{}).get('continuation')!='trap-plus-bytes' or c.get('kernel_memory_visibility')!='kernel-mode-only':raise ValueError('unsupported return or kernel-memory visibility rule')
    if type(a.get('minimum')) is not int or type(a.get('max_entry_steps')) is not int or not 0<a['max_entry_steps']<=4096 or not re.fullmatch(r'[A-Za-z_]\w*',a.get('name','')):raise ValueError('invalid kernel anchor')
    return c

def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

class Observer:
    def __init__(self,remote,contract,btf,binding):
        self.r=remote;self.c=contract;self.btf=btf;self.binding=binding
        self.vbar=remote.register(contract['entry']['vector_base_register'])
        self.sync=self.vbar+contract['entry']['synchronous_vector_offset']
        self.vectors=[self.sync,*(self.vbar+o for o in contract['entry']['asynchronous_vector_offsets'])]
    def mode(self):return self.r.register('cpsr')&15
    def user_registers(self):
        values=self.r.registers(GPRS);values['user_sp']=self.r.register(self.c['user_stack_register'])
        return values
    def entry(self):
        e=self.c['entry'];return dict(pc=self.r.register('pc'),mode=self.mode(),syndrome=self.r.register(e['syndrome_register']),
            return_address=self.r.register(e['return_address_register']),saved_status=self.r.register(e['saved_status_register']))
    def anchor(self):
        """Step kernel entry code until the contract's anchor register holds a kernel object."""
        a=self.c['kernel_anchor']
        for steps in range(a['max_entry_steps']+1):
            value=self.r.register(a['register'])
            if value>=a['minimum']:
                if self.mode()!=MODES[self.c['entry']['kernel_mode']]:raise ValueError('anchor found outside kernel mode')
                return value,steps
            self.r.step()
        raise ValueError('kernel anchor not established within the entry-step bound')
    def step_over(self,address):
        self.r.breakpoint(address,False);self.r.step();self.r.breakpoint(address)
    def kernel(self):
        anchor,steps=self.anchor();return anchor,steps,project(self.binding,self.btf,self.r,anchor)
    def enter(self,regs,e,roots,strict=True):
        """Record a selected synchronous SVC entry; user registers are still untouched here."""
        c=self.c
        if e['mode']!=MODES[c['entry']['kernel_mode']] or e['saved_status']&15!=MODES[c['trap']['user_mode']]:raise ValueError('trap did not enter from the contract user mode')
        site=e['return_address']-c['trap']['bytes'];word=int.from_bytes(self.r.read(site,4),'little')
        if word!=c['trap']['word']:raise ValueError('return address does not follow the contract trap instruction')
        call=dict(number=regs[c['number_register']],**{k:regs[k] for k in c['argument_registers']})
        objects=user_objects(self.binding,roots,call,c,strict)
        return dict(site=site,word=word,continuation=site+c['trap']['bytes'],entry=e,call=dict(number=call['number'],arguments=[call[k] for k in c['argument_registers']]),
            objects=objects,pre=dict(registers=regs,status=e['saved_status'],user_objects=[dict(o,bytes=self.r.read(o['address'],o['size']).hex()) for o in objects],pages=pages(self.r,objects)))
    def complete(self,record,timeout):
        """Run to the continuation; the kernel may not return elsewhere or re-enter first."""
        c=self.c;r=self.r;objects=record['objects'];before=record['pre']['registers']
        r.breakpoint(record['continuation']);r.resume();pc=r.wait(timeout);interrupted=None
        if pc in self.vectors[1:]:
            # An asynchronous exception taken before the first continuation instruction:
            # the return happened (ELR is the continuation, SPSR is user mode) and the
            # user GPRs are still untouched at this vector.
            e=self.entry()
            if e['return_address']!=record['continuation'] or e['saved_status']&15!=MODES[c['return']['user_mode']]:raise ValueError('asynchronous entry before the kernel returned to the continuation')
            interrupted=e;status=e['saved_status']
        elif pc!=record['continuation']:raise ValueError('kernel returned elsewhere or re-entered before the continuation: 0x%x'%pc)
        elif self.mode()!=MODES[c['return']['user_mode']]:raise ValueError('continuation reached outside user mode')
        else:status=r.register('cpsr')
        after=self.user_registers()
        returned=dict(registers=after,status=status,result=after[c['result_register']],user_objects=[dict(o,bytes=r.read(o['address'],o['size']).hex()) for o in objects],pages=pages(r,objects))
        if interrupted:returned['observed_at_asynchronous_entry']=interrupted
        clobbered=sorted(k for k in c['preserved_registers'] if after[k]!=before[k])
        if clobbered:raise ValueError('kernel changed preserved registers: '+', '.join(clobbered))
        returned['changed']=[dict(address=p['address'],offsets=[i for i,(x,y) in enumerate(zip(bytes.fromhex(p['bytes']),bytes.fromhex(q['bytes']))) if x!=y]) for p,q in zip(record['pre']['pages'],returned['pages'])]
        if any(not any(o['address']<=p['address']+i<o['address']+o['size'] for o in objects) for p in returned['changed'] for i in p['offsets']):raise ValueError('kernel changed user bytes outside admitted objects')
        returned['preserved_registers_checked']=len(c['preserved_registers'])
        r.breakpoint(record['continuation'],False)
        return returned

@contextlib.contextmanager
def session(checkpoint,contract,binding,out,timeout,kernel_config):
    """Resume a checkpoint paused behind a loopback gdbstub with vector breakpoints set."""
    checkpoint=Path(checkpoint).resolve();out=Path(out).resolve()
    if out.exists():raise FileExistsError(out)
    spec=machine.verify(checkpoint);contract_raw=Path(contract).read_bytes();binding_raw=Path(binding).read_bytes()
    c=validate_contract(json.loads(contract_raw));b=validate_binding(json.loads(binding_raw))
    if 'kernel' not in spec['files']:raise ValueError('checkpoint has no pinned kernel image')
    kernel=(checkpoint/'assets/kernel').read_bytes();btf=BTF(kernel)
    if kernel_config is not None:check_config(b,Path(kernel_config).read_text())
    elif b.get('kernel_config'):raise ValueError('binding requires the kernel configuration')
    out.mkdir(parents=True);port=free_port()
    with machine.Machine(checkpoint,'boundary',incoming=True,timeout=timeout,execution_dir=out,observer=('-gdb','tcp:127.0.0.1:%d'%port)) as m:
        m.request('migrate-incoming',dict(uri='file:'+str(checkpoint/'vmstate.bin')));m.migration_complete()
        if m.request('query-status')['running']:raise ValueError('incoming checkpoint ran before observation')
        r=Remote(port,timeout=timeout);o=Observer(r,c,btf,b)
        for v in o.vectors:r.breakpoint(v)
        header=dict(contract=c,contract_sha256=sha(contract_raw),binding_sha256=sha(binding_raw),
            checkpoint=dict(path=str(checkpoint),manifest_sha256=sha((checkpoint/'manifest.json').read_bytes()),vmstate_sha256=sha((checkpoint/'vmstate.bin').read_bytes()),kernel_sha256=sha(kernel)))
        r.resume();os.write(m.serial_in,spec['protocol']['continue_line'].encode())
        yield SimpleNamespace(machine=m,remote=r,observer=o,spec=spec,contract=c,header=header,out=out)
        result=m.wait_line(spec['protocol']['success_prefix'],spec['protocol'].get('reject_on_resume',[]))
        if result!=spec['protocol']['expected_success']:raise ValueError('observed guest no longer produces the checkpoint oracle')
        header['oracle']=dict(result=result,matches=True);header['qemu_command']=m.command

CLAIMS=dict(user_binary_layout_used=False,kernel_symbols_used=False,btf_offsets=True,reviewed_field_correspondence=True,kernel_memory_read_in_kernel_mode_only=True)
def is_svc(s,pc,e):return pc==s.observer.sync and e['syndrome']>>26==s.contract['entry']['syndrome_class']

def capture(checkpoint,contract,binding,select,out,occurrence=1,timeout=120,kernel_config=None,binding_root=None):
    if type(occurrence) is not int or occurrence<1:raise ValueError('occurrence must be positive')
    roots=spec_roots(binding_root);candidates=[]
    with session(checkpoint,contract,binding,out,timeout,kernel_config) as s:
        r,o,c=s.remote,s.observer,s.contract
        if not select or any(k!='number' and k not in c['argument_registers'] for k in select):raise ValueError('selection must name the number or argument registers')
        seen=0
        while True:
            pc=r.wait(timeout)
            if pc not in o.vectors:raise ValueError('unexpected stop at 0x%x'%pc)
            regs=o.user_registers();e=o.entry()
            if is_svc(s,pc,e):
                call=dict(number=regs[c['number_register']],**{k:regs[k] for k in c['argument_registers']})
                candidates.append(dict(site=e['return_address']-c['trap']['bytes'],**{k:hex(v) for k,v in call.items()}))
                if all(call[k]==v for k,v in select.items()):
                    seen+=1
                    if seen==occurrence:break
            o.step_over(pc);r.resume()
        record=o.enter(regs,e,roots);anchor,steps,kernel_pre=o.kernel()
        returned=o.complete(record,timeout)
        if 'observed_at_asynchronous_entry' in returned:later=returned['observed_at_asynchronous_entry'];pc=later['pc']
        else:
            r.resume();pc=r.wait(timeout)
            if pc not in o.vectors:raise ValueError('unexpected stop before the next kernel entry')
            later=o.entry()
        post_anchor,post_steps,kernel_post=o.kernel()
        if post_anchor!=anchor:raise ValueError('next kernel entry runs a different task')
        for v in o.vectors:r.breakpoint(v,False)
        r.detach()
    report=dict(format=FORMAT,status='observed',**s.header,selection=dict(select=dict(select),occurrence=occurrence),earlier_svc_entries=candidates[:-1],
        trap=dict(site=record['site'],word=record['word'],continuation=record['continuation']),entry=dict(vector=o.sync,vector_base=o.vbar,**e,anchor=anchor,anchor_steps=steps),
        call=record['call'],pre=record['pre'],kernel_pre=kernel_pre,returned=returned,
        kernel_post=dict(**kernel_post,observed_at=dict(vector_offset=pc-o.vbar,**later),anchor_steps=post_steps,kernel_instructions_between_return_and_observation='entry code only'),claims=CLAIMS)
    (s.out/'boundary.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

SEQUENCE='osrec-svc-boundary-sequence-v1'
def capture_sequence(checkpoint,contract,binding,out,timeout=120,kernel_config=None,binding_root=None,limit=4096):
    """Observe every SVC from resume until the guest stops.

    Kernel post-state of call i is projected at the first later lower-EL entry;
    its pre-state is projected at its own entry. Asynchronous or non-SVC entries
    in between are counted. A call during which the machine exits is terminal.
    """
    roots=spec_roots(binding_root);records=[];pending=None;between=0
    with session(checkpoint,contract,binding,out,timeout,kernel_config) as s:
        r,o=s.remote,s.observer
        while True:
            try:pc=r.wait(timeout)
            except Exited:break
            if pc not in o.vectors:raise ValueError('unexpected stop at 0x%x'%pc)
            regs=o.user_registers();e=o.entry();state=None
            if pending is not None:
                anchor,steps,state=o.kernel()
                if anchor!=pending['anchor']:raise ValueError('next kernel entry runs a different task')
                pending['kernel_post']=dict(**state,observed_at=dict(vector_offset=pc-o.vbar,**e),anchor_steps=steps);pending=None
            if is_svc(s,pc,e):
                record=o.enter(regs,e,roots,strict=False)
                if state is None:anchor,steps,state=o.kernel()
                record.update(ordinal=len(records),anchor=anchor,anchor_steps=steps,kernel_pre=state,entries_before=between);between=0
                records.append(record)
                if len(records)>limit:raise ValueError('sequence exceeds the boundary limit')
                try:record['returned']=o.complete(record,timeout)
                except Exited:record['terminal']=True;break
                e=record['returned'].get('observed_at_asynchronous_entry')
                if e:
                    anchor,steps,state=o.kernel()
                    if anchor!=record['anchor']:raise ValueError('next kernel entry runs a different task')
                    record['kernel_post']=dict(**state,observed_at=dict(vector_offset=e['pc']-o.vbar,**e),anchor_steps=steps);between=1
                    if r.register('pc')==e['pc']:o.step_over(e['pc'])
                else:pending=record
            else:
                between+=1
                if r.register('pc')==pc:o.step_over(pc)
            r.resume()
    for record in records:
        record.pop('objects');record['pre'].pop('pages')
        if 'returned' in record:record['returned'].pop('pages')
    report=dict(format=SEQUENCE,status='observed',**s.header,boundaries=records,terminal=bool(records and records[-1].get('terminal')),claims=CLAIMS)
    (s.out/'sequence.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

def spec_roots(port):
    if port is None:return {}
    return {r['number']:r['arguments'] for r in json.loads(Path(port).read_text())['roots']}

def user_objects(binding,roots,call,contract,strict=True):
    kinds=roots.get(call['number'])
    if kinds is None:
        if strict:raise ValueError('selected syscall has no root in the slice port')
        return []
    found=[]
    for i,kind in enumerate(kinds):
        if kind=='buffer':
            o=binding['user_objects']['buffer'];found.append(dict(argument=i,address=call[contract['argument_registers'][i]],size=o['bytes'],object_id=o['object_id'],permissions=o['permissions']))
        elif kind not in ('signed','unsigned'):raise ValueError('argument kind has no admitted user object: '+kind)
    # Pointer arguments into one buffer (getresuid's three uid words) admit overlapping
    # objects of the same class. They are one memory: kept separate, a replay would hold
    # several independent copies and lose the aliasing. Overlapping or touching objects of
    # the same class and permissions become one object spanning them all.
    merged=[]
    for o in sorted(found,key=lambda o:o['address']):
        last=merged[-1] if merged else None
        if last and last['object_id']==o['object_id'] and last['permissions']==o['permissions'] and o['address']<=last['address']+last['size']:
            last['size']=max(last['size'],o['address']+o['size']-last['address']);last['arguments'].append(o['argument'])
        else:merged.append(dict(o,arguments=[o['argument']]))
    return merged

def pages(remote,objects):
    starts=sorted({a&~0xfff for o in objects for a in range(o['address'],o['address']+o['size'],0x1000)}|{(o['address']+o['size']-1)&~0xfff for o in objects})
    return [dict(address=p,bytes=remote.read(p,0x1000).hex()) for p in starts]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checkpoint',type=Path,required=True);p.add_argument('--contract',type=Path,required=True);p.add_argument('--binding',type=Path,required=True)
    p.add_argument('--port',type=Path,required=True,help='slice port whose root recipe types the arguments')
    p.add_argument('--kernel-config',type=Path,required=True);g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--select',action='append',help='number=N or REGISTER=VALUE');g.add_argument('--all',action='store_true',help='observe every SVC until the guest stops')
    p.add_argument('--occurrence',type=int,default=1);p.add_argument('--out',type=Path,required=True);p.add_argument('--timeout',type=int,default=120);a=p.parse_args()
    if a.all:
        r=capture_sequence(a.checkpoint,a.contract,a.binding,a.out,a.timeout,a.kernel_config,a.port)
        print(json.dumps(dict(status=r['status'],boundaries=len(r['boundaries']),terminal=r['terminal'],oracle=r['oracle']['result']),indent=2));return
    select={}
    for item in a.select:
        k,_,v=item.partition('=')
        if not v:p.error('--select requires KEY=VALUE')
        select[k]=int(v,0)
    r=capture(a.checkpoint,a.contract,a.binding,select,a.out,a.occurrence,a.timeout,a.kernel_config,a.port)
    print(json.dumps(dict(status=r['status'],call=r['call'],result=r['returned']['result'],oracle=r['oracle']['result']),indent=2))
if __name__=='__main__':main()
