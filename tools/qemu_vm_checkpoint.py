#!/usr/bin/env python3
"""Kernel-independent QMP full-machine capture and fresh-process resume.

Recipes pin immutable boot assets and machine arguments. Writable external disks,
networks and other external services require additional state protocols and are
outside this initial transport contract. No SVC number or kernel layout is used.
"""
import argparse,hashlib,json,os,re,select,shutil,subprocess,time
from pathlib import Path

FORMAT='osrec-qemu-machine-checkpoint-v1'
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):Path(path).write_text(json.dumps(value,indent=2)+'\n')

class Machine:
    def __init__(self,bundle,label,incoming=False,timeout=120,execution_dir=None,observer=(),plugin=None,debug_snapshot=False):
        if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9-]{0,31}',label):raise ValueError('invalid execution label')
        # Observer arguments (e.g. a loopback gdbstub) never alter recipe devices or state.
        if any(not isinstance(x,str) for x in observer) or (observer and (len(observer)!=2 or observer[0]!='-gdb' or not re.fullmatch(r'tcp:127\.0\.0\.1:\d{1,5}',observer[1]))):raise ValueError('unsupported machine observer')
        # A TCG plugin observes execution (instructions, memory accesses); it has no device or state effect.
        if plugin is not None:
            path,arguments=plugin
            if not Path(path).is_absolute() or not Path(path).is_file() or Path(path).suffix not in ('.so','.dylib') or any(not re.fullmatch(r'[a-z_]+',k) or ',' in str(v) for k,v in arguments.items()):raise ValueError('unsupported machine plugin')
        self.bundle=Path(bundle).resolve();self.spec=json.loads((self.bundle/'recipe.json').read_text());self.timeout=timeout
        self.execution=Path(execution_dir).resolve() if execution_dir is not None else self.bundle
        self.log=self.execution/(label+'.console.log')
        if self.log.exists():raise ValueError('execution log already exists; choose a new label or output directory')
        self.console_file=self.log.open('wb');self.events=[];self.buffer=b'';self.serial_buffer=b''
        args=[]
        for arg in self.spec['arguments']:
            for name in self.spec['files']:arg=arg.replace('{'+name+'}',str(self.bundle/'assets'/name))
            args.append(arg)
        self.pipe=self.execution/(label+'.serial')
        for suffix in ('.in','.out'):os.mkfifo(str(self.pipe)+suffix,0o600)
        self.serial_in=os.open(str(self.pipe)+'.in',os.O_RDWR|os.O_NONBLOCK)
        self.serial=os.open(str(self.pipe)+'.out',os.O_RDWR|os.O_NONBLOCK)
        self.command=[self.spec['qemu'],*args,'-S','-qmp','stdio','-chardev','pipe,id=checkpoint-console,path='+str(self.pipe),'-serial','chardev:checkpoint-console','-semihosting-config','enable=off','-only-migratable']
        if incoming:self.command+=['-incoming','defer']
        self.command+=list(observer)
        # A snapshot saved at a debugger stop must not carry the 'debug' run state, which an incoming
        # machine cannot enter; without the global state the destination starts paused.
        if debug_snapshot:self.command+=['-global','migration.store-global-state=off']
        if plugin is not None:self.command+=['-plugin',','.join(['file='+str(plugin[0])]+['%s=%s'%kv for kv in plugin[1].items()])]
        self.error_file=(self.execution/(label+'.stderr.log')).open('wb')
        self.process=subprocess.Popen(self.command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.error_file)
        self.sequence=0
        try:
            if 'QMP' not in self.message():raise ValueError('missing QMP greeting')
            self.request('qmp_capabilities')

        except BaseException:self.close();raise
    def message(self):
        deadline=time.monotonic()+self.timeout
        while b'\n' not in self.buffer:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([self.process.stdout],[],[],remaining)[0]:raise TimeoutError('QMP response timed out')
            chunk=os.read(self.process.stdout.fileno(),65536)
            if not chunk:raise ValueError('QMP closed; see stderr log')
            self.buffer+=chunk
        line,self.buffer=self.buffer.split(b'\n',1);return json.loads(line)
    def request(self,name,args=None):
        self.sequence+=1;record=dict(execute=name,id=self.sequence)
        if args is not None:record['arguments']=args
        self.process.stdin.write(json.dumps(record).encode()+b'\n');self.process.stdin.flush()
        while True:
            result=self.message()
            if result.get('id')==self.sequence:
                self.events.append(dict(request=record,response=result))
                if 'error' in result:raise ValueError('QMP '+name+': '+str(result['error']))
                return result.get('return')
    def wait_line(self,prefix,reject=()):
        deadline=time.monotonic()+self.timeout
        while True:
            while b'\n' in self.serial_buffer:
                line,self.serial_buffer=self.serial_buffer.split(b'\n',1);line=line.decode('utf-8','replace').rstrip('\r')
                if any(line.startswith(p) for p in [self.spec['protocol']['failure_prefix'],*reject]):raise ValueError('unexpected guest output: '+line)
                if line.startswith(prefix):return line
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([self.serial],[],[],min(remaining,1))[0]:
                if remaining<=0:raise TimeoutError('guest console marker timed out')
                if self.process.poll() is not None:raise ValueError('QEMU exited before console marker')
                continue
            chunk=os.read(self.serial,65536)
            if not chunk:raise ValueError('guest console closed')
            self.console_file.write(chunk);self.console_file.flush();self.serial_buffer+=chunk
    def migration_complete(self):
        deadline=time.monotonic()+self.timeout
        while time.monotonic()<deadline:
            status=self.request('query-migrate')
            if status.get('status')=='completed':return status
            if status.get('status') in ('failed','cancelled'):raise ValueError('migration failed: '+str(status))
            time.sleep(.05)
        raise TimeoutError('migration timed out')
    def continue_guest(self):
        self.request('cont');os.write(self.serial_in,self.spec['protocol']['continue_line'].encode())
        line=self.wait_line(self.spec['protocol']['success_prefix'])
        if line!=self.spec['protocol']['expected_success']:raise ValueError('guest state oracle differs: '+line)
        return line
    def close(self):
        if hasattr(self,'serial'):os.close(self.serial);os.close(self.serial_in)
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5)
        self.console_file.close();self.error_file.close()
        write(self.execution/(self.log.stem+'.qmp.json'),self.events)
        for suffix in ('.in','.out'):Path(str(self.pipe)+suffix).unlink(missing_ok=True)
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


def verify(bundle):
    bundle=Path(bundle).resolve();spec=json.loads((bundle/'recipe.json').read_text())
    if spec.get('format')!=FORMAT:raise ValueError('unsupported machine checkpoint recipe')
    if sha(spec['qemu'])!=spec['qemu_sha256']:raise ValueError('QEMU binary identity differs')
    for name,item in spec['files'].items():
        if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*',name) or sha(bundle/'assets'/name)!=item['sha256']:raise ValueError('checkpoint boot asset differs: '+name)
    manifest=bundle/'manifest.json'
    if manifest.exists():
        m=json.loads(manifest.read_text())
        if m['recipe_sha256']!=sha(bundle/'recipe.json') or m['vmstate_sha256']!=sha(bundle/'vmstate.bin'):raise ValueError('machine checkpoint identity differs')
    return spec


def resume(bundle,label='resume',timeout=120,execution_dir=None):
    bundle=Path(bundle).resolve();spec=verify(bundle)
    if execution_dir is not None:Path(execution_dir).mkdir(parents=True,exist_ok=False)
    with Machine(bundle,label,incoming=True,timeout=timeout,execution_dir=execution_dir) as m:
        m.request('migrate-incoming',dict(uri='file:'+str(bundle/'vmstate.bin')));migration=m.migration_complete()
        status=m.request('query-status')
        if status['running']:raise ValueError('incoming checkpoint ran before explicit resume')
        # Restored execution must not reboot or re-enter the readiness phase.
        m.request('cont');os.write(m.serial_in,spec['protocol']['continue_line'].encode())
        result=m.wait_line(spec['protocol']['success_prefix'],spec['protocol'].get('reject_on_resume',[]))
        if result!=spec['protocol']['expected_success']:raise ValueError('resumed guest state oracle differs')
        return dict(status='verified',result=result,migration_status=migration['status'],restored_runstate=status['status'],command=m.command,process_id=m.process.pid)


def capture(recipe,out,timeout=120):
    recipe=Path(recipe).resolve();out=Path(out).resolve()
    if out.exists():raise FileExistsError(out)
    spec=json.loads(recipe.read_text())
    if spec.get('format')!=FORMAT or spec.get('external_state')!='immutable-boot-assets-only':raise ValueError('requires explicit immutable external-state recipe')
    if not isinstance(spec.get('arguments'),list) or not all(isinstance(a,str) for a in spec['arguments']):raise ValueError('requires a QEMU argument list')
    forbidden={'-S','-qmp','-incoming','-serial','-chardev','-daemonize','-nographic','-snapshot','-nic','-net','-netdev','-blockdev','-fsdev','-virtfs','-object','-add-fd','-readconfig','-plugin'}
    if forbidden.intersection(a.split('=',1)[0] for a in spec['arguments']):raise ValueError('recipe overrides controlled checkpoint I/O')
    for i,a in enumerate(spec['arguments']):
        if a=='-drive' and (i+1==len(spec['arguments']) or 'readonly=on' not in spec['arguments'][i+1]):raise ValueError('checkpoint requires immutable block devices')
    if '-nodefaults' not in spec['arguments']:raise ValueError('recipe must disable implicit devices and network with -nodefaults')
    protocol=spec.get('protocol',{})
    for key in ('ready_prefix','success_prefix','failure_prefix','expected_success','continue_line'):
        if not isinstance(protocol.get(key),str) or not protocol[key]:raise ValueError('requires a nonempty console protocol: '+key)
    if not protocol['expected_success'].startswith(protocol['success_prefix']) or len(protocol['continue_line'].encode())>128 or not protocol['continue_line'].endswith('\n'):
        raise ValueError('invalid console continuation/oracle')
    qemu=shutil.which(spec['qemu'])
    if qemu is None:raise ValueError('QEMU executable missing')
    spec['qemu']=str(Path(qemu).resolve());spec['qemu_sha256']=sha(spec['qemu'])
    out.mkdir(parents=True);(out/'assets').mkdir()
    for name,item in spec['files'].items():
        if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*',name):raise ValueError('invalid boot asset name')
        source=Path(item['path']);source=source if source.is_absolute() else recipe.parent/source
        if sha(source)!=item['sha256']:raise ValueError('boot asset identity differs: '+name)
        shutil.copyfile(source,out/'assets'/name);item['path']='assets/'+name
    write(out/'recipe.json',spec);verify(out)
    with Machine(out,'source',timeout=timeout) as m:
        m.request('cont');ready=m.wait_line(spec['protocol']['ready_prefix']);m.request('stop')
        stopped=m.request('query-status');assert not stopped['running']
        m.request('migrate',dict(uri='file:'+str(out/'vmstate.bin')));migration=m.migration_complete()
        baseline=m.continue_guest();source_command=m.command;source_pid=m.process.pid
    result=dict(format=FORMAT,status='captured',recipe_sha256=sha(out/'recipe.json'),vmstate_sha256=sha(out/'vmstate.bin'),vmstate_bytes=(out/'vmstate.bin').stat().st_size,
        qemu_version=subprocess.run([spec['qemu'],'--version'],check=True,capture_output=True,text=True).stdout,
        ready=ready,baseline_result=baseline,source_process_id=source_pid,stopped_state=stopped,migration_status=migration['status'],source_command=source_command,
        kernel_agnostic=True,syscall_abi_intercepted=False,state_scope='full QEMU machine CPU/RAM/migratable devices; immutable external assets pinned separately',
        minimality_proven=False,standalone_reduced_executable=False)
    write(out/'manifest.json',result)
    result['resumes']=[resume(out,'resume-'+str(i),timeout) for i in range(2)]
    result['status']='verified';write(out/'manifest.json',result);verify(out);return result


def main():
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True);g.add_argument('--recipe',type=Path);g.add_argument('--resume',type=Path)
    p.add_argument('--out',type=Path);p.add_argument('--label');p.add_argument('--timeout',type=int,default=120);a=p.parse_args()
    if a.recipe:
        if a.out is None:p.error('--recipe requires --out')
        r=capture(a.recipe,a.out,a.timeout)
    else:
        import uuid
        r=resume(a.resume,a.label or 'resume-'+uuid.uuid4().hex[:8],a.timeout,a.out)
    print(json.dumps(r,indent=2))
if __name__=='__main__':main()
