#!/usr/bin/env python3
"""Record the native-backend integration scenario independently under QEMU.

Run the validated lowered mini-OS image's actual instructions, inject explicit
user syscall contexts, and observe results and architecture counter reads. No
application instructions between calls are executed or reconstructed from results.
"""
import argparse
import json
import struct
import subprocess
from pathlib import Path
from gdb_remote import Remote
from svc_boundary import free_port


def record(image, package, out):
    image, package, out = map(lambda p: Path(p).resolve(), (image,package,out))
    manifest = json.loads((image/'manifest.json').read_text())
    package_manifest=json.loads((package/'manifest.json').read_text())
    if manifest['image_sha256']!=package_manifest['source_image_sha256']:
        raise ValueError('oracle image and native package must share the exact image')
    data=(package/'native.bin').read_bytes()
    header=struct.unpack_from('<10Q',data)
    context=struct.unpack_from('<34Q',data,80)
    offset=80+272+520+532584+header[5]*16
    clocks={pc: word for pc,word,_ in struct.iter_unpack('<QII',data[offset:offset+header[6]*16])
            if word&0xfff00000==0xd5300000 and word>>5&65535 in (0xdf01,0xdf02)}
    out.mkdir(parents=True,exist_ok=False)
    port=free_port()
    command=['qemu-system-aarch64','-M','virt-9.2,secure=off,virtualization=off',
             '-cpu','cortex-a53','-accel','tcg','-smp','1','-m','1024M','-nodefaults',
             '-display','none','-monitor','none','-serial','file:'+str(out/'console.txt'),
             '-semihosting-config','enable=off','-device','loader,file='+str(image/'image.elf')+',cpu-num=0',
             '-S','-gdb','tcp:127.0.0.1:'+str(port)]
    counters=[];calls=[]
    with (out/'qemu.stderr.log').open('wb') as err:
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=err)
        try:
            remote=Remote(port,timeout=120)
            pc=context[32]
            remote.breakpoint(pc);remote.resume()
            if remote.wait()!=pc:raise ValueError('initial user context was not reached')
            remote.breakpoint(pc,False);remote.breakpoint(pc+4)
            stop=int(manifest['stop'],16);remote.breakpoint(stop)
            for address in clocks:remote.breakpoint(address)
            def put(name,value):
                number,bits=remote.numbers[name]
                if remote.request('P%x=%s'%(number,value.to_bytes(bits//8,'little').hex()))!='OK':
                    raise ValueError('cannot restore '+name)
            def call(number,*args):
                args=list(args)+[0]*(6-len(args))
                values=list(context[:31]);values[:6]=args;values[8]=number
                for i,value in enumerate(values):put('x%d'%i,value)
                put('cpsr',context[33]);put('sp',context[31]);put('pc',pc)
                remote.resume()
                while True:
                    try:at=remote.wait(30)
                    except TimeoutError:
                        remote.socket.sendall(b'\x03');remote.receive(10)
                        state=remote.registers(['pc','sp','cpsr','x0','x1','x29','x30'])
                        from kernel_boundary_capture import physical
                        physical(remote,True)
                        state['shadow']=list(struct.unpack('<13Q',remote.read(int(manifest['shadow_pa'],16),104)))
                        (out/'failure.json').write_text(json.dumps(state,indent=2)+'\n')
                        raise
                    if at==pc+4:break
                    if at==stop:
                        raise ValueError('QEMU boundary: '+str(remote.registers(['x0','x1','x2','x3'])))
                    if at not in clocks:raise ValueError('unexpected stop at '+hex(at))
                    word=clocks[at];remote.breakpoint(at,False);remote.step()
                    value=remote.register('x%d'%(word&31))
                    counters.append((at,word>>5&65535,value))
                    remote.breakpoint(at);remote.resume()
                result=remote.register('x0')
                calls.append([number,*args,result])
                (out/'progress.json').write_text(json.dumps(dict(calls=len(calls),number=number,result=result,counters=counters))+'\n')
                return result
            for args in ((3,1),(4,2,1),(4,1),(3,2),(3,3),(3,0,6),(3,0,10),(4,1030),(99,1)):
                call(25,*args)
            call(172);call(178)
            mask=call(166,0o77);call(166,0o22);call(166,mask)
            call(65,3,0,1);call(63,99,0,1);call(9999)
            address=call(222,0,4096,3,0x22,(1<<64)-1)
            call(63,3,address,1)
            page=remote.read(address,4096)
            call(226,address,4096,1)
            call(63,3,address,1)
            call(215,address,4096)
        finally:
            process.terminate();process.wait(timeout=10)
    (out/'calls.bin').write_bytes(b''.join(struct.pack('<8Q',*row) for row in calls))
    (out/'counters.bin').write_bytes(b''.join(struct.pack('<3Q',*row) for row in counters))
    (out/'user-page.bin').write_bytes(page)
    report=dict(format='osrec-native-oracle-v1',source_image_sha256=manifest['image_sha256'],
                calls=[dict(number=row[0],arguments=row[1:7],result=row[7]) for row in calls],
                counters=[dict(pc=hex(pc),encoding=hex(key),value=value) for pc,key,value in counters],
                user_page=hex(address))
    (out/'oracle.json').write_text(json.dumps(report,indent=2)+'\n')
    return dict(calls=len(calls),counter_reads=len(counters),user_page=hex(address))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',required=True);p.add_argument('--package',required=True);p.add_argument('--out',required=True)
    a=p.parse_args();print(json.dumps(record(a.image,a.package,a.out)))
