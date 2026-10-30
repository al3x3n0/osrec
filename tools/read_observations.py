"""Shared framed read-boundary transport for host, QEMU and board adapters."""
import hashlib
import json
import struct

READ_SITE = 0x535244


def context_hash(entry, calls, identity):
    context = {"entry":entry,"calls":calls,"kernel":identity["kernel"]}
    return hashlib.sha256(json.dumps(context,sort_keys=True,separators=(",",":")).encode()).hexdigest()


def backend_calls(entry, calls, objects):
    process = objects[entry["roots"]["current_process"]["object"]]["fields"]
    memory_id = process["memory"]["object"]
    for index, call in enumerate(calls):
        ref = call["buffer"]
        if not call["count"] or not ref["object"] or call["count"] > 8-ref["offset"]:
            continue
        file_ref = process.get("fd"+str(call["fd"]),{"object":0})
        file_id = file_ref["object"]
        fd = objects[file_id]["fields"]["backend_fd"] if file_id else -1
        if ref["object"] != memory_id:
            raise ValueError("backend pointer does not belong to process memory")
        yield index, call, file_id, fd


def frame(kind, site, payload):
    return struct.pack("<III",kind,site,len(payload))+payload


def encode(context, reads):
    result = bytearray(b"OSRC\x01\0\0\0"+frame(1,0,context.encode()))
    for index, call, fd, outcome in reads:
        data = bytes.fromhex(outcome["payload"])
        values = (index,fd & 0xffffffff,call["count"],call["buffer"]["object"],call["buffer"]["offset"],
                  outcome["result"] & 0xffffffff,outcome["errno"],len(data))
        result.extend(frame(3,READ_SITE,struct.pack("<8Q",*values)+data))
    result.extend(frame(5,0,b""))
    return bytes(result)


def decode(raw, context, entry, calls, objects):
    if len(raw)>65536 or raw[:8]!=b"OSRC\x01\0\0\0":
        raise ValueError("invalid bounded read-observation stream")
    position=8
    def take():
        nonlocal position
        if len(raw)-position<12: raise ValueError("unfinished read-observation stream")
        kind,site,size=struct.unpack_from("<III",raw,position); position+=12
        if size>len(raw)-position: raise ValueError("truncated read-observation payload")
        payload=raw[position:position+size]; position+=size
        return kind,site,payload
    if take()!=(1,0,context.encode()): raise ValueError("read observations belong to a different entry/kernel/call sequence")
    result=[{"result":0,"errno":0,"payload":""} for _ in calls]
    for index,call,_,fd in backend_calls(entry,calls,objects):
        kind,site,payload=take()
        if kind!=3 or site!=READ_SITE or len(payload)<64: raise ValueError("missing or reordered read boundary")
        values=struct.unpack_from("<8Q",payload)
        number,mapped,count,obj,offset,bits,error,size=values
        if (number,mapped,count,obj,offset)!=(index,fd&0xffffffff,call["count"],call["buffer"]["object"],call["buffer"]["offset"]):
            raise ValueError("recorded read arguments disagree with the checkpoint")
        if bits>0xffffffff or error>4095 or size>64 or len(payload)!=64+size:
            raise ValueError("invalid read observation encoding")
        returned=bits if bits<0x80000000 else bits-0x100000000
        if returned<-1 or returned>min(call["count"],8) or size!=max(returned,0) or (returned<0 and not error) or (returned>=0 and error):
            raise ValueError("inconsistent read observation result/errno/bytes")
        if fd<0 and (returned,error,size)!=(-1,9,0): raise ValueError("invalid descriptor must report EBADF")
        result[index]={"result":returned,"errno":error,"payload":payload[64:].hex()}
    if take()!=(5,0,b"") or position!=len(raw): raise ValueError("extra or unfinished read observations")
    return result
