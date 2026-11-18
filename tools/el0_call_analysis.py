"""Prove private call copies can replace RET with a direct continuation.

No trace targets are used. Original functions and indirect entry points remain
available. Only direct BL sites enter copies whose reachable instructions are
known to preserve/restore X30. Closed copies cannot leave through a context
gateway; partial leaf copies rejoin original code before an unproven operation.
Frame summaries track actual register and memory effects, without
assuming ABI preservation or that unknown pointers cannot alias the stack.
"""
from el0_flat_lower import *
from el0_hardware import system_path
from collections import deque
from dataclasses import dataclass

MASK=(1<<64)-1
PARTIAL_COPY_LIMIT=128
PARTIAL_SCAN_LIMIT=512


def direct_call_site(pc,descriptions):
    # An observation hook performs its checks before executing the original
    # BL. Specializing that BL leaves the hook and its ordering in place.
    entry=descriptions.get(pc)
    return entry is None or entry[0].kind==OBSERVE and not entry[1]


def branch_target(pc,word):
    if word&0xfc000000 in (0x14000000,0x94000000):
        return (pc+4*sign(word&0x3ffffff,26))&MASK
    bits=14 if word&0x7e000000==0x36000000 else 19
    return (pc+4*sign(word>>5&((1<<bits)-1),bits))&MASK


def writes_lr(word):
    op=decode(word)
    if op.kind==MEMORY:
        return bool(op.info&WB and op.info&31==30 or
                    op.info&LOAD and not op.info&HINT and not word&(1<<26) and
                    (word&31==30 or op.info&PAIR and word>>10&31==30))
    # Conservative for SIMD, stores of system registers and discarded results.
    # Exclusive status destinations are excluded by the group/gateway checks.
    return word&31==30


def leaf_body(start,end,words,descriptions,groups=(),limit=32):
    """Reachable CFG is closed, X30-preserving and ends only at RET X30."""
    pending=[start];body=set();returned=False
    while pending:
        pc=pending.pop()
        if pc in body:continue
        if not start<=pc<end or pc not in words or pc in groups or len(body)>=limit:return None
        body.add(pc);word=words[pc];entry=descriptions.get(pc)
        if word&0xfffffc1f==0xd65f0000:
            if entry is not None and (entry[0].kind!=INDIRECT or entry[1]):return None
            if word>>5&31!=30:return None
            returned=True;continue
        if entry is not None:
            op,metadata=entry
            if op.kind!=SYSTEM or not system_path(word,metadata):return None
        elif decode(word).kind==SYSTEM:return None
        if word&0xfc000000==0x94000000:return None
        if word&0xfc000000==0x14000000:
            pending.append(branch_target(pc,word));continue
        if word&0xff000010==0x54000000 or word&0x7e000000 in (0x34000000,0x36000000):
            pending.extend((branch_target(pc,word),pc+4));continue
        if decode(word).kind in (INDIRECT,SVC,BOUNDARY,UNSUPPORTED) or writes_lr(word):return None
        pending.append(pc+4)
    return tuple(sorted(body)) if returned else None


def analyze_calls(words,descriptions,groups,extents,limit=100000):
    bodies={}
    for start,end in extents:
        body=leaf_body(start,end,words,descriptions,groups)
        if body:bodies[start]=body
    result={};size=0
    for pc,word in sorted(words.items()):
        if word&0xfc000000!=0x94000000 or not direct_call_site(pc,descriptions):continue
        target=branch_target(pc,word);body=bodies.get(target)
        if not body or pc+4 not in words or size+len(body)>limit:continue
        result[pc]=body;size+=len(body)
    return result


@dataclass
class FrameProof:
    body:tuple
    registers:tuple
    stores:tuple
    unknown_store:bool
    depth:int


def frame_body(start,end,words,descriptions,groups,callees,limit=64):
    """Track symbolic entry registers, exact SP offsets and saved stack values.

    Unknown stores invalidate all saved slots. Callee effects are substituted
    at each direct call, without assuming any ABI register preservation or
    stack isolation. Only summaries with balanced SP and original X30 return.
    """
    initial=tuple([('in',r) for r in range(31)]+[('sp',0)])
    states={start:(initial,{})};queue=deque([start]);queued={start};body=set()
    stores=set();unknown_store=False;returned={};depth=0
    def put(pc,regs,slots):
        if not start<=pc<end or pc not in words:return False
        old=states.get(pc)
        if old is None:new=(tuple(regs),dict(slots))
        else:
            new=(tuple(a if a==b else None for a,b in zip(old[0],regs)),
                 {k:v for k,v in old[1].items() if k in slots and slots[k]==v})
        if new!=old:
            states[pc]=new
            if pc not in queued:queue.append(pc);queued.add(pc)
        return True
    def invalidate(slots,offset,size):
        for (at,n) in list(slots):
            if at<offset+size and offset<at+n:del slots[at,n]
    while queue:
        pc=queue.popleft();queued.remove(pc)
        if pc in groups or pc not in body and len(body)>=limit:return None
        body.add(pc);w=words[pc];op=decode(w);entry=descriptions.get(pc)
        regs=list(states[pc][0]);slots=dict(states[pc][1]);rd=w&31;rn=w>>5&31
        if w&0xfffffc1f==0xd65f0000:
            if rn!=30 or entry is not None and (entry[0].kind!=INDIRECT or entry[1]):return None
            if regs[30]!=('in',30) or regs[31]!=('sp',0):return None
            returned[pc]=tuple(regs);continue
        if entry is not None:
            if entry[0].kind!=SYSTEM or not system_path(w,entry[1]):return None
            sp=regs[31]
            if sp is None or sp[0]!='sp':return None
            # The emitted inline shadow helper saves two scratch GPRs below
            # live SP. Include those actual stores in the alias summary too.
            scratch=sp[1]-16;invalidate(slots,scratch,16);stores.add((scratch,16))
        elif op.kind==SYSTEM:return None
        if w&0xfc000000==0x94000000:
            callee=callees.get(branch_target(pc,w))
            if callee is None or regs[31] is None or regs[31][0]!='sp':return None
            depth=max(depth,callee.depth+1);sp=regs[31][1]
            if callee.unknown_store:slots.clear();unknown_store=True
            for offset,size in callee.stores:
                offset+=sp;invalidate(slots,offset,size);stores.add((offset,size))
            incoming=regs[:];incoming[30]=('pc',pc+4)
            def substitute(value):
                if value is None:return None
                if value[0]=='in':return incoming[value[1]]
                if value[0]=='sp':return ('sp',sp+value[1])
                return value
            regs=[substitute(value) for value in callee.registers]
        elif w&0xfc000000==0x14000000:
            if not put(branch_target(pc,w),regs,slots):return None
            continue
        elif w&0xff000010==0x54000000 or w&0x7e000000 in (0x34000000,0x36000000):
            if not put(branch_target(pc,w),regs,slots) or not put(pc+4,regs,slots):return None
            continue
        elif op.kind==MEMORY:
            info=op.info;size=1<<(info>>15&7);pair=bool(info&PAIR);vector=bool(w&(1<<26))
            base=regs[rn];offset=None
            if base is not None and base[0]=='sp' and not info&(REGISTER|(1<<44)):
                offset=base[1]+(0 if info&POST else op.imm)
            destinations=[rd,w>>10&31] if pair else [rd]
            if not info&HINT:
                if info&LOAD:
                    values=[slots.get((offset+i*size,size)) if offset is not None and size==8 and not vector else None
                            for i in range(len(destinations))]
                    if not vector:
                        for dest,value in zip(destinations,values):
                            if dest!=31:regs[dest]=value
                else:
                    if offset is None:slots.clear();unknown_store=True
                    else:
                        total=size*len(destinations);invalidate(slots,offset,total);stores.add((offset,total))
                        if size==8 and not vector:
                            for i,src in enumerate(destinations):
                                if src!=31 and regs[src] is not None:slots[offset+i*size,size]=regs[src]
            if info&WB:
                regs[rn]=('sp',base[1]+op.imm) if base is not None and base[0]=='sp' else None
        elif w&0xff800000 in (0x91000000,0xd1000000):
            value=regs[rn];imm=(w>>10&4095)<<(12 if w&(1<<22) else 0)
            if w&(1<<30):imm=-imm
            regs[rd]=('sp',value[1]+imm) if value is not None and value[0]=='sp' else value if not imm else None
        elif w&0xffe0ffe0==0xaa0003e0:
            if rd!=31:regs[rd]=regs[w>>16&31] if w>>16&31!=31 else None
        elif op.kind in (INDIRECT,SVC,BOUNDARY,UNSUPPORTED):return None
        else:
            if rd!=31:regs[rd]=None
            if op.kind==STACK and op.info&DST_SP:regs[31]=None
            if w&0x1f800000==0x12000000 and rd==31 and w>>29&3!=3:regs[31]=None
        if regs[31] is None or regs[31][0]!='sp' or abs(regs[31][1])>1048576:return None
        if len(slots)>128 or len(stores)>256:return None
        if not put(pc+4,regs,slots):return None
    if not returned:return None
    values=list(returned.values());registers=tuple(v if all(row[i]==v for row in values) else None for i,v in enumerate(values[0]))
    return FrameProof(tuple(sorted(body)),registers,tuple(sorted(stores)),unknown_store,depth)


@dataclass
class CallPlan:
    roots:dict
    nodes:dict
    returns:dict
    children:dict
    summaries:dict
    partial:dict


@dataclass
class PartialProof:
    body:tuple
    exits:tuple


def partial_leaf_body(start,end,words,descriptions,groups=(),limit=64,scan_limit=None):
    """Copy an X30-preserving prefix; unproven edges resume original code.

    Unlike a closed frame summary, this proof cannot be used by a parent call.
    It admits no link-writing instruction, context gateway or atomic group.
    Every copied RET therefore still has the direct caller's original X30.
    Unsupported paths leave the copy before executing their first instruction.
    A larger scan may discover a small return-reaching subgraph after pruning;
    the retained body still obeys limit and an oversized result falls back to
    the original bounded scan.
    """
    scan_limit=limit if scan_limit is None else max(limit,scan_limit)
    pending=deque([start]);seen=set();body=set();returned=False
    while pending:
        pc=pending.popleft()
        if pc in seen:continue
        seen.add(pc)
        if not start<=pc<end or pc not in words or pc in groups or len(body)>=scan_limit:continue
        w=words[pc];entry=descriptions.get(pc);op=decode(w)
        if w&0xfffffc1f==0xd65f0000:
            if w>>5&31!=30 or entry is not None and (entry[0].kind!=INDIRECT or entry[1]):continue
            body.add(pc);returned=True;continue
        if entry is not None:
            if entry[0].kind!=SYSTEM or not system_path(w,entry[1]):continue
        elif op.kind==SYSTEM:continue
        if w&0xfc000000==0x94000000:continue
        if w&0xfc000000==0x14000000:
            body.add(pc);pending.append(branch_target(pc,w));continue
        if w&0xff000010==0x54000000 or w&0x7e000000 in (0x34000000,0x36000000):
            body.add(pc);pending.extend((pc+4,branch_target(pc,w)));continue
        if op.kind in (INDIRECT,SVC,BOUNDARY,UNSUPPORTED) or writes_lr(w):continue
        body.add(pc);pending.append(pc+4)
    if not returned or start not in body:return None
    def successors(pc):
        w=words[pc]
        if w&0xfffffc1f==0xd65f0000:return ()
        if w&0xfc000000==0x14000000:return (branch_target(pc,w),)
        elif w&0xff000010==0x54000000 or w&0x7e000000 in (0x34000000,0x36000000):
            return pc+4,branch_target(pc,w)
        return (pc+4,)
    # Copy only nodes that can still reach a copied RET. A slow-only suffix
    # cannot eliminate a return adapter: rejoin original code before its first
    # instruction instead. Reverse reachability retains loops with a return
    # edge and removes entire components that have no copied return path.
    reverse={pc:[] for pc in body};live=set()
    for pc in body:
        if words[pc]&0xfffffc1f==0xd65f0000:live.add(pc)
        for dest in successors(pc):
            if dest in body:reverse[dest].append(pc)
    pending=list(live)
    while pending:
        for parent in reverse[pending.pop()]:
            if parent not in live:live.add(parent);pending.append(parent)
    if start not in live:return None
    body=live
    if len(body)>limit:
        # Exploring more code may expose additional returns whose combined
        # paths exceed the per-copy cap. Retain the bounded-prefix proof then.
        return partial_leaf_body(start,end,words,descriptions,groups,limit)
    exits={dest for pc in body for dest in successors(pc) if dest not in body}
    return PartialProof(tuple(sorted(body)),tuple(sorted(exits)))


def analyze_call_trees(words,descriptions,groups,extents,limit=100000,max_depth=3):
    extents=list(extents);summaries={}
    # A new pass can depend only on summaries from earlier passes: recursive
    # call cycles never bootstrap a proof and the call-tree depth is bounded.
    for level in range(max_depth+1):
        admitted={}
        for start,end in extents:
            if start in summaries:continue
            proof=frame_body(start,end,words,descriptions,groups,summaries)
            if proof is not None and proof.depth<=max_depth:admitted[start]=proof
        if not admitted:break
        summaries.update(admitted)
    legacy=analyze_calls(words,descriptions,groups,extents,limit)
    bodies={body[0]:body for body in legacy.values()}
    bodies.update({start:proof.body for start,proof in summaries.items()})
    partial={}
    for start,end in extents:
        if start in bodies:continue
        proof=partial_leaf_body(start,end,words,descriptions,groups,
                                limit=PARTIAL_COPY_LIMIT,scan_limit=PARTIAL_SCAN_LIMIT)
        if proof:
            partial[start]=proof;bodies[start]=proof.body
    roots={};nodes={};returns={};children={};next_id=1<<64;size=0
    def cost(entry):
        body=bodies[entry]
        return len(body)+sum(cost(branch_target(pc,words[pc])) for pc in body if words[pc]&0xfc000000==0x94000000)
    def add(context,entry,parent,continuation):
        nonlocal next_id
        nodes[context]=bodies[entry];returns[context]=(parent,continuation)
        for pc in bodies[entry]:
            if words[pc]&0xfc000000!=0x94000000:continue
            child=next_id;next_id+=1;children[context,pc]=child
            add(child,branch_target(pc,words[pc]),context,pc+4)
    candidates=[pc for pc,w in sorted(words.items()) if w&0xfc000000==0x94000000 and
                direct_call_site(pc,descriptions) and pc+4 in words and branch_target(pc,w) in bodies]
    # Keep the established closed copies first. Partial prefixes have no nested
    # calls, so taking smaller bodies first maximizes the number of admitted
    # direct call sites in the remaining budget. Ties retain source-PC order;
    # no execution counts, recorded targets or branch outcomes rank a copy.
    def rank(pc):
        entry=branch_target(pc,words[pc])
        if pc in legacy:return 0,0,pc
        if entry in partial:return 2,len(bodies[entry]),pc
        return 1,0,pc
    for pc in sorted(candidates,key=rank):
        entry=branch_target(pc,words[pc]);required=cost(entry)
        if size+required>limit:continue
        size+=required;roots[pc]=bodies[entry];add(pc,entry,None,pc+4)
    return CallPlan(roots,nodes,returns,children,summaries,partial)


def write_call_trees(stream,plan,words,descriptions,original_label,constant,control,page_offsets=False):
    """Emit the proven trees; nested returns must stay in the parent copy."""
    def label(context,pc):return '.Lclone%x_p%x'%(context,pc)
    for context,body in plan.nodes.items():
        selected=set(body)
        target=lambda dest:label(context,dest) if dest in selected else original_label(dest)
        for pc in body:
            w=words[pc];stream.write(label(context,pc)+':\n')
            if w&0xfffffc1f==0xd65f0000:
                parent,continuation=plan.returns[context]
                stream.write('    b %s\n'%(original_label(continuation) if parent is None else label(parent,continuation)))
            elif w&0xfc000000==0x94000000:
                child=plan.children[context,pc]
                stream.write(constant(30,pc+4)+'    b %s\n'%label(child,branch_target(pc,w)))
            elif pc in descriptions:stream.write(system_path(w,descriptions[pc][2],page_offsets=page_offsets))
            elif w&0x9f000000 in (0x10000000,0x90000000):
                delta=sign((w>>29&3)|((w>>5&0x7ffff)<<2),21)
                value=((pc&~4095)+(delta<<12)) if w&(1<<31) else pc+delta
                stream.write(constant(w&31,value&MASK))
            else:stream.write(control(pc,w,target,False))
            if w&0xfffffc1f!=0xd65f0000 and w&0xfc000000!=0x14000000 and pc+4 not in selected:
                stream.write('    b %s\n'%original_label(pc+4))
