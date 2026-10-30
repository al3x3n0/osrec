#!/usr/bin/env python3
"""Draft live-kernel binding paths from a slice checkpoint schema and kernel BTF.

The schema's own reference edges (self/context references and pointer-element
pools) are followed through same-named kernel members, starting at the anchor
record. Persistent leaves are matched by member name, unwrapped through
single-member records (kuid_t.val, atomic_long_t.counter) and width-checked.
The draft is syntactic: every row is a proposal for review, and fields with no
same-named kernel member are reported as model-only. Correspondence of meaning
(projections, derived predicates, page-cache contents) is never inferred.
"""
import argparse,json,re
from pathlib import Path
from kernel_btf import BTF

FORMAT='osrec-live-binding-draft-v1'
SIZES={'int':4,'unsigned int':4,'int32_t':4,'uint32_t':4,'int64_t':8,'uint64_t':8,'long':8,'unsigned long':8,'uint8_t':1,'_Bool':1,'short':2,'uint16_t':2}

def schema_size(c_type):
    m=re.fullmatch(r'(.+?)(\[(\d+)\])?',c_type.strip());return SIZES.get(m.group(1).strip()),bool(m.group(2))

def kind(btf,i):return btf.types[btf.strip(i)]
def pointee_record(btf,i,depth=1):
    t=kind(btf,i)
    for _ in range(depth):
        if t['kind']!='ptr':return None
        t=kind(btf,t['value'])
    return t['name'] if t['kind']=='struct' else None

def unwrap(btf,i,path):
    """Descend single-member records to a scalar, e.g. kuid_t -> .val."""
    for _ in range(4):
        t=kind(btf,i)
        if t['kind'] not in ('struct','union') or len(t['members'])!=1:return i,path
        name,i,_,_=t['members'][0];path+='.'+name
    return i,path

class Draft:
    def __init__(self,btf,policy):
        self.btf=btf;self.fields=policy['fields'];self.rows={};self.objects={};self.pools={}
    def node(self,name):
        n=self.fields[name.split('.')[0]]
        for p in name.split('.')[1:]:n=n['members'][p]
        return n
    def place(self,name,record,prefix,deref,via):
        """Record one kernel access route for a schema object; several routes mean ambiguity."""
        routes=self.objects.setdefault(name,[])
        if any(r['prefix']==prefix for r in routes):return False
        routes.append(dict(record=record,prefix=prefix,deref=deref,via=via));return True
    def member(self,route,name):return route['prefix']+('->' if route['deref'] else '.')+name
    def walk(self,anchor_name,anchor_record):
        target=self.fields[anchor_name]
        if target.get('policy')!='self_reference':raise ValueError('anchor is not a schema self-reference')
        self.place(target['target'],anchor_record,'',False,'anchor');queue=[target['target']]
        while queue:
            name=queue.pop(0)
            for route in list(self.objects[name]):
                record=self.btf.struct(route['record'])
                for member,n in self.node(name).get('members',{}).items():
                    try:_,kernel=self.btf.member(record,member)
                    except KeyError:continue
                    path=self.member(route,member);child=name+'.'+member
                    if n['policy']=='self_reference':targets=[n['target']]
                    elif n['policy']=='context_reference':targets=n['targets']
                    elif n['policy']=='members' and kind(self.btf,kernel)['kind']=='struct':
                        if self.place(child,kind(self.btf,kernel)['name'],path,False,'embedded'):queue.append(child)
                        continue
                    elif n['policy']=='elements' and n['element']['policy']=='context_reference':
                        pool=n['element']['targets'][0].split('[')[0];record_name=pointee_record(self.btf,kernel,2)
                        if record_name:
                            entry=self.pools.setdefault(pool,dict(record=record_name,slots=child,tables=[]))
                            if all(t['path']!=path for t in entry['tables']):entry['tables'].append(dict(path=path,route=route['via']))
                        continue
                    else:continue
                    record_name=pointee_record(self.btf,kernel)
                    if not record_name:continue
                    for t in targets:
                        if self.place(t,record_name,path,True,'reference '+child):queue.append(t)
        for pool,p in self.pools.items():self.place(pool,p['record'],'',False,'pool element')
        # One schema object reached both through a reference and as an embedded member:
        # the retained code follows the reference, and a live pointer-equality check decides.
        self.invariants=[]
        for name,routes in self.objects.items():
            refs=[r for r in routes if r['via'].startswith('reference ')];embedded=[r for r in routes if r['via']=='embedded']
            for r in refs:
                for e in embedded:self.invariants.append(dict(pointer=r['prefix'],object=e['prefix'],field=r['via'][len('reference '):],target=name))
    def leaves(self):
        for name,routes in self.objects.items():
            n=self.node(name)
            members=n['element']['members'] if n['policy']=='elements' else n.get('members',{})
            for member,leaf in members.items():
                if leaf['policy']!='persist':continue
                field=(name+'[]' if n['policy']=='elements' else name)+'.'+member;size,array=schema_size(leaf['type']);candidates=[]
                for route in routes:
                    try:_,kernel=self.btf.member(self.btf.struct(route['record']),member)
                    except KeyError:continue
                    path=self.member(route,member);t=kind(self.btf,kernel)
                    if array and t['kind'] in ('ptr','array'):kernel=t['value'] if t['kind']=='ptr' else t['element'];path+='[0]'
                    kernel,path=unwrap(self.btf,kernel,path)
                    if kind(self.btf,kernel)['kind'] not in ('int','enum'):continue
                    width=self.btf.sizeof(kernel);candidates.append(dict(path=path,route=route['via'],kernel_bytes=width,width_matches=width==size))
                status='model-only' if not candidates else 'proposed' if len(candidates)==1 else 'ambiguous'
                row=dict(status=status,schema_type=leaf['type'],candidates=candidates)
                if status=='ambiguous' and any(i['target']==name for i in self.invariants):
                    row['resolution']='embedded-pointer invariant';row['preferred']=[c['path'] for c in candidates if c['route'].startswith('reference ')]
                self.rows[field]=row
        for name in self.fields:
            n=self.fields[name]
            if n['policy']=='members' and name not in self.objects:
                for member,leaf in n['members'].items():
                    if leaf['policy']=='persist':self.rows[name+'.'+member]=dict(status='unreachable',schema_type=leaf['type'],candidates=[])

def compare(rows,binding):
    """Score the draft against a reviewed binding (scalars and pooled members)."""
    reviewed={f:v['path'] for f,v in binding['scalars'].items()}
    pool=binding['descriptors']['pool']
    reviewed|={pool+'[].'+m:v['path'] for m,v in binding['descriptors']['members'].items()}
    out=dict(agree=[],differs=[],reviewed_only=[],draft_only=[])
    for field,path in reviewed.items():
        key=re.sub(r'\[\d+\]$','',field) if field not in rows else field
        row=rows.get(key)
        if not row or not row['candidates']:out['reviewed_only'].append(field)
        elif any(c['path']==path for c in row['candidates']):out['agree'].append(field)
        else:out['differs'].append(dict(field=field,reviewed=path,draft=[c['path'] for c in row['candidates']]))
    keys={re.sub(r'\[\d+\]$','',f) for f in reviewed}|set(reviewed)
    out['draft_only']=sorted(f for f,r in rows.items() if r['candidates'] and f not in keys)
    out['preferred_agree']=sorted(f for f in out['agree'] if rows.get(re.sub(r'\[\d+\]$','',f),{}).get('preferred',[reviewed[f]])[0]==reviewed[f])
    return out

def draft(policy,kernel,anchor,record,reviewed=None):
    btf=BTF(Path(kernel).read_bytes());d=Draft(btf,json.loads(Path(policy).read_text()));d.walk(anchor,record);d.leaves()
    report=dict(format=FORMAT,anchor=dict(name=anchor,record=record),objects=d.objects,pools=d.pools,invariants=d.invariants,fields=d.rows,
        counts={s:sum(r['status']==s for r in d.rows.values()) for s in ('proposed','ambiguous','model-only','unreachable')},
        scope='syntactic proposals; review required for every row and for all semantic projections')
    if reviewed:
        b=json.loads(Path(reviewed).read_text());c=compare(d.rows,b);pool=d.pools.get(b['descriptors']['pool'],{})
        c['descriptor_table']=dict(reviewed=b['descriptors']['table'],draft=[t['path'] for t in pool.get('tables',[])])
        c['invariants']=dict(reviewed=[(e['pointer'],e['object']) for e in b.get('embedded',[])],draft=[(i['pointer'],i['object']) for i in d.invariants])
        report['against_reviewed']=c
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--policy',type=Path,required=True);p.add_argument('--kernel-image',type=Path,required=True)
    p.add_argument('--anchor',default='current');p.add_argument('--anchor-record',default='task_struct')
    p.add_argument('--reviewed',type=Path,help='reviewed binding to score the draft against');p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    r=draft(a.policy,a.kernel_image,a.anchor,a.anchor_record,a.reviewed)
    a.out.write_text(json.dumps(r,indent=2)+'\n')
    summary=dict(counts=r['counts'])
    if 'against_reviewed' in r:summary['against_reviewed']={k:len(v) for k,v in r['against_reviewed'].items()}
    print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
