"""Empty-list walks: list heads a reviewed contract holds empty at every boundary the slice replays.

An empty `struct list_head` is linked to itself: `head->next == head->prev == head`. A list walk
(`list_for_each_entry`, `list_for_each_entry_safe` and the plist forms over them) starts at
`container_of(head->next, T, member)` and stops when `&pos->member == head`, so over an empty head it
stops at once: `pos` is never an object, only an address whose `member` is the head again.

A contract (`empty_lists` in the analysis contracts) names the heads by object path, with `[]` for
any index (`argument:ctx->__futex_data.queues[].chain.node_list`). For those heads the analysis:

- loads `H.next` and `H.prev` as `H` (the self-link), reading the link as entry state the binding
  declares model state;
- forms `container_of(H, T, m)` as a sentinel `list-head:H#m`, not an object: `&sentinel->m` is `H`,
  and any other access through it blocks;
- decides a for loop never runs when its condition is `!(&pos->m == HEAD)` and its initializer sets
  `pos` from `HEAD->next` with the same side-effect-free HEAD expression: both evaluate HEAD in the same
  state, so `&pos->m` is HEAD's value and the condition is false on entry;
- rejects the contract (a blocker) when the call stores to such a head or the object holding it.

The contract's validation is outside the analysis: the slice never links such a head (its initializer
self-links it, and the code that would link one is a faulting model), and the live binding requires
every live head empty.
"""
import re

SENTINEL='list-head:'
FIELDS=re.compile(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*')

def normalized(path):
    """Index-free spelling. After the root, `->m` through a member's address (`&hb->chain` then `->node_list`) is the
    member `.m`: the contract's heads are members of embedded records, so no pointer step can spell the same path."""
    root=re.match(r'(?:global:(?:tu[0-9]+:)?|argument:ctx->)',path)
    head,rest=(path[:root.end()],path[root.end():]) if root else ('',path)
    return head+re.sub(r'\[\d+\]','[]',rest).replace('->','.')

def validate(items):
    heads=set()
    for item in items or []:
        if (not isinstance(item,dict) or set(item)!={'heads','reason','validated_by'} or not isinstance(item['heads'],list) or not item['heads'] or
                any(not isinstance(h,str) or not re.fullmatch(r'(?:global:|argument:ctx->)[A-Za-z_][\w.\[\]>-]*',h) for h in item['heads']) or not item['reason'] or not item['validated_by']):
            raise ValueError('empty list contract requires heads, reason and validated_by')
        heads|=set(item['heads'])
    return heads

def head(heads,path):
    """Is `path` (an object path) one of the contract's list heads?"""
    return isinstance(path,str) and normalized(path) in heads

def link(heads,path):
    """The head whose next/prev link `path` names, or None."""
    # `H.next` through the head object, `H->next` through its address (`&...->node_list` then `->next`).
    for suffix in ('.next','.prev','->next','->prev'):
        if path.endswith(suffix) and head(heads,path[:-len(suffix)]):return path[:-len(suffix)]
    return None

def sentinel(path,fields):return SENTINEL+path+'#'+fields

def member(path):
    """`&sentinel->m` is the head; another member chain through a sentinel stays a sentinel path."""
    if SENTINEL not in path:return path
    m=re.fullmatch(re.escape(SENTINEL)+r'(.+)#('+FIELDS.pattern+r')->('+FIELDS.pattern+r')',path)
    if m and m[3]==m[2]:return m[1]
    return path

def is_sentinel(path):return SENTINEL in path

WRAPPERS=('ParenExpr','ImplicitCastExpr','ConstantExpr')
def strip(node):
    while node.get('kind') in WRAPPERS and len(node.get('inner',[]))==1:node=node['inner'][0]
    return node

def same(a,b):
    """Structural equality of two expressions (declarations by identity, no locations)."""
    a=strip(a);b=strip(b)
    if a.get('kind')!=b.get('kind'):return False
    for k in ('opcode','name','isArrow','castKind','value'):
        if a.get(k)!=b.get(k):return False
    if a.get('kind')=='DeclRefExpr' and a.get('referencedDecl',{}).get('id')!=b.get('referencedDecl',{}).get('id'):return False
    x=[c for c in a.get('inner',[]) if c.get('kind')];y=[c for c in b.get('inner',[]) if c.get('kind')]
    return len(x)==len(y) and all(same(p,q) for p,q in zip(x,y))

def pure(node):
    """No call, assignment, increment or volatile access: evaluating it twice gives one value."""
    for n in walk_all(node):
        kind=n.get('kind')
        if kind in ('CallExpr','StmtExpr') or kind in ('BinaryOperator','CompoundAssignOperator') and n.get('opcode') in ('=','+=','-=','*=','/=','|=','&=','^=','<<=','>>=',','):return False
        if kind=='UnaryOperator' and n.get('opcode') in ('++','--'):return False
        if 'volatile' in n.get('type',{}).get('qualType',''):return False
    return True

def walk_all(node):
    yield node
    for c in node.get('inner',[]):
        if isinstance(c,dict):yield from walk_all(c)

def member_chain(node):
    """(cursor declaration id, 'm.n') of `&pos->m.n`, or None."""
    node=strip(node)
    if node.get('kind')!='UnaryOperator' or node.get('opcode')!='&':return None
    names=[];node=strip(node['inner'][0])
    while node.get('kind')=='MemberExpr':
        names.append(node.get('name'))
        if node.get('isArrow'):
            base=strip(node['inner'][0])
            if base.get('kind')!='DeclRefExpr':return None
            return base.get('referencedDecl',{}).get('id'),'.'.join(reversed(names))
        node=strip(node['inner'][0])
    return None

def walk_parts(node):
    """(cursor declaration id, 'm.n', HEAD expression, initializer value of the cursor, HEAD in that value) of an
    empty-walk candidate `for (pos = ...; !(&pos->m.n == HEAD); ...)`, or None."""
    parts=node.get('inner',[])
    if node.get('kind')!='ForStmt' or len(parts)!=5 or not parts[0].get('kind') or not parts[2].get('kind'):return None
    condition=strip(parts[2])
    if condition.get('kind')!='UnaryOperator' or condition.get('opcode')!='!':return None
    test=strip(condition['inner'][0])
    if test.get('kind')!='BinaryOperator' or test.get('opcode')!='==' or len(test.get('inner',[]))!=2:return None
    chain=member_chain(test['inner'][0])
    if chain is None:return None
    cursor,fields=chain;bound=strip(test['inner'][1])
    # The initializer: `pos = V` alone or first in a comma list.
    init=strip(parts[0])
    while init.get('kind')=='BinaryOperator' and init.get('opcode')==',':init=strip(init['inner'][0])
    if init.get('kind')!='BinaryOperator' or init.get('opcode')!='=':return None
    target=strip(init['inner'][0])
    if target.get('kind')!='DeclRefExpr' or target.get('referencedDecl',{}).get('id')!=cursor:return None
    value=init['inner'][1]
    # V reads HEAD->next (the walk's first entry) for the same HEAD the condition compares with.
    nexts=[n for n in walk_all(value) if n.get('kind')=='MemberExpr' and n.get('name')=='next' and n.get('isArrow') and same(n['inner'][0],bound)]
    if len(nexts)!=1 or not pure(bound):return None
    return cursor,fields,bound,value,nexts[0]
