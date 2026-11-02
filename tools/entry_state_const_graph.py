"""Constant address graphs: pointer members of const globals with address-constant initializers.

A const-qualified global defined once with an initializer holds the same value
for the whole run (a store to it is undefined behaviour). When a pointer member
of such an object is initialized with an address constant (`&G.m[i]`, possibly
converted), a function designator or a null pointer constant, every load of
that member yields exactly that value. This evaluates such loads to object
paths, so a walk over a constant table, such as an LSM hook list, resolves to
the table's own elements instead of an unknown pointer origin.

Paths use the analyzer's spelling: `global:NAME`, then `.field`, `[index]` and
`->field`. After an object of record type, `->field` is that record's member
(the path denotes the object's address, as `&object` does); after a pointer
member, `->field` follows the member's constant value. Only field and constant
subscript steps over complete struct and array types are walked; unions,
bit-fields, string initializers and anything else end the walk, which leaves the
analyzer's existing handling (and blockers) in place.
"""
import re
from entry_state import children,walk,type_of,fixed_array,constant_initializer,arithmetic_scalar

ROOT=re.compile(r'global:((?:tu[0-9]+:)?[A-Za-z_]\w*)')
STEP=re.compile(r'(\.|->)([A-Za-z_]\w*)|\[([0-9]+)\]')
ATTRIBUTES={'VisibilityAttr','AlignedAttr','UnusedAttr'}
ZERO={'kind':'ImplicitValueInitExpr'}
WRAPPERS=('ParenExpr','ConstantExpr')
CASTS=('BitCast','NoOp','NullToPointer','ArrayToPointerDecay','FunctionToPointerDecay')
# Syntax a constant initializer may contain. Any other node (a call, a string, a
# compound literal) disqualifies the whole object.
CONSTANT_SYNTAX={'InitListExpr','ImplicitValueInitExpr','IntegerLiteral','FloatingLiteral','CharacterLiteral','ParenExpr',
    'ConstantExpr','ImplicitCastExpr','CStyleCastExpr','UnaryOperator','BinaryOperator','MemberExpr','ArraySubscriptExpr','DeclRefExpr'}

def plain(typ):
    """A type without qualifiers or spacing differences (`T *const` and `const T *` views both become `T *`)."""
    return re.sub(r'\s*\*\s*','*',re.sub(r'\s+',' ',re.sub(r'\b(?:const|volatile)\b','',typ)).strip())

def pointer(typ):
    return plain(typ).endswith('*') and '(' not in typ

def strip(node):
    while node.get('kind') in WRAPPERS or node.get('kind') in ('ImplicitCastExpr','CStyleCastExpr') and node.get('castKind') in ('BitCast','NoOp'):
        terms=children(node)
        if len(terms)!=1:break
        node=terms[0]
    return node

class ConstGraph:
    def __init__(self,analyzer):
        self.analyzer=analyzer;self._definitions={};self._walks={}

    def definition(self,name,require_const=True):
        """(definition, initializer) of a global defined exactly once with an initializer."""
        key=(name,require_const)
        if key not in self._definitions:
            nodes=self.analyzer._global_declarations.get(name,[]);result=None
            definitions=[n for n in nodes if n.get('init')]
            # A lone internal-linkage const object without an initializer is a tentative
            # definition: zero-filled and never modifiable.
            tentative=(not definitions and len(nodes)==1 and nodes[0].get('storageClass')=='static' and type_of(nodes[0]).startswith('const ') and
                not nodes[0].get('tls') and not re.search(r'\bvolatile\b',type_of(nodes[0])) and
                {c.get('kind') for c in children(nodes[0]) if c.get('kind','').endswith('Attr')}<=ATTRIBUTES)
            if tentative:result=(nodes[0],ZERO)
            elif len(definitions)==1 and all(not n.get('tls') and (not require_const or type_of(n).startswith('const ')) and
                    not re.search(r'\bvolatile\b',type_of(n)) and
                    {c.get('kind') for c in children(n) if c.get('kind','').endswith('Attr')}<=ATTRIBUTES for n in nodes):
                node=definitions[0];parts=[c for c in children(node) if not c.get('kind','').endswith('Attr')]
                if len(parts)==1 and node.get('storageClass')!='extern' and self.constant_syntax(parts[0]):result=(node,parts[0])
            self._definitions[key]=result
        return self._definitions[key]

    @staticmethod
    def constant_syntax(initializer):
        for n in walk(initializer):
            kind=n.get('kind')
            if kind not in CONSTANT_SYNTAX:return False
            if kind=='UnaryOperator' and n.get('opcode') not in ('&','-','+','~','!'):return False
            if kind=='BinaryOperator' and n.get('opcode') in ('=',',') or kind=='CompoundAssignOperator':return False
            if kind=='DeclRefExpr' and n.get('referencedDecl',{}).get('kind') not in ('VarDecl','FunctionDecl','EnumConstantDecl'):return False
        return True

    def resolve_type(self,typ,unit):
        typ=plain(typ)
        for _ in range(16):
            if (unit,typ) not in self.analyzer.typedefs:break
            typ=plain(self.analyzer.typedefs[(unit,typ)])
        return typ

    def fields(self,typ,unit):
        record=self.analyzer.record_decls.get(self.resolve_type(typ,unit))
        if record is None or record.get('tagUsed')!='struct' or not record.get('completeDefinition'):return None
        if any(c.get('kind')=='PackedAttr' for c in children(record)):return None
        fields=[c for c in children(record) if c.get('kind')=='FieldDecl']
        if any(not f.get('name') or f.get('isBitfield') for f in fields):return None
        return fields

    @staticmethod
    def member_initializer(value,index,count):
        """The initializer of element/field `index` of an aggregate initializer, or None."""
        if value is ZERO:return ZERO
        value=strip(value)
        if value.get('kind')=='ImplicitValueInitExpr' and not children(value):return ZERO
        if value.get('kind')!='InitListExpr' or 'field' in value:return None
        terms=value.get('inner',[])
        if index<len(terms):return terms[index]
        filler=value.get('array_filler',[])
        if index<count and len(filler)==1:return filler[0]
        return None

    def walk(self,path,require_const=True):
        """(canonical path, declared type, initializer or ZERO, unit, object) for a path into a defined global, or None."""
        key=(path,require_const)
        if key in self._walks:return self._walks[key]
        self._walks[key]=None;result=None
        match=ROOT.match(path) if isinstance(path,str) else None
        found=self.definition(match[1],require_const) if match else None
        if found is not None:result=self._walk(match[1],found,path[match.end():],require_const)
        self._walks[key]=result
        return result

    def _walk(self,name,found,rest,require_const):
        node,value=found;unit=node.get('_translation_unit');typ=type_of(node);canonical='global:'+name;steps=0
        while rest:
            step=STEP.match(rest);steps+=1
            if step is None or steps>64 or value is None:return None
            rest=rest[step.end():]
            if step[3] is not None:
                array=fixed_array(re.sub(r'\s+',' ',typ.strip()))
                if array is None:return None
                count=int(array[2]);index=int(step[3])
                if index>=count:return None
                typ=array[1].strip()+typ.strip()[array.end(2)+1:]
                value=self.member_initializer(value,index,count);canonical+='['+str(index)+']';continue
            if step[1]=='->' and pointer(typ):
                if not require_const:return None
                target=self.value(value)
                if target is None or not target.startswith('global:'):return None
                followed=self.walk(target)
                if followed is None:return None
                canonical,typ,value,unit,name=followed
            elif step[1]=='->' and not (self.fields(typ,unit) is not None):return None
            fields=self.fields(typ,unit)
            if fields is None:return None
            index=next((i for i,f in enumerate(fields) if f['name']==step[2]),None)
            if index is None:return None
            typ=type_of(fields[index]);value=self.member_initializer(value,index,len(fields));canonical+='.'+step[2]
        return canonical,typ,value,unit,name

    def value(self,value):
        """The constant value of a pointer initializer: 'null', a global object path, 'function:NAME', or None."""
        if value is ZERO:return 'null'
        if value is None:return None
        node=value
        while True:
            node=strip(node)
            if node.get('kind') in ('ImplicitCastExpr','CStyleCastExpr') and node.get('castKind') in CASTS and len(children(node))==1:
                if node.get('castKind')=='NullToPointer':
                    inner=strip(children(node)[0])
                    while inner.get('kind') in ('ImplicitCastExpr','CStyleCastExpr') and inner.get('castKind') in CASTS and len(children(inner))==1:inner=strip(children(inner)[0])
                    return 'null' if inner.get('kind')=='IntegerLiteral' and str(inner.get('value'))=='0' else None
                if node.get('castKind')=='ArrayToPointerDecay':
                    base=self.lvalue(children(node)[0])
                    return base+'[0]' if base is not None else None
                if node.get('castKind')=='FunctionToPointerDecay':
                    target=strip(children(node)[0])
                    ref=target.get('referencedDecl',{})
                    return 'function:'+ref['name'] if target.get('kind')=='DeclRefExpr' and ref.get('kind')=='FunctionDecl' else None
                node=children(node)[0];continue
            break
        if node.get('kind')=='UnaryOperator' and node.get('opcode')=='&' and len(children(node))==1:
            return self.lvalue(children(node)[0])
        return None

    def lvalue(self,node):
        """The canonical object path of a constant lvalue expression (`G`, `G.m`, `G[i]`, `(&G)->m`)."""
        node=strip(node);kind=node.get('kind');terms=children(node)
        if kind=='DeclRefExpr':
            ref=node.get('referencedDecl',{})
            if ref.get('kind')!='VarDecl' or ref.get('id') not in self.analyzer.globals:return None
            path='global:'+ref['name']
        elif kind=='MemberExpr' and len(terms)==1 and node.get('name'):
            if node.get('isArrow'):
                base=self.value(terms[0])
                if base is None or not base.startswith('global:'):return None
            else:base=self.lvalue(terms[0])
            if base is None:return None
            path=base+'.'+node['name']
        elif kind=='ArraySubscriptExpr' and len(terms)==2:
            array=strip(terms[0]);index=strip(terms[1])
            if not (array.get('kind')=='ImplicitCastExpr' and array.get('castKind')=='ArrayToPointerDecay') or index.get('kind')!='IntegerLiteral':return None
            base=self.lvalue(children(array)[0])
            if base is None:return None
            path=base+'['+str(int(index['value']))+']'
        else:return None
        walked=self.walk(path,require_const=False)
        return walked[0] if walked is not None else None

    def load(self,path):
        """The value set of a load from a const pointer member at `path`, or None."""
        walked=self.walk(path)
        if walked is None or not pointer(walked[1]):return None
        value=self.value(walked[2])
        return None if value is None else {value}

    def canonical(self,path):
        walked=self.walk(path)
        return walked[0] if walked is not None else path

    def leaf(self,path,typ):
        """Evidence that a read of `path` with type `typ` reads a constant pointer member, or a constant scalar object."""
        walked=self.walk(path)
        if walked is None or walked[0]!=path or plain(walked[1])!=plain(typ):return None
        canonical,declared,value,unit,name=walked
        if value is None or re.search(r'\bvolatile\b',declared):return None
        if pointer(declared):
            target=self.value(value)
            if target is None:return None
            initializer={'kind':'address_constant','value':target}
        elif (canonical=='global:'+name or self.definition(name)[1] is ZERO) and arithmetic_scalar(self.resolve_type(declared,unit)):
            # Numeric members of records keep the numeric-record evidence and its policy;
            # only a whole scalar object (for example one marked unused) is covered here.
            if value is ZERO:initializer={'kind':'ImplicitValueInitExpr','type':{'qualType':plain(declared)}}
            else:
                initializer=constant_initializer(strip(value)) or constant_initializer(value)
                if initializer is None:return None
        else:return None
        return dict(kind='defined_const_initializer_leaf',object=name,path=canonical,type=declared,initializer=initializer)
