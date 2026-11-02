"""Member designators of `offsetof` expressions, read from the configured compiler's libclang.

Clang's JSON AST dump does not serialize an OffsetOfExpr's designator. The same
LLVM installation's libclang exposes it (MEMBER_REF children naming each
field), so each OffsetOfExpr in the JSON tree is matched with libclang's view
of the same translation unit by the file and offset of its expansion point and
by its order among the expressions at that point. A position whose expression
count or file differs between the two views stays unannotated, as does every
offsetof when libclang or its Python bindings are not installed beside the
compiler; an unannotated offsetof keeps every existing blocker.
"""
import importlib.util
import os
import sys
from pathlib import Path

_CINDEX={}

def cindex(compiler):
    """The libclang bindings installed with `compiler`, or None."""
    lib=Path(compiler).resolve().parent.parent/'lib'
    if lib in _CINDEX:return _CINDEX[lib]
    library=next((lib/n for n in ('libclang.dylib','libclang.so') if (lib/n).exists()),None)
    bindings=sorted(lib.glob('python3*/site-packages/clang/cindex.py'))
    module=None
    if library is not None and bindings:
        package=bindings[-1].parent
        loaded=sys.modules.get('clang')
        # The bindings import `clang.enumerations`; only this installation's package may provide it.
        if loaded is None or Path(getattr(loaded,'__file__','') or '').parent==package:
            sys.path.insert(0,str(package.parent))
            try:
                import clang.cindex as module
                if module.Config.loaded:
                    if Path(module.Config.library_file or '')!=library:module=None
                else:module.Config.set_library_file(str(library))
            except Exception:module=None
            finally:sys.path.remove(str(package.parent))
    _CINDEX[lib]=module
    return module

def json_positions(tree,directory):
    """OffsetOfExpr nodes by (file, expansion offset), in document order.

    The JSON dump prints a location's file only when it differs from the last
    printed one, so files are recovered by replaying the dump order."""
    current=[None];found={}
    def bare(loc):
        if 'file' in loc:current[0]=loc['file']
        return current[0],loc.get('offset')
    def point(loc):
        if 'spellingLoc' in loc or 'expansionLoc' in loc:
            if 'spellingLoc' in loc:bare(loc['spellingLoc'])
            return bare(loc['expansionLoc']) if 'expansionLoc' in loc else (None,None)
        return bare(loc)
    def visit(value):
        if isinstance(value,list):
            for item in value:visit(item)
            return
        if not isinstance(value,dict):return
        if 'offset' in value and not isinstance(value.get('offset'),dict):bare(value);return
        offsetof=value.get('kind')=='OffsetOfExpr'
        for key,item in value.items():
            if key=='includedFrom':continue
            if key=='range' and isinstance(item,dict):
                begin=point(item['begin']) if isinstance(item.get('begin'),dict) else (None,None)
                if isinstance(item.get('end'),dict):point(item['end'])
                if offsetof and None not in begin:
                    found.setdefault((os.path.realpath(os.path.join(directory,begin[0])),begin[1]),[]).append(value)
                continue
            if key=='loc' and isinstance(item,dict):point(item);continue
            visit(item)
    visit(tree)
    return found

def libclang_positions(module,source,args,directory):
    """Field designators of libclang's offsetof expressions by (file, expansion offset)."""
    previous=os.getcwd();source=Path(source).resolve()
    try:
        os.chdir(directory)
        # The compile arguments name the source itself; libclang takes it separately.
        flags=[a for a in args if not (not a.startswith('-') and Path(a).resolve()==source)]
        unit=module.Index.create().parse(str(source),args=flags)
    except module.TranslationUnitLoadError:return None
    finally:os.chdir(previous)
    if any(d.severity>=module.Diagnostic.Error for d in unit.diagnostics):return None
    found={}
    for cursor in unit.cursor.walk_preorder():
        if cursor.kind!=module.CursorKind.UNEXPOSED_EXPR or cursor.type.kind not in (module.TypeKind.ULONG,module.TypeKind.ULONGLONG):continue
        parts=list(cursor.get_children())
        members=[c for c in parts if c.kind==module.CursorKind.MEMBER_REF]
        if not members:continue
        parent=cursor.semantic_parent
        start=cursor.extent.start
        if start.file is None:continue
        fields=[];records=[]
        for member in members:
            field=member.referenced
            if field is None or field.kind!=module.CursorKind.FIELD_DECL:fields=None;break
            fields.append(field.spelling);records.append(field.semantic_parent.type.spelling)
        designator=None
        if fields is not None:
            # Array subscripts (INTEGER_LITERAL or other expression children after the type) are not field-only.
            subscripted=any(c.kind not in (module.CursorKind.MEMBER_REF,module.CursorKind.TYPE_REF) for c in parts[1:])
            designator=dict(record=records[0],fields=fields,records=records,field_only=not subscripted and all(fields))
        path=os.path.realpath(os.path.join(directory,start.file.name))
        found.setdefault((path,start.offset),[]).append(designator)
    return found

def annotate(tree,compiler,source,args,directory):
    """Attach `_offsetof` designators; return the count of annotated expressions."""
    expressions=json_positions(tree,directory)
    if not expressions:return 0
    module=cindex(compiler)
    if module is None:return 0
    designators=libclang_positions(module,source,args,directory)
    if designators is None:return 0
    count=0
    for key,nodes in expressions.items():
        seen=designators.get(key,[])
        if len(seen)!=len(nodes):continue
        for node,designator in zip(nodes,seen):
            if designator is not None:node['_offsetof']=dict(designator,source='libclang');count+=1
    return count
