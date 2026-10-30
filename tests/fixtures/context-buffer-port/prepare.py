"""Synthetic context-owned buffer cursors; no real-kernel capture is claimed."""
import hashlib
import json
import shutil
from pathlib import Path


def prepare(args,sources):
    root=Path(__file__).parent;raw=(root/'capture.json').read_bytes()
    if (args.capture/'capture.json').read_bytes()!=raw:raise ValueError('buffer capture identity mismatch')
    capture=json.loads(raw);states=capture['states'];count=len(capture['calls'])
    if len(states)!=count+1:raise ValueError('buffer capture lacks boundary states')
    for name in ('buffer_types.h','kernel.c','provider.c','adapter.c','checkpoint-policy.json'):shutil.copyfile(root/name,sources/name)
    arrays=dict(numbers=[capture['number']]*count,operations=capture['calls'],values=[s['result'] for s in states])
    header='#ifndef OSREC_BUFFER_CAPTURE_H\n#define OSREC_BUFFER_CAPTURE_H\n#include <stdint.h>\n#define FIXTURE_CALLS '+str(count)+'\n'
    header+=''.join('extern const uint64_t fixture_'+key+'['+str(len(values))+'];\n' for key,values in arrays.items())
    header+=''.join('extern const uint64_t fixture_'+key+'['+str(len(states))+'][2];\n' for key in ('cursor','alias','end'))
    header+='extern const uint32_t fixture_words['+str(len(states))+'][2][4];\n#endif\n';(sources/'capture.h').write_text(header)
    data='#include "capture.h"\n'+''.join('const uint64_t fixture_'+key+'['+str(len(values))+']={'+','.join('UINT64_C('+str(v)+')' for v in values)+'};\n' for key,values in arrays.items())
    data+=''.join('const uint64_t fixture_'+key+'['+str(len(states))+'][2]={'+','.join('{'+','.join(map(str,s[key]))+'}' for s in states)+'};\n' for key in ('cursor','alias','end'))
    data+='const uint32_t fixture_words['+str(len(states))+'][2][4]={'+','.join('{'+','.join('{'+','.join(map(str,words))+'}' for words in s['words'])+'}' for s in states)+'};\n';(sources/'capture.c').write_text(data)
    return dict(identity=dict(kind='synthetic-context-owned-buffer-cursors',source_sha256={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ('buffer_types.h','kernel.c','provider.c')}),checkpoint=capture,metadata=dict(kernel_image_sha256=None),sources=['kernel.c','provider.c'],headers=['buffer_types.h'],adapter_source='adapter.c',data_source='capture.c',checkpoint_policy='checkpoint-policy.json',required_syscalls=[capture['number']],capture_manifest='capture.json',expected_result=dict(call_count=count,scalar_width=64,input_rejections=4))
