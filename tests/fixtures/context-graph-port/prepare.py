"""Synthetic bounded context-owned graph; no real-kernel capture is claimed."""
import hashlib
import json
import shutil
from pathlib import Path


def prepare(args,sources):
    root=Path(__file__).parent;raw=(root/'capture.json').read_bytes()
    if (args.capture/'capture.json').read_bytes()!=raw:raise ValueError('graph capture identity mismatch')
    capture=json.loads(raw);count=len(capture['calls'])
    for name in ('graph_types.h','kernel.c','adapter.c','checkpoint-policy.json'):
        shutil.copyfile(root/name,sources/name)
    number=capture['number'];states=capture['states']
    if len(states)!=count+1:raise ValueError('graph capture lacks boundary states')
    arrays=dict(operations=[c['operation'] for c in capture['calls']],arguments=[c['value'] for c in capture['calls']],values=[s['result'] for s in states],heads=[s['head'] for s in states],tails=[s['tail'] for s in states])
    header='#ifndef OSREC_GRAPH_CAPTURE_H\n#define OSREC_GRAPH_CAPTURE_H\n#include <stdint.h>\n#define FIXTURE_CALLS '+str(count)+'\n#define FIXTURE_NUMBER UINT64_C('+str(number)+')\nstruct expected_node {uint64_t value;uint32_t live,generation,next;};\n'
    header+=''.join('extern const uint64_t fixture_'+name+'['+str(len(numbers))+'];\n' for name,numbers in arrays.items())
    header+='extern const struct expected_node fixture_nodes['+str(len(states))+'][3];\n#endif\n';(sources/'capture.h').write_text(header)
    data='#include "capture.h"\n'+''.join('const uint64_t fixture_'+name+'['+str(len(numbers))+']={'+','.join('UINT64_C('+str(n)+')' for n in numbers)+'};\n' for name,numbers in arrays.items())
    data+='const struct expected_node fixture_nodes['+str(len(states))+'][3]={\n'
    for state in states:data+='{'+','.join('{UINT64_C('+str(node['value'])+'),'+','.join(str(node[k]) for k in ('live','generation','next'))+'}' for node in state['nodes'])+'},\n'
    (sources/'capture.c').write_text(data+'};\n')
    return dict(identity=dict(kind='synthetic-context-owned-object-graph',source_sha256={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ('graph_types.h','kernel.c')}),checkpoint=capture,metadata=dict(kernel_image_sha256=None),sources=['kernel.c'],headers=['graph_types.h'],adapter_source='adapter.c',data_source='capture.c',checkpoint_policy='checkpoint-policy.json',required_syscalls=[number],capture_manifest='capture.json',expected_result=dict(call_count=count,scalar_width=64,input_rejections=4))
