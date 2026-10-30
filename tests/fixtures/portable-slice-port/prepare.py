"""Synthetic portability fixture; does not claim a capture of a real kernel."""
import hashlib
import json
import shutil
from pathlib import Path


def prepare(args, sources):
    root = Path(__file__).parent
    raw = (root/'capture.json').read_bytes()
    if (args.capture/'capture.json').read_bytes() != raw:
        raise ValueError('synthetic capture identity mismatch')
    capture = json.loads(raw)
    value = capture['initial_value'];values = [value]
    for call in capture['calls']:
        value = (value+call['delta']) & ((1 << 64)-1)
        if value != call['raw_bits']:
            raise ValueError('invalid synthetic capture transition')
        values.append(value)
    for name in ('port_types.h', 'provider.c', 'kernel.c', 'adapter.c', 'checkpoint-policy.json'):
        shutil.copyfile(root/name, sources/name)
    constant = lambda numbers: ','.join('UINT64_C('+str(n)+')' for n in numbers)
    (sources/'capture.h').write_text('#ifndef OSREC_FIXTURE_CAPTURE_H\n#define OSREC_FIXTURE_CAPTURE_H\n#include <stdint.h>\n#define FIXTURE_CALLS '+str(len(capture['calls']))+'\n'+''.join('extern const uint64_t fixture_'+name+'['+str(len(numbers))+'];\n' for name,numbers in (('numbers',[c['number'] for c in capture['calls']]),('deltas',[c['delta'] for c in capture['calls']]),('values',values)))+'#endif\n')
    (sources/'capture.c').write_text('#include "capture.h"\n'+''.join('const uint64_t fixture_'+name+'['+str(len(numbers))+']={'+constant(numbers)+'};\n' for name,numbers in (('numbers',[c['number'] for c in capture['calls']]),('deltas',[c['delta'] for c in capture['calls']]),('values',values))))
    return dict(identity=dict(kind='synthetic-aarch64-portability-fixture',source_sha256={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ('port_types.h','provider.c','kernel.c')}),checkpoint=capture,metadata=dict(kernel_image_sha256=None),sources=['provider.c','kernel.c'],headers=['port_types.h'],adapter_source='adapter.c',data_source='capture.c',checkpoint_policy='checkpoint-policy.json',required_syscalls=sorted({c['number'] for c in capture['calls']}),capture_manifest='capture.json',expected_result=dict(call_count=len(capture['calls']),scalar_width=64,input_rejections=4))
