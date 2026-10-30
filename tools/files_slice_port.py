"""Reviewed OHOS file-profile construction adapter for the portable slice builder."""
import re,shutil
from klee_liteos import ROOT
from files_capture import prepare_source
from export_freestanding_files import load_capture,header,return_hash

def prepare(args,sources):
    generated,identity=prepare_source(args.kernel_root);checkpoint,metadata=load_capture(args.capture,identity)
    checkpoint_header=header(checkpoint)
    analysis_header=checkpoint_header[:checkpoint_header.index('#ifdef OSREC_FILES_REPLAY')]+'''extern const struct files_call files_calls[FILE_CALL_COUNT];
extern const struct files_event files_events[FILE_EVENT_COUNT];
#endif
'''
    (sources/'files_checkpoint.h').write_text(analysis_header)
    data=checkpoint_header.split('#ifdef OSREC_FILES_REPLAY\n',1)[1].rsplit('#endif\n#endif',1)[0].replace('static const struct','const struct')
    (sources/'slice_checkpoint.c').write_text('#include \"files_checkpoint.h\"\n'+data)
    model= (ROOT/'integrations/rtl_aarch64/files_replay.c').read_text().split('static const char *path_argument')[0]
    model=re.sub(r'volatile uint32_t osrec_result\[32\].*?;\n','',model)
    model=model.replace('unsigned char file_pool;','const unsigned char file_pool;')
    model=re.sub(r'void replay_fault\(void\).*?\n','',model)
    model=re.sub(r'static void stop\(void\).*?\n','',model)
    model=re.sub(r'static void fail\(uint32_t code\).*?\n','static void fail(uint32_t code){osrec_slice_abort(&jump,code);}\n',model)
    model=model.replace('static unsigned char witness[192] __attribute__((aligned(8))),content[8];','static unsigned char *witness;\nstatic unsigned char content[8];')
    model=model.replace('static LosVmSpace space;', 'static struct osrec_slice_guard jump;\nstatic const char *entry_path;\nstatic uint32_t entry_path_kind,return_hash;\nstatic uintptr_t arguments[6];\nstatic LosVmSpace space;')
    model=model.replace('p==main_path ? 1 :','p==entry_path && entry_path ? entry_path_kind : p==main_path ? 1 :')
    model='#include "osrec/syscall_slice.h"\n'+model
    (sources/'files_models.c').write_text(model);(sources/'files_syscalls.c').write_text(generated)
    h=(ROOT/'integrations/liteos_a/files_model.h').read_text().replace('extern unsigned char file_pool;','extern const unsigned char file_pool;').replace('#define OS_SYS_MEM_ADDR (&file_pool)','#define OS_SYS_MEM_ADDR ((void *)&file_pool)')
    (sources/'files_model.h').write_text(h)
    shutil.copyfile(ROOT/'integrations/liteos_a/files_slice_adapter.c',sources/'slice_adapter.c')
    shutil.copyfile(ROOT/'integrations/liteos_a/files-checkpoint-schema.json',sources/'slice_checkpoint_policy.json')
    cpu_breakpoints={**{'osrec_app_'+kind+'_'+session:0x5353 if kind=='route' else 0x5354 for session in ('a','b') for kind in ('route','exit')},
        'osrec_app_sequence_first':0x5353,'osrec_app_sequence_second':0x5353,'osrec_app_sequence_exit':0x5354,'osrec_app_fault_route':0x5353,'osrec_app_fault_exit':0x5354}
    return {'checkpoint_policy':'slice_checkpoint_policy.json','cpu_breakpoints':cpu_breakpoints,'identity':identity,'checkpoint':checkpoint,'metadata':metadata,'sources':['files_models.c','files_syscalls.c'],
        'headers':['files_model.h'],'checkpoint_header':'files_checkpoint.h','adapter_source':'slice_adapter.c','data_source':'slice_checkpoint.c',
        'required_syscalls':sorted({c['number'] for c in checkpoint['calls']}),'capture_manifest':'files-checkpoint.manifest.json','expected_result':{'call_count':len(checkpoint['calls']),'event_count':len(checkpoint['dependency_transcript']),'expected_return_hash':return_hash(),'file_length_a':4,'file_length_b':4,'captured_scalar_width':32}}
