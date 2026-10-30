#include "slice_context.h"
#include "slice_dispatch.h"
/* The generated context contains all mutable state of the reviewed boundary models. */
static uint32_t bind_invocation(struct osrec_kernel_context *ctx,const struct osrec_slice_invocation *in)
{
    if(in->ordinal>=FILE_CALL_COUNT)return OSREC_SLICE_BAD_INPUT;
    const struct files_call *c=&files_calls[in->ordinal];
    if(in->number!=c->number || in->args[5])return OSREC_SLICE_BAD_INPUT;
    const struct osrec_user_region *buffer=osrec_user_memory_object(&in->memory,1,192,3);
    if(!buffer)return OSREC_SLICE_BAD_INPUT;
    /* Binding is invocation-local; file state and transcript position remain untouched. */
    unsigned char *next_witness=buffer->image_address;const char *next_path=NULL;uint32_t next_kind=0;uintptr_t arguments[6]={0};
    for(unsigned index=0;index<5;++index){
        unsigned kind=osrec_argument_kind(c->number,index);uint64_t value=in->args[index];uint32_t expected=c->args[index];
        if(kind==0){if(value)return OSREC_SLICE_BAD_INPUT;}
        else if(kind==1 || kind==2){
            uint64_t canonical=kind==1 ? (uint64_t)(int64_t)(int32_t)expected : expected;
            if(value!=expected && value!=canonical)return OSREC_SLICE_BAD_INPUT;
        } else if(kind==3){
            if(expected==0){if(value)return OSREC_SLICE_BAD_INPUT;}
            else if(expected==2){if(!value || osrec_user_memory_resolve(&in->memory,value,1,1))return OSREC_SLICE_BAD_INPUT;}
            else if(expected!=1 || osrec_user_memory_resolve(&in->memory,value,192,3)!=next_witness)return OSREC_SLICE_BAD_INPUT;
        } else if(kind==4){
            if(!expected){if(value)return OSREC_SLICE_BAD_INPUT;}
            else if(expected==3){if(!value || osrec_user_memory_resolve(&in->memory,value,1,1))return OSREC_SLICE_BAD_INPUT;}
            else {
                const char *text=expected==1 ? "/dev/shm/osrec-file.bin" : "/dev/shm/osrec-missing.bin";
                unsigned n=expected==1 ? 24 : 27;next_path=osrec_user_memory_resolve(&in->memory,value,n,1);next_kind=expected;
                if((expected!=1 && expected!=2) || !next_path)return OSREC_SLICE_BAD_INPUT;
                for(unsigned j=0;j<n;++j)if(next_path[j]!=text[j])return OSREC_SLICE_BAD_INPUT;
            }
        } else return OSREC_SLICE_BAD_INPUT;
        if(kind==3)arguments[index]=expected==1 ? (uintptr_t)next_witness : expected==2 ? 1 : 0;
        else if(kind==4)arguments[index]=(expected==1 || expected==2) ? (uintptr_t)next_path : expected==3 ? 1 : 0;
        else arguments[index]=(uintptr_t)value;
    }
    for(unsigned j=0;j<192;++j)if(next_witness[j]!=c->buffer_before[j])return OSREC_SLICE_BAD_INPUT;
    for(unsigned j=0;j<6;++j)ctx->arguments[j]=arguments[j];
    ctx->witness=next_witness;ctx->entry_path=next_path;ctx->entry_path_kind=next_kind;return OSREC_SLICE_OK;
}
static void restore(void *state)
{
    struct osrec_kernel_context *ctx=state;osrec_context_restore(ctx);
    ctx->state[0]=UINT32_MAX;ctx->state[3]=UINT32_MAX;ctx->state[6]=UINT32_MAX;
    ctx->return_hash=UINT32_C(2166136261);
}
static uint32_t enter(void *state,const struct osrec_slice_invocation *in,struct osrec_slice_result *out)
{
    struct osrec_kernel_context *ctx=state;
    uint32_t status=bind_invocation(ctx,in);if(status)return status;
    if(osrec_slice_checkpoint(&ctx->jump)){
        out->diagnostic=ctx->jump.diagnostic;return OSREC_SLICE_DIVERGED;
    }
    const struct files_call *c=&files_calls[in->ordinal];
    ctx->invocation=(uint32_t)in->ordinal;ctx->error=0;
    if(ctx->cursor!=c->event_start || ctx->path_allocated || ctx->lock_depth)osrec_slice_abort(&ctx->jump,29);
    for(unsigned j=0;j<15;++j)if(c->before[j]!=ctx->state[j])osrec_slice_abort(&ctx->jump,30);
    int64_t raw=osrec_kernel_dispatch(ctx,in->number,ctx->arguments);
    if((uint32_t)raw!=c->raw || ctx->error!=c->error || ctx->cursor!=c->event_end || ctx->path_allocated || ctx->lock_depth)osrec_slice_abort(&ctx->jump,32);
    for(unsigned j=0;j<15;++j)if(c->after[j]!=ctx->state[j])osrec_slice_abort(&ctx->jump,33);
    for(unsigned j=0;j<192;++j)if(ctx->witness[j]!=c->buffer_after[j])osrec_slice_abort(&ctx->jump,1);
    ctx->return_hash=(ctx->return_hash^(uint32_t)raw)*UINT32_C(16777619);++ctx->verified;
    /* Do not leave app pointers attached to persistent kernel objects. */
    ctx->witness=NULL;ctx->entry_path=NULL;ctx->entry_path_kind=0;
    out->raw=raw;return OSREC_SLICE_OK;
}
static uint32_t finish(const void *state)
{
    const struct osrec_kernel_context *ctx=state;
    if(ctx->verified!=FILE_CALL_COUNT || ctx->cursor!=FILE_EVENT_COUNT || ctx->return_hash!=FILE_RETURN_HASH || ctx->length!=4 || ctx->path_allocated || ctx->lock_depth)return OSREC_SLICE_DIVERGED;
    for(unsigned j=0;j<15;++j)if(ctx->state[j]!=(j==0 || j==3 || j==6 ? UINT32_MAX : 0))return OSREC_SLICE_DIVERGED;
    if(ctx->content[0]!='a' || ctx->content[1]!='b' || ctx->content[2]!='X' || ctx->content[3]!='Y' || ctx->space.regionMux!=0 || ctx->process.vmSpace!=&ctx->space)return OSREC_SLICE_DIVERGED;
    return OSREC_SLICE_OK;
}
const struct osrec_slice_adapter osrec_kernel_adapter={OSREC_SLICE_ABI,"liteos-a-armv7-captured-32-bit-scalars",sizeof(struct osrec_kernel_context),_Alignof(struct osrec_kernel_context),FILE_CALL_COUNT,restore,enter,finish};
/* Quiescent checks are port-owned; references are rebound by the codec. */
uint32_t osrec_kernel_checkpoint_check(const void *state,uint64_t next)
{
    const struct osrec_kernel_context *ctx=state;
    if(next>FILE_CALL_COUNT || ctx->verified!=next || ctx->cursor!=(next ? files_calls[next-1].event_end : 0) || ctx->invocation!=(next ? next-1 : 0) || ctx->path_allocated || ctx->lock_depth || ctx->witness || ctx->entry_path || ctx->entry_path_kind || ctx->length>sizeof(ctx->content) || ctx->space.regionMux || ctx->process.vmSpace!=&ctx->space)return OSREC_SLICE_BAD_INPUT;
    uint32_t hash=UINT32_C(2166136261);
    for(uint64_t i=0;i<next;++i)hash=(hash^files_calls[i].raw)*UINT32_C(16777619);
    if(ctx->return_hash!=hash)return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=0;i<15;++i)if(ctx->state[i]!=(next ? files_calls[next-1].after[i] : (i==0 || i==3 || i==6 ? UINT32_MAX : 0)))return OSREC_SLICE_BAD_INPUT;
    return OSREC_SLICE_OK;
}
