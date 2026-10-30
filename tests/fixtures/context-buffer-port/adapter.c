#include "slice_context.h"
#include "slice_dispatch.h"
#include "capture.h"
#include "osrec/syscall_slice.h"
static void restore(void *state){osrec_context_restore(state);}
static const uint32_t *pointer(const struct osrec_kernel_context *ctx,const uint64_t pair[2])
{
    return pair[0] ? &ctx->buffers[pair[0]-1].words[pair[1]/4] : NULL;
}
uint32_t osrec_kernel_checkpoint_check(const void *state,uint64_t next)
{
    const struct osrec_kernel_context *ctx=state;
    if(next>FIXTURE_CALLS || ctx->osrec_local_BufferStep_calls_0!=next || ctx->osrec_private_0_visits!=next || ctx->osrec_private_1_visits!=3*next || ctx->cursor!=pointer(ctx,fixture_cursor[next]) || ctx->alias!=pointer(ctx,fixture_alias[next]) || ctx->end!=pointer(ctx,fixture_end[next]))return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=0;i<2;++i){
        if(ctx->buffers[i].guard)return OSREC_SLICE_BAD_INPUT;
        for(unsigned j=0;j<4;++j)if(ctx->buffers[i].words[j]!=fixture_words[next][i][j])return OSREC_SLICE_BAD_INPUT;
    }
    return OSREC_SLICE_OK;
}
static uint32_t enter(void *state,const struct osrec_slice_invocation *in,struct osrec_slice_result *out)
{
    struct osrec_kernel_context *ctx=state;
    if(in->ordinal>=FIXTURE_CALLS || osrec_kernel_checkpoint_check(ctx,in->ordinal) || in->number!=fixture_numbers[in->ordinal] || in->args[0]!=fixture_operations[in->ordinal])return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=2;i<6;++i)if(in->args[i])return OSREC_SLICE_BAD_INPUT;
    const struct osrec_user_region *region=osrec_user_memory_object(&in->memory,1,16,3);
    unsigned char *buffer=osrec_user_memory_resolve(&in->memory,in->args[1],16,3);
    if(!region || !buffer || buffer!=region->image_address)return OSREC_SLICE_BAD_INPUT;
    for(unsigned i=8;i<16;++i)if(buffer[i]!=0xa5)return OSREC_SLICE_BAD_INPUT;
    uintptr_t arguments[6]={in->args[0],(uintptr_t)buffer,0,0,0,0};
    out->raw=osrec_kernel_dispatch(ctx,in->number,arguments);
    if(osrec_kernel_checkpoint_check(ctx,in->ordinal+1) || (uint64_t)out->raw!=fixture_values[in->ordinal+1])return OSREC_SLICE_DIVERGED;
    for(unsigned i=0;i<16;++i)if(buffer[i]!=(i<8 ? (unsigned char)(fixture_values[in->ordinal+1]>>(8*i)) : 0xa5))return OSREC_SLICE_DIVERGED;
    return OSREC_SLICE_OK;
}
static uint32_t finish(const void *state){return osrec_kernel_checkpoint_check(state,FIXTURE_CALLS);}
const struct osrec_slice_adapter osrec_kernel_adapter={OSREC_SLICE_ABI,"synthetic-aarch64-context-buffers",sizeof(struct osrec_kernel_context),_Alignof(struct osrec_kernel_context),FIXTURE_CALLS,restore,enter,finish};
