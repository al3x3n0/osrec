#include "slice_context.h"
#include "slice_dispatch.h"
#include "capture.h"
#include "osrec/syscall_slice.h"
static void restore(void *state){osrec_context_restore(state);}
uint32_t osrec_kernel_checkpoint_check(const void *state,uint64_t next)
{
    const struct osrec_kernel_context *ctx=state;
    return next<=FIXTURE_CALLS && ctx->ledger.calls==next &&
        ctx->ledger.value==fixture_values[next] && ctx->alias==&ctx->ledger ? 0 : OSREC_SLICE_BAD_INPUT;
}
static uint32_t enter(void *state,const struct osrec_slice_invocation *in,struct osrec_slice_result *out)
{
    struct osrec_kernel_context *ctx=state;
    if(in->ordinal>=FIXTURE_CALLS || osrec_kernel_checkpoint_check(ctx,in->ordinal) ||
        in->number!=fixture_numbers[in->ordinal] || in->args[0]!=fixture_deltas[in->ordinal])return OSREC_SLICE_BAD_INPUT;
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
const struct osrec_slice_adapter osrec_kernel_adapter={OSREC_SLICE_ABI,"synthetic-aarch64-64-bit",sizeof(struct osrec_kernel_context),_Alignof(struct osrec_kernel_context),FIXTURE_CALLS,restore,enter,finish};
