#include "flat.h"
struct flat_control *flat_active;
static void copy(struct flat_frame *out,const struct flat_frame *in)
{
    unsigned char *d=(void *)out;const unsigned char *s=(const void *)in;
    for(size_t i=0;i<sizeof *out;i++)d[i]=s[i];
}
flat_target flat_dispatch(struct flat_frame *frame,const struct flat_site *site)
{
    struct flat_control *c=flat_active;
    c->live=frame;
    frame->cpu.pstate|=c->pstate_extra;
    frame->cpu.pc=site->pc;
    if(c->transitions++==c->limit){copy(c->frame,frame);c->status=FLAT_BOUNDARY;return 0;}
    flat_target target=c->handler(c->opaque,frame,site);
    if(frame->cpu.pstate&~(0xf0000000ull|(1ull<<12))){copy(c->frame,frame);c->status=FLAT_BAD_ARGUMENT;return 0;}
    c->guest_sp=frame->cpu.sp;c->pstate_extra=frame->cpu.pstate&~0xf0000000ull;
    if(!target)copy(c->frame,frame);
    return target;
}
enum flat_status flat_run(struct flat_frame *frame,flat_target entry,void *stack,size_t bytes,
                          uint64_t limit,flat_handler handler,void *opaque,uint64_t *transitions)
{
    if(transitions)*transitions=0;
    if(flat_active)return FLAT_BUSY;
    if(!frame || !entry || !stack || !handler || bytes<16384 || !limit ||
       ((uintptr_t)stack&15) || (bytes&15) || bytes>UINTPTR_MAX-(uintptr_t)stack ||
       (frame->cpu.pstate&~(0xf0000000ull|(1ull<<12))))return FLAT_BAD_ARGUMENT;
    uintptr_t lo=(uintptr_t)stack,hi=lo+bytes,f=(uintptr_t)frame;
    if(f>UINTPTR_MAX-sizeof *frame || (f<hi && lo<f+sizeof *frame))return FLAT_BAD_ARGUMENT;
    struct flat_control control={.guest_sp=frame->cpu.sp,.stack_top=hi,.frame=frame,
        .handler=handler,.opaque=opaque,.pstate_extra=frame->cpu.pstate&~0xf0000000ull,.limit=limit};
    flat_active=&control;
    flat_enter(&control,frame,entry);
    flat_active=0;if(transitions)*transitions=control.transitions;
    return (enum flat_status)control.status;
}
void flat_fail(enum flat_status status)
{
    if(!flat_active)__builtin_unreachable();
    if(flat_active->live)copy(flat_active->frame,flat_active->live);
    flat_active->status=status;flat_escape();
}
