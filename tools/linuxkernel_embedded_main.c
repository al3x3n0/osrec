/* A complete native checkpoint. All state, inputs and acceptance checks are
 * linked read-only assets; no original package paths are opened at runtime. */
#include "linuxkernel_embedded.h"
#include "linuxkernel_checkpoint_report.h"
#ifndef OSREC_FREESTANDING
#include <string.h>
#endif
_Static_assert(sizeof(struct checkpoint_expected_event)==80,"embedded oracle ABI");
static int same(const struct lk_el0_event *a,const struct checkpoint_expected_event *b)
{
    return a->exception==b->exception && a->number==b->number &&
           !memcmp(a->arguments,b->arguments,sizeof b->arguments) &&
           a->completed==b->completed && (!b->completed || a->result==b->result);
}
static int duplicate(const struct lk_el0_event *a,const struct lk_el0_event *b)
{return a->exception && b->exception && !memcmp(a->arguments,b->arguments,3*8);}
int main(int argc,char **argv)
{
    const char *trace=NULL;
    if(argc==2 && !strcmp(argv[1],"--describe")) {
        return fwrite(osrec_checkpoint.provenance.data,1,osrec_checkpoint.provenance.size,stdout)==osrec_checkpoint.provenance.size?0:1;
    }
    if(argc==3 && !strcmp(argv[1],"--trace"))trace=argv[2];
    else if(argc!=1){fprintf(stderr,"usage: %s [--describe | --trace OUTPUT.json]\n",argv[0]);return 2;}
    struct lk_el0_native *native=NULL;struct lk_el0_diagnostic diagnostic;
    enum lk_el0_status status=lk_el0_native_open_image(&osrec_checkpoint.image,&native,&diagnostic);
    if(status!=LK_EL0_OK){fprintf(stderr,"checkpoint load failed: status=%u detail=%"PRIu64"\n",status,diagnostic.detail);return 1;}
    struct lk_el0_event *events=NULL;
    uint64_t capacity=osrec_checkpoint.event_count+1024;
    if(lk_el0_native_trace_allocate(native,capacity,&events)!=LK_EL0_OK){lk_el0_native_close(native);return 1;}
    struct lk_el0_result result;
    status=lk_el0_native_execute(native,NULL,&result);
    uint64_t count=lk_el0_native_events(native),used=lk_el0_native_counters_consumed(native),mmio=lk_el0_native_mmio_consumed(native);
    int okay=status==LK_EL0_BOUNDARY && result.diagnostic.reason==osrec_checkpoint.stop_reason &&
             result.diagnostic.pc==osrec_checkpoint.stop_pc &&
             used==osrec_checkpoint.image.counters.size/sizeof(struct lk_el0_counter) &&
             mmio==osrec_checkpoint.image.mmio.size/sizeof(struct lk_el0_mmio);
    uint64_t expected=0;
    for(uint64_t i=0;i<count;i++) {
        if(i && duplicate(events+i,events+i-1))continue;
        if(expected>=osrec_checkpoint.event_count || !same(events+i,osrec_checkpoint.expected+expected)) {
            fprintf(stderr,"checkpoint event mismatch at %"PRIu64" (native event %"PRIu64")\n",expected,i);okay=0;break;
        }
        expected++;
    }
    if(expected!=osrec_checkpoint.event_count)okay=0;
    if(trace) {
        FILE *out=fopen(trace,"w");
        if(!out)okay=0;
        else {if(checkpoint_report(out,"embedded-native-checkpoint",events,count,&result,used,mmio))okay=0;if(fclose(out))okay=0;}
    }
    printf("{\"verified\":%s,\"events\":%"PRIu64",\"expected_events\":%"PRIu64",\"counter_reads\":%"PRIu64",\"mmio_accesses\":%"PRIu64",\"stop_pc\":\"0x%"PRIx64"\",\"identity\":\"%s\"}\n",okay?"true":"false",count,osrec_checkpoint.event_count,used,mmio,result.diagnostic.pc,osrec_checkpoint.identity);
    if(lk_el0_native_close(native)!=LK_EL0_OK)okay=0;
    return okay?0:1;
}
