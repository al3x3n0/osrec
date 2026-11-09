#ifndef LK_CHECKPOINT_REPORT_H
#define LK_CHECKPOINT_REPORT_H
#include "osrec/linuxkernel_el0_native.h"
#ifdef OSREC_FREESTANDING
#include "standalone.h"
#else
#include <inttypes.h>
#include <stdio.h>
#endif
static int checkpoint_report(FILE *out,const char *kind,const struct lk_el0_event *events,
                             uint64_t count,const struct lk_el0_result *result,uint64_t counters,uint64_t mmio)
{
    fprintf(out,"{\"kind\":\"%s\",\"calls\":[\n",kind);
    for(uint64_t i=0;i<count;i++) {
        const struct lk_el0_event *e=events+i;
        fprintf(out,"%s{",i?",\n":"");
        if(e->exception)fprintf(out,"\"event\":\"exception\",\"number\":-1,");
        else fprintf(out,"\"number\":%"PRIu64",",e->number);
        fprintf(out,"\"arguments\":[");
        for(unsigned j=0;j<(e->exception?3u:6u);j++)fprintf(out,"%s%"PRIu64,j?",":"",e->arguments[j]);
        fprintf(out,"],\"result\":");
        if(e->completed)fprintf(out,"%"PRIu64,e->result);else fprintf(out,"null");
        fprintf(out,",\"pc\":\"0x%"PRIx64"\"}",e->pc);
    }
    fprintf(out,"\n],\"end\":{\"status\":%u,\"stop_code\":%"PRIu64",\"pc\":\"0x%"PRIx64"\",\"detail\":\"0x%"PRIx64"\",\"far\":\"0x%"PRIx64"\"},\"counters_consumed\":%"PRIu64",\"mmio_consumed\":%"PRIu64"}\n",result->status,result->diagnostic.reason,result->diagnostic.pc,result->diagnostic.detail,result->diagnostic.far,counters,mmio);
    return ferror(out)?-1:0;
}
#endif
