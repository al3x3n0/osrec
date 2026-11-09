/* Native restored application + captured-kernel library. No injected calls. */
#include "osrec/linuxkernel_el0_native.h"
#include "linuxkernel_checkpoint_report.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void *read_file(const char *name,size_t item,size_t *count)
{
    FILE *f=fopen(name,"rb");if(!f)return NULL;
    if(fseek(f,0,SEEK_END)){fclose(f);return NULL;}
    long bytes=ftell(f);if(bytes<0 || (size_t)bytes%item || bytes>24000000){fclose(f);return NULL;}
    rewind(f);void *data=malloc(bytes?bytes:1);
    if(!data || fread(data,1,bytes,f)!=(size_t)bytes){free(data);fclose(f);return NULL;}
    fclose(f);*count=bytes/item;return data;
}
int main(int argc,char **argv)
{
    if(argc!=4 && argc!=5){fprintf(stderr,"usage: %s PACKAGE COUNTERS.bin|- CALLS.json [MMIO.bin]\n",argv[0]);return 2;}
    struct lk_el0_native *native=NULL;struct lk_el0_diagnostic d;
    enum lk_el0_status status=lk_el0_native_open(argv[1],&native,&d);
    if(status!=LK_EL0_OK){fprintf(stderr,"open status=%u detail=%"PRIu64"\n",status,d.detail);return 1;}
    if(strcmp(argv[2],"-")) {
        size_t count=0;struct lk_el0_counter *counters=read_file(argv[2],sizeof *counters,&count);
        if(!counters || lk_el0_native_counters(native,counters,count)!=LK_EL0_OK)return 2;
        free(counters);
    }
    if(argc==5) {
        size_t count=0;struct lk_el0_mmio *mmio=read_file(argv[4],sizeof *mmio,&count);
        if(!mmio || lk_el0_native_mmio(native,mmio,count)!=LK_EL0_OK)return 2;
        free(mmio);
    }
    struct lk_el0_event *events=NULL;
    if(lk_el0_native_trace_allocate(native,30000,&events)!=LK_EL0_OK)return 2;
    struct lk_el0_result result;
    status=lk_el0_native_execute(native,NULL,&result);
    uint64_t count=lk_el0_native_events(native),used=lk_el0_native_counters_consumed(native);
    uint64_t mmio_used=lk_el0_native_mmio_consumed(native);
    FILE *out=fopen(argv[3],"w");if(!out)return 2;
    int report=checkpoint_report(out,"native-checkpoint",events,count,&result,used,mmio_used);
    if(fclose(out))report=-1;
    printf("{\"events\":%"PRIu64",\"status\":%u,\"stop_code\":%"PRIu64",\"pc\":\"0x%"PRIx64"\",\"detail\":\"0x%"PRIx64"\",\"far\":\"0x%"PRIx64"\",\"counters\":%"PRIu64"}\n",count,status,result.diagnostic.reason,result.diagnostic.pc,result.diagnostic.detail,result.diagnostic.far,used);
    lk_el0_native_close(native);
    return !report && status==LK_EL0_BOUNDARY && result.diagnostic.reason==OSREC_STOP_BOUNDARY?0:1;
}
