/* Execute a restored syscall context through the real captured kernel backend.
 * Deliberately does not resume application instructions: the public checkpoint
 * caller owns that gateway. Repeating the returned context is never a workload. */
#include "osrec/linuxkernel_el0_native.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc,char **argv)
{
    if(argc<2 || argc>3){fprintf(stderr,"usage: %s PACKAGE [SYSCALL_NUMBER]\n",argv[0]);return 2;}
    struct lk_el0_native *native=NULL;
    struct lk_el0_diagnostic d;
    enum lk_el0_status status=lk_el0_native_open(argv[1],&native,&d);
    if(status!=LK_EL0_OK){fprintf(stderr,"open status=%u reason=%"PRIu64" detail=%"PRIu64"\n",status,d.reason,d.detail);return 1;}
    struct osrec_context user=*lk_el0_native_initial(native);
    if(argc==3)user.x[8]=strtoull(argv[2],NULL,0);
    struct lk_el0_result result;
    status=lk_el0_veneer(lk_el0_native_kernel(native),&user,0xd4000001,&result);
    printf("{\"status\":%u,\"syscall\":%"PRIu64",\"result\":%"PRId64",\"pc\":\"0x%"PRIx64"\",\"reason\":%"PRIu64",\"where\":\"0x%"PRIx64"\",\"detail\":\"0x%"PRIx64"\",\"far\":\"0x%"PRIx64"\"}\n",status,user.x[8],(int64_t)result.context.x[0],result.context.pc,result.diagnostic.reason,result.diagnostic.pc,result.diagnostic.detail,result.diagnostic.far);
    if(lk_el0_native_close(native)!=LK_EL0_OK)return 1;
    return status==LK_EL0_OK?0:1;
}
