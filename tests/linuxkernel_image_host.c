#include "linuxkernel_embedded.h"
#ifdef OSREC_FREESTANDING
#include "standalone.h"
#define assert(test) do { if(!(test)){fprintf(stderr,"image assertion at line %u\n",(unsigned)__LINE__);lk_host_exit(1);} } while(0)
#else
#include <assert.h>
#include <stdio.h>
#endif
static void invalid(struct lk_el0_image *image,enum lk_el0_status expected)
{
    struct lk_el0_native *n=(void *)1;struct lk_el0_diagnostic d;
    assert(lk_el0_native_open_image(image,&n,&d)==expected && !n);
}
int main(void)
{
    struct lk_el0_image image=osrec_checkpoint.image;
    image.abi++;invalid(&image,LK_EL0_BAD_ARGUMENT);
    image=osrec_checkpoint.image;image.native.data=NULL;invalid(&image,LK_EL0_BAD_ARGUMENT);
    image=osrec_checkpoint.image;image.counters.size--;invalid(&image,LK_EL0_BAD_ARGUMENT);
    image=osrec_checkpoint.image;
    struct lk_el0_extent extent=image.extents[0];extent.offset=image.memory_size;
    image.extents=&extent;image.extent_count=1;invalid(&image,LK_EL0_BAD_ARGUMENT);
    image=osrec_checkpoint.image;image.native.size--;invalid(&image,LK_EL0_FAULT);
    image=osrec_checkpoint.image;image.memory_size+=4096;invalid(&image,LK_EL0_FAULT);
    image=osrec_checkpoint.image;
    struct lk_el0_counter counter={0,0xffff,0};image.counters=(struct lk_el0_blob){&counter,sizeof counter};
    invalid(&image,LK_EL0_BAD_ARGUMENT);
    struct lk_el0_native *n=NULL;struct lk_el0_diagnostic d;
    assert(lk_el0_native_open_image(&osrec_checkpoint.image,&n,&d)==LK_EL0_OK);
    assert(lk_el0_native_close(n)==LK_EL0_OK);
    puts("embedded image validation and failure cleanup passed");return 0;
}
