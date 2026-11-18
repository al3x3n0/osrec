/* Exercise descriptor loops at every count and mask boundary. */
#include <stdint.h>
struct check {const volatile uint64_t *address;uint64_t mask,value;};
static uint64_t descriptors[33];
struct check flat_pretranslated_checks[34];
uint64_t flat_pretranslated_check_count;
#include "cases.h"
int test_main(void)
{
    for(unsigned f=0;f<sizeof probes/sizeof probes[0];f++)
    for(unsigned count=0;count<=33;count++) {
        flat_pretranslated_check_count=count;
        for(unsigned i=0;i<count;i++) {
            uint64_t value=0x1020304050607080ull*(i+1);
            descriptors[i]=value;
            flat_pretranslated_checks[i]=(struct check){descriptors+i,UINT64_MAX>>i,value};
        }
        /* Any access beyond the live table dereferences an invalid address. */
        flat_pretranslated_checks[count]=(struct check){0,UINT64_MAX,0};
        if(probes[f]()!=1)return 10;
        for(unsigned i=0;i<count;i++)for(unsigned bit=0;bit<64;bit++) {
            descriptors[i]^=1ull<<bit;
            int expected=!(flat_pretranslated_checks[i].mask&(1ull<<bit));
            if(probes[f]()!=expected)return 20;
            descriptors[i]^=1ull<<bit;
        }
        /* Rejection at any position must not read the following descriptor. */
        for(unsigned i=0;i<count;i++) {
            struct check next=flat_pretranslated_checks[i+1];
            flat_pretranslated_checks[i+1].address=0;
            descriptors[i]^=1;
            if(probes[f]()!=0)return 30;
            descriptors[i]^=1;flat_pretranslated_checks[i+1]=next;
        }
    }
    return 0;
}
