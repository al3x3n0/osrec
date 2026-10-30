#include "port_types.h"
enum {PRIVATE_LOW=7};
#define PRIVATE_HIGH UINT64_C(0x100000000)
static const uint64_t private_seed=PRIVATE_HIGH+PRIVATE_LOW;
static Ledger ledger={.value=private_seed,.calls=0};
static Ledger *alias=&ledger;
uint64_t Provider(uint64_t delta,void *output)
{
    alias->value+=delta;++alias->calls;
    unsigned char *bytes=output;
    for(unsigned i=0;i<8;++i)bytes[i]=(unsigned char)(alias->value>>(8*i));
    return alias->value;
}
