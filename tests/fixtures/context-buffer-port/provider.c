#include "buffer_types.h"
static uint64_t visits;
static uint64_t Tick(void)
{
    visits+=3;
    return visits;
}
uint64_t ProviderTick(void)
{
    return Tick();
}
