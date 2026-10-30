#include "port_types.h"
uint64_t Add(uint64_t delta,void *output){return APPLY_DELTA(delta,output);}
int64_t Adjust(int64_t delta,void *output){return (int64_t)APPLY_DELTA((uint64_t)delta,output);}
