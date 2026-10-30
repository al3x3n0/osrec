#ifndef OSREC_BUFFER_TYPES_H
#define OSREC_BUFFER_TYPES_H
#include <stddef.h>
#include <stdint.h>
/* The guard separates array ends from the next buffer's first element. */
typedef struct {uint32_t words[4];uint64_t guard;} Buffer;
uint64_t BufferStep(uint64_t operation,void *output);
uint64_t ProviderTick(void);
#endif
