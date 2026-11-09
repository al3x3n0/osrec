#ifndef OSREC_FLAT_MEMORY_H
#define OSREC_FLAT_MEMORY_H
#include <stddef.h>
#include <stdint.h>
/* Backing spans are canonical: different virtual aliases resolve to the same
 * bytes. All pointers refer to linked target RAM, never OS mapping handles. */
struct flat_ram {uint64_t pa,bytes;unsigned char *data;};
struct flat_mapping {uint64_t va,pa,bytes,attrs;};
struct flat_memory {
    const struct flat_ram *ram;size_t ram_count;
    const struct flat_mapping *kernel;size_t kernel_count;
    uint64_t ttbr0,tcr;
};
enum flat_access {FLAT_READ,FLAT_WRITE,FLAT_EXECUTE};
enum flat_memory_fault {FLAT_CROSS_PAGE=0x100,FLAT_MISSING_RAM,FLAT_ADDRESS_SIZE};
struct flat_translation {unsigned char *data;uint64_t pa,attrs,far;unsigned fault;};
void *flat_physical(const struct flat_memory *,uint64_t,size_t);
/* 4 KiB captured stage-1 tables, 25..48 bits, table AP/XN restrictions and AF.
 * Faults 1..63 are architectural FSCs. Address-size FSC zero uses the distinct
 * FLAT_ADDRESS_SIZE code; missing backing and cross-page operations are explicit
 * boundaries. No host exception is requested. */
struct flat_translation flat_translate(const struct flat_memory *,uint64_t,size_t,enum flat_access,int user);
#endif
