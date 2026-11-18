#ifndef FLAT_TRANSLATION_WATCH_H
#define FLAT_TRANSLATION_WATCH_H
#include <stdint.h>
#include <stddef.h>
#ifndef OSREC_TRACK_PRETRANSLATED_WRITES
#define OSREC_TRACK_PRETRANSLATED_WRITES 0
#endif
#if OSREC_TRACK_PRETRANSLATED_WRITES != 0 && OSREC_TRACK_PRETRANSLATED_WRITES != 1
#error OSREC_TRACK_PRETRANSLATED_WRITES must be 0 or 1
#endif
struct pretranslated_check {const volatile uint64_t *address;uint64_t mask,value;};
/* Watch whole dependency pages: writes to unrelated entries may invalidate
 * conservatively. No descriptor value or RAM translation is cached here. */
static inline int flat_translation_write_overlaps(const struct pretranslated_check *checks,
                                                 size_t count,uintptr_t address,size_t bytes)
{
    if(!bytes)return 0;
    if(bytes-1>UINTPTR_MAX-address)return 1;
    uintptr_t first=address&~(uintptr_t)4095,last=(address+bytes-1)&~(uintptr_t)4095;
    for(size_t i=0;i<count;i++) {
        uintptr_t page=(uintptr_t)checks[i].address&~(uintptr_t)4095;
        if(first<=page && page<=last)return 1;
    }
    return 0;
}
#endif
