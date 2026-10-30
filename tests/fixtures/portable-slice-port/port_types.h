#ifndef OSREC_PORTABLE_FIXTURE_TYPES_H
#define OSREC_PORTABLE_FIXTURE_TYPES_H
#include <stdint.h>
#include <stddef.h>
typedef struct {uint64_t value,calls;} Ledger;
uint64_t Provider(uint64_t,void *);
uint64_t Add(uint64_t,void *);
int64_t Adjust(int64_t,void *);
#define APPLY_DELTA(n,p) Provider(n,p)
#endif
