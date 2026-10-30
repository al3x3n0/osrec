#ifndef OSREC_GRAPH_FIXTURE_TYPES_H
#define OSREC_GRAPH_FIXTURE_TYPES_H
#include <stdint.h>
#include <stddef.h>
typedef struct Node {uint64_t value;uint32_t live,generation;struct Node *next;} Node;
uint64_t GraphStep(uint64_t,uint64_t,void *);
#endif
