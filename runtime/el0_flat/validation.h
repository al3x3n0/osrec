#ifndef FLAT_VALIDATION_H
#define FLAT_VALIDATION_H
/* Exported runtime-config.h overrides this for execution-only images. */
#ifndef OSREC_FLAT_VALIDATION
#define OSREC_FLAT_VALIDATION 1
#endif
#if OSREC_FLAT_VALIDATION != 0 && OSREC_FLAT_VALIDATION != 1
#error OSREC_FLAT_VALIDATION must be 0 or 1
#endif
#endif
