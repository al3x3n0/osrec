#include "osrec/recorder.h"
#include <stdio.h>
#include <string.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #expr); \
    return 1; } } while (0)

int main(void)
{
    const char hash[65] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    unsigned char storage[128];
    struct osrec_buffer b;
    memset(storage, 0xa5, sizeof(storage));
    CHECK(osrec_begin(&b, storage, 83, hash) == -1);
    CHECK(b.failed && b.used == 8);
    CHECK(storage[83] == 0xa5);

    /* Begin(84) + value record(20) + end(12) exactly fills capacity. */
    CHECK(osrec_begin(&b, storage, 116, hash) == 0);
    uint64_t value = UINT64_C(0x0102030405060708);
    CHECK(osrec_values(&b, OSREC_INPUT, 10, &value, 1) == 0);
    const unsigned char wire[] = {8, 7, 6, 5, 4, 3, 2, 1};
    CHECK(memcmp(storage + 96, wire, 8) == 0);
    CHECK(osrec_finish(&b) == 0);
    CHECK(b.used == 116 && b.finished && !b.failed);
    CHECK(storage[116] == 0xa5);
    CHECK(osrec_values(&b, OSREC_INPUT, 10, &value, 1) == -1);
    CHECK(b.failed);

    CHECK(osrec_begin(&b, storage, 115, hash) == 0);
    CHECK(osrec_values(&b, OSREC_INPUT, 10, &value, 1) == 0);
    CHECK(osrec_finish(&b) == -1);
    CHECK(b.failed && !b.finished && b.used == 104);
    CHECK(osrec_append(&b, OSREC_END, 0, NULL, 0) == -1);

    CHECK(osrec_begin(&b, storage, sizeof(storage), hash) == 0);
    CHECK(osrec_values(&b, OSREC_INPUT, 10, &value, SIZE_MAX) == -1);
    CHECK(b.used == 84 && b.failed);
    CHECK(osrec_begin(&b, storage, sizeof(storage), hash) == 0);
    CHECK(osrec_append(&b, OSREC_INPUT, 10, NULL, 1) == -1);
    CHECK(b.used == 84 && b.failed);
    CHECK(osrec_begin(&b, NULL, 128, hash) == -1);
    return 0;
}
