/* Synthetic application for the discovered joint-checkpoint demo. */
#include "osrec_application.h"
_Alignas(8) uint64_t app_output[2];
uint64_t app_returns[6], app_count, app_failed, app_feedback[3];
uintptr_t app_continuation_address;

void osrec_application_main(void)
{
    /* Volatile keeps these values in live user-stack storage across syscalls. */
    volatile struct { uint64_t carry, checksum, step; } continuation = {
        UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xcbf29ce484222325), 0
    };
    app_continuation_address = (uintptr_t)&continuation;
    const uint64_t numbers[2] = {UINT64_C(0x100000051), UINT64_C(0x100000052)};
    const uint64_t deltas[6] = {
        UINT64_C(0x100000005), UINT64_C(0xfffffffffffffffd), 9,
        UINT64_C(0xfffffffeffffffff), UINT64_C(0x200000003), UINT64_C(0xfffffffffffffff9)
    };
    for (unsigned i = 0; i < 6; ++i) {
        uint64_t prior = continuation.carry;
        uint64_t number = numbers[(prior >> 1) & 1];
        uint64_t delta = deltas[i] ^ (prior & 63);
        app_output[0] = prior;
        app_output[1] = (prior >> 8) & 255;
        uint64_t raw = (uint64_t)(i < 2 ?
            osrec_app_syscall_prefix(number, delta, (uintptr_t)app_output, 0, 0, 0, 0) :
            osrec_app_syscall(number, delta, (uintptr_t)app_output, 0, 0, 0, 0));
        app_returns[i] = raw;
        ++app_count;
        app_failed |= app_output[0] != raw || app_output[1] != i + 1;
        continuation.carry = raw ^ (app_output[1] << 32) ^ (prior << 1);
        continuation.checksum = (continuation.checksum ^ raw ^ app_output[1]) * UINT64_C(0x100000001b3);
        continuation.step = i + 1;
    }
    app_feedback[0] = continuation.carry;
    app_feedback[1] = continuation.checksum;
    app_feedback[2] = continuation.step;
}
