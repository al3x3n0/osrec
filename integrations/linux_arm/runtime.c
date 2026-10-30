/* Minimal ARM Linux EABI runtime: no allocator, loader or external libc.
 * This handles replay diagnostics only; modeled kernel reads remain unchanged.
 */
#include <stddef.h>
#include "stdio.h"

static FILE error_stream = {2};
FILE *stderr = &error_stream;

static long write_bytes(int fd, const char *text, size_t size)
{
    register long r0 __asm__("r0") = fd;
    register long r1 __asm__("r1") = (long)text;
    register long r2 __asm__("r2") = (long)size;
    register long r7 __asm__("r7") = 4;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory", "cc");
    return r0;
}

int fputs(const char *text, FILE *stream)
{
    size_t remaining = 0;
    while (text[remaining]) ++remaining;
    while (remaining) {
        long count = write_bytes(stream->fd, text, remaining);
        if (count == -4) continue; /* Linux EINTR. */
        if (count <= 0 || (size_t)count > remaining) return -1;
        text += count;
        remaining -= (size_t)count;
    }
    return 0;
}

int puts(const char *text)
{
    FILE output = {1};
    if (fputs(text, &output) < 0) return -1;
    return fputs("\n", &output);
}

int strcmp(const char *left, const char *right)
{
    while (*left && *left == *right) { ++left; ++right; }
    return (unsigned char)*left - (unsigned char)*right;
}

void *memcpy(void *destination, const void *source, size_t size)
{
    unsigned char *out = destination;
    const unsigned char *in = source;
    for (size_t i = 0; i < size; ++i) out[i] = in[i];
    return destination;
}

void *memset(void *destination, int value, size_t size)
{
    unsigned char *out = destination;
    for (size_t i = 0; i < size; ++i) out[i] = (unsigned char)value;
    return destination;
}

void __aeabi_memcpy(void *out, const void *in, size_t size) { (void)memcpy(out, in, size); }
void __aeabi_memcpy4(void *out, const void *in, size_t size) { (void)memcpy(out, in, size); }
void __aeabi_memcpy8(void *out, const void *in, size_t size) { (void)memcpy(out, in, size); }
void __aeabi_memclr(void *out, size_t size) { (void)memset(out, 0, size); }
void __aeabi_memclr4(void *out, size_t size) { (void)memset(out, 0, size); }
void __aeabi_memclr8(void *out, size_t size) { (void)memset(out, 0, size); }
