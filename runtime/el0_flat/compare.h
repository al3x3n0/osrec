#ifndef FLAT_COMPARE_H
#define FLAT_COMPARE_H
#include <stdint.h>

/* Only use for already-admitted scalar loads. AArch64 branches once after a
 * CMP/CCMP chain. A mismatch installs
 * NZCV=0, keeping Z clear through every remaining conditional comparison. */
static inline int flat_equal2(uint64_t a,uint64_t b,uint64_t c,uint64_t d)
{
#if defined(__aarch64__)
    int equal;
    __asm__("cmp %1,%2\n\tccmp %3,%4,#0,eq\n\tcset %w0,eq" : "=r"(equal)
            : "r"(a),"r"(b),"r"(c),"r"(d) : "cc");
    return equal;
#else
    return (a==b) & (c==d);
#endif
}
static inline int flat_equal3(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f)
{
#if defined(__aarch64__)
    int equal;
    __asm__("cmp %1,%2\n\tccmp %3,%4,#0,eq\n\tccmp %5,%6,#0,eq\n\tcset %w0,eq" : "=r"(equal)
            : "r"(a),"r"(b),"r"(c),"r"(d),"r"(e),"r"(f) : "cc");
    return equal;
#else
    return (a==b) & (c==d) & (e==f);
#endif
}
static inline int flat_equal4(uint64_t a,uint64_t b,uint64_t c,uint64_t d,
                              uint64_t e,uint64_t f,uint64_t g,uint64_t h)
{
#if defined(__aarch64__)
    int equal;
    __asm__("cmp %1,%2\n\tccmp %3,%4,#0,eq\n\tccmp %5,%6,#0,eq\n\tccmp %7,%8,#0,eq\n\tcset %w0,eq" : "=r"(equal)
            : "r"(a),"r"(b),"r"(c),"r"(d),"r"(e),"r"(f),"r"(g),"r"(h) : "cc");
    return equal;
#else
    return (a==b) & (c==d) & (e==f) & (g==h);
#endif
}
#endif
