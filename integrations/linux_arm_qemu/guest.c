/* Limited Linux ABI adapter for the unchanged replay ELF, not a Linux kernel.
 * Only ARM Linux write(4) and exit(1) are supported. Single CPU, IRQs masked.
 */
#include <stdint.h>
#include "config.h"

extern const unsigned char replay_image[];
static uint32_t table[4096] __attribute__((aligned(16384)));

static void uart(char c)
{
    volatile uint32_t *registers = (volatile uint32_t *)0x09000000;
    while (registers[6] & (1U << 5)) {}
    registers[0] = (unsigned char)c;
}

__attribute__((noreturn)) static void finish(uint32_t status)
{
    uint32_t block[2] = {0x20026, status};
    register uint32_t r0 __asm__("r0") = 0x20;
    register void *r1 __asm__("r1") = block;
    __asm__ volatile("svc #0x123456" : "+r"(r0) : "r"(r1) : "memory");
    for (;;) {}
}

__attribute__((noreturn)) void fatal(void)
{
    const char *message = "ABI adapter failed\n";
    while (*message) uart(*message++);
    finish(125);
}

uint32_t linux_syscall(uint32_t *registers, uint32_t saved_status)
{
    if ((saved_status & 31) != 0x10) fatal();
    if (registers[7] == 1) finish(registers[0]);
    if (registers[7] != 4) fatal();
    if (registers[0] != 1 && registers[0] != 2) return (uint32_t)-9;
    uint32_t address = registers[1], size = registers[2];
    if (address >= 0x100000 || size > 0x100000 - address) return (uint32_t)-14;
    const char *text = (const char *)address;
    for (uint32_t i = 0; i < size; ++i) uart(text[i]);
    return size;
}

extern void enter_user(uint32_t entry, uint32_t stack);
void guest_main(void)
{
    unsigned char *memory = (unsigned char *)0x40000000;
    /* QEMU initializes RAM to zero; copy only file-backed ELF segments. */
    static const uint32_t segments[][2] = ELF_LOAD_SEGMENTS;
    for (unsigned segment = 0; segment < sizeof(segments)/sizeof(segments[0]); ++segment) {
        uint32_t begin = segments[segment][0], end = begin + segments[segment][1];
        for (uint32_t i = begin; i < end; ++i) memory[i] = replay_image[i];
    }
    /* Identity map the adapter and devices; map low ELF addresses into RAM. */
    for (uint32_t i = 0; i < 4096; ++i) table[i] = (i << 20) | 0xc02;
    table[0] = 0x40000c02;
    uint32_t base = (uint32_t)table, domain = 1, zero = 0, control;
    __asm__ volatile("mcr p15,0,%0,c2,c0,2\n"
                     "mcr p15,0,%1,c2,c0,0\n"
                     "mcr p15,0,%2,c3,c0,0\n"
                     "mcr p15,0,%0,c8,c7,0\n"
                     "dsb\n"
                     "isb" : : "r"(zero), "r"(base), "r"(domain) : "memory");
    __asm__ volatile("mrc p15,0,%0,c1,c0,0" : "=r"(control));
    control = (control & ~((1U << 13) | (1U << 12) | (1U << 2))) | 1;
    __asm__ volatile("mcr p15,0,%0,c1,c0,0\n isb" : : "r"(control) : "memory");
    uint32_t *stack = (uint32_t *)0xff000;
    char *argument = (char *)0xfe000;
    const char *value = DESCRIBE ? "--describe" : "replay";
    for (unsigned i = 0;; ++i) { argument[i] = value[i]; if (!value[i]) break; }
    stack[0] = DESCRIBE ? 2 : 1;
    stack[1] = 0xfe000;
    stack[2] = DESCRIBE ? 0xfe000 : 0;
    stack[3] = 0; /* argv terminator (describe), or empty environment. */
    stack[4] = 0;
    stack[5] = 0; /* auxv terminator; runtime does not inspect auxv. */
    stack[6] = 0;
    enter_user(ELF_ENTRY, (uint32_t)stack);
    fatal();
}
