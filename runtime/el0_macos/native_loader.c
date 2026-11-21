#define _DARWIN_C_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <unistd.h>

enum { ELF_X = 1, ELF_W = 2, ELF_R = 4 };
enum { TRAP_LAUNCH = 0x410, TRAP_ENTRY = 0x411, TRAP_COMPLETE = 0x412, TRAP_EXIT = 0x413 };
#define NZCV UINT32_C(0xf0000000)
#define NON_EL0 (31 | (3 << 20))
#define BRK(immediate) (UINT32_C(0xd4200000) | ((immediate) << 5))

struct execution {
    uint64_t version, base, size, entry, completion, result, zero_bytes, segment_count;
    uint64_t guest_state, shadow, uart, user_entry, native_stack, active, events, event_capacity, alias_count;
};

struct segment {
    uint64_t address, offset, file_size, memory_size, flags;
};

struct alias {
    uint64_t address, backing, size, flags;
};

struct registers {
    uint64_t x[31], sp, pc, pstate;
    uint8_t vectors[32][16];
    uint32_t fpsr, fpcr;
};

struct observation {
    uint64_t signal, code, syndrome, pc, pstate, x0, far;
};

struct entry_observation {
    struct observation stop;
    uint64_t reached, matched, actual_sp, private_sp, mode;
    struct registers registers;
};

_Static_assert(sizeof(struct registers) == 792 && sizeof(struct entry_observation) == 888, "native evidence ABI");

static struct execution run;
static struct registers expected;
static struct entry_observation entry;
static struct observation completion;
static sigjmp_buf host;
static size_t page;
static uint8_t *permissions;
static uint32_t original_entry_word;
static volatile sig_atomic_t launching = 1, patch_error;

static void fail(const char *message)
{
    fprintf(stderr, "%s\n", message);
    exit(1);
}

static void mach_check(kern_return_t status, const char *operation, uint64_t address)
{
    if (status != KERN_SUCCESS) {
        fprintf(stderr, "%s at %#" PRIx64 ": %s\n", operation, address, mach_error_string(status));
        exit(1);
    }
}

static void *at(uint64_t address, uint64_t bytes)
{
    if (address < run.base || bytes > run.size || address - run.base > run.size - bytes)
        return NULL;
    return (void *)(uintptr_t)address;
}

static void *accessible(uint64_t address, uint64_t bytes, unsigned flags)
{
    void *ptr = at(address, bytes);
    if (!ptr || !bytes)
        return ptr;
    size_t first = (address - run.base) / page;
    size_t last = (address - run.base + bytes - 1) / page;
    for (size_t i = first; i <= last; i++)
        if ((permissions[i] & flags) != flags)
            return NULL;
    return ptr;
}

static int protection(unsigned flags)
{
    return (flags & ELF_R ? PROT_READ : 0) | (flags & ELF_W ? PROT_WRITE : 0) |
        (flags & ELF_X ? PROT_EXEC : 0);
}

static void protect_image(void)
{
    size_t pages = run.size / page;
    for (size_t first = 0, next; first < pages; first = next) {
        unsigned flags = permissions[first];
        for (next = first + 1; next < pages && permissions[next] == flags; next++)
            ;
        void *start = (void *)(uintptr_t)(run.base + first * page);
        size_t size = (next - first) * page;
        if (flags & ELF_X)
            __builtin___clear_cache(start, (char *)start + size);
        if (mprotect(start, size, protection(flags)))
            fail("cannot set native ELF segment protections");
    }
}

static void load_segments(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (!file)
        fail("cannot open checkpoint ELF");
    mach_vm_address_t address = run.base;
    mach_check(mach_vm_allocate(mach_task_self(), &address, run.size, VM_FLAGS_FIXED), "allocate native ELF", address);
    permissions = calloc(run.size / page, 1);
    if (!permissions)
        fail("cannot allocate native permissions");
    uint64_t end = run.base;
    for (uint64_t i = 0; i < run.segment_count; i++) {
        struct segment seg;
        if (fread(&seg, sizeof(seg), 1, stdin) != 1 || !seg.memory_size || seg.address < end ||
            seg.file_size > seg.memory_size || !at(seg.address, seg.memory_size) ||
            (seg.flags != ELF_R && seg.flags != (ELF_R | ELF_X) && seg.flags != (ELF_R | ELF_W)))
            fail("invalid native ELF load segment");
        end = seg.address + seg.memory_size;
        for (size_t j = (seg.address - run.base) / page; j <= (end - 1 - run.base) / page; j++) {
            permissions[j] |= seg.flags;
            if ((permissions[j] & (ELF_W | ELF_X)) == (ELF_W | ELF_X))
                fail("native ELF has writable and executable bytes in the same host page");
        }
        if (seg.file_size && (seg.offset > INT64_MAX || fseeko(file, (off_t)seg.offset, SEEK_SET) ||
            fread((void *)(uintptr_t)seg.address, 1, seg.file_size, file) != seg.file_size))
            fail("short native checkpoint load");
    }
    fclose(file);
}

static void install_aliases(void)
{
    uint64_t end = 0;
    for (uint64_t i = 0; i < run.alias_count; i++) {
        struct alias alias;
        if (fread(&alias, sizeof(alias), 1, stdin) != 1 || !alias.size || alias.address < end ||
            alias.address < UINT64_C(0x100000000) || alias.size > UINT64_MAX - alias.address ||
            (alias.address | alias.backing | alias.size) % page ||
            (alias.flags != ELF_R && alias.flags != (ELF_R | ELF_X) && alias.flags != (ELF_R | ELF_W)) ||
            !accessible(alias.backing, alias.size, (unsigned)alias.flags) ||
            (alias.address + alias.size > run.base && alias.address < run.base + run.size))
            fail("invalid native host alias");
        end = alias.address + alias.size;
        mach_vm_address_t address = alias.address;
        vm_prot_t current, maximum;
        mach_check(mach_vm_remap(mach_task_self(), &address, alias.size, 0, VM_FLAGS_FIXED,
                                 mach_task_self(), alias.backing, FALSE, &current, &maximum, VM_INHERIT_NONE),
                   "share native ELF backing", alias.address);
        if (mprotect((void *)(uintptr_t)address, alias.size, protection((unsigned)alias.flags)))
            fail("cannot set native alias permissions");
    }
}

static bool breakpoint(const struct observation *obs, unsigned immediate)
{
    return obs->signal == SIGTRAP && obs->syndrome >> 26 == 0x3c && (obs->syndrome & 0xffff) == immediate &&
        !(obs->pstate & NON_EL0);
}

static void observe_entry(const struct observation *obs, mcontext_t cpu)
{
    entry.stop = *obs;
    entry.reached = 1;
    const uint64_t *active = accessible(run.active, 8, ELF_R);
    const uint64_t *control = active ? accessible(*active, 72, ELF_R) : NULL;
    const uint64_t *mode = accessible(run.shadow + 80, 8, ELF_R);
    if (!control || !mode)
        return;
    entry.mode = *mode;
    entry.private_sp = control[1];
    entry.actual_sp = cpu->__ss.__sp;
    struct registers *regs = &entry.registers;
    memcpy(regs->x, cpu->__ss.__x, sizeof(cpu->__ss.__x));
    regs->x[29] = cpu->__ss.__fp;
    regs->x[30] = cpu->__ss.__lr;
    regs->pc = obs->pc;
    regs->sp = run.native_stack ? entry.actual_sp : control[0];
    regs->pstate = (obs->pstate & NZCV) | control[8];
    memcpy(regs->vectors, cpu->__ns.__v, sizeof(regs->vectors));
    regs->fpsr = cpu->__ns.__fpsr;
    regs->fpcr = cpu->__ns.__fpcr;
    entry.matched = !entry.mode && control[3] == run.guest_state &&
        control[0] == expected.sp && control[8] == (expected.pstate & ~UINT64_C(0xf0000000)) &&
        entry.actual_sp == (run.native_stack ? expected.sp : entry.private_sp) &&
        !memcmp(regs, &expected, sizeof(expected));
}

static void trap(int signal, siginfo_t *info, void *context)
{
    mcontext_t cpu = ((ucontext_t *)context)->uc_mcontext;
    struct observation obs = {(uint64_t)signal, (uint64_t)info->si_code, cpu->__es.__esr,
                              cpu->__ss.__pc, cpu->__ss.__cpsr, cpu->__ss.__x[0], cpu->__es.__far};
    if (launching && breakpoint(&obs, TRAP_LAUNCH)) {
        launching = 0;
        memset(cpu->__ss.__x, 0, sizeof(cpu->__ss.__x));
        cpu->__ss.__fp = cpu->__ss.__lr = 0;
        cpu->__ss.__pc = run.entry;
        cpu->__ss.__cpsr &= ~NZCV;
        memset(&cpu->__ns, 0, sizeof(cpu->__ns));
        return;
    }
    if (!entry.reached && obs.pc == run.user_entry && breakpoint(&obs, TRAP_ENTRY)) {
        observe_entry(&obs, cpu);
        if (entry.matched) {
            void *start = (void *)(uintptr_t)(run.user_entry & ~(page - 1));
            uint32_t *word = (void *)(uintptr_t)run.user_entry;
            if (!mprotect(start, page, PROT_READ | PROT_WRITE)) {
                *word = original_entry_word;
                __builtin___clear_cache((char *)word, (char *)(word + 1));
                if (!mprotect(start, page, PROT_READ | PROT_EXEC))
                    return;
            }
            patch_error = errno;
        }
    }
    completion = obs;
    siglongjmp(host, 1);
}

static void write_evidence(void)
{
    const uint64_t *result = accessible(run.result, 320, ELF_R);
    const void *guest = accessible(run.guest_state, sizeof(expected), ELF_R);
    const void *shadow = accessible(run.shadow, 104, ELF_R);
    if (!result || !guest || !shadow || result[11] > 4096 || result[3] > run.event_capacity)
        fail("invalid native completion evidence");
    size_t uart_bytes = result[11], event_bytes = result[3] * 80;
    const void *uart = accessible(run.uart, uart_bytes, ELF_R);
    const void *events = accessible(run.events, event_bytes, ELF_R);
    if (fwrite(&entry, sizeof(entry), 1, stdout) != 1 ||
        fwrite(&completion, sizeof(completion), 1, stdout) != 1 ||
        fwrite(result, 320, 1, stdout) != 1 || fwrite(guest, sizeof(expected), 1, stdout) != 1 ||
        fwrite(shadow, 104, 1, stdout) != 1 ||
        (uart_bytes && (!uart || fwrite(uart, 1, uart_bytes, stdout) != uart_bytes)) ||
        (event_bytes && (!events || fwrite(events, 1, event_bytes, stdout) != event_bytes)) || fflush(stdout))
        fail("cannot write native completion evidence");
}

int main(int argc, char **argv)
{
    if (argc != 2)
        fail("usage: native-loader checkpoint");
    page = (size_t)getpagesize();
    if (fread(&run, sizeof(run), 1, stdin) != 1 || run.version != 1 ||
        run.base < UINT64_C(0x100000000) || !run.size || run.size > (UINT64_C(4) << 30) ||
        (run.base | run.size) % page || run.size > UINT64_MAX - run.base ||
        !run.segment_count || run.segment_count > 65535 || run.alias_count > 65536 ||
        run.event_capacity > run.size / 80)
        fail("invalid native loader input");
    load_segments(argv[1]);
    const struct registers *initial = accessible(run.guest_state, sizeof(expected), ELF_R);
    uint32_t *user = accessible(run.user_entry, 4, ELF_R | ELF_X);
    uint32_t *done = accessible(run.completion, 8, ELF_R | ELF_X);
    if (!initial || !user || !done || (run.entry | run.user_entry | run.completion) % 4 ||
        run.user_entry == run.completion + 4 || run.user_entry == run.completion ||
        !accessible(run.entry, 4, ELF_R | ELF_X) || done[0] != 0xd2800ba8 || done[1] != 0xd4000001)
        fail("invalid native checkpoint entry or exit");
    expected = *initial;
    expected.pc = run.user_entry;
    if (run.zero_bytes) {
        uint64_t dczid;
        __asm__ volatile("mrs %0, dczid_el0" : "=r"(dczid));
        if ((dczid & 16) || (UINT64_C(4) << (dczid & 15)) != run.zero_bytes)
            fail("native DC ZVA geometry differs from the ELF contract");
    }
    original_entry_word = *user;
    *user = BRK(TRAP_ENTRY);
    done[0] = BRK(TRAP_COMPLETE);
    done[1] = BRK(TRAP_EXIT);
    protect_image();
    install_aliases();

    stack_t stack = {.ss_sp = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0),
                     .ss_size = 65536};
    struct sigaction action = {.sa_sigaction = trap, .sa_flags = SA_SIGINFO | SA_ONSTACK};
    if (stack.ss_sp == MAP_FAILED || sigaltstack(&stack, NULL) || sigfillset(&action.sa_mask) ||
        sigaction(SIGTRAP, &action, NULL) || sigaction(SIGILL, &action, NULL) ||
        sigaction(SIGSEGV, &action, NULL) || sigaction(SIGBUS, &action, NULL) ||
        sigaction(SIGFPE, &action, NULL))
        fail("cannot install native checkpoint signal boundaries");
    if (!sigsetjmp(host, 1)) {
        __asm__ volatile("brk #0x410" ::: "memory");
        fail("native launch trap returned to the loader");
    }
    if (patch_error)
        fail("cannot restore original instruction at native user entry");
    write_evidence();
    return 0;
}
