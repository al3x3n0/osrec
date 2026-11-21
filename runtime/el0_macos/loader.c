#define _DARWIN_C_SOURCE
#include <Availability.h>
#include <Hypervisor/Hypervisor.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* The host driver admits the ELF and supplies the verified PT_LOAD fields. */
struct execution {
    uint64_t version, ram_base, ram_size, entry, completion, result;
    uint64_t mair, tcr, ttbr0, ttbr1, cpacr, sctlr, vectors, zero_bytes, segment_count;
    uint64_t guest_state, shadow_state, uart;
    uint64_t user_entry, native_stack, active, events, event_capacity;
};

struct segment {
    uint64_t address, offset, file_size, memory_size;
};

struct host_alias {
    uint64_t address, backing, size, flags;
};

struct mapping_window {
    uint64_t gate_pc, address, size, backing, backing_size;
};

enum mapping_op { HOST_MAP = 1, HOST_UNMAP, HOST_PROTECT, HOST_ACCESS_PREFIX, HOST_UACCESS };

struct uaccess_fixup {
    uint64_t pc, target;
};

struct uaccess {
    uint64_t read_entry, write_entry, count;
    struct uaccess_fixup *fixups;
    uint8_t *scratch;
    uint64_t page, flags, return_pc, direction;
    uint64_t calls, faults, faults_at_entry;
    bool active;
};

struct observation {
    uint64_t reason, syndrome, pc, pstate, x0, el1_esr, el1_elr, far, ipa;
    uint64_t sctlr, ttbr0, ttbr1, hcr;
};

struct checkpoint_registers {
    uint64_t x[31], sp, pc, pstate;
    uint8_t vectors[32][16];
    uint32_t fpsr, fpcr;
};

struct user_entry {
    struct observation stop;
    uint64_t reached, matched, actual_sp, private_sp, mode;
    struct checkpoint_registers registers;
};

_Static_assert(sizeof(struct checkpoint_registers) == 792, "checkpoint register ABI");
_Static_assert(sizeof(struct observation) == 104 && sizeof(struct user_entry) == 936, "host evidence ABI");
_Static_assert(sizeof(struct mapping_window) == 40, "host mapping window ABI");

static void fail(const char *message)
{
    fprintf(stderr, "%s\n", message);
    exit(1);
}

#define HV(operation) do { \
    hv_return_t status = (operation); \
    if (status != HV_SUCCESS) { \
        fprintf(stderr, "%s failed: %#x\n", #operation, (unsigned)status); \
        exit(1); \
    } \
} while (0)

static void *at(uint8_t *ram, const struct execution *run, uint64_t address, uint64_t size)
{
    if (address < run->ram_base || size > run->ram_size ||
        address - run->ram_base > run->ram_size - size)
        fail("address outside checkpoint RAM");
    return ram + (address - run->ram_base);
}

static void load(FILE *file, void *destination, uint64_t offset, uint64_t size)
{
    if (size && (fseeko(file, (off_t)offset, SEEK_SET) || fread(destination, 1, size, file) != size))
        fail("short checkpoint read");
}

static bool contains(uint64_t start, uint64_t length, uint64_t address, uint64_t size)
{
    return size <= length && address >= start && address - start <= length - size;
}

static bool overlaps(uint64_t a, uint64_t a_end, uint64_t b, uint64_t b_end)
{
    return a < b_end && b < a_end;
}

static hv_memory_flags_t memory_flags(uint64_t flags)
{
    hv_memory_flags_t permissions = HV_MEMORY_READ;
    if (flags & 1)
        permissions |= HV_MEMORY_EXEC;
    if (flags & 2)
        permissions |= HV_MEMORY_WRITE;
    return permissions;
}

static void create_vm(bool flat, uint64_t highest_alias_byte, bool ipa_4k)
{
    if (!flat) {
        HV(hv_vm_create(NULL));
        return;
    }
    if (__builtin_available(macOS 15.0, *)) {
        bool supported;
        HV(hv_vm_config_get_el2_supported(&supported));
        if (!supported)
            fail("flat EL0 memory requires Apple Silicon with Hypervisor EL2 configuration support");
        hv_vm_config_t config = hv_vm_config_create();
        HV(hv_vm_config_set_el2_enabled(config, true));
        if (ipa_4k) {
#if __MAC_OS_X_VERSION_MAX_ALLOWED >= 260000
            if (__builtin_available(macOS 26.0, *)) {
                HV(hv_vm_config_set_ipa_granule(config, HV_IPA_GRANULE_4KB));
            } else {
                fail("4 KiB IPA mappings require macOS 26 or later");
            }
#else
            fail("4 KiB IPA mappings require macOS 26 or later and a loader built with the macOS 26 SDK");
#endif
        }
        if (highest_alias_byte) {
            uint32_t default_bits, max_bits;
            HV(hv_vm_config_get_default_ipa_size(&default_bits));
            HV(hv_vm_config_get_max_ipa_size(&max_bits));
            if (max_bits < 64 && highest_alias_byte >> max_bits)
                fail("host alias exceeds the supported IPA width");
            if (default_bits < 64 && highest_alias_byte >> default_bits)
                HV(hv_vm_config_set_ipa_size(config, max_bits));
        }
        HV(hv_vm_create(config));
        os_release(config);
    } else {
        fail("flat EL0 memory requires macOS 15 or later");
    }
}

static void check_mapping_window(uint8_t *ram, const struct execution *run,
                                 const struct mapping_window *window, uint64_t granule,
                                 const struct host_alias *aliases, uint64_t alias_count)
{
    const uint32_t gate_code[] = { 0xd503201f, 0xd65f03c0 }; /* NOP; RET */
    if (!window->size || !window->backing_size ||
        (window->address | window->size | window->backing | window->backing_size) % granule ||
        window->size > UINT64_MAX - window->address ||
        overlaps(window->address, window->address + window->size,
                 run->ram_base, run->ram_base + run->ram_size))
        fail("invalid host mapping window");
    if (window->gate_pc % 4 || window->gate_pc == run->entry ||
        window->gate_pc == run->user_entry || window->gate_pc == run->completion ||
        memcmp(at(ram, run, window->gate_pc, sizeof(gate_code)), gate_code, sizeof(gate_code)))
        fail("invalid host mapping gate code");
    at(ram, run, window->backing, window->backing_size);
    for (uint64_t index = 0; index < alias_count; index++) {
        const struct host_alias *a = &aliases[index];
        if (overlaps(window->address, window->address + window->size, a->address, a->address + a->size))
            fail("host mapping window overlaps an initial alias");
    }
}

static uint64_t access_prefix(const struct mapping_window *window, uint64_t granule,
                              const uint8_t *permissions, uint64_t address, uint64_t bytes, uint64_t flags)
{
    if (!bytes || !contains(window->address, window->size, address, 1))
        return 0;
    uint64_t offset = address - window->address;
    uint64_t available = window->size - offset;
    if (bytes > available)
        bytes = available;
    uint64_t allowed = 0;
    while (allowed < bytes && (permissions[offset / granule] & flags) == flags) {
        uint64_t span = granule - offset % granule;
        if (span > bytes - allowed)
            span = bytes - allowed;
        allowed += span;
        offset += span;
    }
    return allowed;
}

static void start_uaccess(hv_vcpu_t vcpu, struct uaccess *copy, const struct execution *run,
                          const struct mapping_window *window, uint64_t granule, const uint8_t *permissions,
                          uint64_t dest, uint64_t source, uint64_t size, uint64_t flags)
{
    if (!copy->count || (flags != 4 && flags != 6))
        fail("invalid host user-copy operation");
    uint64_t address = flags == 4 ? source : dest;
    if (size && !contains(window->address, window->size, address, size))
        fail("host user-copy range outside the mapping window");

    uint64_t prefix = access_prefix(window, granule, permissions, address, size, flags);
    if (prefix < size) {
        HV(hv_vcpu_get_reg(vcpu, HV_REG_LR, &copy->return_pc));
        if (copy->return_pc % 4 || copy->return_pc == run->completion || copy->return_pc == window->gate_pc)
            fail("invalid host user-copy return address");

        copy->page = (address + prefix) & ~(granule - 1);
        copy->flags = permissions[(copy->page - window->address) / granule];
        copy->direction = flags;
        copy->faults_at_entry = copy->faults;
        if (!copy->flags) {
            if (!copy->scratch) {
                copy->scratch = mmap(NULL, granule, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
                if (copy->scratch == MAP_FAILED)
                    fail("cannot allocate a watched user-copy page");
            }
            HV(hv_vm_map(copy->scratch, copy->page, granule, HV_MEMORY_READ | HV_MEMORY_WRITE));
        } else {
            HV(hv_vm_protect(copy->page, granule, HV_MEMORY_READ | HV_MEMORY_WRITE));
        }
        uint64_t mask = __builtin_ctzll(granule);
        uint64_t access = flags == 4 ? 1 : 2;
        /* MASK spans the page, BAS selects all bytes, and PAC selects EL0. */
        uint64_t control = (mask << 24) | (UINT64_C(0xff) << 5) | (access << 3) | (2 << 1) | 1;
        HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGWVR0_EL1, copy->page));
        HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGWCR0_EL1, control));
        HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBVR2_EL1, copy->return_pc));
        HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBCR2_EL1, 0x1e5));
        copy->active = true;
    }
    copy->calls++;
    HV(hv_vcpu_set_reg(vcpu, HV_REG_X0, dest));
    HV(hv_vcpu_set_reg(vcpu, HV_REG_X1, source));
    HV(hv_vcpu_set_reg(vcpu, HV_REG_X2, size));
    HV(hv_vcpu_set_reg(vcpu, HV_REG_PC, flags == 4 ? copy->read_entry : copy->write_entry));
}

static void user_copy_stop(hv_vcpu_t vcpu, struct uaccess *copy, uint64_t granule,
                           const struct observation *observed)
{
    uint64_t ec = observed->syndrome >> 26;
    if (ec == 0x30 && observed->pc == copy->return_pc) {
        if (copy->faults == copy->faults_at_entry)
            fail("host user-copy guard returned without a fixup");
        HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGWCR0_EL1, 0));
        HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBCR2_EL1, 0));
        if (copy->flags)
            HV(hv_vm_protect(copy->page, granule, memory_flags(copy->flags)));
        else
            HV(hv_vm_unmap(copy->page, granule));
        copy->active = false;
        return;
    }
    bool write = observed->syndrome & (1 << 6);
    if (ec != 0x34 || write != (copy->direction == 6) ||
        !contains(copy->page, granule, observed->far, 1))
        fail("unexpected stop in guarded host user copy");
    for (uint64_t i = 0; i < copy->count; i++) {
        if (copy->fixups[i].pc == observed->pc) {
            /* The copied entries target in-routine fixups with no register updates. */
            HV(hv_vcpu_set_reg(vcpu, HV_REG_PC, copy->fixups[i].target));
            copy->faults++;
            return;
        }
    }
    fail("host user copy stopped outside the Linux fixup table");
}

static void handle_mapping_gate(hv_vcpu_t vcpu, uint8_t *ram, const struct execution *run,
                                const struct mapping_window *window, uint64_t granule,
                                uint8_t *permissions, uint64_t counts[4], struct uaccess *copy)
{
    uint64_t op, address, backing, size, flags;
    HV(hv_vcpu_get_reg(vcpu, HV_REG_X0, &op));
    HV(hv_vcpu_get_reg(vcpu, HV_REG_X1, &address));
    HV(hv_vcpu_get_reg(vcpu, HV_REG_X2, &backing));
    HV(hv_vcpu_get_reg(vcpu, HV_REG_X3, &size));
    HV(hv_vcpu_get_reg(vcpu, HV_REG_X4, &flags));
    if (op == HOST_UACCESS) {
        start_uaccess(vcpu, copy, run, window, granule, permissions, address, backing, size, flags);
        return;
    }
    if (op == HOST_ACCESS_PREFIX && run->version >= 5) {
        if (backing || (flags != 4 && flags != 6))
            fail("invalid host access query");
        HV(hv_vcpu_set_reg(vcpu, HV_REG_X0, access_prefix(window, granule, permissions, address, size, flags)));
        counts[HOST_ACCESS_PREFIX - 1]++;
        HV(hv_vcpu_set_reg(vcpu, HV_REG_PC, window->gate_pc + 4));
        return;
    }
    if (op < HOST_MAP || op > HOST_PROTECT || !size || (address | size | backing) % granule ||
        !contains(window->address, window->size, address, size))
        fail("invalid host mapping request");
    if (op == HOST_MAP ? !contains(window->backing, window->backing_size, backing, size) : backing != 0)
        fail("host mapping request uses unauthorized backing");
    if (op == HOST_UNMAP ? flags != 0 : flags != 4 && flags != 6)
        fail("invalid host mapping permissions");

    uint8_t *pages = permissions + (address - window->address) / granule;
    size_t page_count = size / granule;
    for (size_t page = 0; page < page_count; page++)
        if (!!pages[page] != (op != HOST_MAP))
            fail("host mapping request disagrees with current mappings");

    switch (op) {
    case HOST_MAP:
        HV(hv_vm_map(at(ram, run, backing, size), address, size, memory_flags(flags)));
        memset(pages, (int)flags, page_count);
        break;
    case HOST_UNMAP:
        HV(hv_vm_unmap(address, size));
        memset(pages, 0, page_count);
        break;
    case HOST_PROTECT:
        HV(hv_vm_protect(address, size, memory_flags(flags)));
        memset(pages, (int)flags, page_count);
        break;
    }
    counts[op - 1]++;
    HV(hv_vcpu_set_reg(vcpu, HV_REG_PC, window->gate_pc + 4));
}

static struct observation observe(hv_vcpu_t vcpu, const hv_vcpu_exit_t *stop, bool flat)
{
    struct observation observed = {.reason = stop->reason};
    if (stop->reason == HV_EXIT_REASON_EXCEPTION) {
        observed.syndrome = stop->exception.syndrome;
        observed.far = stop->exception.virtual_address;
        observed.ipa = stop->exception.physical_address;
    }
    HV(hv_vcpu_get_reg(vcpu, HV_REG_PC, &observed.pc));
    HV(hv_vcpu_get_reg(vcpu, HV_REG_CPSR, &observed.pstate));
    HV(hv_vcpu_get_reg(vcpu, HV_REG_X0, &observed.x0));
    HV(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &observed.el1_esr));
    HV(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &observed.el1_elr));
    HV(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, &observed.sctlr));
    HV(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, &observed.ttbr0));
    HV(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TTBR1_EL1, &observed.ttbr1));
    if (flat) {
        if (__builtin_available(macOS 15.0, *))
            HV(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_HCR_EL2, &observed.hcr));
    }
    return observed;
}

static void observe_user_entry(hv_vcpu_t vcpu, uint8_t *ram, const struct execution *run,
                               const struct checkpoint_registers *expected, struct user_entry *entry)
{
    const uint64_t nzcv = UINT64_C(0xf0000000);
    const uint64_t invalid_pstate = 31 | (3 << 20);
    const struct observation *stop = &entry->stop;
    if (stop->reason != HV_EXIT_REASON_EXCEPTION || stop->syndrome >> 26 != 0x30 ||
        stop->pc != run->user_entry || stop->pstate & invalid_pstate || stop->el1_esr || stop->el1_elr)
        return;
    entry->reached = 1;
    const uint64_t *active = at(ram, run, run->active, 8);
    const uint64_t *control = at(ram, run, *active, 72);
    const uint64_t *mode = at(ram, run, run->shadow_state + 80, 8);
    entry->mode = *mode;
    entry->private_sp = control[1];
    HV(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL0, &entry->actual_sp));
    struct checkpoint_registers *registers = &entry->registers;
    for (unsigned i = 0; i < 31; i++)
        HV(hv_vcpu_get_reg(vcpu, HV_REG_X0 + i, &registers->x[i]));
    for (unsigned i = 0; i < 32; i++) {
        hv_simd_fp_uchar16_t value;
        HV(hv_vcpu_get_simd_fp_reg(vcpu, HV_SIMD_FP_REG_Q0 + i, &value));
        memcpy(registers->vectors[i], &value, sizeof(value));
    }
    uint64_t fpsr, fpcr;
    HV(hv_vcpu_get_reg(vcpu, HV_REG_FPSR, &fpsr));
    HV(hv_vcpu_get_reg(vcpu, HV_REG_FPCR, &fpcr));
    registers->fpsr = (uint32_t)fpsr;
    registers->fpcr = (uint32_t)fpcr;
    registers->pc = stop->pc;
    registers->pstate = (stop->pstate & nzcv) | control[8];
    registers->sp = run->native_stack ? entry->actual_sp : control[0];
    struct checkpoint_registers relocated = *expected;
    relocated.pc = run->user_entry;
    entry->matched = !entry->mode && control[3] == run->guest_state &&
        control[0] == expected->sp && control[8] == (expected->pstate & ~nzcv) &&
        entry->actual_sp == (run->native_stack ? expected->sp : entry->private_sp) &&
        !memcmp(registers, &relocated, sizeof(relocated));
}

int main(int argc, char **argv)
{
    struct execution run;
    bool ipa_4k = argc == 3 && !strcmp(argv[2], "--4k-ipa");
    if (argc != 2 && !ipa_4k)
        fail("usage: elf-loader checkpoint [--4k-ipa]");
    if (fread(&run, sizeof(run), 1, stdin) != 1 || run.version < 2 || run.version > 6 ||
        !run.segment_count || !run.ram_size || run.ram_size > (UINT64_C(4) << 30) ||
        run.ram_size > UINT64_MAX - run.ram_base || run.event_capacity > run.ram_size / 80)
        fail("invalid loader input");
    FILE *elf = fopen(argv[1], "rb");
    if (!elf)
        fail("cannot open checkpoint ELF");
    uint8_t *ram = mmap(NULL, run.ram_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (ram == MAP_FAILED)
        fail("cannot allocate checkpoint RAM");
    for (uint64_t index = 0; index < run.segment_count; index++) {
        struct segment segment;
        if (fread(&segment, sizeof(segment), 1, stdin) != 1 || segment.file_size > segment.memory_size)
            fail("invalid ELF load segment");
        void *destination = at(ram, &run, segment.address, segment.memory_size);
        load(elf, destination, segment.offset, segment.file_size);
    }
    fclose(elf);
    struct checkpoint_registers expected;
    memcpy(&expected, at(ram, &run, run.guest_state, sizeof(expected)), sizeof(expected));
    if (run.zero_bytes) {
        uint64_t dczid;
        __asm__ volatile("mrs %0, dczid_el0" : "=r"(dczid));
        if ((dczid & 16) || (UINT64_C(4) << (dczid & 15)) != run.zero_bytes)
            fail("Apple Silicon DC ZVA geometry differs from the ELF contract");
    }
    /* Every unexpected EL1 vector immediately traps back to the host. */
    uint32_t *vectors = at(ram, &run, run.vectors, 2048);
    for (unsigned i = 0; i < 16; i++)
        vectors[i * 32] = 0xd4200000; /* BRK #0 */

    bool flat = !(run.sctlr & 1);
    if (ipa_4k && !flat)
        fail("4 KiB IPA mappings require a flat checkpoint");
    uint64_t alias_count = 0, alias_end = 0;
    struct host_alias *aliases = NULL;
    uint64_t granule = 0;
    if (run.version >= 3) {
        long page = sysconf(_SC_PAGESIZE);
        if (!flat || page <= 0 || fread(&alias_count, sizeof(alias_count), 1, stdin) != 1 ||
            alias_count > 65536 || (run.version == 3 && !alias_count))
            fail("invalid host alias count or memory mode");
        granule = ipa_4k ? 4096 : (uint64_t)page;
        if (alias_count) {
            aliases = calloc(alias_count, sizeof(*aliases));
            if (!aliases || fread(aliases, sizeof(*aliases), alias_count, stdin) != alias_count)
                fail("incomplete host alias list");
        }
        uint64_t ram_end = run.ram_base + run.ram_size;
        for (uint64_t index = 0; index < alias_count; index++) {
            const struct host_alias *a = &aliases[index];
            if (!a->size || (a->address | a->backing | a->size) % granule ||
                a->size > UINT64_MAX - a->address || a->address < alias_end ||
                (a->flags != 4 && a->flags != 5 && a->flags != 6))
                fail("invalid or overlapping host alias");
            alias_end = a->address + a->size;
            if (a->address < ram_end && run.ram_base < alias_end)
                fail("host alias overlaps the checkpoint RAM aperture");
            at(ram, &run, a->backing, a->size);
        }
    }
    struct mapping_window window = {0};
    struct uaccess copy = {0};
    uint8_t *permissions = NULL;
    uint64_t mapping_counts[4] = {0};
    if (run.version >= 4) {
        if (fread(&window, sizeof(window), 1, stdin) != 1)
            fail("incomplete host mapping window");
        check_mapping_window(ram, &run, &window, granule, aliases, alias_count);
        uint64_t window_end = window.address + window.size;
        if (window_end > alias_end)
            alias_end = window_end;
    }
    if (run.version >= 6) {
        uint64_t header[3];
        if (granule < 8 || granule > (1U << 31) || (granule & (granule - 1)) ||
            fread(header, sizeof(header), 1, stdin) != 1 || !header[2] || header[2] > 4096)
            fail("invalid host user-copy descriptor");
        copy.read_entry = header[0];
        copy.write_entry = header[1];
        copy.count = header[2];
        copy.fixups = calloc(copy.count, sizeof(*copy.fixups));
        if (!copy.fixups || fread(copy.fixups, sizeof(*copy.fixups), copy.count, stdin) != copy.count)
            fail("incomplete host user-copy fixup table");
    }
    create_vm(flat, alias_end ? alias_end - 1 : 0, ipa_4k);
    if (window.size && !(permissions = calloc(window.size / granule, 1)))
        fail("cannot track host mapping window");
    /* In flat mode an ELF address goes straight to the harness RAM mapping. */
    HV(hv_vm_map(ram, run.ram_base, run.ram_size, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC));
    for (uint64_t index = 0; index < alias_count; index++) {
        const struct host_alias *a = &aliases[index];
        HV(hv_vm_map(at(ram, &run, a->backing, a->size), a->address, a->size, memory_flags(a->flags)));
    }
    free(aliases);
    hv_vcpu_t vcpu;
    hv_vcpu_exit_t *stop;
    HV(hv_vcpu_create(&vcpu, &stop, NULL));
    if (flat) {
        if (__builtin_available(macOS 15.0, *)) {
            /* RW selects AArch64. DC supplies Normal cacheable memory while
             * stage 1 is off, including for exclusive and DC ZVA accesses. */
            HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_HCR_EL2, (UINT64_C(1) << 31) | (UINT64_C(1) << 12)));
        }
    } else {
        HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1, run.mair));
        HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, run.tcr));
        HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, run.ttbr0));
        HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR1_EL1, run.ttbr1));
    }
    HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, run.cpacr));
    HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, run.sctlr));
    HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, run.vectors));
    HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, 0));
    HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, 0));
    HV(hv_vcpu_set_vtimer_mask(vcpu, true));
    HV(hv_vcpu_set_trap_debug_exceptions(vcpu, true));
    HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MDSCR_EL1, UINT64_C(1) << 15)); /* MDE */
    HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBVR0_EL1, run.user_entry));
    HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBCR0_EL1, 0x1e5)); /* EL0 instruction breakpoint */
    HV(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0x3c0)); /* EL0t with asynchronous masks set */
    HV(hv_vcpu_set_reg(vcpu, HV_REG_PC, run.entry));
    HV(hv_vcpu_run(vcpu));

    struct user_entry entry = {.stop = observe(vcpu, stop, flat)};
    observe_user_entry(vcpu, ram, &run, &expected, &entry);
    struct observation observed = entry.stop;
    if (entry.matched) {
        HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBVR0_EL1, run.completion));
        if (window.size) {
            HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBVR1_EL1, window.gate_pc));
            HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBCR1_EL1, 0x1e5));
        }
        for (;;) {
            HV(hv_vcpu_run(vcpu));
            observed = observe(vcpu, stop, flat);
            if (!window.size || observed.reason != HV_EXIT_REASON_EXCEPTION ||
                observed.pstate & (31 | (3 << 20)) || observed.el1_esr || observed.el1_elr ||
                observed.sctlr & 1 || observed.ttbr0 || observed.ttbr1 ||
                !(observed.hcr & (UINT64_C(1) << 12)))
                break;
            if (copy.active)
                user_copy_stop(vcpu, &copy, granule, &observed);
            else if (observed.syndrome >> 26 == 0x30 && observed.pc == window.gate_pc)
                handle_mapping_gate(vcpu, ram, &run, &window, granule, permissions, mapping_counts, &copy);
            else
                break;
        }
    }
    if (copy.active)
        fail("host user copy did not return at EL0");
    free(copy.fixups);
    free(permissions);
    HV(hv_vcpu_destroy(vcpu));
    HV(hv_vm_destroy());
    if (copy.scratch && munmap(copy.scratch, granule))
        fail("cannot release the watched user-copy page");
    const uint64_t *result = at(ram, &run, run.result, 320);
    uint64_t uart_size = result[11];
    uint64_t events = result[3];
    if (uart_size > 4096)
        fail("runtime UART output exceeds buffer");
    if (events > run.event_capacity)
        fail("runtime event count exceeds buffer");
    if (fwrite(&entry, sizeof(entry), 1, stdout) != 1 ||
        fwrite(&observed, sizeof(observed), 1, stdout) != 1 ||
        fwrite(result, 320, 1, stdout) != 1 ||
        fwrite(at(ram, &run, run.guest_state, 792), 792, 1, stdout) != 1 ||
        fwrite(at(ram, &run, run.shadow_state, 104), 104, 1, stdout) != 1 ||
        fwrite(at(ram, &run, run.uart, uart_size), 1, uart_size, stdout) != uart_size ||
        (events && fwrite(at(ram, &run, run.events, events * 80), 80, events, stdout) != events) ||
        (window.size && fwrite(mapping_counts, sizeof(mapping_counts[0]), 3, stdout) != 3) ||
        (run.version >= 5 && fwrite(&mapping_counts[3], sizeof(mapping_counts[3]), 1, stdout) != 1) ||
        (run.version >= 6 && (fwrite(&copy.calls, sizeof(copy.calls), 1, stdout) != 1 ||
                              fwrite(&copy.faults, sizeof(copy.faults), 1, stdout) != 1)) ||
        fflush(stdout))
        fail("cannot write completion evidence");
    return 0;
}
