/* Sample live kernel calls in the pinned AArch64 Linux-user IPC replay. */
#include "qemu-plugin.h"

#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define APP_ENTRY UINT64_C(0x201160)
#define STOP_PC UINT64_C(0x800080059b50)
#define LOWERED_ERET UINT64_C(0x80008001217c)
#define STRIDE 1024u

static const uint64_t svc_pcs[] = {
    0x201170, 0x201298, 0x2012bc, 0x2012e4, 0x20130c,
    0x201330, 0x2013a4, 0x2013c8, 0x2013ec, 0x201414,
    0x20143c, 0x201464, 0x201494, 0x2014bc, 0x2014ec,
};

struct range { uint64_t lo, hi; };
static struct range kernel[64], user[64];
static size_t kernel_count, user_count;
static FILE *samples, *report, *anomalies, *syscalls;
static struct qemu_plugin_register *syscall_register;
static GByteArray *register_data;
static uint64_t syscall_index, syscall_start, syscall_pc, syscall_number;
static uint64_t stack[256];
static size_t depth, max_depth;
static uint64_t instructions, recorded, calls, returns, matched_returns;
static uint64_t nonlocal_returns, returns_without_call, unmatched_returns;
static uint64_t branch_returns, user_resets_with_frames, open_at_stop;
static uint64_t rng, next_sample, sample_bucket;
static unsigned starts, stops, other_cpus;
static bool active;

enum instruction_kind { ORDINARY, CALL, RETURN, INDIRECT, USER, START, STOP, SYSCALL };
static enum instruction_kind prior_kind;
static uint64_t prior_pc;

static bool in_ranges(uint64_t pc, const struct range *ranges, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        if (pc >= ranges[i].lo && pc < ranges[i].hi)
            return true;
    return false;
}

static uint64_t random_offset(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng % STRIDE;
}

static void load_registers(qemu_plugin_id_t id, unsigned cpu)
{
    (void)id;
    if (cpu != 0) return;
    GArray *registers = qemu_plugin_get_registers();
    for (guint i = 0; i < registers->len; ++i) {
        qemu_plugin_reg_descriptor reg = g_array_index(registers, qemu_plugin_reg_descriptor, i);
        if (!g_strcmp0(reg.name, "x8")) syscall_register = reg.handle;
    }
    g_array_free(registers, true);
    if (!syscall_register) g_error("guest X8 unavailable");
}

static void finish_syscall(void)
{
    if (syscall_index)
        fprintf(syscalls, "%" PRIu64 "\t%" PRIx64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\n",
                syscall_index, syscall_pc, syscall_number, syscall_start, instructions);
}

static void unwind(uint64_t target)
{
    if (prior_kind != RETURN && prior_kind != INDIRECT) return;
    if (depth && stack[depth - 1] == target) {
        --depth;
        if (prior_kind == RETURN) ++matched_returns;
        else ++branch_returns;
        return;
    }
    if (prior_kind == INDIRECT) return;
    if (!depth) {
        ++returns_without_call;
        fprintf(anomalies, "empty\t%" PRIx64 "\t%" PRIx64 "\n", prior_pc, target);
        return;
    }
    for (size_t i = depth - 1; i > 0; --i) {
        if (stack[i - 1] == target) {
            ++nonlocal_returns;
            fprintf(anomalies, "nonlocal\t%" PRIx64 "\t%" PRIx64 "\n", prior_pc, target);
            depth = i - 1;
            return;
        }
    }
    ++unmatched_returns;
    fprintf(anomalies, "unmatched\t%" PRIx64 "\t%" PRIx64 "\t%" PRIx64 "\n",
            prior_pc, target, stack[depth - 1]);
}

static void executed(unsigned cpu, void *opaque)
{
    if (cpu != 0) {
        ++other_cpus;
        return;
    }
    uintptr_t packed = (uintptr_t)opaque;
    uint64_t pc = packed >> 3;
    enum instruction_kind kind = packed & 7;
    if (kind == START) {
        ++starts;
        active = true;
    }
    if (!active) return;
    if (kind == STOP) {
        unwind(pc);
        finish_syscall();
        open_at_stop = depth;
        fprintf(anomalies, "open_at_stop");
        for (size_t i = 0; i < depth; ++i)
            fprintf(anomalies, "\t%" PRIx64, stack[i]);
        fputc('\n', anomalies);
        ++stops;
        active = false;
        return;
    }
    if (kind == USER || kind == START || kind == SYSCALL) {
        if (depth) {
            ++user_resets_with_frames;
            fprintf(anomalies, "user_reset\t%" PRIx64 "\t%" PRIx64 "\t%zu\n",
                    prior_pc, pc, depth);
        }
        depth = 0;
        prior_kind = ORDINARY;
        if (kind == SYSCALL) {
            finish_syscall();
            g_byte_array_set_size(register_data, 0);
            if (qemu_plugin_read_register(syscall_register, register_data) != 8)
                g_error("could not read guest X8");
            uint64_t number;
            memcpy(&number, register_data->data, sizeof number);
            syscall_number = GUINT64_FROM_LE(number);
            ++syscall_index;
            syscall_start = instructions;
            syscall_pc = pc;
        }
        return;
    }

    unwind(pc);
    ++instructions;
    if (instructions == next_sample) {
        fprintf(samples, "%" PRIu64 "\t%016" PRIx64 "\t%" PRIu64, instructions, pc, syscall_index);
        for (size_t i = depth; i > 0; --i)
            fprintf(samples, "\t%016" PRIx64, stack[i - 1] - 4);
        fputc('\n', samples);
        ++recorded;
        sample_bucket += STRIDE;
        next_sample = sample_bucket + 1 + random_offset();
    }
    if (kind == CALL) {
        if (depth == G_N_ELEMENTS(stack)) g_error("kernel call stack overflow");
        stack[depth++] = pc + 4;
        if (depth > max_depth) max_depth = depth;
        ++calls;
    } else if (kind == RETURN) {
        ++returns;
    }
    prior_pc = pc;
    prior_kind = kind;
}

static void translated(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); ++i) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        enum instruction_kind kind = ORDINARY;
        if (pc == APP_ENTRY) kind = START;
        else if (pc == STOP_PC) kind = STOP;
        else if (in_ranges(pc, user, user_count)) {
            kind = USER;
            for (size_t j = 0; j < G_N_ELEMENTS(svc_pcs); ++j)
                if (svc_pcs[j] == pc) kind = SYSCALL;
        } else if (pc != LOWERED_ERET && in_ranges(pc, kernel, kernel_count)) {
            uint32_t word;
            if (qemu_plugin_insn_data(insn, &word, sizeof word) != sizeof word ||
                (word & 0xffe0001fu) == 0xd4200000u) continue;
            if ((word & 0xfc000000u) == 0x94000000u ||
                (word & 0xfffffc1fu) == 0xd63f0000u) kind = CALL;
            else if ((word & 0xfffffc1fu) == 0xd65f0000u) kind = RETURN;
            else if ((word & 0xfffffc1fu) == 0xd61f0000u) kind = INDIRECT;
        } else continue;
        qemu_plugin_register_vcpu_insn_exec_cb(insn, executed,
                                              kind == SYSCALL ? QEMU_PLUGIN_CB_R_REGS : QEMU_PLUGIN_CB_NO_REGS,
                                              (void *)(uintptr_t)((pc << 3) | kind));
    }
}

static size_t load_ranges(const char *path, struct range *ranges, size_t capacity)
{
    FILE *file = fopen(path, "rb");
    if (!file) return 0;
    size_t count = fread(ranges, sizeof *ranges, capacity, file);
    fclose(file);
    return count;
}

static void finish(qemu_plugin_id_t id, void *opaque)
{
    (void)id;
    (void)opaque;
    fprintf(report,
            "{\"starts\":%u,\"stops\":%u,\"other_vcpus\":%u,"
            "\"kernel_instructions\":%" PRIu64 ",\"stride\":%u,\"samples\":%" PRIu64 ","
            "\"calls\":%" PRIu64 ",\"returns\":%" PRIu64 ",\"matched_returns\":%" PRIu64 ","
            "\"nonlocal_returns\":%" PRIu64 ",\"returns_without_call\":%" PRIu64 ","
            "\"unmatched_returns\":%" PRIu64 ",\"branch_returns\":%" PRIu64 ","
            "\"user_resets_with_frames\":%" PRIu64 ",\"open_at_stop\":%" PRIu64 ",\"max_depth\":%zu,"
            "\"syscalls\":%" PRIu64 "}\n",
            starts, stops, other_cpus, instructions, STRIDE, recorded, calls, returns, matched_returns,
            nonlocal_returns, returns_without_call, unmatched_returns, branch_returns,
            user_resets_with_frames, open_at_stop, max_depth, syscall_index);
    g_byte_array_unref(register_data);
    if (fclose(samples) || fclose(report) || fclose(anomalies) || fclose(syscalls))
        g_error("could not write stack reports");
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                         int argc, char **argv)
{
    if (info->system_emulation || argc != 2 || !g_str_has_prefix(argv[0], "out=") ||
        !g_str_has_prefix(argv[1], "seed=")) return -1;
    char *end;
    rng = g_ascii_strtoull(argv[1] + 5, &end, 10);
    if (!rng || *end) return -1;
    kernel_count = load_ranges("/work/kernel-ranges.bin", kernel, G_N_ELEMENTS(kernel));
    user_count = load_ranges("/work/user-ranges.bin", user, G_N_ELEMENTS(user));
    if (!kernel_count || !user_count) return -1;
    char *path = g_build_filename(argv[0] + 4, "raw-stacks.tsv", NULL);
    samples = fopen(path, "w");
    g_free(path);
    path = g_build_filename(argv[0] + 4, "capture.json", NULL);
    report = fopen(path, "w");
    g_free(path);
    path = g_build_filename(argv[0] + 4, "unwind.tsv", NULL);
    anomalies = fopen(path, "w");
    g_free(path);
    path = g_build_filename(argv[0] + 4, "syscall-visits.tsv", NULL);
    syscalls = fopen(path, "w");
    g_free(path);
    if (!samples || !report || !anomalies || !syscalls) return -1;
    register_data = g_byte_array_new();
    next_sample = 1 + random_offset();
    qemu_plugin_register_vcpu_init_cb(id, load_registers);
    qemu_plugin_register_vcpu_tb_trans_cb(id, translated);
    qemu_plugin_register_atexit_cb(id, finish, NULL);
    return 0;
}
