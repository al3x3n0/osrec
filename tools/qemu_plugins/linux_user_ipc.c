/* Instruction accounting for the fixed 640-iteration IPC replay. */
#include "qemu-plugin.h"
#include <stdint.h>
#include <glib.h>
#include <stdio.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

struct interval {
    uint64_t lo, hi;
};

static struct interval kernel[64], user[64];
static size_t kernel_count, user_count;
static uint64_t count[3], prefix[3];
static unsigned starts, stops, other_vcpus;
static bool active;
static GHashTable *traps;
static uint64_t host_syscalls[512];
static uint64_t unexpected_syscalls;
static char *output_directory;

static bool inside(uint64_t pc, const struct interval *ranges, size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        if (pc >= ranges[i].lo && pc < ranges[i].hi) {
            return true;
        }
    }
    return false;
}

static void executed(unsigned int cpu, void *opaque)
{
    if (cpu != 0) {
        ++other_vcpus;
        return;
    }
    uintptr_t marker = (uintptr_t)opaque;
    if (marker == 3) {
        active = true;
        ++starts;
        marker = 2;
    } else if (marker == 4) {
        active = false;
        ++stops;
        return;
    }
    if (active) {
        if (marker > 4) {
            gpointer key = (gpointer)marker;
            uintptr_t previous = (uintptr_t)g_hash_table_lookup(traps, key);
            g_hash_table_insert(traps, key, (gpointer)(previous + 1));
            marker = 0;
        }
        ++count[marker];
        if (marker == 1 && count[1] == 10000000) {
            for (size_t i = 0; i < 3; ++i) {
                prefix[i] = count[i];
            }
        }
    }
}

static void translated(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    size_t length = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < length; ++i) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        uintptr_t marker = 0;
        if (pc == 0x201160) {
            marker = 3;
        } else if (pc == 0x800080059b50) {
            marker = 4;
        } else if (inside(pc, user, user_count)) {
            marker = 2;
        } else if (inside(pc, kernel, kernel_count)) {
            uint32_t word = 0;
            if (qemu_plugin_insn_data(insn, &word, sizeof(word)) == sizeof(word) &&
                    (word & 0xffe0001f) != 0xd4200000) {
                /* Charge the lowered ERET to runtime in both variants. */
                marker = pc == 0x80008001217c ? 0 : 1;
            } else {
                marker = pc;
            }
        }
        qemu_plugin_register_vcpu_insn_exec_cb(insn, executed, QEMU_PLUGIN_CB_NO_REGS, (void *)marker);
    }
}

static size_t load(const char *name, struct interval *ranges, size_t capacity)
{
    FILE *file = fopen(name, "rb");
    if (!file) {
        return 0;
    }
    size_t length = fread(ranges, sizeof(*ranges), capacity, file);
    fclose(file);
    return length;
}

static void observe_host_syscall(qemu_plugin_id_t id, unsigned int cpu, int64_t number,
                                 uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                                 uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8)
{
    (void)id; (void)a1; (void)a2; (void)a3; (void)a4;
    (void)a5; (void)a6; (void)a7; (void)a8;
    if (cpu != 0 || !active) return;
    if (number >= 0 && number < 512) ++host_syscalls[number];
    else ++unexpected_syscalls;
}

static FILE *open_report(const char *name)
{
    char *path = g_build_filename(output_directory, name, NULL);
    FILE *file = fopen(path, "w");
    g_free(path);
    return file;
}

static void finish(qemu_plugin_id_t id, void *opaque)
{
    (void)id;
    (void)opaque;
    FILE *tab = open_report("traps.tsv");
    if (tab) {
        GHashTableIter iter;
        gpointer pc, hits;
        g_hash_table_iter_init(&iter, traps);
        while (g_hash_table_iter_next(&iter, &pc, &hits))
            fprintf(tab, "%#" PRIxPTR "\t%" PRIuPTR "\n", (uintptr_t)pc, (uintptr_t)hits);
        fclose(tab);
    }
    g_hash_table_destroy(traps);
    tab = open_report("host-syscalls.tsv");
    if (tab) {
        for (unsigned i = 0; i < 512; ++i)
            if (host_syscalls[i]) fprintf(tab, "%u\t%" PRIu64 "\n", i, host_syscalls[i]);
        if (unexpected_syscalls) fprintf(tab, "-1\t%" PRIu64 "\n", unexpected_syscalls);
        fclose(tab);
    }
    FILE *file = open_report("counts.json");
    if (file) {
        fprintf(file, "{\"starts\":%u,\"stops\":%u,\"other_vcpus\":%u,\"runtime\":%" PRIu64 ",\"kernel\":%" PRIu64
                ",\"user\":%" PRIu64 ",\"prefix_10m\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]}\n",
                starts, stops, other_vcpus, count[0], count[1], count[2], prefix[0], prefix[1], prefix[2]);
        fclose(file);
    }
    g_free(output_directory);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
    if (info->system_emulation || argc > 1 ||
            (argc == 1 && (!g_str_has_prefix(argv[0], "out=") || !argv[0][4]))) {
        return -1;
    }
    kernel_count = load("/work/kernel-ranges.bin", kernel, 64);
    user_count = load("/work/user-ranges.bin", user, 64);
    if (!kernel_count || !user_count) {
        return -1;
    }
    output_directory = g_strdup(argc ? argv[0] + 4 : "/work/profile-direct-transitions-ipc");
    traps = g_hash_table_new(g_direct_hash, g_direct_equal);
    qemu_plugin_register_vcpu_tb_trans_cb(id, translated);
    qemu_plugin_register_vcpu_syscall_cb(id, observe_host_syscall);
    qemu_plugin_register_atexit_cb(id, finish, NULL);
    return 0;
}
