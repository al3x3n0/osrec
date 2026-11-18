/* Single-vCPU, per-instruction counting. No guest instrumentation or trace I/O.
 * map: sorted little-endian <uint64 PC, uint64 flags> pairs.
 * out: shared counter file; survives a debugger stop and QEMU termination.
 * Flags: low 2 bits payload (0 adapter, 1 kernel, 2 application), 4/8/16
 * source visits (kernel/application/synthetic). Window boundaries are PCs.
 */
#include <qemu-plugin.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
struct row { uint64_t pc, flags; };
static struct row *rows;
static size_t nrows;
/* magic, version, start hits, begin hits, end hits, stop hits, reserved x2;
 * then [whole ELF, execution interval] x [adapter,kernel,app,k-source,u-source,synthetic-source]. */
static uint64_t *counts;
static uint64_t start, begin, end, stop;
static int active, computing;
static uint64_t *histogram, text_base, text_bytes;

static void executed(unsigned int cpu, void *userdata)
{
    (void)cpu;
    uintptr_t f = (uintptr_t)userdata;
    if (f & 32) { active=1; counts[2]++; }
    if (f & 64) { computing=1; counts[3]++; }
    if (f & 128) { computing=0; counts[4]++; }
    if (f & 256) { active=0; counts[5]++; }
    if (!active) return;
    if (computing && histogram && (f >> 9)) histogram[(f >> 9)-1]++;
    for (unsigned window=0; window<2; window++) {
        if (window && !computing) continue;
        uint64_t *c=counts+8+6*window;
        c[f&3]++;
        if (f&4) c[3]++;
        if (f&8) c[4]++;
        if (f&16) c[5]++;
    }
}
static void translated(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    for (size_t i=0; i<qemu_plugin_tb_n_insns(tb); i++) {
        struct qemu_plugin_insn *insn=qemu_plugin_tb_get_insn(tb,i);
        uint64_t pc=qemu_plugin_insn_vaddr(insn), f=0;
        size_t lo=0, hi=nrows;
        while (lo<hi) { size_t m=lo+(hi-lo)/2; if (rows[m].pc<pc) lo=m+1; else hi=m; }
        if (lo<nrows && rows[lo].pc==pc) f=rows[lo].flags;
        if (pc==start) f|=32;
        if (pc==begin) f|=64;
        if (pc==end) f|=128;
        if (pc==stop) f|=256;
        if (histogram && pc>=text_base && pc-text_base<text_bytes)
            f|=((pc-text_base)/4+1)<<9;
        qemu_plugin_register_vcpu_insn_exec_cb(insn,executed,QEMU_PLUGIN_CB_NO_REGS,(void *)(uintptr_t)f);
    }
}
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
    (void)info;
    const char *map=NULL, *out=NULL, *hist=NULL;
    for (int i=0; i<argc; i++) {
        if (!strncmp(argv[i],"map=",4)) map=argv[i]+4;
        else if (!strncmp(argv[i],"out=",4)) out=argv[i]+4;
        else if (!strncmp(argv[i],"start=",6)) start=strtoull(argv[i]+6,NULL,0);
        else if (!strncmp(argv[i],"begin=",6)) begin=strtoull(argv[i]+6,NULL,0);
        else if (!strncmp(argv[i],"end=",4)) end=strtoull(argv[i]+4,NULL,0);
        else if (!strncmp(argv[i],"stop=",5)) stop=strtoull(argv[i]+5,NULL,0);
        else if (!strncmp(argv[i],"hist=",5)) hist=argv[i]+5;
        else if (!strncmp(argv[i],"text=",5)) text_base=strtoull(argv[i]+5,NULL,0);
        else if (!strncmp(argv[i],"bytes=",6)) text_bytes=strtoull(argv[i]+6,NULL,0);
        else return -1;
    }
    if (!map || !out || !start || !begin || !end || !stop) return -1;
    FILE *file=fopen(map,"rb");
    if (!file) return -1;
    if (fseek(file,0,SEEK_END)) return -1;
    long size=ftell(file);
    if (size<0 || size%sizeof(*rows)) return -1;
    rewind(file); nrows=(size_t)size/sizeof(*rows); rows=malloc((size_t)size);
    if (size && (!rows || fread(rows,sizeof(*rows),nrows,file)!=nrows)) return -1;
    fclose(file);
    for (size_t i=0; i<nrows; i++)
        if ((i && rows[i-1].pc>=rows[i].pc) || (rows[i].flags&~31ull) || (rows[i].flags&3)==3) return -1;
    int fd=open(out,O_CREAT|O_EXCL|O_RDWR,0600);
    if (fd<0 || ftruncate(fd,20*sizeof(uint64_t))) return -1;
    counts=mmap(NULL,20*sizeof(uint64_t),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    close(fd);
    if (counts==MAP_FAILED) return -1;
    counts[0]=0x3150434952534f; counts[1]=1;
    if (hist) {
        if (!text_base || !text_bytes || text_bytes%4) return -1;
        fd=open(hist,O_CREAT|O_EXCL|O_RDWR,0600);
        if (fd<0 || ftruncate(fd,(off_t)(text_bytes*2))) return -1;
        histogram=mmap(NULL,text_bytes*2,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
        close(fd);
        if (histogram==MAP_FAILED) return -1;
    }
    qemu_plugin_register_vcpu_tb_trans_cb(id,translated);
    return 0;
}
