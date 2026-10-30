/* QEMU TCG plugin: record every executed instruction and memory access of one guest run.
 *
 * Arguments: out=PATH (trace file). Each line is one event, in execution order:
 *   I <vaddr>                      an instruction executed
 *   M <vaddr> <paddr> <size> <L|S> a memory access of the preceding instruction (paddr - for I/O)
 * The trace is flushed after every instruction, so a debugger stop leaves it complete.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version=QEMU_PLUGIN_VERSION;
static FILE *trace;

static void executed(unsigned int vcpu,void *vaddr)
{
    (void)vcpu;fprintf(trace,"I %" PRIx64 "\n",(uint64_t)(uintptr_t)vaddr);fflush(trace);
}
static void accessed(unsigned int vcpu,qemu_plugin_meminfo_t info,uint64_t vaddr,void *data)
{
    (void)vcpu;(void)data;
    struct qemu_plugin_hwaddr *hw=qemu_plugin_get_hwaddr(info,vaddr);
    unsigned size=1u<<qemu_plugin_mem_size_shift(info);char kind=qemu_plugin_mem_is_store(info)?'S':'L';
    if(hw && !qemu_plugin_hwaddr_is_io(hw))fprintf(trace,"M %" PRIx64 " %" PRIx64 " %u %c\n",vaddr,qemu_plugin_hwaddr_phys_addr(hw),size,kind);
    else fprintf(trace,"M %" PRIx64 " - %u %c\n",vaddr,size,kind);
    fflush(trace);
}
static void translated(qemu_plugin_id_t id,struct qemu_plugin_tb *tb)
{
    (void)id;
    for(size_t i=0;i<qemu_plugin_tb_n_insns(tb);++i){
        struct qemu_plugin_insn *insn=qemu_plugin_tb_get_insn(tb,i);
        qemu_plugin_register_vcpu_insn_exec_cb(insn,executed,QEMU_PLUGIN_CB_NO_REGS,(void *)(uintptr_t)qemu_plugin_insn_vaddr(insn));
        qemu_plugin_register_vcpu_mem_cb(insn,accessed,QEMU_PLUGIN_CB_NO_REGS,QEMU_PLUGIN_MEM_RW,NULL);
    }
}
static void finished(qemu_plugin_id_t id,void *data){(void)id;(void)data;if(trace)fclose(trace);trace=NULL;}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,const qemu_info_t *info,int argc,char **argv)
{
    (void)info;const char *out=NULL;
    for(int i=0;i<argc;++i)if(!strncmp(argv[i],"out=",4))out=argv[i]+4;
    if(!out || !(trace=fopen(out,"w")))return -1;
    qemu_plugin_register_vcpu_tb_trans_cb(id,translated);
    qemu_plugin_register_atexit_cb(id,finished,NULL);
    return 0;
}
