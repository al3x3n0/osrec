/* Exercise the actual write-admission hook, including its bitmap fast path. */
#include <assert.h>
#include <stdlib.h>
#include <setjmp.h>
#include "../runtime/el0_flat/program.c"
static unsigned char bytes[16384] __attribute__((aligned(4096)));
static const struct flat_ram ram[]={{0x40000000,sizeof bytes,bytes}};
struct flat_full_image flat_program;
struct flat_control *flat_active;
uint64_t flat_user_context_difference(const struct osrec_context *a,const struct osrec_context *b,unsigned skip)
{(void)a;(void)b;(void)skip;abort();} /* No remembered context in this fixture. */
const uint64_t flat_user_text_count=0;
const struct flat_execmap flat_user_text[1]={{0}};
const struct pretranslated_check flat_pretranslated_checks[]={
    {(const volatile uint64_t *)(bytes+4096),0xff,0},
    {(const volatile uint64_t *)(bytes+8192-8),~0ull,0},
};
const unsigned char flat_immutable_page_bits[]={2};
const struct flat_text_span flat_immutable_text[1]={{0}};
const uint64_t flat_immutable_text_count=0;
static jmp_buf failed;
static int expecting_failure;
void flat_fail(enum flat_status status){(void)status;if(expecting_failure)longjmp(failed,1);abort();}
int main(void)
{
    flat_program.memory.ram=ram;flat_program.memory.ram_count=1;
    flat_pretranslated_check_count=2;
    bitmap_ram_base=ram->pa;bitmap_ram_bytes=ram->bytes;
    for(size_t offset=0;offset<sizeof bytes;offset++)for(size_t size=0;size<=32;size++) {
        if(size>sizeof bytes-offset)continue;
        flat_translation_dirty=0;
        writable_data(0,ram->pa+offset,size);
        int overlap=size && offset<8192 && offset+size>4096;
        assert(flat_translation_dirty==(unsigned)overlap);
        if(size && offset+size<=4096)assert(!flat_translation_dirty);
    }
    flat_translation_dirty=0;osrec_platform_set_ttbr0(0x12345000);
    assert(flat_translation_dirty && flat_program.memory.ttbr0==0x12345000);
    assert(flat_translation_write_overlaps(flat_pretranslated_checks,2,UINTPTR_MAX-3,8));
    assert(!flat_translation_write_overlaps(flat_pretranslated_checks,2,UINTPTR_MAX,0));
    flat_pretranslated_memory=1;flat_program.memory.ttbr0=flat_pretranslated_root=0;
    flat_translation_dirty=1;admit_user_text(0x1234);assert(!flat_translation_dirty);
    writable_data(0x1234,ram->pa+4096,8);assert(flat_translation_dirty);
    *(uint64_t *)(bytes+4096)=0x100; /* outside the observed descriptor mask */
    admit_user_text(0x1234);assert(!flat_translation_dirty);
    writable_data(0x1234,ram->pa+4096,1);assert(flat_translation_dirty);
    bytes[4096]=1;
    expecting_failure=1;
    if(!setjmp(failed)){admit_user_text(0x1234);abort();}
    assert(flat_full_result.detail==0x105 && flat_full_result.far==0 && flat_translation_dirty);
    expecting_failure=0;
    writable_data(0x1234,ram->pa+4096,1);bytes[4096]=0;
    admit_user_text(0x1234);assert(!flat_translation_dirty);
    return 0;
}
