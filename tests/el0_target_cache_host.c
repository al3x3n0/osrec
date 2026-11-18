/* Exercise the real resolver after warming its cache. The oracle uses a
 * linear mapping/PC scan, retaining the preceding diagnostic order. */
#include <assert.h>
#include <setjmp.h>
#include <string.h>
#undef memcpy /* Darwin's checked-libc macro is not a freestanding prototype. */
#include "../runtime/el0_flat/program.c"

static void test_kernel_a(void){}
static void test_kernel_b(void){}
static void test_user(void){}
static const struct flat_pc_index_entry test_kernel_page[1024]={
    [0]={0,test_kernel_a},[1]={0,test_kernel_b}};
static const struct flat_pc_index_entry test_user_page[1024]={[0]={0,test_user}};
static const struct flat_pc_index_entry *const test_kernel_pages[]={test_kernel_page};
static const struct flat_pc_index_entry *const test_user_pages[]={test_user_page};
const struct flat_pc_index flat_pc_indices[]={
    {0x8000,0x1000,test_kernel_pages},{0x2000,0x1000,test_user_pages}};
const uint64_t flat_native_stack_ranges[][2]={{0x8000,0x9000},{0x2000,0x3000}};
const struct flat_mapping flat_maps[]={
    {0x1000,0x40000000,0x1000,0x400},{0x4000,0x40001000,0x1000,0x400}};
const struct flat_text_span flat_immutable_text[]={{0x40000600,0x80}};
const uint64_t flat_immutable_text_count=1;
const unsigned char flat_immutable_page_bits[]={0xff,0xff};
static struct flat_ram test_ram;
static struct osrec_shadow test_shadow;
static struct flat_frame test_frame;
static struct flat_control test_control;
struct flat_control *flat_active=&test_control;
struct flat_full_image flat_program;
static struct flat_pc test_pcs[]={
    {0x2000,test_user},{0x8000,test_kernel_a},{0x8004,test_kernel_b}};
static jmp_buf test_stop;
void flat_fail(enum flat_status status){assert(status==FLAT_BOUNDARY);longjmp(test_stop,1);}

struct test_result {flat_target resume;uint64_t reason,detail,far;};
static struct test_result test_reference(uint64_t pc)
{
    struct test_result r={0};
    if(flat_native_kernel_stack) {
        unsigned kernel=0;
        for(uint64_t i=0;i<flat_native_stack_range_count;i++)
            if(pc>=flat_native_stack_ranges[i][0] && pc<flat_native_stack_ranges[i][1])kernel=1;
        if(kernel!=(flat_program.shadow->mode==OSREC_KERNEL))
            return (struct test_result){0,3,0x103,flat_program.shadow->mode};
        if(flat_program.shadow->mode==OSREC_KERNEL) {
            uint64_t sp=test_frame.cpu.sp,pa=0;unsigned found=0;
            if(sp>=64 && !(sp&15))for(size_t i=0;i<flat_program.memory.kernel_count;i++) {
                const struct flat_mapping *m=flat_program.memory.kernel+i;
                if(sp-64<m->va || sp-m->va>m->bytes || !(m->attrs&0x400) || m->attrs&0x80)continue;
                uint64_t off=sp-64-m->va;
                if(off>UINT64_MAX-m->pa)continue;
                pa=m->pa+off;
                if(test_ram.bytes<64 || pa<test_ram.pa || pa-test_ram.pa>test_ram.bytes-64)continue;
                found=1;break;
            }
            if(!found)return (struct test_result){0,3,0x104,sp};
            if(pa<0x40000680 && pa+64>0x40000600)return (struct test_result){0,3,0x101,pa};
        }
    }
    if(flat_pc_index_count) {
        if(!(pc&3))for(uint64_t i=0;i<flat_pc_index_count;i++) {
            uint64_t base=i?0x2000:0x8000;
            if(pc-base>=0x1000)continue;
            if(pc==0x8000)r.resume=test_kernel_a;
            if(pc==0x8004)r.resume=test_kernel_b;
            if(pc==0x2000)r.resume=test_user;
        }
    } else {
        for(size_t i=0;i<flat_program.pc_count;i++)if(flat_program.pcs[i].pc==pc){r.resume=flat_program.pcs[i].target;return r;}
    }
    if(!r.resume)r.reason=0x100;
    return r;
}
static void test_resolve(uint64_t pc)
{
    struct test_result expected=test_reference(pc);
    memset((void *)&flat_full_result,0,sizeof flat_full_result);
    if(!setjmp(test_stop)) {
        flat_target actual=target(pc);
        assert(!expected.reason && actual==expected.resume);
    } else {
        assert(expected.reason && flat_full_result.reason==expected.reason);
        assert(flat_full_result.pc==pc && flat_full_result.detail==expected.detail && flat_full_result.far==expected.far);
        assert(flat_full_result.missing_pc==(expected.reason==0x100?pc:0));
    }
}
static void test_reset(void)
{
    memset(&target_cache,0,sizeof target_cache);
    test_ram=(struct flat_ram){0x40000000,0x2000,0};
    test_shadow.mode=OSREC_KERNEL;test_frame.cpu.sp=0x1800;test_control.live=&test_frame;
    flat_program=(struct flat_full_image){.memory={&test_ram,1,flat_maps,2,0,0},
        .shadow=&test_shadow,.pcs=test_pcs,.pc_count=3};
    flat_native_kernel_stack=1;flat_native_stack_range_count=1;flat_pc_index_count=2;
    flat_stack_index_init(&stack_index,&flat_program.memory,flat_maps);
    test_resolve(0x8000);assert(target_cache.resume==test_kernel_a);
}
int main(void)
{
    const uint64_t pcs[]={0x8000,0x8004,0x8008,0x8001,0x2000,0,UINT64_MAX};
    /* A stale binding must not return even a nonzero cached destination.
     * Corrupt each cached scalar bit while keeping the live tables valid. */
    for(unsigned field=0;field<5;field++)for(unsigned bit=0;bit<64;bit++) {
        test_reset();target_cache.resume=test_kernel_b;
        switch(field) {
        case 0:target_cache.pc^=1ull<<bit;break;
        case 1:target_cache.mode^=1ull<<bit;break;
        case 2:target_cache.native_stack^=1ull<<bit;break;
        case 3:target_cache.range_count^=1ull<<bit;break;
        case 4:target_cache.index_count^=1ull<<bit;break;
        }
        test_resolve(0x8000);
    }
    for(unsigned field=0;field<2;field++)for(unsigned bit=0;bit<64;bit++) {
        test_reset();
        if(field)test_ram.bytes^=1ull<<bit;else test_ram.pa^=1ull<<bit;
        test_resolve(0x8000);
    }
    for(unsigned bit=0;bit<64;bit++) {
        test_reset();test_frame.cpu.sp^=1ull<<bit;test_resolve(0x8000);
        test_frame.cpu.sp=0x1800;test_resolve(0x8000);
    }
    for(unsigned mode=0;mode<3;mode++)for(unsigned native=0;native<2;native++)
    for(unsigned ranges=0;ranges<=2;ranges++)for(unsigned indices=0;indices<=2;indices++)
    for(unsigned p=0;p<sizeof pcs/sizeof pcs[0];p++) {
        test_reset();test_shadow.mode=mode;flat_native_kernel_stack=native;
        flat_native_stack_range_count=ranges;flat_pc_index_count=indices;
        test_resolve(pcs[p]);test_resolve(pcs[p]);
    }
    test_reset();test_frame.cpu.sp=0x1680;test_resolve(0x8000); /* immutable overlap */
    for(unsigned size=0;size<=0x2000;size+=16) {
        test_reset();test_ram.bytes=size;test_resolve(0x8000);
    }
    test_reset();test_ram.pa+=0x1000;test_resolve(0x8000);
    test_reset();test_ram.pa-=0x1000;test_resolve(0x8000);
    struct flat_mapping mutable_maps[2]={flat_maps[0],flat_maps[1]};
    test_reset();flat_program.memory.kernel=mutable_maps;test_resolve(0x8000);
    mutable_maps[0].attrs|=0x80;test_resolve(0x8000);
    mutable_maps[0].attrs=0;test_resolve(0x8000);
    mutable_maps[0]=flat_maps[0];test_resolve(0x8000);
    flat_program.memory.kernel_count=0;test_resolve(0x8000);
    flat_program.memory.kernel_count=2;test_resolve(0x8000);
    /* Mutable legacy tables must never reuse an indexed or legacy result. */
    test_reset();flat_pc_index_count=0;test_resolve(0x8000);
    test_pcs[1].target=test_kernel_b;test_resolve(0x8000);
    test_pcs[1].target=0;test_resolve(0x8000);
    test_pcs[1].target=test_kernel_a;test_resolve(0x8000);
    flat_pc_index_count=2;test_resolve(0x8000);
    /* Legacy logical-stack resolution does not require a shadow pointer. */
    flat_native_kernel_stack=0;flat_program.shadow=0;test_resolve(0x8000);
    return 0;
}
