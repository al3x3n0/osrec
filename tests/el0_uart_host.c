/* Independent register-buffer/output contract for inline UART operations. */
#include "program.h"
struct osrec_shadow flat_shadow;
struct flat_full_image flat_program;
struct flat_control control,*flat_active=&control;
unsigned char flat_uart[4096],flat_uart_registers[4096];
uint64_t flat_uart_used,test_fast,test_vector[2] __attribute__((aligned(16)));
static unsigned char stack[16384] __attribute__((aligned(16)));
typedef void (*probe)(const struct osrec_context *,struct osrec_context *);
struct fixture {unsigned word;probe run;};
#include "cases.h"
static void fill(unsigned char *p,unsigned char v,size_t n){while(n--)*p++=v;}
static int equal(const void *a,const void *b,size_t n)
{const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
int test_main(void)
{
    static unsigned char registers[4096],output[4096];
    const int offsets[]={0,0x18,0x38,1,4095,-1,4096};
    const unsigned counts[]={0,4095,4096};
    for(unsigned f=0;f<sizeof fixtures/sizeof fixtures[0];f++)for(unsigned flags=0;flags<16;flags++)
    for(unsigned mode=0;mode<2;mode++)for(unsigned off=0;off<7;off++)
    for(unsigned count=0;count<3;count++)for(unsigned changed=0;changed<2;changed++) {
        unsigned w=fixtures[f].word,rn=w>>5&31,rt=w&31,bytes=1u<<(w>>30);
        int load=(w>>22&3)!=0,vector=!!(w&(1u<<26));
        uint64_t va=0x2000000ull+offsets[off],expected_count=counts[count];
        flat_program.uart_va=0x2000000ull+4096*changed;flat_shadow.mode=mode;
        fill(registers,0xa5,sizeof registers);registers[0x18]=0x00;registers[0x19]=0x7f;
        registers[0x1a]=0x80;registers[0x1b]=0xff;
        fill(output,0x5a,sizeof output);
        for(unsigned i=0;i<4096;i++){flat_uart_registers[i]=registers[i];flat_uart[i]=output[i];}
        flat_uart_used=counts[count];
        struct osrec_context before={0},after={0},expected;
        for(unsigned r=0;r<31;r++)before.x[r]=0x1020304050607080ull*(r+1);
        before.sp=(uintptr_t)(stack+sizeof stack);before.pstate=(uint64_t)flags<<28;
        if(rn!=31)before.x[rn]=va;
        control.guest_sp=va;
        if(w==0xb8008c30u)before.x[rn]=va-8;
        if(w==0xb862d820u){before.x[1]=va-8;before.x[2]=2;}
        expected=before;
        int fast=!changed && mode==OSREC_KERNEL && (load?offsets[off]==0x18:offsets[off]==0 || offsets[off]==0x38) &&
            !(offsets[off]==0 && !load && counts[count]==4096);
        uint64_t expected_vector[2]={0x5a5a5a5a5a5a5a5aull,0x5a5a5a5a5a5a5a5aull};
        if(fast) {
            uint64_t value=0;
            if(load) {
                for(unsigned i=0;i<bytes;i++)value|=(uint64_t)registers[offsets[off]+i]<<(8*i);
                if(vector){expected_vector[0]=value;expected_vector[1]=0;}
                else if(rt!=31)expected.x[rt]=w==0xb9800020u?(uint64_t)(int64_t)(int32_t)value:value;
            } else {
                value=vector?expected_vector[0]:rt==31?0:before.x[rt];
                for(unsigned i=0;i<bytes;i++)registers[offsets[off]+i]=(unsigned char)(value>>(8*i));
                if(offsets[off]==0)output[expected_count++]=registers[0];
            }
            if(w==0xb8008c30u)expected.x[rn]=va;
            if(w==0xb8008430u)expected.x[rn]=va+8;
        }
        test_fast=99;fixtures[f].run(&before,&after);
        if(test_fast!=(unsigned)fast)return 10;
        if(!equal(&expected,&after,sizeof expected))return 20;
        if(control.guest_sp!=(fast && w==0xb80087e0u?va+8:va))return 30;
        if(flat_uart_used!=expected_count)return 40;
        if(!equal(registers,flat_uart_registers,4096))return 50;
        if(!equal(output,flat_uart,4096))return 60;
        if(!equal(test_vector,expected_vector,sizeof expected_vector))return 70;
    }
    return 0;
}
