#include "buffer_types.h"
static uint64_t visits;
static Buffer buffers[2]={
    [0]={.words={[0]=0x13579bdf,[3]=0x2468ace0}},
    [1]={.words={0x11223344,0x55667788,0x99aabbcc,0xddeeff00}}
};
static uint32_t *cursor=&buffers[1].words[1],*alias=&buffers[1].words[1],*end=&buffers[1].words[4];
static uint64_t Tick(void)
{
    return ++visits;
}
uint64_t BufferStep(uint64_t operation,void *output)
{
    static uint64_t calls=0;
    uint64_t result=0;
    uint64_t tick=Tick();
    if(ProviderTick()!=3*tick)return UINT64_MAX;
    if(operation==0){cursor=&buffers[0].words[1];alias=cursor;end=&buffers[0].words[4];*cursor=0x10203040;result=*cursor;}
    else if(operation==1){++cursor;*cursor=0x50607080;result=*cursor;}
    else if(operation==2){cursor=&buffers[1].words[0];alias=cursor;end=&buffers[1].words[4];*cursor=0x90a0b0c0;result=*cursor;}
    else if(operation==3){cursor+=3;*cursor=0xd0e0f001;result=*cursor;}
    else if(operation==4){cursor=end;result=UINT64_C(0x100000004);}
    else if(operation==5){cursor=alias=end=NULL;}
    ++calls;
    for(unsigned i=0;i<8;++i)((unsigned char *)output)[i]=(unsigned char)(result>>(8*i));
    return result;
}
