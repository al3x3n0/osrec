/* Embedded byte helpers required by ARM aggregate copies; no allocator or I/O. */
#include <stddef.h>
void *memcpy(void *out,const void *in,size_t size)
{
    volatile unsigned char *destination=out;
    const volatile unsigned char *source=in;
    for(size_t i=0;i<size;++i) destination[i]=source[i];
    return out;
}
void *memset(void *out,int value,size_t size)
{
    volatile unsigned char *destination=out;
    for(size_t i=0;i<size;++i) destination[i]=(unsigned char)value;
    return out;
}
void __aeabi_memcpy(void *out,const void *in,size_t size) { (void)memcpy(out,in,size); }
void __aeabi_memcpy4(void *out,const void *in,size_t size) { (void)memcpy(out,in,size); }
void __aeabi_memcpy8(void *out,const void *in,size_t size) { (void)memcpy(out,in,size); }
void __aeabi_memclr(void *out,size_t size) { (void)memset(out,0,size); }
void __aeabi_memclr4(void *out,size_t size) { (void)memset(out,0,size); }
void __aeabi_memclr8(void *out,size_t size) { (void)memset(out,0,size); }
void __aeabi_memset(void *out,size_t size,int value) { (void)memset(out,value,size); }
void __aeabi_memset4(void *out,size_t size,int value) { (void)memset(out,value,size); }
void __aeabi_memset8(void *out,size_t size,int value) { (void)memset(out,value,size); }
