#include <stddef.h>
void *memcpy(void *out,const void *in,size_t size)
{unsigned char *d=out;const unsigned char *s=in;for(size_t i=0;i<size;i++)d[i]=s[i];return out;}
void *memset(void *out,int byte,size_t size)
{unsigned char *d=out;for(size_t i=0;i<size;i++)d[i]=(unsigned char)byte;return out;}
