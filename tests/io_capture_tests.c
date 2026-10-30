#include "osrec/io_capture.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"read hook check failed: %d\n",__LINE__); return 1; } } while (0)
int main(int argc, char **argv)
{
    const char *hash = argc == 3 ? argv[2] : "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    CHECK(strlen(hash)==64);
    unsigned char storage[512];
    struct osrec_buffer b;
    struct osrec_object_ref ref = {10,2};
    CHECK(osrec_begin(&b,storage,sizeof(storage),hash)==0);
    CHECK(osrec_record_read(&b,0,17,4,ref,2,0,"AB")==0);
    ref.offset=4;
    CHECK(osrec_record_read(&b,1,17,2,ref,0,0,NULL)==0);
    ref.offset=6;
    CHECK(osrec_record_read(&b,2,17,2,ref,-1,11,NULL)==0);
    CHECK(osrec_finish(&b)==0);
    CHECK(b.used==326 && !b.failed);
    if (argc==3) {
        FILE *file=fopen(argv[1],"wb"); CHECK(file);
        CHECK(fwrite(storage,1,b.used,file)==b.used);
        CHECK(fclose(file)==0);
    }
    CHECK(osrec_begin(&b,storage,161,hash)==0);
    CHECK(osrec_record_read(&b,0,17,4,ref,2,0,"AB")==-1);
    CHECK(b.failed && b.used==84 && osrec_finish(&b)==-1);
    CHECK(osrec_begin(&b,storage,sizeof(storage),hash)==0);
    CHECK(osrec_record_read(&b,0,17,1,ref,2,0,"AB")==-1);
    CHECK(b.failed && b.used==84);
    CHECK(osrec_begin(&b,storage,sizeof(storage),hash)==0);
    CHECK(osrec_record_read(&b,0,17,2,ref,-1,0,NULL)==-1);
    CHECK(osrec_begin(&b,storage,sizeof(storage),hash)==0);
    CHECK(osrec_record_read(&b,0,17,2,ref,1,0,NULL)==-1);
    CHECK(osrec_begin(&b,storage,sizeof(storage),hash)==0);
    CHECK(osrec_record_read(&b,0,17,2,(struct osrec_object_ref){0,0},1,0,"A")==-1);
    return 0;
}
