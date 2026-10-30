/* Generated from the reviewed port argument kinds. Capture only. */
static unsigned osrec_native_buffer_object(uint64_t syscall,unsigned argument)
{
    switch(syscall){
    case UINT64_C(148):
        if(argument==0)return 1;
        if(argument==1)return 1;
        if(argument==2)return 1;
        return 0;
    case UINT64_C(150):
        if(argument==0)return 1;
        if(argument==1)return 1;
        if(argument==2)return 1;
        return 0;
    case UINT64_C(63):
        if(argument==1)return 1;
        return 0;
    case UINT64_C(64):
        if(argument==1)return 1;
        return 0;
    case UINT64_C(67):
        if(argument==1)return 1;
        return 0;
    case UINT64_C(68):
        if(argument==1)return 1;
        return 0;
    case UINT64_C(80):
        if(argument==1)return 2;
        return 0;
    case UINT64_C(91):
        if(argument==0)return 1;
        if(argument==1)return 1;
        return 0;
    case UINT64_C(158):
        if(argument==1)return 1;
        return 0;
    case UINT64_C(159):
        if(argument==1)return 1;
        return 0;
    case UINT64_C(90):
        if(argument==0)return 1;
        if(argument==1)return 1;
        return 0;
    case UINT64_C(163):
        if(argument==1)return 1;
        return 0;
    default:return 0;
    }
}
