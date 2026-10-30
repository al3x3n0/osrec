/* Independent fixture: ordinary computation above an architecture dependency. */
extern unsigned long kernel_clock(void);

unsigned long transform(unsigned long value)
{
    return (value * 3) ^ 0x51;
}

unsigned long el0_scenario(unsigned long *result)
{
    unsigned long value = transform(kernel_clock());
    *result = value;
    return value;
}
