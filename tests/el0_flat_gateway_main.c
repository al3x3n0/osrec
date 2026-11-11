/* Exercise the shared gateway independently of captured kernel fixtures. */
extern int flat_gateway_selftest(void);
int flat_main(void)
{
    return flat_gateway_selftest();
}
