/* A callback selected by the scenario, plus intentionally unused private work.
 * Compile at -O0 to leave that work visible to the instruction analyzer.
 */
typedef unsigned (*operation)(unsigned);

static unsigned add_seven(unsigned input)
{
    return input + 7;
}

static unsigned triple(unsigned input)
{
    return input * 3;
}

unsigned callback_scenario(unsigned input, unsigned choose)
{
    unsigned unused = input * 99;
    operation selected = choose ? add_seven : triple;
    (void)unused;
    return selected(input);
}
