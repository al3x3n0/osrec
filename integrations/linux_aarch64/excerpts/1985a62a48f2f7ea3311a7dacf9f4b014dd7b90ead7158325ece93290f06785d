// SPDX-License-Identifier: GPL-2.0-or-later
/* Reviewed original Linux v6.10 lib/find_bit.c definitions. */

unsigned long _find_next_zero_bit(const unsigned long *addr, unsigned long nbits,
					 unsigned long start)
{
	return FIND_NEXT_BIT(~addr[idx], /* nop */, nbits, start);
}
