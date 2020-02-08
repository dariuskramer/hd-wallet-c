#include <stdio.h>
#include <stdint.h>

void dumpmem(const uint8_t *mem, size_t memlen)
{
	for (size_t i = 0; i < memlen; ++i)
		printf("%02x", mem[i]);

	printf("\n");
}
