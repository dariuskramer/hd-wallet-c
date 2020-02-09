#include <unistd.h>
#include <stdio.h>
#include <stdint.h>

void error_print(const char *module, const char *msg)
{
	dprintf(STDERR_FILENO, "%s: %s\n", module, msg);
}

void dumpmem(const uint8_t *mem, size_t memlen)
{
	for (size_t i = 0; i < memlen; ++i)
		printf("%02x", mem[i]);

	printf("\n");
}
