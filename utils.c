#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "hd-wallet.h"

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

int get_next_index(const char **key_path, uint32_t *next_index, bool *hardened)
{
	char	*end;

	if (**key_path == '\0')
		return 0;

	*next_index = (uint32_t)strtoul(*key_path, &end, 10);

	if (*end == KEY_HARDENED_MARKER)
	{
		if (*next_index > KEY_HARDENED_OFFSET)
		{
			ERROR("hardened index overflow");
			return -1;
		}
		*hardened = true;
		end += 1;
	}
	else
		*hardened = false;

	if (*end != '\0')
		end += 1;

	*key_path = end;
	return 1;
}
