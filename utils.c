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

void serialize_be_32(uint32_t i, uint8_t serialized[4])
{
	serialized[0] = (i >> 24);
	serialized[1] = (i >> 16) & 0xff;
	serialized[2] = (i >>  8) & 0xff;
	serialized[3] =  i        & 0xff;
}

void serialize_be_256(const uint8_t *p, uint8_t serialized[32])
{
	serialized[0]  = p[31];
	serialized[1]  = p[30];
	serialized[2]  = p[29];
	serialized[3]  = p[28];
	serialized[4]  = p[27];
	serialized[5]  = p[26];
	serialized[6]  = p[25];
	serialized[7]  = p[24];
	serialized[8]  = p[23];
	serialized[9]  = p[22];
	serialized[10] = p[21];
	serialized[11] = p[20];
	serialized[12] = p[19];
	serialized[13] = p[18];
	serialized[14] = p[17];
	serialized[15] = p[16];
	serialized[16] = p[15];
	serialized[17] = p[14];
	serialized[18] = p[13];
	serialized[19] = p[12];
	serialized[20] = p[11];
	serialized[21] = p[10];
	serialized[22] = p[9];
	serialized[23] = p[8];
	serialized[24] = p[7];
	serialized[25] = p[6];
	serialized[26] = p[5];
	serialized[27] = p[4];
	serialized[28] = p[3];
	serialized[29] = p[2];
	serialized[30] = p[1];
	serialized[31] = p[0];
}
