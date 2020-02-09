#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>

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

void serialize32(uint32_t i, uint8_t serialized[4])
{
	serialized[0] = (i >> 24);
	serialized[1] = (i >> 16) & 0xff;
	serialized[2] = (i >>  8) & 0xff;
	serialized[3] =  i        & 0xff;
}

void serialize256(const uint8_t *src, uint8_t serialized[32])
{
	serialized[0]  = src[31];
	serialized[1]  = src[30];
	serialized[2]  = src[29];
	serialized[3]  = src[28];
	serialized[4]  = src[27];
	serialized[5]  = src[26];
	serialized[6]  = src[25];
	serialized[7]  = src[24];
	serialized[8]  = src[23];
	serialized[9]  = src[22];
	serialized[10] = src[21];
	serialized[11] = src[20];
	serialized[12] = src[19];
	serialized[13] = src[18];
	serialized[14] = src[17];
	serialized[15] = src[16];
	serialized[16] = src[15];
	serialized[17] = src[14];
	serialized[18] = src[13];
	serialized[19] = src[12];
	serialized[20] = src[11];
	serialized[21] = src[10];
	serialized[22] = src[9];
	serialized[23] = src[8];
	serialized[24] = src[7];
	serialized[25] = src[6];
	serialized[26] = src[5];
	serialized[27] = src[4];
	serialized[28] = src[3];
	serialized[29] = src[2];
	serialized[30] = src[1];
	serialized[31] = src[0];
}

void hmac_sha512(const uint8_t *key, size_t keylen,
		const uint8_t *data, size_t datalen,
		uint8_t *left, uint8_t *right)
{
	uint8_t hash[crypto_auth_hmacsha512_BYTES];
	size_t half = sizeof(hash) / 2;
	crypto_auth_hmacsha512_state state;

	crypto_auth_hmacsha512_init(&state, key, keylen);
	crypto_auth_hmacsha512_update(&state, data, datalen);
	crypto_auth_hmacsha512_final(&state, hash);

	memcpy(left, hash, half);
	memcpy(right, hash + half, half);
}
