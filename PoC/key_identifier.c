#include <string.h>
#include <stdio.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

/* Compile with: -lssl -lcrypto
 */

void dumpmem(const uint8_t *mem, size_t memlen);

uint8_t *hash160(const char *msg, size_t msglen, uint8_t *digest)
{
	unsigned char sha256[SHA256_DIGEST_LENGTH] = {0};
	unsigned char ripemd160[RIPEMD160_DIGEST_LENGTH] = {0};

	SHA256((unsigned char*)msg, msglen, sha256);
	RIPEMD160(sha256, SHA256_DIGEST_LENGTH, ripemd160);

	/* dumpmem(sha256, SHA256_DIGEST_LENGTH); */
	/* dumpmem(ripemd160, RIPEMD160_DIGEST_LENGTH); */

	memcpy(digest, ripemd160, RIPEMD160_DIGEST_LENGTH);

	return digest;
}

int main(void)
{
	uint8_t digest[RIPEMD160_DIGEST_LENGTH];
	const char msg[] = "test";

	hash160(msg, sizeof(msg) - 1, digest);

	dumpmem(digest, RIPEMD160_DIGEST_LENGTH);
}
