#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <secp256k1.h>
#include <openssl/sha.h>
#include "libbase58.h"

void dumpmem(const uint8_t *mem, size_t memlen);

void error_print(const char *msg)
{
	fputs(msg, stderr);
}

bool my_sha256(void *digest, const void *data, size_t datasz)
{
	SHA256(data, datasz, digest);
	return true;
}

struct s_extended_key
{
	uint8_t privkey[32];
	uint8_t chaincode[32];
};

void generate_extended_key(uint8_t *privkey, uint8_t *chaincode)
{
	uint8_t seed[32] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"; // 256 bits
	uint8_t key[] = "Bitcoin seed";
	uint8_t hash[crypto_auth_hmacsha512_BYTES];
	crypto_auth_hmacsha512_state state;
	struct s_extended_key *extended_master_key = (struct s_extended_key*)&hash;

	if (sodium_init() < 0)
	{
		error_print("panic! the library couldn't be initialized, it is not safe to use");
	}

	crypto_auth_hmacsha512_init(&state, key, sizeof(key));
	crypto_auth_hmacsha512_update(&state, seed, sizeof(seed));
	crypto_auth_hmacsha512_final(&state, hash);

	extended_master_key = (struct s_extended_key*)&hash;
	memcpy(privkey, extended_master_key->privkey, 32);
	memcpy(chaincode, extended_master_key->chaincode, 32);

	dumpmem(hash, crypto_auth_hmacsha512_BYTES);
	dumpmem(privkey, 32);
	dumpmem(chaincode, 32);
}

int main(void)
{
	uint8_t version[4] = { 0x04, 0x88, 0xad, 0xe4 };
	uint8_t depth = 0x00;
	uint8_t fingerprint[4] = { 0x0 };
	uint8_t child_number[4] = { 0x0 };
	uint8_t chaincode[32] = {0};
	uint8_t privkey[32] = {0};

	generate_extended_key(privkey, chaincode);

	uint8_t data[78] = {0};
	memcpy(data, version, 4);
	data[4] = depth;
	memcpy(data + 5, fingerprint, 4);
	memcpy(data + 9, child_number, 4);
	memcpy(data + 13, chaincode, 32);
	data[45] = 0x0; // byte before privkey
	memcpy(data + 46, privkey, 32);

	dumpmem(data, sizeof data);

	uint8_t b58[128] = {0};
	size_t b58len = sizeof b58;

	b58_sha256_impl = my_sha256;
	bool ret = b58check_enc((char*)b58, &b58len, 0x0, data, sizeof data);
	if (!ret)
	{
		error_print("b58check_enc failed!");
		return EXIT_FAILURE;
	}

	printf("b58len: %zu\n", b58len);
	printf("%s\n", b58+1);
}
