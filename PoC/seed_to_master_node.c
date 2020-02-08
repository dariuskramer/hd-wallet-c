#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <secp256k1.h>

void dumpmem(const uint8_t *mem, size_t memlen);

void error_print(const char *msg)
{
	fputs(msg, stderr);
}

struct s_extended_key
{
	uint8_t privkey[32];
	uint8_t chaincode[32];
};

int main(void)
{
	uint8_t seed[32] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"; // 256 bits
	uint8_t key[] = "Bitcoin seed";
	uint8_t hash[crypto_auth_hmacsha512_BYTES];
	crypto_auth_hmacsha512_state state;
	struct s_extended_key *extended_master_key = (struct s_extended_key*)&hash;

	if (sodium_init() < 0)
	{
		error_print("panic! the library couldn't be initialized, it is not safe to use");
		return EXIT_FAILURE;
	}

	crypto_auth_hmacsha512_init(&state, key, sizeof(key));
	crypto_auth_hmacsha512_update(&state, seed, sizeof(seed));
	crypto_auth_hmacsha512_final(&state, hash);

	extended_master_key = (struct s_extended_key*)&hash;

	secp256k1_context *ctx;
	secp256k1_pubkey pubkey;
	int ret;

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	if (ctx == NULL)
	{
		error_print("secp256k1_context_create: failed to create context!");
		return EXIT_FAILURE;
	}

	ret = secp256k1_ec_seckey_verify(ctx, (const unsigned char*)&extended_master_key->privkey);
	if (ret == 0)
	{
		error_print("secp256k1_ec_seckey_verify: secret key is invalid");
		return EXIT_FAILURE;
	}

	ret = secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char*)&extended_master_key->privkey);
	if (ret == 0)
	{
		error_print("secp256k1_ec_pubkey_create: secret was invalid");
		return EXIT_FAILURE;
	}

	// Serialize PubKey
	uint8_t output[33] = {0};
	size_t outputlen = sizeof output;

	secp256k1_ec_pubkey_serialize(ctx, output, &outputlen, &pubkey, SECP256K1_EC_COMPRESSED);

	secp256k1_context_destroy(ctx);

	// Debug
	printf(">>> HMAC-SHA512: "); dumpmem(hash, crypto_auth_hmacsha512_BYTES);
	printf(">>> Private Key: "); dumpmem(extended_master_key->privkey, 32);
	printf(">>> Chain Code: "); dumpmem(extended_master_key->chaincode, 32);
	printf(">>> Serialized Public Key: "); dumpmem(output, outputlen);

	return EXIT_SUCCESS;
}
