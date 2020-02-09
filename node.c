#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>
#include <secp256k1.h>
#include "hd-wallet.h"

static void node_compute_hmac_sha512(const uint8_t *key, size_t keylen,
		const uint8_t *data, size_t datalen,
		uint8_t hash[crypto_auth_hmacsha512_BYTES])
{
	crypto_auth_hmacsha512_state state;

	crypto_auth_hmacsha512_init(&state, key, keylen);
	crypto_auth_hmacsha512_update(&state, data, datalen);
	crypto_auth_hmacsha512_final(&state, hash);
}

void node_dump(const struct s_wallet_node *master_node)
{
	char privkey_hex[NODE_PRIVKEY_SIZE * 2 + 1];
	char chaincode_hex[NODE_CHAINCODE_SIZE * 2 + 1];
	char compressed_pubkey_hex[NODE_COMPRESSED_PUBKEY_SIZE * 2 + 1];
	char uncompressed_pubkey_hex[NODE_UNCOMPRESSED_PUBKEY_SIZE * 2 + 1];
	unsigned char output[NODE_UNCOMPRESSED_PUBKEY_SIZE];
	size_t outputlen = sizeof(output);

	puts(">>> Dump wallet node");

	sodium_bin2hex(privkey_hex, sizeof(privkey_hex), master_node->privkey, NODE_PRIVKEY_SIZE);
	printf("privkey: %s\n", privkey_hex);

	sodium_bin2hex(chaincode_hex, sizeof(chaincode_hex), master_node->chaincode, NODE_CHAINCODE_SIZE);
	printf("chaincode: %s\n", chaincode_hex);

	secp256k1_ec_pubkey_serialize(ctx, output, &outputlen, &master_node->pubkey, SECP256K1_EC_COMPRESSED);
	sodium_bin2hex(compressed_pubkey_hex, sizeof(compressed_pubkey_hex), output, outputlen);
	printf("compressed pubkey: %s\n", compressed_pubkey_hex);

	outputlen = sizeof(output);
	secp256k1_ec_pubkey_serialize(ctx, output, &outputlen, &master_node->pubkey, SECP256K1_EC_UNCOMPRESSED);
	sodium_bin2hex(uncompressed_pubkey_hex, sizeof(uncompressed_pubkey_hex), output, outputlen);
	printf("uncompressed pubkey: %s\n", uncompressed_pubkey_hex);
}

int node_init(struct s_wallet_node *node, const uint8_t hash[crypto_auth_hmacsha512_BYTES], uint32_t index)
{
	int ret;

	memcpy(node->privkey, hash, NODE_PRIVKEY_SIZE);
	memcpy(node->chaincode, hash + NODE_PRIVKEY_SIZE, NODE_CHAINCODE_SIZE);

	ret = secp256k1_ec_seckey_verify(ctx, (const unsigned char*)&node->privkey);
	if (ret == 0)
	{
		error_print("secp256k1_ec_seckey_verify", "secret key is invalid");
		return -1;
	}

	ret = secp256k1_ec_pubkey_create(ctx, &node->pubkey, (const unsigned char*)&node->privkey);
	if (ret == 0)
	{
		error_print("secp256k1_ec_pubkey_create", "secret was invalid");
		return -1;
	}

	node->index = index;

	return 0;
}

int node_master_generate(const uint8_t *seed, size_t seedlen, struct s_wallet_node *master_node)
{
	uint8_t key[] = "Bitcoin seed";
	uint8_t hash[crypto_auth_hmacsha512_BYTES];

	node_compute_hmac_sha512(key, sizeof(key), seed, seedlen, hash);

	return node_init(master_node, hash, 0);
}
