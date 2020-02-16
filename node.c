#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>
#include <secp256k1.h>
#include "hd-wallet.h"

void node_dump(const struct s_wallet_node *master_node)
{
	char privkey_hex[NODE_PRIVKEY_SIZE * 2 + 1];
	char chaincode_hex[NODE_CHAINCODE_SIZE * 2 + 1];
	char compressed_pubkey_hex[NODE_COMPRESSED_PUBKEY_SIZE * 2 + 1];

	sodium_bin2hex(privkey_hex, sizeof(privkey_hex), master_node->privkey, NODE_PRIVKEY_SIZE);
	printf("privkey: %s\n", privkey_hex);

	sodium_bin2hex(chaincode_hex, sizeof(chaincode_hex), master_node->chaincode, NODE_CHAINCODE_SIZE);
	printf("chaincode: %s\n", chaincode_hex);

	sodium_bin2hex(compressed_pubkey_hex, sizeof(compressed_pubkey_hex), master_node->serialized_pubkey, NODE_COMPRESSED_PUBKEY_SIZE);
	printf("compressed pubkey: %s\n", compressed_pubkey_hex);

	printf("index: %u\n", master_node->index);
}

static int node_init(struct s_wallet_node *node, const uint8_t *left, const uint8_t *right, uint32_t index)
{
	int ret;

	memcpy(node->privkey, left, NODE_PRIVKEY_SIZE);
	memcpy(node->chaincode, right, NODE_CHAINCODE_SIZE);

	ret = secp256k1_ec_seckey_verify(ctx, (const unsigned char*)node->privkey);
	if (ret == 0)
	{
		ERROR("secret key is invalid");
		return -1;
	}

	/* Compute pubkey
	 */
	ret = point_from_byte_array(node->privkey, &node->pubkey);
	if (ret == -1)
		return -1;

	/* Serialize pubkey
	 */
	ret = serialize_point(&node->pubkey, node->serialized_pubkey);
	if (ret == -1)
		return -1;

	node->index = index;

	return 0;
}

int node_master_generate(const uint8_t *seed, size_t seedlen, struct s_wallet_node *master_node)
{
	uint8_t key[] = "Bitcoin seed";
	uint8_t left[crypto_auth_hmacsha512_BYTES / 2];
	uint8_t right[crypto_auth_hmacsha512_BYTES / 2];

	hmac_sha512(key, sizeof(key), seed, seedlen, left, right);

	return node_init(master_node, left, right, 0);
}
