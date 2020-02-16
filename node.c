#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <sodium.h>
#include <secp256k1.h>
#include "hd-wallet.h"

void node_init(struct s_wallet_node *node)
{
	memset(node, 0xff, sizeof(*node));
}

void node_dump(const struct s_wallet_node *master_node)
{
	char privkey_hex[NODE_PRIVKEY_SIZE * 2 + 1];
	char chaincode_hex[NODE_CHAINCODE_SIZE * 2 + 1];
	char pubkey_hex[sizeof(secp256k1_pubkey) * 2 + 1];
	char serialized_pubkey_hex[128];

	// Privkey
	sodium_bin2hex(privkey_hex, sizeof(privkey_hex), master_node->privkey, sizeof(master_node->privkey));
	printf("privkey: %s\n", privkey_hex);

	// Chaincode
	sodium_bin2hex(chaincode_hex, sizeof(chaincode_hex), master_node->chaincode, sizeof(master_node->chaincode));
	printf("chaincode: %s\n", chaincode_hex);

	// Pubkey
	sodium_bin2hex(pubkey_hex, sizeof(pubkey_hex), master_node->pubkey.data, sizeof(master_node->pubkey));
	printf("pubkey: [%s]\n", pubkey_hex);

	// Serialized Pubkey
	sodium_bin2hex(serialized_pubkey_hex, sizeof(serialized_pubkey_hex), master_node->serialized_pubkey, sizeof(master_node->serialized_pubkey));
	printf("serialized pubkey: %s\n", serialized_pubkey_hex);

	printf("index: %u\n", master_node->index);
	printf("depth: %u\n", master_node->depth);
}

static int node_fill(struct s_wallet_node *node, const uint8_t *privkey, const uint8_t *chaincode, uint32_t index, uint8_t depth)
{
	if (secp256k1_ec_seckey_verify(ctx, (const unsigned char*)privkey) == 0)
	{
		ERROR("secret key is invalid");
		return -1;
	}

	memmove(node->privkey,   privkey,   NODE_PRIVKEY_SIZE);
	memmove(node->chaincode, chaincode, NODE_CHAINCODE_SIZE);

	/* Compute the Public Key
	 */
	if (point_from_byte_array(node->privkey, &node->pubkey) == -1)
		return -1;

	/* Serialize the Public Key
	 */
	if (serialize_point(&node->pubkey, node->serialized_pubkey) == -1)
		return -1;

	node->index = index;
	node->depth = depth;

	return 0;
}

int node_generate_master(const uint8_t *seed, size_t seedlen, struct s_wallet_node *master_node)
{
	uint8_t key[] = "Bitcoin seed";
	uint8_t left[crypto_auth_hmacsha512_BYTES / 2];
	uint8_t parsed_left[sizeof(left)];
	uint8_t right[crypto_auth_hmacsha512_BYTES / 2];
	int		ret = 0;

	hmac_sha512(key, sizeof(key), seed, seedlen, left, right);
	parse256(left, parsed_left);

	ret = node_fill(master_node, parsed_left, right, 0, 0);

	sodium_memzero(left, sizeof(left));
	sodium_memzero(parsed_left, sizeof(parsed_left));
	sodium_memzero(right, sizeof(right));

	return ret;
}

int node_compute_key_path(const char *key_path, const struct s_wallet_node *master_node, struct s_wallet_node *target_node)
{
	struct s_wallet_node			parent_node = *master_node;
	struct s_extended_private_key	ext_parent;
	struct s_extended_private_key	ext_child;
	uint32_t						target_index;
	uint8_t							depth = 0;
	int								ret = 0;
	bool							hardened;
	bool							is_target_public = false;

	if (key_path[0] == 'M')
		is_target_public = true;

	// TODO
	assert(key_path[0] != '\0' && key_path[1] == '/');
	key_path += 2;

	/* Bootstrap
	 */
	ext_parent.privkey   = parent_node.privkey;
	ext_parent.chaincode = parent_node.chaincode;
	ext_child.privkey    = target_node->privkey;
	ext_child.chaincode  = target_node->chaincode;

	while ((ret = get_next_index(&key_path, &target_index, &hardened)) == 1)
	{
		/* memcpy(parent_node.privkey,   ext_child.privkey,   sizeof(parent_node.privkey)); */
		/* memcpy(parent_node.chaincode, ext_child.chaincode, sizeof(parent_node.chaincode)); */

		ret = ckd_private_parent_to_private_child(&ext_parent, &ext_child, target_index);
		if (ret == -1)
			goto cleanup;

		depth += 1;
	}
	if (ret == -1)
		goto cleanup;

	/* Fill parent node
	 */
	ret = node_fill(&parent_node, parent_node.privkey, parent_node.chaincode, target_index-1, depth-1); // TODO -1
	if (ret == -1)
		goto cleanup;

	/* Fill child node
	 */
	ret = node_fill(target_node, target_node->privkey, target_node->chaincode, target_index, depth); // TODO -1
	if (ret == -1)
		goto cleanup;

	if (is_target_public)
		sodium_memzero(target_node->privkey, sizeof(target_node->privkey));

	/* Display serialized extended key
	 */
	uint8_t b58[128] = {0};

	node_dump(target_node);
	b58_node(b58, sizeof(b58), target_node, &parent_node, is_target_public);
	printf("b58: %s\n", b58);

	sodium_memzero(b58, sizeof(b58));

cleanup:
	sodium_memzero(&parent_node, sizeof(parent_node));

	return ret;
}
