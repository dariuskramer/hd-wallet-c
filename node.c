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
	char fingerprint_hex[NODE_FINGERPRINT_SIZE * 2 + 1];

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

	// Fingerprint
	sodium_bin2hex(fingerprint_hex, sizeof(fingerprint_hex), master_node->fingerprint, sizeof(master_node->fingerprint));
	printf("fingerprint: %s\n", fingerprint_hex);
}

static int node_fill(struct s_wallet_node *node,
		const struct s_extended_private_key *ext_key,
		const struct s_extended_private_key *ext_parent,
		uint32_t index,
		uint8_t depth)
{
	if (secp256k1_ec_seckey_verify(ctx, (const unsigned char*)ext_key->privkey) == 0)
	{
		ERROR("secret key is invalid");
		return -1;
	}

	memmove(node->privkey,   ext_key->privkey,   NODE_PRIVKEY_SIZE);
	memmove(node->chaincode, ext_key->chaincode, NODE_CHAINCODE_SIZE);

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

	/* Parent fingerprint
	 */
	struct s_wallet_node parent;
	if (point_from_byte_array(ext_parent->privkey, &parent.pubkey) == -1)
		return -1;
	if (serialize_point(&parent.pubkey, parent.serialized_pubkey) == -1)
		return -1;
	key_fingerprint(node->fingerprint, parent.serialized_pubkey);
	sodium_memzero(&parent, sizeof(parent));

	return 0;
}

static void node_print_b58(const struct s_wallet_node *node, bool public)
{
	uint8_t b58[128] = {0};

	b58_node(b58, sizeof(b58), node, public);
	puts((char*)b58);

	sodium_memzero(b58, sizeof(b58));
}

int node_generate_master(const uint8_t *seed, size_t seedlen, struct s_wallet_node *master_node)
{
	struct s_wallet_node			tmp_node;
	struct s_extended_private_key	tmp_key;
	uint8_t							key[] = "Bitcoin seed";
	uint8_t 						left[crypto_auth_hmacsha512_BYTES / 2];
	uint8_t 						right[crypto_auth_hmacsha512_BYTES / 2];
	int								ret = 0;

	hmac_sha512(key, sizeof(key), seed, seedlen, left, right);

	/* Privkey
	 */
	memcpy(tmp_node.privkey, left, NODE_PRIVKEY_SIZE);

	/* Chaincode
	 */
	memcpy(tmp_node.chaincode, right, NODE_CHAINCODE_SIZE);

	/* Pubkey, Index, Depth, Fingerprint
	 */
	tmp_key.privkey = tmp_node.privkey;
	tmp_key.chaincode = tmp_node.chaincode;
	ret = node_fill(master_node, &tmp_key, &tmp_key, 0, 0);
	memset(master_node->fingerprint, 0x00, NODE_FINGERPRINT_SIZE);

	sodium_memzero(left, sizeof(left));
	sodium_memzero(right, sizeof(right));
	sodium_memzero(&tmp_node, sizeof(tmp_node));

	return ret;
}

int node_compute_key_path(const char *key_path, const struct s_wallet_node *master_node, struct s_wallet_node *target_node)
{
	struct s_wallet_node			parent_node;
	struct s_extended_private_key	ext_parent;
	struct s_extended_private_key	ext_child;
	uint32_t						target_index;
	uint8_t							depth = 0;
	int								ret = 0;
	bool							hardened;
	bool							is_target_public = false;

	if (key_path[0] == 'M')
		is_target_public = true;

	/* Bootstrap
	 */
	*target_node = *master_node;
	ext_parent.privkey   = parent_node.privkey;
	ext_parent.chaincode = parent_node.chaincode;
	ext_child.privkey    = target_node->privkey;
	ext_child.chaincode  = target_node->chaincode;

	if (strlen(key_path) < 3)
	{
		node_print_b58(target_node, is_target_public);
		goto cleanup;
	}

	/* Jump to first index
	 */
	key_path += 2;

	while ((ret = get_next_index(&key_path, &target_index, &hardened)) == 1)
	{
		memcpy(ext_parent.privkey,   ext_child.privkey,   NODE_PRIVKEY_SIZE);
		memcpy(ext_parent.chaincode, ext_child.chaincode, NODE_CHAINCODE_SIZE);

		if (hardened)
			target_index |= KEY_HARDENED_OFFSET;

		ret = ckd_private_parent_to_private_child(&ext_parent, &ext_child, target_index);
		if (ret == -1)
			goto cleanup;

		depth += 1;
	}
	if (ret == -1)
		goto cleanup;

	/* Fill child node
	 */
	ret = node_fill(target_node, &ext_child, &ext_parent, target_index, depth);
	if (ret == -1)
		goto cleanup;

	/* Display serialized extended key
	 */
	node_print_b58(target_node, is_target_public);

cleanup:
	sodium_memzero(&parent_node, sizeof(parent_node));

	return ret;
}
