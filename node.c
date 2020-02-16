#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
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

int node_generate_master(const uint8_t *seed, size_t seedlen, struct s_wallet_node *master_node)
{
	uint8_t key[] = "Bitcoin seed";
	uint8_t left[crypto_auth_hmacsha512_BYTES / 2];
	uint8_t parsed_left[sizeof(left)];
	uint8_t right[crypto_auth_hmacsha512_BYTES / 2];
	int		ret = 0;

	hmac_sha512(key, sizeof(key), seed, seedlen, left, right);
	parse256(left, parsed_left);

	memcpy(master_node->privkey, parsed_left, NODE_PRIVKEY_SIZE);
	memcpy(master_node->chaincode, right, NODE_CHAINCODE_SIZE);

	if (secp256k1_ec_seckey_verify(ctx, (const unsigned char*)master_node->privkey) == 0)
	{
		ERROR("secret key is invalid");
		ret = -1;
		goto cleanup;
	}

	master_node->index = 0;
	master_node->depth = 0;

cleanup:
	sodium_memzero(left, sizeof(left));
	sodium_memzero(parsed_left, sizeof(parsed_left));
	sodium_memzero(right, sizeof(right));

	return ret;
}

int node_compute_key_path(const char *key_path, const struct s_wallet_node *master_node, struct s_wallet_node *target_node)
{
	struct s_wallet_node			temp_parent;
	struct s_extended_private_key	parent;
	struct s_extended_private_key	child;
	uint32_t						target_index;
	uint8_t							depth = 0;
	int								ret = 0;
	bool							hardened;
	bool							is_target_public = false;

	if (key_path[0] == 'M')
		is_target_public = true;

	key_path += 2; // m/ TODO

	/* Bootstrap
	 */
	node_init(&temp_parent);
	memcpy(temp_parent.privkey,   master_node->privkey,   sizeof(temp_parent.privkey));
	memcpy(temp_parent.chaincode, master_node->chaincode, sizeof(temp_parent.chaincode));
	parent.privkey   = temp_parent.privkey;
	parent.chaincode = temp_parent.chaincode;
	child.privkey    = target_node->privkey;
	child.chaincode  = target_node->chaincode;

	while ((ret = get_next_index(&key_path, &target_index, &hardened)) == 1)
	{
		ret = ckd_private_parent_to_private_child(&parent, &child, target_index);
		if (ret == -1)
			goto cleanup;

		memcpy(temp_parent.privkey,   child.privkey,   sizeof(temp_parent.privkey));
		memcpy(temp_parent.chaincode, child.chaincode, sizeof(temp_parent.chaincode));

		depth += 1;
	}

	if (ret == -1)
		goto cleanup;

	if (is_target_public)
		sodium_memzero(target_node->privkey, sizeof(target_node->privkey));

	target_node->index = target_index;
	target_node->depth = depth;

cleanup:
	sodium_memzero(&temp_parent, sizeof(temp_parent));

	return ret;
}
