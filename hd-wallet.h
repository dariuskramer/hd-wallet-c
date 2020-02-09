#ifndef HD_WALLET_H
# define HD_WALLET_H

# include <secp256k1.h>

# define SEED_MIN_ENTROPY_SIZE 16
# define NODE_PRIVKEY_SIZE 32
# define NODE_CHAINCODE_SIZE 32
# define NODE_COMPRESSED_PUBKEY_SIZE 33
# define NODE_UNCOMPRESSED_PUBKEY_SIZE 65

# define ERROR(msg) error_print(__func__, (msg))

struct s_wallet_node
{
	uint8_t privkey[NODE_PRIVKEY_SIZE];
	uint8_t pubkey[NODE_COMPRESSED_PUBKEY_SIZE];
	uint8_t chaincode[NODE_CHAINCODE_SIZE];
	uint32_t index;
};

extern secp256k1_context *ctx;

void error_print(const char *module, const char *msg);
void dumpmem(const uint8_t *mem, size_t memlen);
void serialize32(uint32_t i, uint8_t serialized[4]);
void serialize256(const uint8_t *src, uint8_t serialized[32]);
void hmac_sha512(const uint8_t *key, size_t keylen, const uint8_t *data, size_t datalen, uint8_t *left, uint8_t *right);

void node_dump(const struct s_wallet_node *master_node);
int node_master_generate(const uint8_t *seed, size_t seedlen, struct s_wallet_node *master_node);

int serialize_pubkey_from_privkey(const uint8_t *privkey, uint8_t *serialized_pubkey);
int serialize_pubkey_with_index_from_privkey(const uint8_t *privkey, uint8_t *data, uint32_t index);
int ckd_private_parent_to_private_child(const struct s_wallet_node *parent, struct s_wallet_node *child, uint32_t index);
int ckd_public_parent_to_public_child(const struct s_wallet_node *parent, struct s_wallet_node *child, uint32_t index);
int ckd_private_parent_to_public_child(const struct s_wallet_node *parent, struct s_wallet_node *public_child, uint32_t index);

#endif
