#ifndef HD_WALLET_H
# define HD_WALLET_H

# include <secp256k1.h>

# define SEED_MIN_ENTROPY_SIZE 16
# define NODE_PRIVKEY_SIZE 32
# define NODE_CHAINCODE_SIZE 32
# define NODE_COMPRESSED_PUBKEY_SIZE 33
# define NODE_UNCOMPRESSED_PUBKEY_SIZE 65

struct s_wallet_node
{
	uint8_t privkey[NODE_PRIVKEY_SIZE];
	uint8_t chaincode[NODE_CHAINCODE_SIZE];
	secp256k1_pubkey pubkey;
};

extern secp256k1_context *ctx;

void error_print(const char *module, const char *msg);
void dumpmem(const uint8_t *mem, size_t memlen);

void node_dump(const struct s_wallet_node *master_node);
int node_master_generate(const uint8_t *seed, size_t seedlen, struct s_wallet_node *master_node);

#endif