#ifndef HD_WALLET_H
# define HD_WALLET_H

# include <secp256k1.h>
# include <scalar_impl.h>
# include <num_impl.h>

# define SEED_MIN_ENTROPY_SIZE 16
# define NODE_PRIVKEY_SIZE 32
# define NODE_CHAINCODE_SIZE 32
# define NODE_COMPRESSED_PUBKEY_SIZE 33
# define NODE_UNCOMPRESSED_PUBKEY_SIZE 65
# define KEY_HARDENED_MARKER	'\''
# define KEY_HARDENED_OFFSET	(1U << 31)
# define KEY_INDEX_IS_HARDEDNED(i)	((i) >= KEY_HARDENED_OFFSET)

# define ERROR(msg) error_print(__func__, (msg))

struct s_wallet_node
{
	uint8_t				privkey[NODE_PRIVKEY_SIZE];
	uint8_t 			chaincode[NODE_CHAINCODE_SIZE];
	secp256k1_pubkey	pubkey;
	uint32_t			index;
	uint8_t 			serialized_pubkey[NODE_COMPRESSED_PUBKEY_SIZE];
};

struct s_extended_private_key
{
	uint8_t	*privkey;
	uint8_t *chaincode;
};

struct s_extended_public_key
{
	secp256k1_pubkey	*pubkey;
	uint8_t				*chaincode;
};

extern secp256k1_context *ctx;

/* Utils
 */
void error_print(const char *module, const char *msg);
void dumpmem(const uint8_t *mem, size_t memlen);

/* Wrappers
 */
int byte_array_add(uint8_t result[32], const uint8_t a[32], const uint8_t b[32]);
int byte_array_to_scalar(const uint8_t bytearray[32], secp256k1_scalar *s);
int point_from_byte_array(const uint8_t *p, secp256k1_pubkey *pubkey);
int point_from_scalar(const secp256k1_scalar *s, secp256k1_pubkey *pubkey);
int point_add(const secp256k1_pubkey *a, const secp256k1_pubkey *b, secp256k1_pubkey *result);
void serialize32(uint32_t i, uint8_t serialized[4]);
void serialize256(const uint8_t *src, uint8_t serialized[32]);
int serialize_point(const secp256k1_pubkey *point, uint8_t serialized_point[NODE_COMPRESSED_PUBKEY_SIZE]);
int serialize_pubkey_from_privkey(const uint8_t *privkey, uint8_t *serialized_pubkey);
void parse256(const uint8_t serialized[32], uint8_t parsed[32]);
void hmac_sha512(const uint8_t *key, size_t keylen, const uint8_t *data, size_t datalen, uint8_t *left, uint8_t *right);

/* Node
 */
void node_dump(const struct s_wallet_node *master_node);
int node_master_generate(const uint8_t *seed, size_t seedlen, struct s_wallet_node *master_node);

/* CKD
 */
/* int ckd_private_parent_to_private_child( */
/* 		const struct s_extended_private_key *parent, */
/* 		struct s_extended_private_key *child, */
/* 		uint32_t index); */

/* int ckd_public_parent_to_public_child( */
/* 		const struct s_extended_public_key *parent, */
/* 		struct s_extended_public_key *child, */
/* 		uint32_t index); */

/* int ckd_private_parent_to_public_child( */
/* 		const struct s_extended_private_key *parent, */
/* 		struct s_extended_public_key *child, */
/* 		uint32_t index); */

int ckd_private_parent_to_private_child(const struct s_wallet_node *parent, struct s_wallet_node *child, uint32_t index);
int ckd_public_parent_to_public_child(const struct s_wallet_node *parent, struct s_wallet_node *child, uint32_t index);
int ckd_private_parent_to_public_child(const struct s_wallet_node *parent, struct s_wallet_node *public_child, uint32_t index);

#endif
