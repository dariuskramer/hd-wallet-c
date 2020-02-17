#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sodium.h>
#include <secp256k1.h>
#include <scalar_impl.h>
#include <num_impl.h>
#include <libbase58.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include "hd-wallet.h"

void byte_array_init(void *a, size_t size)
{
	memset(a, 0xff, size);
}

int byte_array_add(uint8_t result[32], const uint8_t a[32], const uint8_t b[32])
{
	secp256k1_scalar	sa;
	secp256k1_scalar	sb;
	secp256k1_scalar	sr;
	int					overflow = 0;
	int					ret = 0;

	secp256k1_scalar_set_b32(&sa, a, &overflow);
	if (overflow)
	{
		ERROR("scalar 1 overflow");
		ret = -1;
		goto cleanup;
	}

	secp256k1_scalar_set_b32(&sb, b, &overflow);
	if (overflow)
	{
		ERROR("scalar 2 overflow");
		ret = -1;
		goto cleanup;
	}

	if (secp256k1_scalar_add(&sr, &sa, &sb))
	{
		/* ERROR("scalar add overflow"); */
		/* ret = -1; */
		/* goto cleanup; */
	}

	if (secp256k1_scalar_is_zero(&sr))
	{
		ERROR("scalar is zero");
		ret = -1;
		goto cleanup;
	}

	secp256k1_scalar_get_b32(result, &sr);

cleanup:
	secp256k1_scalar_clear(&sa);
	secp256k1_scalar_clear(&sb);
	secp256k1_scalar_clear(&sr);

	return ret;
}

int byte_array_to_scalar(const uint8_t bytearray[32], secp256k1_scalar *s)
{
	int	overflow = 0;
	int	ret = 0;

	secp256k1_scalar_set_b32(s, bytearray, &overflow);
	if (overflow)
	{
		ERROR("scalar overflow");
		ret = -1;
	}

	ret = secp256k1_scalar_is_zero(s);
	if (ret)
	{
		ERROR("scalar is zero");
		ret = -1;
		secp256k1_scalar_clear(s);
	}

	return ret;
}

int point_from_byte_array(const uint8_t *p, secp256k1_pubkey *pubkey)
{
	if (secp256k1_ec_pubkey_create(ctx, pubkey, (const unsigned char*)p) == 0)
	{
		ERROR("secret was invalid");
		return -1;
	}

	return 0;
}

int point_from_scalar(const secp256k1_scalar *s, secp256k1_pubkey *pubkey)
{
	uint8_t	bytearray[32];
	int		ret;

	secp256k1_scalar_get_b32(bytearray, s);
	ret = point_from_byte_array(bytearray, pubkey);
	sodium_memzero(bytearray, sizeof(bytearray));

	return ret;
}

int point_add(secp256k1_pubkey *result, const secp256k1_pubkey *a, const secp256k1_pubkey *b)
{
	const secp256k1_pubkey	*pubkey_array[2] = {a, b};
	int						ret = 0;

	// convertir une pubkey en GE
	// secp256k1_pubkey_load

	// convertir un GE en GEJ
	// secp256k1_gej_set_ge

	/* secp256k1_gej_add_var(gej_result, gej_a, gej_b, NULL); */

	// add multiples pubkey together
	// secp256k1_ec_pubkey_combine

	ret = secp256k1_ec_pubkey_combine(ctx, result, pubkey_array, sizeof(pubkey_array));
	if (ret == 0)
		ret = -1;

	return ret;
}

void serialize32(uint32_t i, uint8_t serialized[4])
{
	serialized[0] = (i >> 24);
	serialized[1] = (i >> 16) & 0xff;
	serialized[2] = (i >>  8) & 0xff;
	serialized[3] =  i        & 0xff;
}

void serialize256(const uint8_t *src, uint8_t serialized[32])
{
	serialized[0]  = src[31];
	serialized[1]  = src[30];
	serialized[2]  = src[29];
	serialized[3]  = src[28];
	serialized[4]  = src[27];
	serialized[5]  = src[26];
	serialized[6]  = src[25];
	serialized[7]  = src[24];
	serialized[8]  = src[23];
	serialized[9]  = src[22];
	serialized[10] = src[21];
	serialized[11] = src[20];
	serialized[12] = src[19];
	serialized[13] = src[18];
	serialized[14] = src[17];
	serialized[15] = src[16];
	serialized[16] = src[15];
	serialized[17] = src[14];
	serialized[18] = src[13];
	serialized[19] = src[12];
	serialized[20] = src[11];
	serialized[21] = src[10];
	serialized[22] = src[9];
	serialized[23] = src[8];
	serialized[24] = src[7];
	serialized[25] = src[6];
	serialized[26] = src[5];
	serialized[27] = src[4];
	serialized[28] = src[3];
	serialized[29] = src[2];
	serialized[30] = src[1];
	serialized[31] = src[0];
}

int serialize_point(const secp256k1_pubkey *point, uint8_t serialized_point[NODE_COMPRESSED_PUBKEY_SIZE])
{
	size_t	serialized_point_len = NODE_COMPRESSED_PUBKEY_SIZE;

	secp256k1_ec_pubkey_serialize(ctx, serialized_point, &serialized_point_len, point, SECP256K1_EC_COMPRESSED);

	if (serialized_point_len != NODE_COMPRESSED_PUBKEY_SIZE)
	{
		ERROR("serialized point length invalid");
		return -1;
	}

	return 0;
}

void parse256(const uint8_t serialized[32], uint8_t parsed[32])
{
	parsed[0]  = serialized[31];
	parsed[1]  = serialized[30];
	parsed[2]  = serialized[29];
	parsed[3]  = serialized[28];
	parsed[4]  = serialized[27];
	parsed[5]  = serialized[26];
	parsed[6]  = serialized[25];
	parsed[7]  = serialized[24];
	parsed[8]  = serialized[23];
	parsed[9]  = serialized[22];
	parsed[10] = serialized[21];
	parsed[11] = serialized[20];
	parsed[12] = serialized[19];
	parsed[13] = serialized[18];
	parsed[14] = serialized[17];
	parsed[15] = serialized[16];
	parsed[16] = serialized[15];
	parsed[17] = serialized[14];
	parsed[18] = serialized[13];
	parsed[19] = serialized[12];
	parsed[20] = serialized[11];
	parsed[21] = serialized[10];
	parsed[22] = serialized[9];
	parsed[23] = serialized[8];
	parsed[24] = serialized[7];
	parsed[25] = serialized[6];
	parsed[26] = serialized[5];
	parsed[27] = serialized[4];
	parsed[28] = serialized[3];
	parsed[29] = serialized[2];
	parsed[30] = serialized[1];
	parsed[31] = serialized[0];
}

void hmac_sha512(const uint8_t *key, size_t keylen,
		const uint8_t *data, size_t datalen,
		uint8_t *left, uint8_t *right)
{
	uint8_t hash[crypto_auth_hmacsha512_BYTES];
	size_t half = sizeof(hash) / 2;
	crypto_auth_hmacsha512_state state;

	crypto_auth_hmacsha512_init(&state, key, keylen);
	crypto_auth_hmacsha512_update(&state, data, datalen);
	crypto_auth_hmacsha512_final(&state, hash);

	memcpy(left, hash, half);
	memcpy(right, hash + half, half);
}

void hash160(const uint8_t *msg, size_t msglen, uint8_t *digest)
{
	unsigned char sha256[SHA256_DIGEST_LENGTH] = {0};

	SHA256((unsigned char*)msg, msglen, sha256);
	RIPEMD160(sha256, SHA256_DIGEST_LENGTH, digest);
}

void key_fingerprint(uint8_t *fingerprint, const uint8_t *serialized_pubkey)
{
	uint8_t ripemd160[RIPEMD160_DIGEST_LENGTH];

	hash160(serialized_pubkey, NODE_COMPRESSED_PUBKEY_SIZE, ripemd160);
	memcpy(fingerprint, ripemd160, NODE_FINGERPRINT_SIZE);
}

size_t b58_node(uint8_t *b58, size_t b58len, const struct s_wallet_node *node, bool public)
{
	uint8_t			serialized[NODE_SERIALIZED_SIZE];
	unsigned char	cks[crypto_hash_sha256_BYTES];
	unsigned char	cks2[crypto_hash_sha256_BYTES];
	size_t			offset = 0;

	// Version
	if (public)
		memcpy(serialized, "\x04\x88\xb2\x1e", 4);
	else
		memcpy(serialized, "\x04\x88\xad\xe4", 4);
	offset += 4;

	// Depth
	memcpy(serialized + offset, &node->depth, sizeof(node->depth));
	offset += 1;

	// Parent key fingerprint
	memcpy(serialized + offset, node->fingerprint, NODE_FINGERPRINT_SIZE);
	offset += NODE_FINGERPRINT_SIZE;

	// Child number
	serialize32(node->index, serialized + offset);
	offset += 4;

	// Chain code
	memcpy(serialized + offset, node->chaincode, sizeof(node->chaincode));
	offset += 32;

	// Key
	if (public)
		serialize_point(&node->pubkey, serialized + offset);
	else
	{
		memcpy(serialized + offset, "\xff", 1);
		serialize256(node->privkey, serialized + offset + 1);
	}
	offset += 33;

	// Checksum
	crypto_hash_sha256(cks,  serialized, NODE_SERIALIZED_SIZE - 4);
	crypto_hash_sha256(cks2, cks, sizeof(cks2));
	memcpy(serialized + offset, cks2, 4);

	if (!b58enc((char*)b58, &b58len, serialized, sizeof(serialized)))
	{
		printf("b58 error: need %zu bytes\n", b58len);
		assert(false);
	}

	return b58len;
}
