#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <secp256k1.h>
#include <sodium.h>
#include "hd-wallet.h"

int serialize_pubkey_from_privkey(const uint8_t *privkey, uint8_t *serialized_pubkey)
{
	secp256k1_pubkey	pubkey;
	size_t				serialized_pubkey_len = NODE_COMPRESSED_PUBKEY_SIZE;
	int					ret = 0;

	if (secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char*)privkey) == 0)
	{
		ERROR("secret was invalid");
		ret = -1;
		goto cleanup;
	}

	secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &serialized_pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);
	if (serialized_pubkey_len != NODE_COMPRESSED_PUBKEY_SIZE)
	{
		ERROR("compressed pubkey length invalid");
		ret = -1;
	}

cleanup:
	sodium_memzero(&pubkey, sizeof(pubkey));

	return ret;
}

int serialize_pubkey_with_index_from_privkey(const uint8_t *privkey, uint8_t *data, uint32_t index)
{
	uint8_t	serialized_pubkey[NODE_COMPRESSED_PUBKEY_SIZE];
	uint8_t serialized_index[sizeof(index)];
	int		ret = 0;

	ret = serialize_pubkey_from_privkey(privkey, serialized_pubkey);
	if (ret == -1)
		goto cleanup;

	serialize32(index, serialized_index);

	/* Data = serP(point(kpar)) || ser32(i))
	*/

	memcpy(data,                             serialized_pubkey,  sizeof(serialized_pubkey));
	memcpy(data + sizeof(serialized_pubkey), serialized_index,   sizeof(serialized_index));

cleanup:
	sodium_memzero(serialized_pubkey, sizeof(serialized_pubkey));

	return ret;
}

int ckd_private_parent_to_private_child(const struct s_wallet_node *parent, struct s_wallet_node *child, uint32_t index)
{
	uint8_t	left[crypto_auth_hmacsha512_BYTES / 2];
	uint8_t	parsed_left[crypto_auth_hmacsha512_BYTES / 2];
	uint8_t	right[crypto_auth_hmacsha512_BYTES / 2];
	uint8_t	data[128];
	size_t	datalen;
	int		ret = 0;

	if (index > (1U << 31)) /* Hardened child */
	{
		uint8_t serialized_privkey[NODE_PRIVKEY_SIZE];
		uint8_t serialized_index[sizeof(index)];

		assert(sizeof(data) >= (sizeof(serialized_privkey) + sizeof(serialized_index) + 1));

		serialize256(parent->privkey, serialized_privkey);
		serialize32(index, serialized_index);

		/* Data = 0x00 || ser256(kpar) || ser32(i))
		*/
		data[0] = 0x0;
		memcpy(data + 1,                              serialized_privkey, sizeof(serialized_privkey));
		memcpy(data + 1 + sizeof(serialized_privkey), serialized_index,   sizeof(serialized_index));

		datalen = sizeof(serialized_privkey) + sizeof(index) + 1;

		sodium_memzero(serialized_privkey, sizeof(serialized_privkey));
	}
	else /* Normal child */
	{
		secp256k1_pubkey	pubkey;
		uint8_t				serialized_pubkey[NODE_COMPRESSED_PUBKEY_SIZE];
		uint8_t				serialized_index[sizeof(index)];

		assert(sizeof(data) >= (sizeof(serialized_pubkey) + sizeof(serialized_index)));

		/* point(kpar)
		 */
		ret = point(parent->privkey, &pubkey);
		if (ret == -1)
			goto cleanup;

		/* serP(point(kpar))
		 */
		ret = serialize_point(&pubkey, serialized_pubkey);
		if (ret == -1)
			goto cleanup;

		serialize32(index, serialized_index);

		/* Data = serP(point(kpar)) || ser32(i))
		*/
		memcpy(data,                             serialized_pubkey,  sizeof(serialized_pubkey));
		memcpy(data + sizeof(serialized_pubkey), serialized_index,   sizeof(serialized_index));
		datalen = sizeof(serialized_pubkey) + sizeof(serialized_index);

		sodium_memzero(&pubkey,           sizeof(pubkey));
		sodium_memzero(serialized_pubkey, sizeof(serialized_pubkey));
	}

	/* (IL, IR) = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i))
	*/
	hmac_sha512(parent->chaincode, NODE_CHAINCODE_SIZE, data, datalen, left, right);

	/* parse256(IL) ≥ n
	 */
	parse256(left, parsed_left);
	if (secp256k1_ec_seckey_verify(ctx, parsed_left) == 0)
	{
		ERROR("secret key is invalid");
		ret = -1;
		goto cleanup;
	}

	/* ki = parse256(IL) + kpar (mod n)
	*/
	ret = byte_array_add(child->privkey, parsed_left, parent->privkey);
	if (ret == -1)
		goto cleanup;

	/* ci = IR
	 */
	memcpy(child->chaincode, right, NODE_CHAINCODE_SIZE);

	child->index = index;

cleanup:
	sodium_memzero(data, sizeof(data));
	sodium_memzero(left, sizeof(left));
	sodium_memzero(parsed_left, sizeof(parsed_left));
	sodium_memzero(right, sizeof(right));

	return ret;
}

int ckd_public_parent_to_public_child(const struct s_wallet_node *parent, struct s_wallet_node *child, uint32_t index)
{
	secp256k1_pubkey	pubkey;
	secp256k1_pubkey	deserialized_parent_pubkey;
	uint8_t				left[crypto_auth_hmacsha512_BYTES / 2];
	uint8_t				right[crypto_auth_hmacsha512_BYTES / 2];
	uint8_t				data[128];
	size_t				datalen;
	int					ret = 0;

	if (index > (1U << 31)) /* Hardened child */
	{
		ERROR("(public parent key -> public child key) is only defined for non-hardened child keys");
		return -1;
	}

	assert(sizeof(data) >= (NODE_COMPRESSED_PUBKEY_SIZE + sizeof(index)));

	/* Data = serP(Kpar) || ser32(i))
	*/
	serialize_pubkey_with_index_from_privkey(parent->privkey, data, index);
	datalen = NODE_COMPRESSED_PUBKEY_SIZE + sizeof(index);

	/* I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i))
	*/
	hmac_sha512(parent->chaincode, NODE_CHAINCODE_SIZE, data, datalen, left, right);

	/* point(parse256(IL))
	*/
	if (secp256k1_ec_seckey_verify(ctx, left) == 0)
	{
		ERROR("(left) secret key is invalid");
		ret = -1;
		goto cleanup;
	}
	if (secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char*)left) == 0)
	{
		ERROR("(left) secret was invalid");
		ret = -1;
		goto cleanup;
	}

	/* point(parse256(IL)) + Kpar
	*/
	if (secp256k1_ec_pubkey_parse(ctx, &deserialized_parent_pubkey, parent->pubkey, NODE_COMPRESSED_PUBKEY_SIZE) == 0)
	{
		ERROR("public key could not be parsed or is invalid");
		ret = -1;
		goto cleanup;
	}
	if (secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, (const unsigned char *)&deserialized_parent_pubkey) == 0) // TODO BUG HERE
	{
		ERROR("tweak out of range or resulting private key invalid");
		ret = -1;
		goto cleanup;
	}

	memcpy(child->pubkey,    &pubkey, sizeof(pubkey));
	memcpy(child->chaincode, right,   NODE_CHAINCODE_SIZE);
	child->index = index;

	// TODO check left >= n or child->pubkey is the point at infinity

cleanup:
	sodium_memzero(&pubkey, sizeof(pubkey));
	sodium_memzero(&deserialized_parent_pubkey, sizeof(deserialized_parent_pubkey));
	sodium_memzero(data, sizeof(data));
	sodium_memzero(left, sizeof(left));
	sodium_memzero(right, sizeof(right));

	return ret;
}

int ckd_private_parent_to_public_child(const struct s_wallet_node *parent, struct s_wallet_node *public_child, uint32_t index)
{
	struct s_wallet_node	private_child;
	int						ret = 0;

	ret = ckd_private_parent_to_private_child(parent, &private_child, index);
	if (ret == -1)
		goto cleanup;

	serialize_pubkey_from_privkey(private_child.privkey, public_child->pubkey);

	/* memcpy(public_child->pubkey, &pubkey, NODE_COMPRESSED_PUBKEY_SIZE); */
	memcpy(public_child->chaincode, private_child.chaincode, NODE_CHAINCODE_SIZE);
	public_child->index = index;

cleanup:
	sodium_memzero(&private_child, sizeof(private_child));

	return ret;
}
