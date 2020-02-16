#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <secp256k1.h>
#include <sodium.h>
#include "hd-wallet.h"

int ckd_private_parent_to_private_child(
		const struct s_extended_private_key *parent,
		struct s_extended_private_key *child,
		uint32_t index)
{
	uint8_t	left[crypto_auth_hmacsha512_BYTES / 2];
	uint8_t	parsed_left[crypto_auth_hmacsha512_BYTES / 2];
	uint8_t	right[crypto_auth_hmacsha512_BYTES / 2];
	uint8_t	data[128];
	size_t	datalen;
	int		ret = 0;

	if (KEY_INDEX_IS_HARDEDNED(index)) /* Hardened child */
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
		secp256k1_pubkey	parent_pubkey;
		uint8_t				serialized_parent_pubkey[NODE_COMPRESSED_PUBKEY_SIZE];
		uint8_t				serialized_index[sizeof(index)];

		assert(sizeof(data) >= (sizeof(serialized_parent_pubkey) + sizeof(serialized_index)));

		/* point(kpar)
		 */
		ret = point_from_byte_array(parent->privkey, &parent_pubkey);
		if (ret == -1)
			goto cleanup;

		/* serP(point(kpar))
		 */
		ret = serialize_point(&parent_pubkey, serialized_parent_pubkey);
		if (ret == -1)
		{
			sodium_memzero(&parent_pubkey, sizeof(parent_pubkey));
			goto cleanup;
		}

		serialize32(index, serialized_index);

		/* Data = serP(point(kpar)) || ser32(i))
		*/
		memcpy(data,                                    serialized_parent_pubkey,  sizeof(serialized_parent_pubkey));
		memcpy(data + sizeof(serialized_parent_pubkey), serialized_index,          sizeof(serialized_index));
		datalen = sizeof(serialized_parent_pubkey) + sizeof(serialized_index);

		sodium_memzero(&parent_pubkey,           sizeof(parent_pubkey));
		sodium_memzero(serialized_parent_pubkey, sizeof(serialized_parent_pubkey));
	}

	/* (IL, IR) = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i))
	*/
	hmac_sha512(parent->chaincode, NODE_CHAINCODE_SIZE, data, datalen, left, right);

	/* parse256(IL) ≥ n
	 */
	parse256(left, parsed_left);
	if (secp256k1_ec_seckey_verify(ctx, parsed_left) == 0)
	{
		ERROR("left hmac_sha512 is invalid");
		ret = -1;
		goto cleanup;
	}

	/* ki = parse256(IL) + kpar (mod n)
	*/
	ret = byte_array_add(child->privkey, parsed_left, parent->privkey);
	if (ret == -1)
		goto cleanup;
	if (secp256k1_ec_seckey_verify(ctx, child->privkey) == 0)
	{
		ERROR("child privkey is invalid");
		ret = -1;
		goto cleanup;
	}

	/* ci = IR
	 */
	memcpy(child->chaincode, right, NODE_CHAINCODE_SIZE);

cleanup:
	sodium_memzero(data, sizeof(data));
	sodium_memzero(left, sizeof(left));
	sodium_memzero(parsed_left, sizeof(parsed_left));
	sodium_memzero(right, sizeof(right));

	return ret;
}

int ckd_public_parent_to_public_child(
		const struct s_extended_public_key *parent,
		struct s_extended_public_key *child,
		uint32_t index)
{
	uint8_t				left[crypto_auth_hmacsha512_BYTES / 2];
	uint8_t				parsed_left[crypto_auth_hmacsha512_BYTES / 2];
	secp256k1_scalar	scalar_left;
	secp256k1_pubkey	pubkey_left;
	uint8_t				right[crypto_auth_hmacsha512_BYTES / 2];
	uint8_t				serialized_parent_pubkey[NODE_COMPRESSED_PUBKEY_SIZE];
	uint8_t				serialized_index[sizeof(index)];
	uint8_t				data[128];
	size_t				datalen;
	int					ret = 0;

	if (KEY_INDEX_IS_HARDEDNED(index)) /* Hardened child */
	{
		ERROR("(public parent key -> public child key) is only defined for non-hardened child keys");
		return -1;
	}

	assert(sizeof(data) >= (NODE_COMPRESSED_PUBKEY_SIZE + sizeof(index)));

	/* serP(Kpar)
	 */
	ret = serialize_point(parent->pubkey, serialized_parent_pubkey);
	if (ret == -1)
		goto cleanup;

	serialize32(index, serialized_index);

	/* Data = serP(Kpar) || ser32(i))
	*/
	memcpy(data,                                    serialized_parent_pubkey,  sizeof(serialized_parent_pubkey));
	memcpy(data + sizeof(serialized_parent_pubkey), serialized_index,          sizeof(serialized_index));
	datalen = sizeof(serialized_parent_pubkey) + sizeof(serialized_index);

	/* I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i))
	*/
	hmac_sha512(parent->chaincode, NODE_CHAINCODE_SIZE, data, datalen, left, right);

	/* parse256(IL)
	 */
	parse256(left, parsed_left);
	if (secp256k1_ec_seckey_verify(ctx, parsed_left) == 0)
	{
		ERROR("left hmac_sha512 is invalid");
		ret = -1;
		goto cleanup;
	}

	/* point(parse256(IL))
	 */
	ret = byte_array_to_scalar(parsed_left, &scalar_left);
	if (ret == -1)
		goto cleanup;
	ret = point_from_scalar(&scalar_left, &pubkey_left);
	if (ret == -1)
		goto cleanup;

	/* point(parse256(IL)) + Kpar
	*/
	ret = point_add(child->pubkey, &pubkey_left, parent->pubkey);
	if (ret == -1)
		goto cleanup;

	/* chain code ci is IR
	 */
	memcpy(child->chaincode, right, NODE_CHAINCODE_SIZE);

cleanup:
	sodium_memzero(left, sizeof(left));
	sodium_memzero(parsed_left, sizeof(parsed_left));
	secp256k1_scalar_clear(&scalar_left);
	sodium_memzero(&pubkey_left, sizeof(pubkey_left));
	sodium_memzero(right, sizeof(right));
	sodium_memzero(serialized_parent_pubkey, sizeof(serialized_parent_pubkey));
	sodium_memzero(data, sizeof(data));

	return ret;
}

int ckd_private_parent_to_public_child(
		const struct s_extended_private_key *parent,
		struct s_extended_public_key *child,
		uint32_t index)
{
	uint8_t							private_child_privkey[NODE_PRIVKEY_SIZE];
	uint8_t							private_child_chaincode[NODE_CHAINCODE_SIZE];
	struct s_extended_private_key	private_child = {
		.privkey = private_child_privkey,
		.chaincode = private_child_chaincode,
	};
	int								ret = 0;

	ret = ckd_private_parent_to_private_child(parent, &private_child, index);
	if (ret == -1)
		goto cleanup;

	ret = point_from_byte_array(private_child.privkey, child->pubkey);
	if (ret == -1)
		goto cleanup;

	memcpy(child->chaincode, private_child.chaincode, NODE_CHAINCODE_SIZE);

cleanup:
	sodium_memzero(private_child_privkey, sizeof(private_child_privkey));
	sodium_memzero(private_child_chaincode, sizeof(private_child_chaincode));

	return ret;
}
