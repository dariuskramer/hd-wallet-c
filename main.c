#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sodium.h>
#include <secp256k1.h>
#include "hd-wallet.h"

secp256k1_context *ctx;

int read_seed_from_stdin(uint8_t *seed, size_t seedlen)
{
	ssize_t bytes_read;

	bytes_read = read(STDIN_FILENO, seed, seedlen);
	if (bytes_read < 0)
	{
		perror("read");
		return -1;
	}
	else if ((size_t)bytes_read != seedlen)
	{
		ERROR("insufficient entropy");
		return -1;
	}

	return 0;
}

/*
 * Returns:
 * -1 on error
 *  0 if no digit left to parse
 *  1 digit parsed
 */
int get_next_index(const char **key_path, uint32_t *next_index, bool *hardened)
{
	char	*end;

	if (**key_path == '\0')
		return 0;

	*next_index = (uint32_t)strtoul(*key_path, &end, 10);

	if (*end == KEY_HARDENED_MARKER)
	{
		if (*next_index > KEY_HARDENED_OFFSET)
		{
			ERROR("hardened index overflow");
			return -1;
		}
		*hardened = true;
		end += 1;
	}
	else
		*hardened = false;

	if (*end != '\0')
		end += 1;

	*key_path = end;
	return 1;
}

int compute_key_path(const char *key_path, const struct s_wallet_node *master_node, struct s_wallet_node *target_node)
{
	uint32_t	target_index;
	int			ret = 0;
	bool		hardened;

	(void)master_node;
	(void)target_node;

	key_path += 2; // m/ TODO

	while ((ret = get_next_index(&key_path, &target_index, &hardened)) == 1)
	{
		printf("Index: %u [%u]\n", target_index, hardened);
	}

	/* for (uint32_t i = 0; i < 3; ++i) */
	/* { */
	/* 	ret = ckd_private_parent_to_private_child(master_node, target_node, i); */
	/* 	if (ret != -1) */
	/* 	{ */
	/* 		printf(">>> Private Parent -> Private Child Node #%u\n", i); */
	/* 		node_dump(target_node); */
	/* 	} */

	/* 	ret = ckd_public_parent_to_public_child(&master_node, &target_node, i); */
	/* 	if (ret != -1) */
	/* 	{ */
	/* 		printf(">>> Public Parent -> Public Child Node #%u\n", i); */
	/* 		node_dump(&target_node); */
	/* 	} */

	/* 	ret = ckd_private_parent_to_public_child(master_node, target_node, i); */
	/* 	if (ret != -1) */
	/* 	{ */
	/* 		printf(">>> Private Parent -> Public Child Node #%u\n", i); */
	/* 		node_dump(target_node); */
	/* 	} */
	/* } */

	return ret;
}

int main(int ac, char *av[])
{
	int ret;
	uint8_t seed[SEED_MIN_ENTROPY_SIZE];
	size_t seedlen = sizeof(seed);
	struct s_wallet_node master_node = {0};
	struct s_wallet_node target_node = {0};

	if (ac != 2)
	{
		ERROR("usage: hd-wallet key_path");
		return EXIT_FAILURE;
	}

	if (sodium_init() < 0)
	{
		ERROR("libsodium couldn't be initialized");
		return EXIT_FAILURE;
	}

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	if (ctx == NULL)
	{
		ERROR("failed to create secp256k1 context!");
		return EXIT_FAILURE;
	}

	if (isatty(STDIN_FILENO))
		randombytes_buf(seed, seedlen);
	else
	{
		ret = read_seed_from_stdin(seed, seedlen);
		if (ret == -1)
			goto cleanup;
	}

	ret = node_master_generate(seed, seedlen, &master_node);
	if (ret == -1)
		goto cleanup;

	printf(">>> Compute key path: %s\n", av[1]);
	compute_key_path(av[1], &master_node, &target_node);
	node_dump(&target_node);

	return EXIT_SUCCESS;

cleanup:
	secp256k1_context_destroy(ctx);
	sodium_memzero(seed, seedlen);
	sodium_memzero(&master_node, sizeof(master_node));
	sodium_memzero(&target_node, sizeof(target_node));

	return EXIT_FAILURE;
}
