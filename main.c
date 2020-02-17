#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sodium.h>
#include <secp256k1.h>
#include "hd-wallet.h"

secp256k1_context *ctx;

static size_t read_seed_from_stdin(uint8_t *seed, size_t seedlen)
{
	ssize_t bytes_read;

	bytes_read = read(STDIN_FILENO, seed, seedlen);
	if (bytes_read < 0)
	{
		perror("read");
		return 0;
	}
	else if (bytes_read == 0)
	{
		ERROR("nothing read");
		return 0;
	}
	else if ((size_t)bytes_read < SEED_MIN_ENTROPY_SIZE)
	{
		ERROR("insufficient entropy");
		return 0;
	}

	return (size_t)bytes_read;
}

int main(int ac, char *av[])
{
	int ret;
	uint8_t seed[SEED_MAX_ENTROPY_SIZE];
	size_t seedlen = SEED_MAX_ENTROPY_SIZE;
	struct s_wallet_node master_node;
	struct s_wallet_node target_node;

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
		seedlen = read_seed_from_stdin(seed, seedlen);
		if (seedlen == 0)
			goto cleanup;
	}

	node_init(&master_node);
	node_init(&target_node);

	ret = node_generate_master(seed, seedlen, &master_node);
	if (ret == -1)
		goto cleanup;

	if (node_compute_key_path(av[1], &master_node, &target_node) == -1)
		goto cleanup;

	return EXIT_SUCCESS;

cleanup:
	secp256k1_context_destroy(ctx);
	sodium_memzero(seed, sizeof(seed));
	sodium_memzero(&master_node, sizeof(master_node));
	sodium_memzero(&target_node, sizeof(target_node));

	return EXIT_FAILURE;
}
