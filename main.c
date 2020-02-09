#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sodium.h>
#include <secp256k1.h>
#include "hd-wallet.h"

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
		error_print("read", "insufficient entropy");
		return -1;
	}

	return 0;
}

int main(void)
{
	int ret;
	secp256k1_context *ctx;
	uint8_t seed[SEED_ENTROPY_SIZE];
	size_t seedlen = sizeof(seed);

	if (sodium_init() < 0)
	{
		error_print("sodium_init", "couldn't be initialized");
		return EXIT_FAILURE;
	}

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	if (ctx == NULL)
	{
		error_print("secp256k1_context_create", "failed to create context!");
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

	ret = node_master_generate(seed, seedlen, ctx);
	if (ret == -1)
		goto cleanup;

	return EXIT_SUCCESS;

cleanup:
	secp256k1_context_destroy(ctx);
	sodium_memzero(seed, seedlen);

	return EXIT_FAILURE;
}
