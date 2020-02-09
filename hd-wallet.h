#ifndef HD_WALLET_H
# define HD_WALLET_H

# define SEED_ENTROPY_SIZE 32

void error_print(const char *module, const char *msg);
void dumpmem(const uint8_t *mem, size_t memlen);

int node_master_generate(const uint8_t *seed, size_t seedlen, secp256k1_context *ctx);

#endif
