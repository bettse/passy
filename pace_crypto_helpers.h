#ifndef PACE_CRYPTO_HELPERS_H
#define PACE_CRYPTO_HELPERS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>

#ifdef __cplusplus
extern "C" {
#endif

bool pace_kdf_session(const uint8_t* K, size_t K_len, uint32_t counter, uint8_t* key_out);

int my_rng(void* ctx, unsigned char* buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif
