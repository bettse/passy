#ifndef PACE_CRYPTO_H
#define PACE_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief PACE KDF to derive K_pi from the CAN password.
 * Uses SHA-256 to hash the password and a counter (0x03) for mapping.
 */
int pace_kdf_pi(const uint8_t *password, size_t password_len, uint8_t *k_pi);

/**
 * @brief Load BrainpoolP512r1 curve parameters (parameterID = 16).
 */
int load_brainpool_p384r1(mbedtls_ecp_group *grp);

/**
 * @brief Software EC scalar multiplication: R = m * P.
 * Yields CPU periodically to prevent watchdog timeout on Flipper Zero.
 */
int software_ecp_mul(mbedtls_ecp_group *grp, mbedtls_ecp_point *R, const mbedtls_mpi *m, const mbedtls_ecp_point *P);

/**
 * @brief Software EC point addition: R = P + Q (affine coordinates).
 * Used for Generic Mapping: G' = s*G + H.
 */
int software_ecp_add(mbedtls_ecp_group *grp, mbedtls_ecp_point *R, const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q);

#ifdef __cplusplus
}
#endif

#endif // PACE_CRYPTO_H
