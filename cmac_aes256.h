#ifndef CMAC_AES256_H
#define CMAC_AES256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void cmac_aes256(const uint8_t *key, const uint8_t *msg, size_t msg_len, uint8_t *mac);

#ifdef __cplusplus
}
#endif

#endif // CMAC_AES256_H
