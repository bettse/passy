#ifndef SHA384_H
#define SHA384_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void hmac_sha384(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t mac[48]);

#ifdef __cplusplus
}
#endif

#endif /* SHA384_H */
