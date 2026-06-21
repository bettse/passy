#include "cmac_aes256.h"
#include <mbedtls/aes.h>
#include <string.h>
#include <stdbool.h>

static void xor_block(uint8_t *dst, const uint8_t *src1, const uint8_t *src2) {
    for (int i = 0; i < 16; i++) {
        dst[i] = src1[i] ^ src2[i];
    }
}

static void left_shift_block(uint8_t *dst, const uint8_t *src) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; i--) {
        uint8_t next_carry = (src[i] >> 7) & 1;
        dst[i] = (src[i] << 1) | carry;
        carry = next_carry;
    }
}

static void generate_subkeys(mbedtls_aes_context *ctx, uint8_t *k1, uint8_t *k2) {
    uint8_t l[16] = {0};
    uint8_t zero[16] = {0};
    mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, zero, l);

    left_shift_block(k1, l);
    if (l[0] & 0x80) k1[15] ^= 0x87;

    left_shift_block(k2, k1);
    if (k1[0] & 0x80) k2[15] ^= 0x87;
}

void cmac_aes256(const uint8_t *key, const uint8_t *msg, size_t msg_len, uint8_t *mac) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 256);

    uint8_t k1[16], k2[16];
    generate_subkeys(&ctx, k1, k2);

    uint8_t x[16] = {0};
    uint8_t y[16] = {0};
    size_t num_blocks = (msg_len + 15) / 16;
    if (num_blocks == 0) num_blocks = 1;
    
    bool is_complete = (msg_len != 0 && msg_len % 16 == 0);

    for (size_t i = 0; i < num_blocks - 1; i++) {
        xor_block(y, x, &msg[i * 16]);
        mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, y, x);
    }

    uint8_t last_block[16] = {0};
    size_t last_len = msg_len - (num_blocks - 1) * 16;
    memcpy(last_block, &msg[(num_blocks - 1) * 16], last_len);

    if (is_complete) {
        xor_block(last_block, last_block, k1);
    } else {
        last_block[last_len] = 0x80; // Padding
        xor_block(last_block, last_block, k2);
    }

    xor_block(y, x, last_block);
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, y, mac);

    mbedtls_aes_free(&ctx);
}
