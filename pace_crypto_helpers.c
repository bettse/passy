#include "pace_crypto_helpers.h"
#include <furi_hal_random.h>
#include <mbedtls/md.h>
#include <string.h>

void mbedtls_ct_memcpy_if( size_t cond,
                           unsigned char *dest,
                           const unsigned char *src1,
                           const unsigned char *src2,
                           size_t len ) {
    unsigned char mask = -(unsigned char)(cond != 0);
    for (size_t i = 0; i < len; i++) {
        dest[i] = (src1[i] & mask) | (src2[i] & ~mask);
    }
}

int my_rng(void* ctx, unsigned char* buf, size_t len) {
    (void)ctx;
    furi_hal_random_fill_buf(buf, len);
    return 0;
}

bool pace_kdf_session(const uint8_t* K, size_t K_len, uint32_t counter, uint8_t* key_out) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) return false;
    
    if (mbedtls_md_setup(&ctx, md_info, 0) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }
    
    if (mbedtls_md_starts(&ctx) != 0) { mbedtls_md_free(&ctx); return false; }
    if (mbedtls_md_update(&ctx, K, K_len) != 0) { mbedtls_md_free(&ctx); return false; }
    
    uint8_t c_buf[4];
    c_buf[0] = (counter >> 24) & 0xFF;
    c_buf[1] = (counter >> 16) & 0xFF;
    c_buf[2] = (counter >> 8) & 0xFF;
    c_buf[3] = counter & 0xFF;
    
    if (mbedtls_md_update(&ctx, c_buf, 4) != 0) { mbedtls_md_free(&ctx); return false; }
    if (mbedtls_md_finish(&ctx, key_out) != 0) { mbedtls_md_free(&ctx); return false; }
    mbedtls_md_free(&ctx);
    
    return true;
}
