#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "pace_auth.h"
#include <string.h>
#include "passy_reader.h"
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include <mbedtls/platform_util.h>
#include "pace_crypto.h"
#include "pace_crypto_helpers.h"
#include "cmac_aes256.h"
#include <furi.h>
#include <furi_hal_random.h>
#include "passy_i.h"

#define MAX_PK_SIZE 130 // Enough for up to 512-bit uncompressed points

PaceAuthContext* passy_pace_auth_alloc(const uint8_t* k_seed, size_t k_seed_len, uint8_t password_type) {
    PaceAuthContext* ctx = malloc(sizeof(PaceAuthContext));
    memset(ctx, 0, sizeof(PaceAuthContext));
    if (k_seed && k_seed_len > 0) {
        size_t len = k_seed_len;
        if (len > sizeof(ctx->K_seed)) len = sizeof(ctx->K_seed);
        memcpy(ctx->K_seed, k_seed, len);
        ctx->K_seed_len = len;
    }
    ctx->password_type = password_type;
    ctx->pace_established = false;
    return ctx;
}

void passy_pace_auth_free(PaceAuthContext* context) {
    if(context != NULL) {
        mbedtls_platform_zeroize(context, sizeof(PaceAuthContext));
        free(context);
    }
}

// Helper: parse TLV value inside a 7C container from raw APDU response.
// Finds inner tag `target_tag` and returns pointer to value and its length.
// Returns NULL if not found.
static const uint8_t* tlv_find_tag(const uint8_t *data, size_t data_len, uint8_t target_tag, size_t *out_len) {
    if (data_len < 2 || data[0] != 0x7C) return NULL;
    
    size_t off = 1;
    // Parse 7C length
    size_t outer_len;
    if (data[off] & 0x80) {
        size_t nbytes = data[off] & 0x7F;
        off++;
        outer_len = 0;
        for (size_t i = 0; i < nbytes && off < data_len; i++) {
            outer_len = (outer_len << 8) | data[off++];
        }
    } else {
        outer_len = data[off++];
    }
    (void)outer_len;
    
    // Search for target tag inside 7C
    while (off < data_len) {
        uint8_t tag = data[off++];
        if (off >= data_len) break;
        
        size_t len;
        if (data[off] & 0x80) {
            size_t nbytes = data[off] & 0x7F;
            off++;
            len = 0;
            for (size_t i = 0; i < nbytes && off < data_len; i++) {
                len = (len << 8) | data[off++];
            }
        } else {
            len = data[off++];
        }
        
        if (off + len > data_len) break;
        
        if (tag == target_tag) {
            if (out_len) *out_len = len;
            return data + off;
        }
        off += len;
    }
    return NULL;
}

// Helper: build GA APDU with a single TLV tag inside 7C container.
// Returns total APDU length.
static size_t build_ga_apdu(uint8_t *buf, uint8_t cla, uint8_t inner_tag,
                            const uint8_t *value, size_t value_len) {
    size_t off = 0;
    buf[off++] = cla;
    buf[off++] = 0x86;
    buf[off++] = 0x00;
    buf[off++] = 0x00;
    
    size_t lc_off = off++;  // placeholder for Lc
    size_t data_start = off;
    
    // 7C tag
    buf[off++] = 0x7C;
    // Inner content length = inner_tag TLV
    size_t inner_tlv_len = 1; // tag byte
    if (value_len > 127) {
        inner_tlv_len += 2; // long form length
    } else {
        inner_tlv_len += 1; // short form length
    }
    inner_tlv_len += value_len;
    
    // 7C length
    if (inner_tlv_len > 127) {
        buf[off++] = 0x81;
        buf[off++] = (uint8_t)inner_tlv_len;
    } else {
        buf[off++] = (uint8_t)inner_tlv_len;
    }
    
    // Inner tag
    buf[off++] = inner_tag;
    if (value_len > 127) {
        buf[off++] = 0x81;
        buf[off++] = (uint8_t)value_len;
    } else {
        buf[off++] = (uint8_t)value_len;
    }
    
    // Value
    if (value && value_len > 0) {
        memcpy(buf + off, value, value_len);
        off += value_len;
    }
    
    buf[lc_off] = (uint8_t)(off - data_start); // Lc
    buf[off++] = 0x00; // Le
    
    return off;
}

// Removed manual serialize/deserialize functions

bool passy_pace_auth_perform(PaceAuthContext* context, void* reader_ptr) {
    PassyReader* reader = (PassyReader*)reader_ptr;
    BitBuffer* tx_buffer = reader->tx_buffer;
    bool pace_success = true;
    uint8_t *apdu_buf = NULL;
    
    // MbedTLS objects
    mbedtls_ecp_group grp;
    mbedtls_mpi sk_map, sk_PCD;
    mbedtls_ecp_point PK_map_PCD, PK_map_PICC, H_point, sG, G_prime;
    mbedtls_ecp_point PK_PCD, PK_PICC, K_point;
    
    mbedtls_mpi_init(&sk_map);
    mbedtls_mpi_init(&sk_PCD);
    mbedtls_ecp_point_init(&PK_map_PCD);
    mbedtls_ecp_point_init(&PK_map_PICC);
    mbedtls_ecp_point_init(&H_point);
    mbedtls_ecp_point_init(&sG);
    mbedtls_ecp_point_init(&G_prime);
    mbedtls_ecp_point_init(&PK_PCD);
    mbedtls_ecp_point_init(&PK_PICC);
    mbedtls_ecp_point_init(&K_point);

    // ====================================================================
    // Step 1: MSE SET AT — select PACE-ECDH-GM-AES-CBC-CMAC-256
    // ====================================================================
    view_dispatcher_send_custom_event(reader->passy->view_dispatcher, PassyCustomEventPaceStep1);
    furi_delay_ms(50);
    if (reader->passy->abort_read) { pace_success = false; goto cleanup; }
    uint8_t mse_set_at_apdu[] = {
        0x00, 0x22, 0xc1, 0xa4, 
        0x12, // length = 18 bytes
        0x80, 0x0A,
        0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04, // OID: PACE-ECDH-GM-AES-256
        0x83, 0x01, context->password_type, // password ref: MRZ (01) or CAN (02)
        0x84, 0x01, 0x10  // parameter ID: 16
    };
    
    bit_buffer_reset(tx_buffer);
    bit_buffer_append_bytes(tx_buffer, mse_set_at_apdu, sizeof(mse_set_at_apdu));
    
    NfcCommand ret = passy_reader_send(reader);
    if (ret != NfcCommandContinue || reader->last_sw != 0x9000) {
        FURI_LOG_E("PACE", "MSE SET AT Failed: %04X", reader->last_sw);
        pace_success = false; goto cleanup;
    }
    FURI_LOG_I("PACE", "MSE SET AT Succeeded");

    // ====================================================================
    // Step 2: GA Step 1 — get encrypted PICC nonce
    // ====================================================================
    {
        uint8_t ga1[] = { 0x10, 0x86, 0x00, 0x00, 0x02, 0x7C, 0x00, 0x00 };
        bit_buffer_reset(tx_buffer);
        bit_buffer_append_bytes(tx_buffer, ga1, sizeof(ga1));
    }
    
    ret = passy_reader_send(reader);
    if (ret != NfcCommandContinue || reader->last_sw != 0x9000) {
        FURI_LOG_E("PACE", "GA Step 1 Failed: %04X", reader->last_sw);
        pace_success = false; goto cleanup;
    }
    
    const uint8_t *rx_data = bit_buffer_get_data(reader->rx_buffer);
    size_t rx_len = bit_buffer_get_size_bytes(reader->rx_buffer);
    
    // Parse encrypted nonce (tag 0x80 inside 7C)
    size_t enc_nonce_len = 0;
    const uint8_t *enc_nonce = tlv_find_tag(rx_data, rx_len, 0x80, &enc_nonce_len);
    if (!enc_nonce || enc_nonce_len != 16) {
        FURI_LOG_E("PACE", "Invalid PICC nonce length: %d", enc_nonce_len);
        pace_success = false; goto cleanup;
    }
    FURI_LOG_I("PACE", "GA Step 1 OK: got %d-byte encrypted nonce", enc_nonce_len);

    // ====================================================================
    // Decrypt PICC nonce: s = AES-256-ECB-Dec(K_pi, z)
    // ====================================================================
    uint8_t k_pi[32];
    pace_kdf_pi(context->K_seed, context->K_seed_len, k_pi);
    
    uint8_t s_nonce[16]; // decrypted PICC nonce
    {
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_dec(&aes, k_pi, 256);
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, enc_nonce, s_nonce);
        mbedtls_aes_free(&aes);
    }
    FURI_LOG_I("PACE", "Decrypted PICC nonce");

    mbedtls_ecp_group_init(&grp);
    if (load_brainpool_p384r1(&grp) != 0) {
        FURI_LOG_E("PACE", "Failed to load Brainpool P-384 curve");
        pace_success = false;
        goto cleanup;
    }
    FURI_LOG_I("PACE", "Loaded BrainpoolP384r1 curve successfully.");

    // ====================================================================
    // GA Step 2: Generic Mapping — ECDH exchange to derive G'
    // ====================================================================
    view_dispatcher_send_custom_event(reader->passy->view_dispatcher, PassyCustomEventPaceStep2);
    furi_delay_ms(50);
    if (reader->passy->abort_read) { pace_success = false; goto cleanup; }
    apdu_buf = malloc(512);
    if (!apdu_buf) { pace_success = false; goto cleanup; }

    // Generate ephemeral mapping private key
    mbedtls_mpi_fill_random(&sk_map, (grp.nbits + 7) / 8, my_rng, NULL);
    {
        mbedtls_mpi temp;
        mbedtls_mpi_init(&temp);
        mbedtls_mpi_mod_mpi(&temp, &sk_map, &grp.N);
        mbedtls_mpi_copy(&sk_map, &temp);
        mbedtls_mpi_free(&temp);
    }
    
    // PK_map_PCD = sk_map * G
    FURI_LOG_I("PACE", "Computing mapping public key with software_ecp_mul...");
    int mul_ret = software_ecp_mul(&grp, &PK_map_PCD, &sk_map, &grp.G);
    if (mul_ret != 0) {
        FURI_LOG_E("PACE", "Map generator EC scalar mul failed: %d", mul_ret);
        pace_success = false;
        goto cleanup;
    } else {
        FURI_LOG_I("PACE", "Native scalar mul successful.");
    }
    FURI_LOG_I("PACE", "Mapping key computed, preparing GA Step 2 APDU...");
    
    // Send GA Step 2: PK_map_PCD in tag 0x81
    {
        uint8_t pk_buf[MAX_PK_SIZE];
        size_t pk_len = 0;
        mbedtls_ecp_point_write_binary(&grp, &PK_map_PCD, MBEDTLS_ECP_PF_UNCOMPRESSED, &pk_len, pk_buf, sizeof(pk_buf));
        FURI_LOG_D("PACE", "Point serialized, len=%d", pk_len);
        size_t apdu_len = build_ga_apdu(apdu_buf, 0x10, 0x81, pk_buf, pk_len);
        FURI_LOG_D("PACE", "APDU built, len=%d", apdu_len);
        
        bit_buffer_reset(tx_buffer);
        bit_buffer_append_bytes(tx_buffer, apdu_buf, apdu_len);
    }
    
    FURI_LOG_I("PACE", "Sending GA Step 2...");
    furi_delay_ms(1); // Yield before NFC send to let system settle
    ret = passy_reader_send(reader);
    if (ret != NfcCommandContinue || reader->last_sw != 0x9000) {
        FURI_LOG_E("PACE", "GA Step 2 Failed: %04X", reader->last_sw);
        pace_success = false; goto cleanup_buf;
    }
    
    // Parse PICC's mapping public key (tag 0x82)
    rx_data = bit_buffer_get_data(reader->rx_buffer);
    rx_len = bit_buffer_get_size_bytes(reader->rx_buffer);
    {
        size_t picc_pk_len = 0;
        const uint8_t *picc_pk = tlv_find_tag(rx_data, rx_len, 0x82, &picc_pk_len);
        if (!picc_pk || mbedtls_ecp_point_read_binary(&grp, &PK_map_PICC, picc_pk, picc_pk_len) != 0) {
            FURI_LOG_E("PACE", "Invalid PICC mapping key (len=%d)", picc_pk_len);
            pace_success = false; goto cleanup_buf;
        }
    }
    FURI_LOG_I("PACE", "GA Step 2 OK: received PICC mapping key");

    // ====================================================================
    // Compute G' = s*G + H, where H = sk_map * PK_map_PICC
    // ====================================================================
    
    // H = sk_map * PK_map_PICC (ECDH shared point)
    FURI_LOG_I("PACE", "Computing ECDH shared point H...");
    mul_ret = software_ecp_mul(&grp, &H_point, &sk_map, &PK_map_PICC);
    if (mul_ret != 0) {
        FURI_LOG_E("PACE", "ECDH mul failed: %d", mul_ret);
        pace_success = false; goto cleanup_buf;
    }
    
    // sG = s * G
    {
        mbedtls_mpi s_mpi;
        mbedtls_mpi_init(&s_mpi);
        mbedtls_mpi_read_binary(&s_mpi, s_nonce, 16);
        
        FURI_LOG_I("PACE", "Computing s*G...");
        mul_ret = software_ecp_mul(&grp, &sG, &s_mpi, &grp.G);
        mbedtls_mpi_free(&s_mpi);
        if (mul_ret != 0) {
            FURI_LOG_E("PACE", "s*G mul failed: %d", mul_ret);
            pace_success = false; goto cleanup_buf;
        }
    }
    
    // G' = sG + H
    mul_ret = software_ecp_add(&grp, &G_prime, &sG, &H_point);
    if (mul_ret != 0) {
        FURI_LOG_E("PACE", "Point addition failed: %d", mul_ret);
        pace_success = false; goto cleanup_buf;
    }
    FURI_LOG_I("PACE", "Generic Mapping complete: G' computed");

    // ====================================================================
    // GA Step 3: Key Agreement — ephemeral ECDH on G'
    // ====================================================================
    view_dispatcher_send_custom_event(reader->passy->view_dispatcher, PassyCustomEventPaceStep3);
    furi_delay_ms(50);
    if (reader->passy->abort_read) { pace_success = false; goto cleanup_buf; }
    
    // Generate ephemeral private key
    mbedtls_mpi_fill_random(&sk_PCD, (grp.nbits + 7) / 8, my_rng, NULL);
    {
        mbedtls_mpi temp;
        mbedtls_mpi_init(&temp);
        mbedtls_mpi_mod_mpi(&temp, &sk_PCD, &grp.N);
        mbedtls_mpi_copy(&sk_PCD, &temp);
        mbedtls_mpi_free(&temp);
    }
    
    // PK_PCD = sk_PCD * G'
    FURI_LOG_I("PACE", "Computing ephemeral public key...");
    mul_ret = software_ecp_mul(&grp, &PK_PCD, &sk_PCD, &G_prime);
    if (mul_ret != 0) {
        FURI_LOG_E("PACE", "Ephemeral mul failed: %d", mul_ret);
        pace_success = false; goto cleanup_buf;
    }
    
    // Send GA Step 3: PK_PCD in tag 0x83
    {
        uint8_t pk_buf[MAX_PK_SIZE];
        size_t pk_len = 0;
        mbedtls_ecp_point_write_binary(&grp, &PK_PCD, MBEDTLS_ECP_PF_UNCOMPRESSED, &pk_len, pk_buf, sizeof(pk_buf));
        size_t apdu_len = build_ga_apdu(apdu_buf, 0x10, 0x83, pk_buf, pk_len);
        
        bit_buffer_reset(tx_buffer);
        bit_buffer_append_bytes(tx_buffer, apdu_buf, apdu_len);
    }
    
    ret = passy_reader_send(reader);
    if (ret != NfcCommandContinue || reader->last_sw != 0x9000) {
        FURI_LOG_E("PACE", "GA Step 3 Failed: %04X", reader->last_sw);
        pace_success = false; goto cleanup_buf;
    }
    
    // Parse PICC's ephemeral public key (tag 0x84)
    rx_data = bit_buffer_get_data(reader->rx_buffer);
    rx_len = bit_buffer_get_size_bytes(reader->rx_buffer);
    {
        size_t picc_pk_len = 0;
        const uint8_t *picc_pk = tlv_find_tag(rx_data, rx_len, 0x84, &picc_pk_len);
        if (!picc_pk || mbedtls_ecp_point_read_binary(&grp, &PK_PICC, picc_pk, picc_pk_len) != 0) {
            FURI_LOG_E("PACE", "Invalid PICC ephemeral key");
            pace_success = false; goto cleanup_buf;
        }
    }
    FURI_LOG_I("PACE", "GA Step 3 OK: received PICC ephemeral key");

    // ====================================================================
    // Compute shared secret K = sk_PCD * PK_PICC
    // ====================================================================
    FURI_LOG_I("PACE", "Computing shared secret...");
    mul_ret = software_ecp_mul(&grp, &K_point, &sk_PCD, &PK_PICC);
    if (mul_ret != 0) {
        FURI_LOG_E("PACE", "Shared secret mul failed: %d", mul_ret);
        pace_success = false; goto cleanup_buf;
    }
    
    // K = K_point.X (I2OSP padded to curve size)
    uint8_t K_buf[MAX_PK_SIZE];
    size_t k_len = (grp.pbits + 7) / 8;
    mbedtls_mpi_write_binary(&K_point.X, K_buf, k_len);
    
    // Derive session keys
    uint8_t K_enc[32], K_mac[32];
    if (!pace_kdf_session(K_buf, k_len, 1, K_enc)) {
        FURI_LOG_E("PACE", "KDF ENC failed");
        pace_success = false; goto cleanup_buf;
    }
    if (!pace_kdf_session(K_buf, k_len, 2, K_mac)) {
        FURI_LOG_E("PACE", "KDF MAC failed");
        pace_success = false; goto cleanup_buf;
    }
    FURI_LOG_I("PACE", "Session keys derived");

    // ====================================================================
    // GA Step 4: Mutual Authentication
    // ====================================================================
    view_dispatcher_send_custom_event(reader->passy->view_dispatcher, PassyCustomEventPaceStep4);
    furi_delay_ms(50);
    if (reader->passy->abort_read) { pace_success = false; goto cleanup_buf; }
    {
        // Build authentication token input (BSI TR-03110-3 B.1):
        // 7F49 <len>
        //   06 0A <PACE OID>
        //   86 <len> <uncompressed PK_PICC>
        uint8_t *mac_input = apdu_buf;
        size_t mi = 0;
        
        uint8_t pk_buf[MAX_PK_SIZE];
        size_t pk_len = 0;
        mbedtls_ecp_point_write_binary(&grp, &PK_PICC, MBEDTLS_ECP_PF_UNCOMPRESSED, &pk_len, pk_buf, sizeof(pk_buf));
        
        uint8_t pace_oid[] = {0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04};
        size_t inner_len = sizeof(pace_oid) + 1 + (pk_len > 127 ? 2 : 1) + pk_len;
        
        mac_input[mi++] = 0x7F;
        mac_input[mi++] = 0x49;
        if (inner_len > 127) {
            mac_input[mi++] = 0x81;
            mac_input[mi++] = (uint8_t)inner_len;
        } else {
            mac_input[mi++] = (uint8_t)inner_len;
        }
        
        memcpy(mac_input + mi, pace_oid, sizeof(pace_oid));
        mi += sizeof(pace_oid);
        
        mac_input[mi++] = 0x86;
        if (pk_len > 127) {
            mac_input[mi++] = 0x81;
            mac_input[mi++] = (uint8_t)pk_len;
        } else {
            mac_input[mi++] = (uint8_t)pk_len;
        }
        memcpy(mac_input + mi, pk_buf, pk_len);
        mi += pk_len;
        
        // T_PCD = CMAC(K_mac, mac_input)
        uint8_t T_PCD[16];
        cmac_aes256(K_mac, mac_input, mi, T_PCD);
        
        // Send GA Step 4: first 8 bytes of T_PCD in tag 0x85
        size_t apdu_len = build_ga_apdu(apdu_buf, 0x00, 0x85, T_PCD, 8);
        
        bit_buffer_reset(tx_buffer);
        bit_buffer_append_bytes(tx_buffer, apdu_buf, apdu_len);
    }
    
    ret = passy_reader_send(reader);
    if (ret != NfcCommandContinue || reader->last_sw != 0x9000) {
        FURI_LOG_E("PACE", "GA Step 4 Failed (Mutual Auth): %04X", reader->last_sw);
        pace_success = false; goto cleanup_buf;
    }
    
    // Verify PICC's authentication token (optional but good practice)
    rx_data = bit_buffer_get_data(reader->rx_buffer);
    rx_len = bit_buffer_get_size_bytes(reader->rx_buffer);
    {
        size_t t_picc_len = 0;
        const uint8_t *t_picc = tlv_find_tag(rx_data, rx_len, 0x86, &t_picc_len);
        if (!t_picc || t_picc_len != 8) {
            FURI_LOG_E("PACE", "Missing or invalid PICC authentication token!");
            pace_success = false; goto cleanup_buf;
        }

        // Compute expected T_PICC = CMAC(K_mac, 7F49 { OID || PK_PCD })
            uint8_t *mac_input = apdu_buf;
            size_t mi = 0;
            
            uint8_t pk_buf[MAX_PK_SIZE];
            size_t pk_len = 0;
            mbedtls_ecp_point_write_binary(&grp, &PK_PCD, MBEDTLS_ECP_PF_UNCOMPRESSED, &pk_len, pk_buf, sizeof(pk_buf));
            
            uint8_t pace_oid[] = {0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04};
            size_t inner_len = sizeof(pace_oid) + 1 + (pk_len > 127 ? 2 : 1) + pk_len;
            
            mac_input[mi++] = 0x7F;
            mac_input[mi++] = 0x49;
            if (inner_len > 127) {
                mac_input[mi++] = 0x81;
                mac_input[mi++] = (uint8_t)inner_len;
            } else {
                mac_input[mi++] = (uint8_t)inner_len;
            }
            
            memcpy(mac_input + mi, pace_oid, sizeof(pace_oid));
            mi += sizeof(pace_oid);
            
            mac_input[mi++] = 0x86;
            if (pk_len > 127) {
                mac_input[mi++] = 0x81;
                mac_input[mi++] = (uint8_t)pk_len;
            } else {
                mac_input[mi++] = (uint8_t)pk_len;
            }
            memcpy(mac_input + mi, pk_buf, pk_len);
            mi += pk_len;
            
            uint8_t T_PICC_expected[16];
            cmac_aes256(K_mac, mac_input, mi, T_PICC_expected);
            
            volatile uint8_t diff = 0;
            for(int i = 0; i < 8; i++) {
                diff |= t_picc[i] ^ T_PICC_expected[i];
            }
            if (diff != 0) {
                FURI_LOG_E("PACE", "PICC authentication token mismatch!");
                pace_success = false; goto cleanup_buf;
            }
    }
    
    // Save AES-256 session keys to secure messaging context
    if (reader->secure_messaging) {
        memcpy(reader->secure_messaging->KSenc, K_enc, 32);
        memcpy(reader->secure_messaging->KSmac, K_mac, 32);
        reader->secure_messaging->is_aes256 = true;
        memset(reader->secure_messaging->SSC, 0, 16);
    }
    
    FURI_LOG_I("PACE", "=== PACE Authentication Complete! ===");

cleanup_buf:
    free(apdu_buf);
cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&sk_map);
    mbedtls_mpi_free(&sk_PCD);
    mbedtls_ecp_point_free(&PK_map_PCD);
    mbedtls_ecp_point_free(&PK_map_PICC);
    mbedtls_ecp_point_free(&H_point);
    mbedtls_ecp_point_free(&sG);
    mbedtls_ecp_point_free(&G_prime);
    mbedtls_ecp_point_free(&PK_PCD);
    mbedtls_ecp_point_free(&PK_PICC);
    mbedtls_ecp_point_free(&K_point);

    mbedtls_platform_zeroize(k_pi, sizeof(k_pi));
    mbedtls_platform_zeroize(s_nonce, sizeof(s_nonce));
    mbedtls_platform_zeroize(K_buf, sizeof(K_buf));
    mbedtls_platform_zeroize(K_enc, sizeof(K_enc));
    mbedtls_platform_zeroize(K_mac, sizeof(K_mac));

    return pace_success;
}
