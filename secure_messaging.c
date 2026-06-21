#include "secure_messaging.h"
#include "cmac_aes256.h"
#include <mbedtls/aes.h>

#define TAG "SecureMessaging"

uint8_t padding[16] =
    {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

void passy_secure_messaging_adjust_parity(uint8_t key[16]) {
    for(size_t i = 0; i < 16; i++) {
        // Set the parity bit to 1 if the number of 1 bits is even
        for(size_t j = 0; j < 8; j++) {
            if((key[i] >> j) & 0x01) {
                key[i] ^= 0x01;
            }
        }
        key[i] ^= 0x01;
    }
}

void passy_secure_messaging_key_diversification(
    uint8_t input[20],
    size_t input_len,
    uint8_t* output) {
    uint8_t sha[20];
    mbedtls_sha1_context ctx;
    mbedtls_sha1_init(&ctx);
    mbedtls_sha1_starts(&ctx);
    mbedtls_sha1_update(&ctx, input, input_len);
    mbedtls_sha1_finish(&ctx, sha);

    memcpy(output, sha, 16);
    passy_secure_messaging_adjust_parity(output);
}

SecureMessaging* passy_secure_messaging_alloc(
    uint8_t* passport_number,
    uint8_t* date_of_birth,
    uint8_t* date_of_expiry) {
    SecureMessaging* secure_messaging = malloc(sizeof(SecureMessaging));
    memset(secure_messaging, 0, sizeof(SecureMessaging));
    mbedtls_sha1_context ctx;

    memset(secure_messaging->rndIFD, 0x00, sizeof(secure_messaging->rndIFD));
    memset(secure_messaging->Kifd, 0x00, sizeof(secure_messaging->Kifd));

    uint8_t mrz[SECURE_MESSAGING_MAX_SIZE];
    size_t mrz_index = 0;
    strncpy((char*)mrz, (char*)passport_number, 12);
    mrz_index += strlen((char*)passport_number);
    strncpy((char*)mrz + mrz_index, (char*)date_of_birth, 8);
    mrz_index += strlen((char*)date_of_birth);
    strncpy((char*)mrz + mrz_index, (char*)date_of_expiry, 8);
    mrz_index += strlen((char*)date_of_expiry);
    FURI_LOG_D(TAG, "secure_messaging_alloc mrz %s", mrz);

    uint8_t sha[20];

    mbedtls_sha1_init(&ctx);
    mbedtls_sha1_starts(&ctx);
    mbedtls_sha1_update(&ctx, mrz, mrz_index);
    mbedtls_sha1_finish(&ctx, sha);
    mbedtls_sha1_free(&ctx);
    
    memcpy(secure_messaging->mrz_sha1, sha, 20);

    FURI_LOG_D(TAG, "secure_messaging_alloc sha");
    uint8_t D[20];
    memset(D, 0, sizeof(D));
    memcpy(D, sha, 16);

    D[19] = 0x01;
    passy_secure_messaging_key_diversification(D, sizeof(D), secure_messaging->KENC);

    D[19] = 0x02;
    passy_secure_messaging_key_diversification(D, sizeof(D), secure_messaging->KMAC);

    mbedtls_sha1_free(&ctx);
    return secure_messaging;
}

void passy_secure_messaging_free(SecureMessaging* secure_messaging) {
    furi_assert(secure_messaging);
    // Nothing to free;
    free(secure_messaging);
}

void passy_secure_messaging_calculate_session_keys(SecureMessaging* secure_messaging) {
    uint8_t Kseed[16];
    for(size_t i = 0; i < sizeof(Kseed); i++) {
        Kseed[i] = secure_messaging->Kifd[i] ^ secure_messaging->Kicc[i];
    }

    uint8_t D[20];

    memset(D, 0, sizeof(D));
    memcpy(D, Kseed, sizeof(Kseed));

    D[19] = 0x01;
    passy_secure_messaging_key_diversification(D, sizeof(D), secure_messaging->KSenc);

    D[19] = 0x02;
    passy_secure_messaging_key_diversification(D, sizeof(D), secure_messaging->KSmac);
}

void passy_secure_messaging_increment_context(SecureMessaging* secure_messaging) {
    uint8_t* context = secure_messaging->SSC;
    size_t context_len = secure_messaging->is_aes256 ? 16 : 8;
    do {
    } while(++context[--context_len] == 0 && context_len > 0);
}

void passy_secure_messaging_wrap_apdu(SecureMessaging* secure_messaging, BitBuffer* tx_buffer) {
    furi_assert(secure_messaging);
    passy_secure_messaging_increment_context(secure_messaging);

    // Read tx_buffer to wrap the apdu in secure messaging
    size_t message_len = bit_buffer_get_size_bytes(tx_buffer);
    const uint8_t* message = bit_buffer_get_data(tx_buffer);

    uint8_t payload_length = 0;
    bool has_le = false;
    uint8_t le = 0;
    if(message_len == 5) { // APDU with no payload and Le
        has_le = true;
        le = message[4];
    } else if(message_len >= 5) {
        payload_length = message[4];
        if (message_len == (size_t)(5 + payload_length + 1)) { // Lc + payload + Le
            has_le = true;
            le = message[5 + payload_length];
        }
    }

    uint8_t cmd_header[16]; // Padded to 16 bytes for AES block size, but we only use 4 bytes + 0x80 for MAC
    memset(cmd_header, 0, sizeof(cmd_header));
    memcpy(cmd_header, message, 4);
    cmd_header[0] |= 0x0c; // Secure Messaging flag
    cmd_header[4] = 0x80; // Padding starts here

    uint8_t D087[256];
    memset(D087, 0, sizeof(D087));
    size_t D087_len = 0;
    
    if(payload_length > 0) {
        const uint8_t* payload = message + 5;
        uint16_t padded_length = payload_length + 1;
        
        if (secure_messaging->is_aes256) {
            uint8_t padding_len = 16 - (padded_length % 16);
            if (padding_len == 16) padding_len = 0;
            padded_length += padding_len;
        } else {
            uint8_t padding_len = 8 - (padded_length % 8);
            if (padding_len == 8) padding_len = 0;
            padded_length += padding_len;
        }
        
        uint16_t padded_payload_size = padded_length > 272 ? padded_length : 272;
        uint8_t *padded_payload = malloc(padded_payload_size);
        memset(padded_payload, 0, padded_payload_size);
        memcpy(padded_payload, payload, payload_length);
        padded_payload[payload_length] = 0x80;

        uint8_t *encrypted_payload = malloc(padded_payload_size);
        memset(encrypted_payload, 0, padded_payload_size);

        if (secure_messaging->is_aes256) {
            uint8_t iv[16];
            mbedtls_aes_context ctx;
            mbedtls_aes_init(&ctx);
            mbedtls_aes_setkey_enc(&ctx, secure_messaging->KSenc, 256);
            // IV = E(KSenc, SSC)
            mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, secure_messaging->SSC, iv);
            mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, padded_length, iv, padded_payload, encrypted_payload);
            mbedtls_aes_free(&ctx);
        } else {
            uint8_t iv[8] = {0};
            mbedtls_des3_context ctx;
            mbedtls_des3_init(&ctx);
            mbedtls_des3_set2key_enc(&ctx, secure_messaging->KSenc);
            mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, padded_length, iv, padded_payload, encrypted_payload);
            mbedtls_des3_free(&ctx);
        }

        D087[0] = 0x87;
        D087[1] = 1 + padded_length;
        D087[2] = 0x01; // PI (Padding Indicator)
        memcpy(D087 + 3, encrypted_payload, padded_length);
        D087_len = 3 + padded_length;
        free(padded_payload);
        free(encrypted_payload);
    }

    uint8_t D097[3];
    memset(D097, 0, sizeof(D097));
    if(has_le) {
        D097[0] = 0x97;
        D097[1] = 0x01;
        D097[2] = le;
    }

    uint8_t M[512];
    uint16_t M_index = 0;
    memset(M, 0, sizeof(M));
    
    // ICAO 9303: For AES CMAC, the command header is NOT padded before MACing.
    // However, some EAC specs (BSI TR-03110) might require the CmdHeader to be zero-padded to the block length (16 bytes).
    uint8_t cmd_padded_len = secure_messaging->is_aes256 ? 16 : 8;
    memcpy(M, cmd_header, 4);
    if(secure_messaging->is_aes256) {
        M[4] = 0x80;
        memset(M + 5, 0, 11);
    } else {
        memcpy(M, cmd_header, 8); // ISO 7816-4 padding for DES (80 00 00 00)
    }
    M_index += cmd_padded_len;

    if(payload_length > 0) {
        memcpy(M + M_index, D087, D087_len);
        M_index += D087_len;
    }

    if(has_le) {
        memcpy(M + M_index, D097, sizeof(D097));
        M_index += sizeof(D097);
    }

    uint8_t N[512];
    uint16_t N_index = 0;
    memset(N, 0, sizeof(N));
    
    uint8_t ssc_len = secure_messaging->is_aes256 ? 16 : 8;
    memcpy(N, secure_messaging->SSC, ssc_len);
    N_index += ssc_len;
    
    memcpy(N + N_index, M, M_index);
    N_index += M_index;

    uint8_t mac[16];
    memset(mac, 0, sizeof(mac));
    
    uint8_t block_size = secure_messaging->is_aes256 ? 16 : 8;
    N[N_index++] = 0x80;
    while(N_index % block_size != 0) {
        N[N_index++] = 0x00;
    }
    
    if (secure_messaging->is_aes256) {
        cmac_aes256(secure_messaging->KSmac, N, N_index, mac);
    } else {
        passy_mac(secure_messaging->KSmac, N, N_index, mac, true);
    }

    uint8_t D08E[2 + 16];
    memset(D08E, 0, sizeof(D08E));
    
    uint8_t mac_len = 8; // ICAO 9303: MAC is always truncated to 8 bytes, even for AES
    D08E[0] = 0x8E;
    D08E[1] = mac_len;
    memcpy(D08E + 2, mac, mac_len);

    bit_buffer_reset(tx_buffer);

    bit_buffer_append_bytes(tx_buffer, cmd_header, 4);

    uint8_t protected_payload_length = 0;
    protected_payload_length += (2 + mac_len);

    if(payload_length > 0) {
        protected_payload_length += D087_len;
    }
    if(has_le) {
        protected_payload_length += sizeof(D097);
    }

    // Lc
    bit_buffer_append_byte(tx_buffer, protected_payload_length);

    if(payload_length > 0) {
        bit_buffer_append_bytes(tx_buffer, D087, D087_len);
    }

    if(has_le) {
        bit_buffer_append_bytes(tx_buffer, D097, sizeof(D097));
    }
    bit_buffer_append_bytes(tx_buffer, D08E, 2 + mac_len);
    bit_buffer_append_byte(tx_buffer, 0x00); // Le
}

bool passy_secure_messaging_unwrap_rapdu(SecureMessaging* secure_messaging, BitBuffer* rx_buffer) {
    passy_secure_messaging_increment_context(secure_messaging);

    size_t length = bit_buffer_get_size_bytes(rx_buffer);
    const uint8_t* data = bit_buffer_get_data(rx_buffer);
    uint8_t status_word[2];
    uint8_t* mac = NULL;
    uint8_t* encrypted = NULL;
    uint16_t encrypted_len = 0;

    // Look for mac
    size_t i = 0;
    const uint8_t* raw_do87 = NULL;
    size_t raw_do87_len = 0;

    do {
        size_t do_start = i;
        uint8_t type = data[i++];
        size_t len = data[i++];
        if(len == 0x81) {
            len = data[i++];
        } else if(len == 0x82) {
            len = (data[i] << 8) | data[i + 1];
            i += 2;
        }

        switch(type) {
        case 0x87:
            raw_do87 = data + do_start;
            raw_do87_len = (i - do_start) + len;
            // Encrypted data always starts with a 0x01
            encrypted = (uint8_t*)data + i + 1;
            encrypted_len = len - 1;
            break;
        case 0x8E:
            mac = (uint8_t*)data + i;
            break;
        case 0x99:
            status_word[0] = data[i + 0];
            status_word[1] = data[i + 1];
            break;
        default:
            FURI_LOG_W(TAG, "Unknown type %02x", type);
            break;
        }
        i += len;
    } while(i < length - 2);

    if(mac) {
        uint8_t K[512]; // Increased for larger payloads
        memset(K, 0, sizeof(K));
        size_t K_index = 0;
        
        uint8_t ssc_len = secure_messaging->is_aes256 ? 16 : 8;
        memcpy(K, secure_messaging->SSC, ssc_len);
        K_index += ssc_len;
        
        if(raw_do87) {
            memcpy(K + K_index, raw_do87, raw_do87_len);
            K_index += raw_do87_len;
        }

        // Assume the status word is always present
        K[K_index++] = 0x99;
        K[K_index++] = 0x02;
        memcpy(K + K_index, status_word, 2);
        K_index += 2;
        
        uint8_t calculated_mac[16];
        memset(calculated_mac, 0, sizeof(calculated_mac));
        
        uint8_t block_size = secure_messaging->is_aes256 ? 16 : 8;
        K[K_index++] = 0x80;
        while(K_index % block_size != 0) {
            K[K_index++] = 0x00;
        }
        
        if (secure_messaging->is_aes256) {
            cmac_aes256(secure_messaging->KSmac, K, K_index, calculated_mac);
            if(memcmp(mac, calculated_mac, 8) != 0) { // CMAC is truncated to 8 bytes for SM
                FURI_LOG_W(TAG, "Invalid MAC (AES)");
                return false;
            }
        } else {
            passy_mac(secure_messaging->KSmac, K, K_index, calculated_mac, true);
            if(memcmp(mac, calculated_mac, 8) != 0) {
                FURI_LOG_W(TAG, "Invalid MAC (DES)");
                return false;
            }
        }
    }

    uint8_t decrypted[264];
    uint16_t decrypted_len = encrypted_len;
    if(encrypted) {
        if(encrypted_len > sizeof(decrypted)) {
            FURI_LOG_W(TAG, "secure_messaging_unwrap_rapdu encrypted length too large to handle");
            return false;
        }
        
        if (secure_messaging->is_aes256) {
            uint8_t iv[16];
            mbedtls_aes_context ctx;
            mbedtls_aes_init(&ctx);
            mbedtls_aes_setkey_enc(&ctx, secure_messaging->KSenc, 256);
            mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, secure_messaging->SSC, iv);
            
            // Re-init for decryption!
            mbedtls_aes_setkey_dec(&ctx, secure_messaging->KSenc, 256);
            mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, encrypted_len, iv, encrypted, decrypted);
            mbedtls_aes_free(&ctx);
        } else {
            uint8_t iv[8];
            memset(iv, 0, sizeof(iv));
            mbedtls_des3_context ctx;
            mbedtls_des3_init(&ctx);
            mbedtls_des3_set2key_dec(&ctx, secure_messaging->KSenc);
            mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, encrypted_len, iv, encrypted, decrypted);
            mbedtls_des3_free(&ctx);
        }

        // Remove padding
        do {
        } while(decrypted[--decrypted_len] == 0 && decrypted_len > 0);
    }

    // Don't reset until after data has been decrypted
    bit_buffer_reset(rx_buffer);
    if(encrypted) {
        bit_buffer_append_bytes(rx_buffer, decrypted, decrypted_len);
    }

    bit_buffer_append_bytes(rx_buffer, status_word, 2);
    return true;
}
