#pragma once

#include <stdint.h>
#include <stdlib.h>

#include <mbedtls/des.h>
#include <mbedtls/sha1.h>

#include <furi.h>
#include <lib/toolbox/bit_buffer.h>

#include "passy_common.h"

#define SECURE_MESSAGING_MAX_SIZE 128

typedef struct {
    uint8_t KENC[32];
    uint8_t KMAC[32];

    uint8_t rndICC[8];
    uint8_t rndIFD[8];

    uint8_t Kifd[32];
    uint8_t Kicc[32];

    uint8_t KSenc[32];
    uint8_t KSmac[32];
    uint8_t SSC[16]; // AES uses 16-byte SSC

    uint8_t mrz_sha1[20]; // SHA-1 of MRZ info for PACE password

    bool is_aes256;
} SecureMessaging;

SecureMessaging* passy_secure_messaging_alloc(
    uint8_t* passport_number,
    uint8_t* date_of_birth,
    uint8_t* date_of_expiry);

void passy_secure_messaging_free(SecureMessaging* secure_messaging);

void passy_secure_messaging_calculate_session_keys(SecureMessaging* secure_messaging);

void passy_secure_messaging_wrap_apdu(SecureMessaging* secure_messaging, BitBuffer* tx_buffer);

bool passy_secure_messaging_unwrap_rapdu(SecureMessaging* secure_messaging, BitBuffer* rx_buffer);
