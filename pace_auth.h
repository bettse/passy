#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <furi.h>
#include <toolbox/bit_buffer.h>

#include "passy_common.h"
#include "secure_messaging.h"

// The standard PACE authentication flow structure
typedef struct {
    uint8_t K_seed[64];     // PACE CAN (K_pi source) or shared secret K (up to 64 bytes for P512)
    size_t K_seed_len;      // Length of K_seed when used as CAN
    uint8_t K_enc[32];      // Derived Session Encryption Key
    uint8_t K_mac[32];      // Derived Session MAC Key
    uint8_t password_type;
    bool pace_established;
} PaceAuthContext;

PaceAuthContext* passy_pace_auth_alloc(const uint8_t* k_seed, size_t k_seed_len, uint8_t password_type);

void passy_pace_auth_free(PaceAuthContext* context);

// Initiates the PACE protocol (MSE, General Authenticate steps)
// Returns true if PACE successfully derives session keys
// Note: We will need a way to pass the Nfc TX/RX buffers and poller functions
bool passy_pace_auth_perform(PaceAuthContext* context, void* reader);
