#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "pace_crypto.h"
#include "pace_crypto_helpers.h"
#include <string.h>
#include <furi.h>
#include <furi_hal.h>
#include <mbedtls/md.h>

// ============================================================================
// Internal types
// ============================================================================

typedef struct {
    mbedtls_mpi T1, T2, T3, T4, T5, T6, T7, T8;
    mbedtls_mpi mod_B_shifted;
} jac_ctx;

typedef struct {
    mbedtls_mpi X;
    mbedtls_mpi Y;
    mbedtls_mpi Z;
} jac_point;

// ============================================================================
// Internal lifecycle helpers
// ============================================================================

static void jac_ctx_init(jac_ctx *ctx) {
    mbedtls_mpi_init(&ctx->T1); mbedtls_mpi_init(&ctx->T2);
    mbedtls_mpi_init(&ctx->T3); mbedtls_mpi_init(&ctx->T4);
    mbedtls_mpi_init(&ctx->T5); mbedtls_mpi_init(&ctx->T6);
    mbedtls_mpi_init(&ctx->T7); mbedtls_mpi_init(&ctx->T8);
    mbedtls_mpi_init(&ctx->mod_B_shifted);
}

static void jac_ctx_free(jac_ctx *ctx) {
    mbedtls_mpi_free(&ctx->T1); mbedtls_mpi_free(&ctx->T2);
    mbedtls_mpi_free(&ctx->T3); mbedtls_mpi_free(&ctx->T4);
    mbedtls_mpi_free(&ctx->T5); mbedtls_mpi_free(&ctx->T6);
    mbedtls_mpi_free(&ctx->T7); mbedtls_mpi_free(&ctx->T8);
    mbedtls_mpi_free(&ctx->mod_B_shifted);
}

static void jac_init(jac_point *P) {
    mbedtls_mpi_init(&P->X);
    mbedtls_mpi_init(&P->Y);
    mbedtls_mpi_init(&P->Z);
}

static void jac_free(jac_point *P) {
    mbedtls_mpi_free(&P->X);
    mbedtls_mpi_free(&P->Y);
    mbedtls_mpi_free(&P->Z);
}

// ============================================================================
// Modular arithmetic (aliasing-safe)
// ============================================================================

// Standalone safe mod — not currently used but kept for reference.
// All hot-path modular reductions use fast_safe_mod_mpi via macro instead.

// Reuses pre-allocated temp from jac_ctx to avoid aliasing bugs in mbedtls_mpi_mod_mpi.
static int fast_safe_mod_mpi(mbedtls_mpi *R, const mbedtls_mpi *A, const mbedtls_mpi *B, jac_ctx *ctx) {
    mbedtls_mpi *T = &ctx->mod_B_shifted;
    
    // mbedtls_mpi_mod_mpi causes undefined behavior for negative A.
    // So we compute |A| % B, and if A was negative, we return B - (|A| % B).
    int is_negative = (A->s < 0);
    
    // Temporarily make A positive if it was negative (modifies the const A briefly, but restores it)
    // To avoid modifying const A, we copy A to T, then make T positive.
    int ret = mbedtls_mpi_copy(T, A);
    if (ret != 0) return ret;
    T->s = 1; // Make positive
    
    ret = mbedtls_mpi_mod_mpi(T, T, B); // T = |A| % B
    if (ret == 0 && is_negative && mbedtls_mpi_cmp_int(T, 0) != 0) {
        ret = mbedtls_mpi_sub_mpi(T, B, T); // T = B - T
    }
    
    if (ret == 0) {
        ret = mbedtls_mpi_copy(R, T);
    }
    return ret;
}

// ============================================================================
// PACE KDF
// ============================================================================

int pace_kdf_pi(const uint8_t *password, size_t password_len, uint8_t *k_pi) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) return -1;
    
    if (mbedtls_md_setup(&ctx, md_info, 0) != 0) {
        mbedtls_md_free(&ctx);
        return -1;
    }
    if (mbedtls_md_starts(&ctx) != 0) { mbedtls_md_free(&ctx); return -1; }
    if (mbedtls_md_update(&ctx, password, password_len) != 0) { mbedtls_md_free(&ctx); return -1; }
    
    uint8_t counter[4] = {0x00, 0x00, 0x00, 0x03}; // PACE mapping key counter is 3
    if (mbedtls_md_update(&ctx, counter, 4) != 0) { mbedtls_md_free(&ctx); return -1; }
    
    if (mbedtls_md_finish(&ctx, k_pi) != 0) { mbedtls_md_free(&ctx); return -1; }
    mbedtls_md_free(&ctx);
    return 0;
}

// ============================================================================
// BrainpoolP384r1 curve parameters (parameterID = 16, per BSI TR-03110-3)
// ============================================================================

int load_brainpool_p384r1(mbedtls_ecp_group *grp) {
    mbedtls_ecp_group_init(grp);
    int ret = mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_BP384R1);
    if (ret == 0) {
        FURI_LOG_I("ECC", "Successfully loaded BrainpoolP384r1 from MbedTLS built-in.");
        return 0;
    }
    
    FURI_LOG_W("ECC", "MbedTLS does not have BrainpoolP384r1 enabled natively. Falling back to manual load.");

    // Manual fallback using RFC 5639 constants
    mbedtls_mpi_read_string(&grp->P, 16, "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53");
    mbedtls_mpi_read_string(&grp->A, 16, "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826");
    mbedtls_mpi_read_string(&grp->B, 16, "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11");
    mbedtls_mpi_read_string(&grp->G.X, 16, "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E");
    mbedtls_mpi_read_string(&grp->G.Y, 16, "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315");
    mbedtls_mpi_lset(&grp->G.Z, 1);
    mbedtls_mpi_read_string(&grp->N, 16, "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565");
    
    grp->pbits = 384;
    grp->nbits = 384;
    
    // Set a dummy ID so that MbedTLS doesn't crash on standard functions, but mbedtls_ecp_check_pubkey will fail (so don't use it)
    grp->id = MBEDTLS_ECP_DP_NONE;
    return 0;
}

// ============================================================================
// Jacobian coordinate EC point operations
// ============================================================================

// Macro: inside jac_double/jac_add, `ctx` is a jac_ctx* parameter
#define safe_mod_mpi(R, A, B) fast_safe_mod_mpi(R, A, B, ctx)

static int jac_double(mbedtls_ecp_group *grp, jac_point *R, const jac_point *P, jac_ctx *ctx) {
    if (mbedtls_mpi_cmp_int(&P->Z, 0) == 0 || mbedtls_mpi_cmp_int(&P->Y, 0) == 0) {
        return mbedtls_mpi_lset(&R->Z, 0);
    }
    int ret = 0;
    mbedtls_mpi *S = &ctx->T1; mbedtls_mpi *M = &ctx->T2; mbedtls_mpi *X2 = &ctx->T3;
    mbedtls_mpi *Y2 = &ctx->T4; mbedtls_mpi *Z2 = &ctx->T5; mbedtls_mpi *Z4 = &ctx->T6; mbedtls_mpi *temp = &ctx->T7;

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(X2, &P->X, &P->X)); MBEDTLS_MPI_CHK(safe_mod_mpi(X2, X2, &grp->P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(Y2, &P->Y, &P->Y)); MBEDTLS_MPI_CHK(safe_mod_mpi(Y2, Y2, &grp->P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(Z2, &P->Z, &P->Z)); MBEDTLS_MPI_CHK(safe_mod_mpi(Z2, Z2, &grp->P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(Z4, Z2, Z2));       MBEDTLS_MPI_CHK(safe_mod_mpi(Z4, Z4, &grp->P));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(S, &P->X, Y2));     MBEDTLS_MPI_CHK(safe_mod_mpi(S, S, &grp->P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(S, S, 4));          MBEDTLS_MPI_CHK(safe_mod_mpi(S, S, &grp->P));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(M, X2, 3));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(temp, &grp->A, Z4));
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(M, M, temp));
    MBEDTLS_MPI_CHK(safe_mod_mpi(M, M, &grp->P));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&R->X, M, M));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&R->X, &R->X, S));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&R->X, &R->X, S));
    MBEDTLS_MPI_CHK(safe_mod_mpi(&R->X, &R->X, &grp->P));

    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(temp, S, &R->X));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&R->Y, M, temp));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(temp, Y2, Y2));
    MBEDTLS_MPI_CHK(safe_mod_mpi(temp, temp, &grp->P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(temp, temp, 8));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&R->Y, &R->Y, temp));
    MBEDTLS_MPI_CHK(safe_mod_mpi(&R->Y, &R->Y, &grp->P));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&R->Z, &P->Y, &P->Z));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(&R->Z, &R->Z, 2));
    MBEDTLS_MPI_CHK(safe_mod_mpi(&R->Z, &R->Z, &grp->P));

cleanup:
    return ret;
}

static int jac_add(mbedtls_ecp_group *grp, jac_point *R, const jac_point *P, const jac_point *Q, jac_ctx *ctx) {
    if (mbedtls_mpi_cmp_int(&P->Z, 0) == 0) {
        mbedtls_mpi_copy(&R->X, &Q->X); mbedtls_mpi_copy(&R->Y, &Q->Y); mbedtls_mpi_copy(&R->Z, &Q->Z);
        return 0;
    }
    if (mbedtls_mpi_cmp_int(&Q->Z, 0) == 0) {
        mbedtls_mpi_copy(&R->X, &P->X); mbedtls_mpi_copy(&R->Y, &P->Y); mbedtls_mpi_copy(&R->Z, &P->Z);
        return 0;
    }
    int ret = 0;
    mbedtls_mpi *U1 = &ctx->T1; mbedtls_mpi *U2 = &ctx->T2; mbedtls_mpi *S1 = &ctx->T3; mbedtls_mpi *S2 = &ctx->T4;
    mbedtls_mpi *H = &ctx->T5; mbedtls_mpi *r = &ctx->T6; mbedtls_mpi *H2 = &ctx->T7; mbedtls_mpi *H3 = &ctx->T8;
    
    mbedtls_mpi Z1_2, Z2_2, Z1_3, Z2_3;
    mbedtls_mpi_init(&Z1_2); mbedtls_mpi_init(&Z2_2); mbedtls_mpi_init(&Z1_3); mbedtls_mpi_init(&Z2_3);

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Z1_2, &P->Z, &P->Z)); MBEDTLS_MPI_CHK(safe_mod_mpi(&Z1_2, &Z1_2, &grp->P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Z2_2, &Q->Z, &Q->Z)); MBEDTLS_MPI_CHK(safe_mod_mpi(&Z2_2, &Z2_2, &grp->P));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Z1_3, &Z1_2, &P->Z)); MBEDTLS_MPI_CHK(safe_mod_mpi(&Z1_3, &Z1_3, &grp->P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Z2_3, &Z2_2, &Q->Z)); MBEDTLS_MPI_CHK(safe_mod_mpi(&Z2_3, &Z2_3, &grp->P));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(U1, &P->X, &Z2_2)); MBEDTLS_MPI_CHK(safe_mod_mpi(U1, U1, &grp->P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(U2, &Q->X, &Z1_2)); MBEDTLS_MPI_CHK(safe_mod_mpi(U2, U2, &grp->P));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(S1, &P->Y, &Z2_3)); MBEDTLS_MPI_CHK(safe_mod_mpi(S1, S1, &grp->P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(S2, &Q->Y, &Z1_3)); MBEDTLS_MPI_CHK(safe_mod_mpi(S2, S2, &grp->P));

    if (mbedtls_mpi_cmp_mpi(U1, U2) == 0) {
        if (mbedtls_mpi_cmp_mpi(S1, S2) == 0) {
            ret = jac_double(grp, R, P, ctx);
            goto cleanup;
        } else {
            MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&R->Z, 0));
            goto cleanup;
        }
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(H, U2, U1)); MBEDTLS_MPI_CHK(safe_mod_mpi(H, H, &grp->P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(r, S2, S1)); MBEDTLS_MPI_CHK(safe_mod_mpi(r, r, &grp->P));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(H2, H, H)); MBEDTLS_MPI_CHK(safe_mod_mpi(H2, H2, &grp->P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(H3, H2, H)); MBEDTLS_MPI_CHK(safe_mod_mpi(H3, H3, &grp->P));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&R->X, r, r));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&R->X, &R->X, H3));
    
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Z1_2, U1, H2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(&Z1_2, &Z1_2, 2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&R->X, &R->X, &Z1_2));
    MBEDTLS_MPI_CHK(safe_mod_mpi(&R->X, &R->X, &grp->P));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Z1_2, U1, H2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&Z1_2, &Z1_2, &R->X));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&R->Y, r, &Z1_2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Z1_2, S1, H3));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&R->Y, &R->Y, &Z1_2));
    MBEDTLS_MPI_CHK(safe_mod_mpi(&R->Y, &R->Y, &grp->P));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&R->Z, &P->Z, &Q->Z));
    MBEDTLS_MPI_CHK(safe_mod_mpi(&R->Z, &R->Z, &grp->P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&R->Z, &R->Z, H));
    MBEDTLS_MPI_CHK(safe_mod_mpi(&R->Z, &R->Z, &grp->P));

cleanup:
    mbedtls_mpi_free(&Z1_2); mbedtls_mpi_free(&Z2_2); mbedtls_mpi_free(&Z1_3); mbedtls_mpi_free(&Z2_3);
    return ret;
}

// ============================================================================
// Software EC scalar multiplication and point addition
// ============================================================================

// Redefine macro: inside software_ecp_mul/add, `ctx` is a local jac_ctx (not pointer)
#undef safe_mod_mpi
#define safe_mod_mpi(R, A, B) fast_safe_mod_mpi(R, A, B, &ctx)

int software_ecp_mul(mbedtls_ecp_group *grp, mbedtls_ecp_point *R, const mbedtls_mpi *m, const mbedtls_ecp_point *P) {
    int ret = 0;
    jac_point Q, T, Res;
    jac_init(&Q); jac_init(&T); jac_init(&Res);
    jac_ctx ctx;
    jac_ctx_init(&ctx);

    // Lower thread priority so watchdog feeder (normal priority) can run during yields.
    // The NFC worker thread runs at high priority; without this, furi_delay_ms yields
    // only schedule equal/higher priority tasks, starving the IWDG feeder.
    furi_thread_set_current_priority(FuriThreadPriorityNormal);
    
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&Q.X, &P->X));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&Q.Y, &P->Y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&Q.Z, &P->Z));
    
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&Res.Z, 0)); // Res = infinity

    size_t total_bits = mbedtls_mpi_bitlen(m);
    FURI_LOG_I("ECC", "scalar mul: %d bits", total_bits);

    for (size_t i = 0; i < total_bits; i++) {
        if (i % 32 == 0) furi_delay_ms(1); // Yield to prevent thread watchdog timeout
        if (i % 64 == 0 && i > 0) {
            FURI_LOG_D("ECC", "  bit %d/%d", i, total_bits);
        }
        if (mbedtls_mpi_get_bit(m, i) == 1) {
            MBEDTLS_MPI_CHK(jac_add(grp, &T, &Res, &Q, &ctx));
            MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&Res.X, &T.X));
            MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&Res.Y, &T.Y));
            MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&Res.Z, &T.Z));
        }
        MBEDTLS_MPI_CHK(jac_double(grp, &T, &Q, &ctx));
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&Q.X, &T.X));
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&Q.Y, &T.Y));
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&Q.Z, &T.Z));
    }
    FURI_LOG_I("ECC", "scalar mul complete, converting to affine...");
    furi_delay_ms(1); // Yield before inv_mod

    if (mbedtls_mpi_cmp_int(&Res.Z, 0) == 0) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&R->Z, 0));
    } else {
        mbedtls_mpi Zinv, Zinv2, Zinv3;
        mbedtls_mpi_init(&Zinv); mbedtls_mpi_init(&Zinv2); mbedtls_mpi_init(&Zinv3);
        
        MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&Zinv, &Res.Z, &grp->P));
        furi_delay_ms(1); // Yield after inv_mod
        FURI_LOG_D("ECC", "  inv_mod done");
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Zinv2, &Zinv, &Zinv));
        MBEDTLS_MPI_CHK(safe_mod_mpi(&Zinv2, &Zinv2, &grp->P));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Zinv3, &Zinv2, &Zinv));
        MBEDTLS_MPI_CHK(safe_mod_mpi(&Zinv3, &Zinv3, &grp->P));
        
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&R->X, &Res.X, &Zinv2));
        MBEDTLS_MPI_CHK(safe_mod_mpi(&R->X, &R->X, &grp->P));
        
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&R->Y, &Res.Y, &Zinv3));
        MBEDTLS_MPI_CHK(safe_mod_mpi(&R->Y, &R->Y, &grp->P));
        
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&R->Z, 1));
        
        mbedtls_mpi_free(&Zinv); mbedtls_mpi_free(&Zinv2); mbedtls_mpi_free(&Zinv3);
    }
    FURI_LOG_I("ECC", "affine conversion done");

cleanup:
    // Stay at Normal priority — raising causes priority inversion with log system.
    // The NFC hardware uses interrupts/DMA so thread priority doesn't affect RF timing.
    // The NFC callback already sets priority to Lowest after state_machine returns.
    jac_free(&Q); jac_free(&T); jac_free(&Res);
    jac_ctx_free(&ctx);
    return ret;
}

int software_ecp_add(mbedtls_ecp_group *grp, mbedtls_ecp_point *R, const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q) {
    int ret = 0;
    jac_point JP, JQ, JR;
    jac_init(&JP); jac_init(&JQ); jac_init(&JR);
    jac_ctx ctx;
    jac_ctx_init(&ctx);

    // Convert affine → Jacobian (Z = 1)
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&JP.X, &P->X));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&JP.Y, &P->Y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&JP.Z, &P->Z));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&JQ.X, &Q->X));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&JQ.Y, &Q->Y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&JQ.Z, &Q->Z));

    MBEDTLS_MPI_CHK(jac_add(grp, &JR, &JP, &JQ, &ctx));

    // Convert Jacobian → affine
    if (mbedtls_mpi_cmp_int(&JR.Z, 0) == 0) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&R->Z, 0));
    } else {
        mbedtls_mpi Zinv, Zinv2, Zinv3;
        mbedtls_mpi_init(&Zinv); mbedtls_mpi_init(&Zinv2); mbedtls_mpi_init(&Zinv3);

        MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&Zinv, &JR.Z, &grp->P));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Zinv2, &Zinv, &Zinv));
        MBEDTLS_MPI_CHK(safe_mod_mpi(&Zinv2, &Zinv2, &grp->P));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Zinv3, &Zinv2, &Zinv));
        MBEDTLS_MPI_CHK(safe_mod_mpi(&Zinv3, &Zinv3, &grp->P));

        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&R->X, &JR.X, &Zinv2));
        MBEDTLS_MPI_CHK(safe_mod_mpi(&R->X, &R->X, &grp->P));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&R->Y, &JR.Y, &Zinv3));
        MBEDTLS_MPI_CHK(safe_mod_mpi(&R->Y, &R->Y, &grp->P));
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&R->Z, 1));

        mbedtls_mpi_free(&Zinv); mbedtls_mpi_free(&Zinv2); mbedtls_mpi_free(&Zinv3);
    }

cleanup:
    jac_free(&JP); jac_free(&JQ); jac_free(&JR);
    jac_ctx_free(&ctx);
    return ret;
}
