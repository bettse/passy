#include "sha384.h"
#include <string.h>

#define SHA384_BLOCK_SIZE 128
#define SHA384_DIGEST_SIZE 48

typedef struct {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t buffer[128];
} sha384_context;

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
#define Sigma1(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
#define sigma0(x) (ROR64(x, 1) ^ ROR64(x, 8) ^ ((x) >> 7))
#define sigma1(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ ((x) >> 6))

static const uint64_t K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static inline uint64_t load64(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static inline void store64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v);
}

static void sha384_transform(sha384_context *ctx, const uint8_t *data) {
    uint64_t a, b, c, d, e, f, g, h, t1, t2;
    uint64_t W[80];
    int i;

    for (i = 0; i < 16; i++) {
        W[i] = load64(data + i * 8);
    }
    for (i = 16; i < 80; i++) {
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 80; i++) {
        t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
        t2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha384_init(sha384_context *ctx) {
    ctx->state[0] = 0xcbbb9d5dc1059ed8;
    ctx->state[1] = 0x629a292a367cd507;
    ctx->state[2] = 0x9159015a3070dd17;
    ctx->state[3] = 0x152fecd8f70e5939;
    ctx->state[4] = 0x67332667ffc00b31;
    ctx->state[5] = 0x8eb44a8768581511;
    ctx->state[6] = 0xdb0c2e0d64f98fa7;
    ctx->state[7] = 0x47b5481dbefa4fa4;
    ctx->count[0] = ctx->count[1] = 0;
}

static void sha384_update(sha384_context *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    size_t index = (size_t)((ctx->count[0] >> 3) & 0x7F);

    uint64_t bit_len_low = (uint64_t)len << 3;
    uint64_t bit_len_high = (uint64_t)len >> 61;

    if ((ctx->count[0] += bit_len_low) < bit_len_low) {
        ctx->count[1]++;
    }
    ctx->count[1] += bit_len_high;

    if (index > 0) {
        size_t left = 128 - index;
        if (len >= left) {
            memcpy(&ctx->buffer[index], data, left);
            sha384_transform(ctx, ctx->buffer);
            i = left;
            index = 0;
        } else {
            memcpy(&ctx->buffer[index], data, len);
            return;
        }
    }

    while (i + 128 <= len) {
        sha384_transform(ctx, data + i);
        i += 128;
    }

    if (i < len) {
        memcpy(&ctx->buffer[index], data + i, len - i);
    }
}

static void sha384_final(sha384_context *ctx, uint8_t digest[48]) {
    uint8_t padding[128];
    uint8_t length_bytes[16];
    size_t index = (size_t)((ctx->count[0] >> 3) & 0x7F);
    size_t pad_len = (index < 112) ? (112 - index) : (128 + 112 - index);

    store64(length_bytes, ctx->count[1]);
    store64(length_bytes + 8, ctx->count[0]);

    memset(padding, 0, sizeof(padding));
    padding[0] = 0x80;

    sha384_update(ctx, padding, pad_len);
    sha384_update(ctx, length_bytes, 16);

    for (int i = 0; i < 6; i++) {
        store64(digest + i * 8, ctx->state[i]);
    }
}

void hmac_sha384(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t mac[48]) {
    uint8_t k_ipad[SHA384_BLOCK_SIZE];
    uint8_t k_opad[SHA384_BLOCK_SIZE];
    uint8_t tk[SHA384_DIGEST_SIZE];
    int i;
    sha384_context ctx;

    if (key_len > SHA384_BLOCK_SIZE) {
        sha384_init(&ctx);
        sha384_update(&ctx, key, key_len);
        sha384_final(&ctx, tk);
        key = tk;
        key_len = SHA384_DIGEST_SIZE;
    }

    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    if (key_len > 0) {
        memcpy(k_ipad, key, key_len);
        memcpy(k_opad, key, key_len);
    }

    for (i = 0; i < SHA384_BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    sha384_init(&ctx);
    sha384_update(&ctx, k_ipad, SHA384_BLOCK_SIZE);
    sha384_update(&ctx, data, data_len);
    sha384_final(&ctx, tk);

    sha384_init(&ctx);
    sha384_update(&ctx, k_opad, SHA384_BLOCK_SIZE);
    sha384_update(&ctx, tk, SHA384_DIGEST_SIZE);
    sha384_final(&ctx, mac);
}
