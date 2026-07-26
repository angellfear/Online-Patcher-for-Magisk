#pragma once
#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t state[5];
    uint64_t count;
    unsigned char buffer[64];
} SHA1_CTX;

static uint32_t sha1_rol(uint32_t v, int b) { return (v << b) | (v >> (32 - b)); }

static void sha1_transform(uint32_t state[5], const unsigned char buffer[64]) {
    uint32_t a, b, c, d, e, w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)buffer[i*4] << 24) | ((uint32_t)buffer[i*4+1] << 16) |
               ((uint32_t)buffer[i*4+2] << 8) | ((uint32_t)buffer[i*4+3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = sha1_rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }
    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        uint32_t temp = sha1_rol(a, 5) + f + e + k + w[i];
        e = d; d = c; c = sha1_rol(b, 30); b = a; a = temp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void sha1_init(SHA1_CTX *ctx) {
    ctx->state[0] = 0x67452301; ctx->state[1] = 0xEFCDAB89; ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476; ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

static void sha1_update(SHA1_CTX *ctx, const unsigned char *data, size_t len) {
    size_t i, j = (size_t)(ctx->count & 63);
    ctx->count += len;
    for (i = 0; i < len; i++) {
        ctx->buffer[j++] = data[i];
        if (j == 64) {
            sha1_transform(ctx->state, ctx->buffer);
            j = 0;
        }
    }
}

static void sha1_final(SHA1_CTX *ctx, unsigned char digest[20]) {
    unsigned char finalcount[8];
    uint64_t bits = ctx->count * 8;
    for (int i = 0; i < 8; i++) finalcount[i] = (unsigned char)(bits >> (56 - i * 8));

    unsigned char pad = 0x80;
    sha1_update(ctx, &pad, 1);
    unsigned char zero = 0;
    while ((ctx->count & 63) != 56) sha1_update(ctx, &zero, 1);
    sha1_update(ctx, finalcount, 8);

    for (int i = 0; i < 20; i++) {
        digest[i] = (unsigned char)(ctx->state[i/4] >> (24 - (i % 4) * 8));
    }
}

static void sha1_buf(const unsigned char *data, size_t len, unsigned char out[20]) {
    SHA1_CTX ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, out);
}
