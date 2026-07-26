#pragma once
// Minimal big-integer support: only what's needed for RSA-2048 sign
// (modexp with a fixed embedded private key). Big-endian byte arrays in,
// big-endian byte arrays out. Not constant-time; used once at boot.
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define BN_MAX_BYTES 512  /* 4096 bits, enough for 2048-bit modulus products */

typedef struct {
    unsigned char d[BN_MAX_BYTES];
    int len; /* significant bytes, d[0] is most significant of the used tail */
} bn_t;

static void bn_from_bytes(bn_t *r, const unsigned char *bytes, int len) {
    memset(r->d, 0, BN_MAX_BYTES);
    if (len > BN_MAX_BYTES) len = BN_MAX_BYTES;
    memcpy(r->d + (BN_MAX_BYTES - len), bytes, len);
    r->len = BN_MAX_BYTES;
}

static int bn_is_zero(const bn_t *a) {
    for (int i = 0; i < BN_MAX_BYTES; i++) if (a->d[i]) return 0;
    return 1;
}

/* compare full BN_MAX_BYTES arrays */
static int bn_cmp(const bn_t *a, const bn_t *b) {
    return memcmp(a->d, b->d, BN_MAX_BYTES);
}

static void bn_sub_inplace(bn_t *a, const bn_t *b) {
    int borrow = 0;
    for (int i = BN_MAX_BYTES - 1; i >= 0; i--) {
        int v = (int)a->d[i] - (int)b->d[i] - borrow;
        if (v < 0) { v += 256; borrow = 1; } else borrow = 0;
        a->d[i] = (unsigned char)v;
    }
}

static void bn_shl1(bn_t *a) {
    int carry = 0;
    for (int i = BN_MAX_BYTES - 1; i >= 0; i--) {
        int v = (a->d[i] << 1) | carry;
        carry = (v >> 8) & 1;
        a->d[i] = (unsigned char)v;
    }
}

static int bn_get_bit(const bn_t *a, int bitpos) {
    int byte = BN_MAX_BYTES - 1 - bitpos / 8;
    if (byte < 0) return 0;
    return (a->d[byte] >> (bitpos % 8)) & 1;
}

static int bn_bit_length(const bn_t *a) {
    for (int i = 0; i < BN_MAX_BYTES; i++) {
        if (a->d[i]) {
            int bits = (BN_MAX_BYTES - i) * 8;
            unsigned char v = a->d[i];
            int lead = 0;
            while (!(v & 0x80)) { v <<= 1; lead++; }
            return bits - lead;
        }
    }
    return 0;
}

/* r = (a * b) mod m, all as bn_t with full BN_MAX_BYTES width.
   Schoolbook double-width multiply (little-endian accumulator) then
   bit-serial reduction against m. Not fast, but correct and dependency-free;
   runs once at boot per patch cycle. */
static void bn_mulmod(const bn_t *a, const bn_t *b, const bn_t *m, bn_t *r) {
    static uint32_t prod[BN_MAX_BYTES * 2];
    memset(prod, 0, sizeof(prod));

    for (int i = 0; i < BN_MAX_BYTES; i++) {
        unsigned char av = a->d[BN_MAX_BYTES - 1 - i];
        if (av == 0) continue;
        uint32_t carry = 0;
        for (int j = 0; j < BN_MAX_BYTES; j++) {
            unsigned char bv = b->d[BN_MAX_BYTES - 1 - j];
            uint32_t val = prod[i + j] + (uint32_t)av * (uint32_t)bv + carry;
            prod[i + j] = val & 0xff;
            carry = val >> 8;
        }
        int k = i + BN_MAX_BYTES;
        while (carry && k < BN_MAX_BYTES * 2) {
            uint32_t val = prod[k] + carry;
            prod[k] = val & 0xff;
            carry = val >> 8;
            k++;
        }
    }

    static unsigned char prodBytes[BN_MAX_BYTES * 2];
    for (int i = 0; i < BN_MAX_BYTES * 2; i++) {
        prodBytes[BN_MAX_BYTES * 2 - 1 - i] = (unsigned char)prod[i];
    }

    bn_t rem;
    memset(rem.d, 0, BN_MAX_BYTES);
    int total_bits = BN_MAX_BYTES * 2 * 8;
    for (int bitpos = 0; bitpos < total_bits; bitpos++) {
        int byte_idx = bitpos / 8;
        int bit_in_byte = 7 - (bitpos % 8);
        int bit = (prodBytes[byte_idx] >> bit_in_byte) & 1;

        bn_shl1(&rem);
        rem.d[BN_MAX_BYTES - 1] |= (unsigned char)bit;

        if (bn_cmp(&rem, m) >= 0) {
            bn_sub_inplace(&rem, m);
        }
    }

    memcpy(r->d, rem.d, BN_MAX_BYTES);
}

/* r = base^exp mod m */
static void bn_modexp(const bn_t *base, const bn_t *exp, const bn_t *m, bn_t *r) {
    bn_t result, b;
    memset(result.d, 0, BN_MAX_BYTES);
    result.d[BN_MAX_BYTES - 1] = 1; /* result = 1 */

    /* reduce base mod m first */
    bn_t base_r;
    {
        bn_t one;
        memset(one.d, 0, BN_MAX_BYTES);
        one.d[BN_MAX_BYTES - 1] = 1;
        bn_mulmod(base, &one, m, &base_r);
    }
    memcpy(b.d, base_r.d, BN_MAX_BYTES);

    int bits = bn_bit_length(exp);
    for (int i = 0; i < bits; i++) {
        if (bn_get_bit(exp, i)) {
            bn_t tmp;
            bn_mulmod(&result, &b, m, &tmp);
            memcpy(result.d, tmp.d, BN_MAX_BYTES);
        }
        bn_t sq;
        bn_mulmod(&b, &b, m, &sq);
        memcpy(b.d, sq.d, BN_MAX_BYTES);
    }

    memcpy(r->d, result.d, BN_MAX_BYTES);
}
