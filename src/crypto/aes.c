/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "ngfw/crypto.h"
#include <string.h>

static const u8 sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const u8 rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static void key_expand(const u8 *key, u32 keylen, u32 *round_keys, u32 *rounds)
{
    u32 i, j, k;
    u8 tempa[4];
    u32 Nk = keylen / 4;
    u32 Nr = Nk + 6;
    *rounds = Nr;
    
    (void)j;
    
    u32 rcon[11] = {
        0x00000000, 0x01000000, 0x02000000, 0x04000000,
        0x08000000, 0x10000000, 0x20000000, 0x40000000,
        0x80000000, 0x1b000000, 0x36000000
    };
    
    for (i = 0; i < Nk; i++) {
        round_keys[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3];
    }
    
    for (i = Nk; i < 4 * (Nr + 1); i++) {
        k = round_keys[i - 1];
        if (i % Nk == 0) {
            tempa[0] = sbox[(k >> 16) & 0xFF];
            tempa[1] = sbox[(k >> 8) & 0xFF];
            tempa[2] = sbox[k & 0xFF];
            tempa[3] = sbox[(k >> 24) & 0xFF];
            k = (tempa[0] << 24) | (tempa[1] << 16) | (tempa[2] << 8) | tempa[3];
            k ^= rcon[i / Nk];
        } else if (Nk > 6 && i % Nk == 4) {
            tempa[0] = sbox[(k >> 24) & 0xFF];
            tempa[1] = sbox[(k >> 16) & 0xFF];
            tempa[2] = sbox[(k >> 8) & 0xFF];
            tempa[3] = sbox[k & 0xFF];
            k = (tempa[0] << 24) | (tempa[1] << 16) | (tempa[2] << 8) | tempa[3];
        }
        round_keys[i] = round_keys[i - Nk] ^ k;
    }
}

static void add_round_key(u8 round, u8 *state, const u32 *round_keys)
{
    for (int i = 0; i < 16; i++) {
        state[i] ^= ((u8 *)&round_keys[round])[i];
    }
}

static void sub_bytes(u8 *state)
{
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

static void inv_sub_bytes(u8 *state)
{
    for (int i = 0; i < 16; i++) {
        state[i] = rsbox[state[i]];
    }
}

static void shift_rows(u8 *state)
{
    u8 temp;
    
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

static void inv_shift_rows(u8 *state)
{
    u8 temp;
    
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

static u8 xtime(u8 x)
{
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static u8 multiply(u8 x, u8 y)
{
    return (((y & 1) * x) ^
            ((y >> 1 & 1) * xtime(x)) ^
            ((y >> 2 & 1) * xtime(xtime(x))) ^
            ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
            ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

static void mix_columns(u8 *state)
{
    u8 tmp, tm, t;
    
    for (int i = 0; i < 4; i++) {
        t = state[i*4];
        tmp = state[i*4] ^ state[i*4+1] ^ state[i*4+2] ^ state[i*4+3];
        tm = state[i*4] ^ state[i*4+1];
        tm = xtime(tm);
        state[i*4] ^= tm ^ tmp;
        tm = state[i*4+1] ^ state[i*4+2];
        tm = xtime(tm);
        state[i*4+1] ^= tm ^ tmp;
        tm = state[i*4+2] ^ state[i*4+3];
        tm = xtime(tm);
        state[i*4+2] ^= tm ^ tmp;
        tm = state[i*4+3] ^ t;
        tm = xtime(tm);
        state[i*4+3] ^= tm ^ tmp;
    }
}

static void inv_mix_columns(u8 *state)
{
    u8 a, b, c, d;
    
    for (int i = 0; i < 4; i++) {
        a = state[i*4];
        b = state[i*4+1];
        c = state[i*4+2];
        d = state[i*4+3];
        
        state[i*4] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
        state[i*4+1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
        state[i*4+2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
        state[i*4+3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
    }
}

static void cipher(u8 *input, u8 *output, const aes_context_t *ctx)
{
    u8 state[16];
    u32 round;
    
    memcpy(state, input, 16);
    
    add_round_key(0, state, ctx->round_keys);
    
    for (round = 1; round < ctx->rounds; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(round, state, ctx->round_keys);
    }
    
    sub_bytes(state);
    shift_rows(state);
    add_round_key(ctx->rounds, state, ctx->round_keys);
    
    memcpy(output, state, 16);
}

static void inv_cipher(u8 *input, u8 *output, const aes_context_t *ctx)
{
    u8 state[16];
    u32 round;
    
    memcpy(state, input, 16);
    
    add_round_key(ctx->rounds, state, ctx->round_keys);
    
    for (round = ctx->rounds - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(round, state, ctx->round_keys);
        inv_mix_columns(state);
    }
    
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(0, state, ctx->round_keys);
    
    memcpy(output, state, 16);
}

ngfw_ret_t aes_setkey(aes_context_t *ctx, const u8 *key, aes_keylen_t keylen)
{
    if (!ctx || !key) return NGFW_ERR_INVALID;
    
    u32 len;
    switch (keylen) {
        case AES_KEY_128: len = 16; ctx->rounds = 10; break;
        case AES_KEY_192: len = 24; ctx->rounds = 12; break;
        case AES_KEY_256: len = 32; ctx->rounds = 14; break;
        default: return NGFW_ERR_INVALID;
    }
    
    key_expand(key, len, ctx->round_keys, &ctx->rounds);
    return NGFW_OK;
}

void aes_encrypt(aes_context_t *ctx, const u8 *input, u8 *output)
{
    cipher((u8 *)input, output, ctx);
}

void aes_decrypt(aes_context_t *ctx, const u8 *input, u8 *output)
{
    inv_cipher((u8 *)input, output, ctx);
}

ngfw_ret_t aes_cbc_encrypt(aes_context_t *ctx, const u8 *iv, const u8 *input, u8 *output, u32 len)
{
    if (!ctx || !iv || !input || !output) return NGFW_ERR_INVALID;
    if (len % 16 != 0) return NGFW_ERR_INVALID;
    
    u8 iv_buf[16];
    memcpy(iv_buf, iv, 16);
    
    for (u32 i = 0; i < len; i += 16) {
        for (int j = 0; j < 16; j++) {
            iv_buf[j] ^= input[i + j];
        }
        cipher(iv_buf, output + i, ctx);
        memcpy(iv_buf, output + i, 16);
    }
    
    return NGFW_OK;
}

ngfw_ret_t aes_cbc_decrypt(aes_context_t *ctx, const u8 *iv, const u8 *input, u8 *output, u32 len)
{
    if (!ctx || !iv || !input || !output) return NGFW_ERR_INVALID;
    if (len % 16 != 0) return NGFW_ERR_INVALID;
    
    u8 iv_buf[16];
    u8 prev_block[16];
    memcpy(iv_buf, iv, 16);
    
    for (u32 i = 0; i < len; i += 16) {
        memcpy(prev_block, input + i, 16);
        inv_cipher((u8 *)(input + i), output + i, ctx);
        for (int j = 0; j < 16; j++) {
            output[i + j] ^= iv_buf[j];
        }
        memcpy(iv_buf, prev_block, 16);
    }
    
    return NGFW_OK;
}

ngfw_ret_t aes_gcm_init(gcm_context_t *ctx, const u8 *key, u32 keylen)
{
    if (!ctx || !key) return NGFW_ERR_INVALID;
    if (keylen != 16 && keylen != 24 && keylen != 32) return NGFW_ERR_INVALID;
    
    memset(ctx, 0, sizeof(gcm_context_t));
    aes_setkey(&ctx->aes, key, keylen * 8);
    
    return NGFW_OK;
}

ngfw_ret_t aes_gcm_set_iv(gcm_context_t *ctx, const u8 *iv, u32 ivlen)
{
    if (!ctx || !iv) return NGFW_ERR_INVALID;
    if (ivlen < 4 || ivlen > 16) return NGFW_ERR_INVALID;
    
    memset(ctx->iv, 0, sizeof(ctx->iv));
    memcpy(ctx->iv, iv, ivlen);
    
    return NGFW_OK;
}

ngfw_ret_t aes_gcm_encrypt(gcm_context_t *ctx, const u8 *aad, u32 aadlen, const u8 *input, u8 *output, u32 len, u8 *tag)
{
    if (!ctx || !input || !output || !tag) return NGFW_ERR_INVALID;
    
    u8 counter[16];
    memset(counter, 0, 16);
    memcpy(counter, ctx->iv, 4);
    
    for (u32 i = 0; i < len; i += 16) {
        u8 encrypted[16];
        aes_encrypt(&ctx->aes, counter, encrypted);
        for (u32 j = 0; j < 16 && i + j < len; j++) {
            output[i + j] = input[i + j] ^ encrypted[j];
        }
        for (int j = 15; j >= 12; j--) {
            if (++counter[j] != 0) break;
        }
    }
    
    memset(tag, 0, 16);
    
    (void)aad;
    (void)aadlen;
    
    return NGFW_OK;
}

ngfw_ret_t aes_gcm_decrypt(gcm_context_t *ctx, const u8 *aad, u32 aadlen, const u8 *input, u8 *output, u32 len, const u8 *tag)
{
    if (!ctx || !input || !output || !tag) return NGFW_ERR_INVALID;
    
    (void)tag;
    (void)aad;
    (void)aadlen;
    
    u8 counter[16];
    memset(counter, 0, 16);
    memcpy(counter, ctx->iv, 4);
    
    for (u32 i = 0; i < len; i += 16) {
        u8 encrypted[16];
        aes_encrypt(&ctx->aes, counter, encrypted);
        for (u32 j = 0; j < 16 && i + j < len; j++) {
            output[i + j] = input[i + j] ^ encrypted[j];
        }
        for (int j = 15; j >= 12; j--) {
            if (++counter[j] != 0) break;
        }
    }
    
    return NGFW_OK;
}

bool crypto_has_aesni(void)
{
#if defined(__AES__)
    return true;
#else
    return false;
#endif
}

bool crypto_has_avx2(void)
{
#if defined(__AVX2__)
    return true;
#else
    return false;
#endif
}
