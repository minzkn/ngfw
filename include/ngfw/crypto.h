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

#ifndef NGFW_CRYPTO_H
#define NGFW_CRYPTO_H

#include "types.h"

typedef enum {
    CRYPTO_MODE_ECB,
    CRYPTO_MODE_CBC,
    CRYPTO_MODE_CTR,
    CRYPTO_MODE_GCM,
    CRYPTO_MODE_XTS
} crypto_mode_t;

typedef enum {
    AES_KEY_128,
    AES_KEY_192,
    AES_KEY_256
} aes_keylen_t;

typedef struct aes_context {
    u32 round_keys[60];
    u32 rounds;
} aes_context_t;

typedef struct gcm_context {
    aes_context_t aes;
    u64 htable[16];
    u32 iv[4];
    u32 tag[4];
} gcm_context_t;

ngfw_ret_t aes_setkey(aes_context_t *ctx, const u8 *key, aes_keylen_t keylen);
void aes_encrypt(aes_context_t *ctx, const u8 *input, u8 *output);
void aes_decrypt(aes_context_t *ctx, const u8 *input, u8 *output);
ngfw_ret_t aes_cbc_encrypt(aes_context_t *ctx, const u8 *iv, const u8 *input, u8 *output, u32 len);
ngfw_ret_t aes_cbc_decrypt(aes_context_t *ctx, const u8 *iv, const u8 *input, u8 *output, u32 len);
ngfw_ret_t aes_gcm_init(gcm_context_t *ctx, const u8 *key, u32 keylen);
ngfw_ret_t aes_gcm_set_iv(gcm_context_t *ctx, const u8 *iv, u32 ivlen);
ngfw_ret_t aes_gcm_encrypt(gcm_context_t *ctx, const u8 *aad, u32 aadlen, const u8 *input, u8 *output, u32 len, u8 *tag);
ngfw_ret_t aes_gcm_decrypt(gcm_context_t *ctx, const u8 *aad, u32 aadlen, const u8 *input, u8 *output, u32 len, const u8 *tag);

typedef struct sha256_context {
    u32 state[8];
    u64 bitcount;
    u8 buffer[64];
} sha256_context_t;

void sha256_init(sha256_context_t *ctx);
void sha256_update(sha256_context_t *ctx, const u8 *data, u32 len);
void sha256_final(sha256_context_t *ctx, u8 *digest);
void sha256(const u8 *data, u32 len, u8 *digest);

typedef struct md5_context {
    u32 state[4];
    u64 bitcount;
    u8 buffer[64];
} md5_context_t;

void md5_init(md5_context_t *ctx);
void md5_update(md5_context_t *ctx, const u8 *data, u32 len);
void md5_final(md5_context_t *ctx, u8 *digest);
void md5(const u8 *data, u32 len, u8 *digest);

void random_bytes(u8 *buf, u32 len);
u32 random_u32(void);
u64 random_u64(void);

u32 crc32(const u8 *data, u32 len);

bool crypto_has_aesni(void);
bool crypto_has_avx2(void);

#endif
