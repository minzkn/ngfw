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

#ifndef NGFW_HAL_ACCEL_H
#define NGFW_HAL_ACCEL_H

#include "ngfw/types.h"

/*
 * Hardware Acceleration Abstraction Layer
 * Provides access to hardware crypto, checksum offload, etc.
 */

/* Acceleration capabilities */
typedef enum {
    HAL_ACCEL_CRYPTO_AES = (1 << 0),
    HAL_ACCEL_CRYPTO_SHA = (1 << 1),
    HAL_ACCEL_CRYPTO_MD5 = (1 << 2),
    HAL_ACCEL_CHECKSUM_IP = (1 << 3),
    HAL_ACCEL_CHECKSUM_TCP = (1 << 4),
    HAL_ACCEL_CHECKSUM_UDP = (1 << 5),
    HAL_ACCEL_RNG = (1 << 6)
} hal_accel_caps_t;

/* Initialize acceleration subsystem */
ngfw_ret_t hal_accel_init(void);
void hal_accel_shutdown(void);

/* Check capabilities */
bool hal_accel_has_capability(u32 cap);
u32 hal_accel_get_capabilities(void);

/* Crypto operations */
ngfw_ret_t hal_accel_aes_encrypt(const u8 *in, u8 *out, size_t len, const u8 *key, size_t key_len, const u8 *iv);
ngfw_ret_t hal_accel_aes_decrypt(const u8 *in, u8 *out, size_t len, const u8 *key, size_t key_len, const u8 *iv);
ngfw_ret_t hal_accel_sha256(const u8 *in, u8 *out, size_t len);
ngfw_ret_t hal_accel_md5(const u8 *in, u8 *out, size_t len);

/* Checksum offload */
u16 hal_accel_ip_checksum(const void *data, size_t len);
u16 hal_accel_tcp_checksum(const void *ip_hdr, const void *tcp_hdr, size_t len);
u16 hal_accel_udp_checksum(const void *ip_hdr, const void *udp_hdr, size_t len);

/* Random number generation */
ngfw_ret_t hal_accel_random(u8 *buf, size_t len);

/* Forward declaration for hardware acceleration manager */
typedef struct hwaccel hwaccel_t;

#endif
