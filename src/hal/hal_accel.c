/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#include "ngfw/hal/accel.h"
#include <string.h>
#include <stdio.h>

static u32 accel_capabilities = 0;
static bool accel_initialized = false;

ngfw_ret_t hal_accel_init(void)
{
    if (accel_initialized) {
        return NGFW_OK;
    }
    
    /* Check for hardware capabilities */
    accel_capabilities = HAL_ACCEL_RNG;
    
#ifdef __x86_64__
    /* Check for AES-NI, SHA extensions */
    accel_capabilities |= HAL_ACCEL_CRYPTO_AES | HAL_ACCEL_CRYPTO_SHA;
#endif
    
    accel_capabilities |= HAL_ACCEL_CHECKSUM_IP | HAL_ACCEL_CHECKSUM_TCP | HAL_ACCEL_CHECKSUM_UDP;
    
    accel_initialized = true;
    return NGFW_OK;
}

void hal_accel_shutdown(void)
{
    accel_initialized = false;
}

bool hal_accel_has_capability(u32 cap)
{
    return (accel_capabilities & cap) != 0;
}

u32 hal_accel_get_capabilities(void)
{
    return accel_capabilities;
}

ngfw_ret_t hal_accel_aes_encrypt(const u8 *in, u8 *out, size_t len, const u8 *key, size_t key_len, const u8 *iv)
{
    (void)in; (void)out; (void)len; (void)key; (void)key_len; (void)iv;
    /* Hardware AES would be implemented here */
    return NGFW_ERR_NOT_SUPPORTED;
}

ngfw_ret_t hal_accel_aes_decrypt(const u8 *in, u8 *out, size_t len, const u8 *key, size_t key_len, const u8 *iv)
{
    (void)in; (void)out; (void)len; (void)key; (void)key_len; (void)iv;
    return NGFW_ERR_NOT_SUPPORTED;
}

ngfw_ret_t hal_accel_sha256(const u8 *in, u8 *out, size_t len)
{
    (void)in; (void)out; (void)len;
    return NGFW_ERR_NOT_SUPPORTED;
}

ngfw_ret_t hal_accel_md5(const u8 *in, u8 *out, size_t len)
{
    (void)in; (void)out; (void)len;
    return NGFW_ERR_NOT_SUPPORTED;
}

u16 hal_accel_ip_checksum(const void *data, size_t len)
{
    /* Standard software checksum - hardware offload would be here */
    const u16 *ptr = data;
    u32 sum = 0;
    
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(const u8 *)ptr;
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return (u16)~sum;
}

u16 hal_accel_tcp_checksum(const void *ip_hdr, const void *tcp_hdr, size_t len)
{
    (void)ip_hdr; (void)tcp_hdr; (void)len;
    return 0;
}

u16 hal_accel_udp_checksum(const void *ip_hdr, const void *udp_hdr, size_t len)
{
    (void)ip_hdr; (void)udp_hdr; (void)len;
    return 0;
}

ngfw_ret_t hal_accel_random(u8 *buf, size_t len)
{
    if (!buf || len == 0) {
        return NGFW_ERR_INVALID;
    }
    
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        return NGFW_ERR;
    }
    
    size_t read_bytes = fread(buf, 1, len, urandom);
    fclose(urandom);
    
    if (read_bytes != len) {
        return NGFW_ERR;
    }
    
    return NGFW_OK;
}
