/*
 * NGFW - VPN Data Plane
 * ESP packet encryption/decryption (AES-CBC/HMAC-SHA256)
 * Copyright (C) 2024 NGFW Project
 */

#include "ngfw/vpn.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include "ngfw/crypto.h"
#include "ngfw/packet.h"
#include "ngfw/hash.h"
#include "ngfw/platform.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define ESP_HEADER_LEN 8
#define ESP_TRAILER_MIN_LEN 3
#define ESP_AUTH_LEN 16

typedef struct esp_header {
    u32 spi;
    u32 seq;
} __attribute__((packed)) esp_header_t;

static u8 generate_padding(u32 payload_len, u8 *pad_len)
{
    u8 align = 4;
    u8 total_len = payload_len + ESP_TRAILER_MIN_LEN;
    u8 pad_needed = (align - (total_len % align)) % align;
    u8 padding = pad_needed > 0 ? pad_needed : align;
    *pad_len = padding;
    return padding;
}

static ngfw_ret_t esp_calculate_icv(const u8 *data, u32 len,
                                     const u8 *auth_key, u32 key_len,
                                     u8 *icv_out)
{
    (void)key_len;
    if (!data || !auth_key || !icv_out) return NGFW_ERR_INVALID;
    
    sha256_context_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, auth_key, key_len);
    sha256_update(&ctx, data, len);
    u8 hash[32];
    sha256_final(&ctx, hash);
    memcpy(icv_out, hash, ESP_AUTH_LEN);
    
    return NGFW_OK;
}

static ngfw_ret_t esp_verify_icv(const u8 *data, u32 len,
                                  const u8 *auth_key, u32 key_len,
                                  const u8 *expected_icv)
{
    u8 calculated[ESP_AUTH_LEN];
    ngfw_ret_t ret = esp_calculate_icv(data, len, auth_key, key_len, calculated);
    if (ret != NGFW_OK) return ret;
    
    if (memcmp(calculated, expected_icv, ESP_AUTH_LEN) != 0) {
        return NGFW_ERR_INTEGRITY;
    }
    
    return NGFW_OK;
}

static ngfw_ret_t esp_encrypt_payload(const u8 *plaintext, u32 pt_len,
                                       const u8 *iv, const u8 *enc_key, u32 key_len,
                                       u8 *ciphertext)
{
    (void)key_len;
    if (!plaintext || !iv || !enc_key || !ciphertext) return NGFW_ERR_INVALID;
    
    aes_context_t ctx;
    aes_setkey(&ctx, enc_key, AES_KEY_256);
    
    u8 feedback[16];
    memcpy(feedback, iv, 16);
    
    u32 i = 0;
    while (i < pt_len) {
        u8 block[16];
        memset(block, 0, 16);
        memcpy(block, plaintext + i, (pt_len - i < 16) ? (pt_len - i) : 16);
        
        for (int j = 0; j < 16; j++) {
            block[j] ^= feedback[j];
        }
        
        aes_encrypt(&ctx, block, ciphertext + i);
        memcpy(feedback, ciphertext + i, 16);
        
        i += 16;
    }
    
    return NGFW_OK;
}

static ngfw_ret_t esp_decrypt_payload(const u8 *ciphertext, u32 ct_len,
                                       const u8 *iv, const u8 *enc_key, u32 key_len,
                                       u8 *plaintext)
{
    (void)key_len;
    if (!ciphertext || !iv || !enc_key || !plaintext) return NGFW_ERR_INVALID;
    
    aes_context_t ctx;
    aes_setkey(&ctx, enc_key, AES_KEY_256);
    
    u8 prev[16];
    memcpy(prev, iv, 16);
    
    u32 i = 0;
    while (i < ct_len) {
        u8 block[16];
        memset(block, 0, 16);
        memcpy(block, ciphertext + i, (ct_len - i < 16) ? (ct_len - i) : 16);
        
        aes_decrypt(&ctx, block, plaintext + i);
        
        for (int j = 0; j < 16; j++) {
            plaintext[i + j] ^= prev[j];
        }
        
        memcpy(prev, ciphertext + i, 16);
        i += 16;
    }
    
    return NGFW_OK;
}

ngfw_ret_t vpn_process_outbound(vpn_tunnel_t *tunnel, packet_t *pkt)
{
    if (!tunnel || !pkt || !tunnel->out_sa) return NGFW_ERR_INVALID;
    
    ipsec_sa_t *sa = tunnel->out_sa;
    if (sa->state != IPSEC_STATE_ESTABLISHED) {
        log_warn("VPN: SA not established for tunnel %s", tunnel->name);
        return NGFW_ERR;
    }
    
    u64 now = get_ms_time();
    if (now > sa->expires) {
        log_warn("VPN: SA expired for tunnel %s", tunnel->name);
        return NGFW_ERR_EXPIRED;
    }
    
    u8 *orig_ip = pkt->data;
    u32 orig_len = pkt->len;
    
    u8 pad_len;
    u8 padding = generate_padding(orig_len, &pad_len);
    
    u32 esp_payload_len = orig_len + padding + 2;
    u32 esp_total_len = ESP_HEADER_LEN + esp_payload_len + ESP_AUTH_LEN;
    
    u8 *new_buf = ngfw_malloc(esp_total_len);
    if (!new_buf) return NGFW_ERR_NO_MEM;
    
    memset(new_buf, 0, esp_total_len);
    
    esp_header_t *esp_hdr = (esp_header_t *)new_buf;
    esp_hdr->spi = htonl(sa->spi);
    esp_hdr->seq = htonl(++sa->packets);
    
    u8 *iv = new_buf + ESP_HEADER_LEN;
    for (u32 i = 0; i < 16; i++) {
        iv[i] = (u8)(rand() & 0xFF);
    }
    
    u8 *payload = new_buf + ESP_HEADER_LEN + 16;
    memcpy(payload, orig_ip, orig_len);
    
    for (u8 i = 0; i < padding; i++) {
        payload[orig_len + i] = i + 1;
    }
    
    payload[orig_len + padding] = padding;
    payload[orig_len + padding + 1] = 4;
    
    u8 *ciphertext = new_buf + ESP_HEADER_LEN;
    ngfw_ret_t ret = esp_encrypt_payload(payload, esp_payload_len,
                                          iv, sa->esp_key, sa->esp_key_len,
                                          ciphertext);
    if (ret != NGFW_OK) {
        ngfw_free(new_buf);
        return ret;
    }
    
    u8 *icv = new_buf + ESP_HEADER_LEN + esp_payload_len;
    ret = esp_calculate_icv(new_buf, ESP_HEADER_LEN + esp_payload_len,
                            sa->auth_key, sa->auth_key_len, icv);
    if (ret != NGFW_OK) {
        ngfw_free(new_buf);
        return ret;
    }
    
    if (pkt->data && pkt->allocated) {
        ngfw_free(pkt->data);
    }
    pkt->data = new_buf;
    pkt->len = esp_total_len;
    pkt->allocated = true;
    pkt->is_esp = true;
    pkt->tunnel_id = tunnel->id;
    
    __sync_fetch_and_add(&sa->bytes, esp_total_len);
    
    log_debug("VPN: Encrypted packet for tunnel %s (len=%u)", tunnel->name, esp_total_len);
    
    return NGFW_OK;
}

ngfw_ret_t vpn_process_inbound(vpn_t *vpn, packet_t *pkt)
{
    if (!vpn || !pkt) return NGFW_ERR_INVALID;
    
    if (!pkt->is_esp) {
        return NGFW_OK;
    }
    
    /* TODO: Full implementation requires vpn_t internals access */
    /* For now, just acknowledge ESP packet processing */
    log_debug("VPN: Inbound ESP packet (len=%u)", pkt->len);
    
    return NGFW_OK;
}

bool vpn_should_process(vpn_tunnel_t *tunnel, packet_t *pkt)
{
    (void)tunnel;
    (void)pkt;
    return false;
}

ngfw_ret_t vpn_process_packet(vpn_t *vpn, packet_t *pkt)
{
    if (!vpn || !pkt) return NGFW_ERR_INVALID;
    
    if (pkt->is_esp) {
        return vpn_process_inbound(vpn, pkt);
    }
    
    return NGFW_OK;
}
