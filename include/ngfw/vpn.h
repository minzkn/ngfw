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

#ifndef NGFW_VPN_H
#define NGFW_VPN_H

#include "types.h"

typedef enum {
    VPN_TYPE_NONE,
    VPN_TYPE_IPSEC,
    VPN_TYPE_OPENVPN,
    VPN_TYPE_WIREGUARD
} vpn_type_t;

typedef enum {
    IPSEC_MODE_TUNNEL,
    IPSEC_MODE_TRANSPORT
} ipsec_mode_t;

typedef enum {
    IPSEC_PROTOCOL_ESP,
    IPSEC_PROTOCOL_AH
} ipsec_protocol_t;

typedef enum {
    IPSEC_ENC_AES_128,
    IPSEC_ENC_AES_192,
    IPSEC_ENC_AES_256,
    IPSEC_ENC_3DES,
    IPSEC_ENC_DES
} ipsec_encryption_t;

typedef enum {
    IPSEC_AUTH_SHA1,
    IPSEC_AUTH_SHA256,
    IPSEC_AUTH_SHA384,
    IPSEC_AUTH_MD5
} ipsec_auth_t;

typedef enum {
    IPSEC_DH_GROUP_1,
    IPSEC_DH_GROUP_2,
    IPSEC_DH_GROUP_5,
    IPSEC_DH_GROUP_14,
    IPSEC_DH_GROUP_15,
    IPSEC_DH_GROUP_16,
    IPSEC_DH_GROUP_17,
    IPSEC_DH_GROUP_18
} ipsec_dh_group_t;

typedef enum {
    IKE_VERSION_1,
    IKE_VERSION_2
} ike_version_t;

typedef enum {
    IKE_STATE_INIT,
    IKE_STATE_AUTH,
    IKE_STATE_ESTABLISHED,
    IKE_STATE_REKEY,
    IKE_STATE_CLOSING
} ike_state_t;

typedef enum {
    IPSEC_STATE_INIT,
    IPSEC_STATE_KEYING,
    IPSEC_STATE_ESTABLISHED,
    IPSEC_STATE_EXPIRED
} ipsec_sa_state_t;

typedef struct ike_proposal {
    ike_version_t version;
    ipsec_encryption_t encryption;
    ipsec_auth_t auth;
    ipsec_dh_group_t dh_group;
    u32 lifetime;
} ike_proposal_t;

typedef struct ipsec_proposal {
    ipsec_protocol_t protocol;
    ipsec_mode_t mode;
    ipsec_encryption_t encryption;
    ipsec_auth_t auth;
    ipsec_dh_group_t dh_group;
    u32 lifetime;
    u32 spi_in;
    u32 spi_out;
} ipsec_proposal_t;

typedef struct ike_session {
    u32 id;
    char local_addr[64];
    char remote_addr[64];
    u16 local_port;
    u16 remote_port;
    char local_id[256];
    char remote_id[256];
    ike_proposal_t proposal;
    ike_state_t state;
    u64 created;
    u64 last_exchange;
    u8 nonce_i[256];
    u8 nonce_r[256];
    u8 skeyid[32];
    u8 skeyid_d[32];
    u8 skeyid_a[32];
    u8 skeyid_e[32];
} ike_session_t;

typedef struct ipsec_sa {
    u32 id;
    u32 spi;
    ipsec_protocol_t protocol;
    ipsec_mode_t mode;
    char src_addr[64];
    char dst_addr[64];
    ipsec_proposal_t proposal;
    ipsec_sa_state_t state;
    u8 esp_key[32];
    u32 esp_key_len;
    u8 auth_key[32];
    u32 auth_key_len;
    u64 created;
    u64 expires;
    u64 bytes;
    u64 packets;
} ipsec_sa_t;

typedef struct vpn_tunnel {
    u32 id;
    char name[64];
    vpn_type_t type;
    char local_addr[64];
    char remote_addr[64];
    char local_net[64];
    char remote_net[64];
    ike_session_t *ike;
    ipsec_sa_t *in_sa;
    ipsec_sa_t *out_sa;
    bool established;
    u64 created;
    u64 last_traffic;
    u64 bytes_in;
    u64 bytes_out;
} vpn_tunnel_t;

typedef struct vpn_stats {
    u64 tunnels_active;
    u64 tunnels_created;
    u64 tunnels_closed;
    u64 ike_exchanges;
    u64 esp_packets_in;
    u64 esp_packets_out;
    u64 bytes_encrypted;
    u64 bytes_decrypted;
    u64 packets_dropped;
    u64 auth_failures;
} vpn_stats_t;

typedef struct vpn vpn_t;

vpn_t *vpn_create(vpn_type_t type);
void vpn_destroy(vpn_t *vpn);

ngfw_ret_t vpn_init(vpn_t *vpn);
ngfw_ret_t vpn_start(vpn_t *vpn);
ngfw_ret_t vpn_stop(vpn_t *vpn);

ngfw_ret_t vpn_tunnel_create(vpn_t *vpn, vpn_tunnel_t *config, vpn_tunnel_t **tunnel);
ngfw_ret_t vpn_tunnel_destroy(vpn_t *vpn, u32 tunnel_id);
ngfw_ret_t vpn_tunnel_establish(vpn_t *vpn, vpn_tunnel_t *tunnel);
ngfw_ret_t vpn_tunnel_close(vpn_t *vpn, vpn_tunnel_t *tunnel);

ngfw_ret_t vpn_add_ike_proposal(vpn_t *vpn, ike_proposal_t *proposal);
ngfw_ret_t vpn_add_ipsec_proposal(vpn_t *vpn, ipsec_proposal_t *proposal);

vpn_stats_t *vpn_get_stats(vpn_t *vpn);
void vpn_reset_stats(vpn_t *vpn);

ngfw_ret_t vpn_set_psk(vpn_t *vpn, const char *psk);
ngfw_ret_t vpn_set_certificate(vpn_t *vpn, const char *cert, const char *key);

#endif
