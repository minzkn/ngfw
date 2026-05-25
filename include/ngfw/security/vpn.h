/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_SECURITY_VPN_H
#define NGFW_SECURITY_VPN_H

#include "ngfw/types.h"
#include "ngfw/network/packet.h"
#include "ngfw/hash.h"

/*
 * VPN Support
 * IPsec tunnel management with IKEv2
 */

/* VPN types */
typedef enum {
    VPN_TYPE_IPSEC,
    VPN_TYPE_OPENVPN,
    VPN_TYPE_WIREGUARD
} vpn_type_t;

/* VPN states */
typedef enum {
    VPN_STATE_DOWN,
    VPN_STATE_CONNECTING,
    VPN_STATE_UP,
    VPN_STATE_DISCONNECTING
} vpn_state_t;

/* IKEv2 state machine */
typedef enum {
    IKE_STATE_INIT,
    IKE_STATE_SA_INIT,
    IKE_STATE_AUTH,
    IKE_STATE_ESTABLISHED,
    IKE_STATE_REKEYING,
    IKE_STATE_DELETING,
    IKE_STATE_CLOSING,
    IKE_STATE_REKEY
} ike_state_t;

/* IPsec state */
typedef enum {
    IPSEC_STATE_DOWN,
    IPSEC_STATE_ESTABLISHED,
    IPSEC_STATE_EXPIRED
} ipsec_state_t;

/* Encryption algorithms */
typedef enum {
    IPSEC_ENC_NONE,
    IPSEC_ENC_AES_128,
    IPSEC_ENC_AES_256,
    IPSEC_ENC_3DES,
    IPSEC_ENC_DES
} ipsec_enc_t;

/* Authentication algorithms */
typedef enum {
    IPSEC_AUTH_NONE,
    IPSEC_AUTH_MD5,
    IPSEC_AUTH_SHA1,
    IPSEC_AUTH_SHA256,
    IPSEC_AUTH_SHA384,
    IPSEC_AUTH_SHA512
} ipsec_auth_t;

/* DH groups */
typedef enum {
    IPSEC_DH_GROUP_1 = 1,
    IPSEC_DH_GROUP_2 = 2,
    IPSEC_DH_GROUP_5 = 5,
    IPSEC_DH_GROUP_14 = 14,
    IPSEC_DH_GROUP_15 = 15,
    IPSEC_DH_GROUP_16 = 16
} ipsec_dh_t;

/* IPsec protocol */
typedef enum {
    IPSEC_PROTOCOL_AH = 1,
    IPSEC_PROTOCOL_ESP = 2
} ipsec_protocol_t;

/* IPsec mode */
typedef enum {
    IPSEC_MODE_TRANSPORT = 1,
    IPSEC_MODE_TUNNEL = 2
} ipsec_mode_t;

/* IKE version */
typedef enum {
    IKE_VERSION_1 = 1,
    IKE_VERSION_2 = 2
} ike_version_t;

/* IKE proposal */
typedef struct ike_proposal {
    ike_version_t version;
    ipsec_enc_t encryption;
    ipsec_auth_t auth;
    ipsec_dh_t dh_group;
    u32 lifetime;
} ike_proposal_t;

/* IPsec proposal */
typedef struct ipsec_proposal {
    ipsec_protocol_t protocol;
    ipsec_mode_t mode;
    ipsec_enc_t encryption;
    ipsec_auth_t auth;
    ipsec_dh_t dh_group;
    u32 lifetime;
} ipsec_proposal_t;

/* IKE session */
typedef struct ike_session {
    u32 id;
    ike_state_t state;
    u64 initiator_spi;
    u64 responder_spi;
    u8 initiator_nonce[32];
    u8 responder_nonce[32];
    u8 shared_key[64];
    u8 skeyseed[64];
    u64 created;
    u64 last_activity;
    u32 retransmit_count;
    char local_addr[48];
    char remote_addr[48];
    u16 local_port;
    u16 remote_port;
    ike_proposal_t proposal;
} ike_session_t;

/* IPsec Security Association */
typedef struct ipsec_sa {
    u32 id;
    u32 spi;
    u64 seq;
    ipsec_protocol_t protocol;
    ipsec_mode_t mode;
    ipsec_enc_t encryption_alg;
    ipsec_auth_t integrity_alg;
    u8 esp_key[32];
    u8 esp_key_len;
    u8 auth_key[20];
    u8 auth_key_len;
    char src_addr[48];
    char dst_addr[48];
    u64 created;
    u64 expires;
    u64 bytes;
    u64 packets;
    u32 state;
} ipsec_sa_t;

/* VPN tunnel */
typedef struct vpn_tunnel {
    vpn_type_t type;
    char name[64];
    u32 id;
    vpn_state_t state;
    char local_addr[48];
    char remote_addr[48];
    char local_net[48];
    char remote_net[48];
    u32 local_ip;
    u32 remote_ip;
    u32 spi_in;
    u32 spi_out;
    u64 bytes_in;
    u64 bytes_out;
    u64 created;
    u64 established;
    ike_session_t *ike;
    ipsec_sa_t *in_sa;
    ipsec_sa_t *out_sa;
} vpn_tunnel_t;

/* VPN statistics */
typedef struct vpn_stats {
    u64 tunnels_active;
    u64 tunnels_created;
    u64 tunnels_closed;
    u64 packets_encrypted;
    u64 packets_decrypted;
    u64 bytes_encrypted;
    u64 bytes_decrypted;
    u64 ike_sa_created;
    u64 ipsec_sa_created;
    u64 ike_exchanges;
    u64 errors;
} vpn_stats_t;

/* VPN configuration */
typedef struct vpn_tunnel_config {
    char name[64];
    char local_addr[48];
    char remote_addr[48];
    char local_net[48];
    char remote_net[48];
    u32 local_ip;
    u32 remote_ip;
} vpn_tunnel_config_t;

/* Forward declaration - full definition in vpn.c */
typedef struct vpn vpn_t;

/* API */
vpn_t *vpn_create(vpn_type_t type);
void vpn_destroy(vpn_t *vpn);
ngfw_ret_t vpn_init(vpn_t *vpn);
ngfw_ret_t vpn_start(vpn_t *vpn);
ngfw_ret_t vpn_stop(vpn_t *vpn);

ngfw_ret_t vpn_create_tunnel(vpn_t *vpn, const char *name, u32 local_ip, u32 remote_ip);
ngfw_ret_t vpn_create_tunnel_ex(vpn_t *vpn, vpn_tunnel_config_t *config);
ngfw_ret_t vpn_delete_tunnel(vpn_t *vpn, u32 tunnel_id);
ngfw_ret_t vpn_establish_tunnel(vpn_t *vpn, u32 tunnel_id);
ngfw_ret_t vpn_close_tunnel(vpn_t *vpn, u32 tunnel_id);

ngfw_ret_t vpn_encrypt_packet(vpn_t *vpn, u32 tunnel_id, packet_t *pkt);
ngfw_ret_t vpn_decrypt_packet(vpn_t *vpn, u32 tunnel_id, packet_t *pkt);

vpn_stats_t *vpn_get_stats(vpn_t *vpn);
void vpn_reset_stats(vpn_t *vpn);

#endif
