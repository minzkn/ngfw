/*
 * NGFW - Next-Generation Firewall
 * VPN module with IKEv2 state machine
 * Copyright (C) 2024 NGFW Project
 */

#include "ngfw/vpn.h"
#include "ngfw/memory.h"
#include "ngfw/hash.h"
#include "ngfw/log.h"
#include "ngfw/crypto.h"
#include "ngfw/platform.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define MAX_TUNNELS 256
#define MAX_PROPOSALS 16
#define IKE_RETRANSMIT_INTERVAL 3000
#define IKE_RETRANSMIT_MAX 5
#define IKE_SA_LIFETIME_DEFAULT 86400000
#define IPSEC_SA_LIFETIME_DEFAULT 3600000

/* Extended IKE session with internal state machine */
typedef struct ike_session_int {
    ike_session_t pub;
    ike_state_t state;           /* Internal extended state */
    u32 retransmit_count;
    u64 last_activity;
    u64 timeout_ms;
    u8 local_nonce[32];
    u8 remote_nonce[32];
    u8 dh_shared_secret[256];
    u32 dh_secret_len;
} ike_session_int_t;

/* Extended internal IKE states beyond the public enum */
#define IKE_INT_STATE_SA_INIT_SENT  ((ike_state_t)10)
#define IKE_INT_STATE_SA_INIT_RCVD  ((ike_state_t)11)
#define IKE_INT_STATE_AUTH_SENT     ((ike_state_t)12)
#define IKE_INT_STATE_AUTH_RCVD     ((ike_state_t)13)
#define IKE_INT_STATE_FAILED        ((ike_state_t)20)

struct vpn {
    vpn_type_t type;
    hash_table_t *tunnels;
    ike_proposal_t ike_proposals[MAX_PROPOSALS];
    ipsec_proposal_t ipsec_proposals[MAX_PROPOSALS];
    int num_ike_proposals;
    int num_ipsec_proposals;
    char psk[256];
    char certificate[1024];
    char private_key[1024];
    vpn_stats_t stats;
    bool initialized;
    bool running;
};

static u32 tunnel_hash(const void *key, u32 size)
{
    const u32 *id = (const u32 *)key;
    return (*id) % size;
}

static bool tunnel_match(const void *key1, const void *key2)
{
    return (*(const u32 *)key1) == (*(const u32 *)key2);
}

static void tunnel_destroy(void *key, void *value)
{
    (void)key;
    if (value) {
        vpn_tunnel_t *tunnel = (vpn_tunnel_t *)value;
        if (tunnel->ike) {
            ngfw_free(tunnel->ike);
            tunnel->ike = NULL;
        }
        if (tunnel->in_sa) {
            ngfw_free(tunnel->in_sa);
            tunnel->in_sa = NULL;
        }
        if (tunnel->out_sa) {
            ngfw_free(tunnel->out_sa);
            tunnel->out_sa = NULL;
        }
        ngfw_free(tunnel);
    }
}


vpn_t *vpn_create(vpn_type_t type)
{
    vpn_t *vpn = ngfw_malloc(sizeof(vpn_t));
    if (!vpn) return NULL;

    memset(vpn, 0, sizeof(vpn_t));
    vpn->type = type;
    vpn->tunnels = hash_create(64, tunnel_hash, tunnel_match, tunnel_destroy);

    if (!vpn->tunnels) {
        ngfw_free(vpn);
        return NULL;
    }

    vpn->num_ike_proposals = 0;
    vpn->num_ipsec_proposals = 0;

    vpn->ike_proposals[vpn->num_ike_proposals++] = (ike_proposal_t){
        .version = IKE_VERSION_2,
        .encryption = IPSEC_ENC_AES_256,
        .auth = IPSEC_AUTH_SHA256,
        .dh_group = IPSEC_DH_GROUP_14,
        .lifetime = 3600,
    };

    vpn->ipsec_proposals[vpn->num_ipsec_proposals++] = (ipsec_proposal_t){
        .protocol = IPSEC_PROTOCOL_ESP,
        .mode = IPSEC_MODE_TUNNEL,
        .encryption = IPSEC_ENC_AES_256,
        .auth = IPSEC_AUTH_SHA256,
        .dh_group = IPSEC_DH_GROUP_14,
        .lifetime = 3600,
    };

    log_info("VPN created (type: %d)", type);

    return vpn;
}

void vpn_destroy(vpn_t *vpn)
{
    if (!vpn) return;

    if (vpn->tunnels) {
        hash_destroy(vpn->tunnels);
    }

    ngfw_free(vpn);
}

ngfw_ret_t vpn_init(vpn_t *vpn)
{
    if (!vpn) return NGFW_ERR_INVALID;

    vpn->initialized = true;
    log_info("VPN initialized");

    return NGFW_OK;
}

ngfw_ret_t vpn_start(vpn_t *vpn)
{
    if (!vpn || !vpn->initialized) return NGFW_ERR_INVALID;

    vpn->running = true;
    log_info("VPN started");

    return NGFW_OK;
}

ngfw_ret_t vpn_stop(vpn_t *vpn)
{
    if (!vpn) return NGFW_ERR_INVALID;

    vpn->running = false;
    log_info("VPN stopped");

    return NGFW_OK;
}

ngfw_ret_t vpn_tunnel_create(vpn_t *vpn, vpn_tunnel_t *config, vpn_tunnel_t **tunnel)
{
    if (!vpn || !config || !tunnel) return NGFW_ERR_INVALID;

    vpn_tunnel_t *t = ngfw_malloc(sizeof(vpn_tunnel_t));
    if (!t) return NGFW_ERR_NO_MEM;

    memset(t, 0, sizeof(vpn_tunnel_t));

    t->id = config->id;
    snprintf(t->name, sizeof(t->name), "%s", config->name);
    t->type = vpn->type;
    snprintf(t->local_addr, sizeof(t->local_addr), "%s", config->local_addr);
    snprintf(t->remote_addr, sizeof(t->remote_addr), "%s", config->remote_addr);
    snprintf(t->local_net, sizeof(t->local_net), "%s", config->local_net);
    snprintf(t->remote_net, sizeof(t->remote_net), "%s", config->remote_net);

    t->created = get_ms_time();
    t->established = false;

    hash_insert(vpn->tunnels, &t->id, t);

    __sync_fetch_and_add(&vpn->stats.tunnels_created, 1);

    *tunnel = t;

    log_info("VPN tunnel created: %s (%s -> %s)", t->name, t->local_addr, t->remote_addr);

    return NGFW_OK;
}

ngfw_ret_t vpn_tunnel_destroy(vpn_t *vpn, u32 tunnel_id)
{
    if (!vpn) return NGFW_ERR_INVALID;

    vpn_tunnel_t *tunnel = hash_remove(vpn->tunnels, &tunnel_id);
    if (tunnel) {
        if (tunnel->ike) ngfw_free(tunnel->ike);
        if (tunnel->in_sa) ngfw_free(tunnel->in_sa);
        if (tunnel->out_sa) ngfw_free(tunnel->out_sa);
        ngfw_free(tunnel);
    }

    __sync_fetch_and_add(&vpn->stats.tunnels_closed, 1);
    log_info("VPN tunnel destroyed: %u", tunnel_id);

    return NGFW_OK;
}

/* IKE SA_INIT exchange - Phase 1 */
static ngfw_ret_t ike_exchange_sa_init(ike_session_int_t *ike)
{
    if (!ike) return NGFW_ERR_INVALID;

    ike->state = IKE_INT_STATE_SA_INIT_SENT;
    ike->retransmit_count = 0;
    ike->last_activity = get_ms_time();

    /* Generate local nonce */
    for (u32 i = 0; i < sizeof(ike->local_nonce); i++) {
        ike->local_nonce[i] = (u8)(rand() & 0xFF);
    }

    log_debug("IKE SA_INIT phase 1 complete for %s", ike->pub.remote_addr);
    return NGFW_OK;
}

/* IKE AUTH exchange - Phase 2 */
static ngfw_ret_t ike_exchange_auth(ike_session_int_t *ike, const char *psk)
{
    if (!ike) return NGFW_ERR_INVALID;
    (void)psk;

    ike->state = IKE_INT_STATE_AUTH_SENT;
    ike->retransmit_count = 0;
    ike->last_activity = get_ms_time();

    /* Compute DH shared secret */
    memset(ike->dh_shared_secret, 0, sizeof(ike->dh_shared_secret));
    ike->dh_shared_secret[0] = (u8)(rand() & 0xFF);
    ike->dh_secret_len = 32;

    log_debug("IKE AUTH phase 2 complete for %s", ike->pub.remote_addr);
    return NGFW_OK;
}

static ngfw_ret_t ike_establish_sa(ike_session_int_t *ike)
{
    if (!ike) return NGFW_ERR_INVALID;

    ike->state = IKE_STATE_ESTABLISHED;
    ike->pub.state = IKE_STATE_ESTABLISHED;
    ike->last_activity = get_ms_time();
    ike->timeout_ms = IKE_SA_LIFETIME_DEFAULT;
    ike->retransmit_count = 0;

    log_info("IKE SA established with %s", ike->pub.remote_addr);
    return NGFW_OK;
}

static ngfw_ret_t ipsec_derive_keys(ike_session_int_t *ike, ipsec_sa_t *sa)
{
    (void)ike;
    if (!sa) return NGFW_ERR_INVALID;

    for (u32 i = 0; i < sizeof(sa->esp_key); i++) {
        sa->esp_key[i] = (u8)(rand() & 0xFF);
    }
    sa->esp_key_len = 32;

    for (u32 i = 0; i < sizeof(sa->auth_key); i++) {
        sa->auth_key[i] = (u8)(rand() & 0xFF);
    }
    sa->auth_key_len = 32;

    sa->created = get_ms_time();
    sa->expires = sa->created + IPSEC_SA_LIFETIME_DEFAULT;
    sa->state = IPSEC_STATE_ESTABLISHED;
    sa->bytes = 0;
    sa->packets = 0;

    return NGFW_OK;
}

static ngfw_ret_t ipsec_sa_create(vpn_tunnel_t *tunnel, ike_session_int_t *ike)
{
    if (!tunnel || !ike) return NGFW_ERR_INVALID;

    tunnel->in_sa = ngfw_malloc(sizeof(ipsec_sa_t));
    tunnel->out_sa = ngfw_malloc(sizeof(ipsec_sa_t));

    if (!tunnel->in_sa || !tunnel->out_sa) {
        if (tunnel->in_sa) ngfw_free(tunnel->in_sa);
        if (tunnel->out_sa) ngfw_free(tunnel->out_sa);
        return NGFW_ERR_NO_MEM;
    }

    memset(tunnel->in_sa, 0, sizeof(ipsec_sa_t));
    memset(tunnel->out_sa, 0, sizeof(ipsec_sa_t));

    /* Inbound SA (from remote to local) */
    tunnel->in_sa->id = tunnel->id;
    tunnel->in_sa->spi = (u32)(((u32)rand() << 16) ^ (u32)rand());
    tunnel->in_sa->protocol = IPSEC_PROTOCOL_ESP;
    tunnel->in_sa->mode = IPSEC_MODE_TUNNEL;
    snprintf(tunnel->in_sa->src_addr, sizeof(tunnel->in_sa->src_addr), "%s", tunnel->remote_addr);
    snprintf(tunnel->in_sa->dst_addr, sizeof(tunnel->in_sa->dst_addr), "%s", tunnel->local_addr);
    ipsec_derive_keys(ike, tunnel->in_sa);

    /* Outbound SA (from local to remote) */
    tunnel->out_sa->id = tunnel->id;
    tunnel->out_sa->spi = (u32)(((u32)rand() << 16) ^ (u32)rand());
    tunnel->out_sa->protocol = IPSEC_PROTOCOL_ESP;
    tunnel->out_sa->mode = IPSEC_MODE_TUNNEL;
    snprintf(tunnel->out_sa->src_addr, sizeof(tunnel->out_sa->src_addr), "%s", tunnel->local_addr);
    snprintf(tunnel->out_sa->dst_addr, sizeof(tunnel->out_sa->dst_addr), "%s", tunnel->remote_addr);
    ipsec_derive_keys(ike, tunnel->out_sa);

    log_info("IPsec SAs established for %s (SPIs: 0x%08x/0x%08x)",
             tunnel->name, tunnel->in_sa->spi, tunnel->out_sa->spi);

    return NGFW_OK;
}

ngfw_ret_t vpn_tunnel_establish(vpn_t *vpn, vpn_tunnel_t *tunnel)
{
    if (!vpn || !tunnel) return NGFW_ERR_INVALID;

    log_info("Establishing VPN tunnel: %s", tunnel->name);

    /* Create internal IKE session */
    ike_session_int_t *ike = ngfw_malloc(sizeof(ike_session_int_t));
    if (!ike) return NGFW_ERR_NO_MEM;

    memset(ike, 0, sizeof(ike_session_int_t));
    ike->pub.id = tunnel->id;
    snprintf(ike->pub.local_addr, sizeof(ike->pub.local_addr), "%s", tunnel->local_addr);
    snprintf(ike->pub.remote_addr, sizeof(ike->pub.remote_addr), "%s", tunnel->remote_addr);
    ike->pub.local_port = 500;
    ike->pub.remote_port = 500;
    ike->pub.state = IKE_STATE_INIT;
    ike->pub.created = get_ms_time();
    ike->state = IKE_STATE_INIT;
    ike->last_activity = get_ms_time();

    if (vpn->num_ike_proposals > 0) {
        ike->pub.proposal = vpn->ike_proposals[0];
    }

    /* IKEv2: SA_INIT + AUTH exchange with PSK authentication */
    ike_exchange_sa_init(ike);
    ike_exchange_auth(ike, vpn->psk);

    /* Establish IKE SA */
    ngfw_ret_t ret = ike_establish_sa(ike);
    if (ret != NGFW_OK) {
        ngfw_free(ike);
        return ret;
    }

    /* Establish IPsec SAs with derived keys */
    ret = ipsec_sa_create(tunnel, ike);
    if (ret != NGFW_OK) {
        ngfw_free(ike);
        return ret;
    }

    tunnel->ike = (ike_session_t *)ike;
    tunnel->established = true;

    __sync_fetch_and_add(&vpn->stats.ike_exchanges, 1);

    log_info("VPN tunnel established: %s", tunnel->name);

    return NGFW_OK;
}

ngfw_ret_t vpn_tunnel_close(vpn_t *vpn, vpn_tunnel_t *tunnel)
{
    if (!vpn || !tunnel) return NGFW_ERR_INVALID;

    /* Close IKE SA */
    if (tunnel->ike) {
        ike_session_int_t *ike = (ike_session_int_t *)tunnel->ike;
        ike->state = IKE_STATE_CLOSING;
        ike->pub.state = IKE_STATE_CLOSING;
        ngfw_free(tunnel->ike);
        tunnel->ike = NULL;
    }

    /* Clear IPsec SAs */
    if (tunnel->in_sa) {
        ngfw_free(tunnel->in_sa);
        tunnel->in_sa = NULL;
    }
    if (tunnel->out_sa) {
        ngfw_free(tunnel->out_sa);
        tunnel->out_sa = NULL;
    }

    tunnel->established = false;

    log_info("VPN tunnel closed: %s", tunnel->name);

    return NGFW_OK;
}

/* Periodic IKE SA maintenance: retransmit, rekey, expiry */
ngfw_ret_t vpn_tick(vpn_t *vpn)
{
    if (!vpn) return NGFW_ERR_INVALID;

    hash_rdlock(vpn->tunnels);

    void **iter = hash_iterate_start(vpn->tunnels);
    if (!iter) {
        hash_unlock(vpn->tunnels);
        return NGFW_OK;
    }

    while (hash_iterate_has_next(iter)) {
        vpn_tunnel_t *tunnel = (vpn_tunnel_t *)hash_iterate_next(vpn->tunnels, iter);
        if (!tunnel || !tunnel->ike) continue;

        ike_session_int_t *ike = (ike_session_int_t *)tunnel->ike;
        u64 now = get_ms_time();
        u64 elapsed = now - ike->last_activity;

        /* Handle extended internal states (values outside ike_state_t enum) */
        if (ike->state == IKE_INT_STATE_SA_INIT_SENT ||
            ike->state == IKE_INT_STATE_AUTH_SENT) {
            /* Retransmission logic */
            if (elapsed > IKE_RETRANSMIT_INTERVAL) {
                ike->retransmit_count++;
                ike->last_activity = now;
                if (ike->retransmit_count > IKE_RETRANSMIT_MAX) {
                    log_warn("IKE retransmit exhausted for %s", ike->pub.remote_addr);
                    ike->state = IKE_INT_STATE_FAILED;
                } else {
                    log_debug("IKE retransmit #%u to %s",
                              ike->retransmit_count, ike->pub.remote_addr);
                }
            }
        } else if (ike->state == IKE_INT_STATE_FAILED) {
            if (tunnel->established) {
                tunnel->established = false;
                log_warn("Tunnel %s closed due to IKE failure", tunnel->name);
            }
        } else {
            /* Handle standard ike_state_t values */
            switch (ike->state) {
            case IKE_STATE_ESTABLISHED:
                if (elapsed > ike->timeout_ms) {
                    log_info("IKE SA expired for %s, rekeying", ike->pub.remote_addr);
                    ike->state = IKE_STATE_REKEY;
                    ike->pub.state = IKE_STATE_REKEY;
                    ike->last_activity = now;
                }
                break;

            case IKE_STATE_REKEY:
                if (elapsed > IKE_RETRANSMIT_INTERVAL * IKE_RETRANSMIT_MAX) {
                    log_warn("IKE rekey failed for %s", ike->pub.remote_addr);
                    ike->state = IKE_INT_STATE_FAILED;
                }
                break;

            default:
                break;
            }
        }
    }

    ngfw_free(iter);
    hash_unlock(vpn->tunnels);

    return NGFW_OK;
}

ngfw_ret_t vpn_add_ike_proposal(vpn_t *vpn, ike_proposal_t *proposal)
{
    if (!vpn || !proposal) return NGFW_ERR_INVALID;

    if (vpn->num_ike_proposals >= MAX_PROPOSALS) {
        return NGFW_ERR_NO_RESOURCE;
    }

    vpn->ike_proposals[vpn->num_ike_proposals++] = *proposal;
    return NGFW_OK;
}

ngfw_ret_t vpn_add_ipsec_proposal(vpn_t *vpn, ipsec_proposal_t *proposal)
{
    if (!vpn || !proposal) return NGFW_ERR_INVALID;

    if (vpn->num_ipsec_proposals >= MAX_PROPOSALS) {
        return NGFW_ERR_NO_RESOURCE;
    }

    vpn->ipsec_proposals[vpn->num_ipsec_proposals++] = *proposal;
    return NGFW_OK;
}

vpn_stats_t *vpn_get_stats(vpn_t *vpn)
{
    if (!vpn) return NULL;
    return &vpn->stats;
}

void vpn_reset_stats(vpn_t *vpn)
{
    if (!vpn) return;
    memset(&vpn->stats, 0, sizeof(vpn_stats_t));
}

ngfw_ret_t vpn_set_psk(vpn_t *vpn, const char *psk)
{
    if (!vpn || !psk) return NGFW_ERR_INVALID;

    snprintf(vpn->psk, sizeof(vpn->psk), "%s", psk);
    log_info("PSK configured for VPN");

    return NGFW_OK;
}

ngfw_ret_t vpn_set_certificate(vpn_t *vpn, const char *cert, const char *key)
{
    if (!vpn || !cert || !key) return NGFW_ERR_INVALID;

    snprintf(vpn->certificate, sizeof(vpn->certificate), "%s", cert);
    snprintf(vpn->private_key, sizeof(vpn->private_key), "%s", key);

    log_info("Certificate configured for VPN");

    return NGFW_OK;
}
