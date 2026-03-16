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

#include "ngfw/vpn.h"
#include "ngfw/memory.h"
#include "ngfw/hash.h"
#include "ngfw/log.h"
#include "ngfw/crypto.h"
#include "ngfw/platform.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MAX_TUNNELS 256
#define MAX_PROPOSALS 16

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

vpn_t *vpn_create(vpn_type_t type)
{
    vpn_t *vpn = ngfw_malloc(sizeof(vpn_t));
    if (!vpn) return NULL;

    memset(vpn, 0, sizeof(vpn_t));
    vpn->type = type;
    vpn->tunnels = hash_create(64, tunnel_hash, tunnel_match, NULL);

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
    strncpy(t->name, config->name, sizeof(t->name) - 1);
    t->type = vpn->type;
    strncpy(t->local_addr, config->local_addr, sizeof(t->local_addr) - 1);
    strncpy(t->remote_addr, config->remote_addr, sizeof(t->remote_addr) - 1);
    strncpy(t->local_net, config->local_net, sizeof(t->local_net) - 1);
    strncpy(t->remote_net, config->remote_net, sizeof(t->remote_net) - 1);

    t->created = get_ms_time();
    t->established = false;

    hash_insert(vpn->tunnels, &t->id, t);

    vpn->stats.tunnels_created++;

    *tunnel = t;

    log_info("VPN tunnel created: %s (%s -> %s)", t->name, t->local_addr, t->remote_addr);

    return NGFW_OK;
}

ngfw_ret_t vpn_tunnel_destroy(vpn_t *vpn, u32 tunnel_id)
{
    if (!vpn) return NGFW_ERR_INVALID;

    hash_remove(vpn->tunnels, &tunnel_id);

    vpn->stats.tunnels_closed++;

    log_info("VPN tunnel destroyed: %u", tunnel_id);

    return NGFW_OK;
}

static ngfw_ret_t ike_exchange(vpn_t *vpn, vpn_tunnel_t *tunnel)
{
    if (!vpn || !tunnel) return NGFW_ERR_INVALID;

    tunnel->ike = ngfw_malloc(sizeof(ike_session_t));
    if (!tunnel->ike) return NGFW_ERR_NO_MEM;

    memset(tunnel->ike, 0, sizeof(ike_session_t));

    tunnel->ike->id = tunnel->id;
    strncpy(tunnel->ike->local_addr, tunnel->local_addr, sizeof(tunnel->ike->local_addr) - 1);
    strncpy(tunnel->ike->remote_addr, tunnel->remote_addr, sizeof(tunnel->ike->remote_addr) - 1);
    tunnel->ike->local_port = 500;
    tunnel->ike->remote_port = 500;
    tunnel->ike->state = IKE_STATE_INIT;
    tunnel->ike->created = get_ms_time();

    if (vpn->num_ike_proposals > 0) {
        tunnel->ike->proposal = vpn->ike_proposals[0];
    }

    vpn->stats.ike_exchanges++;

    return NGFW_OK;
}

static ngfw_ret_t ipsec_sa_establish(vpn_t *vpn, vpn_tunnel_t *tunnel)
{
    if (!vpn || !tunnel) return NGFW_ERR_INVALID;

    tunnel->in_sa = ngfw_malloc(sizeof(ipsec_sa_t));
    tunnel->out_sa = ngfw_malloc(sizeof(ipsec_sa_t));

    if (!tunnel->in_sa || !tunnel->out_sa) {
        if (tunnel->in_sa) ngfw_free(tunnel->in_sa);
        if (tunnel->out_sa) ngfw_free(tunnel->out_sa);
        return NGFW_ERR_NO_MEM;
    }

    memset(tunnel->in_sa, 0, sizeof(ipsec_sa_t));
    memset(tunnel->out_sa, 0, sizeof(ipsec_sa_t));

    tunnel->in_sa->id = tunnel->id;
    tunnel->in_sa->spi = (u32)(rand() & 0xFFFFFFFF);
    tunnel->in_sa->protocol = IPSEC_PROTOCOL_ESP;
    tunnel->in_sa->mode = IPSEC_MODE_TUNNEL;
    strncpy(tunnel->in_sa->src_addr, tunnel->remote_addr, sizeof(tunnel->in_sa->src_addr) - 1);
    strncpy(tunnel->in_sa->dst_addr, tunnel->local_addr, sizeof(tunnel->in_sa->dst_addr) - 1);
    tunnel->in_sa->state = IPSEC_STATE_ESTABLISHED;
    tunnel->in_sa->created = get_ms_time();
    tunnel->in_sa->expires = tunnel->in_sa->created + 3600000;

    tunnel->out_sa->id = tunnel->id;
    tunnel->out_sa->spi = (u32)(rand() & 0xFFFFFFFF);
    tunnel->out_sa->protocol = IPSEC_PROTOCOL_ESP;
    tunnel->out_sa->mode = IPSEC_MODE_TUNNEL;
    strncpy(tunnel->out_sa->src_addr, tunnel->local_addr, sizeof(tunnel->out_sa->src_addr) - 1);
    strncpy(tunnel->out_sa->dst_addr, tunnel->remote_addr, sizeof(tunnel->out_sa->dst_addr) - 1);
    tunnel->out_sa->state = IPSEC_STATE_ESTABLISHED;
    tunnel->out_sa->created = get_ms_time();
    tunnel->out_sa->expires = tunnel->out_sa->created + 3600000;

    log_info("IPsec SAs established for tunnel %s", tunnel->name);

    return NGFW_OK;
}

ngfw_ret_t vpn_tunnel_establish(vpn_t *vpn, vpn_tunnel_t *tunnel)
{
    if (!vpn || !tunnel) return NGFW_ERR_INVALID;

    log_info("Establishing VPN tunnel: %s", tunnel->name);

    ngfw_ret_t ret = ike_exchange(vpn, tunnel);
    if (ret != NGFW_OK) {
        log_err("IKE exchange failed for tunnel %s", tunnel->name);
        return ret;
    }

    ret = ipsec_sa_establish(vpn, tunnel);
    if (ret != NGFW_OK) {
        log_err("IPsec SA establishment failed for tunnel %s", tunnel->name);
        return ret;
    }

    tunnel->established = true;

    log_info("VPN tunnel established: %s", tunnel->name);

    return NGFW_OK;
}

ngfw_ret_t vpn_tunnel_close(vpn_t *vpn, vpn_tunnel_t *tunnel)
{
    if (!vpn || !tunnel) return NGFW_ERR_INVALID;

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

    tunnel->established = false;

    log_info("VPN tunnel closed: %s", tunnel->name);

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

    strncpy(vpn->psk, psk, sizeof(vpn->psk) - 1);

    log_info("PSK configured for VPN");

    return NGFW_OK;
}

ngfw_ret_t vpn_set_certificate(vpn_t *vpn, const char *cert, const char *key)
{
    if (!vpn || !cert || !key) return NGFW_ERR_INVALID;

    strncpy(vpn->certificate, cert, sizeof(vpn->certificate) - 1);
    strncpy(vpn->private_key, key, sizeof(vpn->private_key) - 1);

    log_info("Certificate configured for VPN");

    return NGFW_OK;
}
