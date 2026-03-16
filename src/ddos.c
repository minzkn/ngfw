#include "ngfw/ddos.h"
#include "ngfw/memory.h"
#include "ngfw/hash.h"
#include "ngfw/log.h"
#include "ngfw/platform.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#define MAX_BLOCKED_IPS 65536

typedef struct ip_flow {
    u32 ip;
    u64 first_seen;
    u64 last_seen;
    u64 packet_count;
    u64 byte_count;
    u64 syn_count;
    u64 ack_count;
    u64 udp_count;
    u64 icmp_count;
    u32 new_connections;
    bool syn_cookie_triggered;
} ip_flow_t;

typedef struct connection_tracker {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u64 created;
    u8 state;
} connection_tracker_t;

struct ddos {
    ddos_profile_t profile;
    ddos_stats_t stats;
    hash_table_t *flow_table;
    hash_table_t *blocked_ips;
    connection_tracker_t *connections;
    u32 max_connections;
    u32 connection_count;
    bool initialized;
    bool running;
    u64 last_cleanup;
};

static u32 flow_hash(const void *key, u32 size)
{
    return (*(const u32 *)key) % size;
}

static bool flow_match(const void *key1, const void *key2)
{
    return (*(const u32 *)key1) == (*(const u32 *)key2);
}

static u32 blocked_ip_hash(const void *key, u32 size)
{
    return (*(const u32 *)key) % size;
}

static bool blocked_ip_match(const void *key1, const void *key2)
{
    return (*(const u32 *)key1) == (*(const u32 *)key2);
}

ddos_t *ddos_create(void)
{
    ddos_t *ddos = ngfw_malloc(sizeof(ddos_t));
    if (!ddos) return NULL;

    memset(ddos, 0, sizeof(ddos_t));

    ddos->flow_table = hash_create(8192, flow_hash, flow_match, NULL);
    ddos->blocked_ips = hash_create(1024, blocked_ip_hash, blocked_ip_match, NULL);

    if (!ddos->flow_table || !ddos->blocked_ips) {
        if (ddos->flow_table) hash_destroy(ddos->flow_table);
        if (ddos->blocked_ips) hash_destroy(ddos->blocked_ips);
        ngfw_free(ddos);
        return NULL;
    }

    ddos->profile.enabled = true;
    ddos->profile.threshold.packets_per_second = 1000;
    ddos->profile.threshold.bytes_per_second = 10000000;
    ddos->profile.threshold.connections_per_second = 100;
    ddos->profile.threshold.concurrent_connections = 1000;

    ddos->profile.penalty_threshold.packets_per_second = 5000;
    ddos->profile.penalty_threshold.bytes_per_second = 50000000;
    ddos->profile.penalty_threshold.connections_per_second = 500;
    ddos->profile.penalty_threshold.concurrent_connections = 5000;

    ddos->profile.penalty_duration = 300;
    ddos->profile.enable_syn_cookie = true;
    ddos->profile.enable_tcp_ratelimit = true;
    ddos->profile.enable_connection_limit = true;
    ddos->profile.max_connections_per_ip = 100;
    ddos->profile.max_new_connections_per_sec = 50;
    ddos->profile.max_packets_per_sec = 1000;
    ddos->profile.max_bandwidth_mbps = 1000;

    ddos->max_connections = 65536;
    ddos->connections = ngfw_malloc(sizeof(connection_tracker_t) * ddos->max_connections);
    if (!ddos->connections) {
        hash_destroy(ddos->flow_table);
        hash_destroy(ddos->blocked_ips);
        ngfw_free(ddos);
        return NULL;
    }

    log_info("DDoS mitigation created");

    return ddos;
}

void ddos_destroy(ddos_t *ddos)
{
    if (!ddos) return;

    if (ddos->running) {
        ddos_stop(ddos);
    }

    hash_destroy(ddos->flow_table);
    hash_destroy(ddos->blocked_ips);
    ngfw_free(ddos->connections);
    ngfw_free(ddos);

    log_info("DDoS mitigation destroyed");
}

ngfw_ret_t ddos_init(ddos_t *ddos)
{
    if (!ddos) return NGFW_ERR_INVALID;

    ddos->initialized = true;
    ddos->last_cleanup = get_ms_time();

    log_info("DDoS mitigation initialized");

    return NGFW_OK;
}

ngfw_ret_t ddos_start(ddos_t *ddos)
{
    if (!ddos || !ddos->initialized) return NGFW_ERR_INVALID;

    ddos->running = true;

    log_info("DDoS mitigation started");

    return NGFW_OK;
}

ngfw_ret_t ddos_stop(ddos_t *ddos)
{
    if (!ddos) return NGFW_ERR_INVALID;

    ddos->running = false;

    log_info("DDoS mitigation stopped");

    return NGFW_OK;
}

ngfw_ret_t ddos_set_profile(ddos_t *ddos, ddos_profile_t *profile)
{
    if (!ddos || !profile) return NGFW_ERR_INVALID;

    memcpy(&ddos->profile, profile, sizeof(ddos_profile_t));

    log_info("DDoS profile updated: %s", profile->name);

    return NGFW_OK;
}

ddos_profile_t *ddos_get_profile(ddos_t *ddos)
{
    return ddos ? &ddos->profile : NULL;
}

static void cleanup_old_flows(ddos_t *ddos)
{
    u64 now = get_ms_time();

    if (now - ddos->last_cleanup < 60000) {
        return;
    }

    ddos->last_cleanup = now;
}

static ip_flow_t *get_or_create_flow(ddos_t *ddos, u32 ip)
{
    ip_flow_t *flow = hash_lookup(ddos->flow_table, &ip);

    if (!flow) {
        flow = ngfw_malloc(sizeof(ip_flow_t));
        if (!flow) return NULL;

        memset(flow, 0, sizeof(ip_flow_t));
        flow->ip = ip;
        flow->first_seen = get_ms_time();
        flow->last_seen = flow->first_seen;

        hash_insert(ddos->flow_table, &ip, flow);
    }

    flow->last_seen = get_ms_time();

    return flow;
}

ngfw_ret_t ddos_check_packet(ddos_t *ddos, packet_t *pkt, bool *should_drop)
{
    if (!ddos || !pkt || !should_drop) return NGFW_ERR_INVALID;

    *should_drop = false;

    if (!ddos->profile.enabled) {
        return NGFW_OK;
    }

    cleanup_old_flows(ddos);

    ddos->stats.total_packets++;
    ddos->stats.total_bytes += pkt->len;

    ip_header_t *ip = packet_get_ip(pkt);
    if (!ip) return NGFW_ERR_INVALID;

    u32 src_ip = ip->src;

    ddos_blocked_ip_t *blocked = hash_lookup(ddos->blocked_ips, &src_ip);
    if (blocked) {
        if (blocked->expires_at > get_ms_time()) {
            *should_drop = true;
            ddos->stats.dropped_packets++;
            return NGFW_OK;
        } else {
            hash_remove(ddos->blocked_ips, &src_ip);
        }
    }

    ip_flow_t *flow = get_or_create_flow(ddos, src_ip);
    if (!flow) return NGFW_ERR_NO_MEM;

    flow->packet_count++;
    flow->byte_count += pkt->len;

    u64 now = get_ms_time();
    u64 elapsed = now - flow->first_seen;
    if (elapsed == 0) elapsed = 1;

    u64 pps = (flow->packet_count * 1000) / elapsed;
    (void)((flow->byte_count * 1000) / elapsed);

    if (pps > ddos->profile.threshold.packets_per_second) {
        if (pps > ddos->profile.penalty_threshold.packets_per_second) {
            *should_drop = true;
            ddos->stats.dropped_packets++;
            ddos->stats.dropped_bytes += pkt->len;

            if (pps > ddos->profile.penalty_threshold.packets_per_second * 2) {
                ddos_block_ip(ddos, src_ip, ddos->profile.penalty_duration,
                             "Excessive packet rate");
            }

            log_warn("DDoS: Dropping packets from %u.%u.%u.%u (PPS: %lu)",
                     (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                     (src_ip >> 8) & 0xFF, src_ip & 0xFF, pps);

            return NGFW_OK;
        }

        ddos->stats.rate_limited_packets++;
    }

    if (ip->protocol == 6) {
        tcp_header_t *tcp = packet_get_tcp(pkt);
        if (tcp) {
            if (tcp->flags & 0x02) {
                flow->syn_count++;
            }
            if (tcp->flags & 0x10) {
                flow->ack_count++;
            }

            u64 syn_pps = (flow->syn_count * 1000) / elapsed;
            if (syn_pps > ddos->profile.max_new_connections_per_sec * 2) {
                if (ddos->profile.enable_syn_cookie) {
                    ddos->stats.syn_cookie_enabled++;
                }
            }
        }
    } else if (ip->protocol == 17) {
        flow->udp_count++;
    } else if (ip->protocol == 1) {
        flow->icmp_count++;
    }

    if (flow->icmp_count > 100 && elapsed < 5000) {
        *should_drop = true;
        ddos->stats.dropped_packets++;
        log_warn("DDoS: ICMP flood from %u.%u.%u.%u",
                 (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                 (src_ip >> 8) & 0xFF, src_ip & 0xFF);
    }

    return NGFW_OK;
}

ngfw_ret_t ddos_check_ip(ddos_t *ddos, u32 ip, bool *should_block)
{
    if (!ddos || !should_block) return NGFW_ERR_INVALID;

    *should_block = false;

    if (!ddos->profile.enabled) {
        return NGFW_OK;
    }

    ddos_blocked_ip_t *blocked = hash_lookup(ddos->blocked_ips, &ip);
    if (blocked) {
        if (blocked->expires_at > get_ms_time()) {
            *should_block = true;
        } else {
            hash_remove(ddos->blocked_ips, &ip);
        }
    }

    return NGFW_OK;
}

ngfw_ret_t ddos_block_ip(ddos_t *ddos, u32 ip, u32 duration_sec, const char *reason)
{
    if (!ddos) return NGFW_ERR_INVALID;

    ddos_blocked_ip_t *blocked = ngfw_malloc(sizeof(ddos_blocked_ip_t));
    if (!blocked) return NGFW_ERR_NO_MEM;

    blocked->ip = ip;
    blocked->blocked_at = get_ms_time();
    blocked->expires_at = blocked->blocked_at + (duration_sec * 1000);
    strncpy(blocked->reason, reason ? reason : "Unknown", sizeof(blocked->reason) - 1);

    hash_insert(ddos->blocked_ips, &ip, blocked);

    ddos->stats.blocked_ips++;
    ddos->stats.attacks_detected++;

    log_warn("DDoS: Blocked IP %u.%u.%u.%u for %u seconds (%s)",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF, duration_sec, reason);

    return NGFW_OK;
}

ngfw_ret_t ddos_unblock_ip(ddos_t *ddos, u32 ip)
{
    if (!ddos) return NGFW_ERR_INVALID;

    hash_remove(ddos->blocked_ips, &ip);

    log_info("DDoS: Unblocked IP %u.%u.%u.%u",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF);

    return NGFW_OK;
}

ngfw_ret_t ddos_unblock_all(ddos_t *ddos)
{
    if (!ddos) return NGFW_ERR_INVALID;

    hash_destroy(ddos->blocked_ips);
    ddos->blocked_ips = hash_create(1024, blocked_ip_hash, blocked_ip_match, NULL);

    log_info("DDoS: Unblocked all IPs");

    return NGFW_OK;
}

ddos_stats_t *ddos_get_stats(ddos_t *ddos)
{
    return ddos ? &ddos->stats : NULL;
}

void ddos_reset_stats(ddos_t *ddos)
{
    if (!ddos) return;
    memset(&ddos->stats, 0, sizeof(ddos_stats_t));
}

ngfw_ret_t ddos_get_blocked_ips(ddos_t *ddos, ddos_blocked_ip_t **ips, u32 *count)
{
    if (!ddos || !count) return NGFW_ERR_INVALID;
    
    u32 total = hash_size(ddos->blocked_ips);
    if (ips) {
        *ips = ngfw_malloc(total * sizeof(ddos_blocked_ip_t));
        if (!*ips) return NGFW_ERR_NO_MEM;
        
        u32 i = 0;
        void **iter = hash_iterate_start(ddos->blocked_ips);
        while (hash_iterate_has_next(iter)) {
            ddos_blocked_ip_t *blocked = (ddos_blocked_ip_t *)hash_iterate_next(ddos->blocked_ips, iter);
            if (blocked) {
                memcpy(&(*ips)[i++], blocked, sizeof(ddos_blocked_ip_t));
            }
        }
    }
    
    *count = total;
    return NGFW_OK;
}
