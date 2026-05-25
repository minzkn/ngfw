/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_SECURITY_DDOS_H
#define NGFW_SECURITY_DDOS_H

#include "ngfw/types.h"
#include "ngfw/network/packet.h"
#include "ngfw/hash.h"

/*
 * DDoS Mitigation
 * Rate limiting, SYN flood protection, IP blocking
 */

#define MAX_BLOCKED_IPS 65536

/* Threshold configuration */
typedef struct ddos_threshold {
    u32 packets_per_second;
    u32 bytes_per_second;
    u32 connections_per_second;
    u32 concurrent_connections;
} ddos_threshold_t;

/* DDoS protection profile */
typedef struct ddos_profile {
    bool enabled;
    char name[64];
    ddos_threshold_t threshold;
    ddos_threshold_t penalty_threshold;
    u32 penalty_duration;
    bool enable_syn_cookie;
    bool enable_tcp_ratelimit;
    bool enable_connection_limit;
    u32 max_connections_per_ip;
    u32 max_new_connections_per_sec;
    u32 max_packets_per_sec;
    u32 max_bandwidth_mbps;
} ddos_profile_t;

/* Blocked IP entry */
typedef struct ddos_blocked_ip {
    u32 ip;
    u64 blocked_at;
    u64 expires_at;
    char reason[64];
    u64 hit_count;
} ddos_blocked_ip_t;

typedef struct ddos_stats {
    u64 blocked_ips;
    u64 packets_dropped;
    u64 syn_flood_detected;
    u64 udp_flood_detected;
    u64 icmp_flood_detected;
    u64 connections_blocked;
    u64 rate_limited;
    u64 total_packets;
    u64 total_bytes;
    u64 dropped_packets;
    u64 dropped_bytes;
    u64 rate_limited_packets;
    u64 attacks_detected;
    bool syn_cookie_enabled;
} ddos_stats_t;

/* Forward declaration - full definition in ddos.c */
typedef struct ddos ddos_t;

ddos_t *ddos_create(void);
void ddos_destroy(ddos_t *ddos);
ngfw_ret_t ddos_init(ddos_t *ddos);
ngfw_ret_t ddos_start(ddos_t *ddos);
ngfw_ret_t ddos_stop(ddos_t *ddos);

ngfw_ret_t ddos_set_profile(ddos_t *ddos, ddos_profile_t *profile);
ddos_profile_t *ddos_get_profile(ddos_t *ddos);

ngfw_ret_t ddos_check_packet(ddos_t *ddos, packet_t *pkt, bool *drop);
ngfw_ret_t ddos_block_ip(ddos_t *ddos, u32 ip, u32 duration_sec, const char *reason);
ngfw_ret_t ddos_unblock_ip(ddos_t *ddos, u32 ip);

ddos_stats_t *ddos_get_stats(ddos_t *ddos);
void ddos_reset_stats(ddos_t *ddos);

#endif
