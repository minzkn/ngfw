#ifndef NGFW_DDOS_H
#define NGFW_DDOS_H

#include "types.h"
#include "packet.h"

typedef enum {
    DDOS_ATTACK_TCP_SYN_FLOOD,
    DDOS_ATTACK_TCP_ACK_FLOOD,
    DDOS_ATTACK_TCP_CONNECTION_FLOOD,
    DDOS_ATTACK_UDP_FLOOD,
    DDOS_ATTACK_ICMP_FLOOD,
    DDOS_ATTACK_HTTP_FLOOD,
    DDOS_ATTACK_DNS_AMPLIFICATION,
    DDOS_ATTACK_NTP_AMPLIFICATION,
    DDOS_ATTACK_SSDP_AMPLIFICATION,
    DDOS_ATTACK_SLOWLORIS,
    DDOS_ATTACK_STANDARD_CONNECTION,
    DDOS_ATTACK_UNKNOWN
} ddos_attack_type_t;

typedef struct ddos_threshold {
    u32 packets_per_second;
    u32 bytes_per_second;
    u32 connections_per_second;
    u32 concurrent_connections;
} ddos_threshold_t;

typedef struct ddos_profile {
    u32 id;
    char name[64];
    bool enabled;
    ddos_threshold_t threshold;
    ddos_threshold_t penalty_threshold;
    u32 penalty_duration;
    bool enable_syn_cookie;
    bool enable_tcp_ratelimit;
    bool enable_udp_ratelimit;
    bool enable_connection_limit;
    bool enable_bandwidth_limit;
    u32 max_connections_per_ip;
    u32 max_new_connections_per_sec;
    u32 max_packets_per_sec;
    u32 max_bandwidth_mbps;
} ddos_profile_t;

typedef struct ddos_stats {
    u64 total_packets;
    u64 total_bytes;
    u64 dropped_packets;
    u64 dropped_bytes;
    u64 syn_cookie_enabled;
    u64 rate_limited_packets;
    u64 blocked_ips;
    u64 attacks_detected;
    u64 attacks_mitigated;
} ddos_stats_t;

typedef struct ddos_blocked_ip {
    u32 ip;
    u64 blocked_at;
    u64 expires_at;
    char reason[128];
} ddos_blocked_ip_t;

typedef struct ddos ddos_t;

ddos_t *ddos_create(void);
void ddos_destroy(ddos_t *ddos);

ngfw_ret_t ddos_init(ddos_t *ddos);
ngfw_ret_t ddos_start(ddos_t *ddos);
ngfw_ret_t ddos_stop(ddos_t *ddos);

ngfw_ret_t ddos_set_profile(ddos_t *ddos, ddos_profile_t *profile);
ddos_profile_t *ddos_get_profile(ddos_t *ddos);

ngfw_ret_t ddos_check_packet(ddos_t *ddos, packet_t *pkt, bool *should_drop);
ngfw_ret_t ddos_check_ip(ddos_t *ddos, u32 ip, bool *should_block);

ngfw_ret_t ddos_block_ip(ddos_t *ddos, u32 ip, u32 duration_sec, const char *reason);
ngfw_ret_t ddos_unblock_ip(ddos_t *ddos, u32 ip);
ngfw_ret_t ddos_unblock_all(ddos_t *ddos);

ddos_stats_t *ddos_get_stats(ddos_t *ddos);
void ddos_reset_stats(ddos_t *ddos);

ngfw_ret_t ddos_get_blocked_ips(ddos_t *ddos, ddos_blocked_ip_t **ips, u32 *count);

#endif
