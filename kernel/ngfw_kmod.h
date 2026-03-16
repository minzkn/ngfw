/*
 * NGFW Kernel Module
 * Next-Generation Firewall for Linux Kernel 6.x
 *
 * Copyright (C) 2024 NGFW Project
 * License: GPL v2
 */

#ifndef NGFW_KMOD_H
#define NGFW_KMOD_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack.h>

#define NGFW_MODULE_NAME "ngfw"
#define NGFW_MODULE_VERSION "1.0.0"

#define NGFW_MAX_RULES 1024
#define NGFW_HASH_SIZE 256

#define NGFW_ACTION_ACCEPT 1
#define NGFW_ACTION_DROP 2
#define NGFW_ACTION_REJECT 3
#define NGFW_ACTION_LOG 4

#define NGFW_LOG_NONE 0
#define NGFW_LOG_NORMAL 1
#define NGFW_LOG_PACKET 2
#define NGFW_LOG_ALL 3

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

struct ngfw_rule {
    u32 id;
    u32 src_ip;
    u32 src_mask;
    u32 dst_ip;
    u32 dst_mask;
    u16 src_port_min;
    u16 src_port_max;
    u16 dst_port_min;
    u16 dst_port_max;
    u8 proto;
    u8 action;
    u8 log_level;
    bool enabled;
    char name[64];
};

struct ngfw_stats {
    u64 packets_total;
    u64 packets_accepted;
    u64 packets_dropped;
    u64 packets_rejected;
    u64 bytes_total;
    u64 tcp_packets;
    u64 udp_packets;
    u64 icmp_packets;
    u64 other_packets;
    u64 sessions_active;
    u64 sessions_created;
    u64 sessions_expired;
    u64 ips_alerts;
    u64 ips_blocked;
};

struct ngfw_session {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 proto;
    u8 state;
    u64 created;
    u64 last_seen;
    u64 packets;
    u64 bytes;
};

struct ngfw_ips_signature {
    u32 id;
    u32 severity;
    char name[128];
    char pattern[256];
    char description[256];
    u8 proto;
    u16 src_port;
    u16 dst_port;
    bool enabled;
};

struct ngfw_config {
    bool enabled;
    u8 default_action;
    u8 log_level;
    u32 session_timeout;
    u32 max_sessions;
    u32 worker_threads;
};

#endif /* NGFW_KMOD_H */
