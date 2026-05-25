/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_NETWORK_PROTO_H
#define NGFW_NETWORK_PROTO_H

#include "ngfw/types.h"

/* Ethernet constants - must be defined before struct declarations */
#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806

/* IP protocol numbers */
#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17
#define IP_PROTO_ICMPV6 58

/*
 * Protocol Headers (packed for memory layout)
 */

/* Ethernet header */
typedef struct eth_header {
    u8 dst[ETH_ALEN];
    u8 src[ETH_ALEN];
    u16 type;
} __attribute__((packed)) eth_header_t;

/* IPv4 header */
typedef struct ip_header {
    u8 version_ihl;
    u8 tos;
    u16 total_len;
    u16 id;
    u16 frag_offset;
    u8 ttl;
    u8 protocol;
    u16 checksum;
    u32 src;
    u32 dst;
} __attribute__((packed)) ip_header_t;

/* IPv6 header */
typedef struct ipv6_header {
    u32 version_tc_flow;
    u16 payload_len;
    u8 next_header;
    u8 hop_limit;
    u8 src[16];
    u8 dst[16];
} __attribute__((packed)) ipv6_header_t;

/* TCP header */
typedef struct tcp_header {
    u16 src_port;
    u16 dst_port;
    u32 seq;
    u32 ack;
    u8 data_offset;
    u8 flags;
    u16 window;
    u16 checksum;
    u16 urgent;
} __attribute__((packed)) tcp_header_t;

/* UDP header */
typedef struct udp_header {
    u16 src_port;
    u16 dst_port;
    u16 len;
    u16 checksum;
} __attribute__((packed)) udp_header_t;

/* ICMP header */
typedef struct icmp_header {
    u8 type;
    u8 code;
    u16 checksum;
    u32 rest;
} __attribute__((packed)) icmp_header_t;

/* Protocol utilities */
#define IP_HEADER_LEN(ip) (((ip)->version_ihl & 0x0F) * 4)

#endif
