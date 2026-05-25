/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_NETWORK_PACKET_H
#define NGFW_NETWORK_PACKET_H

#include "ngfw/types.h"
#include "ngfw/network/proto.h"

/* Packet directions */
typedef enum {
    PKT_DIR_IN,
    PKT_DIR_OUT,
    PKT_DIR_FWD
} packet_dir_t;

/* Packet buffer */
typedef struct packet {
    u8 *data;
    u32 len;
    u32 capacity;
    u32 ifindex_in;
    u32 ifindex_out;
    u64 timestamp;
    u8 direction;
    bool is_esp;
    u32 tunnel_id;
    bool allocated;
} packet_t;

/* Packet operations */
packet_t *packet_create(u32 capacity);
void packet_destroy(packet_t *pkt);
void packet_reset(packet_t *pkt);
ngfw_ret_t packet_append(packet_t *pkt, const void *data, u32 len);
ngfw_ret_t packet_reserve(packet_t *pkt, u32 size);

/* Packet data accessors */
eth_header_t *packet_get_eth(packet_t *pkt);
ip_header_t *packet_get_ip(packet_t *pkt);
ipv6_header_t *packet_get_ipv6(packet_t *pkt);
tcp_header_t *packet_get_tcp(packet_t *pkt);
udp_header_t *packet_get_udp(packet_t *pkt);
icmp_header_t *packet_get_icmp(packet_t *pkt);

u8 packet_get_ip_version(packet_t *pkt);
u8 packet_get_protocol(packet_t *pkt);
u16 packet_get_src_port(packet_t *pkt);
u16 packet_get_dst_port(packet_t *pkt);

/* Checksum calculation */
u16 ip_checksum(const void *data, u32 len);
u16 tcp_calculate_checksum(const ip_header_t *ip, const tcp_header_t *tcp);
u16 udp_calculate_checksum(const ip_header_t *ip, const udp_header_t *udp);

#endif
