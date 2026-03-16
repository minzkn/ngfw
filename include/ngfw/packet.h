#ifndef NGFW_PACKET_H
#define NGFW_PACKET_H

#include "types.h"

#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17
#define IP_PROTO_ICMPV6 58

typedef struct eth_header {
    u8 dst[ETH_ALEN];
    u8 src[ETH_ALEN];
    u16 type;
} __attribute__((packed)) eth_header_t;

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

typedef struct ipv6_header {
    u32 version_tc_flow;
    u16 payload_len;
    u8 next_header;
    u8 hop_limit;
    u8 src[16];
    u8 dst[16];
} __attribute__((packed)) ipv6_header_t;

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

typedef struct udp_header {
    u16 src_port;
    u16 dst_port;
    u16 len;
    u16 checksum;
} __attribute__((packed)) udp_header_t;

typedef struct icmp_header {
    u8 type;
    u8 code;
    u16 checksum;
    u32 rest;
} __attribute__((packed)) icmp_header_t;

typedef struct packet {
    u8 *data;
    u32 len;
    u32 capacity;
    u32 ifindex_in;
    u32 ifindex_out;
    u64 timestamp;
    u8 direction;
} packet_t;

typedef enum {
    PKT_DIR_IN,
    PKT_DIR_OUT,
    PKT_DIR_FWD
} packet_dir_t;

packet_t *packet_create(u32 capacity);
void packet_destroy(packet_t *pkt);
void packet_reset(packet_t *pkt);
ngfw_ret_t packet_append(packet_t *pkt, const void *data, u32 len);
ngfw_ret_t packet_reserve(packet_t *pkt, u32 size);

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

u16 ip_checksum(const void *data, u32 len);
u16 ip_checksum_add(const void *data, u32 len, u32 sum);
u16 tcp_calculate_checksum(const ip_header_t *ip, const tcp_header_t *tcp);
u16 udp_calculate_checksum(const ip_header_t *ip, const udp_header_t *udp);

#define IP_HEADER_LEN(ip) (((ip)->version_ihl & 0x0F) * 4)

#endif
