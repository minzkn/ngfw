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

#include "ngfw/packet.h"
#include "ngfw/memory.h"
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>

packet_t *packet_create(u32 capacity)
{
    packet_t *pkt = ngfw_malloc(sizeof(packet_t));
    if (!pkt) return NULL;
    
    pkt->capacity = capacity > 0 ? capacity : NGFW_PACKET_SIZE;
    pkt->data = ngfw_malloc(pkt->capacity);
    if (!pkt->data) {
        ngfw_free(pkt);
        return NULL;
    }
    
    pkt->len = 0;
    pkt->ifindex_in = 0;
    pkt->ifindex_out = 0;
    pkt->timestamp = 0;
    pkt->direction = PKT_DIR_IN;
    
    return pkt;
}

void packet_destroy(packet_t *pkt)
{
    if (!pkt) return;
    if (pkt->data) ngfw_free(pkt->data);
    ngfw_free(pkt);
}

void packet_reset(packet_t *pkt)
{
    if (!pkt) return;
    pkt->len = 0;
    pkt->ifindex_in = 0;
    pkt->ifindex_out = 0;
    pkt->timestamp = 0;
}

ngfw_ret_t packet_append(packet_t *pkt, const void *data, u32 len)
{
    if (!pkt || !data) return NGFW_ERR_INVALID;
    
    if (pkt->len + len > pkt->capacity) {
        u32 new_cap = pkt->capacity * 2;
        while (new_cap < pkt->len + len) new_cap *= 2;
        
        u8 *new_data = ngfw_realloc(pkt->data, new_cap);
        if (!new_data) return NGFW_ERR_NO_MEM;
        
        pkt->data = new_data;
        pkt->capacity = new_cap;
    }
    
    memcpy(pkt->data + pkt->len, data, len);
    pkt->len += len;
    
    return NGFW_OK;
}

ngfw_ret_t packet_reserve(packet_t *pkt, u32 size)
{
    if (!pkt) return NGFW_ERR_INVALID;
    
    if (size > pkt->capacity) {
        u8 *new_data = ngfw_realloc(pkt->data, size);
        if (!new_data) return NGFW_ERR_NO_MEM;
        
        pkt->data = new_data;
        pkt->capacity = size;
    }
    
    return NGFW_OK;
}

eth_header_t *packet_get_eth(packet_t *pkt)
{
    if (!pkt || pkt->len < sizeof(eth_header_t)) return NULL;
    return (eth_header_t *)pkt->data;
}

ip_header_t *packet_get_ip(packet_t *pkt)
{
    eth_header_t *eth = packet_get_eth(pkt);
    if (!eth) return NULL;
    
    if (pkt->len < ETH_HLEN + sizeof(ip_header_t)) return NULL;
    if (eth->type != ETH_P_IP) return NULL;
    
    return (ip_header_t *)(pkt->data + ETH_HLEN);
}

ipv6_header_t *packet_get_ipv6(packet_t *pkt)
{
    eth_header_t *eth = packet_get_eth(pkt);
    if (!eth) return NULL;
    
    if (pkt->len < ETH_HLEN + sizeof(ipv6_header_t)) return NULL;
    if (eth->type != ETH_P_IPV6) return NULL;
    
    return (ipv6_header_t *)(pkt->data + ETH_HLEN);
}

tcp_header_t *packet_get_tcp(packet_t *pkt)
{
    ip_header_t *ip = packet_get_ip(pkt);
    if (!ip) return NULL;
    
    u32 ip_header_len = (ip->version_ihl & 0x0F) * 4;
    if (pkt->len < ETH_HLEN + ip_header_len + sizeof(tcp_header_t)) return NULL;
    if (ip->protocol != IP_PROTO_TCP) return NULL;
    
    return (tcp_header_t *)(pkt->data + ETH_HLEN + ip_header_len);
}

udp_header_t *packet_get_udp(packet_t *pkt)
{
    ip_header_t *ip = packet_get_ip(pkt);
    if (!ip) return NULL;
    
    u32 ip_header_len = (ip->version_ihl & 0x0F) * 4;
    if (pkt->len < ETH_HLEN + ip_header_len + sizeof(udp_header_t)) return NULL;
    if (ip->protocol != IP_PROTO_UDP) return NULL;
    
    return (udp_header_t *)(pkt->data + ETH_HLEN + ip_header_len);
}

icmp_header_t *packet_get_icmp(packet_t *pkt)
{
    ip_header_t *ip = packet_get_ip(pkt);
    if (!ip) return NULL;
    
    u32 ip_header_len = (ip->version_ihl & 0x0F) * 4;
    if (pkt->len < ETH_HLEN + ip_header_len + sizeof(icmp_header_t)) return NULL;
    if (ip->protocol != IP_PROTO_ICMP) return NULL;
    
    return (icmp_header_t *)(pkt->data + ETH_HLEN + ip_header_len);
}

u8 packet_get_ip_version(packet_t *pkt)
{
    eth_header_t *eth = packet_get_eth(pkt);
    if (!eth) return 0;
    
    if (eth->type == ETH_P_IP && pkt->len >= ETH_HLEN + 1) {
        return (pkt->data[ETH_HLEN] >> 4) & 0x0F;
    }
    if (eth->type == ETH_P_IPV6 && pkt->len >= ETH_HLEN + 1) {
        return 6;
    }
    return 0;
}

u8 packet_get_protocol(packet_t *pkt)
{
    ip_header_t *ip = packet_get_ip(pkt);
    if (!ip) return 0;
    return ip->protocol;
}

u16 packet_get_src_port(packet_t *pkt)
{
    tcp_header_t *tcp = packet_get_tcp(pkt);
    if (tcp) return ntohs(tcp->src_port);
    
    udp_header_t *udp = packet_get_udp(pkt);
    if (udp) return ntohs(udp->src_port);
    
    return 0;
}

u16 packet_get_dst_port(packet_t *pkt)
{
    tcp_header_t *tcp = packet_get_tcp(pkt);
    if (tcp) return ntohs(tcp->dst_port);
    
    udp_header_t *udp = packet_get_udp(pkt);
    if (udp) return ntohs(udp->dst_port);
    
    return 0;
}
