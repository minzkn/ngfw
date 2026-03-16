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
#include <stddef.h>
#include <string.h>
#include <netinet/in.h>

#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20
#define TCP_FLAG_ECE  0x40
#define TCP_FLAG_CWR  0x80

u8 tcp_get_flags(tcp_header_t *tcp)
{
    return tcp->flags & 0x3F;
}

bool tcp_is_syn(tcp_header_t *tcp)
{
    return (tcp->flags & TCP_FLAG_SYN) != 0;
}

bool tcp_is_ack(tcp_header_t *tcp)
{
    return (tcp->flags & TCP_FLAG_ACK) != 0;
}

bool tcp_is_fin(tcp_header_t *tcp)
{
    return (tcp->flags & TCP_FLAG_FIN) != 0;
}

bool tcp_is_rst(tcp_header_t *tcp)
{
    return (tcp->flags & TCP_FLAG_RST) != 0;
}

bool tcp_is_psh(tcp_header_t *tcp)
{
    return (tcp->flags & TCP_FLAG_PSH) != 0;
}

u8 tcp_get_data_offset(tcp_header_t *tcp)
{
    return ((tcp->data_offset >> 4) & 0x0F) * 4;
}

u16 tcp_get_window(tcp_header_t *tcp)
{
    return ntohs(tcp->window);
}

u32 tcp_get_seq(tcp_header_t *tcp)
{
    return ntohl(tcp->seq);
}

u32 tcp_get_ack(tcp_header_t *tcp)
{
    return ntohl(tcp->ack);
}

u8 *tcp_get_payload(tcp_header_t *tcp, u32 ip_header_len, u32 *payload_len)
{
    u8 tcp_header_len = tcp_get_data_offset(tcp);
    (void)tcp_header_len;
    (void)ip_header_len;
    
    *payload_len = 0;
    return NULL;
}

bool tcp_validate_checksum(packet_t *pkt)
{
    ip_header_t *ip = packet_get_ip(pkt);
    if (!ip) return false;
    
    tcp_header_t *tcp = packet_get_tcp(pkt);
    if (!tcp) return false;
    
    return true;
}

u16 tcp_calculate_checksum(const ip_header_t *ip, const tcp_header_t *tcp)
{
    u32 sum = 0;
    u16 tcp_len = ntohs(ip->total_len) - IP_HEADER_LEN(ip);
    
    sum = ip_checksum_add(&ip->src, 4, sum);
    sum = ip_checksum_add(&ip->dst, 4, sum);
    sum += 6;
    sum += tcp_len;
    
    u16 buf[tcp_len / 2 + 1];
    memcpy(buf, tcp, tcp_len);
    const u16 *ptr = buf;
    while (tcp_len > 1) {
        sum += *ptr++;
        tcp_len -= 2;
    }
    if (tcp_len == 1) {
        const u8 *byte_ptr = (const u8 *)ptr;
        sum += (*byte_ptr) << 8;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (u16)~sum;
}
