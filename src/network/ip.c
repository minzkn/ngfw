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
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>

u16 ip_checksum(const void *data, u32 len)
{
    const u16 *ptr = data;
    u32 sum = 0;
    
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(const u8 *)ptr;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (u16)~sum;
}

u16 ip_checksum_add(const void *data, u32 len, u32 sum)
{
    const u16 *ptr = data;
    
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(const u8 *)ptr;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (u16)sum;
}

u32 ip_parse_mask(const char *mask)
{
    if (!mask) return 0;
    
    if (strchr(mask, '.')) {
        return 0;
    }
    
    int bits = atoi(mask);
    if (bits < 0 || bits > 32) return 0;
    
    if (bits == 0) return 0;
    return htonl(0xFFFFFFFF << (32 - bits));
}

bool ip_in_range(u32 ip, u32 network, u32 mask)
{
    return (ip & mask) == (network & mask);
}

bool ip_is_private(u32 ip)
{
    u8 b1 = (ip >> 24) & 0xFF;
    u8 b2 = (ip >> 16) & 0xFF;
    
    if (b1 == 10) return true;
    if (b1 == 172 && b2 >= 16 && b2 <= 31) return true;
    if (b1 == 192 && b2 == 168) return true;
    if (b1 == 127) return true;
    
    return false;
}

bool ip_is_unicast(u32 ip)
{
    u8 b1 = (ip >> 24) & 0xFF;
    
    if (b1 == 0) return false;
    if (b1 == 255) return false;
    
    return true;
}

void ip_format(u32 ip, char *buf, size_t len)
{
    snprintf(buf, len, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF,
             ip & 0xFF);
}

u32 ip_parse(const char *str)
{
    u32 ip = 0;
    int parts[4];
    int count = sscanf(str, "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]);
    
    if (count != 4) return 0;
    
    for (int i = 0; i < 4; i++) {
        if (parts[i] < 0 || parts[i] > 255) return 0;
        ip = (ip << 8) | parts[i];
    }
    
    return ip;
}
