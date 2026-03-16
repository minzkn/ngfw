#include "ngfw/ipv6.h"
#include "ngfw/memory.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

bool ipv6_is_unspecified(const u8 *addr)
{
    if (!addr) return false;
    return addr[0] == 0 && memcmp(addr, &addr[1], 15) == 0;
}

bool ipv6_is_loopback(const u8 *addr)
{
    if (!addr) return false;
    return addr[0] == 0x00 && addr[1] == 0x00 && addr[2] == 0x00 && 
           addr[3] == 0x00 && addr[4] == 0x00 && addr[5] == 0x00 && 
           addr[6] == 0x00 && addr[7] == 0x00 && addr[8] == 0x00 && 
           addr[9] == 0x00 && addr[10] == 0x00 && addr[11] == 0x00 && 
           addr[12] == 0x00 && addr[13] == 0x00 && addr[14] == 0x00 && 
           addr[15] == 0x01;
}

bool ipv6_is_multicast(const u8 *addr)
{
    if (!addr) return false;
    return addr[0] == 0xFF;
}

bool ipv6_is_link_local(const u8 *addr)
{
    if (!addr) return false;
    return addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80;
}

bool ipv6_is_unique_local(const u8 *addr)
{
    if (!addr) return false;
    return (addr[0] & 0xFE) == 0xFC;
}

bool ipv6_is_global_unicast(const u8 *addr)
{
    if (!addr) return false;
    if (ipv6_is_unspecified(addr)) return false;
    if (ipv6_is_loopback(addr)) return false;
    if (ipv6_is_multicast(addr)) return false;
    if (ipv6_is_link_local(addr)) return false;
    if (ipv6_is_unique_local(addr)) return false;
    return true;
}

bool ipv6_is_private(const u8 *addr)
{
    if (!addr) return false;
    if (ipv6_is_link_local(addr)) return true;
    if (ipv6_is_unique_local(addr)) return true;
    if (addr[0] == 0xFE && addr[1] == 0x80) return true;
    return false;
}

bool ipv6_parse(const char *str, u8 *addr)
{
    if (!str || !addr) return false;
    
    struct in6_addr in6;
    if (inet_pton(AF_INET6, str, &in6) != 1) return false;
    
    memcpy(addr, in6.s6_addr, 16);
    return true;
}

char *ipv6_to_string(const u8 *addr, char *buf, size_t len)
{
    if (!addr || !buf || len < 46) return NULL;
    
    struct in6_addr in6;
    memcpy(in6.s6_addr, addr, 16);
    
    if (inet_ntop(AF_INET6, &in6, buf, len) == NULL) return NULL;
    return buf;
}

int ipv6_compare(const u8 *a, const u8 *b)
{
    if (!a || !b) return -1;
    return memcmp(a, b, 16);
}

u32 ipv6_hash(const u8 *addr)
{
    if (!addr) return 0;
    u32 hash = 0;
    for (int i = 0; i < 4; i++) {
        hash ^= ((u32 *)addr)[i];
        hash = (hash << 5) | (hash >> 27);
    }
    return hash;
}

bool ipv6_in_range(const u8 *addr, const u8 *network, u8 prefix_len)
{
    if (!addr || !network || prefix_len > 128) return false;
    
    if (prefix_len == 0) return true;
    
    u8 full_bytes = prefix_len / 8;
    u8 remaining_bits = prefix_len % 8;
    
    if (memcmp(addr, network, full_bytes) != 0) return false;
    
    if (remaining_bits > 0) {
        u8 mask = 0xFF << (8 - remaining_bits);
        if ((addr[full_bytes] & mask) != (network[full_bytes] & mask)) {
            return false;
        }
    }
    
    return true;
}

u8 ipv6_get_scope(const u8 *addr)
{
    if (!addr) return 0;
    
    if (ipv6_is_unspecified(addr)) return 0;
    if (ipv6_is_loopback(addr)) return 1;
    if (ipv6_is_multicast(addr)) return addr[1] & 0x0F;
    if (ipv6_is_link_local(addr)) return 2;
    if (ipv6_is_unique_local(addr)) return 5;
    if (ipv6_is_global_unicast(addr)) return 3;
    
    return 0;
}
