#include "ngfw/packet.h"
#include <stddef.h>
#include <string.h>
#include <netinet/in.h>

u16 udp_get_length(udp_header_t *udp)
{
    return ntohs(udp->len);
}

u16 udp_get_checksum(udp_header_t *udp)
{
    return ntohs(udp->checksum);
}

bool udp_validate_checksum(packet_t *pkt)
{
    ip_header_t *ip = packet_get_ip(pkt);
    if (!ip) return false;
    
    udp_header_t *udp = packet_get_udp(pkt);
    if (!udp) return false;
    
    return true;
}

u16 udp_calculate_checksum(const ip_header_t *ip, const udp_header_t *udp)
{
    u32 sum = 0;
    
    sum = ip_checksum_add(&ip->src, 4, sum);
    sum = ip_checksum_add(&ip->dst, 4, sum);
    sum += IP_PROTO_UDP;
    sum += udp->len;
    
    u32 len = ntohs(udp->len);
    u16 buf[len / 2 + 1];
    memcpy(buf, udp, len);
    const u16 *ptr = buf;
    
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    
    if (len == 1) {
        const u8 *byte_ptr = (const u8 *)ptr;
        sum += (*byte_ptr) << 8;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (u16)~sum;
}
