#include "ngfw/protocols.h"
#include "ngfw/memory.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86DD
#define ETH_TYPE_ARP 0x0806

static const char *protocol_names[] = {
    "ethernet", "ipv4", "ipv6", "tcp", "udp", "icmp", "icmpv6",
    "arp", "dns", "http", "https", "tls", "ssh", "ftp", "smtp", "unknown"
};

protocol_decoder_t *protocol_decoder_create(void)
{
    protocol_decoder_t *decoder = ngfw_malloc(sizeof(protocol_decoder_t));
    if (!decoder) return NULL;
    
    decoder->handlers = NULL;
    return decoder;
}

void protocol_decoder_destroy(protocol_decoder_t *decoder)
{
    if (!decoder) return;
    
    protocol_handler_t *handler = decoder->handlers;
    while (handler) {
        protocol_handler_t *next = handler->next;
        ngfw_free(handler);
        handler = next;
    }
    
    ngfw_free(decoder);
}

ngfw_ret_t protocol_decoder_register(protocol_decoder_t *decoder, protocol_type_t type, decode_fn fn)
{
    if (!decoder || !fn) return NGFW_ERR_INVALID;
    
    protocol_handler_t *handler = ngfw_malloc(sizeof(protocol_handler_t));
    if (!handler) return NGFW_ERR_NO_MEM;
    
    handler->type = type;
    handler->decode = fn;
    handler->next = decoder->handlers;
    decoder->handlers = handler;
    
    return NGFW_OK;
}

ngfw_ret_t protocol_decoder_decode(protocol_decoder_t *decoder, const u8 *data, u32 len, protocol_info_t *info, u32 *num_info)
{
    if (!decoder || !data || !info || !num_info) return NGFW_ERR_INVALID;
    
    *num_info = 0;
    u32 offset = 0;
    u32 count = 0;
    
    if (len < 14) return NGFW_ERR_INVALID;
    
    info[count].type = PROTO_ETHERNET;
    info[count].offset = 0;
    info[count].length = 14;
    info[count].header = (void *)data;
    count++;
    
    u16 eth_type = (data[12] << 8) | data[13];
    offset = 14;
    
    if (eth_type == ETH_TYPE_IPV4 && len >= offset + 20) {
        u8 ip_version = (data[offset] >> 4) & 0x0F;
        if (ip_version == 4) {
            u8 ip_header_len = (data[offset] & 0x0F) * 4;
            
            info[count].type = PROTO_IPV4;
            info[count].offset = offset;
            info[count].length = ip_header_len;
            info[count].header = (void *)(data + offset);
            count++;
            
            u8 proto = data[offset + 9];
            offset += ip_header_len;
            
            if (proto == 6 && len >= offset + 20) {
                info[count].type = PROTO_TCP;
                info[count].offset = offset;
                info[count].length = 20;
                info[count].header = (void *)(data + offset);
                count++;
            } else if (proto == 17 && len >= offset + 8) {
                info[count].type = PROTO_UDP;
                info[count].offset = offset;
                info[count].length = 8;
                info[count].header = (void *)(data + offset);
                count++;
            } else if (proto == 1) {
                info[count].type = PROTO_ICMP;
                info[count].offset = offset;
                info[count].length = 8;
                info[count].header = (void *)(data + offset);
                count++;
            }
        }
    } else if (eth_type == ETH_TYPE_IPV6 && len >= offset + 40) {
        info[count].type = PROTO_IPV6;
        info[count].offset = offset;
        info[count].length = 40;
        info[count].header = (void *)(data + offset);
        count++;
        
        u8 next_header = data[offset + 6];
        offset += 40;
        
        if (next_header == 6 && len >= offset + 20) {
            info[count].type = PROTO_TCP;
            info[count].offset = offset;
            info[count].length = 20;
            info[count].header = (void *)(data + offset);
            count++;
        } else if (next_header == 17 && len >= offset + 8) {
            info[count].type = PROTO_UDP;
            info[count].offset = offset;
            info[count].length = 8;
            info[count].header = (void *)(data + offset);
            count++;
        }
    } else if (eth_type == ETH_TYPE_ARP && len >= offset + 28) {
        info[count].type = PROTO_ARP;
        info[count].offset = offset;
        info[count].length = 28;
        info[count].header = (void *)(data + offset);
        count++;
    }
    
    *num_info = count;
    return NGFW_OK;
}

protocol_type_t protocol_detect_ethernet(const u8 *data, u32 len)
{
    if (!data || len < 14) return PROTO_UNKNOWN;
    return PROTO_ETHERNET;
}

protocol_type_t protocol_detect_ipv4(const u8 *data, u32 len)
{
    if (!data || len < 20) return PROTO_UNKNOWN;
    if ((data[0] >> 4) == 4) return PROTO_IPV4;
    return PROTO_UNKNOWN;
}

protocol_type_t protocol_detect_ipv6(const u8 *data, u32 len)
{
    if (!data || len < 40) return PROTO_UNKNOWN;
    if ((data[0] >> 4) == 6) return PROTO_IPV6;
    return PROTO_UNKNOWN;
}

protocol_type_t protocol_detect_transport(const u8 *data, u32 len, protocol_type_t ip_type)
{
    if (!data || len < 1) return PROTO_UNKNOWN;
    
    if (ip_type == PROTO_IPV4) {
        if (len < 1) return PROTO_UNKNOWN;
        u8 proto = data[9];
        if (proto == 6) return PROTO_TCP;
        if (proto == 17) return PROTO_UDP;
        if (proto == 1) return PROTO_ICMP;
    }
    
    return PROTO_UNKNOWN;
}

const char *protocol_name(protocol_type_t type)
{
    if (type >= PROTO_UNKNOWN) return "unknown";
    return protocol_names[type];
}

protocol_type_t protocol_from_name(const char *name)
{
    if (!name) return PROTO_UNKNOWN;
    
    for (int i = 0; i <= PROTO_UNKNOWN; i++) {
        if (strcmp(name, protocol_names[i]) == 0) {
            return (protocol_type_t)i;
        }
    }
    
    return PROTO_UNKNOWN;
}
