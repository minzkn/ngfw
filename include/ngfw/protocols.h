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

#ifndef NGFW_PROTOCOLS_H
#define NGFW_PROTOCOLS_H

#include "ngfw/types.h"
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    PROTO_ETHERNET,
    PROTO_IPV4,
    PROTO_IPV6,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_ICMPV6,
    PROTO_ARP,
    PROTO_DNS,
    PROTO_HTTP,
    PROTO_HTTPS,
    PROTO_TLS,
    PROTO_SSH,
    PROTO_FTP,
    PROTO_SMTP,
    PROTO_UNKNOWN
} protocol_type_t;

typedef struct protocol_info {
    protocol_type_t type;
    u32 offset;
    u32 length;
    void *header;
} protocol_info_t;

typedef struct protocol_decoder protocol_decoder_t;

typedef ngfw_ret_t (*decode_fn)(const u8 *data, u32 len, protocol_info_t *info);

typedef struct protocol_handler {
    protocol_type_t type;
    decode_fn decode;
    struct protocol_handler *next;
} protocol_handler_t;

struct protocol_decoder {
    protocol_handler_t *handlers;
};

protocol_decoder_t *protocol_decoder_create(void);
void protocol_decoder_destroy(protocol_decoder_t *decoder);
ngfw_ret_t protocol_decoder_register(protocol_decoder_t *decoder, protocol_type_t type, decode_fn fn);
ngfw_ret_t protocol_decoder_decode(protocol_decoder_t *decoder, const u8 *data, u32 len, protocol_info_t *info, u32 *num_info);

protocol_type_t protocol_detect_ethernet(const u8 *data, u32 len);
protocol_type_t protocol_detect_ipv4(const u8 *data, u32 len);
protocol_type_t protocol_detect_ipv6(const u8 *data, u32 len);
protocol_type_t protocol_detect_transport(const u8 *data, u32 len, protocol_type_t ip_type);

const char *protocol_name(protocol_type_t type);
protocol_type_t protocol_from_name(const char *name);

#endif
