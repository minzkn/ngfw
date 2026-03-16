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

#define ICMP_TYPE_ECHO_REPLY    0
#define ICMP_TYPE_DEST_UNREACH  3
#define ICMP_TYPE_SRC_QUENCH    4
#define ICMP_TYPE_REDIRECT      5
#define ICMP_TYPE_ECHO_REQUEST  8
#define ICMP_TYPE_ROUTER_ADV    9
#define ICMP_TYPE_ROUTER_SOL    10
#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_TYPE_PARAM_PROB    12
#define ICMP_TYPE_TIMESTAMP_REQ 13
#define ICMP_TYPE_TIMESTAMP_REP 14

u8 icmp_get_type(icmp_header_t *icmp)
{
    return icmp->type;
}

u8 icmp_get_code(icmp_header_t *icmp)
{
    return icmp->code;
}

u16 icmp_get_checksum(icmp_header_t *icmp)
{
    return ntohs(icmp->checksum);
}

bool icmp_is_echo_request(icmp_header_t *icmp)
{
    return icmp->type == ICMP_TYPE_ECHO_REQUEST;
}

bool icmp_is_echo_reply(icmp_header_t *icmp)
{
    return icmp->type == ICMP_TYPE_ECHO_REPLY;
}

bool icmp_is_destination_unreachable(icmp_header_t *icmp)
{
    return icmp->type == ICMP_TYPE_DEST_UNREACH;
}

bool icmp_is_time_exceeded(icmp_header_t *icmp)
{
    return icmp->type == ICMP_TYPE_TIME_EXCEEDED;
}

u16 icmp_calculate_checksum(icmp_header_t *icmp, u32 len)
{
    return ip_checksum(icmp, len);
}

bool icmp_validate_checksum(icmp_header_t *icmp, u32 len)
{
    u16 checksum = icmp_get_checksum(icmp);
    icmp->checksum = 0;
    
    u16 calculated = icmp_calculate_checksum(icmp, len);
    icmp->checksum = checksum;
    
    return checksum == calculated;
}
