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

#ifndef NGFW_IPV6_H
#define NGFW_IPV6_H

#include "ngfw/types.h"
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>

bool ipv6_is_unspecified(const u8 *addr);
bool ipv6_is_loopback(const u8 *addr);
bool ipv6_is_multicast(const u8 *addr);
bool ipv6_is_link_local(const u8 *addr);
bool ipv6_is_unique_local(const u8 *addr);
bool ipv6_is_global_unicast(const u8 *addr);
bool ipv6_is_private(const u8 *addr);
bool ipv6_parse(const char *str, u8 *addr);
char *ipv6_to_string(const u8 *addr, char *buf, size_t len);
int ipv6_compare(const u8 *a, const u8 *b);
u32 ipv6_hash(const u8 *addr);
bool ipv6_in_range(const u8 *addr, const u8 *network, u8 prefix_len);
u8 ipv6_get_scope(const u8 *addr);

#define IPV6_ADDR_SIZE 16
#define IPV6_PREFIX_MAX 128

#endif
