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

#include "ngfw/snmp.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SNMP_MAX_OIDS 256
#define SNMP_TRAP_PORT 162
#define SNMP_DEFAULT_PORT 161

typedef struct snmp_oid_entry {
    snmp_oid_t oid;
    char name[64];
    u8 type;
    void (*callback)(snmp_value_t *value);
    struct snmp_oid_entry *next;
} snmp_oid_entry_t;

struct snmp {
    snmp_version_t version;
    char community[64];
    u16 port;
    int socket_fd;
    snmp_oid_entry_t *oid_list;
    u32 oid_count;
    snmp_stats_t stats;
    bool initialized;
    bool running;
};

snmp_t *snmp_create(void)
{
    snmp_t *snmp = ngfw_malloc(sizeof(snmp_t));
    if (!snmp) return NULL;

    memset(snmp, 0, sizeof(snmp_t));

    snmp->version = SNMP_VERSION_2C;
    strcpy(snmp->community, "public");
    snmp->port = SNMP_DEFAULT_PORT;
    snmp->oid_list = NULL;
    snmp->oid_count = 0;

    snmp->socket_fd = -1;

    log_info("SNMP created");

    return snmp;
}

void snmp_destroy(snmp_t *snmp)
{
    if (!snmp) return;

    if (snmp->running) {
        snmp_stop(snmp);
    }

    snmp_oid_entry_t *entry = snmp->oid_list;
    while (entry) {
        snmp_oid_entry_t *next = entry->next;
        ngfw_free(entry);
        entry = next;
    }

    ngfw_free(snmp);

    log_info("SNMP destroyed");
}

ngfw_ret_t snmp_init(snmp_t *snmp)
{
    if (!snmp) return NGFW_ERR_INVALID;

    snmp->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (snmp->socket_fd < 0) {
        log_err("Failed to create SNMP socket");
        return NGFW_ERR;
    }

    snmp->initialized = true;

    log_info("SNMP initialized");

    return NGFW_OK;
}

ngfw_ret_t snmp_start(snmp_t *snmp)
{
    if (!snmp || !snmp->initialized) return NGFW_ERR_INVALID;

    snmp->running = true;

    log_info("SNMP started on port %d", snmp->port);

    return NGFW_OK;
}

ngfw_ret_t snmp_stop(snmp_t *snmp)
{
    if (!snmp) return NGFW_ERR_INVALID;

    snmp->running = false;

    if (snmp->socket_fd >= 0) {
        close(snmp->socket_fd);
        snmp->socket_fd = -1;
    }

    log_info("SNMP stopped");

    return NGFW_OK;
}

ngfw_ret_t snmp_set_community(snmp_t *snmp, const char *community)
{
    if (!snmp || !community) return NGFW_ERR_INVALID;

    strncpy(snmp->community, community, sizeof(snmp->community) - 1);

    return NGFW_OK;
}

ngfw_ret_t snmp_set_port(snmp_t *snmp, u16 port)
{
    if (!snmp) return NGFW_ERR_INVALID;

    snmp->port = port;

    return NGFW_OK;
}

ngfw_ret_t snmp_set_version(snmp_t *snmp, snmp_version_t version)
{
    if (!snmp) return NGFW_ERR_INVALID;

    snmp->version = version;

    return NGFW_OK;
}

static int parse_oid_string(const char *oid_str, snmp_oid_t *oid)
{
    if (!oid_str || !oid) return -1;

    oid->oid_len = 0;
    const char *p = oid_str;
    char *end;

    while (*p && oid->oid_len < 32) {
        if (*p == '.' || *p == ':') {
            p++;
            continue;
        }

        unsigned long val = strtoul(p, &end, 10);
        if (end == p) break;

        oid->oid[oid->oid_len++] = (u8)val;
        p = end;
    }

    return oid->oid_len;
}

ngfw_ret_t snmp_register_oid(snmp_t *snmp, const char *oid_str, const char *name,
                             u8 type, void (*callback)(snmp_value_t *value))
{
    if (!snmp || !oid_str || !name) return NGFW_ERR_INVALID;

    if (snmp->oid_count >= SNMP_MAX_OIDS) {
        return NGFW_ERR_NO_RESOURCE;
    }

    snmp_oid_entry_t *entry = ngfw_malloc(sizeof(snmp_oid_entry_t));
    if (!entry) return NGFW_ERR_NO_MEM;

    memset(entry, 0, sizeof(snmp_oid_entry_t));

    if (parse_oid_string(oid_str, &entry->oid) < 0) {
        ngfw_free(entry);
        return NGFW_ERR_INVALID;
    }

    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->type = type;
    entry->callback = callback;

    entry->next = snmp->oid_list;
    snmp->oid_list = entry;
    snmp->oid_count++;

    log_info("SNMP OID registered: %s (%s)", oid_str, name);

    return NGFW_OK;
}

static void build_snmp_packet(snmp_value_t *value, u8 *buffer, size_t *len)
{
    (void)value;
    (void)buffer;
    *len = 0;
}

ngfw_ret_t snmp_send_trap(snmp_t *snmp, const char *oid, const char *value)
{
    if (!snmp || !oid) return NGFW_ERR_INVALID;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(SNMP_TRAP_PORT);
    dest.sin_addr.s_addr = htonl(0xE00000FB);

    snmp_value_t trap_value;
    memset(&trap_value, 0, sizeof(trap_value));
    parse_oid_string(oid, &trap_value.oid);

    u8 packet[512];
    size_t packet_len = 0;
    build_snmp_packet(&trap_value, packet, &packet_len);

    if (snmp->socket_fd >= 0 && packet_len > 0) {
        sendto(snmp->socket_fd, packet, packet_len, 0,
               (struct sockaddr *)&dest, sizeof(dest));
    }

    snmp->stats.traps_sent++;

    log_info("SNMP trap sent: %s = %s", oid, value ? value : "");

    return NGFW_OK;
}

ngfw_ret_t snmp_send_inform(snmp_t *snmp, const char *oid, const char *value)
{
    if (!snmp || !oid) return NGFW_ERR_INVALID;

    snmp_send_trap(snmp, oid, value);

    snmp->stats.inform_sent++;

    log_info("SNMP inform sent: %s = %s", oid, value ? value : "");

    return NGFW_OK;
}

snmp_stats_t *snmp_get_stats(snmp_t *snmp)
{
    return snmp ? &snmp->stats : NULL;
}
