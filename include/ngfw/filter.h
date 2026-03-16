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

#ifndef NGFW_FILTER_H
#define NGFW_FILTER_H

#include "types.h"
#include "session.h"
#include "packet.h"

typedef enum {
    FILTER_ACTION_ACCEPT,
    FILTER_ACTION_DROP,
    FILTER_ACTION_REJECT,
    FILTER_ACTION_LOG,
    FILTER_ACTION_ALERT
} filter_action_t;

typedef enum {
    FILTER_DIR_ANY,
    FILTER_DIR_IN,
    FILTER_DIR_OUT,
    FILTER_DIR_FWD
} filter_dir_t;

typedef enum {
    FILTER_PROTO_ANY,
    FILTER_PROTO_TCP,
    FILTER_PROTO_UDP,
    FILTER_PROTO_ICMP,
    FILTER_PROTO_OTHER
} filter_proto_t;

typedef enum {
    FILTER_IP_ANY,
    FILTER_IP_IPV4,
    FILTER_IP_IPV6
} filter_ip_t;

typedef struct filter_rule {
    u32 id;
    filter_action_t action;
    filter_dir_t dir;
    filter_proto_t proto;
    filter_ip_t ip_type;
    u32 src_ip;
    u32 src_mask;
    u32 dst_ip;
    u32 dst_mask;
    u16 src_port_start;
    u16 src_port_end;
    u16 dst_port_start;
    u16 dst_port_end;
    bool enabled;
    u32 priority;
    void *data;
} filter_rule_t;

typedef struct filter_stats {
    u64 packets_accepted;
    u64 packets_dropped;
    u64 packets_rejected;
    u64 bytes_accepted;
    u64 bytes_dropped;
} filter_stats_t;

typedef struct filter filter_t;

filter_t *filter_create(void);
void filter_destroy(filter_t *filter);
ngfw_ret_t filter_add_rule(filter_t *filter, filter_rule_t *rule);
ngfw_ret_t filter_remove_rule(filter_t *filter, u32 rule_id);
ngfw_ret_t filter_enable_rule(filter_t *filter, u32 rule_id);
ngfw_ret_t filter_disable_rule(filter_t *filter, u32 rule_id);

filter_action_t filter_process_packet(filter_t *filter, packet_t *pkt, session_t *session);
filter_stats_t *filter_get_stats(filter_t *filter);
void filter_reset_stats(filter_t *filter);

int filter_match_rule(filter_rule_t *rule, packet_t *pkt);

#endif
