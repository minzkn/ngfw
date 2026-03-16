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

#ifndef NGFW_PIPELINE_H
#define NGFW_PIPELINE_H

#include "types.h"
#include "packet.h"
#include "session.h"
#include "filter.h"
#include "ips.h"

typedef enum {
    PIPELINE_STAGE_PRE_ROUTING,
    PIPELINE_STAGE_FORWARD,
    PIPELINE_STAGE_INPUT,
    PIPELINE_STAGE_OUTPUT,
    PIPELINE_STAGE_POST_ROUTING
} pipeline_stage_t;

typedef enum {
    PIPELINE_ACTION_CONTINUE,
    PIPELINE_ACTION_DROP,
    PIPELINE_ACTION_ACCEPT,
    PIPELINE_ACTION_REJECT,
    PIPELINE_ACTION_QUEUE,
    PIPELINE_ACTION_LOG
} pipeline_action_t;

typedef struct pipeline_context {
    packet_t *packet;
    session_t *session;
    pipeline_stage_t stage;
    pipeline_action_t action;
    u32 rule_id;
    u32 session_id;
    bool nat_applied;
    bool qos_applied;
    bool vpn_decrypted;
    bool ips_checked;
    bool url_checked;
    u64 timestamp;
    void *user_data;
} pipeline_context_t;

typedef pipeline_action_t (*pipeline_hook_t)(pipeline_context_t *ctx);

typedef struct pipeline_stage_node {
    pipeline_stage_t stage;
    pipeline_hook_t hook;
    void *data;
    struct pipeline_stage_node *next;
} pipeline_stage_node_t;

typedef struct pipeline_stats {
    u64 packets_processed;
    u64 packets_accepted;
    u64 packets_dropped;
    u64 packets_rejected;
    u64 packets_queued;
    u64 sessions_created;
    u64 nat_translations;
    u64 qos_classified;
    u64 ips_alerts;
    u64 url_blocked;
    u64 vpn_processed;
    u64 bytes_processed;
} pipeline_stats_t;

typedef struct pipeline pipeline_t;

pipeline_t *pipeline_create(void);
pipeline_t *pipeline_create_ex(u32 num_stages);
void pipeline_destroy(pipeline_t *pipeline);

ngfw_ret_t pipeline_init(pipeline_t *pipeline);
ngfw_ret_t pipeline_start(pipeline_t *pipeline);
ngfw_ret_t pipeline_stop(pipeline_t *pipeline);

ngfw_ret_t pipeline_register_hook(pipeline_t *pipeline, pipeline_stage_t stage, pipeline_hook_t hook, void *data);
ngfw_ret_t pipeline_unregister_hook(pipeline_t *pipeline, pipeline_stage_t stage, pipeline_hook_t hook);

ngfw_ret_t pipeline_process_packet(pipeline_t *pipeline, packet_t *pkt, pipeline_stage_t stage);

pipeline_stats_t *pipeline_get_stats(pipeline_t *pipeline);
void pipeline_reset_stats(pipeline_t *pipeline);

#endif
