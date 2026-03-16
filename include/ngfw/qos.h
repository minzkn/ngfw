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

#ifndef NGFW_QOS_H
#define NGFW_QOS_H

#include "types.h"
#include "packet.h"

typedef enum {
    QOS_SCHEDULER_FIFO,
    QOS_SCHEDULER_PRIO,
    QOS_SCHEDULER_CBQ,
    QOS_SCHEDULER_HTB,
    QOS_SCHEDULER_FQ_CODEL,
    QOS_SCHEDULER_FQ
} qos_scheduler_t;

typedef enum {
    QOS_CLASS_BEST_EFFORT,
    QOS_CLASS_INTERACTIVE,
    QOS_CLASS_VIDEO,
    QOS_CLASS_VOICE,
    QOS_CLASS_CRITICAL,
    QOS_CLASS_MAX
} qos_class_type_t;

typedef enum {
    QOS_POLICY_DROP,
    QOS_POLICE_RATE,
    QOS_POLICE_PEAK
} qos_police_t;

typedef struct qos_class {
    u32 id;
    char name[64];
    qos_class_type_t type;
    u32 parent_id;
    u32 bandwidth_min;
    u32 bandwidth_max;
    u32 burst;
    u32 priority;
    u32 weight;
    bool enabled;
} qos_class_info_t;

typedef struct qos_filter {
    u32 id;
    u32 class_id;
    u8 protocol;
    u16 src_port_min;
    u16 src_port_max;
    u16 dst_port_min;
    u16 dst_port_max;
    u32 src_ip;
    u32 src_mask;
    u32 dst_ip;
    u32 dst_mask;
    u8 tos;
    bool enabled;
} qos_filter_t;

typedef struct qos_stats {
    u64 packets_queued;
    u64 packets_dropped;
    u64 packets_sent;
    u64 bytes_queued;
    u64 bytes_dropped;
    u64 bytes_sent;
    u64 queue_overflows;
} qos_stats_t;

typedef struct qos_queue {
    packet_t **packets;
    u32 capacity;
    u32 count;
    u32 head;
    u32 tail;
    qos_class_type_t class;
} qos_queue_t;

typedef struct qos qos_t;

qos_t *qos_create(void);
void qos_destroy(qos_t *qos);

ngfw_ret_t qos_init(qos_t *qos, qos_scheduler_t scheduler);
ngfw_ret_t qos_shutdown(qos_t *qos);

ngfw_ret_t qos_add_class(qos_t *qos, qos_class_info_t *class_info);
ngfw_ret_t qos_del_class(qos_t *qos, u32 class_id);
ngfw_ret_t qos_modify_class(qos_t *qos, u32 class_id, qos_class_info_t *class_info);

ngfw_ret_t qos_add_filter(qos_t *qos, qos_filter_t *filter);
ngfw_ret_t qos_del_filter(qos_t *qos, u32 filter_id);

u32 qos_classify_packet(qos_t *qos, packet_t *pkt);

ngfw_ret_t qos_enqueue(qos_t *qos, packet_t *pkt, u32 class_id);
packet_t *qos_dequeue(qos_t *qos, u32 class_id);
packet_t *qos_dequeue_any(qos_t *qos);

qos_stats_t *qos_get_class_stats(qos_t *qos, u32 class_id);
qos_stats_t *qos_get_global_stats(qos_t *qos);

typedef struct qos shaper_t;

shaper_t *shaper_create(u32 bandwidth);
void shaper_destroy(shaper_t *shaper);

ngfw_ret_t shaper_set_rate(shaper_t *shaper, u32 rate);
u32 shaper_get_token_count(shaper_t *shaper);
bool shaper_can_send(shaper_t *shaper, u32 size);
void shaper_consume_tokens(shaper_t *shaper, u32 size);

typedef struct qos_rate_limiter {
    u32 rate;
    u32 burst;
    u64 tokens;
    u64 last_update;
} qos_rate_limiter_t;

qos_rate_limiter_t *rate_limiter_create(u32 rate, u32 burst);
void rate_limiter_destroy(qos_rate_limiter_t *limiter);
bool rate_limiter_allow(qos_rate_limiter_t *limiter, u32 tokens);

typedef struct qos_diffserv {
    u8 dscp_map[64];
    u8 priority_map[8];
} qos_diffserv_t;

ngfw_ret_t diffserv_init(qos_diffserv_t *ds);
u8 diffserv_encode(qos_diffserv_t *ds, qos_class_type_t class);
qos_class_type_t diffserv_decode(qos_diffserv_t *ds, u8 dscp);

#endif
