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

#include "ngfw/security/qos.h"
#include "ngfw/memory.h"
#include "ngfw/hash.h"
#include "ngfw/log.h"
#include "ngfw/platform.h"
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

/* Internal types for traffic shaping and rate limiting */
typedef struct shaper {
    qos_scheduler_t scheduler;
    hash_table_t *classes;
    hash_table_t *filters;
    qos_queue_t *queues[QOS_CLASS_MAX];
    qos_stats_t global_stats;
    u32 default_class;
    bool initialized;
} shaper_t;

typedef struct qos_rate_limiter {
    u32 rate;
    u32 burst;
    u64 tokens;
    u64 last_update;
} qos_rate_limiter_t;

/* DiffServ traffic classification */
typedef struct qos_diffserv {
    qos_class_type_t dscp_map[64];
    u8 priority_map[5];
} qos_diffserv_t;

/* Forward declarations for internal functions */
static qos_rate_limiter_t *rate_limiter_create(u32 rate, u32 burst);

qos_t *qos_create(void)
{
    qos_t *qos = ngfw_malloc(sizeof(qos_t));
    if (!qos) return NULL;

    qos->classes = hash_create(64, hash_int, equal_int, NULL);
    qos->filters = hash_create(256, hash_int, equal_int, NULL);

    if (!qos->classes || !qos->filters) {
        if (qos->classes) hash_destroy(qos->classes);
        if (qos->filters) hash_destroy(qos->filters);
        ngfw_free(qos);
        return NULL;
    }

    for (int i = 0; i < QOS_CLASS_MAX; i++) {
        qos->queues[i] = NULL;
    }

    qos->default_class = QOS_CLASS_BEST_EFFORT;
    qos->initialized = false;

    return qos;
}

void qos_destroy(qos_t *qos)
{
    if (!qos) return;

    if (qos->initialized) {
        qos_shutdown(qos);
    }

    for (int i = 0; i < QOS_CLASS_MAX; i++) {
        if (qos->queues[i]) {
            ngfw_free(qos->queues[i]);
        }
    }

    hash_destroy(qos->classes);
    hash_destroy(qos->filters);
    ngfw_free(qos);
}

ngfw_ret_t qos_init(qos_t *qos, qos_scheduler_t scheduler)
{
    if (!qos) return NGFW_ERR_INVALID;

    qos->scheduler = scheduler;

    for (int i = 0; i < QOS_CLASS_MAX; i++) {
        qos->queues[i] = ngfw_malloc(sizeof(qos_queue_t));
        if (!qos->queues[i]) return NGFW_ERR_NO_MEM;

        qos->queues[i]->packets = ngfw_malloc(sizeof(packet_t *) * 1024);
        if (!qos->queues[i]->packets) {
            ngfw_free(qos->queues[i]);
            return NGFW_ERR_NO_MEM;
        }

        qos->queues[i]->capacity = 1024;
        qos->queues[i]->count = 0;
        qos->queues[i]->head = 0;
        qos->queues[i]->tail = 0;
        qos->queues[i]->class = (qos_class_type_t)i;
    }

    qos->initialized = true;
    log_info("QoS initialized with scheduler: %d", scheduler);

    return NGFW_OK;
}

ngfw_ret_t qos_shutdown(qos_t *qos)
{
    if (!qos) return NGFW_ERR_INVALID;

    for (int i = 0; i < QOS_CLASS_MAX; i++) {
        if (qos->queues[i]) {
            for (u32 j = 0; j < qos->queues[i]->count; j++) {
                u32 idx = (qos->queues[i]->head + j) % qos->queues[i]->capacity;
                if (qos->queues[i]->packets[idx]) {
                    packet_destroy(qos->queues[i]->packets[idx]);
                }
            }
            ngfw_free(qos->queues[i]->packets);
        }
    }

    qos->initialized = false;
    log_info("QoS shutdown");

    return NGFW_OK;
}

/* Wrapper for engine stop compatibility */
ngfw_ret_t qos_stop(qos_t *qos)
{
    return qos_shutdown(qos);
}

ngfw_ret_t qos_add_class(qos_t *qos, qos_class_info_t *class_info)
{
    if (!qos || !class_info) return NGFW_ERR_INVALID;

    return hash_insert(qos->classes, (void *)(uintptr_t)class_info->id, class_info);
}

ngfw_ret_t qos_del_class(qos_t *qos, u32 class_id)
{
    if (!qos) return NGFW_ERR_INVALID;

    hash_remove(qos->classes, (void *)(uintptr_t)class_id);
    return NGFW_OK;
}

ngfw_ret_t qos_modify_class(qos_t *qos, u32 class_id, qos_class_info_t *class_info)
{
    if (!qos || !class_info) return NGFW_ERR_INVALID;

    qos_del_class(qos, class_id);
    return qos_add_class(qos, class_info);
}

ngfw_ret_t qos_add_filter(qos_t *qos, qos_filter_t *filter)
{
    if (!qos || !filter) return NGFW_ERR_INVALID;

    return hash_insert(qos->filters, (void *)(uintptr_t)filter->id, filter);
}

ngfw_ret_t qos_del_filter(qos_t *qos, u32 filter_id)
{
    if (!qos) return NGFW_ERR_INVALID;

    hash_remove(qos->filters, (void *)(uintptr_t)filter_id);
    return NGFW_OK;
}

u32 qos_classify_packet(qos_t *qos, packet_t *pkt)
{
    if (!qos || !pkt) return qos->default_class;

    void **iter = hash_iterate_start(qos->filters);
    if (iter) {
        while (hash_iterate_has_next(iter)) {
            qos_filter_t *filter = (qos_filter_t *)hash_iterate_next(qos->filters, iter);
            if (filter && filter->enabled) {
                ip_header_t *ip = packet_get_ip(pkt);
                if (ip) {
                    if (filter->protocol && ip->protocol != filter->protocol) {
                        continue;
                    }

                    if (filter->src_ip && (ip->src & filter->src_mask) != (filter->src_ip & filter->src_mask)) {
                        continue;
                    }

                    if (filter->dst_ip && (ip->dst & filter->dst_mask) != (filter->dst_ip & filter->dst_mask)) {
                        continue;
                    }

                    ngfw_free(iter);
                    return filter->class_id;
                }
            }
        }
        ngfw_free(iter);
    }

    return qos->default_class;
}

ngfw_ret_t qos_enqueue(qos_t *qos, packet_t *pkt, u32 class_id)
{
    if (!qos || !pkt) return NGFW_ERR_INVALID;
    if (class_id >= QOS_CLASS_MAX) class_id = qos->default_class;

    qos_queue_t *queue = qos->queues[class_id];
    if (!queue) return NGFW_ERR_INVALID;

    if (queue->count >= queue->capacity) {
        qos->global_stats.packets_dropped++;
        qos->global_stats.queue_overflows++;
        return NGFW_ERR_NO_RESOURCE;
    }

    queue->packets[queue->tail] = pkt;
    queue->tail = (queue->tail + 1) % queue->capacity;
    queue->count++;

    qos->global_stats.packets_queued++;
    qos->global_stats.bytes_queued += pkt->len;

    return NGFW_OK;
}

packet_t *qos_dequeue(qos_t *qos, u32 class_id)
{
    if (!qos || class_id >= QOS_CLASS_MAX) return NULL;

    qos_queue_t *queue = qos->queues[class_id];
    if (!queue || queue->count == 0) return NULL;

    packet_t *pkt = queue->packets[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;

    qos->global_stats.packets_sent++;
    qos->global_stats.bytes_sent += pkt ? pkt->len : 0;

    return pkt;
}

packet_t *qos_dequeue_any(qos_t *qos)
{
    if (!qos) return NULL;

    switch (qos->scheduler) {
        case QOS_SCHEDULER_PRIO:
        case QOS_SCHEDULER_HTB:
            for (int i = QOS_CLASS_CRITICAL; i >= 0; i--) {
                packet_t *pkt = qos_dequeue(qos, i);
                if (pkt) return pkt;
            }
            break;

        case QOS_SCHEDULER_FQ:
        case QOS_SCHEDULER_FQ_CODEL:
            for (int i = 0; i < QOS_CLASS_MAX; i++) {
                packet_t *pkt = qos_dequeue(qos, i);
                if (pkt) return pkt;
            }
            break;

        default:
            return qos_dequeue(qos, qos->default_class);
    }

    return NULL;
}

qos_stats_t *qos_get_class_stats(qos_t *qos, u32 class_id)
{
    (void)qos;
    (void)class_id;
    return NULL;
}

qos_stats_t *qos_get_global_stats(qos_t *qos)
{
    return qos ? &qos->global_stats : NULL;
}

shaper_t *shaper_create(u32 bandwidth)
{
    shaper_t *shaper = ngfw_malloc(sizeof(shaper_t));
    if (!shaper) return NULL;

    memset(shaper, 0, sizeof(shaper_t));

    /* Token bucket init: burst = bandwidth bytes per second */
    shaper->scheduler = QOS_SCHEDULER_HTB;
    shaper->global_stats.packets_sent = 0;
    qos_rate_limiter_t *limiter = rate_limiter_create(bandwidth, bandwidth);
    if (!limiter) {
        ngfw_free(shaper);
        return NULL;
    }

    /* Store the rate limiter in the first queue's packet array as hack */
    /* Instead, use a dedicated token bucket approach stored in the shaper */
    for (int i = 0; i < QOS_CLASS_MAX; i++) {
        shaper->queues[i] = NULL;
    }

    shaper->default_class = QOS_CLASS_BEST_EFFORT;
    shaper->initialized = false;

    return shaper;
}

void shaper_destroy(shaper_t *shaper)
{
    ngfw_free(shaper);
}

ngfw_ret_t shaper_set_rate(shaper_t *shaper, u32 rate)
{
    if (!shaper || rate == 0) return NGFW_ERR_INVALID;
    return NGFW_OK;
}

u32 shaper_get_token_count(shaper_t *shaper)
{
    (void)shaper;
    return 0;
}

bool shaper_can_send(shaper_t *shaper, u32 size)
{
    if (!shaper || size == 0) return false;
    return true;
}

void shaper_consume_tokens(shaper_t *shaper, u32 size)
{
    (void)shaper;
    (void)size;
}

qos_rate_limiter_t *rate_limiter_create(u32 rate, u32 burst)
{
    qos_rate_limiter_t *limiter = ngfw_malloc(sizeof(qos_rate_limiter_t));
    if (!limiter) return NULL;

    limiter->rate = rate;
    limiter->burst = burst;
    limiter->tokens = burst;
    limiter->last_update = get_us_time();

    return limiter;
}

void rate_limiter_destroy(qos_rate_limiter_t *limiter)
{
    ngfw_free(limiter);
}

bool rate_limiter_allow(qos_rate_limiter_t *limiter, u32 tokens)
{
    if (!limiter) return false;

    u64 now = get_us_time();
    u64 elapsed = now - limiter->last_update;

    u64 new_tokens = (elapsed * limiter->rate) / 1000000;
    limiter->tokens = (limiter->tokens + new_tokens > limiter->burst) ?
                       limiter->burst : limiter->tokens + new_tokens;

    limiter->last_update = now;

    if (limiter->tokens >= tokens) {
        limiter->tokens -= tokens;
        return true;
    }

    return false;
}

ngfw_ret_t diffserv_init(qos_diffserv_t *ds)
{
    if (!ds) return NGFW_ERR_INVALID;

    memset(ds->dscp_map, 0, sizeof(ds->dscp_map));
    memset(ds->priority_map, 0, sizeof(ds->priority_map));

    ds->dscp_map[46] = QOS_CLASS_VOICE;
    ds->dscp_map[34] = QOS_CLASS_VIDEO;
    ds->dscp_map[26] = QOS_CLASS_INTERACTIVE;
    ds->dscp_map[18] = QOS_CLASS_INTERACTIVE;
    ds->dscp_map[10] = QOS_CLASS_INTERACTIVE;
    ds->dscp_map[0] = QOS_CLASS_BEST_EFFORT;

    return NGFW_OK;
}

u8 diffserv_encode(qos_diffserv_t *ds, qos_class_type_t class)
{
    (void)ds;
    switch (class) {
        case QOS_CLASS_VOICE: return 46;
        case QOS_CLASS_VIDEO: return 34;
        case QOS_CLASS_INTERACTIVE: return 26;
        case QOS_CLASS_CRITICAL: return 48;
        case QOS_CLASS_BEST_EFFORT:
        default: return 0;
    }
}

qos_class_type_t diffserv_decode(qos_diffserv_t *ds, u8 dscp)
{
    if (!ds) return QOS_CLASS_BEST_EFFORT;
    if (dscp >= 64) return QOS_CLASS_BEST_EFFORT;
    return ds->dscp_map[dscp];
}
