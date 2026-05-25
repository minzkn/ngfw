/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_SECURITY_QOS_H
#define NGFW_SECURITY_QOS_H

#include "ngfw/types.h"
#include "ngfw/network/packet.h"
#include "ngfw/hash.h"

/*
 * Quality of Service
 * Traffic shaping and prioritization
 */

typedef enum {
    QOS_SCHEDULER_FIFO,
    QOS_SCHEDULER_PRIO,
    QOS_SCHEDULER_HTB,
    QOS_SCHEDULER_FQ,
    QOS_SCHEDULER_FQ_CODEL
} qos_scheduler_t;

typedef enum {
    QOS_CLASS_BEST_EFFORT,
    QOS_CLASS_INTERACTIVE,
    QOS_CLASS_VIDEO,
    QOS_CLASS_VOICE,
    QOS_CLASS_CRITICAL,
    QOS_CLASS_MAX
} qos_class_type_t;

/* QoS queue - ring buffer of packet pointers */
typedef struct qos_queue {
    struct packet **packets;
    u32 capacity;
    u32 count;
    u32 head;
    u32 tail;
    qos_class_type_t class;
    u32 bandwidth;
    u32 priority;
    u32 quantum;
    u64 bytes_queued;
    u64 bytes_dropped;
    u64 bytes_sent;
} qos_queue_t;

/* QoS filter */
typedef struct qos_filter {
    u32 id;
    u32 class_id;
    u8 protocol;
    u32 src_ip;
    u32 src_mask;
    u32 dst_ip;
    u32 dst_mask;
    u16 src_port;
    u16 dst_port;
    u32 dscp;
    bool enabled;
    u32 priority;
    u64 hits;
} qos_filter_t;

/* QoS class info */
typedef struct qos_class_info {
    u32 id;
    char name[64];
    u32 bandwidth;
    u32 priority;
    u32 quantum;
} qos_class_info_t;

typedef struct qos_stats {
    u64 packets_queued;
    u64 packets_dropped;
    u64 packets_sent;
    u64 bytes_queued;
    u64 bytes_dropped;
    u64 bytes_sent;
    u64 queue_overflows;
} qos_stats_t;

typedef struct qos {
    qos_scheduler_t scheduler;
    hash_table_t *classes;
    hash_table_t *filters;
    qos_queue_t *queues[QOS_CLASS_MAX];
    qos_stats_t global_stats;
    u32 default_class;
    bool initialized;
} qos_t;

qos_t *qos_create(void);
void qos_destroy(qos_t *qos);

ngfw_ret_t qos_init(qos_t *qos, qos_scheduler_t scheduler);
ngfw_ret_t qos_shutdown(qos_t *qos);
ngfw_ret_t qos_stop(qos_t *qos);

ngfw_ret_t qos_add_class(qos_t *qos, qos_class_info_t *class_info);
ngfw_ret_t qos_modify_class(qos_t *qos, u32 class_id, qos_class_info_t *class_info);
ngfw_ret_t qos_del_class(qos_t *qos, u32 class_id);

ngfw_ret_t qos_add_filter(qos_t *qos, qos_filter_t *filter);
ngfw_ret_t qos_del_filter(qos_t *qos, u32 filter_id);

u32 qos_classify_packet(qos_t *qos, packet_t *pkt);
ngfw_ret_t qos_enqueue(qos_t *qos, packet_t *pkt, u32 class_id);
packet_t *qos_dequeue(qos_t *qos, u32 class_id);
packet_t *qos_dequeue_any(qos_t *qos);

qos_stats_t *qos_get_stats(qos_t *qos);
qos_stats_t *qos_get_class_stats(qos_t *qos, u32 class_id);
qos_stats_t *qos_get_global_stats(qos_t *qos);

#endif
