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

#ifndef NGFW_MONITOR_H
#define NGFW_MONITOR_H

#include "types.h"
#include "engine.h"

typedef struct monitor_stats {
    u64 timestamp;
    u64 cpu_usage;
    u64 memory_usage;
    u64 packet_rate;
    u64 byte_rate;
    u64 session_rate;
    u64 threat_rate;
} monitor_stats_t;

typedef struct monitor_counter {
    char name[64];
    u64 value;
    u64 last_value;
    u64 rate;
    u64 timestamp;
} monitor_counter_t;

typedef struct monitor monitor_t;

monitor_t *monitor_create(void);
void monitor_destroy(monitor_t *monitor);

ngfw_ret_t monitor_init(monitor_t *monitor);
ngfw_ret_t monitor_start(monitor_t *monitor);
ngfw_ret_t monitor_stop(monitor_t *monitor);

ngfw_ret_t monitor_record_counter(monitor_t *monitor, const char *name, u64 value);
ngfw_ret_t monitor_get_stats(monitor_t *monitor, monitor_stats_t *stats);

typedef void (*monitor_alert_callback_t)(const char *alert_type, const char *message, void *context);

ngfw_ret_t monitor_set_alert_callback(monitor_t *monitor, monitor_alert_callback_t callback, void *context);
ngfw_ret_t monitor_trigger_alert(monitor_t *monitor, const char *type, const char *message);

typedef struct snmp_agent snmp_agent_t;

snmp_agent_t *snmp_agent_create(void);
void snmp_agent_destroy(snmp_agent_t *agent);

ngfw_ret_t snmp_agent_start(snmp_agent_t *agent, const char *community, u16 port);
ngfw_ret_t snmp_agent_stop(snmp_agent_t *agent);

typedef struct metrics {
    u64 packets_in;
    u64 packets_out;
    u64 bytes_in;
    u64 bytes_out;
    u64 dropped;
    u64 errors;
    u64 sessions;
    u64 connections;
} metrics_t;

typedef struct metrics_collector {
    metrics_t current;
    metrics_t previous;
    u64 timestamp;
} metrics_collector_t;

metrics_collector_t *metrics_collector_create(void);
void metrics_collector_destroy(metrics_collector_t *collector);

ngfw_ret_t metrics_collector_update(metrics_collector_t *collector, const ngfw_stats_t *engine_stats);
ngfw_ret_t metrics_collector_get_rate(metrics_collector_t *collector, metrics_t *rate);

typedef struct stats_reporter {
    char format[16];
    char destination[256];
    u32 interval;
    bool enabled;
} stats_reporter_t;

stats_reporter_t *stats_reporter_create(void);
void stats_reporter_destroy(stats_reporter_t *reporter);

ngfw_ret_t stats_reporter_configure(stats_reporter_t *reporter, const char *format, const char *destination, u32 interval);
ngfw_ret_t stats_reporter_start(stats_reporter_t *reporter);
ngfw_ret_t stats_reporter_stop(stats_reporter_t *reporter);
ngfw_ret_t stats_reporter_send(stats_reporter_t *reporter, const char *data);

#endif
