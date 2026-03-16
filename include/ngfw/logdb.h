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

#ifndef NGFW_LOGDB_H
#define NGFW_LOGDB_H

#include "types.h"

#define LOGDB_MAX_RECORDS 100000
#define LOGDB_PATH_MAX 256

typedef enum {
    LOG_TYPE_FIREWALL,
    LOG_TYPE_IPS,
    LOG_TYPE_URLFILTER,
    LOG_TYPE_NAT,
    LOG_TYPE_VPN,
    LOG_TYPE_SYSTEM,
    LOG_TYPE_AUTH,
    LOG_TYPE_MAX
} log_type_t;

typedef enum {
    LOGDB_LEVEL_DEBUG,
    LOGDB_LEVEL_INFO,
    LOGDB_LEVEL_WARNING,
    LOGDB_LEVEL_ERROR,
    LOGDB_LEVEL_CRITICAL
} logdb_level_t;

typedef struct log_entry {
    u64 id;
    log_type_t type;
    logdb_level_t level;
    u64 timestamp;
    char source[64];
    char message[512];
    char src_ip[48];
    char dst_ip[48];
    u16 src_port;
    u16 dst_port;
    u8 proto;
    char action[16];
    char user[64];
    u32 rule_id;
} log_entry_t;

typedef struct log_filter {
    log_type_t type;
    logdb_level_t level;
    char src_ip[48];
    char dst_ip[48];
    u16 src_port;
    u16 dst_port;
    u8 proto;
    u64 start_time;
    u64 end_time;
    char search[128];
} log_filter_t;

typedef struct log_query {
    log_filter_t filter;
    u32 offset;
    u32 limit;
    bool ascending;
} log_query_t;

typedef struct log_stats {
    u64 total_logs;
    u64 firewall_logs;
    u64 ips_logs;
    u64 urlfilter_logs;
    u64 nat_logs;
    u64 vpn_logs;
    u64 system_logs;
    u64 auth_logs;
    u64 debug_count;
    u64 info_count;
    u64 warning_count;
    u64 error_count;
    u64 critical_count;
} log_stats_t;

typedef struct logdb logdb_t;

logdb_t *logdb_create(const char *db_path);
void logdb_destroy(logdb_t *logdb);

ngfw_ret_t logdb_init(logdb_t *logdb);
ngfw_ret_t logdb_shutdown(logdb_t *logdb);

ngfw_ret_t logdb_add_log(logdb_t *logdb, log_entry_t *entry);
ngfw_ret_t logdb_query(logdb_t *logdb, log_query_t *query, log_entry_t **entries, u32 *count);

ngfw_ret_t logdb_delete_old(logdb_t *logdb, u64 before_timestamp);

log_stats_t *logdb_get_stats(logdb_t *logdb);
void logdb_reset_stats(logdb_t *logdb);

ngfw_ret_t logdb_export_csv(logdb_t *logdb, const char *filename, log_filter_t *filter);
ngfw_ret_t logdb_export_json(logdb_t *logdb, const char *filename, log_filter_t *filter);

ngfw_ret_t logdb_compact(logdb_t *logdb);

typedef void (*logdb_callback_t)(log_entry_t *entry, void *context);
ngfw_ret_t logdb_set_callback(logdb_t *logdb, log_type_t type, logdb_callback_t callback, void *context);

#endif