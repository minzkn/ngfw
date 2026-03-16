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

#include "ngfw/logdb.h"
#include "ngfw/memory.h"
#include "ngfw/list.h"
#include "ngfw/log.h"
#include "ngfw/platform.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/stat.h>

struct logdb {
    char db_path[LOGDB_PATH_MAX];
    list_t *logs;
    log_stats_t stats;
    logdb_callback_t callbacks[LOG_TYPE_MAX];
    void *callback_contexts[LOG_TYPE_MAX];
    pthread_mutex_t lock;
    u64 next_id;
    bool initialized;
};

static const char *log_type_str[] = {
    "firewall", "ips", "urlfilter", "nat", "vpn", "system", "auth"
};

static const char *log_level_str[] = {
    "debug", "info", "warning", "error", "critical"
};

logdb_t *logdb_create(const char *db_path)
{
    logdb_t *logdb = ngfw_malloc(sizeof(logdb_t));
    if (!logdb) return NULL;

    memset(logdb, 0, sizeof(logdb_t));
    
    if (db_path) {
        strncpy(logdb->db_path, db_path, sizeof(logdb->db_path) - 1);
    } else {
        strcpy(logdb->db_path, "/var/log/ngfw/logs.db");
    }

    logdb->logs = list_create(NULL);
    if (!logdb->logs) {
        ngfw_free(logdb);
        return NULL;
    }

    pthread_mutex_init(&logdb->lock, NULL);
    logdb->next_id = 1;

    return logdb;
}

void logdb_destroy(logdb_t *logdb)
{
    if (!logdb) return;

    pthread_mutex_destroy(&logdb->lock);
    list_destroy(logdb->logs);
    ngfw_free(logdb);
}

ngfw_ret_t logdb_init(logdb_t *logdb)
{
    if (!logdb) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&logdb->lock);
    logdb->initialized = true;
    pthread_mutex_unlock(&logdb->lock);

    log_info("Log database initialized: %s", logdb->db_path);
    return NGFW_OK;
}

ngfw_ret_t logdb_shutdown(logdb_t *logdb)
{
    if (!logdb) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&logdb->lock);
    logdb->initialized = false;
    pthread_mutex_unlock(&logdb->lock);

    log_info("Log database shutdown");
    return NGFW_OK;
}

ngfw_ret_t logdb_add_log(logdb_t *logdb, log_entry_t *entry)
{
    if (!logdb || !entry) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&logdb->lock);

    entry->id = logdb->next_id++;
    if (!entry->timestamp) {
        entry->timestamp = get_ms_time();
    }

    log_entry_t *copy = ngfw_malloc(sizeof(log_entry_t));
    if (!copy) {
        pthread_mutex_unlock(&logdb->lock);
        return NGFW_ERR_NO_MEM;
    }

    memcpy(copy, entry, sizeof(log_entry_t));
    list_append(logdb->logs, copy);

    logdb->stats.total_logs++;

    switch (entry->type) {
        case LOG_TYPE_FIREWALL: logdb->stats.firewall_logs++; break;
        case LOG_TYPE_IPS: logdb->stats.ips_logs++; break;
        case LOG_TYPE_URLFILTER: logdb->stats.urlfilter_logs++; break;
        case LOG_TYPE_NAT: logdb->stats.nat_logs++; break;
        case LOG_TYPE_VPN: logdb->stats.vpn_logs++; break;
        case LOG_TYPE_SYSTEM: logdb->stats.system_logs++; break;
        case LOG_TYPE_AUTH: logdb->stats.auth_logs++; break;
        default: break;
    }

    switch (entry->level) {
        case LOGDB_LEVEL_DEBUG: logdb->stats.debug_count++; break;
        case LOGDB_LEVEL_INFO: logdb->stats.info_count++; break;
        case LOGDB_LEVEL_WARNING: logdb->stats.warning_count++; break;
        case LOGDB_LEVEL_ERROR: logdb->stats.error_count++; break;
        case LOGDB_LEVEL_CRITICAL: logdb->stats.critical_count++; break;
        default: break;
    }

    if (logdb->callbacks[entry->type]) {
        logdb->callbacks[entry->type](copy, logdb->callback_contexts[entry->type]);
    }

    while (list_count(logdb->logs) > LOGDB_MAX_RECORDS) {
        list_node_t *node = list_first(logdb->logs);
        if (node) {
            list_remove(logdb->logs, node->data);
            ngfw_free(node->data);
        }
    }

    pthread_mutex_unlock(&logdb->lock);

    return NGFW_OK;
}

static bool log_filter_match(log_entry_t *entry, log_filter_t *filter)
{
    if (filter->type != LOG_TYPE_MAX && entry->type != filter->type) return false;
    if (filter->level != LOGDB_LEVEL_DEBUG && entry->level < filter->level) return false;
    
    if (filter->src_ip[0] && strcmp(entry->src_ip, filter->src_ip) != 0) return false;
    if (filter->dst_ip[0] && strcmp(entry->dst_ip, filter->dst_ip) != 0) return false;
    if (filter->src_port && entry->src_port != filter->src_port) return false;
    if (filter->dst_port && entry->dst_port != filter->dst_port) return false;
    if (filter->proto && entry->proto != filter->proto) return false;

    if (filter->start_time && entry->timestamp < filter->start_time) return false;
    if (filter->end_time && entry->timestamp > filter->end_time) return false;

    if (filter->search[0]) {
        if (!strstr(entry->message, filter->search) &&
            !strstr(entry->source, filter->search)) {
            return false;
        }
    }

    return true;
}

ngfw_ret_t logdb_query(logdb_t *logdb, log_query_t *query, log_entry_t **entries, u32 *count)
{
    if (!logdb || !query || !count) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&logdb->lock);

    u32 matched = 0;
    u32 skipped = 0;
    list_node_t *node;
    list_for_each(logdb->logs, node) {
        log_entry_t *entry = (log_entry_t *)node->data;
        
        if (log_filter_match(entry, &query->filter)) {
            if (skipped < query->offset) {
                skipped++;
                continue;
            }
            matched++;
            if (matched <= query->limit) {
                entries[matched - 1] = entry;
            }
        }
    }

    *count = matched > query->limit ? query->limit : matched;

    pthread_mutex_unlock(&logdb->lock);

    return NGFW_OK;
}

ngfw_ret_t logdb_delete_old(logdb_t *logdb, u64 before_timestamp)
{
    if (!logdb) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&logdb->lock);

    list_node_t *node = list_first(logdb->logs);
    while (node) {
        log_entry_t *entry = (log_entry_t *)node->data;
        list_node_t *next = node->next;

        if (entry->timestamp < before_timestamp) {
            list_remove(logdb->logs, entry);
            ngfw_free(entry);
        }

        node = next;
    }

    pthread_mutex_unlock(&logdb->lock);

    log_info("Deleted logs older than %lu", before_timestamp);
    return NGFW_OK;
}

log_stats_t *logdb_get_stats(logdb_t *logdb)
{
    if (!logdb) return NULL;
    return &logdb->stats;
}

void logdb_reset_stats(logdb_t *logdb)
{
    if (!logdb) return;

    pthread_mutex_lock(&logdb->lock);
    memset(&logdb->stats, 0, sizeof(log_stats_t));
    pthread_mutex_unlock(&logdb->lock);
}

ngfw_ret_t logdb_export_csv(logdb_t *logdb, const char *filename, log_filter_t *filter)
{
    if (!logdb || !filename) return NGFW_ERR_INVALID;

    FILE *fp = fopen(filename, "w");
    if (!fp) return NGFW_ERR;

    fprintf(fp, "id,type,level,timestamp,source,message,src_ip,dst_ip,src_port,dst_port,proto,action,user,rule_id\n");

    pthread_mutex_lock(&logdb->lock);

    list_node_t *node;
    list_for_each(logdb->logs, node) {
        log_entry_t *entry = (log_entry_t *)node->data;

        if (filter && !log_filter_match(entry, filter)) continue;

        fprintf(fp, "%lu,%s,%s,%lu,%s,%s,%s,%s,%u,%u,%u,%s,%s,%u\n",
                entry->id,
                log_type_str[entry->type],
                log_level_str[entry->level],
                entry->timestamp,
                entry->source,
                entry->message,
                entry->src_ip,
                entry->dst_ip,
                entry->src_port,
                entry->dst_port,
                entry->proto,
                entry->action,
                entry->user,
                entry->rule_id);
    }

    pthread_mutex_unlock(&logdb->lock);

    fclose(fp);
    log_info("Exported logs to CSV: %s", filename);
    return NGFW_OK;
}

ngfw_ret_t logdb_export_json(logdb_t *logdb, const char *filename, log_filter_t *filter)
{
    if (!logdb || !filename) return NGFW_ERR_INVALID;

    FILE *fp = fopen(filename, "w");
    if (!fp) return NGFW_ERR;

    fprintf(fp, "[\n");

    pthread_mutex_lock(&logdb->lock);

    bool first = true;
    list_node_t *node;
    list_for_each(logdb->logs, node) {
        log_entry_t *entry = (log_entry_t *)node->data;

        if (filter && !log_filter_match(entry, filter)) continue;

        if (!first) fprintf(fp, ",\n");
        first = false;

        fprintf(fp, "  {\n");
        fprintf(fp, "    \"id\": %lu,\n", entry->id);
        fprintf(fp, "    \"type\": \"%s\",\n", log_type_str[entry->type]);
        fprintf(fp, "    \"level\": \"%s\",\n", log_level_str[entry->level]);
        fprintf(fp, "    \"timestamp\": %lu,\n", entry->timestamp);
        fprintf(fp, "    \"source\": \"%s\",\n", entry->source);
        fprintf(fp, "    \"message\": \"%s\",\n", entry->message);
        fprintf(fp, "    \"src_ip\": \"%s\",\n", entry->src_ip);
        fprintf(fp, "    \"dst_ip\": \"%s\",\n", entry->dst_ip);
        fprintf(fp, "    \"src_port\": %u,\n", entry->src_port);
        fprintf(fp, "    \"dst_port\": %u,\n", entry->dst_port);
        fprintf(fp, "    \"proto\": %u,\n", entry->proto);
        fprintf(fp, "    \"action\": \"%s\",\n", entry->action);
        fprintf(fp, "    \"user\": \"%s\",\n", entry->user);
        fprintf(fp, "    \"rule_id\": %u\n", entry->rule_id);
        fprintf(fp, "  }");
    }

    pthread_mutex_unlock(&logdb->lock);

    fprintf(fp, "\n]\n");

    fclose(fp);
    log_info("Exported logs to JSON: %s", filename);
    return NGFW_OK;
}

ngfw_ret_t logdb_compact(logdb_t *logdb)
{
    if (!logdb) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&logdb->lock);

    (void)list_count(logdb->logs);

    list_node_t *node = list_first(logdb->logs);
    u32 removed = 0;
    while (node) {
        list_node_t *next = node->next;
        log_entry_t *entry = (log_entry_t *)node->data;

        if (entry->level == LOGDB_LEVEL_DEBUG || entry->level == LOGDB_LEVEL_INFO) {
            if (entry->timestamp < get_ms_time() - 86400000UL) {
                list_remove(logdb->logs, entry);
                ngfw_free(entry);
                removed++;
            }
        }

        node = next;
    }

    pthread_mutex_unlock(&logdb->lock);

    log_info("Compacted log database: removed %u entries", removed);
    return NGFW_OK;
}

ngfw_ret_t logdb_set_callback(logdb_t *logdb, log_type_t type, logdb_callback_t callback, void *context)
{
    if (!logdb || type >= LOG_TYPE_MAX) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&logdb->lock);
    logdb->callbacks[type] = callback;
    logdb->callback_contexts[type] = context;
    pthread_mutex_unlock(&logdb->lock);

    return NGFW_OK;
}