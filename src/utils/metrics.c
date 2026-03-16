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

#include "ngfw/metrics.h"
#include "ngfw/memory.h"
#include "ngfw/hash.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_METRICS 256

struct metrics_registry {
    hash_table_t *metrics;
    u32 max_metrics;
};

static u32 metric_name_hash(const void *key, u32 size)
{
    (void)size;
    const char *name = (const char *)key;
    u32 hash = 5381;
    while (*name) {
        hash = ((hash << 5) + hash) + (*name++);
    }
    return hash;
}

static bool metric_name_equal(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b) == 0;
}

metrics_registry_t *metrics_create(void)
{
    metrics_registry_t *registry = ngfw_malloc(sizeof(metrics_registry_t));
    if (!registry) return NULL;
    
    registry->metrics = hash_create(64, metric_name_hash, metric_name_equal, NULL);
    if (!registry->metrics) {
        ngfw_free(registry);
        return NULL;
    }
    
    registry->max_metrics = MAX_METRICS;
    return registry;
}

void metrics_destroy(metrics_registry_t *registry)
{
    if (!registry) return;
    
    hash_destroy(registry->metrics);
    ngfw_free(registry);
}

ngfw_ret_t metrics_register(metrics_registry_t *registry, const char *name, const char *desc, metric_type_t type)
{
    if (!registry || !name) return NGFW_ERR_INVALID;
    
    metric_t *existing = hash_lookup(registry->metrics, name);
    if (existing) return NGFW_ERR_EXISTS;
    
    metric_t *metric = ngfw_malloc(sizeof(metric_t));
    if (!metric) return NGFW_ERR_NO_MEM;
    
    strncpy(metric->name, name, sizeof(metric->name) - 1);
    metric->name[sizeof(metric->name) - 1] = '\0';
    
    if (desc) {
        strncpy(metric->description, desc, sizeof(metric->description) - 1);
        metric->description[sizeof(metric->description) - 1] = '\0';
    } else {
        metric->description[0] = '\0';
    }
    
    metric->type = type;
    
    if (type == METRIC_TYPE_COUNTER) {
        metric->data.counter.value = 0;
    } else if (type == METRIC_TYPE_GAUGE) {
        metric->data.gauge.value = 0;
    } else if (type == METRIC_TYPE_HISTOGRAM) {
        metric->data.histogram.count = 0;
        metric->data.histogram.sum = 0;
        metric->data.histogram.min = 0;
        metric->data.histogram.max = 0;
        metric->data.histogram.buckets = NULL;
        metric->data.histogram.num_buckets = 0;
    }
    
    hash_insert(registry->metrics, metric->name, metric);
    return NGFW_OK;
}

ngfw_ret_t metrics_counter_inc(metrics_registry_t *registry, const char *name)
{
    return metrics_counter_add(registry, name, 1);
}

ngfw_ret_t metrics_counter_add(metrics_registry_t *registry, const char *name, u64 value)
{
    if (!registry || !name) return NGFW_ERR_INVALID;
    
    metric_t *metric = hash_lookup(registry->metrics, name);
    if (!metric || metric->type != METRIC_TYPE_COUNTER) return NGFW_ERR_INVALID;
    
    metric->data.counter.value += value;
    return NGFW_OK;
}

ngfw_ret_t metrics_gauge_set(metrics_registry_t *registry, const char *name, s64 value)
{
    if (!registry || !name) return NGFW_ERR_INVALID;
    
    metric_t *metric = hash_lookup(registry->metrics, name);
    if (!metric || metric->type != METRIC_TYPE_GAUGE) return NGFW_ERR_INVALID;
    
    metric->data.gauge.value = value;
    return NGFW_OK;
}

ngfw_ret_t metrics_gauge_inc(metrics_registry_t *registry, const char *name)
{
    if (!registry || !name) return NGFW_ERR_INVALID;
    
    metric_t *metric = hash_lookup(registry->metrics, name);
    if (!metric || metric->type != METRIC_TYPE_GAUGE) return NGFW_ERR_INVALID;
    
    metric->data.gauge.value++;
    return NGFW_OK;
}

ngfw_ret_t metrics_gauge_dec(metrics_registry_t *registry, const char *name)
{
    if (!registry || !name) return NGFW_ERR_INVALID;
    
    metric_t *metric = hash_lookup(registry->metrics, name);
    if (!metric || metric->type != METRIC_TYPE_GAUGE) return NGFW_ERR_INVALID;
    
    metric->data.gauge.value--;
    return NGFW_OK;
}

ngfw_ret_t metrics_timing_record(metrics_registry_t *registry, const char *name, u64 value)
{
    if (!registry || !name) return NGFW_ERR_INVALID;
    
    metric_t *metric = hash_lookup(registry->metrics, name);
    if (!metric) return NGFW_ERR_INVALID;
    
    if (metric->type == METRIC_TYPE_COUNTER) {
        metric->data.counter.value++;
    } else if (metric->type == METRIC_TYPE_TIMING || metric->type == METRIC_TYPE_HISTOGRAM) {
        metric->data.histogram.count++;
        metric->data.histogram.sum += value;
        if (metric->data.histogram.min == 0 || value < metric->data.histogram.min) {
            metric->data.histogram.min = value;
        }
        if (value > metric->data.histogram.max) {
            metric->data.histogram.max = value;
        }
    }
    
    return NGFW_OK;
}

ngfw_ret_t metrics_get(metrics_registry_t *registry, const char *name, metric_t *metric)
{
    if (!registry || !name || !metric) return NGFW_ERR_INVALID;
    
    metric_t *found = hash_lookup(registry->metrics, name);
    if (!found) return NGFW_ERR_NOT_FOUND;
    
    memcpy(metric, found, sizeof(metric_t));
    return NGFW_OK;
}

char *metrics_export_json(metrics_registry_t *registry)
{
    if (!registry) return NULL;
    
    static char buffer[16384];
    int pos = 0;
    pos += snprintf(buffer + pos, sizeof(buffer) - pos, "{\n");
    
    void **iter = hash_iterate_start(registry->metrics);
    bool first = true;
    while (hash_iterate_has_next(iter)) {
        metric_t *m = hash_iterate_next(registry->metrics, iter);
        if (!m) continue;
        
        if (!first) pos += snprintf(buffer + pos, sizeof(buffer) - pos, ",\n");
        first = false;
        
        if (m->type == METRIC_TYPE_COUNTER) {
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, "  \"%s\": %lu", m->name, m->data.counter.value);
        } else if (m->type == METRIC_TYPE_GAUGE) {
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, "  \"%s\": %ld", m->name, m->data.gauge.value);
        } else if (m->type == METRIC_TYPE_HISTOGRAM || m->type == METRIC_TYPE_TIMING) {
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, "  \"%s\": {\"count\": %lu, \"sum\": %lu, \"min\": %lu, \"max\": %lu}",
                m->name, m->data.histogram.count, m->data.histogram.sum, m->data.histogram.min, m->data.histogram.max);
        }
    }
    
    pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\n}\n");
    return buffer;
}

void metrics_reset(metrics_registry_t *registry)
{
    if (!registry) return;
    hash_destroy(registry->metrics);
    registry->metrics = hash_create(64, metric_name_hash, metric_name_equal, NULL);
}
