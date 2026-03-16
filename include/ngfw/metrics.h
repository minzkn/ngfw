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

#ifndef NGFW_METRICS_H
#define NGFW_METRICS_H

#include "ngfw/types.h"
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    METRIC_TYPE_COUNTER,
    METRIC_TYPE_GAUGE,
    METRIC_TYPE_HISTOGRAM,
    METRIC_TYPE_TIMING
} metric_type_t;

typedef struct metric_counter {
    u64 value;
} metric_counter_t;

typedef struct metric_gauge {
    s64 value;
} metric_gauge_t;

typedef struct metric_histogram {
    u64 count;
    u64 sum;
    u64 min;
    u64 max;
    u64 *buckets;
    u32 num_buckets;
} metric_histogram_t;

typedef struct metric {
    char name[64];
    char description[128];
    metric_type_t type;
    union {
        metric_counter_t counter;
        metric_gauge_t gauge;
        metric_histogram_t histogram;
    } data;
} metric_t;

typedef struct metrics_registry metrics_registry_t;

metrics_registry_t *metrics_create(void);
void metrics_destroy(metrics_registry_t *registry);
ngfw_ret_t metrics_register(metrics_registry_t *registry, const char *name, const char *desc, metric_type_t type);
ngfw_ret_t metrics_counter_inc(metrics_registry_t *registry, const char *name);
ngfw_ret_t metrics_counter_add(metrics_registry_t *registry, const char *name, u64 value);
ngfw_ret_t metrics_gauge_set(metrics_registry_t *registry, const char *name, s64 value);
ngfw_ret_t metrics_gauge_inc(metrics_registry_t *registry, const char *name);
ngfw_ret_t metrics_gauge_dec(metrics_registry_t *registry, const char *name);
ngfw_ret_t metrics_timing_record(metrics_registry_t *registry, const char *name, u64 value);
ngfw_ret_t metrics_get(metrics_registry_t *registry, const char *name, metric_t *metric);
char *metrics_export_json(metrics_registry_t *registry);
void metrics_reset(metrics_registry_t *registry);

#endif
