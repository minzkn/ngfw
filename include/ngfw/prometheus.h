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

#ifndef NGFW_PROMETHEUS_H
#define NGFW_PROMETHEUS_H

#include "types.h"

typedef enum {
    PROMETHEUS_COUNTER,
    PROMETHEUS_GAUGE,
    PROMETHEUS_HISTOGRAM,
    PROMETHEUS_SUMMARY
} prometheus_metric_type_t;

typedef struct prometheus_counter {
    double value;
    char name[128];
    char help[256];
    char label_name[32];
    char label_value[64];
} prometheus_counter_t;

typedef struct prometheus_gauge {
    double value;
    char name[128];
    char help[256];
    char label_name[32];
    char label_value[64];
} prometheus_gauge_t;

typedef struct prometheus_histogram_bucket {
    double le;
    u64 count;
} prometheus_histogram_bucket_t;

typedef struct prometheus_histogram {
    char name[128];
    char help[256];
    prometheus_histogram_bucket_t buckets[16];
    u64 count;
    double sum;
} prometheus_histogram_t;

typedef struct prometheus_metrics {
    prometheus_counter_t counters[256];
    prometheus_gauge_t gauges[256];
    prometheus_histogram_t histograms[64];
    u32 counter_count;
    u32 gauge_count;
    u32 histogram_count;
} prometheus_metrics_t;

typedef struct prometheus prometheus_t;

prometheus_t *prometheus_create(void);
void prometheus_destroy(prometheus_t *prom);

ngfw_ret_t prometheus_init(prometheus_t *prom);
ngfw_ret_t prometheus_start(prometheus_t *prom);
ngfw_ret_t prometheus_stop(prometheus_t *prom);

ngfw_ret_t prometheus_counter_create(prometheus_t *prom, const char *name, const char *help);
ngfw_ret_t prometheus_counter_inc(prometheus_t *prom, const char *name, double value);
ngfw_ret_t prometheus_counter_add(prometheus_t *prom, const char *name, double value);

ngfw_ret_t prometheus_gauge_create(prometheus_t *prom, const char *name, const char *help);
ngfw_ret_t prometheus_gauge_set(prometheus_t *prom, const char *name, double value);
ngfw_ret_t prometheus_gauge_inc(prometheus_t *prom, const char *name);
ngfw_ret_t prometheus_gauge_dec(prometheus_t *prom, const char *name);

ngfw_ret_t prometheus_histogram_create(prometheus_t *prom, const char *name, const char *help, double *buckets, u32 bucket_count);
ngfw_ret_t prometheus_histogram_observe(prometheus_t *prom, const char *name, double value);

ngfw_ret_t prometheus_export(prometheus_t *prom, char *buffer, size_t size);

ngfw_ret_t prometheus_set_web_context(prometheus_t *prom, void *engine);

#endif
