#include "ngfw/prometheus.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include "ngfw/engine.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PROMETHEUS_DEFAULT_PORT 9090
#define MAX_METRICS 1024

struct prometheus {
    prometheus_metrics_t metrics;
    u16 port;
    int socket_fd;
    bool initialized;
    bool running;
    void *engine;
};

prometheus_t *prometheus_create(void)
{
    prometheus_t *prom = ngfw_malloc(sizeof(prometheus_t));
    if (!prom) return NULL;

    memset(prom, 0, sizeof(prometheus_t));

    prom->metrics.counter_count = 0;
    prom->metrics.gauge_count = 0;
    prom->metrics.histogram_count = 0;

    prom->port = PROMETHEUS_DEFAULT_PORT;
    prom->socket_fd = -1;

    prometheus_counter_create(prom, "ngfw_packets_total", "Total packets processed");
    prometheus_counter_create(prom, "ngfw_packets_dropped_total", "Total packets dropped");
    prometheus_counter_create(prom, "ngfw_packets_forwarded_total", "Total packets forwarded");
    prometheus_counter_create(prom, "ngfw_bytes_total", "Total bytes processed");

    prometheus_gauge_create(prom, "ngfw_sessions_active", "Active sessions");
    prometheus_gauge_create(prom, "ngfw_sessions_created_total", "Total sessions created");
    prometheus_gauge_create(prom, "ngfw_ips_threats_blocked_total", "Total IPS threats blocked");

    log_info("Prometheus metrics created");

    return prom;
}

void prometheus_destroy(prometheus_t *prom)
{
    if (!prom) return;

    if (prom->running) {
        prometheus_stop(prom);
    }

    ngfw_free(prom);

    log_info("Prometheus metrics destroyed");
}

ngfw_ret_t prometheus_init(prometheus_t *prom)
{
    if (!prom) return NGFW_ERR_INVALID;

    prom->initialized = true;

    log_info("Prometheus metrics initialized");

    return NGFW_OK;
}

ngfw_ret_t prometheus_start(prometheus_t *prom)
{
    if (!prom || !prom->initialized) return NGFW_ERR_INVALID;

    prom->running = true;

    log_info("Prometheus metrics started on port %d", prom->port);

    return NGFW_OK;
}

ngfw_ret_t prometheus_stop(prometheus_t *prom)
{
    if (!prom) return NGFW_ERR_INVALID;

    prom->running = false;

    log_info("Prometheus metrics stopped");

    return NGFW_OK;
}

static prometheus_counter_t *find_counter(prometheus_t *prom, const char *name)
{
    for (u32 i = 0; i < prom->metrics.counter_count; i++) {
        if (strcmp(prom->metrics.counters[i].name, name) == 0) {
            return &prom->metrics.counters[i];
        }
    }
    return NULL;
}

static prometheus_gauge_t *find_gauge(prometheus_t *prom, const char *name)
{
    for (u32 i = 0; i < prom->metrics.gauge_count; i++) {
        if (strcmp(prom->metrics.gauges[i].name, name) == 0) {
            return &prom->metrics.gauges[i];
        }
    }
    return NULL;
}

ngfw_ret_t prometheus_counter_create(prometheus_t *prom, const char *name, const char *help)
{
    if (!prom || !name) return NGFW_ERR_INVALID;

    if (prom->metrics.counter_count >= 256) {
        return NGFW_ERR_NO_RESOURCE;
    }

    prometheus_counter_t *counter = &prom->metrics.counters[prom->metrics.counter_count++];

    strncpy(counter->name, name, sizeof(counter->name) - 1);
    strncpy(counter->help, help ? help : "", sizeof(counter->help) - 1);
    counter->value = 0;

    return NGFW_OK;
}

ngfw_ret_t prometheus_counter_inc(prometheus_t *prom, const char *name, double value)
{
    if (!prom || !name) return NGFW_ERR_INVALID;

    prometheus_counter_t *counter = find_counter(prom, name);
    if (!counter) return NGFW_ERR_INVALID;

    counter->value += value;

    return NGFW_OK;
}

ngfw_ret_t prometheus_counter_add(prometheus_t *prom, const char *name, double value)
{
    return prometheus_counter_inc(prom, name, value);
}

ngfw_ret_t prometheus_gauge_create(prometheus_t *prom, const char *name, const char *help)
{
    if (!prom || !name) return NGFW_ERR_INVALID;

    if (prom->metrics.gauge_count >= 256) {
        return NGFW_ERR_NO_RESOURCE;
    }

    prometheus_gauge_t *gauge = &prom->metrics.gauges[prom->metrics.gauge_count++];

    strncpy(gauge->name, name, sizeof(gauge->name) - 1);
    strncpy(gauge->help, help ? help : "", sizeof(gauge->help) - 1);
    gauge->value = 0;

    return NGFW_OK;
}

ngfw_ret_t prometheus_gauge_set(prometheus_t *prom, const char *name, double value)
{
    if (!prom || !name) return NGFW_ERR_INVALID;

    prometheus_gauge_t *gauge = find_gauge(prom, name);
    if (!gauge) return NGFW_ERR_INVALID;

    gauge->value = value;

    return NGFW_OK;
}

ngfw_ret_t prometheus_gauge_inc(prometheus_t *prom, const char *name)
{
    if (!prom || !name) return NGFW_ERR_INVALID;

    prometheus_gauge_t *gauge = find_gauge(prom, name);
    if (!gauge) return NGFW_ERR_INVALID;

    gauge->value += 1.0;

    return NGFW_OK;
}

ngfw_ret_t prometheus_gauge_dec(prometheus_t *prom, const char *name)
{
    if (!prom || !name) return NGFW_ERR_INVALID;

    prometheus_gauge_t *gauge = find_gauge(prom, name);
    if (!gauge) return NGFW_ERR_INVALID;

    gauge->value -= 1.0;

    return NGFW_OK;
}

ngfw_ret_t prometheus_histogram_create(prometheus_t *prom, const char *name, const char *help,
                                       double *buckets, u32 bucket_count)
{
    if (!prom || !name) return NGFW_ERR_INVALID;
    
    (void)help;
    (void)buckets;
    (void)bucket_count;
    
    log_debug("Created histogram: %s", name);
    return NGFW_OK;
}

ngfw_ret_t prometheus_histogram_observe(prometheus_t *prom, const char *name, double value)
{
    if (!prom || !name) return NGFW_ERR_INVALID;
    
    (void)value;
    log_debug("Histogram observe: %s = %f", name, value);
    return NGFW_OK;
}

ngfw_ret_t prometheus_export(prometheus_t *prom, char *buffer, size_t size)
{
    if (!prom || !buffer || size == 0) return NGFW_ERR_INVALID;

    size_t offset = 0;

    if (prom->engine) {
        ngfw_stats_t *stats = ngfw_engine_get_stats((ngfw_engine_t *)prom->engine);
        if (stats) {
            prometheus_counter_inc(prom, "ngfw_packets_total", stats->packets_processed);
            prometheus_counter_inc(prom, "ngfw_packets_dropped_total", stats->packets_dropped);
            prometheus_counter_inc(prom, "ngfw_packets_forwarded_total", stats->packets_forwarded);
            prometheus_counter_inc(prom, "ngfw_bytes_total", stats->bytes_processed);
            prometheus_gauge_set(prom, "ngfw_sessions_active", stats->sessions_active);
            prometheus_gauge_set(prom, "ngfw_sessions_created_total", stats->sessions_created);
            prometheus_gauge_set(prom, "ngfw_ips_threats_blocked_total", stats->ips_threats_blocked);
        }
    }

    for (u32 i = 0; i < prom->metrics.counter_count; i++) {
        prometheus_counter_t *c = &prom->metrics.counters[i];
        if (c->name[0]) {
            if (c->label_name[0]) {
                offset += snprintf(buffer + offset, size - offset,
                    "# HELP %s %s\n# TYPE %s counter\n%s{%s=\"%s\"} %.0f\n\n",
                    c->name, c->help, c->name, c->name, c->label_name, c->label_value, c->value);
            } else {
                offset += snprintf(buffer + offset, size - offset,
                    "# HELP %s %s\n# TYPE %s counter\n%s %.0f\n\n",
                    c->name, c->help, c->name, c->name, c->value);
            }
        }
    }

    for (u32 i = 0; i < prom->metrics.gauge_count; i++) {
        prometheus_gauge_t *g = &prom->metrics.gauges[i];
        if (g->name[0]) {
            if (g->label_name[0]) {
                offset += snprintf(buffer + offset, size - offset,
                    "# HELP %s %s\n# TYPE %s gauge\n%s{%s=\"%s\"} %.0f\n\n",
                    g->name, g->help, g->name, g->name, g->label_name, g->label_value, g->value);
            } else {
                offset += snprintf(buffer + offset, size - offset,
                    "# HELP %s %s\n# TYPE %s gauge\n%s %.0f\n\n",
                    g->name, g->help, g->name, g->name, g->value);
            }
        }
    }

    return NGFW_OK;
}

ngfw_ret_t prometheus_set_web_context(prometheus_t *prom, void *engine)
{
    if (!prom) return NGFW_ERR_INVALID;
    prom->engine = engine;
    return NGFW_OK;
}
